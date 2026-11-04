/**
 * Who the Lab is on this host: its base URL and its one did:webvh, which is both
 * the verifier (every door's requests and receipts, key #verifier) and the test
 * issuer (credentials, key #issuer). A third key, the DID's update key, signs the DID log. Keys and
 * the DID log are made on first start and kept in DATA_DIR, so the DID, receipts
 * and credentials stay the same across restarts. A new host needs a new DATA_DIR,
 * and so gets a new DID.
 */
import { createPrivateKey, sign } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import type { IncomingHttpHeaders } from 'node:http';
import { lookup, type LookupAddress } from 'node:dns';
import { BlockList } from 'node:net';
import { join } from 'node:path';
import { exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';
import { Agent } from 'undici';
import {
  MultibaseEncoding, createDID, defaultVerifier, generateParallelDidWeb, multibaseEncode, prepareDataForSigning, resolveDIDFromLog,
  type DIDDocument, type DIDLog, type Signer,
} from 'didwebvh-ts';

export const PORT = Number(process.env.PORT ?? 8401);
// did:webvh needs a domain name, so not bare localhost; *.localhost resolves to this machine.
export const BASE_URL = (process.env.BASE_URL ?? `http://pg.localhost:${PORT}`).replace(/\/$/, '');
export const ORIGIN = new URL(BASE_URL).origin;
/** The path the app lives under ('' at the root, e.g. '/proving-ground'). The DID and the documents a door claims at /.well-known stay at the origin. */
export const PREFIX = new URL(BASE_URL).pathname.replace(/\/$/, '');
export const DATA_DIR = process.env.DATA_DIR ?? 'data';
const HOST = new URL(BASE_URL).host;
/** What the server hands a door. `path` is below the door's URL ('' for the door itself), `url` the full public URL; `route` is the path as public timelines show it, run ID elided. */
export type DoorRequest = { runId: string | null; route: string; method: string; path: string; url: URL; headers: IncomingHttpHeaders; body: string };

/** The one dev switch: on http://localhost (or *.localhost), doors accept http URLs and loopback addresses that the spec would refuse. */
export const DEV = /^http:\/\/(([a-z0-9-]+\.)?localhost|127\.0\.0\.1)(:|$)/.test(BASE_URL);

/** Addresses a door never fetches for a URL a caller chose. */
export const PRIVATE = new BlockList();
for (const [net, bits] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.168.0.0', 16]] as const) PRIVATE.addSubnet(net, bits, 'ipv4');
// No ::ffff:0:0/96 rule: BlockList checks IPv4-mapped IPv6 against the IPv4 rules, and that rule would match every IPv4 address.
for (const [net, bits] of [['::1', 128], ['fc00::', 7], ['fe80::', 10]] as const) PRIVATE.addSubnet(net, bits, 'ipv6');

const isPrivate = (a: LookupAddress) => PRIVATE.check(a.address, a.family === 6 ? 'ipv6' : 'ipv4');
/** Checks every address at connect time, so a second DNS answer can't swap a private one in after a door's own check. */
const PUBLIC_ONLY = new Agent({
  connect: {
    lookup: ((host: string, opts: { all?: boolean }, cb: (...a: unknown[]) => void) =>
      lookup(host, { ...opts, all: true }, (err, addrs) => {
        if (err) return cb(err);
        if (addrs.some(isPrivate)) return cb(Object.assign(new Error(`${host} resolves to a private address.`), { code: 'EPRIVATE' }));
        return opts.all ? cb(null, addrs) : cb(null, addrs[0].address, addrs[0].family);
      })) as never,
  },
});
// Node's fetch takes an undici dispatcher; RequestInit's type doesn't list it.
const pinned = (url: URL, init: RequestInit) => fetch(url, { ...init, dispatcher: PUBLIC_ONLY } as RequestInit);
/** fetch for a URL a caller chose: private addresses refused, except on the dev BASE_URL where the tests serve agents on loopback. */
export const fetchPublic = (url: URL, init: RequestInit = {}) => (DEV ? fetch(url, init) : pinned(url, init));
/** Exported for the test that the guard holds. */
export const fetchPublicStrict = (url: URL) => pinned(url, {});

async function privateJwk(name: string, alg: 'ES256' | 'Ed25519'): Promise<JWK> {
  const file = join(DATA_DIR, `${name}.key.json`);
  if (!existsSync(file)) {
    const { privateKey } = await generateKeyPair(alg, { extractable: true });
    mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(file, JSON.stringify(await exportJWK(privateKey)), { mode: 0o600 });
  }
  return JSON.parse(readFileSync(file, 'utf8'));
}

async function es256(name: string, kid: string) {
  const { kty, crv, x, y, d } = await privateJwk(name, 'ES256');
  const jwk: JWK = { kty, crv, x, y, kid, alg: 'ES256', use: 'sig' };
  return { kid, jwk, key: (await importJWK({ ...jwk, d }, 'ES256')) as CryptoKey, publicKey: (await importJWK(jwk, 'ES256')) as CryptoKey };
}

/** The DID log: read from DATA_DIR, or created for this host on first start. */
async function didLog(keys: Record<'verifier' | 'issuer', JWK>): Promise<DIDLog> {
  const file = join(DATA_DIR, 'did.jsonl');
  if (!existsSync(file)) {
    const update = await privateJwk('did-update', 'Ed25519');
    const updateKey = multibaseEncode(new Uint8Array([0xed, 0x01, ...Buffer.from(update.x!, 'base64url')]), MultibaseEncoding.BASE58_BTC);
    const privateKey = createPrivateKey({ key: update as never, format: 'jwk' });
    const signer: Signer = {
      getVerificationMethodId: () => `did:key:${updateKey}#${updateKey}`,
      sign: async ({ document, proof }) => ({ proofValue: multibaseEncode(sign(null, await prepareDataForSigning(document, proof), privateKey), MultibaseEncoding.BASE58_BTC) }),
    };
    const { log } = await createDID({
      address: HOST, signer, verifier: defaultVerifier, updateKeys: [updateKey],
      // Only settable at creation; lets this DID move host later and keep its history.
      portable: true,
      alsoKnownAsWeb: true,
      didDocument: {
        '@context': ['https://www.w3.org/ns/did/v1'],
        id: '{DID}',
        verificationMethod: Object.entries(keys).map(([name, jwk]) => ({ id: `{DID}#${name}`, type: 'JsonWebKey2020', controller: '{DID}', publicKeyJwk: jwk as never })),
        // #verifier signs requests and receipts; #issuer signs credentials (assertions).
        assertionMethod: ['{DID}#verifier', '{DID}#issuer'],
        authentication: ['{DID}#verifier'],
      },
    });
    writeFileSync(file, log.map((e) => JSON.stringify(e)).join('\n') + '\n');
  }
  return readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
}

const pub = async (name: string) => (({ kty, crv, x, y }) => ({ kty, crv, x, y }))(await privateJwk(name, 'ES256'));
const keys = { verifier: await pub('verifier'), issuer: await pub('issuer') };
const log = await didLog(keys);
const { didDocument: doc, didResolutionMetadata: meta } = await resolveDIDFromLog(log, { verifier: defaultVerifier });
if (!doc) throw new Error(`${DATA_DIR}/did.jsonl does not resolve: ${JSON.stringify(meta)}`);

/** The Lab's identifier, as verifier (every door's client_id) and as issuer; its log is at `${ORIGIN}/.well-known/did.jsonl`. */
export const DID = doc.id;
if (!DID.endsWith(`:${encodeURIComponent(HOST)}`)) {
  throw new Error(`${DATA_DIR}/did.jsonl is ${DID}, not for ${HOST}. A new host gets a new DID: point DATA_DIR at an empty directory.`);
}
for (const [name, jwk] of Object.entries(keys)) {
  const listed = doc.verificationMethod?.find((v) => v.id === `${DID}#${name}`)?.publicKeyJwk as JWK | undefined;
  if (listed?.x !== jwk.x) throw new Error(`${DATA_DIR}/did.jsonl does not list ${DATA_DIR}/${name}.key.json as #${name}. Start with an empty DATA_DIR.`);
}

export const verifier = await es256('verifier', `${DID}#verifier`);
export const issuer = await es256('issuer', `${DID}#issuer`);

/** did.jsonl as served: one log entry per line. */
export const didLogText = log.map((e) => JSON.stringify(e)).join('\n') + '\n';
/** The parallel did:web document, for resolvers that only know did:web. */
export const didWebDocument: DIDDocument = generateParallelDidWeb(DID, doc);
