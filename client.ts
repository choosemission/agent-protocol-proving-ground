/**
 * A reference agent and wallet for the x401 door, in one file: the e2e test's driver, and
 * something to read next to the spec. It does the exchange as a relaying
 * agent would:
 *
 *   node client.ts <run's x401 door URL> [--unsigned]
 *
 * 1. GET the door and decode PROOF-REQUEST.
 * 2. Take the signed entry, resolve the door's did:webvh (checking its whole log)
 *    and check the JAR against the key it names
 *    (or, with --unsigned, the unsigned entry).
 * 3. Get the run's handle credential from the Lab issuer, using the run ID in
 *    the door URL. A real wallet already holds one.
 * 4. Disclose only the claims the DCQL query names, and sign a KB-JWT
 *    binding the presentation to the nonce and the audience.
 * 5. Retry the door with PROOF-RESPONSE and print what came back.
 */
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { SignJWT, decodeJwt, decodeProtectedHeader, exportJWK, generateKeyPair, importJWK, jwtVerify, type JWK, type JWTPayload } from 'jose';
import { defaultVerifier, resolveDIDFromLog } from 'didwebvh-ts';

export const decode = (header: string) => JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
export const encode = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');

type Query = { id: string; claims: { path: string[] }[] };
export type OpenID4VPRequest = JWTPayload & { nonce: string; client_id?: string; dcql_query: { credentials: Query[] } };

export async function newHolder() {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  return { key: privateKey, jwk: await exportJWK(publicKey) };
}

export async function getCredential(origin: string, jwk: unknown, run: string): Promise<string> {
  const res = await fetch(`${origin}/pg/issuer/credential`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jwk, run }) });
  if (!res.ok) throw new Error(`issuer said ${res.status}: ${await res.text()}`);
  return (await res.json()).credential;
}

/** GETs the door; returns the x401 payload, the verified signed request, and the unsigned one. */
export async function challenge(doorUrl: string) {
  const res = await fetch(doorUrl);
  const header = res.headers.get('proof-request');
  if (!header) throw new Error(`expected PROOF-REQUEST, got ${res.status}`);
  const payload = decode(header);
  const entry = (protocol: string) => payload.credential_requirements.digital.requests.find((r: { protocol: string }) => r.protocol === protocol);
  const jar: string = entry('openid4vp-v1-signed').data.request;
  // client_id is decentralized_identifier:did:webvh:<scid>:<host>; fetch its log, verify it, check the JAR with the key it names.
  const did = String(decodeJwt(jar).client_id).replace(/^decentralized_identifier:/, '');
  const [method, , host, ...path] = did.split(':').slice(1);
  if (method !== 'webvh' || !host) throw new Error(`expected a did:webvh client_id, got ${did}`);
  const scheme = /(^|\.)localhost(:|$)/.test(decodeURIComponent(host)) ? 'http' : 'https';
  const url = `${scheme}://${decodeURIComponent(host)}/${path.length ? path.map(decodeURIComponent).join('/') : '.well-known'}/did.jsonl`;
  const log = (await (await fetch(url)).text()).trim().split('\n').map((l) => JSON.parse(l));
  const { didDocument } = await resolveDIDFromLog(log, { verifier: defaultVerifier });
  if (didDocument?.id !== did) throw new Error(`${url} does not resolve to ${did}`);
  const { kid } = decodeProtectedHeader(jar);
  const vm = didDocument.verificationMethod?.find((v) => v.id === kid);
  if (!vm?.publicKeyJwk) throw new Error(`${did} has no key ${kid}`);
  const { payload: signed } = await jwtVerify(jar, await importJWK(vm.publicKeyJwk as JWK, 'ES256'), { typ: 'oauth-authz-req+jwt' });
  return { payload, signed: signed as OpenID4VPRequest, unsigned: entry('openid4vp-v1-unsigned').data as OpenID4VPRequest };
}

/** An SD-JWT presentation with only `disclose` revealed, and a KB-JWT over it. */
export async function present(credential: string, holderKey: CryptoKey, o: { nonce: string; aud: string; disclose: string[] }) {
  const [issuerJwt, ...disclosures] = credential.split('~').filter(Boolean);
  const kept = disclosures.filter((d) => o.disclose.includes(decode(d)[1]));
  const body = `${[issuerJwt, ...kept].join('~')}~`;
  const kb = await new SignJWT({ nonce: o.nonce, aud: o.aud, sd_hash: createHash('sha256').update(body).digest('base64url') })
    .setProtectedHeader({ alg: 'ES256', typ: 'kb+jwt' })
    .setIssuedAt()
    .sign(holderKey);
  return body + kb;
}

/** The PROOF-RESPONSE value: a Result Artifact carrying the result inline. */
export const resultArtifact = (protocol: string, queryId: string, presentation: string) =>
  encode({ request_id: 'pg-x401-v1', credential_result: { protocol, data: { vp_token: { [queryId]: [presentation] } } } });

async function main() {
  const doorUrl = process.argv[2];
  const run = doorUrl && /\/r\/([\w-]+)$/.exec(new URL(doorUrl).pathname)?.[1];
  if (!run) throw new Error("usage: node client.ts <run's x401 door URL> [--unsigned]  (POST /pg/runs to start a run)");
  const unsigned = process.argv.includes('--unsigned');
  const origin = new URL(doorUrl).origin;

  const { signed, unsigned: plain } = await challenge(doorUrl);
  const request = unsigned ? plain : signed;
  const query = request.dcql_query.credentials[0];
  console.log(`← 401 PROOF-REQUEST; using the ${unsigned ? 'unsigned' : 'signed'} entry, nonce ${request.nonce}`);

  const holder = await newHolder();
  const credential = await getCredential(origin, holder.jwk, run);
  const disclose = query.claims.map((c) => c.path[0]);
  const presentation = await present(credential, holder.key, { nonce: request.nonce, aud: unsigned ? `origin:${origin}` : request.client_id!, disclose });
  console.log(`→ retry with PROOF-RESPONSE, disclosing ${disclose.join(', ')}`);

  const res = await fetch(doorUrl, { headers: { 'PROOF-RESPONSE': resultArtifact(`openid4vp-v1-${unsigned ? 'unsigned' : 'signed'}`, query.id, presentation) } });
  const result = res.headers.get('proof-result');
  console.log(`← ${res.status} PROOF-RESULT`, result && decode(result));
  console.log(JSON.stringify(await res.json(), null, 2));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
