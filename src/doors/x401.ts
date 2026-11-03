/**
 * The x401 door: a resource behind x401 0.2.0, as published at
 * proof/x401@7e864af, that asks for the Lab's handle credential.
 *
 * A request without proof gets 401 + PROOF-REQUEST. A retry with
 * PROOF-RESPONSE is walked up LADDER one check at a time; the attempt
 * records the highest step it reached. Getting through returns a Lab-signed
 * receipt in PROOF-RESULT. Stopping returns PROOF-RESULT
 * with an x401 Error Object that names the step and says why.
 *
 * What the agent presents is checked and dropped: no credential, presentation
 * or disclosed value is stored, only which checks passed.
 */
import { randomBytes } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { BlockList } from 'node:net';
import { SignJWT, decodeJwt, decodeProtectedHeader, importJWK, importX509, jwtVerify, type JWK, type JWTPayload } from 'jose';
import type { IncomingHttpHeaders } from 'node:http';
import { BASE_URL, DID, ISSUER_ID, ORIGIN, issuer, verifier } from '../lab.ts';
import { VCT, digest } from '../issuer.ts';
import * as store from '../store.ts';

const SPEC_URL = 'https://github.com/proof/x401/blob/7e864af97cd8202a5380386f52939d759541977d/spec.md';

/** The steps, in the spec's order. `ref` is the spec section each comes from. */
export const LADDER = [
  { name: 'challenged', ref: 'x401-gated-resource-configuration' },
  { name: 'retried', ref: 'route-retry-headers' },
  { name: 'artifact decoded', ref: 'result-artifact' },
  { name: 'nonce matched', ref: 'replay-prevention' },
  { name: 'signature valid', ref: 'proof-validation' },
  { name: 'binding valid', ref: 'verifier-binding' },
  { name: 'query met', ref: 'proof-validation' },
  { name: 'issuer trusted', ref: 'issuer-trust' },
  { name: 'through', ref: 'proof-validation' },
] as const;
type StepName = (typeof LADDER)[number]['name'];
export const THROUGH = LADDER.length - 1;

const CLIENT_ID = `decentralized_identifier:${DID}`;
const REQUEST_ID = 'pg-x401-v1';
const QUERY_ID = 'lab_handle';
const ALGS = ['ES256', 'ES384', 'EdDSA'];
const NONCE_TTL_S = 300;

/** What the door asks for: a Lab handle credential, disclosing the handle (on a run's URL, that run's handle). */
const dcql = (handle: string | null) => ({
  credentials: [
    {
      id: QUERY_ID,
      format: 'dc+sd-jwt',
      meta: { vct_values: [VCT] },
      claims: [{ path: ['handle'], ...(handle && { values: [handle] }) }],
    },
  ],
});

/** Shown on the wall and served at /pg/state. */
export const INFO = {
  door: 'x401',
  spec: { name: 'x401', version: '0.2.0', pinned: 'proof/x401@7e864af', url: SPEC_URL },
  proves: 'A fact about the holder, attested by an issuer',
  about: "It asks for the Lab handle credential (dc+sd-jwt), disclosing handle as your run's handle, and trusts only the Lab test issuer. Both a signed and an unsigned OpenID4VP request are offered.",
  /** The specs the door's requests and responses come from, beyond x401 itself. */
  builds_on: [
    { name: 'OpenID4VP 1.0 (requests, DCQL, and the DC API response in Appendix A)', url: 'https://openid.net/specs/openid-4-verifiable-presentations-1_0.html' },
    { name: 'SD-JWT (disclosures, key binding JWT)', url: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/' },
    { name: 'SD-JWT VC (dc+sd-jwt)', url: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-sd-jwt-vc/' },
  ],
  ladder: LADDER.map((s) => ({ name: s.name, url: `${SPEC_URL}#${s.ref}` })),
  asks: dcql('<run handle>'),
  modes: ['openid4vp-v1-signed', 'openid4vp-v1-unsigned'],
  trusts: ISSUER_ID,
};

type Reply = { status: number; headers: Record<string, string>; body: unknown };

/** Base64url JSON, the encoding of every x401 header (spec: Header Syntax). */
const encode = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
const entry = (text: string, step?: StepName, ok?: boolean): store.Entry => ({ at: new Date().toISOString(), text, step, ok });
const tail = (s: string) => `…${s.slice(-4)}`;

/** A check that failed: the step it failed at, a stable code and a plain reason. */
class Stop extends Error {
  step: StepName;
  code: string;
  constructor(step: StepName, code: string, message: string) {
    super(message);
    this.step = step;
    this.code = code;
  }
}

function need(cond: unknown, step: StepName, code: string, message: string): asserts cond {
  if (!cond) throw new Stop(step, code, message);
}

/** Runs fn; any error it throws becomes a Stop at `step`. */
async function guard<T>(step: StepName, code: string, fn: () => T | Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    throw e instanceof Stop ? e : new Stop(step, code, (e as Error).message);
  }
}

/**
 * The door itself. `route` is the path as shown in public timelines, with the
 * run ID elided.
 */
export function serve(runId: string | null, route: string, method: string, headers: IncomingHttpHeaders) {
  const proof = headers['proof-response'];
  const proofResponse = Array.isArray(proof) ? proof.join(',') : proof;
  return proofResponse === undefined ? challenge(runId, route, method) : retry(runId, route, method, proofResponse);
}

async function challenge(runId: string | null, route: string, method: string): Promise<Reply> {
  const nonce = randomBytes(16).toString('base64url');
  const exp = Math.floor(Date.now() / 1000) + NONCE_TTL_S;
  const openid4vp = {
    response_type: 'vp_token',
    response_mode: 'dc_api',
    nonce,
    dcql_query: dcql(runId && store.handleOf(runId)),
    client_metadata: { vp_formats_supported: { 'dc+sd-jwt': { 'sd-jwt_alg_values': ALGS, 'kb-jwt_alg_values': ALGS } } },
  };
  // The signed entry: a JAR whose client_id resolves to the door's key via did:web.
  const jar = await new SignJWT({ ...openid4vp, client_id: CLIENT_ID, expected_origins: [ORIGIN] })
    .setProtectedHeader({ alg: 'ES256', typ: 'oauth-authz-req+jwt', kid: verifier.kid })
    .setAudience('https://self-issued.me/v2')
    .setIssuedAt()
    .setExpirationTime(exp)
    .sign(verifier.key);
  const payload = {
    scheme: 'x401',
    version: '0.2.0',
    credential_requirements: {
      digital: {
        requests: [
          { protocol: 'openid4vp-v1-signed', data: { request: jar } },
          { protocol: 'openid4vp-v1-unsigned', data: openid4vp },
        ],
      },
    },
    request_id: REQUEST_ID,
  };
  const attempt = store.newAttempt({
    door: 'x401',
    runId,
    nonce,
    nonceExpires: exp,
    step: 0,
    timeline: [
      entry(`→ ${method} ${route}, no proof`),
      entry(`← 401 with PROOF-REQUEST: a signed entry (client_id ${CLIENT_ID}) and an unsigned one, nonce ${tail(nonce)}, valid ${NONCE_TTL_S / 60} minutes.`, 'challenged', true),
    ],
  });
  return {
    status: 401,
    headers: { 'PROOF-REQUEST': encode(payload), 'Cache-Control': 'no-store' },
    // The header is authoritative; the body repeats it for callers that can't read headers.
    body: {
      error: 'proof_required',
      message: 'This door wants an x401 proof. Decode the PROOF-REQUEST header (base64url JSON), answer one of its requests, and retry this URL with PROOF-RESPONSE.',
      x401: payload,
      ...(!runId && { start_a_run: `POST {"handle": "<your-handle>"} to ${BASE_URL}/pg/runs, then use the x401 door URL it returns.` }),
      need_a_credential: `POST {"jwk": <your holder public JWK>, "run": <run ID>} to ${ISSUER_ID}/credential`,
      instructions: `${BASE_URL}/llms.txt`,
      attempt,
      watch: `${BASE_URL}/x401#attempt=${attempt}`,
    },
  };
}

async function retry(runId: string | null, route: string, method: string, header: string): Promise<Reply> {
  const log = [entry(`→ ${method} ${route} with PROOF-RESPONSE`), entry('PROOF-RESPONSE header present.', 'retried', true)];
  const pass = (step: StepName, text: string) => log.push(entry(text, step, true));
  let attempt: store.Attempt | undefined;
  let mode: string | null = null;
  let handle = 'anonymous';

  try {
    // artifact decoded: one base64url JSON Result Artifact holding a dc+sd-jwt presentation
    const step = 'artifact decoded';
    need(/^[A-Za-z0-9_-]+$/.test(header), step, 'invalid_artifact', 'PROOF-RESPONSE must be exactly one base64url (no padding) JSON value.');
    const artifact = await guard(step, 'invalid_artifact', () => JSON.parse(Buffer.from(header, 'base64url').toString('utf8')));
    need(artifact && typeof artifact === 'object', step, 'invalid_artifact', 'PROOF-RESPONSE must decode to a JSON object.');
    need(!('access_token' in artifact), step, 'token_not_supported', 'This door issues no Verification Tokens; send a Result Artifact.');
    const inline = 'credential_result' in artifact;
    need(inline !== ('credential_result_uri' in artifact), step, 'invalid_artifact', 'A Result Artifact carries exactly one of credential_result or credential_result_uri.');
    const result = inline ? artifact.credential_result : await dereference(artifact.credential_result_uri);
    mode = result?.protocol ?? null;
    need(INFO.modes.includes(mode as string), step, 'invalid_artifact', `credential_result.protocol must be one of ${INFO.modes.join(', ')}; got ${JSON.stringify(mode)}.`);
    const data = typeof result.data === 'string' ? await guard(step, 'invalid_artifact', () => JSON.parse(result.data)) : result.data;
    const vp = data?.vp_token?.[QUERY_ID];
    const sdjwt: unknown = Array.isArray(vp) ? vp[0] : vp;
    need(typeof sdjwt === 'string', step, 'invalid_artifact', `Expected credential_result.data.vp_token.${QUERY_ID} to hold a dc+sd-jwt presentation.`);
    const cut = sdjwt.lastIndexOf('~');
    const kbJwt = sdjwt.slice(cut + 1);
    const [issuerJwt, ...disclosures] = sdjwt.slice(0, cut).split('~');
    need(cut > 0 && kbJwt, step, 'invalid_artifact', 'The presentation has no key binding JWT: it must end with ~<KB-JWT>.');
    const kbUnverified = await guard(step, 'invalid_artifact', () => decodeJwt(kbJwt));
    pass(step, `Result Artifact: ${mode}, ${inline ? 'inline' : 'by reference'}, ${disclosures.length} disclosures and a KB-JWT.`);

    // nonce matched: issued by this door, on this run's URL, unexpired, unspent
    const found = typeof kbUnverified.nonce === 'string' ? store.attemptByNonce(kbUnverified.nonce) : undefined;
    need(found, 'nonce matched', 'nonce_unknown', 'The KB-JWT nonce is not one this door issued. Request the route again for a fresh one.');
    need(found.run_id === runId, 'nonce matched', 'nonce_other_run', "That nonce was issued on a different run's door URL.");
    need(!found.nonce_used, 'nonce matched', 'nonce_replayed', 'That nonce was already used. Each challenge works once.');
    need(found.nonce_expires! > Date.now() / 1000, 'nonce matched', 'nonce_expired', `That nonce expired; they last ${NONCE_TTL_S / 60} minutes.`);
    need(store.spendNonce(found.id), 'nonce matched', 'nonce_replayed', 'That nonce was already used. Each challenge works once.');
    attempt = found;
    pass('nonce matched', `Nonce ${tail(found.nonce!)} was issued for this attempt; it is now spent.`);

    // signature valid: issuer JWT, every disclosure digest, holder KB-JWT, sd_hash
    const sig = 'signature valid';
    const { iss } = await guard(sig, 'invalid_signature', () => decodeJwt(issuerJwt));
    const { x5c, alg } = await guard(sig, 'invalid_signature', () => decodeProtectedHeader(issuerJwt));
    const issuerKey =
      iss === ISSUER_ID
        ? issuer.publicKey
        : x5c?.[0] && ALGS.includes(alg ?? '')
          ? await guard(sig, 'invalid_signature', () => importX509(`-----BEGIN CERTIFICATE-----\n${x5c[0]}\n-----END CERTIFICATE-----`, alg!))
          : undefined;
    need(issuerKey, sig, 'issuer_key_unresolved', `No key for issuer ${iss}: the door knows the Lab test issuer, and reads an x5c header.`);
    const claims: JWTPayload & { _sd?: string[]; vct?: string; cnf?: { jwk?: JWK } } = (
      await guard(sig, 'invalid_signature', () => jwtVerify(issuerJwt, issuerKey, { algorithms: ALGS }))
    ).payload;
    // ponytail: top-level object disclosures only; add nested and array-element disclosures when a wallet sends them.
    const disclosed: Record<string, unknown> = {};
    for (const d of disclosures) {
      need(claims._sd?.includes(digest(d)), sig, 'invalid_disclosure', 'A disclosure does not match any digest the issuer signed.');
      const [, name, value] = await guard(sig, 'invalid_disclosure', () => JSON.parse(Buffer.from(d, 'base64url').toString('utf8')));
      disclosed[name] = value;
    }
    const holderJwk = claims.cnf?.jwk;
    need(holderJwk, sig, 'no_holder_key', 'The credential has no cnf.jwk, so the presentation cannot be tied to its holder.');
    const kb = (
      await guard(sig, 'invalid_signature', async () =>
        jwtVerify(kbJwt, await importJWK(holderJwk, decodeProtectedHeader(kbJwt).alg), { algorithms: ALGS, typ: 'kb+jwt', maxTokenAge: '5m' }),
      )
    ).payload;
    need(kb.sd_hash === digest(sdjwt.slice(0, cut + 1)), sig, 'sd_hash_mismatch', 'The KB-JWT sd_hash does not cover the presentation that was sent.');
    pass(sig, `Issuer signature, ${disclosures.length} disclosure digests and the holder's KB-JWT all verify.`);

    // binding valid: signed binds to the door's client_id; unsigned to the invoking origin
    if (mode === 'openid4vp-v1-signed') {
      need(kb.aud === CLIENT_ID, 'binding valid', 'binding_mismatch', `For the signed request the KB-JWT aud must be ${CLIENT_ID}; got ${JSON.stringify(kb.aud)}.`);
      pass('binding valid', `Bound to the door as relying party (${CLIENT_ID}).`);
    } else {
      need(typeof kb.aud === 'string' && kb.aud.startsWith('origin:'), 'binding valid', 'binding_mismatch', `For the unsigned request the KB-JWT aud must be origin:<invoking origin>; got ${JSON.stringify(kb.aud)}.`);
      pass('binding valid', `Bound to origin ${kb.aud.slice(7)} and the nonce. Weaker than signed: the door cannot pre-authorise that origin.`);
    }

    // query met: the DCQL query, without keeping what was disclosed
    need(claims.vct === VCT, 'query met', 'query_not_met', `The query asks for vct ${VCT}.`);
    need(typeof disclosed.handle === 'string', 'query met', 'query_not_met', 'The query asks for handle to be disclosed.');
    const runHandle = runId && store.handleOf(runId);
    need(!runHandle || disclosed.handle === runHandle, 'query met', 'query_not_met', `The query asks for this run's handle, ${runHandle}; the credential attests ${JSON.stringify(disclosed.handle)}.`);
    const extra = Object.keys(disclosed).filter((n) => n !== 'handle');
    pass('query met', `handle ${disclosed.handle} disclosed. ${extra.length ? `Also disclosed, not asked for: ${extra.join(', ')}.` : 'Nothing else disclosed.'}`);
    handle = disclosed.handle as string;

    // issuer trusted
    need(iss === ISSUER_ID, 'issuer trusted', 'untrusted_issuer', `This door trusts the Lab test issuer, ${ISSUER_ID}; this credential is from ${iss}.`);
    pass('issuer trusted', 'Issued by the Lab test issuer.');
  } catch (e) {
    if (!(e instanceof Stop)) throw e;
    const id = attempt?.id ?? store.newAttempt({ door: 'x401', runId, nonce: null, nonceExpires: null, step: 0, timeline: [] });
    const error = { scheme: 'x401', version: '0.2.0', error: e.code, error_description: e.message, error_uri: `${BASE_URL}/x401#attempt=${id}`, request_id: REQUEST_ID, stopped_at: e.step };
    store.finishAttempt(id, {
      step: LADDER.findIndex((s) => s.name === e.step) - 1,
      mode,
      error: e.code,
      reason: e.message,
      more: [...log, entry(e.message, e.step, false), entry(`← 401 with PROOF-RESULT error ${e.code}`)],
    });
    return {
      status: 401,
      headers: { 'PROOF-RESULT': encode(error), 'Cache-Control': 'no-store' },
      body: { ...error, next: 'Request the route again without PROOF-RESPONSE for a fresh challenge.' },
    };
  }

  const receipt = await new SignJWT({
    door: 'x401',
    spec: `x401 0.2.0 (${INFO.spec.pinned})`,
    resource: `${BASE_URL}/pg/doors/x401`,
    request_mode: mode,
    steps: LADDER.map((s) => s.name),
    proves: INFO.proves,
    trusted_issuer: ISSUER_ID,
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'pg-receipt+jwt', kid: verifier.kid })
    .setIssuer(DID)
    .setSubject(handle)
    .setJti(attempt.id)
    .setIssuedAt()
    .sign(verifier.key);
  store.finishAttempt(attempt.id, { step: THROUGH, mode, error: null, reason: null, more: [...log, entry('All checks passed.', 'through', true), entry('← 200 with a signed receipt in PROOF-RESULT')] });
  return {
    status: 200,
    headers: { 'PROOF-RESULT': encode({ scheme: 'x401', version: '0.2.0', result: 'accepted', receipt }), 'Cache-Control': 'no-store' },
    body: { through: true, door: 'x401', handle, receipt, verify_receipt_with: `${BASE_URL}/pg/jwks.json`, attempt: attempt.id, watch: `${BASE_URL}/x401#attempt=${attempt.id}` },
  };
}

// A Result Artifact by reference makes the door fetch a URL the caller chose,
// so private and loopback addresses are refused.
// ponytail: checks the address once and fetch resolves again, so DNS rebinding can slip past;
// pin the resolved address before deploying next to internal services.
const PRIVATE = new BlockList();
for (const [net, bits] of [['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8], ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.168.0.0', 16]] as const) PRIVATE.addSubnet(net, bits, 'ipv4');
// No ::ffff:0:0/96 rule: BlockList checks IPv4-mapped IPv6 against the IPv4 rules, and that rule would match every IPv4 address.
for (const [net, bits] of [['::1', 128], ['fc00::', 7], ['fe80::', 10]] as const) PRIVATE.addSubnet(net, bits, 'ipv6');

async function dereference(uri: unknown) {
  const step = 'artifact decoded';
  const url = await guard(step, 'invalid_reference', () => new URL(String(uri)));
  need(url.protocol === 'https:', step, 'invalid_reference', 'credential_result_uri must be an https URL.');
  const { address, family } = await guard(step, 'invalid_reference', () => lookup(url.hostname));
  need(!PRIVATE.check(address, family === 6 ? 'ipv6' : 'ipv4'), step, 'invalid_reference', 'credential_result_uri resolves to a private address.');
  const res = await guard(step, 'invalid_reference', () => fetch(url, { redirect: 'error', signal: AbortSignal.timeout(5000) }));
  need(res.ok, step, 'invalid_reference', `Fetching credential_result_uri returned ${res.status}.`);
  const text = await res.text();
  need(text.length <= 64_000, step, 'invalid_reference', 'The referenced credential result is over 64 kB.');
  return guard(step, 'invalid_reference', () => JSON.parse(text));
}
