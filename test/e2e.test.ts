/**
 * End to end: the real server on a spare port, driven by client.ts, one test
 * per place an attempt can stop. Needs openssl on PATH for the x5c issuer.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import dns from 'node:dns/promises';
import { once } from 'node:events';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, before, test } from 'node:test';
import { SignJWT, createLocalJWKSet, decodeJwt, decodeProtectedHeader, importJWK, importPKCS8, jwtVerify, type JWK } from 'jose';
import { defaultVerifier, resolveDIDFromLog } from 'didwebvh-ts';
import { challenge, decode, encode, getCredential, newHolder, present, resultArtifact } from '../client.ts';

const tmp = mkdtempSync(join(tmpdir(), 'pg-'));
const port = 20000 + Math.floor(Math.random() * 20000);
// Under a path, as on the Lab: the DID and /.well-known stay at the origin.
const ORIGIN = `http://pg.localhost:${port}`;
const BASE = `${ORIGIN}/proving-ground`;
Object.assign(process.env, { PORT: String(port), BASE_URL: BASE, DATA_DIR: tmp });
const { server } = await import('../src/server.ts');
after(() => server.close());

const holder = await newHolder();
let door: string;
let credential: string;

async function startRun(handle: string) {
  const res = await fetch(`${BASE}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle }) });
  assert.equal(res.status, 201);
  return res.json();
}

before(async () => {
  if (!server.listening) await once(server, 'listening');
  const run = await startRun('test-team');
  door = run.doors.x401;
  credential = await getCredential(BASE, holder.jwk, run.run);
});

/** One full attempt; `tweak` changes what the wallet sends. */
type Tweak = {
  unsigned?: boolean; aud?: string; nonce?: string; disclose?: string[]; credential?: string;
  /** Changes the presentation after the KB-JWT is signed. */
  presentation?: (p: string) => string;
  header?: (h: string) => string;
  /** Runs between the challenge and the retry. */
  between?: (nonce: string) => void;
  /** Where to send the retry, if not the door that challenged. */
  to?: string;
};

async function attempt(tweak: Tweak = {}) {
  const { signed, unsigned } = await challenge(door);
  const request = tweak.unsigned ? unsigned : signed;
  const query = request.dcql_query.credentials[0];
  let presentation = await present(tweak.credential ?? credential, holder.key, {
    nonce: tweak.nonce ?? request.nonce,
    aud: tweak.aud ?? (tweak.unsigned ? `origin:${BASE}` : request.client_id!),
    disclose: tweak.disclose ?? query.claims.map((c) => c.path[0]),
  });
  if (tweak.presentation) presentation = tweak.presentation(presentation);
  tweak.between?.(request.nonce);
  let header = resultArtifact(`openid4vp-v1-${tweak.unsigned ? 'unsigned' : 'signed'}`, query.id, presentation);
  if (tweak.header) header = tweak.header(header);
  return send(header, tweak.to);
}

async function send(header: string, to = door) {
  const res = await fetch(to, { headers: { 'PROOF-RESPONSE': header } });
  return { status: res.status, result: decode(res.headers.get('proof-result')!), body: await res.json(), header };
}

async function stopsAt(step: string, error: string, r: Awaited<ReturnType<typeof send>>) {
  assert.equal(r.status, 401);
  assert.equal(r.result.scheme, 'x401');
  assert.equal(r.result.error, error, r.result.error_description);
  assert.equal(r.result.stopped_at, step);
}

/** A credential signed by a key the door can find (x5c) but does not trust. */
/** The Lab credential's issuer and its key ID. */
const labIssuer = () => ({ iss: decodeJwt(credential).iss as string, kid: decodeProtectedHeader(credential).kid as string });

function foreignIssuer() {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=foreign.example', '-keyout', join(tmp, 'f.key'), '-out', join(tmp, 'f.crt')], { stdio: 'ignore' });
  const x5c = readFileSync(join(tmp, 'f.crt'), 'utf8').replace(/-----[^-]+-----|\s/g, '');
  return { x5c, key: importPKCS8(readFileSync(join(tmp, 'f.key'), 'utf8'), 'ES256') };
}

/** Re-signs the Lab credential's payload under another issuer. */
async function reissue(iss: string, signer: { key: CryptoKey; x5c?: string[]; kid?: string }, edit = (c: Record<string, unknown>) => c) {
  const [jwt, ...disclosures] = credential.split('~').filter(Boolean);
  const claims = edit(decode(jwt.split('.')[1]));
  const reissued = await new SignJWT({ ...claims, iss }).setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: signer.x5c, kid: signer.kid }).sign(signer.key);
  return `${reissued}~${disclosures.join('~')}~`;
}

test('signed request: through, with a receipt that verifies against the door JWKS', async () => {
  const r = await attempt();
  assert.equal(r.status, 200);
  assert.equal(r.result.result, 'accepted');
  assert.equal(r.body.handle, 'test-team');
  const jwks = createLocalJWKSet(await (await fetch(`${BASE}/pg/jwks.json`)).json());
  const { payload } = await jwtVerify(r.result.receipt, jwks, { typ: 'pg-receipt+jwt' });
  assert.equal(payload.sub, 'test-team');
  assert.equal(payload.request_mode, 'openid4vp-v1-signed');
  assert.equal(payload.jti, r.body.attempt);
});

test('the door\'s client_id is a did:webvh whose served log verifies and names the JAR key', async () => {
  const { signed } = await challenge(door); // resolves did.jsonl with didwebvh-ts and checks the JAR
  const did = signed.client_id!.replace(/^decentralized_identifier:/, '');
  assert.match(did, new RegExp(`^did:webvh:[^:]+:pg\\.localhost%3A${port}$`));
  const res = await fetch(`${ORIGIN}/.well-known/did.jsonl`);
  assert.match(res.headers.get('content-type')!, /^text\/jsonl/);
  const genesis = JSON.parse((await res.text()).split('\n')[0]);
  assert.equal(genesis.parameters.portable, true);
  const web = await (await fetch(`${ORIGIN}/.well-known/did.json`)).json();
  assert.equal(web.id, `did:web:pg.localhost%3A${port}`);
  assert.ok(web.alsoKnownAs.includes(did));
});

test('the handle credential is issued by the Lab did:webvh and verifies against its #issuer key', async () => {
  const { signed } = await challenge(door);
  const did = signed.client_id!.replace(/^decentralized_identifier:/, '');
  const { iss, kid } = labIssuer();
  assert.equal(iss, did); // one DID, verifier and issuer
  assert.equal(kid, `${did}#issuer`);
  const log = (await (await fetch(`${ORIGIN}/.well-known/did.jsonl`)).text()).trim().split('\n').map((l) => JSON.parse(l));
  const { didDocument } = await resolveDIDFromLog(log, { verifier: defaultVerifier });
  assert.ok(didDocument!.assertionMethod!.includes(kid));
  const vm = didDocument!.verificationMethod!.find((v) => v.id === kid)!;
  await jwtVerify(credential.split('~')[0], await importJWK(vm.publicKeyJwk as JWK, 'ES256'), { typ: 'dc+sd-jwt' });
});

test('unsigned request: through, bound to the origin', async () => {
  const r = await attempt({ unsigned: true });
  assert.equal(r.status, 200, JSON.stringify(r.result));
});

test('replaying a presentation stops at nonce matched', async () => {
  const first = await attempt();
  assert.equal(first.status, 200);
  await stopsAt('nonce matched', 'nonce_replayed', await send(first.header));
});

test('wrong audience stops at binding valid', async () => {
  await stopsAt('binding valid', 'binding_mismatch', await attempt({ aud: 'decentralized_identifier:did:web:evil.example' }));
});

test('withholding the handle stops at query met', async () => {
  await stopsAt('query met', 'query_not_met', await attempt({ disclose: [] }));
});

test("another run's handle credential stops at query met", async () => {
  const other = await startRun('other-team');
  await stopsAt('query met', 'query_not_met', await attempt({ credential: await getCredential(BASE, holder.jwk, other.run) }));
});

test('the issuer refuses without a known run', async () => {
  const res = await fetch(`${BASE}/pg/issuer/credential`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ jwk: holder.jwk, run: 'nope' }) });
  assert.equal(res.status, 400);
});

test('a foreign issuer with x5c stops at issuer trusted', async () => {
  const f = foreignIssuer();
  const foreign = await reissue('https://foreign.example', { key: (await f.key) as CryptoKey, x5c: [f.x5c] });
  await stopsAt('issuer trusted', 'untrusted_issuer', await attempt({ credential: foreign }));
});

test('an issuer with no findable key stops at signature valid', async () => {
  const stray = await newHolder();
  await stopsAt('signature valid', 'issuer_key_unresolved', await attempt({ credential: await reissue('https://stray.example', { key: stray.key }) }));
});

test('a credential claiming the Lab issuer but signed by another key stops at signature valid', async () => {
  const forger = await newHolder();
  await stopsAt('signature valid', 'invalid_signature', await attempt({ credential: await reissue(labIssuer().iss, { key: forger.key, kid: labIssuer().kid }) }));
});

test('a tampered KB-JWT stops at signature valid', async () => {
  const r = await attempt({
    header: (h) => {
      const a = decode(h);
      const vp = a.credential_result.data.vp_token.lab_handle;
      vp[0] = vp[0].slice(0, -3) + (vp[0].endsWith('AAA') ? 'BBB' : 'AAA');
      return encode(a);
    },
  });
  await stopsAt('signature valid', 'invalid_signature', r);
});

test('a nonce the door never issued stops at nonce matched', async () => {
  await stopsAt('nonce matched', 'nonce_unknown', await attempt({ nonce: 'made-up-nonce' }));
});

test("a nonce from another run's door stops at nonce matched", async () => {
  const other = await startRun('nonce-thief');
  await stopsAt('nonce matched', 'nonce_other_run', await attempt({ to: other.doors.x401 }));
});

test('an expired nonce stops at nonce matched', async () => {
  const db = new DatabaseSync(join(tmp, 'proving-ground.db'));
  const r = await attempt({ between: (nonce) => db.prepare('update attempts set nonce_expires = 0 where nonce = ?').run(nonce) });
  db.close();
  await stopsAt('nonce matched', 'nonce_expired', r);
});

test('a disclosure the issuer never signed stops at signature valid', async () => {
  const forged = Buffer.from(JSON.stringify(['salt', 'handle', 'someone-else'])).toString('base64url');
  await stopsAt('signature valid', 'invalid_disclosure', await attempt({ credential: `${credential}${forged}~` }));
});

test('a credential without cnf stops at signature valid', async () => {
  const f = foreignIssuer();
  const noCnf = await reissue('https://foreign.example', { key: (await f.key) as CryptoKey, x5c: [f.x5c] }, ({ cnf, ...c }) => c);
  await stopsAt('signature valid', 'no_holder_key', await attempt({ credential: noCnf }));
});

test('dropping a disclosure after signing the KB-JWT stops at signature valid', async () => {
  const dropDisclosure = (p: string) => { const parts = p.split('~'); return `${parts[0]}~${parts.at(-1)}`; };
  await stopsAt('signature valid', 'sd_hash_mismatch', await attempt({ presentation: dropDisclosure }));
});

test('a Verification Token instead of a Result Artifact stops at artifact decoded', async () => {
  await stopsAt('artifact decoded', 'token_not_supported', await send(encode({ access_token: 'x' })));
});

test('a by-reference result at a private address is refused', async () => {
  const r = await send(encode({ credential_result_uri: 'https://localhost/x' }));
  await stopsAt('artifact decoded', 'invalid_reference', r);
  assert.match(r.result.error_description, /private address/);
});

/**
 * Fakes the door's DNS lookup (to `address`) and its fetch of URI (serving `body()`); everything else is real.
 * Plain assignment, not t.mock.method: syncBuiltinESMExports only carries plain properties to the door's named import.
 */
const URI = 'https://results.example/r';
function fakeReference(t: { after: (fn: () => void) => void }, address: string, family: 4 | 6, body: () => unknown) {
  const { lookup } = dns;
  const realFetch = globalThis.fetch;
  dns.lookup = (async () => ({ address, family })) as unknown as typeof dns.lookup;
  globalThis.fetch = (url, init) => (String(url) === URI ? Promise.resolve(Response.json(body())) : realFetch(url, init));
  syncBuiltinESMExports();
  t.after(() => {
    dns.lookup = lookup;
    globalThis.fetch = realFetch;
    syncBuiltinESMExports();
  });
}

test('a by-reference result resolving to an IPv4-mapped loopback address is refused', async (t) => {
  fakeReference(t, '::ffff:127.0.0.1', 6, () => ({}));
  const r = await send(encode({ credential_result_uri: URI }));
  await stopsAt('artifact decoded', 'invalid_reference', r);
  assert.match(r.result.error_description, /private address/);
});

test('a by-reference result over https is fetched and gets through', async (t) => {
  let served: unknown;
  fakeReference(t, '203.0.113.7', 4, () => served);
  const r = await attempt({
    header: (h) => {
      const a = decode(h);
      served = a.credential_result;
      return encode({ request_id: a.request_id, credential_result_uri: URI });
    },
  });
  assert.equal(r.status, 200, JSON.stringify(r.result));
  assert.equal(r.result.result, 'accepted');
});

test('garbage stops at artifact decoded', async () => {
  await stopsAt('artifact decoded', 'invalid_artifact', await send('not base64!'));
  await stopsAt('artifact decoded', 'invalid_artifact', await send(encode({ hello: 'door' })));
});

test('a by-reference result over http is refused', async () => {
  await stopsAt('artifact decoded', 'invalid_reference', await send(encode({ credential_result_uri: 'http://localhost/x' })));
});

test('the homepage, the x401 page and the stylesheet are served; unknown pages are not', async () => {
  for (const p of ['/', '/x401', '/style.css']) assert.equal((await fetch(`${BASE}${p}`)).status, 200, p);
  assert.equal((await fetch(`${BASE}/nope`)).status, 404);
  const css = await fetch(`${BASE}/style.css`);
  assert.match(css.headers.get('content-type')!, /^text\/css/);
  assert.ok((await css.text()).startsWith('/*'), 'the stylesheet is sent as CSS, not as a JSON string');
  assert.equal((await fetch(`${ORIGIN}/x401`)).status, 404, 'outside the prefix');
  assert.equal((await fetch(`${BASE}/.well-known/did.jsonl`)).status, 404, 'the DID is at the origin only');
  const csp = (await fetch(`${BASE}/x401`)).headers.get('content-security-policy')!;
  assert.match(csp, /script-src 'sha256-/);
  assert.doesNotMatch(csp, /script-src[^;]*unsafe-inline/);
});

test('a caller-chosen fetch refuses a private address at connect time', async () => {
  const { fetchPublicStrict } = await import('../src/lab.ts');
  await assert.rejects(fetchPublicStrict(new URL(`${BASE}/`)), (e: Error) => /private address/.test(String((e.cause as Error)?.message)));
});

test('an agent can find its way in without running JavaScript', async () => {
  const home = await (await fetch(`${BASE}/`)).text();
  assert.match(home, /\/pg\/doors\/x401/);
  assert.ok(home.includes(`href="/proving-ground/llms.txt"`) && home.includes(`href="/proving-ground/x401"`), 'links carry the prefix');
  const llms = await (await fetch(`${BASE}/llms.txt`)).text();
  for (const s of ['/pg/runs', '/pg/issuer/credential', '/pg/doors/x401/r/<run ID>', 'proof/x401@7e864af']) assert.ok(llms.includes(s), s);
  const anon = await (await fetch(`${BASE}/pg/doors/x401`)).json();
  assert.match(anon.start_a_run, /\/pg\/runs/);
  assert.equal(anon.instructions, `${BASE}/llms.txt`);
});

test('an unknown run is a 404', async () => {
  assert.equal((await fetch(`${BASE}/pg/doors/x401/r/${'x'.repeat(22)}`)).status, 404);
});

test('the wall shows the run through, and timelines keep no credentials', async () => {
  const state = (await (await fetch(`${BASE}/pg/state`)).json()).doors.find((d: { door: string }) => d.door === 'x401');
  const row = state.runs.find((r: { handle: string }) => r.handle === 'test-team');
  assert.equal(row.step, state.ladder.length - 1);
  assert.equal(state.first.handle, 'test-team');
  assert.ok(state.stopped.some((s: { error: string }) => s.error === 'nonce_replayed'));
  assert.ok(!JSON.stringify(state).includes(door.split('/r/')[1]), 'run ID leaked onto the wall');
  const detail = await (await fetch(`${BASE}/pg/attempts/${state.recent[0].id}`)).json();
  assert.ok(detail.timeline.length > 0);
  assert.ok(!JSON.stringify(detail).includes(credential.slice(0, 40)), 'credential stored');
});
