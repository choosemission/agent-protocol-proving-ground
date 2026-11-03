/**
 * End to end: the real server on a spare port, driven by client.ts, one test
 * per place an attempt can stop. Needs openssl on PATH for the x5c issuer.
 */
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { SignJWT, createLocalJWKSet, importPKCS8, jwtVerify } from 'jose';
import { challenge, decode, encode, getCredential, newHolder, present, resultArtifact } from '../client.ts';

const tmp = mkdtempSync(join(tmpdir(), 'pg-'));
const port = 20000 + Math.floor(Math.random() * 20000);
const BASE = `http://localhost:${port}`;
Object.assign(process.env, { PORT: String(port), DATA_DIR: tmp });
const { server } = await import('../src/server.ts');
after(() => server.close());

const holder = await newHolder();
let door: string;
let credential: string;

before(async () => {
  if (!server.listening) await once(server, 'listening');
  const res = await fetch(`${BASE}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle: 'test-team' }) });
  assert.equal(res.status, 201);
  door = (await res.json()).door;
  credential = await getCredential(BASE, holder.jwk);
});

/** One full attempt; `tweak` changes what the wallet sends. */
async function attempt(tweak: { unsigned?: boolean; aud?: string; disclose?: string[]; credential?: string; header?: (h: string) => string } = {}) {
  const { signed, unsigned } = await challenge(door);
  const request = tweak.unsigned ? unsigned : signed;
  const query = request.dcql_query.credentials[0];
  const presentation = await present(tweak.credential ?? credential, holder.key, {
    nonce: request.nonce,
    aud: tweak.aud ?? (tweak.unsigned ? `origin:${BASE}` : request.client_id!),
    disclose: tweak.disclose ?? query.claims.map((c) => c.path[0]),
  });
  let header = resultArtifact(`openid4vp-v1-${tweak.unsigned ? 'unsigned' : 'signed'}`, query.id, presentation);
  if (tweak.header) header = tweak.header(header);
  return send(header);
}

async function send(header: string) {
  const res = await fetch(door, { headers: { 'PROOF-RESPONSE': header } });
  return { status: res.status, result: decode(res.headers.get('proof-result')!), body: await res.json(), header };
}

async function stopsAt(step: string, error: string, r: Awaited<ReturnType<typeof send>>) {
  assert.equal(r.status, 401);
  assert.equal(r.result.scheme, 'x401');
  assert.equal(r.result.error, error, r.result.error_description);
  assert.equal(r.result.stopped_at, step);
}

/** A credential signed by a key the door can find (x5c) but does not trust. */
function foreignIssuer() {
  execFileSync('openssl', ['req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes', '-days', '1', '-subj', '/CN=foreign.example', '-keyout', join(tmp, 'f.key'), '-out', join(tmp, 'f.crt')], { stdio: 'ignore' });
  const x5c = readFileSync(join(tmp, 'f.crt'), 'utf8').replace(/-----[^-]+-----|\s/g, '');
  return { x5c, key: importPKCS8(readFileSync(join(tmp, 'f.key'), 'utf8'), 'ES256') };
}

/** Re-signs the Lab credential's payload under another issuer. */
async function reissue(iss: string, signer: { key: CryptoKey; x5c?: string[] }) {
  const [jwt, ...disclosures] = credential.split('~').filter(Boolean);
  const claims = decode(jwt.split('.')[1]);
  const reissued = await new SignJWT({ ...claims, iss }).setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', x5c: signer.x5c }).sign(signer.key);
  return `${reissued}~${disclosures.join('~')}~`;
}

test('signed request: through, with a receipt that verifies against the door JWKS', async () => {
  const r = await attempt();
  assert.equal(r.status, 200);
  assert.equal(r.result.result, 'accepted');
  assert.equal(r.body.ledger.company, 'Quarry & Rind (fictional)');
  const jwks = createLocalJWKSet(await (await fetch(`${BASE}/pg/jwks.json`)).json());
  const { payload } = await jwtVerify(r.result.receipt, jwks, { typ: 'pg-receipt+jwt' });
  assert.equal(payload.sub, 'test-team');
  assert.equal(payload.request_mode, 'openid4vp-v1-signed');
  assert.equal(payload.jti, r.body.attempt);
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

test('withholding role stops at query met', async () => {
  await stopsAt('query met', 'query_not_met', await attempt({ disclose: ['employer'] }));
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
  await stopsAt('signature valid', 'invalid_signature', await attempt({ credential: await reissue(`${BASE}/pg/issuer`, { key: forger.key }) }));
});

test('a tampered KB-JWT stops at signature valid', async () => {
  const r = await attempt({
    header: (h) => {
      const a = decode(h);
      const vp = a.credential_result.data.vp_token.quarry_rind_staff;
      vp[0] = vp[0].slice(0, -3) + (vp[0].endsWith('AAA') ? 'BBB' : 'AAA');
      return encode(a);
    },
  });
  await stopsAt('signature valid', 'invalid_signature', r);
});

test('garbage stops at artifact decoded', async () => {
  await stopsAt('artifact decoded', 'invalid_artifact', await send('not base64!'));
  await stopsAt('artifact decoded', 'invalid_artifact', await send(encode({ hello: 'door' })));
});

test('a by-reference result over http is refused', async () => {
  await stopsAt('artifact decoded', 'invalid_reference', await send(encode({ credential_result_uri: 'http://localhost/x' })));
});

test('an unknown run is a 404', async () => {
  assert.equal((await fetch(`${BASE}/pg/x401/r/${'x'.repeat(22)}/ledger`)).status, 404);
});

test('the wall shows the run through, and timelines keep no credentials', async () => {
  const state = await (await fetch(`${BASE}/pg/state`)).json();
  const row = state.runs.find((r: { handle: string }) => r.handle === 'test-team');
  assert.equal(row.step, state.ladder.length - 1);
  assert.equal(state.first.handle, 'test-team');
  assert.ok(state.stopped.some((s: { error: string }) => s.error === 'nonce_replayed'));
  assert.ok(!JSON.stringify(state).includes(door.split('/r/')[1].split('/')[0]), 'run ID leaked onto the wall');
  const detail = await (await fetch(`${BASE}/pg/attempts/${state.recent[0].id}`)).json();
  assert.ok(detail.timeline.length > 0);
  assert.ok(!JSON.stringify(detail).includes(credential.slice(0, 40)), 'credential stored');
});
