/**
 * The OpenID4VCI issuer: the real server on a spare port, under a path as on the
 * Lab, driven over HTTP the way a wallet would.
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { after, before, test } from 'node:test';

const tmp = mkdtempSync(join(tmpdir(), 'pg-vci-'));
const port = 20000 + Math.floor(Math.random() * 20000);
const ORIGIN = `http://pg.localhost:${port}`;
const BASE = `${ORIGIN}/proving-ground`;
const ISSUER = `${BASE}/pg/issuer`;
Object.assign(process.env, { PORT: String(port), BASE_URL: BASE, DATA_DIR: tmp });
const { server } = await import('../src/server.ts');
after(() => server.close());
before(async () => { if (!server.listening) await once(server, 'listening'); });
const db = () => new DatabaseSync(join(tmp, 'proving-ground.db'));
const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';

let handles = 0;
async function startRun() {
  const res = await fetch(`${BASE}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle: `vci-${++handles}` }) });
  assert.equal(res.status, 201);
  return res.json();
}
const codeOf = (o: { credential_offer: { grants: Record<string, { 'pre-authorized_code': string }> } }) => o.credential_offer.grants[PRE_AUTH]['pre-authorized_code'];

const getJson = async (url: string) => {
  const res = await fetch(url);
  assert.equal(res.status, 200, url);
  assert.match(res.headers.get('content-type') ?? '', /application\/json/);
  return res.json();
};

test('issuer and AS metadata sit at the origin, well-known part before the path', async () => {
  const md = await getJson(`${ORIGIN}/.well-known/openid-credential-issuer/proving-ground/pg/issuer`);
  assert.equal(md.credential_issuer, ISSUER);
  assert.equal(md.credential_endpoint, `${md.credential_issuer}/credential`);
  assert.equal(md.nonce_endpoint, `${ISSUER}/nonce`);
  assert.equal(md.credential_configurations_supported.lab_handle.format, 'dc+sd-jwt');
  const as = await getJson(`${ORIGIN}/.well-known/oauth-authorization-server/proving-ground/pg/issuer`);
  assert.equal(as.issuer, ISSUER);
  assert.equal(as.token_endpoint, `${ISSUER}/token`);
  assert.equal(as['pre-authorized_grant_anonymous_access_supported'], true);
});

test('a run carries a credential offer, and /offer mints another', async () => {
  const run = await startRun();
  assert.deepEqual(Object.keys(run.credential_offer), ['credential_issuer', 'credential_configuration_ids', 'grants']);
  assert.equal(run.credential_offer.credential_issuer, ISSUER);
  assert.deepEqual(run.credential_offer.credential_configuration_ids, ['lab_handle']);
  const code = codeOf(run);
  assert.ok(code.length >= 43, code);
  const scheme = new URL(run.credential_offer_uri_scheme);
  assert.equal(scheme.protocol, 'openid-credential-offer:');
  assert.deepEqual(JSON.parse(scheme.searchParams.get('credential_offer')!), run.credential_offer);

  const again = await getJson(`${BASE}/pg/runs/${run.run}/offer`);
  assert.notEqual(codeOf(again), code);
  const rows = db().prepare("select used, expires - unixepoch() ttl from vci where kind = 'code' and value in (?, ?)").all(code, codeOf(again)) as { used: number; ttl: number }[];
  assert.equal(rows.length, 2);
  for (const r of rows) { assert.equal(r.used, 0); assert.ok(r.ttl > 590 && r.ttl <= 600, String(r.ttl)); }
  assert.equal((await fetch(`${BASE}/pg/runs/${'x'.repeat(22)}/offer`)).status, 404);
});

const form = (o: Record<string, string>) => ({ method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams(o).toString() });
const redeem = (code: string) => fetch(`${ISSUER}/token`, form({ grant_type: PRE_AUTH, 'pre-authorized_code': code }));

test('token: a code buys one access token, once', async () => {
  const run = await startRun();
  const second = codeOf(await getJson(`${BASE}/pg/runs/${run.run}/offer`));
  for (const code of [codeOf(run), second]) {
    const res = await redeem(code);
    assert.equal(res.status, 200);
    assert.equal(res.headers.get('cache-control'), 'no-store');
    const t = await res.json();
    assert.equal(t.token_type, 'Bearer');
    assert.equal(t.expires_in, 300);
    assert.ok(t.access_token.length >= 43);
    const again = await redeem(code);
    assert.equal(again.status, 400);
    assert.equal((await again.json()).error, 'invalid_grant');
  }
});

test('token: expired, unknown and wrong-grant requests are refused', async () => {
  const run = await startRun();
  db().prepare('update vci set expires = 0 where value = ?').run(codeOf(run));
  assert.equal((await (await redeem(codeOf(run))).json()).error, 'invalid_grant');
  assert.equal((await (await redeem('nope')).json()).error, 'invalid_grant');
  const res = await fetch(`${ISSUER}/token`, form({ grant_type: 'authorization_code', code: 'x' }));
  assert.equal(res.status, 400);
  assert.equal((await res.json()).error, 'unsupported_grant_type');
});
