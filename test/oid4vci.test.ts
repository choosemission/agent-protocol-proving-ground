/**
 * The OpenID4VCI issuer: the real server on a spare port, under a path as on the
 * Lab, driven over HTTP the way a wallet would.
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtempSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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
