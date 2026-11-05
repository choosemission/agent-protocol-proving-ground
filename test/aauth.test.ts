/**
 * End to end for the aauth door: the real server, driven by aauth-client.ts (which signs with
 * @hellocoop/httpsig, so the door's verifier is checked against another implementation), one test
 * per stop code. Requests the client can't make, such as a stale `created` or the wrong scheme, are
 * signed here by `forge`, a second small signer. Stand-in servers on other ports host agent
 * providers, and a person server of the test's own (a PS that isn't the Lab's); `person` plays the
 * person on the Lab test PS's interaction page.
 */
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, sign as cryptoSign } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { SignJWT, createLocalJWKSet, decodeJwt, exportJWK, generateKeyPair, jwtVerify, type JWK } from 'jose';
import { authToken, call, checkResourceToken, newAgent, personToken, psFor, requirement, serveProvider, walk, type Agent, type Interact, type Ps, type Reply } from '../aauth-client.ts';

// ---- The proving ground ----

const port = 20000 + Math.floor(Math.random() * 20000);
const ORIGIN = `http://pg.localhost:${port}`;
const BASE = `${ORIGIN}/proving-ground`;
const DOOR = `${BASE}/pg/doors/aauth`;
Object.assign(process.env, { PORT: String(port), BASE_URL: BASE, DATA_DIR: mkdtempSync(join(tmpdir(), 'pg-aauth-')) });
const { server } = await import('../src/server.ts');

// ---- Stand-ins: agent providers, and a person server that isn't the Lab's ----

const providers: Awaited<ReturnType<typeof serveProvider>>[] = [];
/** A stand-in server for a person server or access server of the test's own: its metadata at `dwk`, its JWKS, and a key that signs its tokens. */
async function otherServer(dwk: string, o: { issuer?: (id: string) => string } = {}) {
  const { privateKey, publicKey } = await generateKeyPair('Ed25519');
  const jwk: JWK = { ...(await exportJWK(publicKey)), kid: 'other-1', alg: 'Ed25519' };
  let id = '';
  const s = createServer((req, res) => {
    const p = new URL(req.url!, 'http://x').pathname;
    const body = p === `/.well-known/${dwk}` ? { issuer: o.issuer?.(id) ?? id, jwks_uri: `${id}/jwks.json` } : p === '/jwks.json' ? { keys: [jwk] } : null;
    if (!body) return res.writeHead(404).end();
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  });
  s.listen(0);
  await once(s, 'listening');
  id = `http://localhost:${(s.address() as { port: number }).port}`;
  others.push(s);
  /** Signs a token as this server: typ and claims as given. */
  const mint = (typ: string, claims: Record<string, unknown>) =>
    new SignJWT({ iss: id, dwk, jti: crypto.randomUUID(), iat: now(), exp: now() + 600, ...claims }).setProtectedHeader({ alg: 'Ed25519', typ, kid: 'other-1' }).sign(privateKey);
  return { id, mint };
}
const others: ReturnType<typeof createServer>[] = [];
after(() => { server.close(); for (const p of providers) p.server.close(); for (const s of others) s.close(); });

const now = () => Math.floor(Date.now() / 1000);
let n = 0;
/** A new agent with its own provider on a stand-in, and a run; `ps` defaults to the Lab test PS. */
async function team(o: { ps?: string; documents?: (d: Agent['documents']) => void } = {}) {
  const host = await serveProvider();
  providers.push(host);
  const agent = await newAgent(host.local, { ps: o.ps ?? ORIGIN });
  o.documents?.(agent.documents);
  host.serve(agent);
  const handle = `team-${++n}-${Math.random().toString(36).slice(2, 6)}`;
  const res = await fetch(`${BASE}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle }) });
  assert.equal(res.status, 201);
  const run = await res.json();
  return { agent, handle, door: run.doors.aauth as string };
}

/** The person on the Lab test PS's interaction page: opens it with the code and decides. */
const person = (decision = 'allow', account = 'test-user'): Interact => async (url, code) => {
  const page = await fetch(`${url}?code=${encodeURIComponent(code)}`);
  const html = await page.text();
  const pending = /name="pending" value="([^"]+)"/.exec(html)?.[1];
  if (!pending) throw new Error(`no decision page (${page.status}): ${html}`);
  const done = await fetch(url, { method: 'POST', body: new URLSearchParams({ pending, decision, account }) });
  assert.equal(done.status, 200, await done.clone().text());
};

let ps: Ps;
before(async () => {
  if (!server.listening) await once(server, 'listening');
  ps = await psFor(ORIGIN);
});

/** A person token and a resource token for it, from the Lab test PS. */
async function personAndChallenge(t: Awaited<ReturnType<typeof team>>) {
  const pt = await personToken(t.agent, ps, ORIGIN, person());
  const r = await call(t.agent, t.door, pt);
  assert.equal(r.status, 401);
  return { pt, rt: requirement(r.headers)!['resource-token'] };
}

function stopped(r: Reply, status: number, pgStop: string, step: string, sigError?: string) {
  assert.equal(r.body.pg_stop, pgStop, JSON.stringify(r.body));
  assert.equal(r.status, status);
  assert.equal(r.body.stopped_at, step);
  if (sigError) {
    assert.equal(r.headers.get('signature-error')?.split(',')[0], `error=${sigError}`);
    assert.equal(r.body.type, `urn:ietf:params:sig-error:${sigError}`);
  }
}

/**
 * A signed request made by hand, to break what the library won't: `components`, `created`, the
 * scheme, the key, and the bytes sent after signing.
 */
async function forge(a: Agent, url: string, jwt: string, o: { method?: string; body?: string; components?: string[]; created?: number; scheme?: string; key?: JWK; sendBody?: string; headers?: Record<string, string> } = {}): Promise<Reply> {
  const u = new URL(url);
  const method = o.method ?? (o.body === undefined ? 'GET' : 'POST');
  const headers: Record<string, string> = { ...o.headers };
  if (o.body !== undefined) {
    headers['content-type'] = 'application/json';
    headers['content-digest'] = `sha-256=:${createHash('sha256').update(o.body).digest('base64')}:`;
  }
  headers['signature-key'] = o.scheme ?? `sig=jwt;jwt="${jwt}"`;
  const components = o.components ?? ['@method', '@authority', '@path', 'signature-key', ...(o.body !== undefined ? ['content-type', 'content-digest'] : [])];
  const params = `(${components.map((c) => `"${c}"`).join(' ')});created=${o.created ?? now()}`;
  const value = (c: string) => (c === '@method' ? method : c === '@authority' ? u.host : c === '@path' ? u.pathname : headers[c]);
  const base = [...components.map((c) => `"${c}": ${value(c)}`), `"@signature-params": ${params}`].join('\n');
  const signature = cryptoSign(null, Buffer.from(base), createPrivateKey({ key: (o.key ?? a.signingKey) as never, format: 'jwk' })).toString('base64');
  const res = await fetch(url, { method, headers: { ...headers, 'signature-input': `sig=${params}`, signature: `sig=:${signature}:` }, body: o.sendBody ?? o.body });
  return { status: res.status, headers: res.headers, body: await res.json() };
}

const state = async () => (await (await fetch(`${BASE}/pg/state`)).json()).doors.find((d: { door: string }) => d.door === 'aauth');
const attempt = async (id: unknown) => (await fetch(`${BASE}/pg/attempts/${id}`)).json();

// ---- Discovery ----

test('discovery: resource and PS metadata at the origin, the Link relation, and the door on the homepage', async () => {
  const meta = await (await fetch(`${ORIGIN}/.well-known/aauth-resource.json`)).json();
  assert.equal(meta.issuer, ORIGIN);
  assert.equal(meta.access_mode, 'auth-token');
  assert.equal(meta.authorization_endpoint, `${DOOR}/authorize`);
  assert.deepEqual(Object.keys(meta.scope_descriptions), ['receipt']);
  assert.equal(ps.issuer, ORIGIN);
  assert.equal(ps.person_token_endpoint, `${DOOR}/ps/person`);
  const r = await fetch(DOOR);
  assert.equal(r.status, 401);
  assert.equal(r.headers.get('aauth-requirement'), 'requirement=agent-token');
  assert.equal(r.headers.get('link'), `<${ORIGIN}/.well-known/aauth-resource.json>; rel="aauth-resource"`);
  const llms = await (await fetch(`${BASE}/llms.txt`)).text();
  assert.match(llms, /### aauth/);
  assert.match(llms, /@aauth\/agent/);
  assert.match(await (await fetch(`${BASE}/`)).text(), /The aauth door/);
});

// ---- Through ----

test('through with the Lab test PS: person token, resource token, auth token, receipt', async () => {
  const t = await team();
  const s = await walk(t.agent, t.door, person());
  assert.equal(s.first.status, 401);
  assert.equal(requirement(s.first.headers)?.requirement, 'person-token');
  assert.equal(requirement(s.second!.headers)?.requirement, 'auth-token');
  assert.equal(s.third!.status, 200, JSON.stringify(s.third!.body));
  const jwks = createLocalJWKSet(await (await fetch(`${BASE}/pg/jwks.json`)).json());
  const { payload, protectedHeader } = await jwtVerify(s.third!.body.receipt as string, jwks, { typ: 'pg-receipt+jwt' });
  assert.equal(payload.sub, t.handle);
  assert.equal(payload.ps, ORIGIN);
  assert.equal(payload.agent_provider, t.agent.provider);
  assert.match(String(protectedHeader.kid), /#verifier$/);
  // The PS's own checks (6.7.3, 9.4.4) hold for what the door and the Lab PS issued.
  const a = await attempt(s.third!.body.attempt);
  assert.equal(a.step, 5);
  assert.equal(a.handle, t.handle);
  assert.ok(a.timeline.some((e: { text: string }) => e.text.startsWith('At the Lab test PS: the person allowed it')));
  assert.ok(!JSON.stringify(a).includes('eyJ'), 'no token is stored');
  const w = await state();
  assert.equal(w.first.handle !== undefined, true);
  assert.ok(w.runs.some((r: { handle: string; step: number }) => r.handle === t.handle && r.step === 5));
});

test('through with a person server of your own: the door accepts any PS', async () => {
  const other = await otherServer('aauth-person.json');
  const t = await team({ ps: other.id });
  const first = await call(t.agent, t.door, await t.agent.agentToken());
  assert.match(String(first.body.detail), new RegExp(`names your PS, ${other.id}`));
  const cnf = { jwk: t.agent.publicJwk };
  const pt = await other.mint('aa-person+jwt', { aud: ORIGIN, sub: 'person-1', cnf });
  const second = await call(t.agent, t.door, pt);
  const rt = requirement(second.headers)!['resource-token'];
  const rtClaims = await checkResourceToken(t.agent, rt, ORIGIN, other.id, pt);
  assert.equal(rtClaims.aud, other.id);
  const auth = await other.mint('aa-auth+jwt', { aud: ORIGIN, ps: other.id, sub: 'person-1', scope: 'receipt', cnf });
  const third = await call(t.agent, t.door, auth);
  assert.equal(third.status, 200, JSON.stringify(third.body));
  assert.equal(decodeJwt(third.body.receipt as string).ps, other.id);
});

test('the authorization endpoint: a person token gets a resource token for the scope asked', async () => {
  const t = await team();
  const pt = await personToken(t.agent, ps, ORIGIN, person());
  const r = await call(t.agent, `${DOOR}/authorize`, pt, { body: { scope: 'receipt' } });
  assert.equal(r.status, 200, JSON.stringify(r.body));
  const rt = r.body.resource_token as string;
  assert.equal(decodeJwt(rt).scope, 'receipt');
  const auth = await authToken(t.agent, ps, rt, pt, person());
  const done = await call(t.agent, t.door, auth);
  assert.equal(done.status, 200, JSON.stringify(done.body));
  // An agent token there is asked for a person token (6.6); GET is not the endpoint.
  const asAgent = await call(t.agent, `${DOOR}/authorize`, await t.agent.agentToken(), { body: { scope: 'receipt' } });
  assert.equal(requirement(asAgent.headers)?.requirement, 'person-token');
  assert.equal((await fetch(`${DOOR}/authorize`)).status, 405);
});

test('a returning agent gets its person token without asking the person again', async () => {
  const t = await team();
  await personToken(t.agent, ps, ORIGIN, person());
  const again = await call(t.agent, ps.person_token_endpoint, await t.agent.agentToken(), { body: { resource: ORIGIN, capabilities: ['interaction'] } });
  assert.equal(again.status, 200);
});

// ---- The Lab test PS ----

test('Lab PS: without the interaction capability it has no way to reach the person (user_unreachable)', async () => {
  const t = await team();
  const r = await call(t.agent, ps.person_token_endpoint, await t.agent.agentToken(), { body: { resource: ORIGIN } });
  assert.equal(r.status, 403);
  assert.equal(r.body.error, 'user_unreachable');
});

test('Lab PS: only the proving ground, signed with content-digest and content-type, by the agent that asked', async () => {
  const t = await team();
  const elsewhere = await call(t.agent, ps.person_token_endpoint, await t.agent.agentToken(), { body: { resource: 'https://elsewhere.example', capabilities: ['interaction'] } });
  assert.equal(elsewhere.status, 400);
  assert.equal(elsewhere.body.error, 'invalid_request');
  const undigested = await forge(t.agent, ps.person_token_endpoint, await t.agent.agentToken(), { body: JSON.stringify({ resource: ORIGIN }), components: ['@method', '@authority', '@path', 'signature-key'] });
  assert.equal(undigested.status, 401);
  assert.match(undigested.headers.get('signature-error')!, /^error=invalid_input, required_input=\(.*"content-digest" "content-type"\)$/);
  // The pending URL answers only the agent and key that made the request (13.2), then 410 after its result.
  const first = await call(t.agent, ps.person_token_endpoint, await t.agent.agentToken(), { body: { resource: ORIGIN, capabilities: ['interaction'] } });
  assert.equal(first.status, 202);
  const location = first.headers.get('location')!;
  const stranger = (await team()).agent;
  assert.equal((await call(stranger, location, await stranger.agentToken())).status, 404);
  const req = requirement(first.headers)!;
  await person()(req.url, req.code);
  assert.equal((await call(t.agent, location, await t.agent.agentToken())).status, 200);
  assert.equal((await call(t.agent, location, await t.agent.agentToken())).status, 410);
  // The code was single use.
  assert.equal((await fetch(`${req.url}?code=${req.code}`)).status, 410);
});

test('Lab PS: the person declines (denied)', async () => {
  const t = await team();
  await assert.rejects(personToken(t.agent, ps, ORIGIN, person('deny')), /403.*denied/);
});

test('Lab PS: a presented token other than the one the resource token names (invalid_resource_token)', async () => {
  const t = await team();
  const { rt } = await personAndChallenge(t);
  const otherPt = await personToken(t.agent, ps, ORIGIN, person());
  await assert.rejects(authToken(t.agent, ps, rt, otherPt, person()), /invalid_resource_token.*presented_jti/);
});

// ---- signed request ----

test('no_signature: an unsigned request is asked for an agent token, and told where to start', async () => {
  const r = await fetch(DOOR);
  const body = await r.json();
  assert.equal(body.pg_stop, 'no_signature');
  assert.equal(body.stopped_at, 'signed request');
  assert.equal(body.resource_metadata, `${ORIGIN}/.well-known/aauth-resource.json`);
  assert.ok(body.libraries.length > 0);
});

test('signature_headers: Signature-Key but no Signature', async () => {
  const r = await fetch(DOOR, { headers: { 'signature-key': 'sig=jwt;jwt="x"', 'signature-input': 'sig=("@method");created=1' } });
  stopped({ status: r.status, headers: r.headers, body: await r.json() }, 401, 'signature_headers', 'signed request', 'invalid_signature');
});

test('signature_components: @authority not covered, and the server says what it requires', async () => {
  const t = await team();
  const r = await forge(t.agent, t.door, await t.agent.agentToken(), { components: ['@method', '@path', 'signature-key'] });
  stopped(r, 401, 'signature_components', 'signed request', 'invalid_input');
  assert.equal(r.headers.get('signature-error'), 'error=invalid_input, required_input=("@method" "@authority" "@path" "signature-key")');
});

test('signature_stale: created two minutes ago', async () => {
  const t = await team();
  stopped(await forge(t.agent, t.door, await t.agent.agentToken(), { created: now() - 120 }), 401, 'signature_stale', 'signed request', 'invalid_signature');
});

test('signature_clock_skew: created two minutes ahead', async () => {
  const t = await team();
  stopped(await forge(t.agent, t.door, await t.agent.agentToken(), { created: now() + 120 }), 401, 'signature_clock_skew', 'signed request', 'clock_skew');
});

test('signature_scheme: hwk is not for AAuth agents', async () => {
  const t = await team();
  const j = t.agent.publicJwk;
  const r = await forge(t.agent, t.door, '', { scheme: `sig=hwk;kty="OKP";crv="Ed25519";x="${j.x}";alg="Ed25519"` });
  stopped(r, 401, 'signature_scheme', 'signed request', 'unsupported_scheme');
  assert.equal(r.headers.get('accept-signature-scheme'), 'jwt');
});

// ---- agent identified ----

test('token_unreadable: a resource token presented back to the resource', async () => {
  const t = await team();
  const { rt } = await personAndChallenge(t);
  stopped(await call(t.agent, t.door, rt), 401, 'token_unreadable', 'agent identified', 'invalid_jwt');
});

test("agent_token_invalid: the agent identifier's domain isn't its provider's", async () => {
  const t = await team();
  stopped(await call(t.agent, t.door, await t.agent.agentToken({ claims: { sub: 'aauth:me@elsewhere.example' } })), 401, 'agent_token_invalid', 'agent identified', 'invalid_jwt');
});

test('agent_token_expired', async () => {
  const t = await team();
  stopped(await call(t.agent, t.door, await t.agent.agentToken({ claims: { iat: now() - 7200, exp: now() - 3600 } })), 401, 'agent_token_expired', 'agent identified', 'expired_jwt');
});

test("agent_issuer_mismatch: the provider's metadata names another issuer", async () => {
  const t = await team({ documents: (d) => void (d['aauth-agent.json'].issuer = 'https://other.example') });
  stopped(await call(t.agent, t.door, await t.agent.agentToken()), 401, 'agent_issuer_mismatch', 'agent identified', 'issuer_mismatch');
});

test("agent_unknown_key: no key in the provider's JWKS has that kid", async () => {
  const t = await team();
  stopped(await call(t.agent, t.door, await t.agent.agentToken({ header: { kid: 'nope' } })), 401, 'agent_unknown_key', 'agent identified', 'unknown_key');
});

test('key_unsupported: cnf.jwk with the polymorphic EdDSA alg', async () => {
  const t = await team();
  const r = await call(t.agent, t.door, await t.agent.agentToken({ claims: { cnf: { jwk: { ...t.agent.publicJwk, alg: 'EdDSA' } } } }));
  stopped(r, 401, 'key_unsupported', 'agent identified', 'unsupported_algorithm');
  assert.equal(r.headers.get('accept-signature-alg'), 'Ed25519, ES256');
});

test('signature_invalid: signed with a key other than cnf.jwk; the base comes back to the agent, not onto the wall', async () => {
  const t = await team();
  const { privateKey } = await generateKeyPair('Ed25519', { extractable: true });
  const r = await forge(t.agent, t.door, await t.agent.agentToken(), { key: { ...(await exportJWK(privateKey)), alg: 'Ed25519' } });
  stopped(r, 401, 'signature_invalid', 'agent identified', 'invalid_signature');
  assert.match(String(r.body.signature_base), /^"@method": GET\n"@authority": /);
  assert.ok(!JSON.stringify(await attempt(r.body.attempt)).includes('eyJ'));
});

// ---- person identified ----

test('person_aud: a person token for another resource', async () => {
  const other = await otherServer('aauth-person.json');
  const t = await team({ ps: other.id });
  const pt = await other.mint('aa-person+jwt', { aud: 'https://elsewhere.example', sub: 'p', cnf: { jwk: t.agent.publicJwk } });
  stopped(await call(t.agent, t.door, pt), 401, 'person_aud', 'person identified', 'invalid_jwt');
});

test('person_token_invalid: a person token that lives more than an hour', async () => {
  const other = await otherServer('aauth-person.json');
  const t = await team({ ps: other.id });
  const pt = await other.mint('aa-person+jwt', { aud: ORIGIN, sub: 'p', cnf: { jwk: t.agent.publicJwk }, exp: now() + 7200 });
  stopped(await call(t.agent, t.door, pt), 401, 'person_token_invalid', 'person identified', 'invalid_jwt');
});

test('content_digest: the body sent is not the body signed', async () => {
  const t = await team();
  const pt = await personToken(t.agent, ps, ORIGIN, person());
  const r = await forge(t.agent, `${DOOR}/authorize`, pt, { body: '{"scope":"receipt"}', sendBody: '{"scope":"other"}' });
  stopped(r, 401, 'content_digest', 'person identified', 'invalid_signature');
});

// ---- resource token issued ----

test('invalid_scope, invalid_request and invalid_account at the authorization endpoint', async () => {
  const t = await team();
  const pt = await personToken(t.agent, ps, ORIGIN, person());
  const scope = await call(t.agent, `${DOOR}/authorize`, pt, { body: { scope: 'everything' } });
  stopped(scope, 400, 'invalid_scope', 'resource token issued');
  assert.equal(scope.body.error, 'invalid_scope');
  stopped(await call(t.agent, `${DOOR}/authorize`, pt, { body: {} }), 400, 'invalid_request', 'resource token issued');
  stopped(await call(t.agent, `${DOOR}/authorize`, pt, { body: { scope: 'receipt', account: 'me' } }), 400, 'invalid_account', 'resource token issued');
});

test('person_token_required: an auth token at the authorization endpoint', async () => {
  const t = await team();
  const s = await walk(t.agent, t.door, person());
  const r = await call(t.agent, `${DOOR}/authorize`, s.auth!, { body: { scope: 'receipt' } });
  stopped(r, 401, 'person_token_required', 'resource token issued');
  assert.equal(requirement(r.headers)?.requirement, 'person-token');
});

// ---- authorized ----

test('a person token where an auth token is needed is treated as a person token, never as a grant', async () => {
  const t = await team();
  const { pt } = await personAndChallenge(t);
  const again = await call(t.agent, t.door, pt);
  assert.equal(again.status, 401);
  assert.equal(requirement(again.headers)?.requirement, 'auth-token');
});

test('auth_issuer: an auth token from an access server, though this resource has none', async () => {
  const as = await otherServer('aauth-access.json');
  const t = await team();
  const auth = await as.mint('aa-auth+jwt', { aud: ORIGIN, ps: as.id, sub: 'p', scope: 'receipt', cnf: { jwk: t.agent.publicJwk } });
  stopped(await call(t.agent, t.door, auth), 401, 'auth_issuer', 'authorized', 'invalid_jwt');
});

test('auth_unmatched: an auth token no resource token of this door led to gets a fresh challenge', async () => {
  const other = await otherServer('aauth-person.json');
  const t = await team({ ps: other.id });
  const auth = await other.mint('aa-auth+jwt', { aud: ORIGIN, ps: other.id, sub: 'p', scope: 'receipt', cnf: { jwk: t.agent.publicJwk } });
  const r = await call(t.agent, t.door, auth);
  stopped(r, 401, 'auth_unmatched', 'authorized');
  const rt = decodeJwt(requirement(r.headers)!['resource-token']);
  assert.equal(rt.presented_jti, decodeJwt(auth).jti);
});

test('auth_claims: the PS granted more than the resource token asked for', async () => {
  const other = await otherServer('aauth-person.json');
  const t = await team({ ps: other.id });
  const cnf = { jwk: t.agent.publicJwk };
  const pt = await other.mint('aa-person+jwt', { aud: ORIGIN, sub: 'p', cnf });
  await call(t.agent, t.door, pt);
  const auth = await other.mint('aa-auth+jwt', { aud: ORIGIN, ps: other.id, sub: 'p', scope: 'receipt admin', cnf });
  stopped(await call(t.agent, t.door, auth), 401, 'auth_claims', 'authorized', 'invalid_jwt');
});

test('scope_insufficient: an auth token without receipt is stepped up with a new resource token', async () => {
  const other = await otherServer('aauth-person.json');
  const t = await team({ ps: other.id });
  const cnf = { jwk: t.agent.publicJwk };
  const pt = await other.mint('aa-person+jwt', { aud: ORIGIN, sub: 'p', cnf });
  await call(t.agent, t.door, pt);
  const auth = await other.mint('aa-auth+jwt', { aud: ORIGIN, ps: other.id, sub: 'p', cnf });
  const r = await call(t.agent, t.door, auth);
  stopped(r, 401, 'scope_insufficient', 'authorized');
  assert.equal(requirement(r.headers)?.requirement, 'auth-token');
});

test('the aauth wall: funnel and stop codes', async () => {
  const w = await state();
  assert.equal(w.ladder.length, 6);
  assert.ok(w.reached[5] >= 1);
  const codes = w.stopped.map((s: { error: string }) => s.error);
  for (const c of ['no_signature', 'signature_stale', 'agent_unknown_key', 'person_aud', 'auth_claims']) assert.ok(codes.includes(c), c);
});
