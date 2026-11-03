/**
 * End to end for the poppy door: the real server, driven by poppy-client.ts, one test per stop code.
 * Keycloak is replaced by a minimal stand-in on another port, which also hosts the test agents'
 * client metadata and JWKS. The stand-in issues ES256 tokens like Keycloak's (iss, azp, aud from
 * the audience mapper, scope), takes the door's admin calls, and records sign-in error events.
 */
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { once } from 'node:events';
import { mkdtempSync } from 'node:fs';
import { createServer, type IncomingMessage } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { SignJWT, calculateJwkThumbprint, createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, type JWK } from 'jose';
import { call, companySaid, discover, message, newAgent, newSession, sessionJwt, signIn, type Agent, type Company, type Session } from '../poppy-client.ts';

// ---- The stand-in issuer, and the agents' own documents ----

const si = await generateKeyPair('ES256');
const siJwk = { ...(await exportJWK(si.publicKey)), kid: 'si-1', alg: 'ES256' };
const agents = new Map<string, { metadata: unknown; jwks: unknown; status?: number }>();
const kcClients = new Map<string, Record<string, unknown> & { attributes: Record<string, string> }>();
const optionalScopes: string[] = [];
const kcEvents: { time: number; type: string; clientId: string; error: string }[] = [];
const codes = new Map<string, { clientId: string; redirectUri: string; challenge: string; scope: string }>();
let user = 'user-1';

const standin = createServer(async (req, res) => {
  const url = new URL(req.url!, ISSUER);
  const p = url.pathname;
  const json = (status: number, body?: unknown, headers: Record<string, string> = {}) => {
    res.writeHead(status, { 'content-type': 'application/json', ...headers });
    res.end(body === undefined ? undefined : JSON.stringify(body));
  };
  const a = /^\/agents\/([^/]+)\/(agent|jwks)\.json$/.exec(p);
  if (a && agents.has(a[1])) {
    const ag = agents.get(a[1])!;
    if (ag.status) return json(ag.status, undefined, { location: `${SI}/elsewhere` });
    return json(200, a[2] === 'agent' ? ag.metadata : ag.jwks);
  }
  if (p === '/.well-known/oauth-authorization-server/realms/test') {
    return json(200, {
      issuer: ISSUER, authorization_endpoint: `${OIDC}/auth`, token_endpoint: `${OIDC}/token`, revocation_endpoint: `${OIDC}/revoke`,
      grant_types_supported: ['authorization_code', 'refresh_token'], protected_resources: [BASE],
    });
  }
  if (p === `/realms/test/protocol/openid-connect/certs`) return json(200, { keys: [siJwk] });
  if (p === `/realms/test/protocol/openid-connect/auth`) {
    // The User signs in as `user` and approves at once.
    const q = url.searchParams;
    const c = kcClients.get(q.get('client_id')!);
    if (!c || !(c.redirectUris as string[]).includes(q.get('redirect_uri')!)) return json(400, { error: 'invalid_client' });
    const code = crypto.randomUUID();
    codes.set(code, { clientId: q.get('client_id')!, redirectUri: q.get('redirect_uri')!, challenge: q.get('code_challenge')!, scope: q.get('scope')! });
    return json(302, undefined, { location: `${q.get('redirect_uri')}?${new URLSearchParams({ code, state: q.get('state')!, iss: ISSUER })}` });
  }
  if (p === `/realms/test/protocol/openid-connect/token`) {
    const form = new URLSearchParams(await text(req));
    if (form.get('grant_type') === 'client_credentials') {
      return form.get('client_secret') === 'door-secret' && form.get('client_id') === 'proving-ground-door' ? json(200, { access_token: 'admin', expires_in: 300 }) : json(401, { error: 'unauthorized_client' });
    }
    const grant = codes.get(form.get('code')!);
    codes.delete(form.get('code')!);
    const c = grant && kcClients.get(grant.clientId);
    try {
      if (!c || form.get('redirect_uri') !== grant!.redirectUri) throw new Error('invalid_grant');
      const keys = createLocalJWKSet(await (await fetch(c.attributes['jwks.url'])).json());
      await jwtVerify(form.get('client_assertion')!, keys, { issuer: grant!.clientId, subject: grant!.clientId, audience: ISSUER });
      if (sha(form.get('code_verifier')!) !== grant!.challenge) throw new Error('invalid_grant');
    } catch {
      kcEvents.push({ time: Date.now(), type: 'CODE_TO_TOKEN_ERROR', clientId: grant?.clientId ?? '', error: 'invalid_client_credentials' });
      return json(400, { error: 'invalid_client' });
    }
    return json(200, { access_token: await mint({ azp: grant!.clientId, scope: grant!.scope }), token_type: 'Bearer', expires_in: 300, refresh_token: 'r', scope: grant!.scope });
  }
  // The admin API, as the door uses it.
  if (p.startsWith('/admin/realms/test/')) {
    if (req.headers.authorization !== 'Bearer admin') return json(401);
    const rest = p.slice('/admin/realms/test'.length);
    if (req.method === 'POST' && rest === '/clients') {
      const rep = JSON.parse(await text(req));
      if (kcClients.has(rep.clientId)) return json(409);
      kcClients.set(rep.clientId, rep);
      return json(201, undefined, { location: `${SI}/admin/realms/test/clients/${encodeURIComponent(rep.clientId)}` });
    }
    if (req.method === 'GET' && rest === '/clients') return json(200, [{ id: encodeURIComponent(url.searchParams.get('clientId')!) }]);
    if (req.method === 'PUT' && rest.startsWith('/clients/') && !rest.includes('/optional-client-scopes/')) {
      const rep = JSON.parse(await text(req));
      kcClients.set(rep.clientId, rep);
      return json(204);
    }
    if (rest === '/client-scopes') return json(200, [{ id: 'scope-1', name: 'conversations' }]);
    if (req.method === 'PUT' && rest.endsWith('/optional-client-scopes/scope-1')) return optionalScopes.push(rest.split("/")[2]), json(204);
    if (rest === '/events') return json(200, kcEvents.filter((e) => e.clientId === url.searchParams.get('client')));
  }
  json(404);
});
standin.listen(0);
await once(standin, 'listening');
const SI = `http://localhost:${(standin.address() as { port: number }).port}`;
const ISSUER = `${SI}/realms/test`;
const OIDC = `${ISSUER}/protocol/openid-connect`;

const text = async (req: IncomingMessage) => { let s = ''; for await (const c of req) s += c; return s; };
const sha = (s: string) => createHash('sha256').update(s).digest('base64url');

/** An access token as the issuer makes them; `claims` override. */
const mint = (claims: Record<string, unknown>, key: CryptoKey = si.privateKey) =>
  new SignJWT({ aud: [BASE, 'account'], sub: user, scope: 'conversations', ...claims }).setProtectedHeader({ alg: 'ES256', kid: 'si-1', typ: 'JWT' })
    .setIssuer(ISSUER).setIssuedAt().setExpirationTime('5m').setJti(crypto.randomUUID()).sign(key);

// ---- The proving ground ----

const port = 20000 + Math.floor(Math.random() * 20000);
const BASE = `http://localhost:${port}`;
Object.assign(process.env, { PORT: String(port), DATA_DIR: mkdtempSync(join(tmpdir(), 'pg-poppy-')), POPPY_ISSUER: ISSUER, POPPY_ADMIN_CLIENT_SECRET: 'door-secret' });
const { server } = await import('../src/server.ts');
after(() => { server.close(); standin.close(); });

let company: Company;
let n = 0;
/** A new agent with its documents hosted on the stand-in; registered with a run unless `register` is false. */
async function newTeam(o: { register?: boolean; metadata?: (m: Record<string, unknown>) => unknown; jwks?: (j: { keys: JWK[] }) => unknown } = {}) {
  const name = `team-${++n}-${Math.random().toString(36).slice(2, 6)}`;
  const agent = await newAgent(`${SI}/agents/${name}`);
  agents.set(name, { metadata: o.metadata?.(agent.metadata) ?? agent.metadata, jwks: o.jwks?.(agent.jwks) ?? agent.jwks });
  let run;
  if (o.register !== false) {
    const res = await fetch(`${BASE}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle: name, client_id: agent.clientId }) });
    assert.equal(res.status, 201);
    run = await res.json();
  }
  return { name, agent, run, session: await newSession(agent, company) };
}

before(async () => {
  if (!server.listening) await once(server, 'listening');
  company = await discover(BASE);
});

const browser = async (url: string) => (await fetch(url, { redirect: 'manual' })).headers.get('location')!;

/** A request with a hand-made Poppy-Session (or none), and extra headers. */
async function raw(url: string, o: { jwt?: string; method?: string; body?: unknown; headers?: Record<string, string> } = {}) {
  const res = await fetch(url, {
    method: o.method ?? 'POST',
    headers: { ...(o.jwt !== undefined && { 'Poppy-Session': o.jwt }), 'content-type': 'application/json', ...o.headers },
    body: o.method === 'GET' ? undefined : JSON.stringify(o.body ?? message('hi')),
  });
  return { status: res.status, headers: res.headers, body: await res.json() };
}

function stopped(r: { status: number; body: Record<string, unknown> }, status: number, error: string, pgStop: string, step: string) {
  assert.equal(r.body.pg_stop, pgStop, JSON.stringify(r.body));
  assert.equal(r.status, status);
  if (error) assert.equal(r.body.error, error);
  assert.equal(r.body.stopped_at, step);
}

/** Signs a Session JWT like the client does, with header and payload overrides. */
async function forged(s: Session, url: string, o: { header?: Record<string, unknown>; claims?: Record<string, unknown>; key?: CryptoKey } = {}) {
  const u = new URL(url);
  return new SignJWT({ iss: s.agent.clientId, aud: ISSUER, sid: s.sid, sub: s.sub, htm: 'POST', htu: `${u.origin}${u.pathname}`, iat: Math.floor(Date.now() / 1000), jti: crypto.randomUUID(), ...o.claims })
    .setProtectedHeader({ typ: 'poppy-session+jwt', alg: 'ES256', kid: s.kid, poppy_dlg: s.delegation, ...o.header })
    .sign(o.key ?? s.key);
}

const delegation = (agent: Agent, claims: Record<string, unknown>, lifetime: number) => {
  const iat = Math.floor(Date.now() / 1000);
  return new SignJWT(claims).setProtectedHeader({ alg: 'ES256', typ: 'poppy-delegation+jwt', kid: agent.jwks.keys[0].kid })
    .setIssuer(agent.clientId).setIssuedAt(iat).setExpirationTime(iat + lifetime).setJti(crypto.randomUUID()).sign(agent.key);
};

const state = async () => (await (await fetch(`${BASE}/pg/state`)).json()).doors.find((d: { door: string }) => d.door === 'poppy');

// ---- Through ----

test('discovery: poppy.json and the protected resource metadata', async () => {
  const doc = await (await fetch(`${BASE}/.well-known/poppy.json`)).json();
  assert.equal(doc.protocol_version, '0.3');
  assert.equal(doc.organization.domain, `localhost:${port}`);
  assert.equal(doc.auth.issuer, ISSUER);
  assert.deepEqual(doc.auth.scope_hints, { conversations: { changes: 'none', personal_data: false } });
  assert.deepEqual(doc.agent.protocols, [{ type: 'poppy', endpoint: `${BASE}/pg/doors/poppy/conversations` }]);
  assert.deepEqual(await (await fetch(`${BASE}/.well-known/oauth-protected-resource`)).json(), { resource: BASE, authorization_servers: [ISSUER] });
});

test('through: conversation signed out, sign-in at the issuer, signed-in reply with a receipt', async () => {
  const { agent, run, session: s } = await newTeam();
  assert.equal(run.poppy.client_metadata, 'valid', JSON.stringify(run.poppy));
  const kc = kcClients.get(agent.clientId)!;
  assert.equal(kc.clientAuthenticatorType, 'client-jwt');
  assert.equal(kc.attributes['jwks.url'], agent.metadata.jwks_uri);
  assert.ok(optionalScopes.includes(encodeURIComponent(agent.clientId)));

  const started = await call(s, 'POST', company.endpoint, message('Hello'));
  assert.equal(started.status, 201);
  assert.equal(started.body.status, 'idle');
  const id = started.body.conversation_id;
  const read = await call(s, 'GET', `${company.endpoint}/${id}/events`);
  assert.equal(read.status, 200);
  assert.match(companySaid(read.body)[0]!, /You said: "Hello"/);
  const ask = read.body.events.find((e: { type: string }) => e.type === 'authorization');
  assert.deepEqual([ask.error, ask.scope], ['insufficient_scope', 'conversations']);

  s.token = (await signIn(agent, company, ask.scope, browser)).access_token;
  const sent = await call(s, 'POST', `${company.endpoint}/${id}/messages?wait=0&cursor=${read.body.cursor}`, message('Signed in now'));
  assert.equal(sent.status, 202);
  const receipt = sent.body.events.find((e: { message?: { data?: { receipt?: string } } }) => e.message?.data?.receipt).message.data.receipt;
  const { payload } = await jwtVerify(receipt, createLocalJWKSet(await (await fetch(`${BASE}/pg/jwks.json`)).json()), { typ: 'pg-receipt+jwt' });
  assert.equal(payload.sub, run.handle);
  assert.equal(payload.door, 'poppy');

  const st = await state();
  assert.equal(st.runs.find((r: { handle: string }) => r.handle === run.handle).step, st.ladder.length - 1);
  const detail = await (await fetch(`${BASE}/pg/attempts/${payload.jti}`)).json();
  assert.equal(detail.step, st.ladder.length - 1);
  assert.deepEqual([...new Set(detail.timeline.filter((e: { ok?: boolean }) => e.ok).map((e: { step: string }) => e.step))], st.ladder.map((l: { name: string }) => l.name));
  const stored = JSON.stringify(detail);
  for (const secret of [s.token, s.delegation, 'Signed in now']) assert.ok(!stored.includes(secret.slice(0, 30)), 'stored a secret or message text');
});

test('a retried message returns the original response; a DPoP-bound token with its proof is accepted', async () => {
  const { session: s } = await newTeam();
  const m = message('once');
  const first = await call(s, 'POST', company.endpoint, m);
  const again = await call(s, 'POST', company.endpoint, m);
  assert.deepEqual(again.body, first.body);

  const dpop = await generateKeyPair('ES256');
  const jwk = await exportJWK(dpop.publicKey);
  const token = await mint({ azp: s.agent.clientId, cnf: { jkt: await calculateJwkThumbprint(jwk) } });
  s.token = token;
  const url = `${company.endpoint}/${first.body.conversation_id}/events`;
  const proof = await new SignJWT({ htm: 'GET', htu: url, ath: sha(token), jti: crypto.randomUUID() }).setProtectedHeader({ alg: 'ES256', typ: 'dpop+jwt', jwk }).setIssuedAt().sign(dpop.privateKey);
  const res = await fetch(url, { headers: { 'Poppy-Session': await sessionJwt(s, 'GET', url), Authorization: `DPoP ${token}`, DPoP: proof } });
  assert.equal(res.status, 200, await res.clone().text());
});

// ---- Every stop ----

test('no_session: no Poppy-Session header', async () => {
  stopped(await raw(company.endpoint), 400, 'invalid_session', 'no_session', 'session presented');
});

test('session_malformed: a header that is not a JWT', async () => {
  stopped(await raw(company.endpoint, { jwt: 'garbage' }), 400, 'invalid_session', 'session_malformed', 'client resolved');
});

test('client_refused: a client_id no run registered, and the error says how to register', async () => {
  const { session: s } = await newTeam({ register: false });
  const r = await call(s, 'POST', company.endpoint, message('hi'));
  stopped(r, 400, 'invalid_session', 'client_refused', 'client resolved');
  assert.match(r.body.error_description, /client_id refused.*\/pg\/runs/);
});

test('client_metadata_invalid: client_id differs from the URL, or the document redirects', async () => {
  const { run, session: s } = await newTeam({ metadata: (m) => ({ ...m, client_id: 'https://elsewhere.example/agent.json' }) });
  assert.equal(run.poppy.client_metadata, 'invalid');
  stopped(await call(s, 'POST', company.endpoint, message('hi')), 400, 'invalid_session', 'client_metadata_invalid', 'client resolved');
  const t2 = await newTeam({ register: false });
  agents.get(t2.name)!.status = 302;
  await fetch(`${BASE}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle: `${t2.name}`, client_id: t2.agent.clientId }) });
  const r = await call(t2.session, 'POST', company.endpoint, message('hi'));
  stopped(r, 400, 'invalid_session', 'client_metadata_invalid', 'client resolved');
  assert.match(r.body.error_description, /302/);
});

test('jwks_invalid: a JWKS with a private key in it', async () => {
  const { session: s } = await newTeam({ jwks: (j) => ({ keys: [{ ...j.keys[0], d: 'secret' }] }) });
  stopped(await call(s, 'POST', company.endpoint, message('hi')), 400, 'invalid_session', 'jwks_invalid', 'client resolved');
});

test('delegation_missing: a Session JWT signed directly with the JWKS key', async () => {
  const { agent, session: s } = await newTeam();
  const jwt = await forged(s, company.endpoint, { header: { poppy_dlg: undefined, kid: agent.jwks.keys[0].kid }, key: agent.key });
  stopped(await raw(company.endpoint, { jwt }), 400, 'invalid_session', 'delegation_missing', 'delegation valid');
});

test('delegation_invalid: a delegation that lasts more than 24 hours', async () => {
  const { agent, session: s } = await newTeam();
  const cnf = { ...(await exportJWK((await generateKeyPair('ES256')).publicKey)) };
  s.delegation = await delegation(agent, { cnf: { jwk: cnf } }, 25 * 3600);
  stopped(await call(s, 'POST', company.endpoint, message('hi')), 400, 'invalid_session', 'delegation_invalid', 'delegation valid');
});

test('session_signature: kid is not the delegated key thumbprint', async () => {
  const { session: s } = await newTeam();
  stopped(await raw(company.endpoint, { jwt: await forged(s, company.endpoint, { header: { kid: 'not-the-thumbprint' } }) }), 400, 'invalid_session', 'session_signature', 'session valid');
});

test('session_claims: no sid', async () => {
  const { session: s } = await newTeam();
  stopped(await raw(company.endpoint, { jwt: await forged(s, company.endpoint, { claims: { sid: undefined } }) }), 400, 'invalid_session', 'session_claims', 'session valid');
});

test('aud_mismatch: aud is the domain, not the issuer', async () => {
  const { session: s } = await newTeam();
  stopped(await raw(company.endpoint, { jwt: await forged(s, company.endpoint, { claims: { aud: BASE } }) }), 400, 'invalid_session', 'aud_mismatch', 'session valid');
});

test('htu_mismatch: signed for another URL', async () => {
  const { session: s } = await newTeam();
  stopped(await raw(company.endpoint, { jwt: await sessionJwt(s, 'POST', `${BASE}/elsewhere`) }), 400, 'invalid_session', 'htu_mismatch', 'session valid');
});

test('iat_out_of_window: a Session JWT ten minutes old', async () => {
  const { session: s } = await newTeam();
  stopped(await raw(company.endpoint, { jwt: await forged(s, company.endpoint, { claims: { iat: Math.floor(Date.now() / 1000) - 600 } }) }), 400, 'invalid_session', 'iat_out_of_window', 'session valid');
});

test('ath_mismatch: ath with no access token', async () => {
  const { session: s } = await newTeam();
  stopped(await raw(company.endpoint, { jwt: await sessionJwt(s, 'POST', company.endpoint, { ath: 'x' }) }), 400, 'invalid_session', 'ath_mismatch', 'session valid');
});

test('sub_mismatch: another User ID in a known Session', async () => {
  const { session: s } = await newTeam();
  assert.equal((await call(s, 'POST', company.endpoint, message('hi'))).status, 201);
  stopped(await raw(company.endpoint, { jwt: await sessionJwt(s, 'POST', company.endpoint, { sub: 'someone-else' }) }), 400, 'invalid_session', 'sub_mismatch', 'session valid');
});

test('invalid_request: a message with no content', async () => {
  const { session: s } = await newTeam();
  stopped(await call(s, 'POST', company.endpoint, { message: { id: 'm1', author: { type: 'agent' } } }), 400, 'invalid_request', 'invalid_request', 'conversation started');
});

test('message_id_conflict: a message ID reused with other content', async () => {
  const { session: s } = await newTeam();
  const m = message('first');
  await call(s, 'POST', company.endpoint, m);
  stopped(await call(s, 'POST', company.endpoint, { message: { ...m.message, text: 'second' } }), 409, 'message_id_conflict', 'message_id_conflict', 'conversation started');
});

test('conversation_not_found: another User reads the conversation', async () => {
  const { agent, session: s } = await newTeam();
  const id = (await call(s, 'POST', company.endpoint, message('hi'))).body.conversation_id;
  const other = await newSession(agent, company);
  stopped(await call(other, 'GET', `${company.endpoint}/${id}/events`), 404, 'conversation_not_found', 'conversation_not_found', 'reply read');
});

test('conversation_closed: a message after close', async () => {
  const { session: s } = await newTeam();
  const id = (await call(s, 'POST', company.endpoint, message('hi'))).body.conversation_id;
  const closed = await call(s, 'POST', `${company.endpoint}/${id}/close`, {});
  assert.deepEqual([closed.status, closed.body.status], [200, 'closed']);
  stopped(await call(s, 'POST', `${company.endpoint}/${id}/messages`, message('still there?')), 409, 'conversation_closed', 'conversation_closed', 'reply read');
});

test('invalid_cursor: a cursor from nowhere', async () => {
  const { session: s } = await newTeam();
  const id = (await call(s, 'POST', company.endpoint, message('hi'))).body.conversation_id;
  stopped(await call(s, 'GET', `${company.endpoint}/${id}/events?cursor=nope`), 400, 'invalid_cursor', 'invalid_cursor', 'reply read');
});

test('token_invalid: a token the issuer did not sign', async () => {
  const { session: s } = await newTeam();
  s.token = await mint({ azp: s.agent.clientId }, (await generateKeyPair('ES256')).privateKey);
  const r = await call(s, 'POST', company.endpoint, message('hi'));
  stopped(r, 401, 'invalid_token', 'token_invalid', 'signed in');
  assert.match(r.headers.get('www-authenticate')!, /error="invalid_token"/);
});

test('token_other_client: a token issued to another client_id', async () => {
  const { session: s } = await newTeam();
  s.token = await mint({ azp: 'https://other.example/agent.json' });
  stopped(await call(s, 'POST', company.endpoint, message('hi')), 400, 'invalid_session', 'token_other_client', 'signed in');
});

test('dpop_invalid: a DPoP-bound token sent as Bearer', async () => {
  const { session: s } = await newTeam();
  s.token = await mint({ azp: s.agent.clientId, cnf: { jkt: 'abc' } });
  stopped(await call(s, 'POST', company.endpoint, message('hi')), 401, 'invalid_dpop_proof', 'dpop_invalid', 'signed in');
});

test('session_ended: another account in the same Session', async () => {
  const { session: s } = await newTeam();
  s.token = await mint({ azp: s.agent.clientId });
  assert.equal((await call(s, 'POST', company.endpoint, message('hi'))).status, 201);
  s.token = await mint({ azp: s.agent.clientId, sub: 'user-2' });
  stopped(await call(s, 'POST', company.endpoint, message('hi')), 400, 'session_ended', 'session_ended', 'signed in');
});

test('account_required: signed out on a conversation that used an account', async () => {
  const { session: s } = await newTeam();
  s.token = await mint({ azp: s.agent.clientId });
  const id = (await call(s, 'POST', company.endpoint, message('hi'))).body.conversation_id;
  s.token = undefined;
  const r = await call(s, 'POST', `${company.endpoint}/${id}/messages`, message('signed out now'));
  stopped(r, 401, '', 'account_required', 'authorized call');
  assert.equal(r.headers.get('www-authenticate'), 'Bearer scope="conversations"');
});

test("sign-in errors at the issuer show on the attempt's timeline", async () => {
  const { name, agent, session: s } = await newTeam();
  const r = await call(s, 'POST', company.endpoint, message('hi'));
  // An assertion signed with a key that isn't in the JWKS: the issuer refuses, out of the door's sight.
  const imposter = { ...agent, key: (await generateKeyPair('ES256')).privateKey };
  await assert.rejects(signIn(imposter, company, 'conversations', browser), /invalid_client/);
  await call(s, 'GET', `${company.endpoint}/${r.body.conversation_id}/events`);
  const attempt = (await state()).recent.find((a: { handle: string }) => a.handle === name).id;
  const detail = await (await fetch(`${BASE}/pg/attempts/${attempt}`)).json();
  assert.ok(detail.timeline.some((e: { text: string }) => /At the issuer: CODE_TO_TOKEN_ERROR/.test(e.text)), JSON.stringify(detail.timeline));
});

test('the poppy wall, the door intro and the run response', async () => {
  assert.equal((await fetch(`${BASE}/poppy`)).status, 200);
  const intro = await (await fetch(`${BASE}/pg/doors/poppy`)).json();
  assert.equal(intro.discovery, `${BASE}/.well-known/poppy.json`);
  const bad = await fetch(`${BASE}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle: 'bad-client', client_id: 'ftp://x' }) });
  assert.equal(bad.status, 400);
  const llms = await (await fetch(`${BASE}/llms.txt`)).text();
  assert.ok(llms.includes('personal-agent-protocol@6fb46d3'));
});
