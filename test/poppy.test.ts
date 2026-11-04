/**
 * End to end for the poppy door: the real server, driven by poppy-client.ts, one test per stop code,
 * and the door's own authorization server. A small server on another port hosts the test agents'
 * client metadata and JWKS; `browser` plays the User on the door's consent page.
 */
import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtempSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { SignJWT, createLocalJWKSet, exportJWK, generateKeyPair, jwtVerify, type JWK } from 'jose';
import { call, companySaid, discover, message, newAgent, newSession, refresh, revoke, sessionJwt, signIn, tokenRequest, type Agent, type Company, type Session } from '../poppy-client.ts';

// ---- The agents' own documents ----

const agents = new Map<string, { metadata: unknown; jwks: unknown; status?: number }>();
const host = createServer((req, res) => {
  const a = /^\/agents\/([^/]+)\/(agent|jwks)\.json$/.exec(req.url!);
  const ag = a && agents.get(a[1]);
  if (!ag) return res.writeHead(404).end();
  if (ag.status) return res.writeHead(ag.status, { location: `${AGENTS}/elsewhere` }).end();
  res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(a[2] === 'agent' ? ag.metadata : ag.jwks));
});
host.listen(0);
await once(host, 'listening');
const AGENTS = `http://localhost:${(host.address() as { port: number }).port}`;

// ---- The proving ground ----

const port = 20000 + Math.floor(Math.random() * 20000);
const ORIGIN = `http://pg.localhost:${port}`;
const BASE = `${ORIGIN}/proving-ground`;
const ISSUER = `${BASE}/pg/doors/poppy`;
Object.assign(process.env, { PORT: String(port), BASE_URL: BASE, DATA_DIR: mkdtempSync(join(tmpdir(), 'pg-poppy-')) });
const { server } = await import('../src/server.ts');
after(() => { server.close(); host.close(); });

let company: Company;
let n = 0;
/** A new agent with its documents hosted on the stand-in; registered with a run unless `register` is false. */
async function newTeam(o: { register?: boolean; metadata?: (m: Record<string, unknown>) => unknown; jwks?: (j: { keys: JWK[] }) => unknown } = {}) {
  const name = `team-${++n}-${Math.random().toString(36).slice(2, 6)}`;
  const agent = await newAgent(`${AGENTS}/agents/${name}`);
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
  company = await discover(ORIGIN);
});

/** The User in a browser: opens the authorization URL, picks Allow or Deny as `account` on the consent page, and returns where they were sent back to. */
const browser = (account = 'test-user', decision = 'allow') => async (url: string) => {
  const res = await fetch(url, { redirect: 'manual' });
  if (res.status === 302) return res.headers.get('location')!;
  const html = await res.text();
  const consent = /name="consent" value="([^"]+)"/.exec(html)?.[1];
  if (!consent) throw new Error(`no consent page (${res.status}): ${html}`);
  const back = await fetch(`${ISSUER}/authorize`, { method: 'POST', redirect: 'manual', body: new URLSearchParams({ consent, account, decision }) });
  assert.equal(back.status, 302, await back.clone().text());
  return back.headers.get('location')!;
};
/** Signs the agent in as `account`, and puts the access token on the Session. */
const signedIn = async (s: Session, account = 'test-user') => (s.token = (await signIn(s.agent, company, 'conversations', browser(account))).access_token);

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
  const doc = await (await fetch(`${ORIGIN}/.well-known/poppy.json`)).json();
  assert.equal(doc.protocol_version, '0.3');
  assert.equal(doc.organization.domain, `pg.localhost:${port}`);
  assert.equal(doc.auth.issuer, ISSUER);
  assert.deepEqual(doc.auth.scope_hints, { conversations: { changes: 'none', personal_data: false } });
  assert.deepEqual(doc.agent.protocols, [{ type: 'poppy', endpoint: `${BASE}/pg/doors/poppy/conversations` }]);
  assert.deepEqual(await (await fetch(`${ORIGIN}/.well-known/oauth-protected-resource`)).json(), { resource: ORIGIN, authorization_servers: [ISSUER] });
  // The door is its own issuer: discover() has checked issuer and protected_resources (3.2).
  const as = company.as;
  assert.deepEqual([as.issuer, as.protected_resources], [ISSUER, [ORIGIN]]);
  assert.deepEqual(as.grant_types_supported, ['authorization_code', 'refresh_token']);
  for (const e of ['authorization_endpoint', 'token_endpoint', 'revocation_endpoint']) assert.ok(as[e].startsWith(`${ISSUER}/`), e);
  assert.equal(as.client_id_metadata_document_supported, true);
});

test('through: conversation signed out, sign-in at the issuer, signed-in reply with a receipt', async () => {
  const { agent, run, session: s } = await newTeam();
  assert.equal(run.poppy.client_metadata, 'valid', JSON.stringify(run.poppy));

  const started = await call(s, 'POST', company.endpoint, message('Hello'));
  assert.equal(started.status, 201);
  assert.equal(started.body.status, 'idle');
  const id = started.body.conversation_id;
  const read = await call(s, 'GET', `${company.endpoint}/${id}/events`);
  assert.equal(read.status, 200);
  assert.match(companySaid(read.body)[0]!, /You said: "Hello"/);
  const ask = read.body.events.find((e: { type: string }) => e.type === 'authorization');
  assert.deepEqual([ask.error, ask.scope], ['insufficient_scope', 'conversations']);

  const tokens = await signIn(agent, company, ask.scope, browser());
  assert.deepEqual([tokens.token_type, tokens.scope, typeof tokens.refresh_token], ['Bearer', 'conversations', 'string']);
  s.token = tokens.access_token;
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

test('a retried message returns the original response', async () => {
  const { session: s } = await newTeam();
  const m = message('once');
  const first = await call(s, 'POST', company.endpoint, m);
  const again = await call(s, 'POST', company.endpoint, m);
  assert.deepEqual(again.body, first.body);
});

// ---- The door's authorization server ----

/** The authorization URL the client would open, with overrides. */
function authUrl(agent: Agent, o: Record<string, string> = {}) {
  const u = new URL(company.as.authorization_endpoint);
  u.search = new URLSearchParams({ response_type: 'code', client_id: agent.clientId, redirect_uri: (agent.metadata.redirect_uris as string[])[0], scope: 'conversations', state: 'st', code_challenge: 'E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM', code_challenge_method: 'S256', ...o }).toString();
  return u.toString();
}

test('authorize: an unlisted redirect_uri gets a page, never a redirect; other errors redirect with iss', async () => {
  const { agent } = await newTeam();
  const page = await fetch(authUrl(agent, { redirect_uri: 'https://evil.example/cb' }), { redirect: 'manual' });
  assert.deepEqual([page.status, page.headers.get('location')], [400, null]);
  for (const [o, error] of [[{ scope: 'everything' }, 'invalid_scope'], [{ scope: '' }, 'invalid_scope'], [{ code_challenge_method: 'plain' }, 'invalid_request']] as const) {
    const back = new URL((await fetch(authUrl(agent, o), { redirect: 'manual' })).headers.get('location')!).searchParams;
    assert.deepEqual([back.get('error'), back.get('iss'), back.get('state')], [error, ISSUER, 'st']);
  }
  const consent = await fetch(authUrl(agent), { redirect: 'manual' });
  assert.equal(consent.headers.get('x-frame-options'), 'DENY');
  assert.match(await consent.text(), new RegExp(`${new URL(AGENTS).host} asks to act for you`));
});

test('authorize: a loopback redirect URI matches on any port', async () => {
  const { agent } = await newTeam({ metadata: (m) => ({ ...m, redirect_uris: ['http://127.0.0.1/callback'] }) });
  assert.equal((await fetch(authUrl(agent, { redirect_uri: 'http://127.0.0.1:53111/callback' }), { redirect: 'manual' })).status, 200);
  assert.equal((await fetch(authUrl(agent, { redirect_uri: 'http://127.0.0.1:53111/other' }), { redirect: 'manual' })).status, 400);
});

test('a declined sign-in comes back as access_denied, with iss', async () => {
  const { agent } = await newTeam();
  await assert.rejects(signIn(agent, company, 'conversations', browser('test-user', 'deny')), /declined: access_denied/);
});

test('token: the client assertion is addressed to the issuer only, and PKCE is checked', async () => {
  const { agent } = await newTeam();
  const back = new URL(await browser()(authUrl(agent))).searchParams;
  const code = back.get('code')!;
  const assertion = (aud: unknown) => new SignJWT({ aud } as Record<string, unknown>).setProtectedHeader({ alg: 'ES256', kid: agent.jwks.keys[0].kid })
    .setIssuer(agent.clientId).setSubject(agent.clientId).setIssuedAt().setExpirationTime('2m').setJti(crypto.randomUUID()).sign(agent.key);
  const post = async (aud: unknown, verifier = 'x'.repeat(43)) => {
    const res = await fetch(company.as.token_endpoint, { method: 'POST', body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: (agent.metadata.redirect_uris as string[])[0], code_verifier: verifier, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await assertion(aud) }) });
    return { status: res.status, body: await res.json() };
  };
  for (const aud of [company.as.token_endpoint, [ISSUER], `${ISSUER}/`]) {
    const r = await post(aud);
    assert.deepEqual([r.status, r.body.error], [401, 'invalid_client'], JSON.stringify(aud));
  }
  // The right audience but the wrong verifier: the code is spent either way.
  const r = await post(ISSUER);
  assert.deepEqual([r.status, r.body.error], [400, 'invalid_grant']);
  assert.match(r.body.error_description, /code_verifier/);
  assert.equal((await post(ISSUER)).body.error, 'invalid_grant');
});

test('refresh gives a new access token; revoking the refresh token ends both', async () => {
  const { agent, session: s } = await newTeam();
  const first = await signIn(agent, company, 'conversations', browser());
  const again = await refresh(agent, company, first.refresh_token!);
  assert.deepEqual([again.token_type, again.scope, again.refresh_token], ['Bearer', 'conversations', undefined]);
  await assert.rejects(refresh(agent, company, first.refresh_token!, 'conversations orders'), /invalid_scope/);
  s.token = again.access_token;
  assert.equal((await call(s, 'POST', company.endpoint, message('hi'))).status, 201);
  assert.deepEqual(await revoke(agent, company, first.refresh_token!), {});
  await assert.rejects(refresh(agent, company, first.refresh_token!), /invalid_grant/);
  stopped(await call(s, 'POST', company.endpoint, message('hi')), 401, 'invalid_token', 'token_invalid', 'signed in');
  // Another client can't use or revoke this client's refresh token.
  const other = await newTeam();
  const t = await signIn(agent, company, 'conversations', browser());
  await assert.rejects(tokenRequest(other.agent, company, company.as.token_endpoint, { grant_type: 'refresh_token', refresh_token: t.refresh_token! }), /invalid_grant/);
  await revoke(other.agent, company, t.refresh_token!);
  assert.equal((await refresh(agent, company, t.refresh_token!)).token_type, 'Bearer');
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
  s.token = 'not-a-token-the-door-issued';
  const r = await call(s, 'POST', company.endpoint, message('hi'));
  stopped(r, 401, 'invalid_token', 'token_invalid', 'signed in');
  assert.match(r.headers.get('www-authenticate')!, /error="invalid_token"/);
});

test('token_other_client: a token issued to another client_id', async () => {
  const { session: s } = await newTeam();
  const other = await newTeam();
  s.token = await signedIn(other.session);
  stopped(await call(s, 'POST', company.endpoint, message('hi')), 400, 'invalid_session', 'token_other_client', 'signed in');
});

test('session_ended: another account in the same Session', async () => {
  const { session: s } = await newTeam();
  await signedIn(s, 'alice');
  assert.equal((await call(s, 'POST', company.endpoint, message('hi'))).status, 201);
  await signedIn(s, 'bob');
  stopped(await call(s, 'POST', company.endpoint, message('hi')), 400, 'session_ended', 'session_ended', 'signed in');
});

test('account_required: signed out on a conversation that used an account', async () => {
  const { session: s } = await newTeam();
  await signedIn(s);
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
  await assert.rejects(signIn(imposter, company, 'conversations', browser()), /invalid_client/);
  await call(s, 'GET', `${company.endpoint}/${r.body.conversation_id}/events`);
  const attempt = (await state()).recent.find((a: { handle: string }) => a.handle === name).id;
  const detail = await (await fetch(`${BASE}/pg/attempts/${attempt}`)).json();
  assert.ok(detail.timeline.some((e: { text: string }) => /At the issuer: token refused, invalid_client/.test(e.text)), JSON.stringify(detail.timeline));
});

test('the poppy wall, the door intro and the run response', async () => {
  assert.equal((await fetch(`${BASE}/poppy`)).status, 200);
  const intro = await (await fetch(`${BASE}/pg/doors/poppy`)).json();
  assert.equal(intro.discovery, `${ORIGIN}/.well-known/poppy.json`);
  const bad = await fetch(`${BASE}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle: 'bad-client', client_id: 'ftp://x' }) });
  assert.equal(bad.status, 400);
  const llms = await (await fetch(`${BASE}/llms.txt`)).text();
  assert.ok(llms.includes('personal-agent-protocol@6fb46d3'));
});
