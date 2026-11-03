/**
 * The poppy door: a Company under Personal Agent Protocol (Poppy) 0.3, as
 * published at personal-agent-protocol@6fb46d3, with a Company Agent that
 * echoes and, once you sign in, tells you which account you used.
 *
 * Discovery is at /.well-known/poppy.json and /.well-known/oauth-protected-resource.
 * Sign-in is at an external Keycloak (POPPY_ISSUER); the door only verifies
 * its access tokens, and registers each run's client_id there.
 *
 * An attempt is one Session (client_id + sid). Each request is walked up
 * LADDER; the attempt keeps the highest step it reached. A request stops
 * with the spec's error (invalid_session, invalid_token, conversation_not_found,
 * ...) plus `pg_stop`, the door's finer stop code, and `stopped_at`.
 *
 * Nothing the agent signs or sends is stored: not the JWTs, not the token, not
 * the message text. Conversations live in memory.
 */
import { createHash, randomBytes } from 'node:crypto';
import { lookup } from 'node:dns/promises';
import { EmbeddedJWK, SignJWT, calculateJwkThumbprint, createRemoteJWKSet, decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, type JWK, type JWTPayload } from 'jose';
import { BASE_URL, DEV, DID, PRIVATE, verifier, type DoorRequest } from '../lab.ts';
import * as store from '../store.ts';

const SPEC_URL = 'https://github.com/personal-agent-protocol/personal-agent-protocol/blob/6fb46d381ac1b94265795132af13848ec442b6f6/content/versions/0.3/spec.mdx';
/** The same text, rendered with anchors. */
const SPEC_SITE = 'https://personalagentprotocol.org/docs/0.3/spec';

/** The steps, in the order a Personal Agent meets them. `ref` is the spec section each comes from. */
export const LADDER = [
  { name: 'session presented', ref: 'session-header' },
  { name: 'client resolved', ref: 'agent-identity' },
  { name: 'delegation valid', ref: 'delegated-keys' },
  { name: 'session valid', ref: 'session-verification' },
  { name: 'conversation started', ref: 'sending-messages' },
  { name: 'reply read', ref: 'reading-events' },
  { name: 'signed in', ref: 'access-tokens' },
  { name: 'authorized call', ref: 'conversation-sign-in' },
  { name: 'through', ref: 'conversation-sign-in' },
] as const;
type StepName = (typeof LADDER)[number]['name'];
export const THROUGH = LADDER.length - 1;

// Sign-in: a Keycloak realm. Its admin API registers clients and reports sign-in errors.
const ISSUER = (process.env.POPPY_ISSUER ?? 'https://idp.agentlab.choosemission.com/realms/protocol-proving-experiments').replace(/\/$/, '');
const ADMIN = ISSUER.replace(/\/realms\//, '/admin/realms/');
const TOKEN_ENDPOINT = `${ISSUER}/protocol/openid-connect/token`;
const ADMIN_CLIENT_ID = process.env.POPPY_ADMIN_CLIENT_ID ?? 'proving-ground-door';
const ADMIN_CLIENT_SECRET = process.env.POPPY_ADMIN_CLIENT_SECRET;
const issuerKeys = createRemoteJWKSet(new URL(`${ISSUER}/protocol/openid-connect/certs`));

const SCOPE = 'conversations';
const ENDPOINT = `${BASE_URL}/pg/doors/poppy/conversations`;
const DOMAIN = new URL(BASE_URL).host;
const ID = /^[A-Za-z0-9_-]{1,256}$/;
const IAT_WINDOW_S = 60;
const CLIENT_CACHE_MS = 5 * 60_000;

/** Served by the server at these paths (the door claims them). */
export const WELL_KNOWN = {
  '/.well-known/poppy.json': () => ({
    protocol_version: '0.3',
    organization: { name: 'Agent Lab proving ground', domain: DOMAIN },
    auth: {
      issuer: ISSUER,
      scopes: { [SCOPE]: 'Let the Company Agent see which account you signed in with, in a conversation' },
      scope_hints: { [SCOPE]: { changes: 'none', personal_data: false } },
    },
    agent: { protocols: [{ type: 'poppy', endpoint: ENDPOINT }] },
  }),
  '/.well-known/oauth-protected-resource': () => ({ resource: new URL(BASE_URL).origin, authorization_servers: [ISSUER] }),
};

/** Shown on the wall and served at /pg/state. */
export const INFO = {
  door: 'poppy',
  spec: { name: 'Personal Agent Protocol', version: '0.3', pinned: 'personal-agent-protocol@6fb46d3', url: SPEC_URL },
  proves: 'A Personal Agent acting for a signed-in User',
  about: `A Company with a Company Agent at ${ENDPOINT}. Start at /.well-known/poppy.json. Register your client_id with your run; sign in at ${ISSUER} with scope ${SCOPE}.`,
  builds_on: [
    { name: 'OAuth Client ID Metadata Document (client_id is a URL)', url: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/' },
    { name: 'RFC 9728, OAuth 2.0 Protected Resource Metadata', url: 'https://www.rfc-editor.org/rfc/rfc9728' },
    { name: 'RFC 7523, private_key_jwt client assertions', url: 'https://www.rfc-editor.org/rfc/rfc7523' },
    { name: 'RFC 9449, DPoP (htm/htu/ath, and DPoP-bound tokens)', url: 'https://www.rfc-editor.org/rfc/rfc9449' },
  ],
  ladder: LADDER.map((s) => ({ name: s.name, url: `${SPEC_SITE}#${s.ref}` })),
  issuer: ISSUER,
  endpoint: ENDPOINT,
};

type Reply = { status: number; headers: Record<string, string>; body: unknown };

/** Every stop: the step it stops at, and the HTTP status and spec error it answers with. */
const STOPS = {
  no_session: ['session presented', 400, 'invalid_session'],
  session_malformed: ['client resolved', 400, 'invalid_session'],
  client_refused: ['client resolved', 400, 'invalid_session'],
  client_metadata_invalid: ['client resolved', 400, 'invalid_session'],
  jwks_invalid: ['client resolved', 400, 'invalid_session'],
  delegation_missing: ['delegation valid', 400, 'invalid_session'],
  delegation_invalid: ['delegation valid', 400, 'invalid_session'],
  session_signature: ['session valid', 400, 'invalid_session'],
  session_claims: ['session valid', 400, 'invalid_session'],
  aud_mismatch: ['session valid', 400, 'invalid_session'],
  htu_mismatch: ['session valid', 400, 'invalid_session'],
  iat_out_of_window: ['session valid', 400, 'invalid_session'],
  ath_mismatch: ['session valid', 400, 'invalid_session'],
  sub_mismatch: ['session valid', 400, 'invalid_session'],
  invalid_request: ['conversation started', 400, 'invalid_request'],
  message_id_conflict: ['conversation started', 409, 'message_id_conflict'],
  conversation_not_found: ['reply read', 404, 'conversation_not_found'],
  conversation_closed: ['reply read', 409, 'conversation_closed'],
  invalid_cursor: ['reply read', 400, 'invalid_cursor'],
  token_invalid: ['signed in', 401, 'invalid_token'],
  token_other_client: ['signed in', 400, 'invalid_session'],
  dpop_invalid: ['signed in', 401, 'invalid_dpop_proof'],
  session_ended: ['signed in', 400, 'session_ended'],
  account_required: ['authorized call', 401, ''],
} as const satisfies Record<string, readonly [StepName, number, string]>;
type Code = keyof typeof STOPS;

class Stop extends Error {
  code: Code;
  constructor(code: Code, message: string) {
    super(message);
    this.code = code;
  }
}
function need(cond: unknown, code: Code, message: string): asserts cond {
  if (!cond) throw new Stop(code, message);
}
async function guard<T>(code: Code, fn: () => T | Promise<T>): Promise<T> {
  try {
    return await fn();
  } catch (e) {
    throw e instanceof Stop ? e : new Stop(code, (e as Error).message);
  }
}

const entry = (text: string, step?: StepName, ok?: boolean): store.Entry => ({ at: new Date().toISOString(), text, step, ok });
const tail = (s: string) => `…${s.slice(-4)}`;
const sha256 = (s: string) => createHash('sha256').update(s).digest('base64url');
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];
const nowS = () => Math.floor(Date.now() / 1000);

// ---- Clients: client_id is a URL serving client metadata (4.1) ----

type Client = { at: number; meta: { client_id: string; client_name?: string; jwks_uri: string; redirect_uris: string[] }; keys: JWK[]; registered?: string; eventsSince: number };
// ponytail: in-memory caches and conversations, lost on restart and unbounded; move to SQLite with a TTL before real traffic.
const clients = new Map<string, Client>();

const allowedScheme = (u: URL) => u.protocol === 'https:' || (DEV && u.protocol === 'http:');

/** Why a client_id can't be registered with a run, or null. */
export function clientIdProblem(v: unknown): string | null {
  if (typeof v !== 'string' || v.length > 2048) return 'client_id must be a URL string: the HTTPS URL of your client metadata document.';
  const u = URL.canParse(v) ? new URL(v) : null;
  if (!u || !allowedScheme(u) || u.hash || u.username) return `client_id must be an HTTPS URL with no fragment${DEV ? ' (http is allowed while BASE_URL is http://localhost)' : ''}.`;
  return null;
}

/** GETs a URL the agent gave us: https, public address, no redirects (5.3, section 3). */
async function fetchJson(u: string, code: Code, what: string) {
  const url = await guard(code, () => new URL(u));
  need(allowedScheme(url), code, `${what} must be an HTTPS URL; got ${u}.`);
  if (!DEV) {
    const { address, family } = await guard(code, () => lookup(url.hostname));
    need(!PRIVATE.check(address, family === 6 ? 'ipv6' : 'ipv4'), code, `${what} resolves to a private address.`);
  }
  const res = await guard(code, () => fetch(url, { redirect: 'manual', signal: AbortSignal.timeout(5000), headers: { accept: 'application/json' } }));
  need(res.status === 200, code, `Fetching ${what} (${u}) returned ${res.status}; it must return 200 without redirecting.`);
  const text = await res.text();
  need(text.length <= 64_000, code, `${what} is over 64 kB.`);
  return guard(code, () => JSON.parse(text));
}

/** Fetches and checks a client's metadata and keys, and (re)registers it at the issuer when they change. */
async function resolveClient(clientId: string, log: store.Entry[]): Promise<Client> {
  const cached = clients.get(clientId);
  if (cached && Date.now() - cached.at < CLIENT_CACHE_MS) return cached;
  const code = 'client_metadata_invalid';
  const meta = await fetchJson(clientId, code, 'The client metadata document');
  need(meta && typeof meta === 'object', code, 'The client metadata document must be a JSON object.');
  need(meta.client_id === clientId, code, `client_id in the document (${JSON.stringify(meta.client_id)}) must equal the URL it was fetched from, ${clientId}.`);
  const host = new URL(clientId).hostname.toLowerCase();
  const sameDomain = (u: unknown) => typeof u === 'string' && URL.canParse(u) && allowedScheme(new URL(u)) && new URL(u).hostname.toLowerCase() === host;
  need(sameDomain(meta.jwks_uri), code, `jwks_uri must be an HTTPS URL on ${host}.`);
  const loopback = (u: string) => /^http:\/\/(127\.0\.0\.1|\[::1\])(:\d+)?\//.test(u);
  need(Array.isArray(meta.redirect_uris) && meta.redirect_uris.length > 0, code, 'redirect_uris must be a non-empty list.');
  for (const r of meta.redirect_uris) need(sameDomain(r) || loopback(r), code, `Redirect URI ${r} must be an HTTPS URL on ${host}, or a loopback redirect URI.`);
  need(meta.token_endpoint_auth_method === 'private_key_jwt', code, `token_endpoint_auth_method must be private_key_jwt; got ${JSON.stringify(meta.token_endpoint_auth_method)}.`);

  const jwks = await fetchJson(meta.jwks_uri, 'jwks_invalid', 'jwks_uri');
  const keys: JWK[] = jwks?.keys;
  need(Array.isArray(keys) && keys.length > 0, 'jwks_invalid', 'jwks_uri must return {"keys": [...]} with at least one key.');
  need(keys.every((k) => PRIVATE_MEMBERS.every((m) => !(m in k))), 'jwks_invalid', 'jwks_uri contains private key members. Publish public keys only, and replace the leaked key.');

  const client: Client = { at: Date.now(), meta, keys, registered: cached?.registered, eventsSince: cached?.eventsSince ?? Date.now() };
  const shape = JSON.stringify([meta.jwks_uri, meta.redirect_uris, meta.client_name]);
  if (client.registered !== shape) {
    try {
      log.push(entry(await registerAtIssuer(client)));
      client.registered = shape;
    } catch (e) {
      log.push(entry(`Couldn't register the client at the issuer: ${(e as Error).message} Sign-in will fail until it is; signed-out steps still work.`, undefined, false));
    }
  }
  clients.set(clientId, client);
  return client;
}

/** Called when a run is started with a client_id: resolves it now, so sign-in works before the first Session request. */
export async function register(clientId: string) {
  const log: store.Entry[] = [];
  try {
    await resolveClient(clientId, log);
    return { client_metadata: 'valid', issuer: log.map((e) => e.text).join(' ') || 'Already registered.', discovery: `${BASE_URL}/.well-known/poppy.json` };
  } catch (e) {
    if (!(e instanceof Stop)) throw e;
    return { client_metadata: 'invalid', problem: e.message, next: 'Fix it; the door fetches it again on your first Session request, and registers it at the issuer then.' };
  }
}

// ---- The issuer's admin API (Keycloak) ----

let adminToken: { value: string; exp: number } | undefined;
async function admin(method: string, path: string, body?: unknown) {
  if (!adminToken || adminToken.exp < Date.now()) {
    const res = await fetch(TOKEN_ENDPOINT, {
      method: 'POST',
      body: new URLSearchParams({ grant_type: 'client_credentials', client_id: ADMIN_CLIENT_ID, client_secret: ADMIN_CLIENT_SECRET! }),
      signal: AbortSignal.timeout(5000),
    });
    if (!res.ok) throw new Error(`the door's admin sign-in (${ADMIN_CLIENT_ID}) returned ${res.status}.`);
    const t = await res.json();
    adminToken = { value: t.access_token, exp: Date.now() + (t.expires_in - 30) * 1000 };
  }
  return fetch(`${ADMIN}${path}`, {
    method,
    headers: { authorization: `Bearer ${adminToken.value}`, ...(body !== undefined && { 'content-type': 'application/json' }) },
    body: body === undefined ? undefined : JSON.stringify(body),
    signal: AbortSignal.timeout(5000),
  });
}

/** Creates or updates the Keycloak client for a client_id, with the Poppy scope optional. */
async function registerAtIssuer({ meta }: Client) {
  if (!ADMIN_CLIENT_SECRET) throw new Error('POPPY_ADMIN_CLIENT_SECRET is not set.');
  const rep = {
    clientId: meta.client_id,
    name: meta.client_name ?? meta.client_id,
    protocol: 'openid-connect',
    publicClient: false,
    clientAuthenticatorType: 'client-jwt',
    standardFlowEnabled: true,
    implicitFlowEnabled: false,
    directAccessGrantsEnabled: false,
    serviceAccountsEnabled: false,
    consentRequired: true,
    redirectUris: meta.redirect_uris,
    webOrigins: [],
    attributes: {
      'use.jwks.url': 'true',
      'jwks.url': meta.jwks_uri,
      'token.endpoint.auth.signing.alg': 'ES256',
      'pkce.code.challenge.method': 'S256',
      'oauth2.device.authorization.grant.enabled': 'false',
      'use.refresh.tokens': 'true',
    },
  };
  let res = await admin('POST', '/clients', rep);
  let id = res.headers.get('location')?.split('/').pop();
  if (res.status === 409) {
    id = (await (await admin('GET', `/clients?clientId=${encodeURIComponent(meta.client_id)}`)).json())[0]?.id;
    res = await admin('PUT', `/clients/${id}`, rep);
  }
  if (!res.ok || !id) throw new Error(`the issuer's admin API returned ${res.status}.`);
  const scope = ((await (await admin('GET', '/client-scopes')).json()) as { id: string; name: string }[]).find((s) => s.name === SCOPE);
  if (!scope) throw new Error(`the issuer has no client scope named ${SCOPE}.`);
  const r = await admin('PUT', `/clients/${id}/optional-client-scopes/${scope.id}`);
  if (!r.ok) throw new Error(`adding scope ${SCOPE} returned ${r.status}.`);
  return `Registered at the issuer as a private_key_jwt (ES256) client, PKCE S256, with optional scope ${SCOPE}.`;
}

/** Sign-in happens at the issuer, out of the door's sight; its error events fill the gap. Best effort. */
async function issuerErrors(client: Client): Promise<store.Entry[]> {
  if (!ADMIN_CLIENT_SECRET) return [];
  try {
    const from = new Date(client.eventsSince).toISOString().slice(0, 10);
    const res = await admin('GET', `/events?client=${encodeURIComponent(client.meta.client_id)}&dateFrom=${from}&max=20`);
    const events = ((await res.json()) as { time: number; type: string; error?: string }[]).filter((e) => e.type.endsWith('_ERROR') && e.time > client.eventsSince);
    if (events.length) client.eventsSince = Math.max(...events.map((e) => e.time));
    return events.sort((a, b) => a.time - b.time).map((e) => ({ at: new Date(e.time).toISOString(), text: `At the issuer: ${e.type}${e.error ? ` (${e.error})` : ''}.`, ok: false }));
  } catch {
    return [];
  }
}

// ---- Sessions and conversations ----

type Session = { sub: string; agentId?: unknown; account: string | null; attempt: string; step: number; runId: string | null };
const sessions = new Map<string, Session>();

type Event = { id: string; type: string; created_at: string; [k: string]: unknown };
type Conversation = { id: string; client: string; sub: string; account: string | null; events: Event[]; closed: boolean };
const conversations = new Map<string, Conversation>();
/** Accepted message IDs, per User: the content and the response, for retries (8.3). */
const accepted = new Map<string, { content: string; status: number; body: unknown }>();

function addEvent(c: Conversation, e: Record<string, unknown>) {
  c.events.push({ id: `evt_${c.events.length + 1}`, created_at: new Date().toISOString(), type: 'message', ...e } as Event);
}
const state = (c: Conversation) => ({ status: c.closed ? 'closed' : 'idle', responder: 'agent' });
function read(c: Conversation, cursor: string | null) {
  const from = cursor === null ? 0 : c.events.findIndex((e) => e.id === cursor) + 1;
  need(from > 0 || cursor === null, 'invalid_cursor', `Cursor ${cursor} isn't an event of this conversation.`);
  const events = c.events.slice(from);
  return { conversation_id: c.id, events, cursor: events.at(-1)?.id ?? cursor, has_more: false, ...state(c) };
}

/** The canned Company Agent: echoes; with the account scope, says which account and hands over a receipt. */
async function companyReply(c: Conversation, text: unknown, s: Session, handle: string | null, scoped: boolean) {
  const said = typeof text === 'string' ? `You said: "${text.slice(0, 200)}". ` : '';
  if (!scoped) {
    addEvent(c, { message: { id: `msg_${randomBytes(6).toString('base64url')}`, role: 'company', author: { type: 'agent' }, text: `${said}I'm the proving ground's test Company Agent; I echo. Sign in with scope ${SCOPE} and send another message, and I'll tell you which account you used.` } });
    addEvent(c, { type: 'authorization', error: 'insufficient_scope', scope: SCOPE });
    return;
  }
  const receipt = await new SignJWT({ door: 'poppy', spec: `Poppy 0.3 (${INFO.spec.pinned})`, resource: ENDPOINT, steps: LADDER.map((x) => x.name), proves: INFO.proves, issuer: ISSUER })
    .setProtectedHeader({ alg: 'ES256', typ: 'pg-receipt+jwt', kid: verifier.kid })
    .setIssuer(DID)
    .setSubject(handle ?? 'anonymous')
    .setJti(s.attempt)
    .setIssuedAt()
    .sign(verifier.key);
  addEvent(c, { message: { id: `msg_${randomBytes(6).toString('base64url')}`, role: 'company', author: { type: 'agent' }, text: `${said}You're signed in, to account ${tail(c.account!)}. That's the door: here's your receipt.`, data: { receipt } } });
}

/** A Poppy message (8.4), or a Stop. */
function checkMessage(m: Record<string, unknown> | undefined) {
  need(m && typeof m === 'object', 'invalid_request', 'The body needs a "message" object.');
  need(typeof m.id === 'string' && ID.test(m.id), 'invalid_request', 'message.id must be 1 to 256 characters of A-Z a-z 0-9 - _.');
  const author = m.author as { type?: unknown } | undefined;
  need(author?.type === 'agent' || author?.type === 'human', 'invalid_request', 'message.author.type must be "agent" or "human".');
  need(['text', 'data', 'context', 'extensions'].some((k) => m[k] !== undefined), 'invalid_request', 'A message needs at least one of text, data, context or extensions.');
  return m as { id: string; text?: unknown; data?: unknown };
}

/** The intro for a request to the door's own URL, which isn't a Poppy endpoint. */
const intro = (): Reply => ({
  status: 200,
  headers: {},
  body: {
    door: 'poppy',
    message: 'This door is a Company under Personal Agent Protocol 0.3. Start with discovery; the conversation endpoint is in poppy.json.',
    discovery: `${BASE_URL}/.well-known/poppy.json`,
    register: `POST {"handle": "<your-handle>", "client_id": "<your client metadata URL>"} to ${BASE_URL}/pg/runs. The door refuses Session JWTs from a client_id no run registered.`,
    spec: SPEC_URL,
    instructions: `${BASE_URL}/llms.txt`,
    wall: `${BASE_URL}/poppy`,
  },
});

// ---- The door ----

const ROUTE = /^\/conversations(?:\/([^/]+)\/(messages|events|handoff|close))?$/;

export async function serve(r: DoorRequest): Promise<Reply> {
  const m = ROUTE.exec(r.path);
  if (!m) return r.path === '' && r.method === 'GET' ? intro() : { status: 404, headers: {}, body: { error: 'not_found', message: `The conversation endpoint is ${ENDPOINT}.` } };
  const [, convId, action] = m;
  const method = action === 'events' ? 'GET' : 'POST';
  if (r.method !== method) return { status: 405, headers: { Allow: method }, body: { error: 'method_not_allowed' } };

  const log: store.Entry[] = [entry(`→ ${r.method} ${r.route}${r.url.search ? ' ?' + [...r.url.searchParams.keys()].join('&') : ''}`)];
  let session: Session | undefined;
  let runId: string | null = null;
  let reached = -1;
  const pass = (step: StepName, text: string) => {
    const i = LADDER.findIndex((s) => s.name === step);
    if (i > (session?.step ?? -1) && i > reached) log.push(entry(text, step, true));
    reached = Math.max(reached, i);
  };

  try {
    // session presented
    const jwt = r.headers['poppy-session'];
    need(typeof jwt === 'string' && jwt, 'no_session', 'Every request to a Poppy endpoint carries a Poppy-Session header (5.2).');
    pass('session presented', 'Poppy-Session header present.');

    // client resolved: iss is a client_id some run registered; its metadata and keys check out
    const header = await guard('session_malformed', () => decodeProtectedHeader(jwt));
    const claims = await guard('session_malformed', () => decodeJwt(jwt));
    const clientId = claims.iss;
    need(typeof clientId === 'string', 'session_malformed', 'The Session JWT has no iss; it must be your client_id.');
    const run = store.runByClient(clientId);
    need(run, 'client_refused', `client_id refused: no run registered ${clientId}. POST {"handle": ..., "client_id": "${clientId}"} to ${BASE_URL}/pg/runs first.`);
    const client = await resolveClient(clientId, log);
    pass('client resolved', `Client ${new URL(clientId).host}: metadata and ${client.keys.length} key(s) fetched and valid.`);

    // delegation valid (5.2, in its order)
    const dlg = header.poppy_dlg;
    need(typeof dlg === 'string', 'delegation_missing', 'The Session JWT header has no poppy_dlg. Session JWTs are signed with a delegated key, never directly with a jwks_uri key.');
    const dh = await guard('delegation_invalid', () => decodeProtectedHeader(dlg));
    const signer = client.keys.find((k) => k.kid === dh.kid);
    need(signer, 'delegation_invalid', `No key in jwks_uri has kid ${JSON.stringify(dh.kid)}, the delegation's kid.`);
    const { payload: d } = await guard('delegation_invalid', async () =>
      jwtVerify(dlg, await importJWK(signer, dh.alg), { typ: 'poppy-delegation+jwt', algorithms: ['ES256', 'PS384'], requiredClaims: ['iat', 'exp', 'jti'] }),
    );
    need(d.iss === clientId, 'delegation_invalid', `The delegation's iss must be the Session JWT's iss, ${clientId}.`);
    need(d.exp! - d.iat! <= 86_400, 'delegation_invalid', 'A delegation lasts at most 24 hours: exp - iat must be ≤ 86400.');
    const cnf = (d as JWTPayload & { cnf?: { jwk?: JWK } }).cnf?.jwk;
    need(cnf && typeof cnf === 'object' && PRIVATE_MEMBERS.every((k) => !(k in cnf)), 'delegation_invalid', 'The delegation needs cnf.jwk, a public key with no private members.');
    runId = run.id; // the client's own key vouched for this request: from here it counts on the run's row
    pass('delegation valid', `Delegation from key ${tail(String(dh.kid))} verifies; it expires in ${Math.round((d.exp! - nowS()) / 60)} minutes.`);

    // session valid (5.3)
    need(header.kid === (await calculateJwkThumbprint(cnf)), 'session_signature', "The Session JWT's kid must be the RFC 7638 thumbprint of the delegated key.");
    const { payload: s } = await guard('session_signature', async () => jwtVerify(jwt, await importJWK(cnf, 'ES256'), { typ: 'poppy-session+jwt', algorithms: ['ES256'] }));
    for (const c of ['sid', 'sub', 'htm', 'htu', 'jti']) need(typeof s[c] === 'string' && s[c], 'session_claims', `The Session JWT needs ${c}.`);
    need(typeof s.iat === 'number', 'session_claims', 'The Session JWT needs iat.');
    need(ID.test(s.sid as string), 'session_claims', 'sid uses the Conversation ID characters: 1 to 256 of A-Z a-z 0-9 - _.');
    need(s.aud === ISSUER, 'aud_mismatch', `aud must be the Company's identifier, its issuer ${ISSUER}, as a single string.`);
    const htu = `${r.url.origin}${r.url.pathname}`;
    need(s.htm === r.method, 'htu_mismatch', `htm must be ${r.method}.`);
    need(URL.canParse(s.htu as string) && `${new URL(s.htu as string).origin}${new URL(s.htu as string).pathname}` === htu, 'htu_mismatch', `htu must be ${htu}, without query or fragment.`);
    need(Math.abs(nowS() - (s.iat as number)) <= IAT_WINDOW_S, 'iat_out_of_window', `iat must be within ${IAT_WINDOW_S} seconds of now. Sign a fresh Session JWT for each request.`);
    const auth = /^(Bearer|DPoP) (.+)$/i.exec(String(r.headers.authorization ?? ''));
    const token = auth?.[2];
    need(token ? s.ath === sha256(token) : s.ath === undefined, 'ath_mismatch', token ? 'ath must be the base64url SHA-256 of the access token sent.' : 'ath must be absent when no access token is sent.');
    const key = `${clientId}|${s.sid}`;
    session = sessions.get(key);
    need(!session || (session.sub === s.sub && session.agentId === s.agent_id), 'sub_mismatch', 'A Session keeps the same sub and agent_id in every Session JWT. Start a new sid for another User.');
    if (!session) {
      const attempt = store.newAttempt({ door: 'poppy', runId, nonce: null, nonceExpires: null, step: -1, timeline: [] });
      session = { sub: s.sub as string, agentId: s.agent_id, account: null, attempt, step: -1, runId };
      sessions.set(key, session);
    }
    pass('session valid', `Session ${tail(s.sid as string)} for User ${tail(s.sub as string)}: signature, aud, htm/htu, iat and ath check out.`);
    const handle = store.handleOf(runId);

    // signed in: an access token from the issuer, issued to this client
    let scoped = false;
    if (token) {
      const { payload: t } = await guard('token_invalid', () => jwtVerify(token, issuerKeys, { issuer: ISSUER, audience: BASE_URL }));
      need((t.azp ?? t.client_id) === clientId, 'token_other_client', 'The access token was issued to another client_id. Use a token issued to the Session JWT\'s iss.');
      const jkt = (t as { cnf?: { jkt?: string } }).cnf?.jkt;
      if (jkt) {
        const proof = r.headers.dpop;
        need(auth![1].toLowerCase() === 'dpop' && typeof proof === 'string', 'dpop_invalid', 'The access token is DPoP-bound: send Authorization: DPoP <token> and a DPoP proof.');
        const { payload: p, protectedHeader: ph } = await guard('dpop_invalid', () => jwtVerify(proof, EmbeddedJWK, { typ: 'dpop+jwt' }));
        need((await calculateJwkThumbprint(ph.jwk!)) === jkt, 'dpop_invalid', "The DPoP proof's key isn't the one the token is bound to.");
        need(p.htm === r.method && p.htu === htu && p.ath === sha256(token) && Math.abs(nowS() - (p.iat ?? 0)) <= IAT_WINDOW_S, 'dpop_invalid', 'The DPoP proof needs this htm and htu, the token\'s ath, and a fresh iat.');
      }
      need(!session.account || session.account === t.sub, 'session_ended', 'This Session used another account. Start a new Session (new sid) for this one.');
      session.account = t.sub!;
      scoped = String(t.scope ?? '').split(' ').includes(SCOPE);
      pass('signed in', `Access token from the issuer, issued to this client${jkt ? ', DPoP-bound' : ''}, account ${tail(t.sub!)}${scoped ? '' : `, without scope ${SCOPE}`}.`);
    } else if (!session.account) {
      log.push(...(await issuerErrors(client)));
    }

    // the conversation
    const owner = (c: Conversation | undefined) => c && c.client === clientId && c.sub === s.sub && (!c.account || !token || c.account === session!.account);
    let conv = convId === undefined ? undefined : conversations.get(convId);
    if (convId !== undefined) {
      need(owner(conv), 'conversation_not_found', 'No conversation with that ID for this client, User and account.');
      need(!conv!.account || token, 'account_required', 'This conversation used an account; continue it signed in.');
    }
    const params = r.url.searchParams;
    const wait = params.get('wait');
    need(wait === null || /^\d+$/.test(wait), 'invalid_request', 'wait is a whole number of seconds.');
    const cursor = params.get('cursor');
    let status = 200;
    let body: Record<string, unknown>;

    if (action === 'events') {
      body = read(conv!, cursor);
    } else if (action === 'handoff' || action === 'close') {
      const c = conv!;
      need(!(action === 'handoff' && c.closed), 'conversation_closed', 'This conversation is closed.');
      if (action === 'handoff') addEvent(c, { message: { id: `msg_${randomBytes(6).toString('base64url')}`, role: 'company', author: { type: 'agent' }, text: 'Nobody works at this door; a person will never join.' } });
      else if (!c.closed) (c.closed = true), addEvent(c, { type: 'state', status: 'closed', responder: 'agent' });
      status = action === 'handoff' ? 202 : 200;
      body = state(c);
    } else {
      // POST {endpoint}, or {endpoint}/{id}/messages
      need(!conv?.closed, 'conversation_closed', 'This conversation is closed.');
      const parsed = await guard('invalid_request', () => JSON.parse(r.body || '{}'));
      need(!parsed.parent_conversation_id, 'invalid_request', 'This door offers no Direct Conversations.');
      const msg = checkMessage(parsed.message);
      const idKey = `${clientId}|${s.sub}|${msg.id}`;
      const content = JSON.stringify(msg);
      const before = accepted.get(idKey);
      if (before) {
        need(before.content === content, 'message_id_conflict', `Message ID ${msg.id} was already accepted with different content.`);
        log.push(entry(`Retry of message ${tail(msg.id)}: the original response again.`));
        status = before.status;
        body = before.body as Record<string, unknown>;
        conv = conversations.get(body.conversation_id as string);
      } else {
        if (!conv) {
          conv = { id: `cnv_${randomBytes(9).toString('base64url')}`, client: clientId, sub: s.sub as string, account: null, events: [], closed: false };
          conversations.set(conv.id, conv);
        }
        if (scoped) conv.account = session.account;
        addEvent(conv, { message: { ...msg, role: 'user' } });
        if (msg.text !== undefined || msg.data !== undefined) await companyReply(conv, msg.text, session, handle, scoped);
        status = convId === undefined ? 201 : 202;
        body = { conversation_id: conv.id, ...state(conv) };
        accepted.set(idKey, { content, status, body });
        pass('conversation started', `Conversation ${tail(conv.id)} ${convId === undefined ? 'started' : 'continued'} with message ${tail(msg.id)}.`);
        if (scoped) pass('authorized call', `Signed-in message with scope ${SCOPE}: the conversation now uses account ${tail(session.account!)}.`);
      }
      if (wait !== null) body = { ...read(conv!, cursor), ...state(conv!) };
    }

    // reply read, through: what the read handed back
    const events = (body.events ?? []) as Event[];
    const company = events.filter((e) => e.type === 'message' && (e.message as { role: string }).role === 'company');
    if (company.length) pass('reply read', `Read ${company.length} Company Agent message(s).`);
    if (company.some((e) => (e.message as { data?: { receipt?: string } }).data?.receipt)) {
      pass('reply read', 'Read the Company Agent reply.');
      pass('through', "Read the signed-in reply and its receipt. All checks passed.");
    }
    log.push(entry(`← ${status}`));
    store.finishAttempt(session.attempt, { step: reached, mode: token ? 'signed in' : 'signed out', error: null, reason: null, more: log });
    session.step = Math.max(session.step, reached);
    return { status, headers: { 'Cache-Control': 'no-store' }, body };
  } catch (e) {
    if (!(e instanceof Stop)) throw e;
    const [step, status, error] = STOPS[e.code];
    const id = session?.attempt ?? store.newAttempt({ door: 'poppy', runId, nonce: null, nonceExpires: null, step: -1, timeline: [] });
    log.push(entry(e.message, step, false), entry(`← ${status} ${error || 'challenge'} (${e.code})`));
    store.finishAttempt(id, { step: Math.max(reached, LADDER.findIndex((s) => s.name === step) - 1), mode: null, error: e.code, reason: e.message, more: log });
    if (session) session.step = Math.max(session.step, reached);
    const headers: Record<string, string> = { 'Cache-Control': 'no-store' };
    if (status === 401) headers['WWW-Authenticate'] = e.code === 'dpop_invalid' ? 'DPoP error="invalid_dpop_proof"' : e.code === 'token_invalid' ? 'Bearer error="invalid_token"' : `Bearer scope="${SCOPE}"`;
    return {
      status,
      headers,
      body: {
        ...(error && { error, error_description: e.message }),
        ...(!error && { message: e.message }),
        stopped_at: step,
        pg_stop: e.code,
        attempt: id,
        watch: `${BASE_URL}/poppy#attempt=${id}`,
      },
    };
  }
}
