/**
 * The poppy door: a Company under Personal Agent Protocol (Poppy) 0.3, as
 * published at personal-agent-protocol@6fb46d3, with a Company Agent that
 * echoes and, once you sign in, tells you which account you used.
 *
 * Discovery is at /.well-known/poppy.json and /.well-known/oauth-protected-resource.
 * The door is its own OAuth issuer (3.2), at ISSUER: it resolves each client_id
 * as a Client ID Metadata Document, so no agent registers anywhere, and signs
 * the User in with a test account (no password; nothing here is a real account).
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
import { SignJWT, calculateJwkThumbprint, decodeJwt, decodeProtectedHeader, importJWK, jwtVerify, type JWK, type JWTPayload } from 'jose';
import { BASE_URL, DEV, DID, ORIGIN, PREFIX, PRIVATE, fetchPublic, verifier, type DoorRequest } from '../lab.ts';
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

/** The Company's issuer, and so its identifier (3.2): the door's own URL. Its OAuth endpoints are below it. */
const ISSUER = `${BASE_URL}/pg/doors/poppy`;
const SCOPE = 'conversations';
const SCOPE_TEXT = 'Let the Company Agent see which account you signed in with, in a conversation';
const ENDPOINT = `${ISSUER}/conversations`;
const DOMAIN = new URL(BASE_URL).host;
/** https://{organization.domain}: the protected resource, and what access tokens are for. */
const RESOURCE = new URL(BASE_URL).origin;
const ACCESS_TTL_S = 600;
const REFRESH_TTL_S = 30 * 86_400;
const CODE_TTL_S = 60;
const CONSENT_TTL_S = 600;
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
      scopes: { [SCOPE]: SCOPE_TEXT },
      scope_hints: { [SCOPE]: { changes: 'none', personal_data: false } },
    },
    agent: { protocols: [{ type: 'poppy', endpoint: ENDPOINT }] },
  }),
  '/.well-known/oauth-protected-resource': () => ({ resource: RESOURCE, authorization_servers: [ISSUER] }),
  // RFC 8414 §3.1: the well-known segment goes between the host and the issuer's path.
  [`/.well-known/oauth-authorization-server${new URL(ISSUER).pathname}`]: () => ({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/authorize`,
    token_endpoint: `${ISSUER}/token`,
    revocation_endpoint: `${ISSUER}/revoke`,
    grant_types_supported: ['authorization_code', 'refresh_token'],
    response_types_supported: ['code'],
    code_challenge_methods_supported: ['S256'],
    token_endpoint_auth_methods_supported: ['private_key_jwt'],
    token_endpoint_auth_signing_alg_values_supported: ['ES256', 'PS384'],
    revocation_endpoint_auth_methods_supported: ['private_key_jwt'],
    scopes_supported: [SCOPE],
    authorization_response_iss_parameter_supported: true,
    client_id_metadata_document_supported: true,
    protected_resources: [RESOURCE],
  }),
};

/** Shown on the wall and served at /pg/state. */
export const INFO = {
  door: 'poppy',
  spec: { name: 'Personal Agent Protocol', version: '0.3', pinned: 'personal-agent-protocol@6fb46d3', url: SPEC_URL },
  proves: 'A Personal Agent acting for a signed-in User',
  about: `A Company with a Company Agent at ${ENDPOINT}. Start at /.well-known/poppy.json. Register your client_id with your run; sign in at the door's own issuer, ${ISSUER}, with scope ${SCOPE}.`,
  builds_on: [
    { name: 'OAuth Client ID Metadata Document (client_id is a URL)', url: 'https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/' },
    { name: 'RFC 9728, OAuth 2.0 Protected Resource Metadata', url: 'https://www.rfc-editor.org/rfc/rfc9728' },
    { name: 'RFC 8414, OAuth 2.0 Authorization Server Metadata', url: 'https://www.rfc-editor.org/rfc/rfc8414' },
    { name: 'RFC 7636, PKCE', url: 'https://www.rfc-editor.org/rfc/rfc7636' },
    { name: 'RFC 7523, private_key_jwt client assertions', url: 'https://www.rfc-editor.org/rfc/rfc7523' },
    { name: 'RFC 9207, iss in the authorization response', url: 'https://www.rfc-editor.org/rfc/rfc9207' },
    { name: 'RFC 7009, token revocation', url: 'https://www.rfc-editor.org/rfc/rfc7009' },
  ],
  ladder: LADDER.map((s) => ({ name: s.name, url: `${SPEC_SITE}#${s.ref}` })),
  issuer: ISSUER,
  endpoint: ENDPOINT,
};

/** A Buffer body is sent as HTML. */
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
const rand = (n = 24) => randomBytes(n).toString('base64url');
const sha256 = (s: string) => createHash('sha256').update(s).digest('base64url');
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];
const nowS = () => Math.floor(Date.now() / 1000);

// ---- Clients: client_id is a URL serving client metadata (4.1) ----

type Client = { at: number; meta: { client_id: string; client_name?: string; jwks_uri: string; redirect_uris: string[] }; keys: JWK[] };
// ponytail: in-memory caches and conversations, lost on restart and unbounded; move to SQLite with a TTL before real traffic.
const clients = new Map<string, Client>();

const allowedScheme = (u: URL) => u.protocol === 'https:' || (DEV && u.protocol === 'http:');

/** Why a client_id can't be registered with a run, or null. */
export function clientIdProblem(v: unknown): string | null {
  if (typeof v !== 'string' || v.length > 2048) return 'client_id must be a URL string: the HTTPS URL of your client metadata document.';
  const u = URL.canParse(v) ? new URL(v) : null;
  if (!u || !allowedScheme(u) || u.hash || u.username) return `client_id must be an HTTPS URL with no fragment${DEV ? ' (http is allowed while BASE_URL is on localhost)' : ''}.`;
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
  const res = await guard(code, () => fetchPublic(url, { redirect: 'manual', signal: AbortSignal.timeout(5000), headers: { accept: 'application/json' } }));
  need(res.status === 200, code, `Fetching ${what} (${u}) returned ${res.status}; it must return 200 without redirecting.`);
  const text = await res.text();
  need(text.length <= 64_000, code, `${what} is over 64 kB.`);
  return guard(code, () => JSON.parse(text));
}

/** A loopback redirect URI, for an app on the User's computer (RFC 8252 §7.3). */
const LOOPBACK = /^http:\/\/(127\.0\.0\.1|\[::1\])(:\d+)?\//;

/** Fetches and checks a client's metadata and keys. */
async function resolveClient(clientId: string): Promise<Client> {
  const cached = clients.get(clientId);
  if (cached && Date.now() - cached.at < CLIENT_CACHE_MS) return cached;
  const code = 'client_metadata_invalid';
  const meta = await fetchJson(clientId, code, 'The client metadata document');
  need(meta && typeof meta === 'object', code, 'The client metadata document must be a JSON object.');
  need(meta.client_id === clientId, code, `client_id in the document (${JSON.stringify(meta.client_id)}) must equal the URL it was fetched from, ${clientId}.`);
  const host = new URL(clientId).hostname.toLowerCase();
  const sameDomain = (u: unknown) => typeof u === 'string' && URL.canParse(u) && allowedScheme(new URL(u)) && new URL(u).hostname.toLowerCase() === host;
  need(sameDomain(meta.jwks_uri), code, `jwks_uri must be an HTTPS URL on ${host}.`);
  need(Array.isArray(meta.redirect_uris) && meta.redirect_uris.length > 0, code, 'redirect_uris must be a non-empty list.');
  for (const r of meta.redirect_uris) need(sameDomain(r) || LOOPBACK.test(r), code, `Redirect URI ${r} must be an HTTPS URL on ${host}, or a loopback redirect URI.`);
  need(meta.token_endpoint_auth_method === 'private_key_jwt', code, `token_endpoint_auth_method must be private_key_jwt; got ${JSON.stringify(meta.token_endpoint_auth_method)}.`);

  const jwks = await fetchJson(meta.jwks_uri, 'jwks_invalid', 'jwks_uri');
  const keys: JWK[] = jwks?.keys;
  need(Array.isArray(keys) && keys.length > 0, 'jwks_invalid', 'jwks_uri must return {"keys": [...]} with at least one key.');
  need(keys.every((k) => PRIVATE_MEMBERS.every((m) => !(m in k))), 'jwks_invalid', 'jwks_uri contains private key members. Publish public keys only, and replace the leaked key.');

  const client: Client = { at: Date.now(), meta, keys };
  clients.set(clientId, client);
  return client;
}

/** Called when a run is started with a client_id: checks its metadata now, so problems show before the first request. */
export async function register(clientId: string) {
  try {
    await resolveClient(clientId);
    return { client_metadata: 'valid', discovery: `${ORIGIN}/.well-known/poppy.json` };
  } catch (e) {
    if (!(e instanceof Stop)) throw e;
    return { client_metadata: 'invalid', problem: e.message, next: 'Fix it; the door fetches it again on your first Session request, and at sign-in.' };
  }
}

// ---- The door's own authorization server (3.2, 4.1, 4.2, 4.4, 4.6, 4.7) ----
// No registration: a client is whatever its client_id URL says it is (CIMD). Tokens are opaque
// strings the door looks up, since the door is also the only resource that accepts them.

type Grant = { client: string; account: string; scope: string; exp: number };
// ponytail: in-memory, like the conversations; a restart signs everyone out. Move to SQLite with the rest.
const consents = new Map<string, Omit<Grant, 'account'> & { redirectUri: string; state: string | null; challenge: string }>();
const codes = new Map<string, Grant & { redirectUri: string; challenge: string }>();
const refreshTokens = new Map<string, Grant>();
const accessTokens = new Map<string, Grant & { refresh: string }>();

/** Sets k, dropping expired entries first. */
// ponytail: O(n) per insert, fine for a test door; a timer or a TTL store if these maps grow large.
function put<V extends { exp: number }>(m: Map<string, V>, k: string, v: V) {
  for (const [key, x] of m) if (x.exp < Date.now()) m.delete(key);
  m.set(k, v);
}
const expIn = (s: number) => Date.now() + s * 1000;

class OAuthError extends Error {
  error: string;
  status: number;
  constructor(error: string, message: string, status = 400) {
    super(message);
    this.error = error;
    this.status = status;
  }
}
function fail(error: string, message: string, status = 400): never {
  throw new OAuthError(error, message, status);
}
function oauth(cond: unknown, error: string, message: string, status = 400): asserts cond {
  if (!cond) fail(error, message, status);
}

/** Sign-in happens on other requests than the conversation; what happened there joins the client's next attempt. */
const signInNotes = new Map<string, store.Entry[]>();
function note(clientId: unknown, text: string, ok: boolean) {
  if (typeof clientId !== 'string' || !store.runByClient(clientId)) return;
  signInNotes.set(clientId, [...(signInNotes.get(clientId) ?? []).slice(-19), entry(`At the issuer: ${text}`, undefined, ok ? undefined : false)]);
}

const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
/** A sign-in page. It can't be framed, so nobody can trick a click on Allow. */
const page = (status: number, title: string, text: string, form = ''): Reply => ({
  status,
  // The server's Content-Security-Policy, with frame-ancestors 'none', covers it too.
  headers: { 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY' },
  body: Buffer.from(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${esc(title)}</title><link rel="stylesheet" href="${PREFIX}/style.css">
<main class="pg"><h1>${esc(title)}</h1><p>${esc(text)}</p>${form}</main>`),
});

/** Sends the User back to the client, always with iss (RFC 9207). */
function back(redirectUri: string, state: string | null, params: Record<string, string>): Reply {
  const u = new URL(redirectUri);
  for (const [k, v] of Object.entries({ ...params, ...(state !== null && { state }), iss: ISSUER })) u.searchParams.set(k, v);
  return { status: 302, headers: { Location: u.href, 'Cache-Control': 'no-store' }, body: Buffer.alloc(0) };
}

/** redirect_uri matches a registered one exactly, or differs only in the port of a loopback URI (4.2). */
function redirectMatches(registered: string, given: string) {
  if (registered === given) return true;
  if (!LOOPBACK.test(registered) || !LOOPBACK.test(given)) return false;
  const [a, b] = [new URL(registered), new URL(given)];
  a.port = b.port = '';
  return a.href === b.href;
}

/** GET /authorize: Direct Sign-In (4.2) starts here, and shows the consent page. */
async function authorize(q: URLSearchParams): Promise<Reply> {
  // Until client_id and redirect_uri check out, errors stay on a page and never redirect (RFC 6749 §4.1.2.1).
  const clientId = q.get('client_id') ?? '';
  const refuse = (text: string) => (note(clientId, `sign-in refused: ${text}`, false), page(400, 'Sign-in refused', text));
  const problem = clientIdProblem(clientId);
  if (problem) return refuse(`invalid_client: ${problem}`);
  let client: Client;
  try {
    client = await resolveClient(clientId);
  } catch (e) {
    if (!(e instanceof Stop)) throw e;
    return refuse(`invalid_client: ${e.message}`);
  }
  const redirectUri = q.get('redirect_uri') ?? '';
  if (!client.meta.redirect_uris.some((r) => redirectMatches(r, redirectUri))) return refuse(`redirect_uri ${redirectUri} isn't one of the client's redirect_uris.`);

  const state = q.get('state');
  const error = (error: string, text: string) => (note(clientId, `${error}: ${text}`, false), back(redirectUri, state, { error, error_description: text }));
  if (q.get('response_type') !== 'code') return error('unsupported_response_type', 'response_type must be code.');
  const challenge = q.get('code_challenge') ?? '';
  if (q.get('code_challenge_method') !== 'S256' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)) return error('invalid_request', 'PKCE is required: code_challenge_method S256 and a code_challenge (RFC 7636).');
  const scopes = [...new Set((q.get('scope') ?? '').split(' ').filter(Boolean))];
  if (!scopes.length || scopes.some((s) => s !== SCOPE)) return error('invalid_scope', `scope is required, and this Company has one: ${SCOPE} (4.7).`);

  const id = rand();
  put(consents, id, { client: clientId, scope: scopes.join(' '), redirectUri, state, challenge, exp: expIn(CONSENT_TTL_S) });
  note(clientId, 'consent page shown.', true);
  return page(200, 'Sign in to the proving ground', `${new URL(clientId).host} asks to act for you here, with scope ${SCOPE}: ${SCOPE_TEXT}. This is a test sign-in: no password, and nothing here is a real account.`, `
<form method="post" action="${ISSUER}/authorize">
<input type="hidden" name="consent" value="${id}">
<p><label>Test account <input name="account" value="test-user" pattern="[a-z0-9-]{1,31}" required></label></p>
<p><button name="decision" value="allow">Allow</button> <button name="decision" value="deny" formnovalidate>Deny</button></p>
</form>`);
}

/** POST /authorize: the User's click on the consent page. */
function decide(form: URLSearchParams): Reply {
  const id = form.get('consent') ?? '';
  const c = consents.get(id);
  if (!c || c.exp < Date.now()) return page(400, 'This sign-in expired', 'Start again from your agent.');
  const allow = form.get('decision') === 'allow';
  const account = form.get('account') ?? '';
  if (allow && !/^[a-z0-9-]{1,31}$/.test(account)) return page(400, 'Pick a test account', 'An account name is 1 to 31 lowercase letters, digits and hyphens. Go back and try again.');
  consents.delete(id);
  if (!allow) return note(c.client, 'the User declined.', false), back(c.redirectUri, c.state, { error: 'access_denied' });
  const code = rand();
  put(codes, code, { client: c.client, account, scope: c.scope, redirectUri: c.redirectUri, challenge: c.challenge, exp: expIn(CODE_TTL_S) });
  note(c.client, `the User approved ${c.scope} as account ${account}.`, true);
  return back(c.redirectUri, c.state, { code });
}

/** private_key_jwt (4.1): the assertion is signed by a jwks_uri key, and addressed to the issuer and nothing else. */
async function authenticate(form: URLSearchParams): Promise<string> {
  oauth(form.get('client_assertion_type') === 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', 'invalid_client', 'Authenticate with private_key_jwt: client_assertion_type urn:ietf:params:oauth:client-assertion-type:jwt-bearer and a client_assertion (4.1).', 401);
  const assertion = form.get('client_assertion') ?? '';
  let header, claims;
  try {
    [header, claims] = [decodeProtectedHeader(assertion), decodeJwt(assertion)];
  } catch {
    fail('invalid_client', 'client_assertion is not a JWT.', 401);
  }
  const clientId = claims.iss;
  oauth(typeof clientId === 'string' && !clientIdProblem(clientId), 'invalid_client', "The assertion's iss must be your client_id.", 401);
  oauth(!form.has('client_id') || form.get('client_id') === clientId, 'invalid_client', "client_id must be the assertion's iss.", 401);
  let client: Client;
  try {
    client = await resolveClient(clientId);
  } catch (e) {
    if (!(e instanceof Stop)) throw e;
    fail('invalid_client', e.message, 401);
  }
  const key = header.kid ? client.keys.find((k) => k.kid === header.kid) : client.keys.length === 1 ? client.keys[0] : undefined;
  oauth(key, 'invalid_client', `No key in jwks_uri has kid ${JSON.stringify(header.kid)}.`, 401);
  try {
    await jwtVerify(assertion, await importJWK(key, header.alg), { algorithms: ['ES256', 'PS384'], issuer: clientId, subject: clientId, requiredClaims: ['exp', 'iat', 'jti'] });
  } catch (e) {
    fail('invalid_client', `The client assertion doesn't verify: ${(e as Error).message}`, 401);
  }
  oauth(claims.aud === ISSUER, 'invalid_client', `The assertion's aud must be the issuer, ${ISSUER}, as a single string; got ${JSON.stringify(claims.aud)} (4.1).`, 401);
  return clientId;
}

/** POST /token: the authorization code (4.2) or a refresh token (4.4) for tokens (4.7). */
async function token(form: URLSearchParams): Promise<Reply> {
  const clientId = await authenticate(form);
  const issue = (g: Grant, refresh: string, newRefresh: boolean): Reply => {
    const access = rand(32);
    put(accessTokens, access, { ...g, refresh, exp: expIn(ACCESS_TTL_S) });
    note(clientId, `tokens issued for account ${g.account}, scope ${g.scope}.`, true);
    return { status: 200, headers: { 'Cache-Control': 'no-store' }, body: { access_token: access, token_type: 'Bearer', expires_in: ACCESS_TTL_S, ...(newRefresh && { refresh_token: refresh }), scope: g.scope } };
  };
  const grantType = form.get('grant_type');
  if (grantType === 'authorization_code') {
    const code = form.get('code') ?? '';
    const c = codes.get(code);
    codes.delete(code);
    oauth(c && c.exp > Date.now() && c.client === clientId, 'invalid_grant', 'The code is unknown, used, expired, or was issued to another client.');
    oauth(form.get('redirect_uri') === c.redirectUri, 'invalid_grant', 'redirect_uri must be the one sign-in started with.');
    oauth(sha256(form.get('code_verifier') ?? '') === c.challenge, 'invalid_grant', "code_verifier doesn't match the code_challenge (S256).");
    const g = { client: clientId, account: c.account, scope: c.scope, exp: expIn(REFRESH_TTL_S) };
    const refresh = rand(32);
    put(refreshTokens, refresh, g);
    return issue(g, refresh, true);
  }
  if (grantType === 'refresh_token') {
    const refresh = form.get('refresh_token') ?? '';
    const r = refreshTokens.get(refresh);
    oauth(r && r.exp > Date.now() && r.client === clientId, 'invalid_grant', 'The refresh token is unknown, expired, revoked, or was issued to another client.');
    // Fewer scopes may be asked for, never more (4.4). Using it doesn't extend its life, and it isn't rotated.
    const scope = form.get('scope') ?? r.scope;
    oauth(scope.split(' ').every((s) => r.scope.split(' ').includes(s)), 'invalid_scope', `This refresh token has scope ${r.scope}.`);
    return issue({ ...r, scope }, refresh, false);
  }
  fail('unsupported_grant_type', 'grant_type must be authorization_code or refresh_token.');
}

/** POST /revoke (4.6, RFC 7009): a refresh token goes with every access token made from it. */
async function revoke(form: URLSearchParams): Promise<Reply> {
  const clientId = await authenticate(form);
  const t = form.get('token') ?? '';
  if (refreshTokens.get(t)?.client === clientId) {
    refreshTokens.delete(t);
    for (const [k, a] of accessTokens) if (a.refresh === t) accessTokens.delete(k);
    note(clientId, 'refresh token revoked.', true);
  }
  if (accessTokens.get(t)?.client === clientId) accessTokens.delete(t);
  return { status: 200, headers: { 'Cache-Control': 'no-store' }, body: {} };
}

async function oauthEndpoint(r: DoorRequest): Promise<Reply> {
  const form = new URLSearchParams(r.method === 'POST' ? r.body : r.url.search);
  try {
    if (r.path === '/authorize') return r.method === 'GET' ? await authorize(form) : decide(form);
    if (r.method !== 'POST') return { status: 405, headers: { Allow: 'POST' }, body: { error: 'method_not_allowed' } };
    return r.path === '/token' ? await token(form) : await revoke(form);
  } catch (e) {
    if (!(e instanceof OAuthError)) throw e;
    let clientId: unknown = form.get('client_id');
    try { clientId ??= decodeJwt(form.get('client_assertion') ?? '').iss; } catch { /* not a JWT */ }
    note(clientId, `${r.path.slice(1)} refused, ${e.error}: ${e.message}`, false);
    return { status: e.status, headers: { 'Cache-Control': 'no-store' }, body: { error: e.error, error_description: e.message } };
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
  addEvent(c, { message: { id: `msg_${randomBytes(6).toString('base64url')}`, role: 'company', author: { type: 'agent' }, text: `${said}You're signed in, to account ${c.account}. That's the door: here's your receipt.`, data: { receipt } } });
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
    discovery: `${ORIGIN}/.well-known/poppy.json`,
    register: `POST {"handle": "<your-handle>", "client_id": "<your client metadata URL>"} to ${BASE_URL}/pg/runs. The door refuses Session JWTs from a client_id no run registered.`,
    spec: SPEC_URL,
    instructions: `${BASE_URL}/llms.txt`,
    wall: `${BASE_URL}/poppy`,
  },
});

// ---- The door ----

const ROUTE = /^\/conversations(?:\/([^/]+)\/(messages|events|handoff|close))?$/;

export async function serve(r: DoorRequest): Promise<Reply> {
  if (['/authorize', '/token', '/revoke'].includes(r.path)) return oauthEndpoint(r);
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
    const client = await resolveClient(clientId);
    pass('client resolved', `Client ${new URL(clientId).host}: metadata and ${client.keys.length} key(s) fetched and valid.`);
    log.push(...(signInNotes.get(clientId) ?? []));
    signInNotes.delete(clientId);

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
    const token = /^Bearer (.+)$/i.exec(String(r.headers.authorization ?? ''))?.[1];
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

    // signed in: an access token from the door's issuer, issued to this client
    let scoped = false;
    if (token) {
      const t = accessTokens.get(token);
      need(t && t.exp > Date.now(), 'token_invalid', 'The access token is unknown, expired or revoked. Refresh it (4.4), or sign in again.');
      need(t.client === clientId, 'token_other_client', "The access token was issued to another client_id. Use a token issued to the Session JWT's iss.");
      need(!session.account || session.account === t.account, 'session_ended', 'This Session used another account. Start a new Session (new sid) for this one.');
      session.account = t.account;
      scoped = t.scope.split(' ').includes(SCOPE);
      pass('signed in', `Access token from the issuer, issued to this client, account ${t.account}${scoped ? '' : `, without scope ${SCOPE}`}.`);
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
        if (scoped) pass('authorized call', `Signed-in message with scope ${SCOPE}: the conversation now uses account ${session.account}.`);
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
    if (status === 401) headers['WWW-Authenticate'] = e.code === 'token_invalid' ? 'Bearer error="invalid_token"' : `Bearer scope="${SCOPE}"`;
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
