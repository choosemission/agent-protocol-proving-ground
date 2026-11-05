/**
 * The Lab test person server for the aauth door: a minimal PS (AAuth -11 Appendix "A Minimal
 * Person Server") for agents that have none of their own. Any PS will do at the door; this one
 * exists so an agent can climb the whole ladder without running one.
 *
 * Its identifier is the Lab's origin, shared with the door's resource role and told apart by the
 * well-known document (`aauth-person.json`), as 4.3 allows. It issues only for the proving ground,
 * and only for test accounts: whoever opens the interaction page picks an account name, with no
 * password. Nothing here is a real person.
 *
 *   POST {PS}/person          person token (7.1), after binding the agent to a test account (13.14)
 *   POST {PS}/token           auth token (7.2) for a resource token whose aud is this PS (three-party)
 *   GET  {PS}/pending/<id>    the deferred response (11.8), polled with a signed GET by the same agent
 *   GET  {PS}/interact        the interaction page (11.6.3): ?code=XXXX-XXXX
 *   POST {PS}/interact        the person's decision
 *   GET  {PS}/jwks.json       its signing key
 *
 * ponytail: bindings, consents and pending requests live in memory; a restart forgets them all.
 */
import { createHmac, randomBytes } from 'node:crypto';
import { SignJWT, decodeJwt, type JWK } from 'jose';
import { BASE_URL, ORIGIN, PREFIX, ed25519, type DoorRequest } from '../lab.ts';
import { Fail, holdLocally, sfString, sigErrorResponse, thumbprint, verifyRequest, verifyToken, type SignedRequest, type VerifiedRequest } from './aauth-sig.ts';

/** The PS's identifier: the origin (11.1.1 allows scheme and host only). */
export const ID = ORIGIN;
export const PS = `${BASE_URL}/pg/doors/aauth/ps`;
const PENDING_TTL_MS = 10 * 60_000;
const ACCOUNT = /^[a-z0-9-]{1,31}$/;

const key = await ed25519('aauth-ps', 'lab-ps-1');
holdLocally(ID, 'aauth-person.json', () => [key.jwk]);
export const jwks = () => ({ keys: [key.jwk] });

export const METADATA = {
  issuer: ID,
  jwks_uri: `${PS}/jwks.json`,
  person_token_endpoint: `${PS}/person`,
  auth_token_endpoint: `${PS}/token`,
  name: 'Agent Lab test person server',
  description: 'A **test** person server for the Agent Lab proving ground. It issues only for the proving ground, for test accounts with no password. Nothing here is a real person.',
  accept_signature_algs: ['Ed25519', 'ES256'],
};

type Reply = { status: number; headers: Record<string, string>; body: unknown };
export type Hooks = {
  /** Adds a line to the timeline of the attempt using this signing key, if the door knows it. */
  note: (thumbprint: string | null, text: string, ok: boolean) => void;
  /** The resource's scope descriptions, for the consent page. */
  scopes: Record<string, string>;
  /** The resource identifier this PS issues for. */
  resource: string;
};

const nowS = () => Math.floor(Date.now() / 1000);
const tail = (s: string) => `…${s.slice(-4)}`;
const problem = (status: number, error: string, detail: string, headers: Record<string, string> = {}): Reply => ({
  status, headers: { 'Content-Type': 'application/problem+json', 'Cache-Control': 'no-store', ...headers }, body: { error, detail },
});

/** Agent (iss, sub) → the test account it acts for. Once bound, never another (13.14). */
const bindings = new Map<string, string>();
/** `${agent}|${resource}|${scope}` the account approved. */
const consents = new Set<string>();
type Pending = {
  id: string; agent: string; thumbprint: string; kind: 'bind' | 'consent'; code: string; exp: number;
  status: 'pending' | 'interacting' | 'done' | 'gone'; result?: Reply;
  /** What to issue once the person has decided. */
  issue: (account: string) => Promise<Reply>;
  show: { agent: string; provider: string; scope?: string; justification?: string };
};
const pending = new Map<string, Pending>();
const byCode = new Map<string, string>();
function sweep() {
  for (const [id, p] of pending) if (p.exp < Date.now() - PENDING_TTL_MS) pending.delete(id), byCode.delete(p.code);
}

/** Directed sub (14.1): one per account and resource, never varying with the agent or its key. */
const directed = (account: string, resource: string) => createHmac('sha256', key.secret).update(`${account}\n${resource}`).digest().subarray(0, 16).toString('base64url');

/** An interaction code (11.6.3.1): 40 bits of Crockford base32, shown as XXXX-XXXX. */
const CROCKFORD = '0123456789ABCDEFGHJKMNPQRSTVWXYZ';
function newCode() {
  const n = randomBytes(5).reduce((a, b) => (a << 8n) | BigInt(b), 0n);
  return Array.from({ length: 8 }, (_, i) => CROCKFORD[Number((n >> BigInt(35 - i * 5)) & 31n)]).join('');
}
const normalize = (c: string) => c.replace(/-/g, '').toUpperCase().replace(/[IL]/g, '1').replace(/O/g, '0');
const display = (c: string) => `${c.slice(0, 4)}-${c.slice(4)}`;

/** The request as the verifier sees it: @authority is the public host, @path the full public path. */
export const signed = (r: DoorRequest): SignedRequest => ({
  method: r.method, authority: new URL(BASE_URL).host, path: r.url.pathname, query: r.url.search.slice(1), scheme: r.url.protocol.slice(0, -1), headers: r.headers, bytes: r.bytes,
});

/** The cnf thumbprint of whatever token Signature-Key carries, unverified: only to find the attempt a refusal belongs on. */
export async function claimedThumbprint(r: DoorRequest): Promise<string | null> {
  try {
    const jwt = /jwt="([^"]+)"/.exec(String(r.headers['signature-key'] ?? ''))?.[1];
    const j = (decodeJwt(jwt!).cnf as { jwk?: JWK }).jwk!;
    return await thumbprint(j);
  } catch {
    return null;
  }
}

/** Pages for the person. They can't be framed, so nobody can trick a click on Allow. */
const esc = (s: string) => s.replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const page = (status: number, title: string, html: string): Reply => ({
  status,
  headers: { 'Cache-Control': 'no-store', 'X-Frame-Options': 'DENY' },
  body: Buffer.from(`<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>${esc(title)}</title><link rel="stylesheet" href="${PREFIX}/style.css">
<main><p class="test-banner"><strong>Test person server.</strong> This is the Agent Lab's stand-in for a real person server: no sign-in, no real people, and it issues only for the proving ground. <a href="${BASE_URL}/aauth#ps-guide">What a real one does</a></p>
<h1>${esc(title)}</h1>${html}</main>`),
});
/** What a real PS would do at this point, beside what this one does. */
const REAL = {
  bind: `<div class="aside"><p class="label">A real person server here</p><p>would first sign you in to your own account, with a password or passkey, because a PS must authenticate whoever approves (13.13). It would show the agent's provider by name, from its metadata, and the resource's name and description. You would link this agent to yourself once, and later requests could be answered without asking you.</p></div>`,
  consent: `<div class="aside"><p class="label">A real person server here</p><p>would show what the resource says the scope means, and mark the agent's justification as unchecked. It would remember your answer, so you aren't asked again, and might reach you by push notification instead of a code. With missions, it would also check the request fits the task you approved.</p></div>`,
};

// ---- Endpoints ----

/** Verifies a PS request: signed with an agent token, and with content-digest and content-type covered on a POST (11.3.3.1). */
async function caller(r: DoorRequest, hooks: Hooks): Promise<VerifiedRequest> {
  const v = await verifyRequest(signed(r), { require: r.method === 'POST' ? ['content-digest', 'content-type'] : [] });
  if (v.kind !== 'agent') throw new Fail('agent', 'invalid_jwt', 'token_unreadable', `The Lab PS's endpoints take your agent token in Signature-Key, not a ${v.kind} token (7).`);
  return v;
}

function body(r: DoorRequest) {
  try {
    const b = JSON.parse(r.body);
    if (b && typeof b === 'object' && !Array.isArray(b)) return b as Record<string, unknown>;
  } catch { /* below */ }
  throw new PsError(problem(400, 'invalid_request', 'The body must be a JSON object.'));
}
class PsError extends Error {
  reply: Reply;
  constructor(reply: Reply) {
    super((reply.body as { detail?: string }).detail ?? 'refused');
    this.reply = reply;
  }
}
const refuse = (status: number, error: string, detail: string): never => { throw new PsError(problem(status, error, detail)); };

/** 202 with requirement=interaction (11.6.3), the person's next step. */
function interaction(v: VerifiedRequest, kind: Pending['kind'], show: Pending['show'], issue: Pending['issue'], capabilities: unknown, hooks: Hooks): Reply {
  if (!Array.isArray(capabilities) || !capabilities.includes('interaction')) {
    hooks.note(v.thumbprint, 'refused, user_unreachable: the agent did not declare the interaction capability.', false);
    return problem(403, 'user_unreachable', 'This PS has to reach the person, and has no channel of its own: send "capabilities": ["interaction"] and send the person to the interaction URL it returns (7.1, 11.7).');
  }
  sweep();
  const id = randomBytes(18).toString('base64url');
  const code = newCode();
  pending.set(id, { id, agent: `${v.claims.iss}|${v.claims.sub}`, thumbprint: v.thumbprint, kind, code, exp: Date.now() + PENDING_TTL_MS, status: 'pending', issue, show });
  byCode.set(code, id);
  hooks.note(v.thumbprint, `${kind === 'bind' ? 'the agent is new here: asked the person which test account it acts for' : `asked the person to consent to ${show.scope}`} (interaction code ${display(code)}).`, true);
  return deferred(pending.get(id)!);
}
const deferred = (p: Pending): Reply => ({
  status: 202,
  headers: {
    Location: `${PS}/pending/${p.id}`,
    'Retry-After': '1',
    'Cache-Control': 'no-store',
    'Content-Type': 'application/json',
    ...(p.status === 'pending' && { 'AAuth-Requirement': `requirement=interaction;url=${sfString(`${PS}/interact`)};code=${sfString(display(p.code))}` }),
  },
  body: { status: p.status === 'interacting' ? 'interacting' : 'pending' },
});

/** POST {PS}/person (7.1). */
async function person(r: DoorRequest, hooks: Hooks): Promise<Reply> {
  const v = await caller(r, hooks);
  const b = body(r);
  if (b.resource !== hooks.resource) refuse(400, 'invalid_request', `resource must be the proving ground, ${hooks.resource}: this test PS issues for nothing else.`);
  if (b.mission_s256 !== undefined) refuse(400, 'invalid_request', 'This PS has no mission_endpoint, so no missions: send no mission_s256.');
  if (b.subagent_token !== undefined || b.upstream_token !== undefined) refuse(400, 'invalid_request', 'This PS handles neither sub-agents nor call chaining.');
  const agent = `${v.claims.iss}|${v.claims.sub}`;
  const resource = hooks.resource;
  const agentExp = v.claims.exp as number;
  const cnf = v.cnf!;
  const issue = async (account: string): Promise<Reply> => {
    const iat = nowS();
    const exp = Math.min(iat + 3600, agentExp);
    const jti = randomBytes(12).toString('base64url');
    const token = await new SignJWT({ dwk: 'aauth-person.json', aud: resource, sub: directed(account, resource), cnf: { jwk: cnf } })
      .setProtectedHeader({ alg: 'Ed25519', typ: 'aa-person+jwt', kid: key.kid })
      .setIssuer(ID).setJti(jti).setIssuedAt(iat).setExpirationTime(exp).sign(key.key);
    hooks.note(v.thumbprint, `person token issued for test account ${account}, to ${resource}, expiring in ${Math.round((exp - iat) / 60)} minutes.`, true);
    return { status: 200, headers: { 'Cache-Control': 'no-store' }, body: { person_token: token, expires_in: exp - iat } };
  };
  const account = bindings.get(agent);
  if (account) return issue(account);
  return interaction(v, 'bind', { agent: String(v.claims.sub), provider: new URL(String(v.claims.iss)).host }, issue, b.capabilities, hooks);
}

/** POST {PS}/token (7.2): three-party, the resource token's aud is this PS. */
async function token(r: DoorRequest, hooks: Hooks): Promise<Reply> {
  const v = await caller(r, hooks);
  const b = body(r);
  const agent = `${v.claims.iss}|${v.claims.sub}`;
  if (typeof b.resource_token !== 'string') refuse(400, 'invalid_request', 'resource_token is required.');
  if (typeof b.presented_token !== 'string') refuse(400, 'invalid_request', 'presented_token is required: the person token (or auth token) you presented to the resource that issued the resource token (7.2.1).');
  if (b.upstream_token !== undefined || b.subagent_token !== undefined) refuse(400, 'invalid_request', 'This PS handles neither sub-agents nor call chaining.');

  // Both tokens must be the proving ground's and this PS's: refused before verifying, so nothing is fetched from a URL the agent chose.
  const peek = (jwt: string) => { try { return decodeJwt(jwt); } catch { return {} as Record<string, unknown>; } };
  if (peek(b.resource_token as string).iss !== hooks.resource) refuse(400, 'invalid_resource_token', `This test PS only redeems resource tokens from the proving ground, ${hooks.resource}.`);
  const presentedIssuer = peek(b.presented_token as string);
  if (presentedIssuer.iss !== ID) refuse(400, 'invalid_presented_token', `The presented token must be one this PS issued (iss ${ID}).`);

  // The resource token (6.7.2).
  const rt = await verifyToken(b.resource_token as string, 'resource', { stage: 'agent' }).catch((e) => {
    if (!(e instanceof Fail)) throw e;
    return refuse(400, e.pg.endsWith('_expired') ? 'expired_resource_token' : 'invalid_resource_token', e.message);
  });
  const c = rt.claims;
  const rtBad = (m: string) => refuse(400, 'invalid_resource_token', m);
  if (c.aud !== ID) rtBad(`The resource token's aud must be this PS, ${ID}; got ${JSON.stringify(c.aud)}.`);
  for (const k of ['ps', 'sub', 'presented_jti', 'agent_jkt']) if (typeof c[k] !== 'string') rtBad(`The resource token needs ${k}.`);
  if (c.ps !== ID) rtBad(`The resource token's ps must name this PS, ${ID}.`);
  if (c.agent_jkt !== v.thumbprint) rtBad("The resource token's agent_jkt isn't the thumbprint of the key that signed this request: it was issued to another key.");

  // The presented token, against the resource token (6.7.2 step 3).
  const typ = (() => { try { return JSON.parse(Buffer.from(String(b.presented_token).split('.')[0], 'base64url').toString()).typ; } catch { return null; } })();
  const kind = typ === 'aa-person+jwt' ? 'person' : typ === 'aa-auth+jwt' ? 'auth' : refuse(400, 'invalid_presented_token', 'presented_token must be a person token (aa-person+jwt) or an auth token (aa-auth+jwt).');
  const pt = await verifyToken(b.presented_token as string, kind, { stage: kind, aud: c.iss as string }).catch((e) => {
    if (!(e instanceof Fail)) throw e;
    return refuse(400, e.pg.endsWith('_expired') ? 'expired_presented_token' : 'invalid_presented_token', e.message);
  });
  if ((await thumbprint(pt.cnf!)) !== c.agent_jkt) refuse(400, 'invalid_presented_token', "The presented token's cnf.jwk isn't the key the resource token names in agent_jkt.");
  const p = pt.claims;
  if (p.jti !== c.presented_jti) rtBad(`The resource token's presented_jti (${c.presented_jti}) isn't the presented token's jti (${p.jti}). Send the token you presented when you got this resource token.`);
  if ((kind === 'person' ? p.iss : p.ps) !== c.ps) rtBad("The resource token's ps isn't the presented token's PS.");
  for (const k of ['sub', 'mission_s256', 'tenant']) if (p[k] !== c[k]) rtBad(`The resource token's ${k} doesn't match the presented token's.`);
  const account = bindings.get(agent);
  if (!account || directed(account, c.iss as string) !== c.sub) rtBad("The resource token's sub isn't the person this agent acts for here. Get a person token from this PS first.");

  const scope = typeof c.scope === 'string' ? c.scope : '';
  const agentExp = v.claims.exp as number;
  const cnf = v.cnf!;
  const issue = async (): Promise<Reply> => {
    for (const s of scope.split(' ').filter(Boolean)) consents.add(`${agent}|${c.iss}|${s}`);
    const iat = nowS();
    const exp = Math.min(iat + 3600, agentExp, p.exp as number);
    const auth = await new SignJWT({ dwk: 'aauth-person.json', aud: c.iss, ps: ID, sub: c.sub, ...(scope && { scope }), cnf: { jwk: cnf } })
      .setProtectedHeader({ alg: 'Ed25519', typ: 'aa-auth+jwt', kid: key.kid })
      .setIssuer(ID).setJti(randomBytes(12).toString('base64url')).setIssuedAt(iat).setExpirationTime(exp).sign(key.key);
    hooks.note(v.thumbprint, `auth token issued for scope ${scope || '(none)'}, expiring in ${Math.round((exp - iat) / 60)} minutes.`, true);
    return { status: 200, headers: { 'Cache-Control': 'no-store' }, body: { auth_token: auth, expires_in: exp - iat } };
  };
  const consented = scope.split(' ').filter(Boolean).every((s) => consents.has(`${agent}|${c.iss}|${s}`));
  if (consented) return issue();
  const justification = typeof b.justification === 'string' ? b.justification.slice(0, 500) : undefined;
  return interaction(v, 'consent', { agent: String(v.claims.sub), provider: new URL(String(v.claims.iss)).host, scope, justification }, issue, b.capabilities, hooks);
}

/** GET {PS}/pending/<id> (11.8): the same agent, signed, on every poll (13.2). */
async function poll(r: DoorRequest, id: string, hooks: Hooks): Promise<Reply> {
  const v = await verifyRequest(signed(r));
  const p = pending.get(id);
  if (!p || v.kind !== 'agent' || p.agent !== `${v.claims.iss}|${v.claims.sub}` || p.thumbprint !== v.thumbprint) {
    return problem(404, 'not_found', 'No pending request with that URL for this agent and key. Poll with a signed GET, presenting the agent token that made the request.');
  }
  if (p.status === 'gone') return problem(410, 'gone', 'This pending request already returned its result.');
  if (p.exp < Date.now() && p.status !== 'done') {
    p.status = 'gone';
    hooks.note(p.thumbprint, 'the pending request expired before the person decided.', false);
    return problem(408, 'expired', 'The person did not decide in time. Make the request again for a new code.');
  }
  if (p.status !== 'done') return deferred(p);
  p.status = 'gone';
  return p.result!;
}

/** GET {PS}/interact: the page the person opens, with the code the agent showed them. */
function interactPage(r: DoorRequest): Reply {
  const given = r.url.searchParams.get('code');
  if (given === null) {
    return page(200, 'Enter your code', `<p>Enter the code your agent showed you.</p><form method="get" action="${PS}/interact"><p><input name="code" placeholder="XXXX-XXXX" required></p><p><button>Continue</button></p></form>`);
  }
  const id = byCode.get(normalize(given));
  const p = id ? pending.get(id) : undefined;
  if (!p || p.status !== 'pending' || p.exp < Date.now()) return page(410, 'That code isn\'t valid', '<p>It was mistyped, already used, or expired (invalid_code). Ask your agent to start again.</p>');
  // Single use: consumed on arrival (11.6.3.1).
  byCode.delete(p.code);
  p.status = 'interacting';
  const s = p.show;
  const ask = p.kind === 'bind'
    ? `<p>An agent asks to act for you at the proving ground.</p><dl><dt>Agent</dt><dd><code>${esc(s.agent)}</code></dd><dt>Agent provider</dt><dd>${esc(s.provider)}</dd></dl>
       <p>This is a test person server: pick a test account name. There is no password, and nothing here is a real account. Once you allow it, this agent always acts for that account here.</p>
       <p><label>Test account <input name="account" value="test-user" pattern="[a-z0-9-]{1,31}" required></label></p>`
    : `<p>Your agent <code>${esc(s.agent)}</code> (from ${esc(s.provider)}) asks for scope <code>${esc(s.scope ?? '')}</code> at the proving ground.</p>
       ${s.justification ? `<p>The agent says (its own words, not checked): <q>${esc(s.justification)}</q></p>` : ''}`;
  return page(200, p.kind === 'bind' ? 'Let this agent act for you?' : 'Allow this access?', `<form method="post" action="${PS}/interact"><input type="hidden" name="pending" value="${p.id}">${ask}
<p><button name="decision" value="allow">Allow</button> <button name="decision" value="deny" formnovalidate>Deny</button></p></form>${REAL[p.kind]}`);
}

/** POST {PS}/interact: the person's decision. */
async function decide(r: DoorRequest, hooks: Hooks): Promise<Reply> {
  const form = new URLSearchParams(r.body);
  const p = pending.get(form.get('pending') ?? '');
  if (!p || p.status !== 'interacting') return page(400, 'This request is over', '<p>It was decided already, or expired. Ask your agent to start again.</p>');
  const allow = form.get('decision') === 'allow';
  let account = bindings.get(p.agent);
  if (allow && p.kind === 'bind') {
    const chosen = form.get('account') ?? '';
    if (!ACCOUNT.test(chosen)) return page(400, 'Pick a test account', '<p>An account name is 1 to 31 lowercase letters, digits and hyphens. Go back and try again.</p>');
    if (account && account !== chosen) return page(409, 'This agent acts for someone else', `<p>It is bound to another test account. An agent acts for one person only.</p>`);
    account = chosen;
    bindings.set(p.agent, account);
  }
  p.status = 'done';
  if (!allow || !account) {
    hooks.note(p.thumbprint, `the person declined (${p.kind === 'bind' ? 'acting for them' : `scope ${p.show.scope}`}).`, false);
    p.result = problem(403, 'denied', 'The person declined.');
    return page(200, 'Declined', '<p>Your agent will be told. You can close this tab.</p>');
  }
  hooks.note(p.thumbprint, p.kind === 'bind' ? `the person allowed it, as test account ${account}.` : `the person consented to ${p.show.scope}.`, true);
  p.result = await p.issue(account);
  return page(200, 'Done', '<p>Your agent can carry on now. You can close this tab.</p>');
}

export async function serve(r: DoorRequest, hooks: Hooks): Promise<Reply> {
  const sub = r.path.slice('/ps'.length);
  try {
    if (r.method === 'GET' && sub === '/jwks.json') return { status: 200, headers: {}, body: jwks() };
    if (sub === '/interact') return r.method === 'GET' ? interactPage(r) : await decide(r, hooks);
    const m = /^\/pending\/([A-Za-z0-9_-]{24})$/.exec(sub);
    if (m && r.method === 'GET') return await poll(r, m[1], hooks);
    if (r.method === 'POST' && sub === '/person') return await person(r, hooks);
    if (r.method === 'POST' && sub === '/token') return await token(r, hooks);
    return problem(404, 'not_found', `The Lab test PS's endpoints are in ${ID}/.well-known/aauth-person.json.`);
  } catch (e) {
    if (e instanceof Fail) {
      hooks.note(await claimedThumbprint(r), `${sub.slice(1)} refused, ${e.sig}: ${e.message}`, false);
      const s = sigErrorResponse(e);
      return { ...s, headers: { ...s.headers, 'Cache-Control': 'no-store' } };
    }
    if (e instanceof PsError) {
      hooks.note(await claimedThumbprint(r), `${sub.slice(1)} refused, ${(e.reply.body as { error: string }).error}: ${e.message}`, false);
      return e.reply;
    }
    throw e;
  }
}
