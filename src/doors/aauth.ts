/**
 * The aauth door: a resource under the AAuth Protocol (draft-hardt-oauth-aauth-protocol-11, as
 * tagged at dickhardt/AAuth@178e9e6), signing per draft-hardt-httpbis-signature-key-09. It serves
 * a receipt to an agent that holds an auth token for scope `receipt`, obtained from the agent's
 * person server (three-party, 4.2.4). Any PS will do; the Lab test PS (aauth-ps.ts) is here for
 * agents without one.
 *
 * The door's identifier is the Lab's origin, since an AAuth server identifier is scheme and host
 * only (11.1.1). Its metadata is at /.well-known/aauth-resource.json, the PS's at aauth-person.json.
 *
 * An attempt is one signing key on one run's URL: every token an agent holds is bound to the same
 * key (cnf), so the key threads its requests together. Each request is walked up LADDER, and the
 * attempt keeps the highest step. A request that fails before its signature verifies makes an
 * attempt of its own. Every stop answers as the spec says (Signature-Error, AAuth-Requirement, or
 * an RFC 9457 error), plus `pg_stop`, the door's finer code, and `stopped_at`.
 *
 * Nothing the agent signs or sends is stored: not the tokens, not the signatures.
 */
import { randomBytes } from 'node:crypto';
import { SignJWT } from 'jose';
import { BASE_URL, DID, ORIGIN, ed25519, verifier, type DoorRequest } from '../lab.ts';
import * as store from '../store.ts';
import * as ps from './aauth-ps.ts';
import { ACCEPT_ALG, Fail, holdLocally, serverIdProblem, sfString, sigErrorResponse, unsigned, verifyRequest, type VerifiedRequest } from './aauth-sig.ts';

const SPEC_URL = 'https://github.com/dickhardt/AAuth/blob/178e9e68b6578e4d6f7d0bf30f33b4c38833e3a1/draft-hardt-oauth-aauth-protocol.md';
/** The same text as published (draft -11), with the section anchors. */
const SPEC_SITE = 'https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html';
const SIGKEY_URL = 'https://github.com/dickhardt/signature-key/blob/69f5ba2647be848feed043fb6d8b0790e43cd0b6/draft-hardt-httpbis-signature-key.md';

/** The steps, in the order an agent meets them. `ref` is the -11 section each comes from. */
export const LADDER = [
  { name: 'signed request', ref: 'verification' },
  { name: 'agent identified', ref: 'agent-tokens' },
  { name: 'person identified', ref: 'person-token-verification' },
  { name: 'resource token issued', ref: 'resource-token' },
  { name: 'authorized', ref: 'auth-tokens' },
  { name: 'through', ref: 'auth-tokens' },
] as const;
type StepName = (typeof LADDER)[number]['name'];
export const THROUGH = LADDER.length - 1;
const STAGE_STEP: Record<Fail['stage'], StepName> = { request: 'signed request', agent: 'agent identified', person: 'person identified', auth: 'authorized' };

/** The resource's identifier (11.1.1): the origin. */
const ID = ORIGIN;
const DOOR = `${BASE_URL}/pg/doors/aauth`;
const AUTHORIZE = `${DOOR}/authorize`;
const SCOPE = 'receipt';
const SCOPE_TEXT = "Collect a signed receipt from the proving ground, naming your run's handle";
const RESOURCE_TOKEN_TTL_S = 300;
const LINK = `<${ID}/.well-known/aauth-resource.json>; rel="aauth-resource"`;
const AGENT_ID = /^aauth:([A-Za-z0-9._+-]{1,255})@([a-z0-9.-]+)$/;

const key = await ed25519('aauth-resource', 'lab-resource-1');
holdLocally(ID, 'aauth-resource.json', () => [key.jwk]);

/** Libraries an agent can build on. The door doesn't use them: it checks with its own code. */
const LIBRARIES = [
  { name: '@aauth/agent (TypeScript): agent tokens, signed requests, person tokens, token exchange, deferred responses', url: 'https://www.npmjs.com/package/@aauth/agent' },
  { name: '@hellocoop/httpsig (TypeScript): RFC 9421 signing with the Signature-Key header', url: 'https://www.npmjs.com/package/@hellocoop/httpsig' },
  { name: 'aauth-python-library (Python): request signing and verification', url: 'https://github.com/christian-posta/aauth-python-library' },
  { name: 'aauth-go-library (Go): request signing and verification', url: 'https://github.com/christian-posta/aauth-go-library' },
  { name: 'dotnet-samples (.NET): the AAuth SDK and samples', url: 'https://github.com/aauth-dev/dotnet-samples' },
  { name: 'aauth-person-server: a person server you can run yourself', url: 'https://github.com/christian-posta/aauth-person-server' },
];

/** Served by the server at these paths, at the origin. */
export const WELL_KNOWN = {
  '/.well-known/aauth-resource.json': () => ({
    issuer: ID,
    jwks_uri: `${DOOR}/jwks.json`,
    access_mode: 'auth-token',
    name: 'Agent Lab proving ground',
    description: `The **aauth door** of the Agent Lab proving ground. It serves a receipt to an agent that holds an auth token for scope \`${SCOPE}\`.`,
    documentation_uri: `${BASE_URL}/aauth`,
    authorization_endpoint: AUTHORIZE,
    scope_descriptions: { [SCOPE]: SCOPE_TEXT },
    signature_window: 60,
    accept_signature_algs: ['Ed25519', 'ES256'],
  }),
  '/.well-known/aauth-person.json': () => ps.METADATA,
};

/** Shown on the wall and served at /pg/state. */
export const INFO = {
  door: 'aauth',
  spec: { name: 'AAuth Protocol', version: '-11', pinned: 'dickhardt/AAuth@178e9e6', url: SPEC_URL },
  proves: 'An agent with its own identity, acting for a person through their person server',
  about: `A resource at ${ID} (metadata at /.well-known/aauth-resource.json). Sign every request (RFC 9421, Signature-Key jwt scheme) with a key your agent provider bound in an agent token, get a person token from a person server, and trade the resource token the door gives you at that PS for an auth token with scope ${SCOPE}. Bring your own PS, or use the Lab test PS at ${ID} (aauth-person.json).`,
  builds_on: [
    { name: 'HTTP Signature Keys (draft-hardt-httpbis-signature-key-09, at dickhardt/signature-key@69f5ba2): Signature-Key, Signature-Error', url: SIGKEY_URL },
    { name: 'RFC 9421, HTTP Message Signatures', url: 'https://www.rfc-editor.org/rfc/rfc9421' },
    { name: 'RFC 9651, Structured Field Values', url: 'https://www.rfc-editor.org/rfc/rfc9651' },
    { name: 'RFC 9530, Content-Digest', url: 'https://www.rfc-editor.org/rfc/rfc9530' },
    { name: 'RFC 7638, JWK Thumbprint', url: 'https://www.rfc-editor.org/rfc/rfc7638' },
    { name: 'RFC 9457, Problem Details', url: 'https://www.rfc-editor.org/rfc/rfc9457' },
  ],
  ladder: LADDER.map((s) => ({ name: s.name, url: `${SPEC_SITE}#${s.ref}` })),
  resource: ID,
  person_server: ID,
  /** The wall's "Try it" box: the reference agent, which is its own agent provider. */
  try: `node aauth-client.ts ${BASE_URL} \\\n  --public-url <https URL that reaches port 8403>\n\nIt prints the Lab test PS's interaction links: open them to pick a test account and consent.`,
  libraries: LIBRARIES,
  advice: [
    `Start at ${ID}/.well-known/aauth-resource.json, then call ${DOOR}/r/<run ID> and follow each AAuth-Requirement it answers with.`,
    'You need an agent provider: an HTTPS origin serving /.well-known/aauth-agent.json and a JWKS, whose key signs your agent token (a self-hosted agent is its own agent provider). The door fetches it, so it must be reachable from the internet.',
    `No person server? Use the Lab test PS: issuer ${ID}, metadata at ${ID}/.well-known/aauth-person.json. Put "ps": "${ID}" in your agent token and send "capabilities": ["interaction"]. The first time, it answers 202 with an interaction URL and code: hand them to your person (the human running you), who opens {url}?code={code} and picks a test account, while you poll the Location it gave you. It is a stand-in with no sign-in and no real people: passing with it shows your agent speaks AAuth, not that a real person authorized it.`,
    `Use a library rather than hand-rolling RFC 9421 and the Signature-Key header: ${LIBRARIES.slice(0, 2).map((l) => l.url).join(', ')} (TypeScript), or the Python, Go and .NET ones in ${SPEC_URL.replace(/\/blob\/.*/, '')}#implementations. The door checks with its own verifier, so where a library and the door disagree, the stop says why.`,
  ],
};

type Reply = { status: number; headers: Record<string, string>; body: unknown };

const entry = (text: string, step?: StepName, ok?: boolean): store.Entry => ({ at: new Date().toISOString(), text, step, ok });
const tail = (s: unknown) => `…${String(s).slice(-4)}`;
const nowS = () => Math.floor(Date.now() / 1000);
const stepIndex = (s: StepName) => LADDER.findIndex((x) => x.name === s);

// ---- Attempts: one signing key on one run ----

type ResourceToken = { jti: string; ps: string; sub: string; scope: string; presentedExp: number; mission_s256?: unknown; tenant?: unknown };
type Thread = { attempt: string; runId: string | null; step: number; provider?: string };
// ponytail: in memory and unbounded, like poppy's Sessions; a restart starts every thread again.
const threads = new Map<string, Thread>();
const latest = new Map<string, Thread>();
/** The resource tokens the door issued, by the key they name (agent_jkt): the last 20 of each. */
const issued = new Map<string, ResourceToken[]>();
/** What the Lab test PS did, by signing key, to join that key's next request at the door. */
const psNotes = new Map<string, store.Entry[]>();
function note(tp: string | null, text: string, ok: boolean) {
  if (!tp) return;
  psNotes.set(tp, [...(psNotes.get(tp) ?? []).slice(-19), entry(`At the Lab test PS: ${text}`, undefined, ok ? undefined : false)]);
  if (psNotes.size > 1000) psNotes.delete(psNotes.keys().next().value!);
}
const hooks: ps.Hooks = { note, scopes: { [SCOPE]: SCOPE_TEXT }, resource: ID };

function threadFor(runId: string | null, tp: string): Thread {
  const k = `${runId ?? '-'}|${tp}`;
  // The authorization endpoint has no run in its URL: there, a key continues its latest attempt.
  let t = threads.get(k) ?? (runId === null ? latest.get(tp) : undefined);
  if (!t) {
    t = { attempt: store.newAttempt({ door: 'aauth', runId, nonce: null, nonceExpires: null, step: -1, timeline: [] }), runId, step: -1 };
    threads.set(k, t);
  }
  latest.set(tp, t);
  return t;
}

// ---- Stops ----

/** A stop that isn't a Signature-Error: an endpoint error (RFC 9457) or a requirement the agent didn't meet. */
class Stop extends Error {
  step: StepName;
  code: string;
  status: number;
  headers: Record<string, string>;
  body: Record<string, unknown>;
  constructor(step: StepName, code: string, status: number, message: string, headers: Record<string, string> = {}, body: Record<string, unknown> = {}) {
    super(message);
    this.step = step;
    this.code = code;
    this.status = status;
    this.headers = headers;
    this.body = body;
  }
}
const problem = (step: StepName, code: string, error: string, message: string) => new Stop(step, code, 400, message, { 'Content-Type': 'application/problem+json' }, { error, detail: message });

/** The intro, for a request with no signature: who the door is, and where to start. */
const intro = () => ({
  door: 'aauth',
  message: `This door is a resource under the AAuth Protocol -11. Sign your requests (RFC 9421, Signature-Key jwt scheme) and present your agent token. Every step after that is an AAuth-Requirement from the door.`,
  resource_metadata: `${ID}/.well-known/aauth-resource.json`,
  person_server: `${ID}/.well-known/aauth-person.json (the Lab test PS, if you have none of your own)`,
  start: `POST {"handle": "<your-handle>"} to ${BASE_URL}/pg/runs, then call ${DOOR}/r/<run ID>.`,
  spec: SPEC_URL,
  libraries: LIBRARIES,
  instructions: `${BASE_URL}/llms.txt`,
  wall: `${BASE_URL}/aauth`,
});

// ---- Resource tokens (6.7) ----

async function resourceToken(tp: string, from: { jti: string; ps: string; sub: string; exp: number; mission_s256?: unknown; tenant?: unknown }, scope: string) {
  const jti = randomBytes(12).toString('base64url');
  const iat = nowS();
  const optional = Object.fromEntries(Object.entries({ mission_s256: from.mission_s256, tenant: from.tenant }).filter(([, v]) => v !== undefined));
  const jwt = await new SignJWT({ dwk: 'aauth-resource.json', aud: from.ps, ps: from.ps, sub: from.sub, presented_jti: from.jti, agent_jkt: tp, scope, ...optional })
    .setProtectedHeader({ alg: 'Ed25519', typ: 'aa-resource+jwt', kid: key.kid })
    .setIssuer(ID).setJti(jti).setIssuedAt(iat).setExpirationTime(iat + RESOURCE_TOKEN_TTL_S).sign(key.key);
  issued.set(tp, [...(issued.get(tp) ?? []).slice(-19), { jti, ps: from.ps, sub: from.sub, scope, presentedExp: from.exp, ...optional }]);
  return { jwt, jti };
}
const authRequirement = (jwt: string) => ({ 'AAuth-Requirement': `requirement=auth-token;resource-token=${sfString(jwt)}` });

/** The receipt: a JWT the Lab's verifier key signs, naming the run's handle. */
async function receipt(t: Thread, psId: string) {
  return new SignJWT({ door: 'aauth', spec: `AAuth Protocol -11 (${INFO.spec.pinned})`, resource: ID, steps: LADDER.map((s) => s.name), proves: INFO.proves, ps: psId, ...(t.provider && { agent_provider: t.provider }) })
    .setProtectedHeader({ alg: 'ES256', typ: 'pg-receipt+jwt', kid: verifier.kid })
    .setIssuer(DID)
    .setSubject((t.runId && store.handleOf(t.runId)) ?? 'anonymous')
    .setJti(t.attempt)
    .setIssuedAt()
    .sign(verifier.key);
}

// ---- The door ----

export async function serve(r: DoorRequest): Promise<Reply> {
  if (r.path.startsWith('/ps/')) return ps.serve(r, hooks);
  if (r.path === '/jwks.json' && r.method === 'GET') return { status: 200, headers: {}, body: { keys: [key.jwk] } };
  if (r.path !== '' && r.path !== '/authorize') return { status: 404, headers: { 'Content-Type': 'application/problem+json' }, body: { error: 'not_found', detail: `The resource is ${DOOR}; its authorization endpoint is ${AUTHORIZE}.` } };
  const authorize = r.path === '/authorize';
  if (authorize && r.method !== 'POST') return { status: 405, headers: { Allow: 'POST' }, body: { error: 'method_not_allowed', detail: 'The authorization endpoint takes a signed POST (6.6).' } };

  const log: store.Entry[] = [entry(`→ ${r.method} ${r.route}`)];
  const base = { 'Cache-Control': 'no-store', Link: LINK };
  let t: Thread | undefined;
  let reached = -1;
  let mode: string | null = null;
  const pass = (step: StepName, text: string) => {
    const i = stepIndex(step);
    if (i > (t?.step ?? -1) && i > reached) log.push(entry(text, step, true));
    reached = Math.max(reached, i);
  };
  const done = (status: number, headers: Record<string, string>, body: Record<string, unknown>, said: string): Reply => {
    log.push(entry(`← ${status} ${said}`));
    store.finishAttempt(t!.attempt, { step: reached, mode, error: null, reason: null, more: log });
    t!.step = Math.max(t!.step, reached);
    return { status, headers: { ...base, ...headers }, body: { ...body, attempt: t!.attempt, watch: `${BASE_URL}/aauth#attempt=${t!.attempt}` } };
  };

  try {
    const req = ps.signed(r);
    if (unsigned(req)) {
      throw new Stop('signed request', 'no_signature', 401, 'The request is not signed. Sign it (RFC 9421) and present your agent token in Signature-Key: sig=jwt;jwt="<agent token>" (6.1).', { 'AAuth-Requirement': 'requirement=agent-token' }, intro());
    }
    let v: VerifiedRequest;
    try {
      v = await verifyRequest(req, { aud: ID });
    } catch (e) {
      if (e instanceof Fail && e.stage !== 'request') pass('signed request', 'Signature headers present, covering the required components, created within the window, jwt scheme.');
      throw e;
    }
    t = threadFor(r.runId, v.thumbprint);
    mode = `${v.kind} token`;
    // What the Lab test PS did since this key's last request came first, so it goes first.
    log.unshift(...(psNotes.get(v.thumbprint) ?? []));
    psNotes.delete(v.thumbprint);
    pass('signed request', `Signature covering ${v.covered.join(' ')}, created ${nowS() - v.created} s ago, jwt scheme.`);
    const c = v.claims;

    if (v.kind === 'agent') {
      // Agent identifier (5.2): aauth:local@domain, domain the agent provider's.
      const m = AGENT_ID.exec(String(c.sub));
      const host = new URL(String(c.iss)).hostname;
      const fail = (msg: string): never => { throw new Fail('agent', 'invalid_jwt', 'agent_token_invalid', msg); };
      if (!m) fail(`The agent token's sub must be an agent identifier, aauth:local@domain (local: A-Z a-z 0-9 . _ + -, 1 to 255); got ${JSON.stringify(c.sub)}.`);
      if (m![2] !== host) fail(`The agent identifier's domain (${m![2]}) must be its agent provider's, the host of iss (${host}).`);
      if (m![1].includes('+') && typeof c.parent_agent !== 'string') fail("A top-level agent's local part has no +; + marks a sub-agent, whose token carries parent_agent (5.2).");
      if (c.ps !== undefined && serverIdProblem(c.ps)) fail(`The agent token's ps (${JSON.stringify(c.ps)}) ${serverIdProblem(c.ps)}.`);
      t.provider = String(c.iss);
      const life = (c.exp as number) - (c.iat as number);
      pass('agent identified', `Agent ${c.sub} from agent provider ${host}: agent token and signature verify.${life > 86_400 ? ` (It lives ${Math.round(life / 3600)} h; agent tokens SHOULD NOT exceed 24 h.)` : ''}`);
      const toPs = c.ps ? `Your agent token names your PS, ${c.ps}: get a person token for ${ID} from its person_token_endpoint (7.1)` : `Your agent token names no PS (no ps claim). Get a person token for ${ID} from your PS (7.1); no PS? Use the Lab test PS, ${ID}, and put "ps": "${ID}" in your agent token`;
      return done(401, { 'AAuth-Requirement': 'requirement=person-token' }, { detail: `${toPs}, then sign with it in place of your agent token (6.4).`, person_server: `${ID}/.well-known/aauth-person.json` }, 'requirement=person-token');
    }

    if (v.kind === 'person') {
      if (typeof c.sub !== 'string' || !c.sub) throw new Fail('person', 'invalid_jwt', 'person_token_invalid', 'The person token needs sub, the directed identifier.');
      if ('scope' in c || 'account' in c) throw new Fail('person', 'invalid_jwt', 'person_token_invalid', 'A person token carries no scope or account (7.1.2). It identifies; it does not authorize.');
      pass('agent identified', 'Agent token not seen at the door: your PS checked it when it issued your person token.');
      pass('person identified', `Person ${tail(c.sub)} from PS ${c.iss}: person token verifies, addressed to ${ID}, bound to your key.`);
      let scope = SCOPE;
      if (authorize) {
        let b: Record<string, unknown>;
        try {
          b = JSON.parse(r.body);
        } catch {
          throw problem('resource token issued', 'invalid_request', 'invalid_request', 'The body must be JSON: {"scope": "receipt"} (6.6).');
        }
        if (typeof b?.scope !== 'string' || !b.scope.trim()) throw problem('resource token issued', 'invalid_request', 'invalid_request', 'scope is required, a space-separated string (6.6).');
        const asked = [...new Set(b.scope.split(' ').filter(Boolean))];
        if (asked.some((s) => s !== SCOPE)) throw problem('resource token issued', 'invalid_scope', 'invalid_scope', `This resource has one scope, ${SCOPE} (scope_descriptions in its metadata).`);
        if (b.account !== undefined) throw problem('resource token issued', 'invalid_account', 'invalid_account', 'This resource holds no accounts; send no account.');
        scope = asked.join(' ');
      }
      const rt = await resourceToken(v.thumbprint, { jti: String(c.jti), ps: String(c.iss), sub: c.sub, exp: c.exp as number, mission_s256: c.mission_s256, tenant: c.tenant }, scope);
      pass('resource token issued', `Resource token ${tail(rt.jti)} for scope ${scope}, aud your PS ${c.iss}, naming person token ${tail(c.jti)}.`);
      if (authorize) return done(200, {}, { resource_token: rt.jwt }, 'resource_token');
      return done(401, authRequirement(rt.jwt), { detail: `Take the resource token to your PS's auth_token_endpoint, with the person token you just presented as presented_token (7.2), and sign with the auth token it gives you (9.4.2).` }, 'requirement=auth-token');
    }

    // An auth token (9.4.3).
    if (authorize) {
      throw new Stop('resource token issued', 'person_token_required', 401, 'The authorization endpoint takes a person token, not an auth token (6.6). Present your person token there, or call the resource itself with your auth token.', { 'AAuth-Requirement': 'requirement=person-token' });
    }
    const bad = (msg: string): never => { throw new Fail('auth', 'invalid_jwt', 'auth_claims', msg); };
    if (c.dwk !== 'aauth-person.json') throw new Fail('auth', 'invalid_jwt', 'auth_issuer', `This resource has no access server: its resource tokens name your PS as aud, so the auth token comes from your PS, with dwk aauth-person.json (9.4.1). Got dwk ${c.dwk}.`);
    if (typeof c.sub !== 'string' || !c.sub) bad('The auth token needs sub (9.4.1).');
    if (c.ps !== c.iss) bad(`An auth token a PS issues has ps equal to iss (9.4.1); got iss ${c.iss}, ps ${JSON.stringify(c.ps)}.`);
    pass('agent identified', 'Agent token not seen at the door: your PS checked it when it issued your tokens.');
    pass('person identified', 'Person token not seen in this attempt: your PS issued this auth token against one.');
    const presented = { jti: String(c.jti), ps: String(c.iss), sub: c.sub as string, exp: c.exp as number, mission_s256: c.mission_s256, tenant: c.tenant };
    const rt = issued.get(v.thumbprint)?.findLast((x) => x.ps === c.iss && x.sub === c.sub);
    if (!rt) {
      const fresh = await resourceToken(v.thumbprint, presented, SCOPE);
      throw new Stop('authorized', 'auth_unmatched', 401, `This door issued no resource token for person ${tail(c.sub)} at PS ${c.iss} to this key (or has restarted since), so it can't check what your PS granted against what it asked. Here is one: take it to your PS (6.5).`, authRequirement(fresh.jwt));
    }
    pass('resource token issued', `Resource token ${tail(rt.jti)} was issued to this key earlier.`);
    const granted = typeof c.scope === 'string' ? c.scope.split(' ').filter(Boolean) : [];
    const asked = rt.scope.split(' ');
    if (granted.some((s) => !asked.includes(s))) bad(`The auth token's scope (${c.scope}) is broader than the resource token's (${rt.scope}); a PS may narrow scope, never widen it (11.10).`);
    if ((c.exp as number) > rt.presentedExp) bad('The auth token outlives the token it was obtained with; its exp must not be later than the presented token\'s (9.4.1).');
    if (c.mission_s256 !== rt.mission_s256) bad("The auth token's mission_s256 must be the resource token's (9.4.1).");
    if (!granted.includes(SCOPE)) {
      const fresh = await resourceToken(v.thumbprint, presented, SCOPE);
      throw new Stop('authorized', 'scope_insufficient', 401, `The auth token grants ${c.scope ?? 'no scope'}; this needs ${SCOPE}. Here is a resource token for it: take it to your PS, with this auth token as presented_token (6.5).`, authRequirement(fresh.jwt));
    }
    pass('authorized', `Auth token from PS ${c.iss} for scope ${c.scope}: bound to your key, addressed to ${ID}, within what resource token ${tail(rt.jti)} asked for.`);
    pass('through', 'Served the receipt. All checks passed.');
    return done(200, {}, { door: 'aauth', message: `Through. You act for person ${tail(c.sub)} at PS ${c.iss}, with scope ${c.scope}. Here is your receipt.`, receipt: await receipt(t, String(c.iss)) }, 'receipt');
  } catch (e) {
    let step: StepName, code: string, status: number, headers: Record<string, string>, body: Record<string, unknown>, said: string;
    if (e instanceof Fail) {
      const s = sigErrorResponse(e);
      [step, code, status, headers, body, said] = [STAGE_STEP[e.stage], e.pg, s.status, s.headers, s.body, `Signature-Error ${e.sig}`];
      if (e.sig === 'unsupported_algorithm') headers['Accept-Signature-Alg'] ??= ACCEPT_ALG;
    } else if (e instanceof Stop) {
      [step, code, status, headers, body, said] = [e.step, e.code, e.status, e.headers, { detail: e.message, ...e.body }, e.headers['AAuth-Requirement'] ?? String(e.body.error ?? e.code)];
    } else throw e;
    const id = t?.attempt ?? store.newAttempt({ door: 'aauth', runId: r.runId, nonce: null, nonceExpires: null, step: -1, timeline: [] });
    log.push(entry(e.message, step, false), entry(`← ${status} ${said.replace(/resource-token="[^"]+"/, 'resource-token=…')} (${code})`));
    store.finishAttempt(id, { step: Math.max(reached, stepIndex(step) - 1), mode, error: code, reason: e.message, more: log });
    if (t) t.step = Math.max(t.step, reached);
    return { status, headers: { ...base, ...headers }, body: { ...body, stopped_at: step, pg_stop: code, attempt: id, watch: `${BASE_URL}/aauth#attempt=${id}` } };
  }
}
