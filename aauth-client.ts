/**
 * A reference agent for the aauth door (AAuth Protocol -11), in one file: the e2e test's driver, and
 * something to read next to the spec. The AAuth flow is written out by hand; signing each request
 * (RFC 9421 with the Signature-Key header) is left to @hellocoop/httpsig, as an agent would.
 *
 *   node aauth-client.ts <proving ground URL> [--handle <h>] [--ps <PS identifier>] [--public-url <https URL that reaches --port>] [--port <n>]
 *
 * 1. Be its own agent provider (5.1): serve /.well-known/aauth-agent.json and a JWKS, and sign an
 *    agent token binding the agent's key to aauth:<local>@<host> (5.3). Locally that's
 *    http://localhost:<port>; a remote proving ground can only fetch it through --public-url.
 * 2. Discover the resource (11.2.4) and the PS (11.2.2), checking each issuer.
 * 3. Call the door with the agent token: 401 requirement=person-token (6.4).
 * 4. Get a person token from the PS (7.1); the first time, the person picks a test account at the
 *    interaction URL (11.6.3) while the agent polls (11.8).
 * 5. Call the door with the person token: 401 requirement=auth-token and a resource token (6.5),
 *    checked as 6.7.3 says.
 * 6. Trade it at the PS for an auth token (7.2), after the person consents; check it (9.4.4).
 * 7. Call the door with the auth token: 200 and a receipt.
 *
 * Skipped: missions, sub-agents, the PS interaction relay, AAuth-Capabilities on resource calls.
 */
import { randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { bareItemToString, fetch as signedFetch, parseDictionary, type BareItem, type Item } from '@hellocoop/httpsig';
import { SignJWT, calculateJwkThumbprint, createLocalJWKSet, decodeJwt, exportJWK, generateKeyPair, jwtVerify, type JWK } from 'jose';

const now = () => Math.floor(Date.now() / 1000);
const sleep = (s: number) => new Promise((r) => setTimeout(r, s * 1000));

async function getJson(url: string) {
  const res = await fetch(url);
  if (!res.ok) throw new Error(`${url} returned ${res.status}: ${await res.text()}`);
  return res.json();
}

/** Metadata at {issuer}/.well-known/{dwk}, whose issuer must be the one asked for (11.2). */
async function metadata(issuer: string, dwk: string) {
  const doc = await getJson(`${issuer}/.well-known/${dwk}`);
  if (doc.issuer !== issuer) throw new Error(`${issuer}/.well-known/${dwk} says issuer ${doc.issuer}`);
  return doc;
}

/**
 * An agent and its own agent provider (5.1): the provider's key signs agent tokens; the agent's key
 * signs requests. `provider` is the provider's identifier, an origin.
 */
export async function newAgent(provider: string, o: { ps?: string; local?: string } = {}) {
  const ap = await generateKeyPair('Ed25519', { extractable: true });
  const apJwk: JWK = { ...(await exportJWK(ap.publicKey)), kid: 'ap-1', alg: 'Ed25519' };
  const own = await generateKeyPair('Ed25519', { extractable: true });
  const publicJwk: JWK = { ...(await exportJWK(own.publicKey)), alg: 'Ed25519' };
  const signingKey = { ...(await exportJWK(own.privateKey)), alg: 'Ed25519' };
  const id = `aauth:${o.local ?? `ref-${randomBytes(4).toString('hex')}`}@${new URL(provider).hostname}`;
  return {
    id,
    provider,
    ps: o.ps,
    signingKey,
    publicJwk,
    thumbprint: await calculateJwkThumbprint(publicJwk),
    providerKey: ap.privateKey,
    /** What the provider serves at /.well-known/aauth-agent.json and its jwks_uri. */
    documents: {
      'aauth-agent.json': { issuer: provider, jwks_uri: `${provider}/jwks.json`, name: 'Proving ground reference agent' } as Record<string, unknown>,
      jwks: { keys: [apJwk] } as Record<string, unknown>,
    },
    /** An agent token (5.3.1); `claims` overrides any claim, `header` any header member. */
    async agentToken(over: { claims?: Record<string, unknown>; header?: Record<string, unknown>; key?: CryptoKey } = {}) {
      return new SignJWT({ iss: provider, dwk: 'aauth-agent.json', sub: id, cnf: { jwk: publicJwk }, ...(o.ps && { ps: o.ps }), iat: now(), exp: now() + 3600, jti: randomBytes(8).toString('hex'), ...over.claims })
        .setProtectedHeader({ alg: 'Ed25519', typ: 'aa-agent+jwt', kid: 'ap-1', ...over.header })
        .sign(over.key ?? ap.privateKey);
    },
  };
}
export type Agent = Awaited<ReturnType<typeof newAgent>>;

/** Serves an agent provider's two documents; returns its identifier and a way to change them. */
export async function serveProvider(port = 0) {
  let docs: Agent['documents'] | undefined;
  const server = createServer((req, res) => {
    const p = new URL(req.url ?? '/', 'http://x').pathname;
    const body = p === '/.well-known/aauth-agent.json' ? docs?.['aauth-agent.json'] : p === '/jwks.json' ? docs?.jwks : undefined;
    if (!body) return res.writeHead(404).end();
    res.writeHead(200, { 'content-type': 'application/json' }).end(JSON.stringify(body));
  });
  await new Promise<void>((r) => server.listen(port, r));
  const local = `http://localhost:${(server.address() as { port: number }).port}`;
  return { local, server, serve: (a: Agent) => void (docs = a.documents) };
}

export type Reply = { status: number; headers: Headers; body: Record<string, unknown> };

/** One signed request (11.3.3), presenting `jwt` in Signature-Key; a body is covered by content-digest. */
export async function call(a: Agent, url: string, jwt: string, init: { method?: string; body?: unknown; components?: string[] } = {}): Promise<Reply> {
  const method = init.method ?? (init.body === undefined ? 'GET' : 'POST');
  const res = await signedFetch(url, {
    method,
    ...(init.body !== undefined && { headers: { 'content-type': 'application/json' }, body: JSON.stringify(init.body) }),
    signingKey: a.signingKey,
    signatureKey: { type: 'jwt', jwt },
    ...(init.components && { components: init.components }),
  }) as Response;
  const text = await res.text();
  let body: Record<string, unknown> = {};
  try { body = JSON.parse(text); } catch { body = { text }; }
  return { status: res.status, headers: res.headers, body };
}

/** The AAuth-Requirement header (11.6.1), as {requirement, ...params}. */
export function requirement(h: Headers): Record<string, string> | null {
  const v = h.get('aauth-requirement');
  if (!v) return null;
  const [value, params] = parseDictionary(v).get('requirement') as Item;
  return { requirement: bareItemToString(value), ...Object.fromEntries([...params].map(([k, x]) => [k, bareItemToString(x as BareItem)])) };
}

/** The person, at an interaction URL: what the agent hands them (url, code). */
export type Interact = (url: string, code: string) => Promise<void>;

/** A PS request that may be deferred (11.8): on 202 with requirement=interaction, the person goes to the URL while the agent polls Location. */
async function deferred(a: Agent, endpoint: string, first: Reply, interact: Interact): Promise<Reply> {
  let r = first;
  let told = false;
  while (r.status === 202) {
    const req = requirement(r.headers);
    if (req?.requirement === 'interaction' && !told) {
      told = true;
      void interact(req.url, req.code);
    }
    const location = r.headers.get('location');
    if (!location) throw new Error('202 without Location');
    await sleep(Number(r.headers.get('retry-after') ?? 5));
    r = await call(a, new URL(location, endpoint).toString(), await a.agentToken());
  }
  return r;
}

export type Ps = Awaited<ReturnType<typeof psFor>>;
export const psFor = (id: string) => metadata(id, 'aauth-person.json');

/** A person token for `resource` from the agent's PS (7.1). */
export async function personToken(a: Agent, ps: Ps, resource: string, interact: Interact) {
  const r = await deferred(a, ps.person_token_endpoint, await call(a, ps.person_token_endpoint, await a.agentToken(), { body: { resource, capabilities: ['interaction'] } }), interact);
  if (r.status !== 200) throw new Error(`person token: ${r.status} ${JSON.stringify(r.body)}`);
  const token = r.body.person_token as string;
  const c = decodeJwt(token);
  if (c.aud !== resource || (c.cnf as { jwk: JWK }).jwk.x !== a.publicJwk.x) throw new Error('the person token is not for this resource, or not bound to this key');
  return token;
}

/** Checks a resource token the resource challenged with (6.7.3). */
export async function checkResourceToken(a: Agent, jwt: string, resource: string, ps: string, presented: string) {
  const meta = await metadata(resource, 'aauth-resource.json');
  const { payload } = await jwtVerify(jwt, createLocalJWKSet(await getJson(meta.jwks_uri)), { typ: 'aa-resource+jwt', issuer: resource });
  const p = decodeJwt(presented);
  if (payload.agent_jkt !== a.thumbprint) throw new Error("the resource token's agent_jkt is not this agent's key");
  if (payload.ps !== ps || payload.sub !== p.sub || payload.presented_jti !== p.jti) throw new Error('the resource token does not name this PS, person and presented token');
  return payload;
}

/** An auth token for a resource token (7.2), checked as 9.4.4 says. */
export async function authToken(a: Agent, ps: Ps, resourceToken: string, presented: string, interact: Interact, extra: Record<string, unknown> = {}) {
  const r = await deferred(a, ps.auth_token_endpoint, await call(a, ps.auth_token_endpoint, await a.agentToken(), { body: { resource_token: resourceToken, presented_token: presented, capabilities: ['interaction'], ...extra } }), interact);
  if (r.status !== 200) throw new Error(`auth token: ${r.status} ${JSON.stringify(r.body)}`);
  const token = r.body.auth_token as string;
  const c = decodeJwt(token);
  const rt = decodeJwt(resourceToken);
  if (c.iss !== rt.aud || c.aud !== rt.iss || (c.cnf as { jwk: JWK }).jwk.x !== a.publicJwk.x || c.sub !== decodeJwt(presented).sub) throw new Error('the auth token does not match the resource token');
  return token;
}

/** The whole flow, steps 3 to 7. `door` is the run's door URL; returns each response along the way. */
export async function walk(a: Agent, door: string, interact: Interact) {
  const resource = new URL(door).origin;
  const meta = await metadata(resource, 'aauth-resource.json');
  const ps = await psFor(a.ps ?? resource);
  const first = await call(a, door, await a.agentToken());
  if (requirement(first.headers)?.requirement !== 'person-token') return { first };
  const person = await personToken(a, ps, meta.issuer, interact);
  const second = await call(a, door, person);
  const req = requirement(second.headers);
  if (req?.requirement !== 'auth-token') return { first, second };
  await checkResourceToken(a, req['resource-token'], resource, ps.issuer, person);
  const auth = await authToken(a, ps, req['resource-token'], person, interact, { justification: 'Collect my proving-ground receipt.' });
  const third = await call(a, door, auth);
  return { first, second, third, person, auth };
}

async function main() {
  const [base, ...rest] = process.argv.slice(2);
  const opt = (k: string) => { const i = rest.indexOf(`--${k}`); return i >= 0 ? rest[i + 1] : undefined; };
  if (!base || base.startsWith('--')) throw new Error('usage: node aauth-client.ts <proving ground URL> [--handle <h>] [--ps <PS identifier>] [--public-url <https URL>] [--port <n>]');
  const port = Number(opt('port') ?? 8403);
  const host = await serveProvider(port);
  const provider = (opt('public-url') ?? host.local).replace(/\/$/, '');
  const agent = await newAgent(new URL(provider).origin, { ps: opt('ps') ?? new URL(base).origin });
  host.serve(agent);
  console.log(`agent ${agent.id}, agent provider ${agent.provider}, PS ${agent.ps}`);

  const run = await (await fetch(`${base.replace(/\/$/, '')}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle: opt('handle') ?? `agent-${randomBytes(3).toString('hex')}` }) })).json();
  console.log('run:', run.handle, run.doors.aauth);
  const steps = await walk(agent, run.doors.aauth, async (url, code) => console.log(`\nOpen this, check the code is ${code}, and decide:\n${url}?code=${encodeURIComponent(code)}\n`));
  for (const [k, r] of Object.entries(steps)) if (typeof r === 'object') console.log(`${k}: ← ${r.status} ${r.headers.get('aauth-requirement')?.replace(/resource-token="[^"]+"/, 'resource-token=…') ?? ''}`, r.status === 200 ? '' : JSON.stringify(r.body));
  if (steps.third?.status === 200) console.log(`receipt: ${steps.third.body.receipt}`);
  host.server.close();
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
