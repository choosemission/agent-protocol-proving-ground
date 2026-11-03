/**
 * A reference Personal Agent for the poppy door (Personal Agent Protocol 0.3), in one file:
 * the e2e test's driver, and something to read next to the spec.
 *
 *   node poppy-client.ts <proving ground URL> [--handle <h>] [--public-url <https URL that reaches --port>] [--port <n>]
 *
 * 1. Discovery (3, 3.2): poppy.json, the protected resource metadata, the issuer's metadata.
 * 2. Identity (4.1): serve a client metadata document and JWKS; client_id is the document's URL.
 *    Locally that's http://localhost:<port>; the issuer can only fetch the JWKS through --public-url.
 * 3. Register the client_id with a run (proving-ground specific).
 * 4. A Session (5.2): a delegated key for this User, a delegation signed by the JWKS key, and a
 *    Session JWT per request.
 * 5. Start a conversation, read the reply and its authorization event (8.3, 8.5, 8.11).
 * 6. Direct Sign-In (4.2): authorization code + PKCE, iss check, private_key_jwt assertion to the issuer.
 * 7. Continue the conversation signed in, with ath, and read the reply with the receipt.
 *
 * Skipped: DPoP (a SHOULD; the door verifies it if the token is bound), refresh and revocation,
 * Web Bot Auth signatures, SSE.
 */
import { createHash, randomBytes } from 'node:crypto';
import { createServer } from 'node:http';
import { fileURLToPath } from 'node:url';
import { SignJWT, calculateJwkThumbprint, exportJWK, generateKeyPair, type JWK } from 'jose';

const rand = (n = 16) => randomBytes(n).toString('base64url');
const sha256 = (s: string) => createHash('sha256').update(s).digest('base64url');
const now = () => Math.floor(Date.now() / 1000);

async function getJson(url: string, init?: RequestInit) {
  const res = await fetch(url, init);
  if (!res.ok) throw new Error(`${url} returned ${res.status}: ${await res.text()}`);
  return res.json();
}

/** A Personal Agent's identity: one signing key in its JWKS, and its client metadata (4.1). */
export async function newAgent(base: string) {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const jwk = await exportJWK(publicKey);
  jwk.kid = await calculateJwkThumbprint(jwk);
  jwk.alg = 'ES256';
  const clientId = `${base}/agent.json`;
  return {
    clientId,
    key: privateKey,
    jwks: { keys: [jwk] },
    metadata: {
      client_id: clientId,
      client_name: 'Proving ground reference agent',
      jwks_uri: `${base}/jwks.json`,
      redirect_uris: [`${base}/callback`],
      token_endpoint_auth_method: 'private_key_jwt',
    } as Record<string, unknown>,
  };
}
export type Agent = Awaited<ReturnType<typeof newAgent>>;

/** Discovery (3, 3.1, 3.2), with the checks a Personal Agent MUST make. */
export async function discover(origin: string) {
  const doc = await getJson(`${origin}/.well-known/poppy.json`);
  const host = new URL(origin).host;
  if (doc.protocol_version !== '0.3') throw new Error(`unsupported protocol_version ${doc.protocol_version}`);
  if (String(doc.organization?.domain).toLowerCase() !== host.toLowerCase()) throw new Error(`organization.domain ${doc.organization?.domain} isn't ${host}`);
  const resource = `${new URL(origin).protocol}//${host.toLowerCase()}`;
  const prm = await getJson(`${origin}/.well-known/oauth-protected-resource`);
  if (prm.resource !== resource) throw new Error(`protected resource metadata names ${prm.resource}, not ${resource}`);
  const issuer: string = doc.auth?.issuer ?? prm.authorization_servers?.[0];
  if (!prm.authorization_servers?.includes(issuer)) throw new Error(`issuer ${issuer} isn't in authorization_servers`);
  // RFC 8414 §3.1: the well-known segment goes between the host and the issuer's path.
  const iss = new URL(issuer);
  const as = await getJson(`${iss.origin}/.well-known/oauth-authorization-server${iss.pathname.replace(/\/$/, '')}`);
  if (as.issuer !== issuer) throw new Error(`the issuer's metadata names ${as.issuer}`);
  if (!as.protected_resources?.map((r: string) => r.toLowerCase()).includes(resource)) throw new Error(`the issuer's protected_resources doesn't list ${resource}, so it doesn't vouch for this domain`);
  const endpoint: string = doc.agent.protocols.find((p: { type: string }) => p.type === 'poppy').endpoint;
  return { doc, issuer, as, endpoint, scopes: Object.keys(doc.auth?.scopes ?? {}) };
}
export type Company = Awaited<ReturnType<typeof discover>>;

/** A Session for one User at one Company: its own delegated key, vouched for by the JWKS key (5.2). */
export async function newSession(agent: Agent, company: Company, sub = `usr_${rand(9)}`) {
  const { privateKey, publicKey } = await generateKeyPair('ES256');
  const cnf = await exportJWK(publicKey);
  const delegation = await new SignJWT({ cnf: { jwk: cnf } })
    .setProtectedHeader({ alg: 'ES256', typ: 'poppy-delegation+jwt', kid: agent.jwks.keys[0].kid })
    .setIssuer(agent.clientId)
    .setIssuedAt()
    .setExpirationTime('1h')
    .setJti(rand())
    .sign(agent.key);
  return { agent, company, sid: rand(), sub, key: privateKey, kid: await calculateJwkThumbprint(cnf), delegation, token: undefined as string | undefined };
}
export type Session = Awaited<ReturnType<typeof newSession>>;

/** The Poppy-Session header for one request. */
export function sessionJwt(s: Session, method: string, url: string, claims: Record<string, unknown> = {}) {
  const u = new URL(url);
  return new SignJWT({ sid: s.sid, sub: s.sub, htm: method, htu: `${u.origin}${u.pathname}`, ...(s.token && { ath: sha256(s.token) }), ...claims })
    .setProtectedHeader({ typ: 'poppy-session+jwt', alg: 'ES256', kid: s.kid, poppy_dlg: s.delegation })
    .setIssuer(s.agent.clientId)
    .setAudience(s.company.issuer)
    .setIssuedAt()
    .setJti(rand())
    .sign(s.key);
}

/** A request to a Poppy endpoint: Session header always, access token when signed in. */
export async function call(s: Session, method: string, url: string, body?: unknown) {
  const res = await fetch(url, {
    method,
    headers: {
      'Poppy-Session': await sessionJwt(s, method, url),
      ...(s.token && { Authorization: `Bearer ${s.token}` }),
      ...(body !== undefined && { 'Content-Type': 'application/json' }),
    },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  return { status: res.status, headers: res.headers, body: await res.json() };
}

export const message = (text: string) => ({ message: { id: `msg_${rand(12)}`, author: { type: 'agent' }, text } });

/** A client assertion (4.1): aud is the issuer, short-lived, unique jti. */
const assertion = (agent: Agent, issuer: string) =>
  new SignJWT({}).setProtectedHeader({ alg: 'ES256', kid: agent.jwks.keys[0].kid }).setIssuer(agent.clientId).setSubject(agent.clientId)
    .setAudience(issuer).setIssuedAt().setExpirationTime('2m').setJti(rand()).sign(agent.key);

/**
 * Direct Sign-In (4.2). `browser` opens the authorization URL for the User and resolves with the
 * URL they were sent back to.
 */
export async function signIn(agent: Agent, company: Company, scope: string, browser: (url: string) => Promise<string>) {
  const verifier = rand(32);
  const state = rand();
  const redirectUri = (agent.metadata.redirect_uris as string[])[0];
  const auth = new URL(company.as.authorization_endpoint);
  auth.search = new URLSearchParams({ response_type: 'code', client_id: agent.clientId, redirect_uri: redirectUri, scope, state, code_challenge: sha256(verifier), code_challenge_method: 'S256' }).toString();
  const back = new URL(await browser(auth.toString())).searchParams;
  if (back.get('iss') !== company.issuer) throw new Error(`sign-in came back with iss ${back.get('iss')}, not ${company.issuer}`);
  if (back.get('state') !== state) throw new Error('sign-in came back with the wrong state');
  if (!back.get('code')) throw new Error(`sign-in declined: ${back.get('error')}`);
  const tokens = await getJson(company.as.token_endpoint, {
    method: 'POST',
    body: new URLSearchParams({
      grant_type: 'authorization_code', code: back.get('code')!, redirect_uri: redirectUri, code_verifier: verifier,
      client_id: agent.clientId, client_assertion_type: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', client_assertion: await assertion(agent, company.issuer),
    }),
  });
  const granted = String(tokens.scope ?? scope).split(' ');
  if (!granted.includes(scope)) throw new Error(`the User didn't grant ${scope}`);
  return tokens as { access_token: string; refresh_token?: string; token_type: string };
}

/** Every Company message in a read, as text. */
export const companySaid = (read: { events: { type: string; message?: { role: string; text?: string } }[] }) =>
  read.events.filter((e) => e.type === 'message' && e.message?.role === 'company').map((e) => e.message!.text);

async function main() {
  const args = process.argv.slice(2);
  const opt = (name: string) => { const i = args.indexOf(`--${name}`); return i >= 0 ? args[i + 1] : undefined; };
  const origin = args[0]?.replace(/\/$/, '');
  if (!origin || origin.startsWith('--')) throw new Error('usage: node poppy-client.ts <proving ground URL> [--handle <h>] [--public-url <https URL>] [--port <n>]');
  const port = Number(opt('port') ?? 8402);
  const agent = await newAgent((opt('public-url') ?? `http://localhost:${port}`).replace(/\/$/, ''));

  // Serve the client metadata, the JWKS and the sign-in callback.
  let callback: (url: string) => void = () => {};
  const server = createServer((req, res) => {
    const p = new URL(req.url ?? '/', agent.clientId).pathname;
    if (p === '/agent.json') return res.end(JSON.stringify(agent.metadata));
    if (p === '/jwks.json') return res.end(JSON.stringify(agent.jwks));
    if (p === '/callback') { callback(new URL(req.url!, agent.clientId).toString()); return res.end('Signed in. You can close this tab.'); }
    res.writeHead(404).end();
  }).listen(port);
  console.log(`client_id ${agent.clientId}`);

  const company = await discover(origin);
  console.log(`discovered: issuer ${company.issuer}, endpoint ${company.endpoint}, scopes ${company.scopes.join(' ')}`);
  const run = await getJson(`${origin}/pg/runs`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ handle: opt('handle') ?? `agent-${rand(3).toLowerCase().replace(/[^a-z0-9]/g, 'x')}`, client_id: agent.clientId }) });
  console.log('run:', run.handle, run.poppy);

  const s = await newSession(agent, company);
  const started = await call(s, 'POST', `${company.endpoint}?wait=5`, message('Hello from the reference agent.'));
  console.log(`← ${started.status}`, companySaid(started.body));
  const ask = started.body.events?.find((e: { type: string }) => e.type === 'authorization');
  if (!ask) return void server.close();

  const tokens = await signIn(agent, company, ask.scope, (url) => {
    console.log(`\nOpen this to sign in:\n${url}\n`);
    return new Promise((resolve) => (callback = resolve));
  });
  s.token = tokens.access_token;
  const id = started.body.conversation_id;
  const signedIn = await call(s, 'POST', `${company.endpoint}/${id}/messages?wait=5&cursor=${started.body.cursor}`, message('Signed in now.'));
  console.log(`← ${signedIn.status}`, companySaid(signedIn.body));
  const receipt = signedIn.body.events?.find((e: { message?: { data?: { receipt?: string } } }) => e.message?.data?.receipt)?.message.data.receipt;
  console.log(receipt ? `receipt: ${receipt}` : JSON.stringify(signedIn.body, null, 2));
  server.close();
}

if (process.argv[1] === fileURLToPath(import.meta.url)) await main();
