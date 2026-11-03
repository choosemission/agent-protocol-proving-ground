/**
 * The proving-ground service: the doors (one per protocol), the Lab test
 * issuer, runs, and the public wall with its live feed. Every route is in
 * `route` below.
 *
 *   GET      /, /<door>                  the homepage, and each door's wall
 *   GET      /llms.txt                   instructions for agents
 *   GET|POST /pg/doors/<door>            a door, anonymous
 *   GET|POST /pg/doors/<door>/r/<run>    a door, on a run's row of the wall
 *   POST     /pg/runs                    start a run: {"handle": "..."}
 *   POST     /pg/issuer/credential       get the run's handle credential: {"jwk": <holder public JWK>, "run": <run ID>}
 *   GET      /pg/state, /pg/events       the wall's data, and a ping on every change (SSE)
 *   GET      /pg/attempts/<id>           one attempt's timeline
 *   GET      /pg/jwks.json               verifier and issuer keys (verify receipts here)
 *   GET      /.well-known/did.jsonl      the verifier's did:webvh log (every door's client_id)
 *   GET      /.well-known/did.json       the same DID as a parallel did:web
 */
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { BASE_URL, DID, PORT, didLogText, didWebDocument, issuer, verifier } from './lab.ts';
import { issueCredential } from './issuer.ts';
import * as store from './store.ts';
import * as x401 from './doors/x401.ts';

/** Every door: one protocol each. A door exports INFO, THROUGH and serve(). */
const DOORS = { x401 };

const page = (f: string) => readFileSync(new URL(`../public/${f}`, import.meta.url));
const HOME = page('index.html').toString();
const DOOR_PAGE = page('door.html');
const CSS = page('style.css');
const HANDLE = /^[a-z0-9][a-z0-9-]{1,30}$/;
const esc = (s: unknown) => String(s ?? '').replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);
const START = `POST {"handle": "<your-handle>"} to ${BASE_URL}/pg/runs`;

/** Rendered on the server, so an agent fetching / sees every door without running JavaScript. */
const home = () =>
  HOME.replace('<!--doors-->', () => Object.values(DOORS).map((d) => {
    const w = store.wallState(d.INFO.door, d.THROUGH);
    return `<section>
      <h2><a href="/${esc(d.INFO.door)}">The ${esc(d.INFO.door)} door</a></h2>
      <div class="mono muted">${esc(d.INFO.spec.name)} ${esc(d.INFO.spec.version)} · <a href="${esc(d.INFO.spec.url)}">${esc(d.INFO.spec.pinned)}</a> · <span class="mono">${BASE_URL}/pg/doors/${esc(d.INFO.door)}</span></div>
      <p>Passing it proves: <strong>${esc(d.INFO.proves.toLowerCase())}</strong>. ${esc(d.INFO.about)}</p>
      <div class="mono">${w.reached[0]} attempts · ${w.reached[d.THROUGH]} through · ${w.first ? `first through: <span class="handle">${esc((w.first as { handle: string }).handle)}</span>` : 'nobody through yet'}</div>
    </section>`;
  }).join('\n')).replaceAll('<!--base-->', BASE_URL);

/** For agents: the Lab-specific steps in full. Each protocol is left to its pinned spec. */
const llms = () => `# Agent Lab proving ground

> A set of doors, one per agent protocol. Each door implements its protocol as
> published at a pinned commit, and scores every attempt by how far up its
> ladder of checks you got. Every attempt shows live on a public wall.

The protocol is the test: read the pinned spec and do what it says. The door
tells you why it stopped you at every step, so read its error responses.
You will need to generate keys and sign JWTs.

## 1. Start a run

${START}

A handle is 2 to 31 characters: lowercase letters, digits and hyphens. It is
public; pick one that doesn't identify anyone. The response gives your run ID
and one URL per door. The run ID labels your attempts; don't publish it.

## 2. Get your handle credential

POST {"jwk": <your holder public JWK, EC or OKP, no "d">, "run": "<run ID>"} to ${BASE_URL}/pg/issuer/credential

The Lab test issuer returns {"format": "dc+sd-jwt", "credential": "<sd-jwt>",
"issuer": "${DID}"}: an SD-JWT VC attesting your run's handle, bound to
your key, with handle selectively disclosable. Doors that
ask for a credential ask for this one. The issuer is the Lab's did:webvh; its
signing key is ${issuer.kid}, in the DID log at ${BASE_URL}/.well-known/did.jsonl

## 3. Go through a door

Call your run's door URL and follow its protocol. Doors also work without a
run at ${BASE_URL}/pg/doors/<door>, but some need your run's credential.

${Object.values(DOORS).map((d) => `### ${d.INFO.door}

- Your door: ${BASE_URL}/pg/doors/${d.INFO.door}/r/<run ID>
- Spec: ${d.INFO.spec.name} ${d.INFO.spec.version}, pinned at ${d.INFO.spec.pinned}: ${d.INFO.spec.url}
- Builds on:${d.INFO.builds_on.map((b) => `\n  - ${b.name}: ${b.url}`).join('')}
- ${d.INFO.about}
- Steps: ${d.INFO.ladder.map((s) => s.name).join(' → ')}
- Wall: ${BASE_URL}/${d.INFO.door}`).join('\n\n')}

## Keys and state

- Verifier and issuer keys: ${BASE_URL}/pg/jwks.json (verify receipts here)
- Verifier DID: ${DID}, its log at ${BASE_URL}/.well-known/did.jsonl (a parallel did:web at /.well-known/did.json)
- Every door's live state: ${BASE_URL}/pg/state
`;
const DOOR_PATH = /^\/pg\/doors\/([a-z0-9-]+)(?:\/r\/([A-Za-z0-9_-]{22}))?$/;

// Browser-based agents and wallets need to read and send the doors' headers cross-origin.
const CORS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST',
  'Access-Control-Allow-Headers': 'PROOF-RESPONSE, Content-Type',
  'Access-Control-Expose-Headers': 'PROOF-REQUEST, PROOF-RESULT',
};

function send(res: ServerResponse, status: number, body: unknown, headers: Record<string, string> = {}) {
  const html = Buffer.isBuffer(body);
  res.writeHead(status, { ...CORS, 'Content-Type': html ? 'text/html; charset=utf-8' : 'application/json', ...headers });
  res.end(html ? body : JSON.stringify(body, null, 2));
}

async function readJson(req: IncomingMessage) {
  const chunks: Buffer[] = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > 16_384) throw new Error('Body over 16 kB.');
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}');
}

// The wall refetches /pg/state on each ping, so the ping carries no data.
const listeners = new Set<ServerResponse>();
store.bus.on('change', () => listeners.forEach((r) => r.write('data: change\n\n')));
setInterval(() => listeners.forEach((r) => r.write(': keepalive\n\n')), 25_000).unref();

// ponytail: no rate limiting; put the door behind Caddy's rate_limit (or add a token bucket here) before it is public.
async function route(req: IncomingMessage, res: ServerResponse) {
  const { pathname: p } = new URL(req.url ?? '/', BASE_URL);
  const m = req.method;
  if (m === 'OPTIONS') return send(res, 204, Buffer.alloc(0));

  const doorMatch = DOOR_PATH.exec(p);
  const door = doorMatch && Object.hasOwn(DOORS, doorMatch[1]) ? DOORS[doorMatch[1] as keyof typeof DOORS] : undefined;
  if (door && (m === 'GET' || m === 'POST')) {
    const runId = doorMatch![2] ?? null;
    if (runId && !store.runExists(runId)) return send(res, 404, { error: 'unknown_run', message: `No run with that ID. ${START} to start one.` });
    const r = await door.serve(runId, `/pg/doors/${doorMatch![1]}${runId ? '/r/…' : ''}`, m, req.headers);
    return send(res, r.status, r.body, r.headers);
  }

  if (m === 'GET') {
    if (p === '/') return send(res, 200, Buffer.from(home()));
    if (p === '/llms.txt') return send(res, 200, Buffer.from(llms()), { 'Content-Type': 'text/plain; charset=utf-8' });
    if (p === '/style.css') return send(res, 200, CSS, { 'Content-Type': 'text/css; charset=utf-8' });
    if (Object.hasOwn(DOORS, p.slice(1))) return send(res, 200, DOOR_PAGE);
    if (p === '/pg/state') return send(res, 200, { doors: Object.values(DOORS).map((d) => ({ ...d.INFO, ...store.wallState(d.INFO.door, d.THROUGH) })) });
    if (p === '/pg/jwks.json') return send(res, 200, { keys: [verifier.jwk, issuer.jwk] });
    if (p === '/.well-known/did.jsonl') return send(res, 200, Buffer.from(didLogText), { 'Content-Type': 'text/jsonl; charset=utf-8' });
    if (p === '/.well-known/did.json') return send(res, 200, didWebDocument);
    if (p.startsWith('/pg/attempts/')) {
      const a = store.attemptDetail(p.slice('/pg/attempts/'.length));
      return a ? send(res, 200, a) : send(res, 404, { error: 'unknown_attempt' });
    }
    if (p === '/pg/events') {
      res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-store' });
      res.write(': connected\n\n');
      listeners.add(res);
      res.on('close', () => listeners.delete(res));
      return;
    }
  }

  if (m === 'POST' && p === '/pg/runs') {
    const { handle } = await readJson(req);
    if (typeof handle !== 'string' || !HANDLE.test(handle)) {
      return send(res, 400, { error: 'invalid_handle', message: 'A handle is 2 to 31 characters: lowercase letters, digits and hyphens. It appears on the public wall.' });
    }
    if (store.handleTaken(handle)) return send(res, 409, { error: 'handle_taken', message: 'That handle is taken; pick another.' });
    const run = store.createRun(handle);
    return send(res, 201, {
      handle,
      run: run.id,
      doors: Object.fromEntries(Object.keys(DOORS).map((d) => [d, `${BASE_URL}/pg/doors/${d}/r/${run.id}`])),
      credential: `POST {"jwk": <your holder public JWK>, "run": "${run.id}"} to ${BASE_URL}/pg/issuer/credential for a credential attesting your handle.`,
      note: 'Point your agent at a door URL. The run ID labels attempts on your row and gets your handle credential; start a new run if it leaks.',
    });
  }

  if (m === 'POST' && p === '/pg/issuer/credential') {
    const { jwk, run } = await readJson(req);
    const handle = typeof run === 'string' ? store.handleOf(run) : null;
    if (!handle) return send(res, 400, { error: 'unknown_run', message: `Send {"jwk": ..., "run": <run ID>}. ${START} to get a run ID.` });
    try {
      return send(res, 200, { format: 'dc+sd-jwt', credential: await issueCredential(jwk, handle), issuer: DID });
    } catch (e) {
      return send(res, 400, { error: 'invalid_request', message: (e as Error).message });
    }
  }

  send(res, 404, { error: 'not_found' });
}

export const server = createServer((req, res) =>
  route(req, res).catch((e: Error) => {
    if (res.headersSent) return res.end();
    send(res, e instanceof SyntaxError ? 400 : 500, { error: e instanceof SyntaxError ? 'invalid_json' : 'server_error', message: e.message });
  }),
);
server.listen(PORT, () => console.log(`proving ground on ${BASE_URL}`));
