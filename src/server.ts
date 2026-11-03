/**
 * The proving-ground service: the x401 door, the Lab test issuer, runs, and
 * the public wall with its live feed. Every route is in `route` below.
 *
 *   GET|POST /pg/x401/ledger             the door, anonymous
 *   GET|POST /pg/x401/r/<run>/ledger     the door, on a run's row of the wall
 *   POST     /pg/runs                    start a run: {"handle": "..."}
 *   POST     /pg/issuer/credential       get a test credential: {"jwk": <holder public JWK>}
 *   GET      /pg/state, /pg/events       the wall's data, and a ping on every change (SSE)
 *   GET      /pg/attempts/<id>           one attempt's timeline
 *   GET      /pg/jwks.json               door and issuer keys (verify receipts here)
 *   GET      /.well-known/did.json       the door's did:web (its client_id)
 *   GET      /.well-known/jwt-vc-issuer/pg/issuer   SD-JWT VC issuer metadata
 */
import { readFileSync } from 'node:fs';
import { createServer, type IncomingMessage, type ServerResponse } from 'node:http';
import { BASE_URL, PORT, didDocument, door, issuer } from './lab.ts';
import { issueCredential, issuerMetadata } from './issuer.ts';
import * as store from './store.ts';
import { DOOR, THROUGH, x401Door } from './x401.ts';

const WALL = readFileSync(new URL('../public/index.html', import.meta.url));
const HANDLE = /^[a-z0-9][a-z0-9-]{1,30}$/;
const DOOR_PATH = /^\/pg\/x401(?:\/r\/([A-Za-z0-9_-]{22}))?\/ledger$/;

// Browser-based agents and wallets need to read and send the x401 headers cross-origin.
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
  if (doorMatch && (m === 'GET' || m === 'POST')) {
    const runId = doorMatch[1] ?? null;
    if (runId && !store.runExists(runId)) return send(res, 404, { error: 'unknown_run', message: `No run with that ID. Start one at ${BASE_URL}/` });
    const proof = req.headers['proof-response'];
    const r = await x401Door(runId, runId ? '/pg/x401/r/…/ledger' : '/pg/x401/ledger', m, Array.isArray(proof) ? proof.join(',') : proof);
    return send(res, r.status, r.body, r.headers);
  }

  if (m === 'GET') {
    if (p === '/') return send(res, 200, WALL);
    if (p === '/pg/state') return send(res, 200, { ...DOOR, ...store.wallState(THROUGH) });
    if (p === '/pg/jwks.json') return send(res, 200, { keys: [door.jwk, issuer.jwk] });
    if (p === '/.well-known/did.json') return send(res, 200, didDocument);
    if (p === '/.well-known/jwt-vc-issuer/pg/issuer') return send(res, 200, issuerMetadata);
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
      door: `${BASE_URL}/pg/x401/r/${run.id}/ledger`,
      note: 'Point your agent at the door URL. The run ID labels attempts on your row; it is not a credential, so start a new run if it leaks.',
    });
  }

  if (m === 'POST' && p === '/pg/issuer/credential') {
    const { jwk } = await readJson(req);
    try {
      return send(res, 200, { format: 'dc+sd-jwt', credential: await issueCredential(jwk), issuer: issuerMetadata.issuer });
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
