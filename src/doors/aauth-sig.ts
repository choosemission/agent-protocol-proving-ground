/**
 * The aauth door's own verifier: HTTP Message Signatures (RFC 9421) as AAuth -11 profiles them,
 * the Signature-Key header's jwt scheme (draft-hardt-httpbis-signature-key-09), and AAuth token
 * verification with key discovery at {iss}/.well-known/{dwk}. Written for the door, not taken from
 * an AAuth library, so that an agent built on a library is checked by a second implementation.
 *
 * Every failure is a Fail: the Signature-Error code the spec gives it, the door's finer `pg` code,
 * the token it was about (`stage`), and a reason in plain words.
 */
import { createHash, createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { calculateJwkThumbprint, decodeJwt, decodeProtectedHeader, errors, importJWK, jwtVerify, type JWK, type JWTPayload } from 'jose';
import { DEV, fetchPublic } from '../lab.ts';

/** The algorithms this verifier implements: Ed25519 is a MUST, ES256 a SHOULD (11.3.1). */
export const ALGS = ['Ed25519', 'ES256'] as const;
export const ACCEPT_ALG = ALGS.join(', ');
/** The signature validity window for `created`, and the bound on a token's future `iat` (11.3.4). */
export const WINDOW_S = 60;
/** The four components every AAuth signature covers (11.3.3.1). */
export const BASE_COMPONENTS = ['@method', '@authority', '@path', 'signature-key'];
const PRIVATE_MEMBERS = ['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth'];
const nowS = () => Math.floor(Date.now() / 1000);

export type Stage = 'request' | 'agent' | 'person' | 'auth';
export type TokenKind = 'agent' | 'person' | 'auth' | 'resource';
export const TYP: Record<TokenKind, string> = { agent: 'aa-agent+jwt', person: 'aa-person+jwt', auth: 'aa-auth+jwt', resource: 'aa-resource+jwt' };
const DWK: Record<TokenKind, string[]> = { agent: ['aauth-agent.json'], person: ['aauth-person.json'], auth: ['aauth-person.json', 'aauth-access.json'], resource: ['aauth-resource.json'] };
const KIND_OF_TYP = Object.fromEntries(Object.entries(TYP).map(([k, t]) => [t, k])) as Record<string, TokenKind>;

/** A refusal: `sig` is the Signature-Error code, `pg` the door's own, `stage` which token it concerns. */
export class Fail extends Error {
  sig: string;
  pg: string;
  stage: Stage;
  headers: Record<string, string>;
  /** Sent back to the caller only, never stored: it can hold the caller's own tokens. */
  debug?: Record<string, unknown>;
  constructor(stage: Stage, sig: string, pg: string, message: string, headers: Record<string, string> = {}) {
    super(message);
    this.stage = stage;
    this.sig = sig;
    this.pg = pg;
    this.headers = headers;
  }
}

// ---- Structured Field Values (RFC 9651): the parts these headers use ----

export class Token {
  value: string;
  constructor(value: string) { this.value = value; }
}
export class Bytes {
  value: Buffer;
  constructor(value: Buffer) { this.value = value; }
}
export type Bare = string | number | boolean | Token | Bytes;
export type Params = Map<string, Bare>;
export type Item = { value: Bare; params: Params };
export type Member = { value: Bare | Item[]; params: Params };

/** Parses a Dictionary; throws on anything RFC 9651 refuses. */
export function parseDictionary(input: string): Map<string, Member> {
  let i = 0;
  const s = input;
  const fail = (what: string): never => { throw new SyntaxError(`${what} at position ${i}`); };
  const ows = () => { while (s[i] === ' ' || s[i] === '\t') i++; };
  const sp = () => { while (s[i] === ' ') i++; };
  const key = () => {
    if (!/[a-z*]/.test(s[i] ?? '')) fail('expected a key');
    const start = i;
    while (/[a-z0-9_\-.*]/.test(s[i] ?? '')) i++;
    return s.slice(start, i);
  };
  const bare = (): Bare => {
    const c = s[i] ?? '';
    if (c === '-' || /[0-9]/.test(c)) {
      const m = /^-?\d{1,15}(\.\d{1,3})?/.exec(s.slice(i)) ?? fail('bad number');
      i += m[0].length;
      return Number(m[0]);
    }
    if (c === '"') {
      let out = '';
      i++;
      for (;;) {
        const ch = s[i++] ?? fail('unterminated string');
        if (ch === '\\') {
          const n = s[i++];
          if (n !== '"' && n !== '\\') fail('bad escape');
          out += n;
        } else if (ch === '"') return out;
        else if (ch < ' ' || ch > '~') fail('bad string character');
        else out += ch;
      }
    }
    if (c === ':') {
      const end = s.indexOf(':', i + 1);
      if (end < 0) fail('unterminated byte sequence');
      const b64 = s.slice(i + 1, end);
      if (!/^[A-Za-z0-9+/]*={0,2}$/.test(b64)) fail('bad byte sequence');
      i = end + 1;
      return new Bytes(Buffer.from(b64, 'base64'));
    }
    if (c === '?') {
      const v = s[i + 1];
      if (v !== '0' && v !== '1') fail('bad boolean');
      i += 2;
      return v === '1';
    }
    if (/[A-Za-z*]/.test(c)) {
      const start = i;
      while (/[!#$%&'*+\-.^_`|~0-9A-Za-z:/]/.test(s[i] ?? '')) i++;
      return new Token(s.slice(start, i));
    }
    return fail('expected an item');
  };
  const params = (): Params => {
    const p: Params = new Map();
    while (s[i] === ';') {
      i++;
      sp();
      const k = key();
      let v: Bare = true;
      if (s[i] === '=') { i++; v = bare(); }
      p.set(k, v);
    }
    return p;
  };
  const member = (): Member => {
    if (s[i] === '(') {
      i++;
      const items: Item[] = [];
      for (;;) {
        sp();
        if (s[i] === ')') { i++; break; }
        items.push({ value: bare(), params: params() });
        if (s[i] !== ' ' && s[i] !== ')') fail('bad inner list');
      }
      return { value: items, params: params() };
    }
    return { value: bare(), params: params() };
  };
  const out = new Map<string, Member>();
  sp();
  while (i < s.length) {
    const k = key();
    if (s[i] === '=') { i++; out.set(k, member()); } else out.set(k, { value: true, params: params() });
    ows();
    if (i >= s.length) break;
    if (s[i] !== ',') fail('expected a comma');
    i++;
    ows();
    if (i >= s.length) fail('trailing comma');
  }
  return out;
}

const serializeBare = (v: Bare): string =>
  typeof v === 'string' ? `"${v.replace(/[\\"]/g, (c) => `\\${c}`)}"`
  : typeof v === 'number' ? String(v)
  : typeof v === 'boolean' ? (v ? '?1' : '?0')
  : v instanceof Token ? v.value
  : `:${v.value.toString('base64')}:`;
const serializeParams = (p: Params) => [...p].map(([k, v]) => (v === true ? `;${k}` : `;${k}=${serializeBare(v)}`)).join('');
/** Serializes a dictionary member value, the way @signature-params needs it. */
export const serializeInnerList = (items: Item[], params: Params) => `(${items.map((x) => serializeBare(x.value) + serializeParams(x.params)).join(' ')})${serializeParams(params)}`;
/** An sf-string, for building response headers. */
export const sfString = (s: string) => serializeBare(s);

// ---- Identifiers and keys ----

/** Why a string isn't a server identifier (11.1.1): https, scheme and host only, lowercase. The dev switch allows http and a port. Null if it is one. */
export function serverIdProblem(v: unknown): string | null {
  if (typeof v !== 'string' || !URL.canParse(v)) return 'is not a URL';
  const u = new URL(v);
  if (u.protocol !== 'https:' && !(DEV && u.protocol === 'http:')) return `must use https${DEV ? ' (http is allowed while the proving ground runs on localhost)' : ''}`;
  if (u.port && !DEV) return 'must not have a port';
  if (v !== `${u.protocol}//${u.host}`) return 'must be the scheme and host only: lowercase, with no path, trailing slash, query or fragment';
  return null;
}

/** A JWK as Algorithm Determination requires it: a fully-specified alg this verifier implements, kty and crv agreeing with it, public only. */
export function checkJwk(jwk: unknown, stage: Stage, what: string): JWK & { alg: (typeof ALGS)[number] } {
  const k = jwk as Record<string, unknown> | undefined;
  const bad = (sig: string, pg: string, m: string, headers: Record<string, string> = {}): never => { throw new Fail(stage, sig, pg, `${what}: ${m}`, headers); };
  if (!k || typeof k !== 'object' || typeof k.kty !== 'string') bad('invalid_key', 'key_invalid', 'is not a JWK (no kty).');
  if (PRIVATE_MEMBERS.some((m) => m in k!)) bad('invalid_key', 'key_invalid', 'has private key members. Publish public keys only, and replace this one.');
  if (typeof k!.alg !== 'string') bad('unsupported_algorithm', 'key_unsupported', 'has no alg. Every key AAuth conveys carries a fully-specified alg (11.3.1).', { 'Accept-Signature-Alg': ACCEPT_ALG });
  if (k!.alg === 'EdDSA') bad('unsupported_algorithm', 'key_unsupported', 'has alg EdDSA, which is polymorphic and forbidden; use Ed25519 (RFC 9864).', { 'Accept-Signature-Alg': ACCEPT_ALG });
  if (!(ALGS as readonly string[]).includes(k!.alg as string)) bad('unsupported_algorithm', 'key_unsupported', `has alg ${k!.alg}; this door accepts ${ACCEPT_ALG}.`, { 'Accept-Signature-Alg': ACCEPT_ALG });
  const b64 = (x: unknown, len: number) => typeof x === 'string' && /^[A-Za-z0-9_-]+$/.test(x) && Buffer.from(x, 'base64url').length === len;
  if (k!.alg === 'Ed25519' && !(k!.kty === 'OKP' && k!.crv === 'Ed25519' && b64(k!.x, 32))) bad('invalid_key', 'key_invalid', 'has alg Ed25519, so it must be kty OKP, crv Ed25519, with a 32-byte x.');
  if (k!.alg === 'ES256' && !(k!.kty === 'EC' && k!.crv === 'P-256' && b64(k!.x, 32) && b64(k!.y, 32))) bad('invalid_key', 'key_invalid', 'has alg ES256, so it must be kty EC, crv P-256, with x and y.');
  return k as JWK & { alg: (typeof ALGS)[number] };
}

/** The RFC 7638 thumbprint, over the required members only. */
export const thumbprint = (jwk: JWK) => calculateJwkThumbprint(jwk);

// ---- Key discovery: {iss}/.well-known/{dwk} → jwks_uri → kid (11.4) ----

type Discovered = { at: number; keys: JWK[] };
// ponytail: unbounded in-memory cache; fine for a test door, bound it (LRU) before real traffic.
const cache = new Map<string, Discovered>();
const CACHE_MS = 5 * 60_000;
/** Keys this server holds itself (the Lab test PS, the door's resource key), so it never fetches its own origin. */
const local = new Map<string, () => JWK[]>();
export const holdLocally = (iss: string, dwk: string, keys: () => JWK[]) => local.set(`${iss}|${dwk}`, keys);

async function getJson(u: string, stage: Stage, kind: TokenKind, what: string) {
  const fail = (m: string): never => { throw new Fail(stage, 'invalid_jwt', `${kind}_issuer_unreachable`, m); };
  const url = URL.canParse(u) ? new URL(u) : fail(`${what} (${u}) is not a URL.`);
  if (url.protocol !== 'https:' && !(DEV && url.protocol === 'http:')) fail(`${what} (${u}) must be an https URL.`);
  let res: Response;
  try {
    res = await fetchPublic(url, { redirect: 'manual', signal: AbortSignal.timeout(5000), headers: { accept: 'application/json' } });
  } catch (e) {
    return fail(`Fetching ${what} (${u}) failed: ${(e as Error).message}`);
  }
  if (res.status !== 200) fail(`Fetching ${what} (${u}) returned ${res.status}; it must return 200 without redirecting.`);
  const text = await res.text();
  if (text.length > 64_000) fail(`${what} (${u}) is over 64 kB.`);
  try {
    return JSON.parse(text);
  } catch {
    return fail(`${what} (${u}) is not JSON.`);
  }
}

/** The issuer's keys: the metadata document (issuer checked by byte equality, 11.2), then its jwks_uri. */
async function discover(iss: string, dwk: string, stage: Stage, kind: TokenKind, fresh: boolean): Promise<Discovered> {
  const held = local.get(`${iss}|${dwk}`);
  if (held) return { at: Date.now(), keys: held() };
  const k = `${iss}|${dwk}`;
  const hit = cache.get(k);
  // Refetch at most once a minute, even for an unknown kid (11.4).
  if (hit && (Date.now() - hit.at < (fresh ? 60_000 : CACHE_MS))) return hit;
  const where = `${iss}/.well-known/${dwk}`;
  const meta = await getJson(where, stage, kind, 'The issuer metadata');
  if (!meta || typeof meta !== 'object' || !('issuer' in meta)) throw new Fail(stage, 'issuer_missing', `${kind}_issuer_missing`, `${where} has no issuer member.`);
  if (meta.issuer !== iss) throw new Fail(stage, 'issuer_mismatch', `${kind}_issuer_mismatch`, `${where} says issuer ${JSON.stringify(meta.issuer)}; it must be ${iss}, byte for byte.`);
  if (typeof meta.jwks_uri !== 'string') throw new Fail(stage, 'invalid_jwt', `${kind}_issuer_unreachable`, `${where} has no jwks_uri.`);
  const jwks = await getJson(meta.jwks_uri, stage, kind, 'The issuer JWKS');
  if (!Array.isArray(jwks?.keys)) throw new Fail(stage, 'invalid_jwt', `${kind}_issuer_unreachable`, `${meta.jwks_uri} must be {"keys": [...]}.`);
  const d = { at: Date.now(), keys: jwks.keys as JWK[] };
  cache.set(k, d);
  return d;
}

export type Verified = { kind: TokenKind; header: Record<string, unknown>; claims: JWTPayload & Record<string, unknown>; cnf?: JWK & { alg: string } };

/**
 * An AAuth token, per 11.5.2 and its own section: typ, dwk, the issuer's key by kid, the signature,
 * exp with no tolerance, iss a server identifier, and the lifetime caps. `aud` when the caller
 * knows whom it must be for. `stage` is the step a failure belongs to; a caller verifying a token
 * from a request body maps the Fail to that parameter's own error codes.
 */
export async function verifyToken(jwt: string, kind: TokenKind, o: { stage: Stage; aud?: string; requireCnf?: boolean } = { stage: 'agent' }): Promise<Verified> {
  const { stage } = o;
  const bad = (m: string, pg = `${kind}_token_invalid`, sig = 'invalid_jwt'): never => { throw new Fail(stage, sig, pg, m); };
  let header: Record<string, unknown>;
  let claims: JWTPayload & Record<string, unknown>;
  try {
    header = decodeProtectedHeader(jwt) as Record<string, unknown>;
    claims = decodeJwt(jwt) as JWTPayload & Record<string, unknown>;
  } catch {
    return bad(`The ${kind} token is not a well-formed JWT.`);
  }
  const name = `The ${kind} token`;
  if (header.typ !== TYP[kind]) bad(`${name}'s typ must be ${TYP[kind]}; got ${JSON.stringify(header.typ)}.`);
  if (typeof header.alg !== 'string' || !(ALGS as readonly string[]).includes(header.alg)) bad(`${name} is signed with alg ${JSON.stringify(header.alg)}; this door accepts ${ACCEPT_ALG} (never none, EdDSA or a symmetric algorithm).`);
  if (typeof header.kid !== 'string') bad(`${name} has no kid in its header.`);
  const iss = claims.iss;
  const issProblem = serverIdProblem(iss);
  if (issProblem) bad(`${name}'s iss ${JSON.stringify(iss)} ${issProblem}.`);
  if (typeof claims.dwk !== 'string' || !DWK[kind].includes(claims.dwk)) bad(`${name}'s dwk must be ${DWK[kind].join(' or ')}; got ${JSON.stringify(claims.dwk)}.`);
  for (const c of ['iat', 'exp']) if (typeof claims[c] !== 'number') bad(`${name} needs ${c}.`);
  if (kind !== 'agent' && typeof claims.jti !== 'string') bad(`${name} needs jti.`);
  if (kind !== 'resource' && (o.requireCnf ?? true)) {
    const j = (claims.cnf as { jwk?: unknown } | undefined)?.jwk;
    if (!j) bad(`${name} needs cnf.jwk, the key it is bound to.`);
  }

  // The issuer's key, then the signature. Nothing about a claim's value is acted on before it verifies.
  let found = await discover(iss as string, claims.dwk as string, stage, kind, false);
  let key = found.keys.find((k) => k.kid === header.kid);
  if (!key) {
    found = await discover(iss as string, claims.dwk as string, stage, kind, true);
    key = found.keys.find((k) => k.kid === header.kid);
  }
  if (!key) throw new Fail(stage, 'unknown_key', `${kind}_unknown_key`, `No key in ${iss}'s JWKS (via /.well-known/${claims.dwk}) has kid ${JSON.stringify(header.kid)}.`);
  const issuerKey = checkJwk(key, stage, `The issuer key ${header.kid}`);
  if (issuerKey.alg !== header.alg) bad(`${name} is signed with alg ${header.alg}, but key ${header.kid} is for ${issuerKey.alg}.`);
  try {
    await jwtVerify(jwt, await importJWK(issuerKey, issuerKey.alg), { algorithms: [issuerKey.alg], typ: TYP[kind] });
  } catch (e) {
    if (e instanceof errors.JWTExpired) throw new Fail(stage, 'expired_jwt', `${kind}_token_expired`, `${name} expired at ${new Date((claims.exp as number) * 1000).toISOString()}. Get a fresh one.`);
    return bad(`${name} does not verify against ${iss}'s key ${header.kid}: ${(e as Error).message}`);
  }
  if ((claims.iat as number) > nowS() + WINDOW_S) throw new Fail(stage, 'clock_skew', `${kind}_clock_skew`, `${name}'s iat is ${(claims.iat as number) - nowS()} seconds ahead of this server's clock (see the Date header).`);
  if ((kind === 'person' || kind === 'auth') && (claims.exp as number) - (claims.iat as number) > 3600) bad(`${name} lives ${(claims.exp as number) - (claims.iat as number)} seconds; exp - iat must not exceed 3600.`);
  if (o.aud !== undefined && claims.aud !== o.aud) bad(`${name}'s aud must be ${o.aud}, as one string; got ${JSON.stringify(claims.aud)}.`, `${kind}_aud`);
  const cnfJwk = (claims.cnf as { jwk?: unknown } | undefined)?.jwk;
  const cnf = cnfJwk === undefined ? undefined : checkJwk(cnfJwk, stage, `${name}'s cnf.jwk`);
  return { kind, header, claims, cnf };
}

// ---- Verifying a signed request (11.3.4) ----

export type SignedRequest = { method: string; authority: string; path: string; query: string; scheme: string; headers: Record<string, string | string[] | undefined>; bytes: Buffer };
export type VerifiedRequest = Verified & { jwt: string; thumbprint: string; covered: string[]; created: number };

const header = (r: SignedRequest, name: string) => {
  const v = r.headers[name];
  return Array.isArray(v) ? v.join(', ') : v;
};

/** True if the request carries no signature at all: the resource then challenges with requirement=agent-token. */
export const unsigned = (r: SignedRequest) => !['signature', 'signature-input', 'signature-key'].some((h) => header(r, h) !== undefined);

/** The value of one covered component, per RFC 9421 §2. */
function componentValue(r: SignedRequest, c: Item): string {
  const bad = (m: string): never => { throw new Fail('request', 'invalid_signature', 'signature_headers', m); };
  if (typeof c.value !== 'string') bad('Every covered component in Signature-Input is a string.');
  const name = c.value as string;
  if (c.params.size) bad(`Covered component "${name}" has parameters (${[...c.params.keys()].join(', ')}); this door implements components without parameters.`);
  switch (name) {
    case '@method': return r.method;
    case '@authority': return r.authority;
    case '@path': return r.path || '/';
    case '@query': return `?${r.query}`;
    case '@scheme': return r.scheme;
    case '@request-target': return `${r.path}${r.query ? `?${r.query}` : ''}`;
    case '@target-uri': return `${r.scheme}://${r.authority}${r.path}${r.query ? `?${r.query}` : ''}`;
  }
  if (name.startsWith('@')) bad(`Covered component "${name}" isn't one this door implements for a request.`);
  if (name !== name.toLowerCase()) bad(`Covered field names are lowercase; got "${name}".`);
  const v = header(r, name);
  if (v === undefined) throw new Fail('request', 'invalid_signature', 'signature_headers', `Signature-Input covers "${name}", but the request has no ${name} header.`);
  return v.trim();
}

/** The signature base (RFC 9421 §2.5). */
export function signatureBase(r: SignedRequest, items: Item[], params: Params) {
  return [...items.map((c) => `"${c.value as string}": ${componentValue(r, c)}`), `"@signature-params": ${serializeInnerList(items, params)}`].join('\n');
}

/** Content-Digest (RFC 9530), checked whenever the signature covers it. */
function checkDigest(r: SignedRequest, stage: Stage) {
  const bad = (m: string): never => { throw new Fail(stage, 'invalid_signature', 'content_digest', m); };
  let d: Map<string, Member>;
  try {
    d = parseDictionary(header(r, 'content-digest') ?? '');
  } catch {
    return bad('Content-Digest is not a structured-field dictionary.');
  }
  const known = [...d].filter(([alg]) => alg === 'sha-256' || alg === 'sha-512');
  if (!known.length) bad('Content-Digest needs a sha-256 or sha-512 member.');
  for (const [alg, m] of known) {
    if (!(m.value instanceof Bytes)) bad(`Content-Digest ${alg} must be a byte sequence, :base64:.`);
    if (!createHash(alg.replace('-', '')).update(r.bytes).digest().equals((m.value as Bytes).value)) bad(`Content-Digest ${alg} doesn't match the body sent.`);
  }
}

/**
 * Verifies a signed AAuth request in the order 11.3.4 gives, and the token it carries in
 * Signature-Key (jwt scheme). `require` adds to the four base components; `aud` is what a person
 * or auth token must be addressed to. Which token types an endpoint takes is the caller's decision.
 */
export async function verifyRequest(r: SignedRequest, o: { require?: string[]; aud?: string } = {}): Promise<VerifiedRequest> {
  const req = (sig: string, pg: string, m: string, headers?: Record<string, string>): never => { throw new Fail('request', sig, pg, m, headers); };
  // 1. The three headers.
  const missing = ['signature', 'signature-input', 'signature-key'].filter((h) => header(r, h) === undefined);
  if (missing.length) req('invalid_signature', 'signature_headers', `The request has no ${missing.join(' or ')} header. Every AAuth request carries Signature, Signature-Input and Signature-Key (11.3).`);
  let inputs: Map<string, Member>, sigs: Map<string, Member>, keys: Map<string, Member>;
  try {
    inputs = parseDictionary(header(r, 'signature-input')!);
    sigs = parseDictionary(header(r, 'signature')!);
    keys = parseDictionary(header(r, 'signature-key')!);
  } catch (e) {
    return req('invalid_signature', 'signature_headers', `Signature, Signature-Input and Signature-Key are structured-field dictionaries (RFC 9651); one doesn't parse: ${(e as Error).message}.`);
  }
  // The label being verified: the first in Signature-Input with a Signature-Key member.
  const label = [...inputs.keys()].find((l) => keys.has(l)) ?? req('invalid_signature', 'signature_headers', `No label in Signature-Input (${[...inputs.keys()].join(', ')}) has a member in Signature-Key. Use the same label in all three headers.`);
  const input = inputs.get(label)!;
  const sig = sigs.get(label);
  if (!Array.isArray(input.value)) req('invalid_signature', 'signature_headers', `Signature-Input ${label} must be an inner list of covered components.`);
  if (!sig || !(sig.value instanceof Bytes)) req('invalid_signature', 'signature_headers', `Signature has no byte sequence for label ${label}.`);
  const items = input.value as Item[];

  // 2. Covered components.
  const covered = items.map((x) => x.value as string);
  const required = [...BASE_COMPONENTS, ...(o.require ?? [])];
  const absent = required.filter((c) => !covered.includes(c));
  if (absent.length) {
    req('invalid_input', 'signature_components', `The signature must cover ${required.map((c) => `"${c}"`).join(' ')}; it doesn't cover ${absent.map((c) => `"${c}"`).join(' ')}.`, {
      'Signature-Error': `error=invalid_input, required_input=(${required.map(sfString).join(' ')})`,
    });
  }

  // 3. created, within the window. expires is honored when present.
  const created = input.params.get('created');
  if (typeof created !== 'number' || !Number.isInteger(created)) req('invalid_signature', 'signature_stale', `Signature-Input ${label} needs created, an integer (Unix time).`);
  const age = nowS() - (created as number);
  if (age > WINDOW_S) req('invalid_signature', 'signature_stale', `created is ${age} seconds old; the window is ${WINDOW_S}. Sign each request when you send it.`);
  if (-age > WINDOW_S) req('clock_skew', 'signature_clock_skew', `created is ${-age} seconds ahead of this server's clock (see the Date header).`);
  const expires = input.params.get('expires');
  if (expires !== undefined && (typeof expires !== 'number' || expires < nowS())) req('invalid_signature', 'signature_stale', 'The signature has expired (its expires parameter is in the past).');

  // 4. The scheme. AAuth agents use jwt and nothing else (11.3.2).
  const member = keys.get(label)!;
  const scheme = member.value instanceof Token ? member.value.value : null;
  if (scheme !== 'jwt') {
    req('unsupported_scheme', 'signature_scheme', `Signature-Key ${label} uses scheme ${JSON.stringify(scheme ?? member.value)}; AAuth agents present a token under the jwt scheme: ${label}=jwt;jwt="<token>".`, { 'Accept-Signature-Scheme': 'jwt' });
  }
  const jwt = member.params.get('jwt');
  if (typeof jwt !== 'string') throw new Fail('agent', 'invalid_jwt', 'token_unreadable', `Signature-Key ${label}=jwt needs a jwt parameter, a string holding the token.`);

  // 5. The key: which token, then that token's checks.
  let typ: unknown;
  try {
    typ = decodeProtectedHeader(jwt).typ;
  } catch {
    throw new Fail('agent', 'invalid_jwt', 'token_unreadable', 'The jwt in Signature-Key is not a well-formed JWT.');
  }
  const kind = KIND_OF_TYP[typ as string];
  if (!kind || kind === 'resource') {
    throw new Fail('agent', 'invalid_jwt', 'token_unreadable', `The token in Signature-Key has typ ${JSON.stringify(typ)}; present an agent token (aa-agent+jwt), a person token (aa-person+jwt) or an auth token (aa-auth+jwt). A resource token goes to your PS, not back to the resource.`);
  }
  const stage = kind as Stage;
  const v = await verifyToken(jwt, kind, { stage, aud: kind === 'agent' ? undefined : o.aud });

  // 6-7. The algorithm, from the key; then the signature itself.
  const key = v.cnf!;
  if (covered.includes('content-digest')) checkDigest(r, stage);
  const base = signatureBase(r, items, input.params);
  const publicKey = createPublicKey({ key: key as never, format: 'jwk' });
  const sigBytes = (sig!.value as Bytes).value;
  const ok = key.alg === 'Ed25519' ? cryptoVerify(null, Buffer.from(base), publicKey, sigBytes) : cryptoVerify('sha256', Buffer.from(base), { key: publicKey, dsaEncoding: 'ieee-p1363' }, sigBytes);
  if (!ok) {
    const f = new Fail(stage, 'invalid_signature', 'signature_invalid', `The HTTP message signature doesn't verify with the ${kind} token's cnf.jwk (${key.alg}). signature_base in this response is the base this server built; compare it with yours.`);
    f.debug = { signature_base: base };
    throw f;
  }
  return { ...v, jwt, thumbprint: await thumbprint(key), covered, created: created as number };
}

/** A Signature-Error response's headers and RFC 9457 body (the Signature-Key draft's Signature-Error section). */
export function sigErrorResponse(f: Fail) {
  return {
    status: 401,
    headers: { 'Signature-Error': `error=${f.sig}`, 'Content-Type': 'application/problem+json', ...f.headers },
    body: { type: `urn:ietf:params:sig-error:${f.sig}`, status: 401, error: f.sig, detail: f.message, ...f.debug },
  };
}
