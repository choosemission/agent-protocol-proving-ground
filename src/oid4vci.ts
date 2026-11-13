/**
 * The Lab test issuer over OpenID4VCI 1.0, pre-authorized code flow only:
 * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html (1.0, final).
 *
 * The issuer is its own authorization server, with anonymous token access. Creating
 * a run mints the offer (D-002), so the run ID stays the only authorisation. Holder
 * binding is a `jwt` proof carrying a did:key `kid` or a `jwk` (D-003). The signing
 * lives in issuer.ts.
 */
import { ECDH } from 'node:crypto';
import { multibaseDecode } from 'didwebvh-ts';
import type { JWK } from 'jose';
import { BASE_URL, ORIGIN } from './lab.ts';
import { VCT } from './issuer.ts';
import * as store from './store.ts';

/** The Credential Issuer Identifier. Every endpoint sits under it. */
export const CREDENTIAL_ISSUER = `${BASE_URL}/pg/issuer`;
export const CONFIG_ID = 'lab_handle';
export const PRE_AUTH = 'urn:ietf:params:oauth:grant-type:pre-authorized_code';
export const PROOF_ALGS = ['ES256', 'EdDSA'];

// The well-known part goes between the host and the identifier's path (OpenID4VCI §12.2.2, RFC 8414 §3.1).
const wellKnown = (name: string) => `/.well-known/${name}${new URL(CREDENTIAL_ISSUER).pathname}`;

export const WELL_KNOWN = {
  [wellKnown('openid-credential-issuer')]: () => ({
    credential_issuer: CREDENTIAL_ISSUER,
    credential_endpoint: `${CREDENTIAL_ISSUER}/credential`,
    nonce_endpoint: `${CREDENTIAL_ISSUER}/nonce`,
    credential_configurations_supported: {
      [CONFIG_ID]: {
        format: 'dc+sd-jwt',
        vct: VCT,
        credential_signing_alg_values_supported: ['ES256'],
        cryptographic_binding_methods_supported: ['did:key', 'jwk'],
        proof_types_supported: { jwt: { proof_signing_alg_values_supported: PROOF_ALGS } },
      },
    },
  }),
  [wellKnown('oauth-authorization-server')]: () => ({
    issuer: CREDENTIAL_ISSUER,
    token_endpoint: `${CREDENTIAL_ISSUER}/token`,
    grant_types_supported: [PRE_AUTH],
    'pre-authorized_grant_anonymous_access_supported': true,
  }),
};

/** Where a client finds the issuer metadata: for docs and hints. */
export const METADATA_URL = `${ORIGIN}${wellKnown('openid-credential-issuer')}`;

/** A fresh credential offer for a run: a single-use pre-authorized code, good for 10 minutes. */
export function offer(runId: string) {
  const credential_offer = {
    credential_issuer: CREDENTIAL_ISSUER,
    credential_configuration_ids: [CONFIG_ID],
    grants: { [PRE_AUTH]: { 'pre-authorized_code': store.mintVci('code', runId, 600) } },
  };
  return { credential_offer, credential_offer_uri_scheme: `openid-credential-offer://?credential_offer=${encodeURIComponent(JSON.stringify(credential_offer))}` };
}

type Reply = { status: number; body: unknown; headers?: Record<string, string> };
const NO_STORE = { 'Cache-Control': 'no-store' };
const oauthError = (status: number, error: string, error_description: string): Reply => ({ status, body: { error, error_description }, headers: NO_STORE });

/** Token endpoint (RFC 6749 §5, OpenID4VCI §6): a pre-authorized code for a 5-minute opaque access token. */
function token(body: string): Reply {
  const form = new URLSearchParams(body);
  if (form.get('grant_type') !== PRE_AUTH) return oauthError(400, 'unsupported_grant_type', `Only ${PRE_AUTH} is supported.`);
  const code = form.get('pre-authorized_code');
  if (!code) return oauthError(400, 'invalid_request', 'Send pre-authorized_code from your credential offer, form-encoded.');
  const runId = store.spendVci('code', code);
  if (!runId) return oauthError(400, 'invalid_grant', 'That pre-authorized code is unknown, spent or expired (they last 10 minutes). GET /pg/runs/<run ID>/offer for a fresh offer.');
  return { status: 200, body: { access_token: store.mintVci('token', runId, 300), token_type: 'Bearer', expires_in: 300 }, headers: NO_STORE };
}

/** Everything under /pg/issuer. `path` is below it. */
export async function serve(method: string, path: string, headers: Record<string, string | string[] | undefined>, body: string): Promise<Reply | null> {
  if (method !== 'POST') return null;
  if (path === '/token') return token(body);
  // Not a protected resource (§7.1): no token needed.
  if (path === '/nonce') return { status: 200, body: { c_nonce: store.mintVci('nonce', null, 300) }, headers: NO_STORE };
  return null;
}

/**
 * A did:key DID URL's public key as a JWK: Ed25519 (`z6Mk…`, multicodec 0xed) or
 * P-256 (`zDn…`, 0x1200, compressed point). The fragment must be the key's own
 * multibase, as did:key defines it. Throws on anything else.
 */
export function didKeyToJwk(kid: string): JWK {
  const m = /^did:key:(z[1-9A-HJ-NP-Za-km-z]+)#(z[1-9A-HJ-NP-Za-km-z]+)$/.exec(kid);
  if (!m) throw new Error('kid must be a did:key DID URL: did:key:<multibase>#<multibase>.');
  if (m[1] !== m[2]) throw new Error("A did:key kid's fragment must be the key's own multibase.");
  const b = Buffer.from(multibaseDecode(m[1]).bytes);
  if (b[0] === 0xed && b[1] === 0x01 && b.length === 34) return { kty: 'OKP', crv: 'Ed25519', x: b.subarray(2).toString('base64url') };
  if (b[0] === 0x80 && b[1] === 0x24 && b.length === 35) {
    const point = ECDH.convertKey(b.subarray(2), 'prime256v1', undefined, undefined, 'uncompressed') as Buffer;
    return { kty: 'EC', crv: 'P-256', x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') };
  }
  throw new Error('Only Ed25519 (z6Mk…) and P-256 (zDn…) did:key are supported.');
}
