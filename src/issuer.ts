/**
 * The Lab test issuer. It gives anyone an SD-JWT VC (dc+sd-jwt) saying the
 * holder works at Quarry & Rind as a stock clerk, bound to the holder key
 * they send. Every claim is selectively disclosable, so a wallet can show
 * the door only what it asks for.
 *
 * The claims are fixed and fictional. This is what lets the door reach its
 * "issuer trusted" step, and nothing more.
 */
import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, type JWK } from 'jose';
import { BASE_URL, ISSUER_ID, issuer } from './lab.ts';

export const VCT = `${BASE_URL}/pg/vct/quarry-rind-staff`;

/** SD-JWT disclosure digest: base64url(sha-256(ascii(disclosure))). */
export const digest = (s: string) => createHash('sha256').update(s).digest('base64url');

const CLAIMS = { given_name: 'Sam', family_name: 'Example', employer: 'Quarry & Rind', role: 'stock-clerk' };

/** Throws on a holder key that is not a public EC or OKP JWK. */
export async function issueCredential(holder: JWK) {
  if (!holder || typeof holder !== 'object' || 'd' in holder || !['EC', 'OKP'].includes(holder.kty ?? '')) {
    throw new Error('Send {"jwk": <your holder public key>} as an EC or OKP JWK without "d".');
  }
  const { kty, crv, x, y } = holder;
  const disclosures = Object.entries(CLAIMS).map(([name, value]) =>
    Buffer.from(JSON.stringify([randomBytes(16).toString('base64url'), name, value])).toString('base64url'),
  );
  const jwt = await new SignJWT({
    iss: ISSUER_ID,
    vct: VCT,
    cnf: { jwk: { kty, crv, x, y } },
    _sd: disclosures.map(digest).sort(),
    _sd_alg: 'sha-256',
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', kid: issuer.kid })
    .setIssuedAt()
    .setExpirationTime('30d')
    .sign(issuer.key);
  return `${jwt}~${disclosures.join('~')}~`;
}

/** SD-JWT VC issuer metadata, so other verifiers can check our credentials too. */
export const issuerMetadata = { issuer: ISSUER_ID, jwks: { keys: [issuer.jwk] } };
