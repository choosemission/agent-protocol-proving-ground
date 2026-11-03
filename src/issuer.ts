/**
 * The Lab test issuer, shared by every door: the Lab's did:webvh, signing with its #issuer key. It gives a run an SD-JWT VC
 * (dc+sd-jwt) attesting the run's handle, bound to the holder key the caller
 * sends. The handle is selectively disclosable.
 *
 * Asking needs the run ID, which is what the run's door URLs carry, so the
 * credential says no more than "this holder was given the run with this handle".
 */
import { createHash, randomBytes } from 'node:crypto';
import { SignJWT, type JWK } from 'jose';
import { BASE_URL, DID, issuer } from './lab.ts';

export const VCT = `${BASE_URL}/pg/vct/handle`;

/** SD-JWT disclosure digest: base64url(sha-256(ascii(disclosure))). */
export const digest = (s: string) => createHash('sha256').update(s).digest('base64url');

/** Throws on a holder key that is not a public EC or OKP JWK. */
export async function issueCredential(holder: JWK, handle: string) {
  if (!holder || typeof holder !== 'object' || 'd' in holder || !['EC', 'OKP'].includes(holder.kty ?? '')) {
    throw new Error('Send {"jwk": <your holder public key>, "run": <run ID>} with an EC or OKP JWK without "d".');
  }
  const { kty, crv, x, y } = holder;
  const disclosure = Buffer.from(JSON.stringify([randomBytes(16).toString('base64url'), 'handle', handle])).toString('base64url');
  const jwt = await new SignJWT({
    iss: DID,
    vct: VCT,
    cnf: { jwk: { kty, crv, x, y } },
    _sd: [digest(disclosure)],
    _sd_alg: 'sha-256',
  })
    .setProtectedHeader({ alg: 'ES256', typ: 'dc+sd-jwt', kid: issuer.kid })
    .setIssuedAt()
    .setExpirationTime('30d')
    .sign(issuer.key);
  return `${jwt}~${disclosure}~`;
}

