/**
 * Who the Lab is on this host: its base URL, the proving ground's did:web, and
 * the two signing keys, the verifier's (every door's requests and receipts)
 * and the test issuer's (credentials). Keys are made on first start and kept in DATA_DIR, so
 * receipts and credentials stay verifiable across restarts.
 */
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { exportJWK, generateKeyPair, importJWK, type JWK } from 'jose';

export const PORT = Number(process.env.PORT ?? 8401);
export const BASE_URL = (process.env.BASE_URL ?? `http://localhost:${PORT}`).replace(/\/$/, '');
export const ORIGIN = new URL(BASE_URL).origin;
export const DATA_DIR = process.env.DATA_DIR ?? 'data';

/** The verifier's identifier, shared by every door; resolves to `${ORIGIN}/.well-known/did.json`. */
export const DID = `did:web:${encodeURIComponent(new URL(BASE_URL).host)}`;
export const ISSUER_ID = `${BASE_URL}/pg/issuer`;

async function loadOrCreate(name: string, kid: string) {
  const file = join(DATA_DIR, `${name}.key.json`);
  if (!existsSync(file)) {
    const { privateKey } = await generateKeyPair('ES256', { extractable: true });
    mkdirSync(DATA_DIR, { recursive: true });
    writeFileSync(file, JSON.stringify(await exportJWK(privateKey)), { mode: 0o600 });
  }
  const { kty, crv, x, y, d } = JSON.parse(readFileSync(file, 'utf8')) as JWK;
  const jwk: JWK = { kty, crv, x, y, kid, alg: 'ES256', use: 'sig' };
  return { kid, jwk, key: (await importJWK({ ...jwk, d }, 'ES256')) as CryptoKey, publicKey: (await importJWK(jwk, 'ES256')) as CryptoKey };
}

export const verifier = await loadOrCreate('verifier', `${DID}#verifier`);
export const issuer = await loadOrCreate('issuer', `${ISSUER_ID}#key-1`);

export const didDocument = {
  '@context': ['https://www.w3.org/ns/did/v1'],
  id: DID,
  verificationMethod: [{ id: verifier.kid, type: 'JsonWebKey2020', controller: DID, publicKeyJwk: verifier.jwk }],
  assertionMethod: [verifier.kid],
  authentication: [verifier.kid],
};
