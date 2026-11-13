/**
 * The Lab test issuer over OpenID4VCI 1.0, pre-authorized code flow only:
 * https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html (1.0, final).
 *
 * The issuer is its own authorization server, with anonymous token access. Creating
 * a run mints the offer (D-002), so the run ID stays the only authorisation. Holder
 * binding is a `jwt` proof carrying a did:key `kid` or a `jwk` (D-003). The signing
 * lives in issuer.ts.
 */
import { BASE_URL, ORIGIN } from './lab.ts';
import { VCT } from './issuer.ts';

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
