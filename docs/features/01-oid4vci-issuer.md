# 01 OpenID4VCI issuer
Goal: an agent gets the run's handle credential over OpenID4VCI 1.0 (pre-authorized code flow), proving it holds the key the credential is bound to. Today `POST /pg/issuer/credential` takes any public JWK with no proof of possession.
Done = a run's response carries a credential offer, and a client that follows only OpenID4VCI 1.0 (metadata → token → nonce → credential with a `jwt` proof) gets a `dc+sd-jwt` handle credential bound to its did:key or JWK. The old POST is gone, and the x401 door still lets that credential through.
Feature test: `npm test` (new `test/oid4vci.test.ts`, plus `test/e2e.test.ts` with `client.ts` now issuing over OpenID4VCI), and the probe in task 9 against the deployed Lab.
Out of scope: authorization code flow, `tx_code`, DPoP, deferred and batch issuance, encrypted responses, vcdm2 (D-004), a wall/ladder for issuance (Later), Lab sign-in.
Decisions: D-001, D-002, D-003, D-004

Spec: [OpenID4VCI 1.0](https://openid.net/specs/openid-4-verifiable-credential-issuance-1_0.html). Pin the version in the code's docs like the doors do.

## Shape
- Credential issuer identifier: `${BASE_URL}/pg/issuer`. On the Lab that's `https://agentlab.choosemission.com/proving-ground/pg/issuer`.
- The issuer is its own authorization server (no `authorization_servers`), and token access is anonymous (`pre-authorized_grant_anonymous_access_supported: true`).
- Metadata is served at the origin, with the well-known part inserted before the path:
  - `/.well-known/openid-credential-issuer/proving-ground/pg/issuer`
  - `/.well-known/oauth-authorization-server/proving-ground/pg/issuer`
  - Locally, with no path in `BASE_URL`, these are `/.well-known/…/pg/issuer`.
- One credential configuration, `lab_handle`:
  - `format: dc+sd-jwt` and `vct: ${BASE_URL}/pg/vct/handle`;
  - `credential_signing_alg_values_supported: [ES256]` (the `#issuer` key);
  - `cryptographic_binding_methods_supported: [did:key, jwk]`;
  - `proof_types_supported.jwt.proof_signing_alg_values_supported: [ES256, EdDSA]`.
- Endpoints, under `${BASE_URL}/pg/issuer`: `/token`, `/nonce` and `/credential`.

## Tasks
- [x] 1. Issuer metadata and AS metadata
      Criteria: the two documents above are served at the origin paths, registered through `WELL_KNOWN` in `server.ts` (the same mechanism poppy uses). `credential_issuer` equals the identifier exactly, and every endpoint URL sits under it. A new `src/oid4vci.ts` holds this and later tasks; `issuer.ts` keeps the signing.
      Test: `node --test test/oid4vci.test.ts`: both GETs return 200 JSON, and the issuer document's `credential_issuer` + `/credential` equals `credential_endpoint`.
- [x] 2. Credential offer on run creation
      Criteria: `POST /pg/runs` adds `credential_offer` and `credential_offer_uri_scheme`.
      - `credential_offer` is `{credential_issuer, credential_configuration_ids: ["lab_handle"], grants: {"urn:ietf:params:oauth:grant-type:pre-authorized_code": {"pre-authorized_code"}}}`.
      - `credential_offer_uri_scheme` is the `openid-credential-offer://?credential_offer=…` form.
      - The pre-authorized code is random, stored against the run in SQLite (`store.ts`), single use, and valid for 10 minutes.
      - `GET /pg/runs/<run>/offer` mints a fresh offer, for an agent whose code expired.
      Test: the run response has an offer with a 43+ character code. Minting a second offer leaves both codes usable until they're spent.
- [x] 3. Token endpoint
      Criteria: the endpoint takes a form-encoded `grant_type=urn:ietf:params:oauth:grant-type:pre-authorized_code&pre-authorized_code=…`.
      - It returns `{access_token, token_type: "Bearer", expires_in: 300}` with `Cache-Control: no-store`. The access token is opaque, stored against the run, and good for 5 minutes.
      - A spent, expired or unknown code gives `400 {error: "invalid_grant"}`, and any other grant type gives `unsupported_grant_type`.
      Test: token OK. The same code twice → `invalid_grant`. An expired code (clock injected, as x401's nonce test does) → `invalid_grant`.
- [x] 4. Nonce endpoint
      Criteria: `POST /nonce` → `{c_nonce}` with `Cache-Control: no-store`. The nonce is stored, single use, and valid for 5 minutes. It needs no access token.
      Test: two calls return different nonces.
- [x] 5. did:key → JWK
      Criteria: `didKeyToJwk(kid)` accepts `did:key:z6Mk…#z6Mk…` (Ed25519 → OKP) and `did:key:zDn…#zDn…` (P-256 → EC). P-256 decompresses the point with `crypto.ECDH.convertKey`. A fragment that isn't the key's own multibase is refused, and so are other multicodecs. No new dependency: base58btc is about 15 lines.
      Test: unit tests against the [did:key spec test vectors](https://w3c-ccg.github.io/did-key-spec/) for both key types. A tampered fragment throws.
- [x] 6. Credential endpoint
      Criteria: it takes `Authorization: Bearer <access_token>` and `{credential_configuration_id: "lab_handle", proofs: {jwt: [<proof>]}}`.
      - The proof header must have `typ` = `openid4vci-proof+jwt` and `alg` = ES256 or EdDSA, plus exactly one of `kid` (a did:key DID URL, resolved by task 5) or `jwk` (public).
      - The proof payload needs `aud` = the credential issuer identifier, `nonce` = an unspent `c_nonce` (spent here), and an `iat` within 5 minutes. `iss` is ignored (anonymous pre-auth).
      - On success it issues with `issueCredential(holderJwk, handle)`, which puts `cnf.jwk` = `{kty, crv, x, y}`, and responds `{credentials: [{credential}]}`.
      - Errors, from the spec's Credential Error Response: `invalid_token` (401), `invalid_credential_request`, `unknown_credential_configuration`, `invalid_proof`, `invalid_nonce`.
      Test: four happy paths, with proofs signed via `jose` as did:key Ed25519, did:key P-256, `jwk` P-256 and `jwk` Ed25519. Each credential's `cnf.jwk` matches the proof key. Refusal cases: wrong `typ`, wrong `aud`, a reused nonce, an unknown nonce, an expired token, no token, a `kid` fragment mismatch, and a JWK with `d`.
- [x] 7. Proof shaped like the credentials wallet's
      Criteria: a proof built exactly as the wallet's `create_key_proof` (`profile: openid4vci`, D36) is accepted:
      - header exactly `{alg, kid: did:key:X#X, typ}`;
      - payload exactly `{aud, iat, nonce}`, with no `iss`.

      The fixture is generated in the test, not copied from the wallet, and no real key material is involved.
      Test: one test per key type, with a header and payload whose keys equal those sets.
- [x] 8. Move `client.ts` to OpenID4VCI and remove the plain POST
      Criteria: `getCredential` in `client.ts` runs offer → token → nonce → proof → credential. `POST /pg/issuer/credential` returns 404 (as built: that path is now the OpenID4VCI credential endpoint, so the old `{jwk, run}` POST gets `401 invalid_token`). The README's "The handle credential" section, `/llms.txt` text and the run response's `credential` hint all describe the offer flow. `x401.md` step 2 points at it. The README's "Not built yet" loses "Issuance: OpenID4VCI".
      Test: `npm test` (all of e2e x401, poppy and aauth) green, and `npm run typecheck` clean.
- [ ] 9. Deploy to the Lab
      Criteria: in affinidi-lab:
      - Add both well-known paths to `@lab_identity` in `infra/agent-services/caddy/Caddyfile`.
      - Bump the proving-ground pin in `compose.yaml`.
      - Add a `verify.sh` probe for the issuer metadata.
      - Deploy. Ask the user first: deploys are theirs to run.
      Test: `curl -s https://agentlab.choosemission.com/.well-known/openid-credential-issuer/proving-ground/pg/issuer | jq .credential_issuer` prints the identifier. A run created on the Lab returns an offer whose code `/token` accepts.

## Later
- An OpenID4VCI door: score issuance attempts on a ladder and show them on a wall (offer → token → nonce → proof → issued).
- `tx_code`, and offers by reference (`credential_offer_uri`).
- vcdm2 issuance (D-004).
- Rate limiting on `/token` and `/credential`, under the existing `ponytail:` note in `server.ts`.
