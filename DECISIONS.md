# Decisions

## D-001 2026-11-13 OpenID4VCI issuance lives in the proving ground, replacing the plain POST
Context: the Lab wants to prove an agent can run OpenID4VCI with the credentials wallet MCP. Decision: upgrade the existing handle issuer here, with the same `#issuer` key and Lab DID. Why: the key, the DID, the SD-JWT code and a verifier that trusts the issuer (the x401 door) already live here, so it's the shortest path to "earn a credential, then use it". Rejected: a new general-purpose Lab issuer in affinidi-lab, because who the credential is about (agent, member, or the link between them) and how a member authorises it are unsettled; it was parked. Also rejected: a new key on the Lab DID, because there's no DID-update path.

## D-002 2026-11-13 Pre-authorized code flow, with the run as the authorisation
Context: OpenID4VCI needs something to authorise issuance, and the authorization code flow assumes a browser. Decision: pre-authorized code flow. Creating a run mints the offer. The issuer is its own authorization server, with anonymous token access, no `tx_code` and no DPoP. Why: an agent can run it with no human, and the run ID already is the authorisation today, so the trust is unchanged. Rejected: the authorization code flow (needs a user agent and Lab sign-in); `tx_code` (adds nothing while anyone can start a run).

## D-003 2026-11-13 Holder binding by a `jwt` proof: did:key `kid` or `jwk`
Context: the plain POST put any JWK into `cnf.jwk` without proof of possession. The credentials wallet's `create_key_proof` sends `kid` = a did:key DID URL, no `jwk` and no `iss` (wallet D36). Decision: accept either `kid` (did:key Ed25519 or P-256, resolved locally) or `jwk`. Require `aud` = the credential issuer identifier and a `c_nonce` from the nonce endpoint. Write `cnf.jwk`. Why: these are the spec's two common binding methods, and `cnf.jwk` is what the x401 door and the wallet already check. Rejected: other DID methods (no need yet); `cnf.kid` (the door reads `cnf.jwk`).

## D-004 2026-11-13 SD-JWT VC only for now
Context: the Lab DID's signing keys are P-256. The credentials wallet verifies vcdm2 only with `eddsa-jcs-2022` (Ed25519). Decision: issue `dc+sd-jwt` only. Why: it works today on both sides, and it's what the x401 door asks for. Rejected for now: adding `ecdsa-jcs-2019` to the wallet, or an Ed25519 key on the Lab DID. Either is needed before vcdm2.

## D-005 2026-11-13 The wallet proof runs against the deployed Lab
Context: the credentials wallet resolves did:webvh only on public hosts, with no override (its D51/D52). Locally, `pg.localhost` credentials would store as `verified: false`. Decision: feature 02's run uses `https://agentlab.choosemission.com/proving-ground`. Feature 01's tests run locally with `jose`. Why: it keeps the wallet's security rule intact and tests the real path. Rejected: a dev-host switch in the wallet (it would contradict an accepted wallet decision).

## D-006 2026-11-13 The agent uses the x401 door's unsigned request
Context: the credentials wallet has no way to verify a JAR (a signed request object). Decision: the holder skill takes `openid4vp-v1-unsigned` and binds to `origin:<origin>`. Why: reading a signed request's payload without verifying it would claim a check that didn't happen. Rejected: decoding the JAR unverified.
