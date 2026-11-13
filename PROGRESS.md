# Progress
## 2026-11-13 plan: OpenID4VCI issuer and agent wallet proof
Done: feature specs `docs/features/01-oid4vci-issuer.md` and `02-agent-wallet-proof.md`, decisions D-001 to D-006. Tested: n/a (plan). Next: 01 task 1. Before writing code, check the OpenID4VCI 1.0 details the spec assumes (`proofs.jwt`, the `credentials: [{credential}]` response, well-known placement) against the spec text.
## 2026-11-13 01-oid4vci-issuer task 1: issuer and AS metadata
Done: `src/oid4vci.ts` serves the issuer and AS metadata at the origin with the well-known part before the path, registered through `WELL_KNOWN`. Spec details checked against the 1.0 text first: `proofs.jwt` array, `credentials: [{credential}]`, well-known insertion, nonce POST with no-store, and proof `iss` MUST be omitted for anonymous pre-auth (we ignore it, per the plan). Tested: `node --test test/oid4vci.test.ts` → pass. Next: task 2.
