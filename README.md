# Proving ground: the x401 door

A proof of concept for the Agent Lab proving ground
([plan](../affinidi-lab/docs/proving-ground-plan.md), phase 1, x401 only).
One protected resource, Quarry & Rind's stock ledger (fictional), behind
**x401 0.2.0 as published at
[`proof/x401@7e864af`](https://github.com/proof/x401/blob/7e864af97cd8202a5380386f52939d759541977d/spec.md)**,
and a public wall that shows every attempt live.

It implements the draft as of that commit. It claims nothing about conformance.

## Run it

Needs Node 22.18 or later. It runs the TypeScript directly, with no build step.

```sh
npm install
npm start                 # http://localhost:8401, the wall is at /
npm test                  # end to end: every place an attempt can stop (needs openssl)
npm run typecheck
```

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8401` | |
| `BASE_URL` | `http://localhost:$PORT` | Public URL. Sets the door's `did:web`, the issuer ID and every link |
| `DATA_DIR` | `./data` | SQLite database and the two signing keys, made on first start |

## Try it

```sh
# Start a run: your row on the wall. The handle is public.
curl -X POST localhost:8401/pg/runs -H 'content-type: application/json' -d '{"handle":"relaybox"}'
# → {"door": "http://localhost:8401/pg/x401/r/<run>/ledger", ...}

# Walk through it with the reference agent and wallet
node client.ts http://localhost:8401/pg/x401/r/<run>/ledger            # signed request
node client.ts http://localhost:8401/pg/x401/r/<run>/ledger --unsigned # unsigned request
```

Anyone can call the door without a run at `/pg/x401/ledger`; those attempts
share the wall's anonymous row. [`client.ts`](client.ts) is about 100 lines
and is meant to be read next to the spec.

## The exchange

1. **Challenge.** A request without proof gets `401` and `PROOF-REQUEST`: a
   base64url x401 payload with two entries in `credential_requirements.digital.requests`:
   - `openid4vp-v1-signed`: a JAR signed by the door, with `client_id`
     `decentralized_identifier:did:web:<host>`. The key is in `/.well-known/did.json`.
   - `openid4vp-v1-unsigned`: the same OpenID4VP request, unsigned.

   Both carry one fresh nonce, valid for five minutes, and this DCQL query:
   a `dc+sd-jwt` credential of vct `<BASE_URL>/pg/vct/quarry-rind-staff`,
   disclosing `employer` (equal to `Quarry & Rind`) and `role`. The body repeats
   the payload for callers that can't read headers. There is no `oauth`
   member, because the door does no token exchange.
2. **Credential.** `POST /pg/issuer/credential {"jwk": <holder public JWK>}`
   returns an SD-JWT VC from the Lab test issuer, bound to that key, with
   every claim selectively disclosable. Issuer metadata is at
   `/.well-known/jwt-vc-issuer/pg/issuer`.
3. **Retry.** The same URL with `PROOF-RESPONSE`: a Result Artifact whose
   `credential_result` is `{protocol, data: {vp_token: {quarry_rind_staff: [<sd-jwt>~<kb-jwt>]}}}`,
   inline or by `credential_result_uri` (https only, never a private address).
4. **Through:** `200`, the ledger, and `PROOF-RESULT` carrying
   `{scheme, version, result: "accepted", receipt}`.
   **Stopped:** `401` and `PROOF-RESULT` carrying an x401 Error Object with
   the step it stopped at (`stopped_at`) and an `error_uri` that opens the
   attempt's timeline on the wall.

## The ladder

An attempt is scored by the highest step it reached. Each step links to the
spec section it comes from, on the wall.

| Step | Checks | Stop codes |
| --- | --- | --- |
| challenged | The door issued a PROOF-REQUEST and a nonce | |
| retried | A PROOF-RESPONSE came back on the same route | |
| artifact decoded | One base64url JSON Result Artifact, a known protocol, a presentation ending in a KB-JWT | `invalid_artifact`, `token_not_supported`, `invalid_reference` |
| nonce matched | Issued by this door, on this run's URL, unexpired, and not used before. It is spent here | `nonce_unknown`, `nonce_other_run`, `nonce_expired`, `nonce_replayed` |
| signature valid | Issuer JWT (Lab issuer key, or the `x5c` header), every disclosure digest, the KB-JWT against `cnf.jwk` (at most 5 minutes old), and `sd_hash` | `issuer_key_unresolved`, `invalid_signature`, `invalid_disclosure`, `no_holder_key`, `sd_hash_mismatch` |
| binding valid | Signed: KB-JWT `aud` is the door's `client_id`. Unsigned: `aud` is `origin:<origin>` | `binding_mismatch` |
| query met | vct matches, `employer` is Quarry & Rind, `role` is disclosed. The timeline notes any claim disclosed that the query didn't ask for | `query_not_met` |
| issuer trusted | `iss` is the Lab test issuer | `untrusted_issuer` |
| through | All of the above | |

The plan's sketch has *request decoded* before *retried*. The door can't see
an agent decode its request, so this ladder uses steps the door can observe.

## The receipt

An ES256 JWT, `typ: pg-receipt+jwt`, signed by the door (`kid` `<did>#door`).
Verify it against `/pg/jwks.json` or the door's DID document.

```json
{
  "iss": "did:web:localhost%3A8401", "sub": "<run handle or anonymous>", "jti": "<attempt id>", "iat": 0,
  "door": "x401", "spec": "x401 0.2.0 (proof/x401@7e864af)", "resource": "<BASE_URL>/pg/x401/ledger",
  "request_mode": "openid4vp-v1-signed", "steps": ["challenged", "…", "through"],
  "proves": "A fact about the person, attested by an issuer", "trusted_issuer": "<BASE_URL>/pg/issuer"
}
```

It records that the attempt got through. It carries no claim the holder disclosed.

## What is stored

For each attempt: the run, the highest step, the request mode, the stop code
and reason, and a plain-words timeline. **Never stored:** credentials,
presentations, disclosed values or IP addresses. The wall shows handles,
never run IDs. A run ID labels attempts and is not a credential.

## Files

| | |
| --- | --- |
| [`src/x401.ts`](src/x401.ts) | The door: challenge, the ladder of checks, the receipt |
| [`src/issuer.ts`](src/issuer.ts) | The Lab test issuer |
| [`src/store.ts`](src/store.ts) | Runs and attempts in SQLite (`node:sqlite`), and the change bus |
| [`src/lab.ts`](src/lab.ts) | Base URL, `did:web`, signing keys |
| [`src/server.ts`](src/server.ts) | Routes, CORS for the x401 headers, SSE |
| [`public/index.html`](public/index.html) | The wall: runs, live feed, funnel, stop codes, attempt timelines |
| [`client.ts`](client.ts) | Reference agent and wallet |
| [`test/e2e.test.ts`](test/e2e.test.ts) | The real server, driven through every stop |

## Not built yet

Each of these is left out on purpose, and each would take a small change.

- **Before going public:** rate limiting (Caddy `rate_limit`), and pinning
  the resolved address for `credential_result_uri` against DNS rebinding.
  Both are marked `ponytail:` in the code. A retention period also needs
  deciding, along with the privacy check (decision 6 in the plan).
- **Lab integration:** Lab sign-in for runs, six-digit completion codes,
  Slack "first through" notices, and the move to `servers/proving-ground`.
- **Spec surface:** OAuth token exchange and Verification Tokens, the HTML
  `<data>` embedding, a verifier-hosted fulfilment page for the DC API,
  DCQL `trusted_authorities`, nested and array disclosures, and other
  credential formats.
- **Issuance:** OpenID4VCI. The issuer is a plain POST for now.
- **Wall:** the per-door interop grid (declared software against route),
  *My attempts*, and the archived snapshot after each event.
