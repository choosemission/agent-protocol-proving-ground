# The aauth door

A resource under **AAuth Protocol -11 as tagged at
[`dickhardt/AAuth@178e9e6`](https://github.com/dickhardt/AAuth/blob/178e9e68b6578e4d6f7d0bf30f33b4c38833e3a1/draft-hardt-oauth-aauth-protocol.md)**
(`draft-hardt-oauth-aauth-protocol-11`; the repo's HEAD, `70d6737`, had the same text when it was
pinned), signing per **HTTP Signature Keys -09 at
[`dickhardt/signature-key@69f5ba2`](https://github.com/dickhardt/signature-key/blob/69f5ba2647be848feed043fb6d8b0790e43cd0b6/draft-hardt-httpbis-signature-key.md)**.
Section links below go to the published -11,
[ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html).
The door implements the draft as of that tag and claims nothing about conformance.

Code: [`aauth.ts`](aauth.ts) (the resource), [`aauth-sig.ts`](aauth-sig.ts) (the verifier),
[`aauth-ps.ts`](aauth-ps.ts) (the Lab test person server). Reference agent:
[`aauth-client.ts`](../../aauth-client.ts), meant to be read next to the spec.

```sh
node aauth-client.ts http://pg.localhost:8401                       # every step, locally; open the links it prints
node aauth-client.ts https://<proving ground> --public-url https://<tunnel to :8403>
```

## What the agent does

PS authorization access, three-party
([4.2.4](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#resource-access-modes)):

1. Sign every request (RFC 9421) covering `@method @authority @path signature-key`, presenting a
   token in `Signature-Key: sig=jwt;jwt="…"`. First the **agent token** its agent provider signed.
2. The door answers `401` with `AAuth-Requirement: requirement=person-token`.
3. The agent gets a **person token** for the door from its PS, and signs with it instead.
4. The door answers `401` with `requirement=auth-token; resource-token="…"`. The agent could
   instead `POST {"scope": "receipt"}` to the authorization endpoint with its person token.
5. The agent takes the resource token, with the person token as `presented_token`, to its PS, and
   gets an **auth token**.
6. Signed with the auth token, the door answers `200` with a receipt.

## The resource

| | |
| --- | --- |
| Identifier | The Lab's origin, `https://agentlab.choosemission.com`. A server identifier is scheme and host only ([11.1.1](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#identifiers-and-discovery)), so not `BASE_URL`. Person and auth tokens are addressed (`aud`) to it, and resource tokens are issued (`iss`) by it |
| Metadata | `/.well-known/aauth-resource.json`, at the origin: `access_mode: auth-token`, `authorization_endpoint`, `scope_descriptions`, `accept_signature_algs: [Ed25519, ES256]`. Every response carries `Link: <…/aauth-resource.json>; rel="aauth-resource"` |
| Resource endpoint | `<BASE_URL>/pg/doors/aauth/r/<run>`, or `<BASE_URL>/pg/doors/aauth` without a run |
| Authorization endpoint | `<BASE_URL>/pg/doors/aauth/authorize`. Takes a person token and `{"scope": "receipt"}`, and returns `{"resource_token": …}` |
| Scope | `receipt`: "Collect a signed receipt from the proving ground, naming your run's handle" |
| Resource tokens | `aa-resource+jwt`, Ed25519, valid for 5 minutes. `aud` and `ps` are the PS that issued the presented token, since there is no AS. Also `sub`, `presented_jti`, `agent_jkt` (the signing key's thumbprint), `scope`, and `mission_s256` and `tenant` when the presented token had them. Keys at `<BASE_URL>/pg/doors/aauth/jwks.json` |
| Receipt | `200 {"receipt": …}`: an ES256 JWT, `typ: pg-receipt+jwt`, verifiable against `/pg/jwks.json`, with `sub` your run's handle, `jti` the attempt, and `ps` the PS that authorized you |

**The run is in the URL.** AAuth signs `@path`, and the door's identifier is the origin, so
tokens are the same for every run and the run ID can sit in the path, as on the x401 door. The
authorization endpoint has no run in its URL. There, a key continues the latest attempt it made.

## Any person server

The door accepts a person token or auth token from **any** PS. It finds the issuer's keys at
`{iss}/.well-known/aauth-person.json`, as it does for every token, and checks
the same things whatever PS issued the token. Your PS is the `iss` of the person token you present, not the `ps` claim in your
agent token. That claim only tells the door, and you, where to go
([5.3.1](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#agent-token-structure)).

The door has no access server, so an auth token must come from the PS that issued the person token
(`dwk: aauth-person.json`, `ps` = `iss`). The door then checks what that PS did with the resource
token, which is how the ladder tests the PS as well as the agent:

- **Scope.** The auth token's scope must be within the resource token's. A PS may narrow scope,
  never widen it.
- **Lifetime.** The auth token must not outlive the person token it was obtained with.
- **Mission.** `mission_s256` must match.
- **Identity.** `sub` must match. It is a directed identifier, the same for every token the PS
  issues to the door.

## The Lab test person server

For agents with no PS of their own: a minimal PS (the spec's appendix, "A Minimal Person Server").

| | |
| --- | --- |
| Identifier | The same origin as the resource. Roles that share an origin share an identifier, told apart by the well-known document ([4.3](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#roles)) |
| Metadata | `/.well-known/aauth-person.json`: `person_token_endpoint`, `auth_token_endpoint`, `jwks_uri`, and nothing optional. No missions, no interaction relay, no revocation |
| Using it | Put `"ps": "<origin>"` in your agent token, and send `"capabilities": ["interaction"]` with each request. Without that capability the PS can't reach the person, and answers `403 user_unreachable` ([7.1](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#person-token-endpoint)) |
| Requests | Signed with your **agent token**, and covering `content-digest` and `content-type` on a POST ([11.3.3.1](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#covered-components)). It issues only for the proving ground |
| The person | The first person token for an agent, and the first auth token for a scope, need the person. The PS answers `202` with `AAuth-Requirement: requirement=interaction; url=…; code="XXXX-XXXX"` and a `Location` to poll. The person opens `{url}?code={code}`. The code is single use and Crockford base32, compared ignoring case and hyphens. The person picks a **test account** name, with no password, and clicks Allow or Deny. The agent polls `Location` with signed GETs, using the same agent and key, until it gets `200`, `403 denied` or `408 expired`. After a result the URL is `410` |
| Binding | An agent, identified by its agent token's `iss` and `sub`, acts for one test account for good ([13.14](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#agent-person-binding)). Its `sub` at the door is a keyed hash of the account and the door's identifier |
| Tokens | Person tokens and auth tokens, Ed25519, at most an hour, and no longer than the agent token, or (for an auth token) the presented token |
| Checks at the token endpoint | The whole of [6.7.2](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#resource-token): the resource token's `aud` and `ps` name this PS; `agent_jkt` is the signing key's thumbprint; the presented token verifies, addressed to the resource and bound to `agent_jkt`; `presented_jti`, `sub`, `mission_s256` and `tenant` match; `sub` is the person this agent acts for. Errors are `invalid_request`, `invalid_resource_token`, `expired_resource_token`, `invalid_presented_token` and `expired_presented_token` |

What it did joins the timeline of the attempt using that signing key, at that key's next request
to the door. That covers each interaction asked for, each decision, each token issued, and each
refusal with its reason, such as `person refused, invalid_input: The signature must cover …`.

**Not real people.** The spec says a PS reachable from a network MUST authenticate whoever
approves ([13.13](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#ps-approval-endpoint-auth)).
This one doesn't. Whoever holds the code picks a test account. That's the point: nothing it
asserts is about anyone. It issues for no resource but the proving ground. Bindings, consents and
pending requests are in memory, and a restart forgets them.

## The ladder

**An attempt is one signing key on one run's URL.** Every token an agent holds is bound to the same
key (`cnf`, `agent_jkt`), so the key threads its requests together, and the attempt keeps the
highest step reached. A request that fails before its signature verifies makes an attempt of its
own on the run's row, since the run is in the URL. A step is credited as passed when a later
token implies it. A person token, for example, means a PS checked the agent token, so an agent
that starts with one gets **agent identified** without the door seeing its agent token.

| Step | Checks | Stop codes |
| --- | --- | --- |
| [signed request](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#verification) | `Signature`, `Signature-Input` and `Signature-Key` present and parse (RFC 9651); a label in all three; covered: `@method @authority @path signature-key`; `created` within 60 s (and `expires`, if present, not past); scheme `jwt` | `no_signature`, `signature_headers`, `signature_components`, `signature_stale`, `signature_clock_skew`, `signature_scheme` |
| [agent identified](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#agent-tokens) | `typ` `aa-agent+jwt`; `alg` Ed25519 or ES256; `kid`; `iss` a server identifier; `dwk` `aauth-agent.json`; `iat`, `exp`, `cnf.jwk`; the provider's metadata at `{iss}/.well-known/aauth-agent.json` has `issuer` equal to `iss`; its JWKS has the `kid`, with a fully-specified `alg` that matches the header's; the signature verifies; unexpired (no leeway); `iat` no more than 60 s ahead; `cnf.jwk` public, with a fully-specified `alg` (never `EdDSA`) agreeing with `kty`/`crv`; the HTTP signature verifies with it (and `content-digest`, if covered, matches the body); `sub` is `aauth:local@domain`, with `domain` the provider's host and no `+` without `parent_agent`; `ps`, if present, a server identifier. Answer: `401 requirement=person-token` | `token_unreadable`, `agent_token_invalid`, `agent_token_expired`, `agent_clock_skew`, `agent_issuer_unreachable`, `agent_issuer_missing`, `agent_issuer_mismatch`, `agent_unknown_key`, `key_invalid`, `key_unsupported`, `signature_invalid`, `content_digest` |
| [person identified](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#person-token-verification) | The same token checks, with `typ` `aa-person+jwt` and `dwk` `aauth-person.json`, from any PS; also `jti`; `aud` is the door's identifier; `exp - iat` ≤ 3600; `sub` present; no `scope` or `account`; the HTTP signature verifies with its `cnf.jwk` | `person_token_invalid`, `person_token_expired`, `person_aud`, `person_issuer_*`, `person_unknown_key`, … as above |
| [resource token issued](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#resource-token) | On the resource endpoint, the challenge carries one. At the authorization endpoint: a person token (not an auth token), a JSON body, `scope` present and only `receipt`, no `account` | `invalid_request`, `invalid_scope`, `invalid_account`, `person_token_required` |
| [authorized](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#auth-tokens) | The token checks with `typ` `aa-auth+jwt`; `dwk` `aauth-person.json` (no AS here); `aud` the door; `exp - iat` ≤ 3600; `sub` present; `ps` equal to `iss`; a resource token the door issued to this key names that PS and `sub`; scope within it, lifetime within the presented token's, same `mission_s256`; scope includes `receipt` | `auth_token_invalid`, `auth_token_expired`, `auth_aud`, `auth_issuer`, `auth_claims`, `auth_unmatched`, `scope_insufficient`, … as above |
| through | `200` with the receipt | |

How each stop answers:

- **A token or signature that fails** gets `401` with
  `Signature-Error: error=<code>`
  ([11.3.4](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#verification)).
  Missing components get `invalid_input` with `required_input=(…)`; the wrong scheme
  `unsupported_scheme` with `Accept-Signature-Scheme: jwt`; an unusable `alg`
  `unsupported_algorithm` with `Accept-Signature-Alg: Ed25519, ES256`. The body is RFC 9457, with
  `type: urn:ietf:params:sig-error:<code>`.
- **A signature that doesn't verify** also returns `signature_base`, the base the door built, so
  you can compare it with yours. That base is never stored or shown on the wall.
- **No signature at all** gets `401 requirement=agent-token`, with a body that says where to
  start.
- **Authorization endpoint errors** are `400` problem+json
  ([6.6.3](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#authorization-endpoint-request)).
- **`auth_unmatched` and `scope_insufficient`** are step-ups: `401 requirement=auth-token` with a
  fresh resource token naming the auth token you sent.
- **Every stop body** also has `stopped_at`, `pg_stop` (the code above), `attempt`, and `watch`,
  a link to the attempt's timeline.

A person token sent where an auth token is needed is not a stop. The door treats it as the person
token it is, and challenges for an auth token again. It never takes it as a grant
([13.11](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#person-token-not-authorization)).

## For coding assistants attempting the door

`/llms.txt` and the door's `401` bodies say this too: **use a library** for RFC 9421 and the
Signature-Key header rather than writing your own. Structured-field quoting, the signature base
and `content-digest` are where hand-written signers go wrong.

- TypeScript: [`@aauth/agent`](https://www.npmjs.com/package/@aauth/agent) (agent tokens, signed
  requests, person tokens, token exchange, deferred responses) and
  [`@hellocoop/httpsig`](https://www.npmjs.com/package/@hellocoop/httpsig) (signing with
  `Signature-Key`; the reference agent uses it).
- Python [`aauth-python-library`](https://github.com/christian-posta/aauth-python-library), Go
  [`aauth-go-library`](https://github.com/christian-posta/aauth-go-library), .NET
  [`dotnet-samples`](https://github.com/aauth-dev/dotnet-samples), and a person server to run,
  [`aauth-person-server`](https://github.com/christian-posta/aauth-person-server).

The door doesn't use any of them. It verifies with its own code (`aauth-sig.ts`), so it is a second
implementation for whichever library you choose. Where the two disagree, the stop says which check
failed and why. The tests run the reference agent, signing with `@hellocoop/httpsig`, through the
door.

## Not scored

- **The agent's own checks.** These are the resource token check
  ([6.7.3](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#resource-token)),
  the auth token response check, and the checks on the issuer of each metadata document it
  fetches. The door can't see them; the reference agent does them.
- **Agent token lifetime over 24 hours.** It's a SHOULD NOT, so the timeline notes it and the door
  doesn't stop.
- **Replay within the window.** A MAY; the door keeps no replay cache.
- **`AAuth-Capabilities`** on resource requests. The door never needs to raise `interaction` itself.

## HTTPS and the dev switch

A server identifier must be `https` with no port, and every metadata, JWKS and endpoint URL
`https`. When `BASE_URL` is `http://localhost`, `http://*.localhost` or `http://127.0.0.1` (`DEV`
in [`lab.ts`](../lab.ts)), the door and the Lab PS accept `http` and a port in identifiers and URLs,
and fetch loopback addresses. That's how the tests and a local run work. That identifier,
`http://pg.localhost:8401`, isn't one the spec allows, so a library may refuse it: run against a
public proving ground, or relax the library the same way. Anywhere else the door refuses `http`,
ports and private addresses. Your agent provider's documents must then be on public HTTPS
(`--public-url`).

## Not built yet

- **Revocation.** There is no `revocation_endpoint` on either the resource or the Lab PS (it is
  RECOMMENDED for a resource that accepts person tokens), so `revoked_jwt` never happens.
- **Deferred delivery.** No deferred `202` for `requirement=auth-token`
  ([6.5.1](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#requirement-auth-token)).
  The door always uses the `401`.
- **Other access modes.** Agent identity alone, resource-managed with `AAuth-Access`, person
  identity alone, and four-party federation.
- **In the Lab PS:** missions, sub-agents, call chaining, the interaction relay, `callback`
  redirects after the interaction, `Prefer: wait` (it answers at once), clarification, and
  rate-limiting failed codes
  ([11.6.3.1](https://www.ietf.org/archive/id/draft-hardt-oauth-aauth-protocol-11.html#interaction-required)).
- **Persistence.** Attempts' threads, the resource tokens issued, the key caches and the Lab PS's
  state are in memory, marked `ponytail:` in the code.
- **Rate limiting,** as for every door.
