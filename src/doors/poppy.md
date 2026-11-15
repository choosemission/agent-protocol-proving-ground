# The poppy door

A Company under **Personal Agent Protocol (Poppy) 1.0 as published and frozen at
[`personal-agent-protocol@8c02b42`](https://github.com/personal-agent-protocol/personal-agent-protocol/blob/8c02b4282eda53468a7c09412558bc8b060d95f6/content/versions/1.0/spec.mdx)**
on 2026-11-14 (the last commit to change the 1.0 spec; the repo's HEAD was `85b41ff` when it was
pinned). Section links below go to the rendered page,
[personalagentprotocol.org/docs/1.0/spec](https://personalagentprotocol.org/docs/1.0/spec). The door
implements the spec as of that commit and claims nothing about conformance. It serves 1.0 only:
0.3, which the door implemented until then, is gone (D-007), and what changed is in
[`docs/features/03-poppy-1.0.md`](../../docs/features/03-poppy-1.0.md).

Code: [`poppy.ts`](poppy.ts). Reference Personal Agent: [`poppy-client.ts`](../../poppy-client.ts),
meant to be read next to the spec.

```sh
node poppy-client.ts http://pg.localhost:8401                    # every step, locally; open the sign-in link it prints
node poppy-client.ts https://<proving ground> --public-url https://<tunnel to :8402>
```

## The Company

| | |
| --- | --- |
| Discovery | `/.well-known/poppy.json` and `/.well-known/oauth-protected-resource` (`resource` is the door's origin, `authorization_servers` the issuer, `scopes_supported` the one scope). Locally `organization.domain` carries the port, which 1.0 allows (3.1) |
| Identifier, Session `aud` | The issuer: the door itself, `<BASE_URL>/pg/doors/poppy` |
| Company Agent | `poppy` protocol at `<BASE_URL>/pg/doors/poppy/conversations`, with the `description` 1.0 requires ([8.1](https://personalagentprotocol.org/docs/1.0/spec#conversation-protocols)) |
| Version | `protocol_version: "1.0"`, no `supported_versions`. Every Session request carries `Poppy-Version`; the door serves any `1.x` as 1.0 ([3.4](https://personalagentprotocol.org/docs/1.0/spec#versions)) |
| Scope | `conversations`: "Let the Company Agent see which account you signed in with, in a conversation". Hints: `changes: none`, `personal_data: false` |
| Sign-in | Direct Sign-In at the door's own issuer (below), with a test account |

The Company Agent is canned. Signed out, it echoes your message and adds an `authorization`
event asking for `conversations`
([8.11](https://personalagentprotocol.org/docs/1.0/spec#conversation-sign-in)). Signed in with
that scope, it echoes, names the test account you signed in as, and puts a
receipt in the reply's `data.receipt`: an ES256 JWT, `typ: pg-receipt+jwt`, verifiable against
`/pg/jwks.json`, with `sub` your run's handle and `jti` the attempt.

## Linking an agent to a run

Poppy has no place for a run ID: a Personal Agent sends the same Session JWTs to every Company.
So the door links by `client_id`:

```sh
curl -X POST localhost:8401/pg/runs -H 'content-type: application/json' \
  -d '{"handle": "relaybox", "client_id": "https://agent.example/agent.json"}'
# → {..., "poppy": {"client_metadata": "valid", "discovery": ...}}
```

The door fetches and checks the client metadata document then. If it is wrong, the run is still
made, and `poppy.problem` says why; the door fetches it again on every request after its 5-minute
cache expires. One `client_id` belongs to one run.

**No anonymous use.** A Session JWT whose `iss` no run registered gets `invalid_session` with
`error_description` "client_id refused: ... POST {handle, client_id} to /pg/runs first"
([4.1](https://personalagentprotocol.org/docs/1.0/spec#agent-identity) lets a Company refuse a
`client_id` this way). These attempts show on the wall's anonymous row. Sign-in itself needs no
run: the issuer accepts any `client_id` whose metadata checks out.

## The issuer

The door is its own OAuth issuer ([3.2](https://personalagentprotocol.org/docs/1.0/spec#oauth-server)),
so it needs nothing from outside and nobody registers a client: the `client_id` URL *is* the
registration ([CIMD](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)).
Its metadata is at `/.well-known/oauth-authorization-server/pg/doors/poppy` (RFC 8414 §3.1), with
`protected_resources: [<origin>]`.

| Endpoint | What it does | Refuses with |
| --- | --- | --- |
| `GET …/authorize` | Fetches the client metadata. `redirect_uri` must match one of its `redirect_uris` exactly, or differ only in a loopback URI's port (RFC 8252 §7.3); until both check out, errors show on a page and never redirect. Then: `response_type=code`, PKCE `S256`, `scope` present and only `conversations`. Shows a consent page naming the client's **domain** (not its self-chosen `client_name`), every time. A request without `prompt=consent` is noted on the timeline, not refused (below) | `invalid_request`, `invalid_scope`, `unsupported_response_type`, back to the client with `iss` and `state` |
| `POST …/authorize` | The User's click: **Allow** as a test account (default `test-user`, any name; no password), or **Deny**. Sends the browser back with `code` (or `error=access_denied`) and always `iss` (RFC 9207) | |
| `POST …/token` | `authorization_code` (one use, 60 s, same client and `redirect_uri`, PKCE checked) or `refresh_token` (same client; `scope` may narrow). Client auth is `private_key_jwt` only: an ES256 or PS384 assertion signed by a `jwks_uri` key, `iss` = `sub` = `client_id`, with `exp`, `iat`, `jti`, `exp - iat` at most 5 minutes, and `aud` **exactly** the issuer as one string, so the token endpoint URL, an array or a trailing slash are refused (4.1). `resource` is absent (the default token) or the domain resource, `https://{organization.domain}`; any other is `invalid_target` (4.5). Returns an opaque Bearer access token (10 min), a refresh token (30 days, not rotated, use doesn't extend it), and exactly the scope granted | `invalid_client` (401), `invalid_grant`, `invalid_scope`, `invalid_target`, `unsupported_grant_type` |
| `POST …/revoke` | RFC 7009, same client auth. Revoking a refresh token also revokes the access tokens made from it | `invalid_client` (401) |

**`prompt=consent`.** A Personal Agent MUST send it unless it receives the redirect only on the
device that opened the authorization URL ([4.2](https://personalagentprotocol.org/docs/1.0/spec#direct-sign-in)).
The door can't see which, so a request without it, and with a redirect URI that isn't loopback, adds
"note: no prompt=consent" to the timeline and carries on (D-009). The consent page shows either way.

The consent page can't be framed (`X-Frame-Options: DENY`). Tokens are opaque because the door is
the only resource that takes them. Like Sessions and conversations, they are in memory: a restart
signs everyone out.

## The ladder

**An attempt is one Session** (`client_id` + `sid` + User ID: a known `sid` with another `sub` is
another Session, [5.3](https://personalagentprotocol.org/docs/1.0/spec#session-verification)). Every request in it is walked up the ladder,
and the attempt keeps the highest step reached. A request that fails before the Session is
verified makes an attempt of its own. Failures count on the run's row only once the delegation
verifies, because only then has the client's own key vouched for the request; before that, they go
on the anonymous row.

| Step | Checks | Stop codes |
| --- | --- | --- |
| [session presented](https://personalagentprotocol.org/docs/1.0/spec#session-header) | The request to the conversation endpoint carries `Poppy-Session`, and `Poppy-Version` `1.x` | `no_session`, `version_unsupported` |
| [client resolved](https://personalagentprotocol.org/docs/1.0/spec#agent-identity) | The JWT decodes; `iss` is a `client_id` a run registered; its metadata (fetched without redirects, public address, HTTPS) has `client_id` equal to its URL, `jwks_uri` and `redirect_uris` on its domain (or loopback redirects), `token_endpoint_auth_method: private_key_jwt`; the JWKS has keys and no private members | `session_malformed`, `client_refused`, `client_metadata_invalid`, `jwks_invalid` |
| [delegation valid](https://personalagentprotocol.org/docs/1.0/spec#delegated-keys) | `poppy_dlg` present; its `kid` names a JWKS key that verifies it (ES256 or PS384); `typ` `poppy-delegation+jwt`; `iss` is the Session JWT's; unexpired; `exp - iat` ≤ 24 h; `cnf.jwk` is public | `delegation_missing`, `delegation_invalid` |
| [session valid](https://personalagentprotocol.org/docs/1.0/spec#session-verification) | `kid` is the delegated key's RFC 7638 thumbprint and the signature verifies with it (`typ` `poppy-session+jwt`, ES256); `sid`, `sub`, `htm`, `htu`, `jti`, `iat` present; `aud` is the issuer as one string; `htm`/`htu` match the request; `iat` within 60 s; `ath` matches the token, or is absent without one | `session_signature`, `session_claims`, `aud_mismatch`, `htu_mismatch`, `iat_out_of_window`, `ath_mismatch` |
| [conversation started](https://personalagentprotocol.org/docs/1.0/spec#sending-messages) | `POST {endpoint}` (or `.../messages`) with a top-level request `id` and a valid message is accepted: 201 (202), body `{conversation_id}` only. The same `id` with the same path and body gets the original response; request IDs are unique per User across all requests | `invalid_request`, `request_id_conflict` |
| [reply read](https://personalagentprotocol.org/docs/1.0/spec#reading-events) | A read (`GET .../events`, or a `POST` with `wait`) returned a Company Agent message | `conversation_not_found`, `conversation_closed`, `invalid_cursor` |
| [signed in](https://personalagentprotocol.org/docs/1.0/spec#access-tokens) | `Authorization: Bearer` carries an access token the issuer issued, unexpired and unrevoked; it was issued to the Session's `client_id`; the Session hasn't used another account | `token_invalid`, `token_other_client`, `session_ended` |
| [authorized call](https://personalagentprotocol.org/docs/1.0/spec#conversation-sign-in) | A signed-in message with scope `conversations` was accepted; the conversation now uses that account | `account_required` |
| through | A read returned the signed-in reply with its receipt | |

How each stop answers, following [section 7](https://personalagentprotocol.org/docs/1.0/spec#apis)
and [8.13](https://personalagentprotocol.org/docs/1.0/spec#conversation-errors): every Session
check is `400 {"error": "invalid_session"}`, `version_unsupported` is 400, `session_ended` is 400, `token_invalid` is 401 with
`WWW-Authenticate: Bearer error="invalid_token"`, `account_required` is a 401 challenge with no
error code (`Bearer scope="conversations"`), and the conversation errors are their own codes.
Every stop body also has `error_description`, `stopped_at`, `pg_stop` (the code above), and a
`watch` link to the attempt's timeline.

A token without `conversations` isn't a stop: the message is accepted and the Company Agent asks
for the scope again with an `authorization` event, as 8.11 says.

**Why there is no "discovered" step.** The agreed sketch started with *discovered*. Discovery
documents carry no Session header (5.2), so the door can't tell whose fetch of `poppy.json` it was.
The first step it can attribute is a Session request. Using the right `aud` (the issuer) and
endpoint is the evidence of discovery, and a wrong `aud` stops at `aud_mismatch`.

**Sign-in** happens on other requests than the conversation. For a `client_id` a run registered,
what the issuer did (consent shown, approved or declined, tokens issued, and every refusal with its
reason, such as `token refused, invalid_client: The assertion's aud must be the issuer...`) joins
the timeline of the client's next Session request.

## Not scored

- **`prompt=consent`** (4.2): noted on the timeline, as above.
- **`resource` at sign-in.** A Personal Agent SHOULD NOT send it (4.5); the door ignores it there,
  and checks it only at the token endpoint.
- **DPoP.** The issuer only issues Bearer tokens, which 4.5 allows, so a DPoP proof is never needed.
- **The agent's checks.** Whether the agent checked `organization.domain`, the issuer's
  `protected_resources`, `iss` in the authorization response, the device sign-in link's host, or
  `protocol_version`. The door can't see them; the reference client does them.
- **Reused `jti`** in Session JWTs and client assertions. A MAY; not checked.
- **A delegated key that signed for another User ID** (5.2). A MAY; not checked.
- **Web Bot Auth** operator signatures (5.3, a SHOULD).

## HTTPS and the dev switch

The spec requires HTTPS for every URL it exchanges, and refuses private addresses. When
`BASE_URL` is `http://localhost`, `http://*.localhost` or `http://127.0.0.1` (`DEV` in
[`lab.ts`](../lab.ts)), the door accepts `http` client metadata, JWKS and redirect URIs, and
fetches loopback addresses. That's how the tests and a local run work. On any other `BASE_URL`,
`http` and private addresses are refused, so an agent signing in at a public proving ground serves
its documents on public HTTPS (`--public-url`).

## Not built yet

- Direct Conversations (`parent_conversation_id` gets `invalid_request`), browser join, the
  `apis` listing, Device Sign-In, `tasks.endpoint` (excluded tasks, skills, feedback), extensions
  and `Poppy-Extensions`, Pushed Authorization Requests, `supported_versions`, `cursor_expired`,
  SSE (a read with `Accept: text/event-stream` gets JSON, which 8.6 allows), and holding a read for
  `wait` (the reply is ready at once).
- Handoff, cancel and close are acted on as they are accepted, so `working` is always `false` in a
  response. A handoff sets `handoff` to `pending`, then back to `none` with a message saying nobody
  will join, adding a `state` event for each. A cancel then changes nothing. A close sets `closed`
  and adds a `state` event; closing again is 202 and changes nothing (8.9, 8.12).
- Conversations, Sessions, tokens and the client cache are in memory and lost on restart (marked
  `ponytail:` in the code).
- Rate limiting (5.6), as for every door.
