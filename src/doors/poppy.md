# The poppy door

A Company under **Personal Agent Protocol (Poppy) 0.3 as published at
[`personal-agent-protocol@6fb46d3`](https://github.com/personal-agent-protocol/personal-agent-protocol/blob/6fb46d381ac1b94265795132af13848ec442b6f6/content/versions/0.3/spec.mdx)**
(the last commit to change the 0.3 spec; the repo's HEAD was `7205250` when it was pinned).
Section links below go to the rendered page,
[personalagentprotocol.org/docs/0.3/spec](https://personalagentprotocol.org/docs/0.3/spec),
which matched the pinned file at the time. The door implements the draft as of that commit and claims
nothing about conformance.

Code: [`poppy.ts`](poppy.ts). Reference Personal Agent: [`poppy-client.ts`](../../poppy-client.ts),
meant to be read next to the spec.

```sh
node poppy-client.ts http://pg.localhost:8401                    # every step, locally; open the sign-in link it prints
node poppy-client.ts https://<proving ground> --public-url https://<tunnel to :8402>
```

## The Company

| | |
| --- | --- |
| Discovery | `/.well-known/poppy.json` and `/.well-known/oauth-protected-resource` (`resource` is the door's origin, `authorization_servers` the issuer) |
| Identifier, Session `aud` | The issuer: the door itself, `<BASE_URL>/pg/doors/poppy` |
| Company Agent | `poppy` protocol at `<BASE_URL>/pg/doors/poppy/conversations` |
| Scope | `conversations`: "Let the Company Agent see which account you signed in with, in a conversation". Hints: `changes: none`, `personal_data: false` |
| Sign-in | Direct Sign-In at the door's own issuer (below), with a test account |

The Company Agent is canned. Signed out, it echoes your message and adds an `authorization`
event asking for `conversations`
([8.11](https://personalagentprotocol.org/docs/0.3/spec#conversation-sign-in)). Signed in with
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
([4.1](https://personalagentprotocol.org/docs/0.3/spec#agent-identity) lets a Company refuse a
`client_id` this way). These attempts show on the wall's anonymous row. Sign-in itself needs no
run: the issuer accepts any `client_id` whose metadata checks out.

## The issuer

The door is its own OAuth issuer ([3.2](https://personalagentprotocol.org/docs/0.3/spec#oauth-server)),
so it needs nothing from outside and nobody registers a client: the `client_id` URL *is* the
registration ([CIMD](https://datatracker.ietf.org/doc/draft-ietf-oauth-client-id-metadata-document/)).
Its metadata is at `/.well-known/oauth-authorization-server/pg/doors/poppy` (RFC 8414 §3.1), with
`protected_resources: [<origin>]`.

| Endpoint | What it does | Refuses with |
| --- | --- | --- |
| `GET …/authorize` | Fetches the client metadata. `redirect_uri` must match one of its `redirect_uris` exactly, or differ only in a loopback URI's port (RFC 8252 §7.3); until both check out, errors show on a page and never redirect. Then: `response_type=code`, PKCE `S256`, `scope` present and only `conversations`. Shows a consent page naming the client's **domain** (not its self-chosen `client_name`) | `invalid_request`, `invalid_scope`, `unsupported_response_type`, back to the client with `iss` and `state` |
| `POST …/authorize` | The User's click: **Allow** as a test account (default `test-user`, any name; no password), or **Deny**. Sends the browser back with `code` (or `error=access_denied`) and always `iss` (RFC 9207) | |
| `POST …/token` | `authorization_code` (one use, 60 s, same client and `redirect_uri`, PKCE checked) or `refresh_token` (same client; `scope` may narrow). Client auth is `private_key_jwt` only: an ES256 or PS384 assertion signed by a `jwks_uri` key, `iss` = `sub` = `client_id`, with `exp`, `iat`, `jti`, and `aud` **exactly** the issuer as one string, so the token endpoint URL, an array or a trailing slash are refused (4.1). Returns an opaque Bearer access token (10 min), a refresh token (30 days, not rotated, use doesn't extend it), and exactly the scope granted | `invalid_client` (401), `invalid_grant`, `invalid_scope`, `unsupported_grant_type` |
| `POST …/revoke` | RFC 7009, same client auth. Revoking a refresh token also revokes the access tokens made from it | `invalid_client` (401) |

The consent page can't be framed (`X-Frame-Options: DENY`). Tokens are opaque because the door is
the only resource that takes them. Like Sessions and conversations, they are in memory: a restart
signs everyone out.

## The ladder

**An attempt is one Session** (`client_id` + `sid`). Every request in it is walked up the ladder,
and the attempt keeps the highest step reached. A request that fails before the Session is
verified makes an attempt of its own. Failures count on the run's row only once the delegation
verifies, because only then has the client's own key vouched for the request; before that, they go
on the anonymous row.

| Step | Checks | Stop codes |
| --- | --- | --- |
| [session presented](https://personalagentprotocol.org/docs/0.3/spec#session-header) | The request to the conversation endpoint carries `Poppy-Session` | `no_session` |
| [client resolved](https://personalagentprotocol.org/docs/0.3/spec#agent-identity) | The JWT decodes; `iss` is a `client_id` a run registered; its metadata (fetched without redirects, public address, HTTPS) has `client_id` equal to its URL, `jwks_uri` and `redirect_uris` on its domain (or loopback redirects), `token_endpoint_auth_method: private_key_jwt`; the JWKS has keys and no private members | `session_malformed`, `client_refused`, `client_metadata_invalid`, `jwks_invalid` |
| [delegation valid](https://personalagentprotocol.org/docs/0.3/spec#delegated-keys) | `poppy_dlg` present; its `kid` names a JWKS key that verifies it (ES256 or PS384); `typ` `poppy-delegation+jwt`; `iss` is the Session JWT's; unexpired; `exp - iat` ≤ 24 h; `cnf.jwk` is public | `delegation_missing`, `delegation_invalid` |
| [session valid](https://personalagentprotocol.org/docs/0.3/spec#session-verification) | `kid` is the delegated key's RFC 7638 thumbprint and the signature verifies with it (`typ` `poppy-session+jwt`, ES256); `sid`, `sub`, `htm`, `htu`, `jti`, `iat` present; `aud` is the issuer as one string; `htm`/`htu` match the request; `iat` within 60 s; `ath` matches the token, or is absent without one; a known `sid` keeps its `sub` and `agent_id` | `session_signature`, `session_claims`, `aud_mismatch`, `htu_mismatch`, `iat_out_of_window`, `ath_mismatch`, `sub_mismatch` |
| [conversation started](https://personalagentprotocol.org/docs/0.3/spec#sending-messages) | `POST {endpoint}` (or `.../messages`) with a valid message is accepted: 201 (202). A retried message ID with the same content gets the original response | `invalid_request`, `message_id_conflict` |
| [reply read](https://personalagentprotocol.org/docs/0.3/spec#reading-events) | A read (`GET .../events`, or a `POST` with `wait`) returned a Company Agent message | `conversation_not_found`, `conversation_closed`, `invalid_cursor` |
| [signed in](https://personalagentprotocol.org/docs/0.3/spec#access-tokens) | `Authorization: Bearer` carries an access token the issuer issued, unexpired and unrevoked; it was issued to the Session's `client_id`; the Session hasn't used another account | `token_invalid`, `token_other_client`, `session_ended` |
| [authorized call](https://personalagentprotocol.org/docs/0.3/spec#conversation-sign-in) | A signed-in message with scope `conversations` was accepted; the conversation now uses that account | `account_required` |
| through | A read returned the signed-in reply with its receipt | |

How each stop answers, following [section 7](https://personalagentprotocol.org/docs/0.3/spec#apis)
and [8.13](https://personalagentprotocol.org/docs/0.3/spec#conversation-errors): every Session
check is `400 {"error": "invalid_session"}`, `session_ended` is 400, `token_invalid` is 401 with
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

- **`resource`** (RFC 8707). The issuer ignores it; Poppy says `invalid_target` for one it doesn't
  serve (4.5).
- **DPoP.** The issuer only issues Bearer tokens, which 4.5 allows, so a DPoP proof is never needed.
- **The agent's checks.** Whether the agent checked `organization.domain`, the issuer's
  `protected_resources`, `iss` in the authorization response, the device sign-in link's host, or
  `protocol_version`. The door can't see them; the reference client does them.
- **Reused `jti`** in Session JWTs and client assertions. A MAY; not checked.
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
  `apis` listing, Device Sign-In, excluded tasks, feedback, extensions, SSE (a read with
  `Accept: text/event-stream` gets JSON, which 8.6 allows), and holding a read for `wait` (the reply
  is ready at once).
- Handoff and close are minimal: handoff adds a message saying nobody will join, and changes
  nothing else; close adds a `closed` state event.
- Conversations, Sessions, tokens and the client cache are in memory and lost on restart (marked
  `ponytail:` in the code).
- Rate limiting (5.6), as for every door.
