# The poppy door's Keycloak realm

The poppy door ([`src/doors/poppy.md`](../src/doors/poppy.md)) uses Keycloak as its OAuth issuer:
realm `protocol-proving-experiments` at `https://idp.agentlab.choosemission.com`. Personal Agents
sign in there; the door registers their clients there and verifies the tokens it issues. Below is
the setup the door's code expects. Names in `code` must match exactly.

Only the issuer and its metadata have been checked against the live realm. The admin calls and
the token claims are tested against a stand-in in [`test/poppy.test.ts`](../test/poppy.test.ts).

## The door's environment

| Variable | Default | |
| --- | --- | --- |
| `POPPY_ISSUER` | `https://idp.agentlab.choosemission.com/realms/protocol-proving-experiments` | The issuer. Must be a Keycloak realm URL (`.../realms/<realm>`): the door derives the token endpoint, the JWKS (`/protocol/openid-connect/certs`) and the admin API (`.../admin/realms/<realm>`) from it |
| `POPPY_ADMIN_CLIENT_ID` | `proving-ground-door` | The door's admin client, below |
| `POPPY_ADMIN_CLIENT_SECRET` | none | Its secret. Without it the door skips registering clients and reading events; signed-out steps still work, sign-in doesn't |
| `BASE_URL` | | The proving ground's public URL. The `conversations` scope's audience mapper must emit exactly this |

## 1. Realm settings

- **General.** The issuer is
  `https://idp.agentlab.choosemission.com/realms/protocol-proving-experiments`. The frontend URL
  must stay the public host, since the door compares `iss` character for character.
- **Login.** Turn on *User registration*, so participants can make the account they sign in with.
  Turn on *Verify email* if the realm has mail.
- **Tokens.** *Revoke Refresh Token* on, *Refresh Token Max Reuse* 0: refresh token rotation,
  realm-wide (Poppy 4.4 follows RFC 6749 §6). Access tokens of 5 to 15 minutes are fine. The
  default signature algorithm can stay RS256; the door accepts whatever the realm's JWKS holds.
- **Client registration.** Nothing to change: the door registers clients through the admin API,
  not dynamic registration. No client policies are needed; the door sets each client's attributes
  itself (step 4).

## 2. The `conversations` client scope

*Client scopes → Create client scope:*

- Name `conversations`, type **Optional**, protocol OpenID Connect.
- *Display on consent screen* on, consent text: "Let the Company Agent see which account you
  signed in with, in a conversation".
- *Include in token scope* on.
- Mapper: *By configuration → Audience*, name `proving-ground audience`, *Included Custom
  Audience* = the proving ground's `BASE_URL` (no trailing slash), *Add to access token* on, *Add
  to ID token* off. The door requires `aud` to include `BASE_URL`.

Don't make it a realm default scope: the door adds it to each agent client as an optional scope,
so it is in a token only when the agent asks for it. This is the scope `poppy.json` advertises in
`auth.scopes` and `auth.scope_hints` (`changes: none`, `personal_data: false`).

## 3. The door's admin client, `proving-ground-door`

*Clients → Create client:*

- Client ID `proving-ground-door`, OpenID Connect.
- *Client authentication* on (confidential), authenticator *Client Id and Secret*.
- *Standard flow* off, *Direct access grants* off, *Service accounts roles* on.
- *Service accounts roles → Assign role → Filter by clients*, `realm-management`:
  `manage-clients`, `view-clients`, `query-clients`, `view-events`.
- *Credentials*: copy the secret into the door's `POPPY_ADMIN_CLIENT_SECRET`.

## 4. What the door registers for each agent

When a run is started with a `client_id`, the door fetches and checks the client metadata
document, then creates (or, if it exists, updates) a Keycloak client:

| Keycloak | Value |
| --- | --- |
| Client ID | The `client_id` URL |
| Name | `client_name`, or the URL |
| Client authentication | On, authenticator `client-jwt` (Signed JWT), *Use JWKS URL* on, *JWKS URL* = `jwks_uri` |
| `token.endpoint.auth.signing.alg` | `ES256` |
| `pkce.code.challenge.method` | `S256` |
| Standard flow | On; implicit, direct access grants, service accounts and device grant off |
| Consent required | On, so the User approves the scopes on the Company's page (4.2) |
| Valid redirect URIs | `redirect_uris`, exactly |
| Optional client scopes | `conversations` added |

The door picks up changes to `jwks_uri`, `redirect_uris` or `client_name` when its 5-minute
metadata cache expires on the next Session request. Keycloak fetches the JWKS itself, so it must be
on public HTTPS.

## 5. Events

*Realm settings → Events → User events settings:* *Save events* on, an expiration such as 7 days,
and at least these types saved: `LOGIN_ERROR`, `CODE_TO_TOKEN_ERROR`, `CLIENT_LOGIN_ERROR`,
`REFRESH_TOKEN_ERROR`, `PERMISSION_TOKEN_ERROR`. The door reads a client's `*_ERROR` events with
`GET /admin/realms/protocol-proving-experiments/events?client=<client_id>` and puts them on the
attempt's timeline, since sign-in failures happen where it can't see them. Admin events aren't
needed.

## 6. `protected_resources`: one rewritten response

Poppy 3.2 says the issuer's OAuth metadata MUST list the Company's domain in
`protected_resources` (RFC 9728 §4), and a Personal Agent MUST check it before using
`poppy.json`. Keycloak doesn't emit that field (checked on the live realm). The reference client
refuses the Company without it, as the spec says it should.

Personal Agents fetch the metadata at the RFC 8414 §3.1 URL, which the live realm serves:

```
https://idp.agentlab.choosemission.com/.well-known/oauth-authorization-server/realms/protocol-proving-experiments
```

Have the proxy in front of Keycloak rewrite that one response to add the field. With nginx:

```nginx
location = /.well-known/oauth-authorization-server/realms/protocol-proving-experiments {
    proxy_pass http://keycloak;
    proxy_set_header Host $host;
    proxy_set_header Accept-Encoding "";          # sub_filter needs an uncompressed body
    sub_filter_types application/json;
    sub_filter_once on;
    sub_filter '{"issuer":' '{"protected_resources":["https://<proving ground host>"],"issuer":';
}
```

With Caddy, either build it with the `replace-response` module and do the same replacement, or
serve a static copy of the metadata with the field added (`handle` + `file_server`), and refresh
that copy when Keycloak changes its endpoints. The value is `https://` plus the host of the
proving ground's `BASE_URL`, with no path, port or trailing slash. Leave
`/realms/protocol-proving-experiments/.well-known/oauth-authorization-server` and the OpenID
configuration alone: Poppy doesn't read them.

Check it:

```sh
curl -s https://idp.agentlab.choosemission.com/.well-known/oauth-authorization-server/realms/protocol-proving-experiments | jq .protected_resources
```

## Where Keycloak is more lenient than Poppy

The door doesn't score these, because it can't see them (see the door's *Not scored*): Keycloak
accepts a client assertion whose `aud` is the token endpoint rather than the issuer, drops unknown
scopes instead of answering `invalid_scope`, adds its default client scopes to tokens, and ignores
`resource`. It also advertises grants Poppy agents don't use (`password`, `implicit`, ...); the
door's clients have them off.
