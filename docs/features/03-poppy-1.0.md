# 03 The poppy door on Personal Agent Protocol 1.0
Goal: move the poppy door from Poppy 0.3 (`personal-agent-protocol@6fb46d3`) to Poppy 1.0, published and frozen on 2026-11-14 at `personal-agent-protocol@8c02b42` ([/docs/1.0/spec](https://personalagentprotocol.org/docs/1.0/spec)). 1.0 is 0.4 plus fixes, and 0.4 carried most of the breaking changes, so the door has to take both.
Done = a Personal Agent that follows only the 1.0 text gets through the door, and one that follows 0.3 is stopped. It is stopped at `version_unsupported` on its first Session request, or earlier by `protocol_version: "1.0"` in discovery. `poppy-client.ts` speaks 1.0, and the door's docs, wall and `/llms.txt` name 1.0 and the new pin.
Feature test: `npm test`, with `test/poppy.test.ts` updated for every changed stop and a test for each new one, then `node poppy-client.ts` against a local server and, after deploy, against the Lab.
Out of scope: Device Sign-In, Direct Conversations, browser join, `tasks.endpoint`, extensions and `Poppy-Extensions` (the door lists none), DPoP (the door issues Bearer tokens), SSE. All are unchanged from today's "Not built yet".
Decisions: proposed D-007 to D-009 below. They are not recorded in DECISIONS.md until agreed.

Changelog read: [1.0](https://personalagentprotocol.org/docs/changelog#v1-0) and [0.4](https://personalagentprotocol.org/docs/changelog#v0-4) (`content/shared/changelog.mdx`).

## Proposed decisions
- **D-007 1.0 only.** The door serves 1.0 and drops 0.3, with no `supported_versions`. It pins one version, as every door does. A 0.3 agent is told why at `version_unsupported`. Rejected: serving 0.3 alongside via `supported_versions` (3.4), which would double the door's code and tests for a version nobody is building to now.
- **D-008 Enforce what a Company MAY enforce, where an agent MUST comply.** The door rejects a client assertion that lasts more than 5 minutes (4.1: the agent MUST, the Company MAY reject). The same pattern as poppy's existing strict `aud` check.
- **D-009 `prompt=consent` is noted, not scored.** The door can't tell whether an agent receives the redirect only on the device that opened the URL, which is the exception to the MUST in 4.2. A missing `prompt=consent` goes on the timeline as a note and doesn't stop the attempt. The door's consent page already shows every time.

## What changes, by area
Each item cites the 1.0 section and the changelog entry. Items marked *Breaking* make today's door or client wrong under 1.0.

**Discovery (3, 3.1, 3.4)**
- `protocol_version: "1.0"`. *Breaking* for 0.3 agents.
- Each `agent.protocols` entry has a required `description` (*Breaking*, "Conversation protocol descriptions"). The door has none today.
- `organization.domain` may now carry a port that isn't 443. The door's dev setup (`pg.localhost:8401`) is now spec-legal, so the dev switch covers less.
- Optional, and worth doing: `scopes_supported` in the protected resource metadata (3.2).

**Versions (3.4, 5.2, 7)**
- Every request with the Session header carries `Poppy-Version: 1.0`. A missing or incompatible version gets `400 {"error": "version_unsupported"}`, and the door MUST NOT handle the request under another version. This is a new stop.

**Sessions (5.2, 5.3)**
- A Session is looked up by `client_id`, `sid` *and* User ID ("Sessions found by User ID too"). A known `sid` with another `sub` is a different Session, not an error, and the Agent ID isn't checked. The `sub_mismatch` stop must go.
- Delegations MUST accept PS384 as well as ES256 ("PS384 required"). The door already does, for delegations and client assertions.
- New, as a MAY: refuse a delegated key that already signed for another User ID. Not proposed here; see Later.

**OAuth at the door's issuer (4.1, 4.2, 4.5, 4.7)**
- Client assertion `exp` at most 5 minutes after `iat` (D-008; *Breaking* for agents with longer assertions).
- `prompt=consent` on Direct Sign-In requests (D-009).
- `resource`: a sign-in without it covers every resource. A token request names one resource or none, and the Company returns `invalid_target` for a resource it doesn't serve ("One sign-in for every resource"). Today the door ignores `resource`. It should accept none or `https://{organization.domain}`, and answer `invalid_target` otherwise.
- PAR (4.2) is optional for a Company and only a SHOULD for an agent when offered. Not proposed; see Later.
- "Same DPoP key at refresh" doesn't apply, since the door issues Bearer tokens.

**Conversations (8.2–8.13)**, where most of the breaking change is:
- Every conversation `POST` has a top-level request `id` (*Breaking*). A message's ID is its request's ID, so `message.id` goes. A retry with the same `id`, path and body gets the original response. The same `id` with another path or body gets `409 request_id_conflict`, replacing `message_id_conflict`. IDs are unique per User across all their requests, not per conversation.
- A `POST` without `wait` returns only `{conversation_id}`; it means accepted, not acted on (*Breaking*).
- State is four fields, `working`, `handoff`, `responder` and `closed`, replacing `status` (*Breaking*). Every read returns all four, and `state` events carry `handoff`, `responder` and `closed`. The canned agent replies at once, so `working` is always `false` in a response.
- `POST …/handoff` takes `{id}` and returns 202. `handoff` goes to `pending`, then back to `none` with a message saying nobody will join, adding a `state` event for each change.
- New: `POST …/handoff/cancel` takes `{id}` and returns 202. It changes nothing when `handoff` isn't `pending`.
- `POST …/close` takes `{id}` and returns 202, not 200. A close of a closed conversation is 202 and changes nothing. After a close, messages, handoffs and cancels get `conversation_closed`.
- Ownership is the `client_id`, User ID and account; Agent IDs aren't part of it (8.2). The door's `owner()` already matches this.
- The `authorization` event (8.11) is unchanged.

**Errors (7, 8.13)**: `version_unsupported` and `request_id_conflict` are new; `message_id_conflict` is gone.

## Tasks
- [ ] 1. Pin 1.0 and update discovery
      Criteria: `SPEC_URL` pins `content/versions/1.0/spec.mdx` at `8c02b42`, and `SPEC_SITE` is `/docs/1.0/spec`. The 1.0 headings keep every anchor the ladder links to (checked: `#session-header`, `#agent-identity`, `#delegated-keys`, `#session-verification`, `#sending-messages`, `#reading-events`, `#access-tokens`, `#conversation-sign-in`). `poppy.json` has `protocol_version: "1.0"` and a `description` on the `poppy` entry. The protected resource metadata adds `scopes_supported`.
      Test: the discovery test asserts the 1.0 document; `/llms.txt` names `personal-agent-protocol@8c02b42`.
- [ ] 2. `Poppy-Version` and `version_unsupported`
      Criteria: checked at the "session presented" step, right after the Session header is found. Missing, or not `1.x`, gives `400 {"error": "version_unsupported"}` with `pg_stop: version_unsupported`. Any `1.x` is accepted (3.4: minor versions are compatible), and the door answers as 1.0.
      Test: missing → stop; `0.3` → stop; `1.1` → accepted.
- [ ] 3. Sessions by User ID
      Criteria: sessions keyed by `client_id|sid|sub`. `sub_mismatch` is removed from `STOPS`, the ladder table and the docs. The Agent ID isn't compared.
      Test: replace the `sub_mismatch` test. The same `sid` with another `sub` is a second Session with its own attempt, and both get through.
- [ ] 4. Conversation requests with request IDs
      Criteria: every conversation POST needs a top-level `id` (`invalid_request` without it, or with characters outside the URL-safe base64 alphabet). Messages carry no `id`; the door records the request's ID as the message's. Retry detection is keyed by `client_id|sub|id`, and compares the path and body. `request_id_conflict` (409) replaces `message_id_conflict`. A POST without `wait` returns `{conversation_id}` only.
      Test: replace the `message_id_conflict` test, adding a case for the same ID on another path. The retry test keeps the original response.
- [ ] 5. State in four fields; handoff, cancel and close
      Criteria: reads and `wait` responses carry `working: false`, `handoff`, `responder` and `closed`. `state` events carry `handoff`, `responder` and `closed`. Handoff, cancel and close follow "What changes" above. Routes add `handoff/cancel`.
      Test: the through test asserts the four fields. New tests for handoff (pending, then none, with a message), cancel, close (202, again 202), and `conversation_closed` for a message and a cancel after close.
- [ ] 6. Issuer: assertion lifetime and `resource`
      Criteria: a client assertion with `exp - iat > 300` gets `invalid_client` (D-008). At the token endpoint, a `resource` other than `https://{organization.domain}` gets `invalid_target`. A Direct Sign-In without `prompt=consent` adds a timeline note through the existing sign-in notes (D-009).
      Test: a 10-minute assertion → `invalid_client`; `resource=https://elsewhere.example` → `invalid_target`; no `prompt=consent` → the note appears on the attempt.
- [ ] 7. `poppy-client.ts` on 1.0
      Criteria: it accepts only a `1.x` document, sends `Poppy-Version: 1.0`, gives every POST a request `id`, reads the four state fields, sends `prompt=consent` (the reference client opens the URL and gets the redirect on one machine, but sends it anyway, since that is the conservative choice), and keeps its 2-minute assertions, already within the 5-minute limit.
      Test: `npm test` drives it through; `node poppy-client.ts http://pg.localhost:8401` reaches the receipt.
- [ ] 8. Docs
      Criteria: `src/doors/poppy.md` covers the 1.0 pin, every section link to `/docs/1.0/spec`, the ladder table (new and removed stops), and "Not built yet" with the items under Later. The README doors table names 1.0. The wall picks the pin up from `INFO`.
      Test: the links resolve; `grep -rn "0\.3\|6fb46d3"` over `src`, `README.md` and the clients finds nothing about poppy.
- [ ] 9. Deploy
      Criteria: push, bump the pin in affinidi-lab's `infra/agent-services/compose.yaml`, deploy (the user), probe `…/.well-known/poppy.json` for `protocol_version: "1.0"`.
      Test: `node poppy-client.ts https://agentlab.choosemission.com/proving-ground --public-url <tunnel>` gets the receipt.

## Later
- Pushed Authorization Requests (4.2): list `pushed_authorization_request_endpoint`, and maybe score whether an agent uses it when offered (a SHOULD).
- Refusing a delegated key that signed for another User ID (5.2, a MAY).
- `tasks.endpoint` (9), `supported_versions` (if a 1.1 ever needs serving alongside), `cursor_expired`, SSE with `working` events, Device Sign-In, Direct Conversations.
