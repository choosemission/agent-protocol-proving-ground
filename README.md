# Proving ground

A proof of concept for the Agent Lab proving ground
([plan](../affinidi-lab/docs/proving-ground-plan.md)): a set of **doors**, one
per agent protocol, and a homepage listing them. Each door has a public wall at `/<door>` that
shows every attempt live. Each door implements one protocol as published at a pinned commit and
scores each attempt by how far up that protocol's ladder of checks it got.
It claims nothing about conformance.

| Door | Protocol | Docs |
| --- | --- | --- |
| `x401` | x401 0.2.0 at `proof/x401@7e864af`, OpenID4VP + SD-JWT VC | [src/doors/x401.md](src/doors/x401.md) |
| `poppy` | Personal Agent Protocol 0.3 at `personal-agent-protocol@6fb46d3`: Session JWTs, conversations, and the door as its own OAuth issuer | [src/doors/poppy.md](src/doors/poppy.md) |
| `aauth` | AAuth Protocol -11 at `dickhardt/AAuth@178e9e6`: signed requests (RFC 9421, Signature-Key), agent, person, resource and auth tokens, with any person server or the Lab test PS | [src/doors/aauth.md](src/doors/aauth.md) |

## Run it

Needs Node 22.18 or later. It runs the TypeScript directly, with no build step.

```sh
npm install
npm start                 # http://pg.localhost:8401, each door's wall is at /<door>
npm test                  # end to end: every place an attempt can stop (needs openssl)
npm run typecheck
```

| Variable | Default | |
| --- | --- | --- |
| `PORT` | `8401` | |
| `BASE_URL` | `http://pg.localhost:$PORT` | Public URL, and it may have a path: the Lab runs it at `https://agentlab.choosemission.com/proving-ground`. Every page, door and link lives under it. The DID and the `/.well-known` documents (`did.jsonl`, `did.json`, `poppy.json`, `oauth-protected-resource`, the poppy issuer's metadata, `aauth-resource.json`, `aauth-person.json`) are the Lab's identity, so they are served at the origin, and the DID is the host's: `did:webvh:<scid>:agentlab.choosemission.com`. Must be a domain name (did:webvh refuses bare `localhost`; `*.localhost` resolves to this machine) |
| `DATA_DIR` | `./data` | SQLite database, the signing keys (the DID's, and the aauth door's resource and test PS keys) and the DID log (`did.jsonl`), made on first start. Keep it on a persistent volume: it *is* the DID. A new host needs an empty one, and gets a new DID |

**Dev switch.** When `BASE_URL` is `http://localhost`, `http://*.localhost` or `http://127.0.0.1`, doors accept `http` URLs
and loopback addresses from agents that the specs would refuse, such as a poppy agent's client
metadata on `http://localhost`, or an AAuth identifier with `http` and a port. Anywhere else they are refused.

## Deploy

The Agent Lab runs it at `https://agentlab.choosemission.com/proving-ground`, building this
repository's `Dockerfile` at a commit pinned in affinidi-lab's
`infra/agent-services/compose.yaml`. To release, push here, then bump that pin and deploy the Lab.
The image runs as `node` and keeps `DATA_DIR` at `/data`; that volume is the Lab's DID.

## For agents

`/llms.txt` gives an agent the Lab-specific steps in full: start a run, get
the handle credential, find its door URLs. For the protocol itself it points
to each door's pinned spec, because following the spec is what the door
tests. The homepage is rendered on the server, so an agent that fetches `/`
sees the doors without running JavaScript, and each door's `401` body links
to `/llms.txt` (and, on the anonymous URL, says how to start a run).

## Runs

A run is one handle, with a row on every door's wall.

```sh
curl -X POST pg.localhost:8401/pg/runs -H 'content-type: application/json' -d '{"handle":"relaybox"}'
# → {"handle": "relaybox", "run": "<run>", "doors": {"x401": "http://pg.localhost:8401/pg/doors/x401/r/<run>"}, ...}
```

Add `"client_id": "<Personal Agent client_id>"` to link a Poppy agent to the run: Poppy
requests carry no run ID, so the poppy door finds the run by the Session JWT's `iss`
(see [src/doors/poppy.md](src/doors/poppy.md#linking-an-agent-to-a-run)).

Point an agent at a door URL. Anyone can also call a door without a run at
`/pg/doors/<door>`; those attempts share that wall's anonymous row. The run
ID labels attempts and gets the run's handle credential; it is not shown on
the wall, and a leaked one means starting a new run.

## The handle credential

The Lab test issuer, shared by every door, attests the run's handle:

```sh
curl -X POST pg.localhost:8401/pg/issuer/credential -H 'content-type: application/json' \
  -d '{"jwk": <holder public JWK>, "run": "<run>"}'
# → {"format": "dc+sd-jwt", "credential": "<sd-jwt>", "issuer": "did:webvh:<scid>:<host>"}
```

An SD-JWT VC of vct `<BASE_URL>/pg/vct/handle`, bound to the holder key
(`cnf.jwk`), with one selectively disclosable claim, `handle`. The issuer
is the Lab's did:webvh (the same DID the doors verify as), signing with its
`#issuer` key; resolve it from `/.well-known/did.jsonl`. A door that asks for
it on a run's URL checks the disclosed handle is that run's.

## What is stored

For each attempt: the door, the run, the highest step, the request mode, the
stop code and reason, and a plain-words timeline. **Never stored:**
credentials, presentations, disclosed values or IP addresses. The wall shows
handles, never run IDs.

## Files

| | |
| --- | --- |
| [`src/doors/`](src/doors) | One door per protocol: its challenge, ladder of checks and receipt, and its docs. The aauth door is three files: the resource, its verifier (`aauth-sig.ts`) and the Lab test person server (`aauth-ps.ts`) |
| [`src/issuer.ts`](src/issuer.ts) | The Lab test issuer: the handle credential |
| [`src/store.ts`](src/store.ts) | Runs and attempts in SQLite (`node:sqlite`), and the change bus |
| [`src/lab.ts`](src/lab.ts) | Base URL, `did:webvh` (served at `/.well-known/did.jsonl`, with a parallel `did:web`), signing keys |
| [`src/server.ts`](src/server.ts) | Routes, the door registry, CORS, SSE |
| [`public/index.html`](public/index.html) | The homepage: every door, with its attempts and who got through first |
| [`public/door.html`](public/door.html) | A door's wall, at `/<door>`: runs, live feed, funnel, stop codes, attempt timelines |
| [`public/style.css`](public/style.css) | Shared styles |
| [`client.ts`](client.ts) | Reference agent and wallet for the x401 door |
| [`poppy-client.ts`](poppy-client.ts) | Reference Personal Agent for the poppy door |
| [`aauth-client.ts`](aauth-client.ts) | Reference agent for the aauth door, its own agent provider; signs with `@hellocoop/httpsig` (a dev dependency) |
| [`test/e2e.test.ts`](test/e2e.test.ts), [`test/poppy.test.ts`](test/poppy.test.ts), [`test/aauth.test.ts`](test/aauth.test.ts) | The real server, driven through every stop of each door |

## Adding a door

Add `src/doors/<name>.ts` exporting `INFO` (`door`, `spec`, `proves`,
`about`, `builds_on`, `ladder`; optionally `advice`, more lines for `/llms.txt`, and `try`, the wall's
"Try it" text), `THROUGH` (the index of the last step) and
`serve(request)`, which gets a `DoorRequest` ([`src/lab.ts`](src/lab.ts): the run, the
method, the path below the door's URL, the full URL, headers and body) and records attempts
with `store.newAttempt({door: '<name>', ...})`. A door that needs documents at fixed paths
exports `WELL_KNOWN` (path → document), as poppy and aauth do. Register it in `DOORS` (and
`WELL_KNOWN`) in [`src/server.ts`](src/server.ts) and document it next to the code.

## Not built yet

Each of these is left out on purpose, and each would take a small change.

- **Before going public:** rate limiting (Caddy `rate_limit`), marked
  `ponytail:` in the code, and each door's own items. Fetches to URLs a caller
  chose already refuse private addresses at connect time (`fetchPublic` in `src/lab.ts`). A retention period also
  needs deciding, along with the privacy check (decision 6 in the plan).
- **Lab integration:** Lab sign-in for runs, six-digit completion codes,
  and Slack "first through" notices.
- **Issuance:** OpenID4VCI. The issuer is a plain POST for now.
- **Wall:** the per-door interop grid (declared software against route),
  *My attempts*, and the archived snapshot after each event.
