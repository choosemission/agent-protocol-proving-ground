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
| `BASE_URL` | `http://pg.localhost:$PORT` | Public URL. Sets the verifier's `did:webvh`, the issuer ID and every link. Must be a domain name (did:webvh refuses bare `localhost`; `*.localhost` resolves to this machine) |
| `DATA_DIR` | `./data` | SQLite database, the signing keys and the DID log (`did.jsonl`), made on first start. Keep it on a persistent volume: it *is* the DID. A new host needs an empty one, and gets a new DID |

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
| [`src/doors/`](src/doors) | One door per protocol: its challenge, ladder of checks and receipt, and its docs |
| [`src/issuer.ts`](src/issuer.ts) | The Lab test issuer: the handle credential |
| [`src/store.ts`](src/store.ts) | Runs and attempts in SQLite (`node:sqlite`), and the change bus |
| [`src/lab.ts`](src/lab.ts) | Base URL, `did:webvh` (served at `/.well-known/did.jsonl`, with a parallel `did:web`), signing keys |
| [`src/server.ts`](src/server.ts) | Routes, the door registry, CORS, SSE |
| [`public/index.html`](public/index.html) | The homepage: every door, with its attempts and who got through first |
| [`public/door.html`](public/door.html) | A door's wall, at `/<door>`: runs, live feed, funnel, stop codes, attempt timelines |
| [`public/style.css`](public/style.css) | Shared styles |
| [`client.ts`](client.ts) | Reference agent and wallet for the x401 door |
| [`test/e2e.test.ts`](test/e2e.test.ts) | The real server, driven through every stop |

## Adding a door

Add `src/doors/<name>.ts` exporting `INFO` (`door`, `spec`, `proves`,
`about`, `ladder`), `THROUGH` (the index of the last step) and
`serve(runId, route, method, headers)`, which records attempts with
`store.newAttempt({door: '<name>', ...})`. Register it in `DOORS` in
[`src/server.ts`](src/server.ts) and document it next to the code.

## Not built yet

Each of these is left out on purpose, and each would take a small change.

- **Before going public:** rate limiting (Caddy `rate_limit`), marked
  `ponytail:` in the code, and each door's own items. A retention period also
  needs deciding, along with the privacy check (decision 6 in the plan).
- **Lab integration:** Lab sign-in for runs, six-digit completion codes,
  Slack "first through" notices, and the move to `servers/proving-ground`.
- **Issuance:** OpenID4VCI. The issuer is a plain POST for now.
- **Wall:** the per-door interop grid (declared software against route),
  *My attempts*, and the archived snapshot after each event.
