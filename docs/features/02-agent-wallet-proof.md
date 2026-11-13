# 02 An agent earns the credential and uses it, with the credentials wallet
Goal: show that an AI agent can run OpenID4VCI itself, holding its key in the credentials wallet MCP (`credentials-wallet-mcp`), then present the credential at the x401 door, without a private key or disclosure being written by the agent. It's the wallet's "first milestone after v1" (approach A: the agent runs the protocol, the wallet signs and stores), narrowed to SD-JWT VC (D-004).
Done = a fresh Claude Code session, given only a run's credential offer and door URL (plus a skill only if task 2 showed one is needed), ends with the handle credential stored in the wallet with `verified: true` and an x401 `through` receipt that verifies against `/pg/jwks.json`, all on the deployed Lab.
Feature test: the task 2 and task 4 runs on `https://agentlab.choosemission.com/proving-ground`. Evidence: the session transcript (tool calls only), the receipt JWT verified with `jose`, the run's row on the x401 wall at `through`, and `wallet-admin audit tail` showing one `create_key_proof` and one `create_presentation`.
Out of scope: verifying the x401 JAR in the wallet (D-006), approach B (a protocol MCP server), vcdm2, any wallet code change.
Decisions: D-003, D-005, D-006. Wallet: D36 (key proof shape), D51/D52 (public did:webvh hosts only).
Depends on: 01 deployed (its task 9).

## Tasks
- [ ] 1. Wallet binary carries F8
      Criteria: `credentials-wallet-mcp/scripts/build-signed.sh` is run and Claude Code restarted. `resolve_did` on the Lab DID `did:webvh:QmXkpUHLentyt7M8djmZqj55RpdwDF4cM4VQCcXvPKx3WY:agentlab.choosemission.com` returns the document with `#issuer`. Today's registered binary refuses did:webvh.
      Test: `resolve_did` through MCP, which prints the document. The user approves keychain prompts if asked.
- [ ] 2. The run, on the Lab, with no skill
      Criteria: a fresh Claude Code session has the wallet MCP and nothing else: no skill and no hints beyond the prompt.
      1. Create a wallet identity (`create_identity`, Ed25519).
      2. Start a run on the Lab with a throwaway handle.
      3. Give the agent one prompt: "Here is a credential offer and an x401 door URL. Get the credential into your wallet and get through the door." Include the run's `credential_offer` and door URL.

      The agent may read `/llms.txt` and the specs. Expected path:
      1. metadata → `/token` → `/nonce`;
      2. `create_key_proof` (`openid4vci`, `audience` = `credential_issuer`, `nonce` = `c_nonce`) → `/credential` → `store_credential` (`verified: true`, `issuer` = the Lab DID);
      3. door → `query_credentials` with the unsigned request's `dcql_query` (D-006) → `create_presentation` (`nonce`, `audience` = `origin:<origin>`) → `PROOF-RESPONSE` → through.

      Record, for each step, pass or fail and, where it went wrong, what the agent misunderstood.
      Test: the evidence listed under Feature test, in `credentials-wallet-mcp/PROGRESS.md` (milestone entry). If a failure is the proving ground's fault (a wrong error, missing `/llms.txt` text), fix it there as a task in 01. If it's the wallet's fault, record the gap.
- [ ] 3. A skill, only if task 2 needed one
      Criteria: if task 2 got through unaided, skip this task and say so in the log. Otherwise, write `credentials-wallet-mcp/skills/oid4vci-holder/SKILL.md` covering only the steps the agent got wrong, plus one rule: the access token is a bearer token, so don't echo it.
      Test: rerun task 2 with the skill. It gets through.
- [ ] 4. P-256 holder
      Criteria: task 2 again with a P-256 identity, plus the skill if task 3 wrote one.
      Test: the same evidence. `cnf.jwk` is EC P-256 and the KB-JWT is ES256.
- [ ] 5. Write it up
      Criteria: proving-ground README "For agents" names the wallet as one reference holder, and says whether an agent needed a skill. The wallet's PLAN.md milestone is updated (SD-JWT VC only, the Lab's proving-ground issuer), with a wallet D# recording why.
      Test: the links resolve, and `git diff` shows the wallet D# referencing this spec.

## Later
- Signed x401 requests: needs JAR verification, in the wallet or a protocol layer (wallet PLAN.md x401 roadmap).
- Approach B: an OpenID4VCI protocol MCP server on the wallet's `core`, so the credential never passes through the agent's context.
- The Lab's own issuer for credentials about the link between an agent and a Lab member (delegation credential, `affinidi-lab/docs/x401-in-the-lab.md`). Parked 2026-11-13.
