# AegisProbe

AegisProbe is a model-led penetration testing assistant for authorized targets.

The project is built around a simple principle: the model should remain the strategist. The runtime supplies scope controls, high-quality evidence, tool access, memory, and guardrails, but it should not force the model through a hardcoded scanner pipeline or rigid role choreography.

## What Changed

AegisProbe now focuses on the gaps that make many pentest agents feel shallow:

- Preserves raw observations and failed-command memory instead of hiding the real tool output.
- Loads pentest behavior from an external prompt pack instead of burying hardcoded prompts in runtime code.
- Gives the model a read-only expert workbench snapshot with surface facts, auth state, access exposure, payload affordances, request drafts, findings, and raw evidence snippets.
- Extracts HTML title/forms/scripts/links from safe GET observations so login forms and insertion points are visible without ad-hoc shell parsing.
- Separates anonymous baselines, authenticated baselines, and cross-role comparisons for unauthorized access, BOLA, BFLA, IDOR, and tenant-isolation testing.
- Generates payload candidates and reviewable HTTP request drafts without sending probes automatically.
- Blocks repeated low-signal actions such as shell-grepping static JavaScript or multiline `python -c` HAR parsing after structured evidence already exists.
- Provides a Codex-inspired terminal surface with compact status/event rendering while keeping AegisProbe's own security-workbench style.
- Uses local lab smoke tests to measure speed and capability instead of relying on demos.

## Safety Model

AegisProbe is intended for systems you own or have explicit permission to test.

- Read-only observations are preferred for initial discovery.
- Anonymous and authenticated GET/HEAD baselines are safe evidence-gathering actions.
- State-changing routes stay passive until active authorization, test-data boundaries, and rollback expectations are explicit.
- Payload candidates and request drafts are advisory workbench material. They do not execute by themselves.
- Active scanners and exploit proofs remain scope/approval gated.

## Core Concepts

### Model-Led Runtime

The runtime gives the model facts and affordances, not a fixed task list. The model can choose `webapp_recon`, `expert_snapshot`, `access_exposure_map`, `anonymous_baseline_fetch`, `safe_readonly_fetch`, `payload_candidates`, `payload_request_drafts`, shell commands, or a final answer based on evidence.

Runtime guardrails reject known low-value loops rather than prescribing a task order. For example, after `webapp_recon` or JS analysis has recorded structured evidence, static vendor JS text extraction is blocked. PowerShell multiline `python -c` parsing of browser artifacts is also blocked because it reliably corrupts quoting and wastes turns.

### Expert Snapshot

`expert_snapshot` renders the current pentest workbench from stored evidence:

- latest raw evidence snippets
- endpoint and API surface
- auth contexts and validation attempts
- access exposure summary
- anonymous/authenticated baseline state
- payload candidates and request drafts
- failed attempts and blocked tools
- open hypotheses and findings

```powershell
node apps/cli/dist/index.js expert-snapshot <session-id>
```

### Access Exposure Map

`access_exposure_map` summarizes where the model still needs anonymous baselines, where auth gates are observed, where role comparison is ready, and which mutation routes must remain passive.

High-fidelity fetch JSON is folded into the map, so the model can see evidence like:

- anonymous `GET /api/admin/users` -> `200`, body hash `abc...`
- alice `GET /api/admin/users` -> `200`, same or different body hash
- bob `GET /api/orders/102` -> `200`, cross-tenant object read

```powershell
node apps/cli/dist/index.js access-map <session-id>
node apps/cli/dist/index.js anonymous-fetch <session-id> https://target/api/admin/users --method GET
node apps/cli/dist/index.js safe-fetch <session-id> https://target/api/admin/users alice --method GET
node apps/cli/dist/index.js anonymous-fetch <session-id> https://target/admin/ --method HEAD --timeout-ms 10000
```

### Payload Workbench

The payload layer generates candidates and request drafts from observed routes, parameters, body fields, technologies, and auth context. It does not hardcode a one-size-fits-all exploit chain.

CVE matches are treated as prioritized hypotheses and validation references. AegisProbe does not inject embedded CVE exploit commands into the model context; request-level probes should come from current evidence and the payload workbench.

```powershell
node apps/cli/dist/index.js payload-candidates <session-id> --focus authz
node apps/cli/dist/index.js payload-drafts <session-id> --focus mass_assignment
```

### Terminal UI

The CLI now renders a compact AegisProbe event stream:

- status markers for work started, approvals, completions, failures, and blocked actions
- shortened command/details lines instead of large bracketed event dumps
- a concise `aegis probe>` interactive prompt

The design was informed by the OpenAI Codex TUI architecture: persistent history, a bottom composer/status surface, and unified tool event rendering. The implementation is separate and project-specific.

## Quick Start

```powershell
pnpm install
pnpm build
pnpm exec playwright install chromium
```

Secrets are read from environment variables. `configs/config.yaml` references `DEEPSEEK_API_KEY` and `FOFA_KEY`; do not store live keys in repository files.

Run an authorized assessment:

```powershell
node apps/cli/dist/index.js pentest https://example.com --yes
```

Allow active scanners only when they are explicitly in scope:

```powershell
node apps/cli/dist/index.js pentest https://example.com --active --rate 2 --yes
```

## Useful Commands

```powershell
# Tool and knowledge checks
node apps/cli/dist/index.js tools --check
node apps/cli/dist/index.js knowledge stats
node apps/cli/dist/index.js knowledge search CVE-2021-44228

# Web/API discovery
node apps/cli/dist/index.js webapp-recon <session-id> https://target.example --max-pages 10
node apps/cli/dist/index.js api-description-import <session-id> https://target.example/openapi.json

# Business logic and authorization
node apps/cli/dist/index.js auth-context add <session-id> --name alice --base-url https://target.example --authorization "Bearer <token>"
node apps/cli/dist/index.js authz-matrix <session-id>
node apps/cli/dist/index.js authz-plan <session-id>
node apps/cli/dist/index.js business-plan <session-id>
node apps/cli/dist/index.js business-compare <session-id> next --left alice --right bob

# Model workbench
node apps/cli/dist/index.js expert-snapshot <session-id>
node apps/cli/dist/index.js access-map <session-id>
node apps/cli/dist/index.js payload-candidates <session-id>
node apps/cli/dist/index.js payload-drafts <session-id>
```

## Local Lab Regression

The fastest regression target is `labs/targets/local-multirole-app`, a local Express app with intentional authorization flaws:

- BOLA/IDOR on `GET /api/orders/:id`
- BFLA on `GET /api/admin/users`
- mass-assignment risk on `PATCH /api/users/:id`

Run the business-logic smoke test:

```powershell
pnpm lab:smoke:local-multirole
```

The current local run completes in roughly 4-5 seconds on this machine, including:

- browser/API recon
- endpoint normalization
- auth surface modeling
- expert snapshot generation
- two local JWT auth contexts
- read-only cross-role authorization proof

Reports are written under `data/lab-smoke/`.

Other lab targets in this workspace include OWASP Juice Shop, DVWA, and Vulhub cases. OWASP crAPI is the next recommended API/business-logic benchmark because it covers BOLA, BFLA, mass assignment, JWT issues, and excessive data exposure.

## Verification

```powershell
pnpm --filter @aegisprobe/security test
pnpm --filter @aegisprobe/security typecheck
pnpm --filter @aegisprobe/core test
pnpm --filter @aegisprobe/core typecheck
pnpm --filter @aegisprobe/security build
pnpm --filter @aegisprobe/core build
pnpm --filter @aegisprobe/cli typecheck
pnpm --filter @aegisprobe/cli build
pnpm lab:smoke:local-multirole
```

Latest verified counts:

- `@aegisprobe/security`: 85 tests passing
- `@aegisprobe/core`: 64 tests passing
- local multi-role smoke: passing, total runtime about 4.1 seconds

## Prompt Packs

Pentest system behavior is externalized under:

```text
configs/prompt-packs/pentest-expert/
```

Set a custom pack with:

```powershell
$env:AEGISPROBE_PROMPT_PACK="E:\path\to\prompt-pack"
```

Prompt packs are guidance, not hardcoded task decisions.

## Repository Layout

```text
apps/cli/                     CLI entrypoint
packages/core/                Agent runtime, pentest loop, tool dispatch, expert snapshot
packages/security/            Recon models, access exposure map, payload workbench, CVE/security logic
packages/shared/              Shared types and utilities
packages/storage/             SQLite audit store
configs/prompt-packs/         External prompt packs
scripts/                      Lab smoke harness and batch runners
labs/targets/                 Local vulnerable labs
docs/                         Research notes, smoke harness docs, handoff docs
```

## Research Notes

See [docs/pentest-agent-research-notes.md](docs/pentest-agent-research-notes.md) for the current design notes from PentestGPT, PentestEval, AutoPentester, OWASP Juice Shop, OWASP crAPI, and BOLA research.
