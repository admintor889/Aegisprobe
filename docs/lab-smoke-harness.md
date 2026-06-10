# Agent Lab Smoke Harness

The lab harness tests the real persistent `AgentThread`, not a scripted pentest workflow.

## Isolation

The harness has two processes:

1. `scripts/agent-lab-smoke.mjs` loads public case metadata, sends only the target URL to AegisProbe, and records the resulting conversation and tool envelopes.
2. `scripts/lab-proof-evaluator.mjs` independently loads the known proof configuration and checks the target after the agent turn.

The evaluator has no SQLite store handle and cannot write evidence, findings, or messages into the agent session. A passing evaluator proves only that the lab is exploitable; the report separately records what the agent actually did.

## Usage

Build packages and configure the model API key first:

```powershell
pnpm build
pnpm lab:smoke:s2-045
pnpm lab:smoke:s2-045:proof
pnpm lab:smoke:local-multirole
```

Useful options:

```text
--case <id>
--target <url>
--max-tool-rounds <n>
--active-proof
--start-target
--allow-fail
```

Reports are written under `data/lab-smoke/`. They include assistant messages, tool names and execution status, raw-output byte counts, artifacts, evaluator observations, and whether proof data was loaded by the agent process.

`--active-proof` is for isolated local labs only. Proof cases must remain bounded and non-destructive.
