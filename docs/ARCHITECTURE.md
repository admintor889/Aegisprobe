# AegisProbe Architecture

## Main Runtime

AegisProbe has one default execution path:

```text
CLI user message
  -> MainAgent.runConversationTurn()
  -> AgentThread
  -> provider.streamComplete(messages, tools)
  -> model-selected tool calls
  -> raw tool result envelopes
  -> provider.streamComplete(...)
  -> assistant response
```

Bare URLs are ordinary user messages. There is no URL-specific pentest pipeline, phase scheduler, decision queue, goal oracle, or control plane in this path.

## AgentThread

`packages/core/src/agent-thread.ts` owns:

- durable conversation history
- user, assistant, tool-call, and tool-result ordering
- prompt-pack system context
- context compaction
- turn interruption and resource ceilings

`packages/core/src/conversation-loop.ts` owns only the model/tool loop. The model decides which registered tool to call and whether another call is useful.

Provider-specific reasoning state returned alongside a tool call is persisted separately from visible assistant text and replayed unchanged on later provider requests. It is transport state, not a system-generated plan.

## Tool Results

Each tool returns the same factual envelope:

```json
{
  "version": 1,
  "tool": "execute_shell",
  "status": "success",
  "startedAt": "...",
  "endedAt": "...",
  "durationMs": 42,
  "exitCode": 0,
  "stdout": "...",
  "stderr": "",
  "artifacts": [],
  "truncated": {
    "stdout": false,
    "stderr": false,
    "stdoutBytes": 120,
    "stderrBytes": 0
  }
}
```

Before an envelope enters the active model context, its exact JSON is stored under the session artifact directory with a SHA-256 hash. Small results remain inline. Large text receives a deterministic head/tail preview; large JSON receives a valid JSON preview wrapper. The model can read exact byte ranges with `artifact_read`.

Older tool previews may be collapsed to their artifact references when the active context exceeds its budget. Tool-call/result ordering and the immutable raw artifacts remain intact. The execution layer does not infer that a vulnerability is proven, generate corrective hints, or replace raw output with a heuristic conclusion.

## Security Capabilities

`packages/core/src/agent-thread-tools.ts` registers capabilities for:

- shell execution
- file reading and directory listing
- raw HTTP requests
- bounded security probes
- browser web reconnaissance and API inventory
- technology fingerprinting
- CVE lookup
- payload candidates and HTTP request drafts
- query-only graph memory
- public-web search and fetch
- exact artifact range reads
- FOFA search

Tool descriptions live in `configs/prompt-packs/pentest-expert/conversation/tool-semantics.json`.

## Boundaries

The model owns strategy. The runtime still owns non-negotiable boundaries:

- command policy and approval
- approval for non-read-only HTTP methods
- public-only DNS/IP validation for research fetches, including redirect revalidation
- user interruption
- exact output artifacts, active-preview accounting, and explicit truncation
- conversation persistence
- context budget compaction

These controls constrain execution authority, not pentest reasoning.

## Lab Evaluation

`scripts/agent-lab-smoke.mjs` runs the real AgentThread with the target URL as its only task message.

Known proof material is loaded only by `scripts/lab-proof-evaluator.mjs`, a separate process launched after the agent turn. The evaluator does not receive the SQLite store and cannot add evidence or findings to the agent session.
