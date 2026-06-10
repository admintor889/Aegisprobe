# AegisProbe

> A model-led penetration testing agent.  
> The model decides what to do — the runtime provides tools, guardrails, and high-fidelity evidence.

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20.0-brightgreen.svg)](https://nodejs.org)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.x-3178c6.svg)](https://www.typescriptlang.org/)

---

## Philosophy

Most pentest "agents" are really scanner pipelines with an LLM wrapper — they predefine phases, order tools into queues, and use the model as a glorified parameter-filler.

AegisProbe takes the opposite approach:

```
user message → model → tool calls → raw results → model → ...
```

The **model** is the strategist. It chooses when to recon, when to research, when to craft a payload, and when to conclude. The **runtime** handles what it should: scope boundaries, shell policy, tool execution, context transport, and evidence persistence. There is no hardcoded phase schedule, no decision queue, no goal oracle, and no turn limit — the model decides when it is done.

This architecture was validated against [Codex](https://openai.com/index/unrolling-the-codex-agent-loop/) and [Claude Code](https://code.claude.com/docs/en/how-claude-code-works): both succeed because they give the model raw tool access with clean scaffolding, not because they script a workflow.

---

## Core Capabilities

### 16 Built-in Tools — Model-Chosen, Not Pipeline-Driven

| Tool | Description |
|------|-------------|
| `execute_shell` | Arbitrary shell commands with structured result envelopes |
| `read_file` / `write_file` | Workspace-scoped file I/O |
| `list_directory` | Directory enumeration |
| `artifact_read` | Byte-range reads of large tool results via SHA-256 artifacts |
| `http_request` | Raw HTTP with approval gates for non-GET methods |
| `security_probe` | DNS, HTTP headers, basic recon probes |
| `web_recon` | Headful browser recon (Playwright) with HAR/network capture |
| `fingerprint` | Technology fingerprinting (Wappalyzer-compatible) |
| `cve_lookup` | Local CVE knowledge base matching with exploit references |
| `payload_candidates` | Evidence-grounded payload generation (no execution) |
| `payload_request_drafts` | HTTP request drafts with baseline/probe variants |
| `graph_query` | Read-only security graph memory (never proposes actions) |
| `web_search` | Public web search (DuckDuckGo) |
| `web_fetch` | Public URL fetch with private-network isolation |
| `fofa_search` | FOFA network-space search engine queries |

### Durable Research Loop

- **Web research**: `web_search` + `web_fetch` let the model independently research CVEs, exploits, and technologies. No automated CVE→exploit trigger — the model decides what to look up and what to act on.
- **CVE knowledge base**: Local fingerprints (nuclei templates + Wappalyzer signatures) matched against observed technologies with version-range-aware scoring.
- **Payload workbench**: Candidates are generated from evidence, insertion points, auth context, and technology — but never automatically executed. Request drafts pair each probe with a baseline for differential comparison.

### Context Management (No Lost Evidence)

- **Tool result envelopes**: Every tool result is a structured JSON envelope with `stdout`, `stderr`, `exitCode`, `timing`, `truncated` flags, and byte counts. The exact envelope is persisted as a SHA-256-addressed artifact.
- **Bounded active context**: The newest N tool results stay inline; older results collapse to artifact references. The model can read exact byte ranges via `artifact_read`.
- **Compaction**: Long conversations are summarized by a separate fast-model call. The split always aligns on clean API boundaries — never between a `tool_call` and its `tool_result`.
- **Provider reasoning state**: DeepSeek V4 `reasoning_content` is preserved and replayed across tool rounds. It is transport state, not displayed text.

### Cost-Optimized Model Routing

| Operation | Model | Max Tokens |
|-----------|-------|-----------|
| Main reasoning (penetration decisions) | `deepseek-v4-pro` | 16,000 |
| Compaction / summarization | `deepseek-v4-flash` | 3,000 |

No code changes needed — the provider switches models automatically based on the `fast: true` parameter.

### Policy: Maximum Freedom, Minimum Danger

The shell policy follows a simple principle: **validate targets, not operators**.

| Category | Policy |
|----------|--------|
| `rm -rf /`, `format C:`, `shutdown`, `reg delete`, `--dangerously-bypass` | **Blocked always** |
| `Invoke-Expression` / `iex` | Allowed with explicit approval (exploit PoCs need it) |
| Security tools (`nuclei`, `nmap`, `sqlmap`, `hydra`, etc.) | Allowed with normal approval (no pre-judgment) |
| Shell redirects (`>`, `>>`) | Path validation — workspace: allowed; external: blocked |
| File operations (`Rename-Item`, `Move-Item`, `Copy-Item`) | Path validation — workspace: allowed; external: blocked |
| All other shell commands | Allowed with human approval |

The policy does not block legitimate pentest actions just because they share syntax with dangerous operations.

---

## Quick Start

### Prerequisites

- Node.js ≥ 20
- pnpm ≥ 9
- A DeepSeek API key ([platform.deepseek.com](https://platform.deepseek.com))
- PowerShell (Windows) or bash (Linux/macOS)

### Setup

```bash
git clone https://github.com/admintor889/Aegisprobe.git
cd Aegisprobe

# Install dependencies and build all packages
pnpm install
pnpm build

# Install Playwright browser for web_recon
pnpm exec playwright install chromium
```

### Configure

Create `.env` in the project root:

```env
DEEPSEEK_API_KEY=sk-...
# Optional
FOFA_KEY=your-fofa-key
```

The default config (`configs/config.yaml`) uses `deepseek-v4-pro` for main reasoning and `deepseek-v4-flash` for compaction. Edit the model names if using different providers.

### First Run

```bash
# Authorized security assessment of a target
node apps/cli/dist/index.js pentest https://your-target.example --yes

# Interactive chat mode with full tools
node apps/cli/dist/index.js chat
```

In chat mode, type `/help` to see available commands. Use `/pentest <url>` to start a new assessment, `/clear` to reset context, and `/exit` to quit.

---

## Architecture

```
apps/cli/              CLI entrypoint (Commander.js)
packages/
  core/                AgentThread, tool registry, conversation loop, compaction, approvals
  provider/            OpenAI-compatible streaming client (DeepSeek-focused)
  security/            Recon models, payload workbench, CVE matching, fingerprinting
  policy/              Shell command safety evaluation
  storage/             SQLite audit store (conversations, evidence, CVE matches)
  context/             Semantic evidence indexing (BM25 + recency/severity boosts)
  shared/              Types, path validation, target parsing
  skills/              Prompt-pack skill loader
  mcp/                 MCP server integration
  shell/               Shell execution primitives
  tools/               Tool inventory and capability introspection
  server/              Web UI event bridge server
configs/
  config.yaml          Provider, agent, storage, FOFA, web-research, MCP config
  prompt-packs/
    pentest-expert/    External prompt pack (system prompt, tool semantics, methodology)
scripts/
  agent-lab-smoke.mjs  Lab smoke harness for regression testing
  lab-proof-evaluator.mjs  Isolated proof evaluator (cannot write to agent session)
docs/                  Architecture, research notes, smoke harness documentation
```

### Runtime Flow

```
CLI → MainAgent.runConversationTurn()
    → AgentThread.run()
        → compaction (if needed, via deepseek-v4-flash)
        → load conversation history from SQLite
        → agent-thread-tools.buildAgentThreadTools()
        → conversation-loop.runConversationTurn()
            → boundActiveToolContext (collapse old results)
            → provider.streamComplete(messages, tools, fast: false)
            → model emits text and/or tool calls
            → execute tool → structured envelope → artifact store
            → persist message to SQLite
            → feed result back into conversation
            → repeat until model produces text without tool calls
        → yield events to CLI for display
```

---

## Interactive Commands

All available in `/chat` mode:

| Command | Description |
|---------|-------------|
| `/pentest <url>` | Start authorized assessment of a target |
| `/shell <command>` | Execute a shell command |
| `/probe <target> [type]` | Run DNS / HTTP-header / recon probe |
| `/clear` | Reset conversation history |
| `/tools` | Show available tool inventory |
| `/tools --check` | Show tool availability status |
| `/runs` | Show security tool run ledger |
| `/agents` | Show active sub-agents |
| `/exit` | End session |

And standalone CLI commands:

```bash
# Session inspection
node apps/cli/dist/index.js runs <session-id>
node apps/cli/dist/index.js evidence <session-id>
node apps/cli/dist/index.js hypotheses <session-id>
node apps/cli/dist/index.js graph-state <session-id>
node apps/cli/dist/index.js expert-snapshot <session-id>
node apps/cli/dist/index.js access-map <session-id>

# Payload workbench
node apps/cli/dist/index.js payload-candidates <session-id> --focus authz
node apps/cli/dist/index.js payload-drafts <session-id> --focus sql_injection

# Web discovery
node apps/cli/dist/index.js webapp-recon <session-id> https://target --max-pages 10
node apps/cli/dist/index.js api-description-import <session-id> https://target/openapi.json
```

---

## Lab Testing

### Local Multi-Role App (BOLA / BFLA / Mass Assignment)

```bash
pnpm lab:smoke:local-multirole
```

Starts a local Express app with intentional authorization flaws, then runs the agent against it with an isolated proof evaluator. The evaluator verifies findings without writing into the agent's session.

### Vulhub Targets

```bash
pnpm lab:vulhub:s2-045           # Struts2 S2-045
pnpm lab:vulhub:flask-ssti       # Flask SSTI
pnpm lab:vulhub:spring-22978     # Spring CVE-2022-22978
pnpm lab:vulhub:apisix-45232     # APISIX CVE-2021-45232
pnpm lab:vulhub:matrix           # Run full matrix
```

### Verified Against

| Target | Result |
|--------|--------|
| ActiveMQ CVE-2026-34197 | ✅ Root RCE achieved via Jolokia → XML config injection |
| Juice Shop | ✅ Recon, fingerprinting, payload workbench |
| DVWA | ✅ SQL injection and XSS payload candidates generated |
| WebGoat | ✅ Registration surface identified |

---

## Verification

```bash
pnpm --filter @aegisprobe/security test    # 90 tests
pnpm --filter @aegisprobe/policy test      # 14 tests
pnpm --filter @aegisprobe/core test        # 42 tests (1 fixture-only skip)
pnpm --filter @aegisprobe/provider test    # Reasoning-state streaming
pnpm build                                  # 13 packages, all passing
```

---

## Configuration

All prompt behavior is externalized to `configs/prompt-packs/pentest-expert/`:

```
system.md              System prompt (role, boundaries, methodology reference)
tool-semantics.json    Tool descriptions (what the model sees)
tool-use.md            Detailed tool usage guidance
methodology-reference.md  PTES / NIST SP 800-115 / OWASP WSTG reference
payload-capabilities.md   Payload generation categories and guardrails
conversation/          Compaction prompt, interactive system prompt
subagents/             Sub-agent role definitions
```

Override the pack path with `AEGISPROBE_PROMPT_PACK`:

```bash
export AEGISPROBE_PROMPT_PACK=/path/to/custom-pack
```

---

## Design Decisions

### No Turn Limits
The model decides when a task is complete. There is no `maxToolRounds`, `maxTurns`, or iteration cap — the `while(true)` loop exits naturally when the model produces text without further tool calls. Context compaction and token budgets provide organic back-pressure.

### No Pipeline, No Queue, No Oracle
Goals, phases, decision queues, and proof functions have been removed from the default code path. The agent was previously split between a "model-led" conversation loop and a parallel pipeline that pre-scheduled scans, injected CVE exploits, scored coverage, and selected next actions. All of that is gone. The model sees evidence and tools — nothing more.

### Isolated Proof Evaluation
`scripts/lab-proof-evaluator.mjs` runs as a separate process. It receives the target and the agent's final state, independently verifies whether exploitation succeeded, and reports. It cannot inject findings, evidence, or commands into the agent session.

### Prompt Packs, Not Hardcoded Prompts
No pentest methodology, exploit checklist, or security jargon is hardcoded in TypeScript. System prompts and tool semantics live in markdown and JSON files under `configs/prompt-packs/`. The runtime loads and renders them via template substitution.

---

## Research Foundation

The architecture was informed by:

- [PentestGPT (USENIX Security 2024)](https://www.usenix.org/conference/usenixsecurity24/presentation/deng) — Pentesting Task Trees, context management, sub-task decomposition
- [Cairn](https://github.com/oritera/Cairn) — Fact/Intent/Hint shared state, OODA loop, multi-worker parallelism
- [PentAGI](https://github.com/vxcontrol/pentagi) — Complete execution environment, memory layer, observability
- [AutoPenBench](https://www.emergentmind.com/papers/2410.03225) — Full-auto vs assisted agent success rates
- [Classical Planning + LLM Agents](https://arxiv.org/abs/2512.11143) — PDDL behavior models for agent planning
- [AWE](https://arxiv.org/abs/2603.00960), [HPTSA](https://arxiv.org/abs/2603.13164), [CHAP](https://arxiv.org/abs/2604.12094) — Web pentest specialization, supervisor/subagent hierarchies
- [OpenAI Codex agent loop](https://openai.com/index/unrolling-the-codex-agent-loop/) — Turn-based tool loop without workflow scripting
- [Claude Code](https://code.claude.com/docs/en/how-claude-code-works) — Permission system design, context editing, sub-agent tools

Detailed research notes: [docs/pentest-agent-research-notes.md](docs/pentest-agent-research-notes.md)

---

## License

MIT — see [LICENSE](LICENSE).

> **⚠️ Usage Notice**: AegisProbe is intended for authorized security testing of systems you own or have explicit written permission to test. Unauthorized scanning or exploitation of systems is illegal in most jurisdictions. The authors assume no liability for misuse.
