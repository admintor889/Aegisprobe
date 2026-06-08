# AegisProbe — Setup Guide

AI-driven autonomous penetration testing agent. Evidence-first, model-autonomous, no hardcoded pipelines.

## Prerequisites

| Requirement | Minimum Version | Check |
|---|---|---|
| Node.js | >= 22.14.0 | `node --version` |
| pnpm | >= 10.0.0 | `pnpm --version` |
| Docker (optional) | Latest | For vulhub targets |
| Python 3 (optional) | >= 3.8 | For `exploit_sender.py` |

## Quick Start (3 steps)

### 1. Install dependencies

```bash
pnpm install
```

### 2. Set your DeepSeek API key

Copy the env template and edit:

```bash
cp .env.example .env
# Edit .env and add your provider key from the template.
```

### 3. Build and start

```bash
pnpm build        # TypeScript → JavaScript
pnpm webui        # Start Web UI on http://127.0.0.1:3000 (Windows)
                   # Or: bash start.sh (Linux/macOS)
```

Or use the launcher scripts:

```bash
# Windows
start.cmd

# Linux / macOS
bash start.sh
```

## Configuration

All settings in `configs/config.yaml`. See `configs/config.yaml.example` for full reference.

Key settings:

| Setting | Default | Description |
|---|---|---|
| `provider.model` | `deepseek-v4-pro` | Primary model |
| `agent.shell` | `auto` | Shell mode — auto-detect from platform |
| `storage.sqlitePath` | `./data/aegisprobe.sqlite` | Database location |
| `agent.requireShellApproval` | `true` | Prompt before each shell command |

## CLI Usage

```bash
# Start a pentest session (interactive)
node apps/cli/dist/index.js pentest http://target:8080 --active --yes

# Show available tools
node apps/cli/dist/index.js tools

# Start Web UI
node apps/cli/dist/index.js webui --port 3000

# Resume a session
node apps/cli/dist/index.js pentest <session-id> --resume
```

## Running with Vulhub Targets (optional)

Requires Docker:

```bash
# Start a target
docker compose -f labs/targets/vulhub/struts2/s2-045/docker-compose.yml up -d

# Run pentest against it
node apps/cli/dist/index.js pentest http://127.0.0.1:8080 --active --yes --max-turns 25

# Stop the target
docker compose -f labs/targets/vulhub/struts2/s2-045/docker-compose.yml down
```

## Project Structure

```
agent-pentest-assistant/
├── apps/cli/               # CLI entry point
├── apps/webui/             # Web UI (HTML/CSS/JS)
├── packages/
│   ├── core/               # Agent runtime, pentest loop, browser recon
│   ├── security/           # Decision models, exploit engine, CVE chain
│   ├── shared/             # Shared types
│   ├── storage/            # SQLite audit store
│   ├── context/            # BM25 context manager
│   ├── provider/           # LLM provider (DeepSeek)
│   ├── shell/              # Cross-platform shell runner
│   ├── mcp/                # MCP protocol client
│   ├── server/             # Express + WebSocket server
│   ├── skills/             # Skill registry
│   ├── tools/              # Tool parsing
│   └── policy/             # Authorization policy
├── configs/                # Configuration files
├── data/                   # Runtime data (SQLite, CVE knowledge base)
├── labs/targets/           # Vulnerable lab targets (Docker)
├── scripts/                # Smoke tests and batch runners
├── tools/                  # External tools, start scripts
└── skills/                 # Agent skills
```

## Troubleshooting

### `node: not found` or `pnpm: not found`
Install Node.js >= 22.14.0 from https://nodejs.org, then `npm install -g pnpm`.

### `DEEPSEEK_API_KEY not set`
Copy `.env.example` → `.env` and add your API key from https://platform.deepseek.com.

### Build errors
```bash
pnpm clean    # if available
pnpm install
pnpm build
```

### Shell commands fail on Windows
Ensure `agent.shell` is set to `auto` or `powershell` in `configs/config.yaml`.
You can also set `AEGISPROBE_SHELL=powershell` environment variable.

### Web UI doesn't connect
Make sure the WebSocket server started on port 3000. Check firewall settings.
