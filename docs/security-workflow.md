# Security Workflow

AegisProbe now has a Pentagi-inspired security orchestration layer. It does not blindly execute scanner chains. It builds an auditable workflow, injects it into the main agent loop, and lets the model translate each step into approved subagent, shell, or file actions.

## Reference Model

Pentagi organizes work around flows, tasks, subtasks, agent roles, tool calls, memory, and result storage. AegisProbe maps that idea into a terminal-first architecture:

- Flow: `security_workflows`
- Subtask: `security_tasks`
- Agent roles: `recon`, `frontend`, `fingerprint`, `cve`, `web_vuln`, `reviewer`
- Tool boundary: AegisProbe policy and approval layer
- Memory/result storage: SQLite observations, findings, evidence, subagent outputs
- Skill guidance: loaded YAML and `SKILL.md` entries, compiled into phase guidance

## Default Phases

1. `scope`: confirm target, authorization, exclusions, intensity, time window.
2. `recon`: passive DNS, WHOIS, certificate, public sources, and subdomain planning.
3. `asset_discovery`: subdomain, HTTP service, related asset, and attack-surface discovery.
4. `fingerprint`: framework, server, version, WAF/CDN, and confidence analysis.
5. `frontend`: JavaScript assets, source maps, endpoints, hardcoded data, and routes.
6. `vulnerability_analysis`: CVE/advisory matching from confirmed evidence.
7. `safe_validation`: non-destructive OWASP and misconfiguration validation.
8. `reporting`: normalized findings, evidence, confidence, and remediation.

## Runtime Behavior

- A URL/domain security intent creates a workflow automatically.
- Workflow and phase tasks are saved to SQLite before execution.
- Relevant skills are selected per phase and injected into the decision prompt.
- The agent should prefer subagents for parallel analysis before requesting active commands.
- Active network probes still require explicit approval through the existing shell policy.
- The deterministic `pentest` pipeline runs the built-in baseline probe, launches frontend/CVE/OWASP subagents, records adapter availability, and executes only installed external tools that pass scope and approval checks.
- Findings, evidence, assets, technologies, and CVE-match tables are available for reporting and follow-up analysis.

## Tool Adapter Catalog

Local source references live under `third_party/security-tools/` and are intentionally git-ignored. The adapter catalog currently covers:

- `subfinder`: passive subdomain discovery.
- `amass`: passive attack-surface enumeration reference adapter.
- `dnsx`: DNS enrichment.
- `httpx`: HTTP probing and technology hints.
- `katana`: crawl frontend routes, JavaScript, forms, and API endpoints.
- `WhatWeb` and `Wappalyzer`: technology fingerprinting.
- `nuclei`: low-impact tech/exposure templates plus optional active validation.
- `dirsearch`: recursive directory brute-force with JSON output, requires explicit approval.
- `nmap`: port scanning and service/version detection, with C-segment work disabled unless scope allows it.

Active adapters are blocked unless `allowActiveProbing` is true; C-segment/CIDR adapters are also blocked unless `allowCidrDiscovery` is true.

## CLI

```powershell
node .\apps\cli\dist\index.js skill-plan frontend secret scan -n 3
node .\apps\cli\dist\index.js workflow <session-id>
node .\apps\cli\dist\index.js findings <session-id>
node .\apps\cli\dist\index.js pentest https://example.com
node .\apps\cli\dist\index.js pentest https://example.com --active --rate 1
```

## Current Boundary

This layer now has typed, policy-aware adapter commands and a first automatic pipeline. It still does not install scanner binaries, download nuclei templates, brute-force content, exploit vulnerabilities, or scan C-segments by default. Deeper output parsers and a local CVE database importer are the next hardening areas.
