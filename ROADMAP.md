# AegisProbe Development Roadmap

## Current Development Focus (v3.2 - Mature WebApp Recon)

The next development line moves the agent away from CVE-first behavior and toward evidence-backed web application assessment. The first shipped increment is `webapp-recon`, aligned with OWASP WSTG entry-point identification, Burp/ZAP crawler behavior, Katana-style JavaScript endpoint discovery, and Playwright runtime network observation.

What `webapp-recon` collects:

- Same-origin pages, links, forms, script assets, and page summaries.
- Runtime network requests, including `fetch`/XHR method, URL, status, and content type where available.
- JavaScript endpoint candidates, source-map hints, internal-host/debug signals, and redacted secret-like strings.
- API inventory merged from forms, links/resources, JavaScript source, and runtime traffic.
- Authentication surface model: login pages, auth endpoints, password forms, auth-related storage keys, and review notes.

Immediate v3.2 follow-ups:

- Feed the API inventory into authorization and business-logic test planning.
- Add request/response clustering so repeated runtime traffic becomes normalized API shapes, not raw URL lists.
- Add authenticated context comparison using two Playwright storage states for BOLA/IDOR and function-level authorization checks.
- Add passive source-map retrieval and safe frontend secret false-positive triage.
- Render WebApp recon artifacts in the right-hand Web UI execution flow.

## Current Status (v3.1 — Intelligent Termination + Web UI)

AegisProbe is an AI-driven autonomous penetration testing agent following PTES + OWASP WSTG methodology. v3.1 adds **intelligent termination model** (goal satisfaction + deadlock detection aligned with Cairn/PentestGPT), **structured tool results** (Claude Code-style JSON), **Web UI dashboard** (three-panel reactive frontend), and **context state anchoring** to prevent fragmentation across long-running assessments.

### What We Have ✅

| Capability | Status | Notes |
|-----------|--------|-------|
| **Web UI Dashboard** | ✅ v3.1 | Three-panel reactive frontend (files/history, chat, agent flow). Express + WebSocket server. Live event bridging via `--webui` flag. |
| **Intelligent Termination Model** | ✅ v3.1 | Goal satisfaction + deadlock detection + safety-net ceiling. Aligned with Cairn's Reason→Complete and PentestGPT's PTT exhaustion model. |
| **Structured Tool Results** | ✅ v3.1 | Claude Code-style JSON tool results with status/error/hint fields. Prevents syntax-error retry loops. Applied to shell, security_probe, and MCP tools. |
| **Context State Anchoring** | ✅ v3.1 | Per-turn structured "what we know" summary prevents context fragmentation across long-running assessments. Last 3 observations only. |
| **MCP Browser Integration** | ✅ v3.1 | Playwright MCP browser tools available for SPA login flows. Model prompted to use browser for React/Angular/Vue SPAs instead of curl+regex. |
| **SNMP/Common-Service Discovery** | ✅ v3.1 | Prompt nudges model to check UDP services (SNMP 161) and common TCP ports when HTTP yields little. |
| **Exploit Methodology (8 types)** | ✅ v3.0 | Type-based: http_request_smuggling, deserialization, file_upload_to_rce, command_injection, sqli, path_traversal, ssrf, auth_bypass |
| **Generic Exploit Runner** | ✅ v3.0 | Single `exploit_sender.py` supports all types, Docker/WSL Java payload generation, Runtime.exec-compatible |
| **TypeScript Loader** | ✅ v3.0 | Auto-framework detection, fingerprint matching, LLM prompt injection via pentest-runtime.ts |
| **Attack Chain Rule Engine** | ✅ v2.2 | 50+ structured chains, 5 condition types, OR/AND logic, MITRE ATT&CK mapping, 0-100 confidence scoring |
| **Graph Model (Evidence/Hypothesis/Override)** | ✅ | Cairn-inspired Blackboard Architecture — 25+ types, YAML, snapshot/checkpoint |
| **Stigmergy Subagent Coordination** | ✅ | Graph-driven dispatch, 9→4 simplified roles, no direct agent communication |
| **Goal Satisfaction Model** | ✅ v2.2 | PTT task tree + 7-dim coverage scoring + Reason complete/continue decision |
| **Multi-layer Exploit Engine** | ✅ v2.2 | ExploitManager + 6 adapters (Metasploit RPC, msfconsole, sqlmap, nuclei exploit, searchsploit, custom scripts) |
| **CVE Chain Automation** | ✅ v2.2 | Fingerprint → CVE match → CVSS+EPSS+KEV scoring → payload generation → exploit dispatch |
| **CPE 2.3 Semantic Matcher** | ✅ v2.2 | NIST IR 7695: 11-field URI parse, 60+ aliases, 4-level confidence, semver range + OWASP DC evidence weighting |
| **OWASP Validation Pipeline** | ✅ v2.2 | 10 categories × nuclei real tags + curl/http checks + browser checks + ZAP-style job pipeline |
| **EPSS + KEV Integration** | ✅ v2.1 | FIRST.org EPSS API + CISA KEV JSON cache + 3D priority scoring |
| **Pentest Workflow Enhancement** | ✅ v2.2 | 15 device profiles + default creds, JS deep analysis, WAF-aware rate controller |
| **Self-Learning Feedback** | ✅ v2.1 | AttackPathRecord JSON serialization + BM25 cross-session retrieval |
| **Tool Auto-Discovery** | ✅ v2.1 | PATH + tools/bin scanning for 36 security tools with install hints |
| CVSS 3.1 Calculator | ✅ | Vector parsing, base/temporal scoring |
| Wappalyzer Fingerprinting | ✅ | ~3,500 technology profiles, real-time |
| Semantic Version Matching | ✅ | `>=`, `<`, `~>`, `^` range support |
| 25-Tool Chain + auto-discovery | ✅ | reconFTW-inspired adapters, versionArgsFor complete |
| NVD API Client | ✅ | Online CVE lookup + offline CVSS library |
| FOFA Integration | ✅ | Passive information gathering |
| MCP Browser | ✅ | Playwright 23 tools |
| SQLite Audit Trail | ✅ | 25+ tables, full traceability |
| Unit Tests (65 → security) | ✅ v2.2 | cvss(9), semver(12), cpe-matcher(7+4), graph(8), plus 25 existing = 65 |

### Recently Completed (v3.1)

| Item | Effort | Date |
|------|--------|------|
| Web UI Dashboard (three-panel + Express/WS server) | 1 day | 2025-06 |
| Intelligent Termination (goal model + deadlock) | 0.5 day | 2025-06 |
| Structured Tool Results (Claude Code-style JSON) | 0.5 day | 2025-06 |
| Context State Anchoring (Cairn-style graph summary) | 0.5 day | 2025-06 |
| MCP Browser for SPA / SNMP Discovery prompts | 0.5 day | 2025-06 |

### Recently Completed (v2.2)

| Item | Effort | Date |
|------|--------|------|
| Multi-layer Exploit Engine (6 adapters) | 1 day | 2025-07 |
| CVE Chain (fingerprint→CVE→payload) | 0.5 day | 2025-07 |
| OWASP Automated Validation Pipeline | 0.5 day | 2025-07 |
| CPE 2.3 Semantic Matcher (DependencyCheck-style) | 1 day | 2025-07 |
| Goal Satisfaction Model (PTT + 7-dim) | 0.5 day | 2025-07 |
| Pentest Workflow (device profiles + JS + rate) | 0.5 day | 2025-07 |
| Unit Tests (25→65 in security) | 0.5 day | 2025-07 |

### Gap Analysis vs. Mature Projects

| Gap | Severity | Effort | Description |
|-----|----------|--------|-------------|
| **Post-Exploitation Module** | 🔴 Critical | 5-7 days | privilege escalation, credential extraction, lateral movement |
| **Standard Benchmark Suite** | 🟡 Medium | 3-5 days | No quantitative evaluation (PentestGPT has 104 XBOW benchmarks) |
| **Container Isolation** | 🟡 Medium | 2-3 days | All tools run on host; Docker sandbox for risky tools |
| **Screenshot Gallery** | 🟢 Low | 1 day | gowitness adapter exists; add gallery viewer |
| **HTML/PDF Reports** | 🟢 Low | 2-3 days | Currently Markdown only |
| **Daemon Mode** | 🟢 Low | 2-3 days | Background agent with web UI |

### Completed Items (v2.0 → v2.2)

| Item | Version | Description |
|------|---------|-------------|
| Metasploit RPC Integration | v2.2 | MsfRpcClient + MsfConsoleAdapter in ExploitManager |
| Automated OWASP Validation | v2.2 | nuclei real tags + ZAP-style job pipeline |
| EPSS + KEV Integration | v2.1 | 3D CVSS×EPSS×KEV priority scoring |
| CVE Matcher Upgrade | v2.2 | CPE 2.3 semantic matcher (replaced substring grep) |
| Test Coverage | v2.2 | 25→65 security tests |
| Tool Auto-Discovery | v2.1 | PATH + tools/bin scanning |
| Self-Learning Feedback | v2.1 | AttackPathRecord + BM25 retrieval |
| Graph Model | v2.1 | Evidence/Hypothesis/Override |
| Stigmergy Coordination | v2.1 | 9→4 roles, graph-driven dispatch |
| Core Parameterization | v2.2 | Architecture analysis: DI pattern confirmed, ~60 private methods in 20+ modules |

## Recommended Next Steps (Priority Order)

### Phase 3: Post-Exploitation (Week 1-2)
1. Post-exploitation module — privesc (sudo -l, SUID, cron), credential extraction (hashdump), lateral movement (pivoting)

### Phase 4: Hardening (Week 3-4)
2. Benchmark suite — 10-20 vulnhub/HTB targets with automated scoring
3. Container isolation — Docker sandbox for exploit/nuclei/dirsearch
4. HTML/PDF reports — currently Markdown only

### Phase 5: Polish (Week 5-6)
5. Screenshot gallery — gowitness viewer
6. Daemon mode — background agent with web UI

## Architecture Reference (v2.2)

```
packages/
├── security/src/       (24 modules)
│   ├── graph-types.ts     Evidence/Hypothesis/Override/PenetrationGraph (25+ types)
│   ├── graph.ts           Graph engine — create/mutate/snapshot/query/checkpoint
│   ├── graph-scheduler.ts Analysis/Investigation task dispatch + prompt builder
│   ├── goal-model.ts      PTT task tree + 7-dim coverage + Reason termination
│   ├── exploit-engine.ts  ExploitManager + 6 adapters (902 lines)
│   ├── cve-chain.ts       Fingerprint→CVE→Payload→Exploit (546 lines)
│   ├── cpe-matcher.ts     CPE 2.3 semantic matcher (OWASP DC-style)
│   ├── owasp-validator.ts 10 OWASP categories auto-validate (ZAP pipeline)
│   ├── pentest-workflow.ts Device profiles + JS analysis + rate control
│   ├── epss-kev.ts        EPSS API + CISA KEV + 3D priority scoring
│   ├── feedback.ts        Self-learning: AttackPathRecord + BM25 retrieval
│   ├── types.ts           (55+ type definitions)
│   ├── adapters.ts        (25 tools + auto-discovery + versionArgsFor)
│   ├── decision-models.ts (2734)
│   ├── normalizer.ts      (1374)
│   ├── pipeline-support.ts
│   ├── knowledge-base.ts
│   ├── exploits.ts
│   ├── wappalyzer.ts      (~3,500 fingerprints)
│   ├── cvss.ts            (CVSS 3.1)
│   ├── semver.ts          (version matching)
│   ├── nvd.ts             (NVD API)
│   ├── fofa.ts            (FOFA)
│   ├── attack-chains.ts
│   └── utils.ts
│
├── core/src/           (22+ modules)
│   ├── index.ts           MainAgent + graph integration
│   ├── subagent-roles.ts  9 legacy roles (deprecated)
│   ├── subagent-roles-v2.ts  4 simplified roles
│   ├── subagent-stigmergy.ts Graph-driven dispatch + Stigmergy context
│   ├── subagent-runtime.ts
│   ├── subagent-orchestration.ts
│   ├── tool-handlers.ts   DI-based handler registry (documented)
│   ├── pentest-runtime.ts
│   ├── pentest-decision.ts
│   ├── security-*.ts      (10 modules)
│   └── ...
│
└── context/src/        (2 modules)
    ├── index.ts           BM25 context builder
    └── vectorizer.ts      BM25 index
```

## Comparison: AegisProbe vs. Mature Projects

| Dimension | AegisProbe v2.2 | PentestGPT | Cairn | Osmedeus | reconFTW | Metasploit |
|-----------|----------------|------------|-------|----------|----------|------------|
| AI-Driven | ✅ LLM orchestrator | ✅ GPT-4 | ✅ LLM workers | ⚠️ Rule-based | ❌ | ❌ |
| **Graph Model** | ✅ Evidence/Hypothesis | ❌ | ✅ Facts/Intents | ❌ | ❌ | ❌ |
| **Goal Model** | ✅ PTT + 7-dim scoring | ✅ PTT (attack tree) | ✅ Facts→Complete | ❌ | ❌ | ❌ |
| **Stigmergy** | ✅ Graph-board coordination | ❌ Direct | ✅ Blackboard | ❌ | ❌ | ❌ |
| **Agent Roles** | 4 simplified | ~5 | **0 (role-less)** | ✅ YAML | ❌ | ✅ Modules |
| **CPE Semantic Match** | ✅ CPE 2.3 + DC-style | ⚠️ Basic | ❌ | ❌ | ❌ | ❌ |
| **OWASP Auto-Validate** | ✅ 10 categories | ❌ | ❌ | ❌ | ❌ | ❌ |
| **EPSS/KEV** | ✅ 3D prioritization | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Exploit Engine** | ✅ 6 adapters (msf/sqlmap/nuclei/searchsploit) | ❌ | ❌ | ❌ | ❌ | ✅ 2000+ exploits |
| **Self-Learning** | ✅ BM25 feedback | ❌ | ❌ | ❌ | ❌ | ❌ |
| **Tool Discovery** | ✅ PATH scan | ✅ Docker | ✅ Container | ✅ PATH | ❌ | ❌ |
| **Device Profiles** | ✅ 15 devices + default creds | ❌ | ❌ | ❌ | ❌ | ❌ |
| Modular Code | ✅ 55+ modules | ✅ Modular | ✅ Modular | ✅ YAML | ❌ Monolithic | ✅ Modules |
| CVE Matching | ✅ CVSS+EPSS+KEV+CPE | ✅ Database | ❌ None | ✅ Nuclei | ❌ | ✅ msfconsole |
| Fingerprinting | ✅ Wappalyzer 3.5K | ⚠️ Basic | ❌ None | ✅ Custom | ⚠️ whatweb | ❌ |
| Post-Exploitation | ❌ | ❌ | ❌ | ❌ | ❌ | ✅ meterpreter |
| Web UI | ❌ CLI only | ✅ Web | ❌ | ✅ Web | ❌ CLI | ✅ msfweb |
| Report Generation | ✅ Markdown | ✅ HTML/PDF | ❌ | ✅ HTML | ✅ Markdown | ✅ Various |
| Parallel Agents | ✅ Stigmergy parallel | ❌ Sequential | ✅ Parallel | ✅ Parallel | ❌ | ❌ |
| Context Retrieval | ✅ BM25 RAG | ⚠️ Basic | ❌ | ❌ | ❌ | ❌ |
| Benchmark | ❌ | ✅ 104 XBOW (86.5%) | ✅ 54/54 CTF AK | ❌ | ❌ | ✅ msfconsole |
| Container Isolation | ❌ | ✅ Docker | ✅ Docker | ✅ Docker | ❌ | ❌ |
| Unit Tests | ✅ 65 security tests | ⚠️ Limited | ⚠️ Limited | ❌ | ❌ | ✅ msftest |
