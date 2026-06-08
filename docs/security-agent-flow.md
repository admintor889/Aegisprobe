# Security Agent Flow

This project keeps external security testing behind explicit authorization and approval. The goal is to integrate mature recon and validation workflows without turning the terminal assistant into an uncontrolled scanner.

## Local References

Reference projects cloned under `third_party/agentic-pentest/`:

- `PentestGPT`: agentic pipeline, session persistence, live walkthrough, Docker/tool preinstall model.
- `autopentest-ai`: OWASP/WSTG phase coverage, evidence discipline, specialized roles, quality gates.
- `pentest-ai-killer`: MCP/tool adapter reference for exposing security tools to agents.
- `SubHunterX`: practical recon chain using subfinder, amass, httpx, dirsearch, katana, and related tools.

Security tool source references live under `third_party/security-tools/`. Project-local binaries live under `tools/bin/`.

Additional orchestration references cloned under `third_party/research/`:

- `AutoRecon`: service discovery drives follow-up enumeration, with output pattern matching and scan concurrency limits.
- `reconFTW`: practical web recon chain around subdomain discovery, DNS resolution, HTTP probing, crawling, nuclei, fuzzing, and reports.
- `osmedeus-workflow`: declarative modules with dependencies, preconditions, output artifacts, JSONL post-processing, and reporting hooks.
- `rengine`: database-backed recon workflow and scan engine reference.
- `strix`: AI security agent loop with explicit scope context, actions, observations, and iteration limits.

Use `node .\apps\cli\dist\index.js tools` to inspect configured adapters, and `node .\apps\cli\dist\index.js tools --check` to verify that local binaries can actually start on the current OS.

Local knowledge sources:

- `tools/templates/nuclei-templates`: ProjectDiscovery community templates, indexed into `data/security-knowledge/nuclei-cve-index.json`.
- `third_party/security-tools/wappalyzer`: Wappalyzer technology fingerprints, used with nuclei metadata to build `data/security-knowledge/framework-knowledge.json`.
- `third_party/security-tools/yakit` and `third_party/security-tools/yaklang`: Yakit/Yaklang local references for the PoC database model and nuclei integration.
- `data/security-knowledge/business-logic-knowledge.json`: built-in business-logic playbooks for authorization, workflow, tenancy, pricing, race, and abuse cases.

Run `powershell -ExecutionPolicy Bypass -File .\tools\sync-security-knowledge.ps1` to update local references and rebuild the searchable index. Use `knowledge stats` and `knowledge search <query>` to inspect it.

## Execution Model

The assistant should treat penetration testing as a controlled workflow:

1. Confirm authorization, allowed targets, exclusions, rate limits, and active-test flags.
2. Create a security workflow and phase tasks in SQLite.
3. Run built-in DNS/HTTP baseline probes first.
4. Use passive/safe tools for recon, asset discovery, fingerprinting, and crawling.
5. For web applications, run `webapp-recon` before CVE or exploit selection so the agent has browser-visible pages, forms, runtime traffic, JavaScript endpoints, API inventory, and authentication surface evidence.
6. Delegate evidence interpretation to subagents for recon, frontend, fingerprint, CVE, and OWASP analysis.
7. Gate active scanners such as nuclei validation, dirsearch fuzzing, nmap port scanning, or any exploit-like checks behind explicit scope and shell approval.
8. Normalize outputs into assets, technologies, evidence, findings, CVE matches, and remediation.
9. Match version and technology evidence against local curated advisories, framework/CMS profiles, and the local nuclei template index, keeping all matches as candidates until validated.
10. Update validation-check state from evidence so the report separates observed signals, blocked active checks, and pending work.
11. Render a Markdown report with scope, assets, findings, CVE candidates, checklist state, evidence index, and prioritized next actions.

## Adaptive Orchestration Loop

The pipeline is no longer only a fixed one-shot command list. It now runs a bounded feedback loop inspired by AutoRecon, reconFTW, Osmedeus, reNgine, and Strix:

- Normalize every approved tool output into assets, technologies, findings, CVE candidates, and notes.
- Feed newly discovered hostnames into `dnsx` and batch `httpx` probing.
- Feed live HTTP URLs into `webapp-recon` and `katana` crawling before low-impact `nuclei` tech/exposure/misconfig matching.
- Record active `nuclei` validation as a blocked adaptive action unless `allowActiveProbing` is explicitly enabled.
- Store each adaptive decision as evidence before execution, then parse and feed its result back into the same workflow.
- Cap adaptive runs per pipeline pass to avoid uncontrolled loops and preserve the Codex-like approval boundary.

## Evidence-Driven Decision Queue

The decision queue is not a phase pipeline. It is a ranked set of next-action candidates derived from the current evidence graph.

For Web/API targets, normalized API assets now preserve lightweight metadata in the asset graph so queue items can reference concrete insertion-point evidence:

- `method pathTemplate`, not only raw URLs;
- query parameter names and body parameter hints;
- route sources such as runtime network traffic, JavaScript, OpenAPI, or GraphQL;
- auth requirement, confidence, examples, and risk signals.

The queue uses this evidence to prioritize authorization and business-logic planning around high-value API routes, similar to mature proxy/crawler workflows where discovered requests and insertion points drive audit selection. If an authorization plan reports route templates but lacks replayable examples, the queue asks for concrete browser/runtime sample requests before role comparison or payload testing.

Authorization comparison is gated by approved auth context evidence. With zero approved contexts, the queue asks for roles/users/tenants before business-impact testing. With one approved context and blocked authorization candidates, it asks for a second approved role instead of falling back to generic business-logic planning. Once at least two contexts and concrete read-only API examples exist, the queue can execute a read-only cross-role comparison from normalized API evidence.

This still preserves model autonomy: the model chooses among ranked candidates, but every candidate must explain which endpoint, parameter, auth state, source, or evidence gap justifies it. CVE/exploit validation remains post-fingerprint and approval-gated.

## Web Operating Picture

For web targets, each autonomous decision turn now receives a compact Web/API operating picture before recent raw observations. This is the agent's equivalent of a live proxy site map:

- normalized endpoint map: method, path template, query parameters, body hints, source, auth requirement, confidence, examples, risk signals, and route score;
- auth state: anonymous/unknown/authenticated context availability, approved role contexts, role comparison count, and next auth evidence needed;
- evidence gaps: missing browser recon, JS analysis, API normalization, auth surface modeling, concrete examples, or approved auth contexts;
- allowed next action families: browser/JS/API/auth evidence collection, read-only role comparison, business-logic planning from normalized routes, or targeted post-fingerprint validation;
- blocked-until-evidence boundaries: endpoint payload testing without endpoint/parameter evidence, cross-role checks without approved roles, state mutation without approval/safe boundary, and CVE/exploit validation without product/version evidence.

This operating picture is deliberately not a fixed pipeline. It gives the model the same facts a mature tester would keep in a Burp/ZAP/Katana-style site map, while preserving autonomous choice among evidence-backed next actions.

## Integrated Tool Chain

Current adapters:

- `subfinder`: passive subdomain discovery.
- `amass`: passive attack-surface mapping.
- `dnsx`: DNS resolution and enrichment.
- `httpx`: HTTP probing, status, title, server, TLS, CDN, and tech hints.
- `katana`: crawler and JavaScript/API route discovery.
- `webapp-recon`: Playwright read-only browser mapping for pages, forms, runtime network requests, JavaScript endpoints, API inventory, and authentication surface.
- `nuclei`: tech/exposure/misconfig and approval-gated validation.
- `dirsearch`: recursive directory brute-force with JSON output.
- `nmap`: comprehensive TCP+UDP+NSE port scanning with service/version detection; CIDR-sensitive discovery disabled by default.
- `WhatWeb`: source adapter, requires Ruby runtime on Windows.
- `Wappalyzer`: source adapter, requires Node package setup before CLI use.

## Normalized Security Data

Approved tool output is parsed best-effort before it reaches the long-term context:

- `subfinder` and `amass` produce domain/subdomain assets.
- `dnsx` produces domain, CNAME, and IP assets.
- `httpx` produces URL/service assets plus web server, CDN/WAF, framework, and technology records.
- `katana` produces URL and JavaScript assets plus source-map, sensitive-route, API-route, and credential-like URL findings.
- `webapp-recon` produces browser runtime evidence: pages, forms, network requests, JS endpoint candidates, source-map hints, redacted secret-like strings, API inventory, and authentication surface notes.
- `nuclei` produces evidence-backed findings and CVE matches from JSONL classifications.
- `dirsearch` produces discovered path and redirect findings for authorized content discovery.
- `nmap` produces service assets with version fingerprints and device/management-surface candidates such as printer, camera, VPN, and management HTTPS indicators.

The local CVE matcher is intentionally conservative: curated advisory rules can create version-backed candidates, and the nuclei template index can create lower-confidence product/template candidates. Findings still require manual validation before final reporting.

## Framework And CMS Intelligence

The framework index combines curated high-value product seeds, Wappalyzer fingerprint fields, and nuclei template metadata. It currently prioritizes PHP frameworks/CMS, Java authentication/framework/application-server stacks, enterprise OA/ERP/admin systems, CI/wiki/database management surfaces, and ecommerce CMS.

Representative profiles include ThinkPHP, Apache Shiro, Apache Struts, Spring Framework, Spring Boot, Oracle WebLogic Server, Apache Tomcat, JBoss/WildFly, WordPress, Drupal, Joomla, DedeCMS, Discuz, PHPCMS, EmpireCMS, MetInfo, ZenTao, RuoYi, JeecgBoot, Seeyon OA, Weaver OA, Yonyou, Kingdee, Jenkins, Atlassian Confluence, phpMyAdmin, and Magento. These profiles are used for recognition, prioritization, and candidate CVE/template matching only; they do not authorize exploit execution.

## OWASP And Business Logic Coverage

Each pipeline run stores an OWASP Top 10 validation matrix as evidence. The matrix separates passive signals from approval-required active checks for access control, crypto failures, injection, insecure design, misconfiguration, vulnerable components, authentication/session issues, integrity failures, logging/monitoring, and SSRF.

Each pipeline also attaches business-logic validation checks. Current playbooks cover:

- Object ownership and IDOR/BOLA validation.
- Function-level authorization and hidden admin routes.
- Mass assignment and object property authorization.
- Workflow step bypass and state transition abuse.
- Price, quantity, coupon, credit, and refund tampering.
- Race conditions and replay/double-submit abuse.
- Authentication recovery, 2FA, invite, and email-change logic.
- Tenant isolation and organization boundary checks.
- Business flow abuse and automation controls.
- File/object lifecycle and ownership after upload/share/delete.

The matrix is also expanded into durable validation checks:

- `pending`: no matching evidence has been collected yet.
- `observed`: passive evidence or a finding suggests the check is relevant.
- `validated`: reserved for future explicit proof workflows.
- `blocked`: active validation is needed but the current scope did not authorize active probing.
- `ruled_out`: reserved for future evidence-backed negative validation.

Use `checklist <session-id>` or `/checklist` to inspect this state. Use `report <session-id>` or `/report` to render the current Markdown assessment.

## Safety Defaults

- Every shell command still requires approval.
- Active probing is disabled unless `--active` is passed.
- CIDR/C-segment discovery is disabled unless `--allow-cidr` is passed.
- Private/reserved ranges are excluded by default.
- Tool outputs are stored as summaries/evidence, not as unrestricted raw sensitive dumps.
- Findings should be evidence-backed; hypotheses stay as tasks or notes.

## Next Integration Targets

- Add small project-local wordlists for safe dirsearch discovery.
- Add nuclei template path management and template update command.
- Add explicit validation workflows that can move checks from `observed` to `validated` or `ruled_out` with stronger proof requirements.
- Add HTML/PDF export after the Markdown report stabilizes.
