# Agent Lab Smoke Harness

`scripts/agent-lab-smoke.mjs` is a local regression harness for checking whether AegisProbe's evidence-driven web workflow behaves correctly on deliberately vulnerable labs.

The harness is intentionally separate from the agent's decision logic:

- lab-specific proof data lives in `scripts/agent-lab-smoke-cases.json`;
- the agent still performs browser recon, API normalization, auth surface modeling, and decision queue planning from observed evidence;
- each report captures the Web/API operating picture, control-plane stage, readiness gates, evidence counts, route frontier, decision guards, and blocked-until-evidence boundaries so regressions toward raw URL lists or CVE-first behavior are visible;
- optional active proof runs only when `--active-proof` is passed;
- proof cases must be non-destructive and must record SQLite evidence, tool-run summary, and a validated finding only when the configured assertion is observed.

Run the current S2-045 smoke after building packages:

```powershell
pnpm --filter @aegisprobe/core build
pnpm lab:smoke:local-multirole
pnpm lab:smoke:s2-045
pnpm lab:smoke:s2-045:proof
pnpm lab:vulhub:s2-045
pnpm lab:vulhub:flask-ssti
pnpm lab:vulhub:spring-22978
pnpm lab:vulhub:apisix-45232
```

The default case expects a Vulhub Struts2 S2-045 target at `http://127.0.0.1:8080/`. Override with `--target` when the lab publishes a different URL.

`pnpm lab:smoke:local-multirole` starts `labs/targets/local-multirole-app`, runs browser/API recon, records an expert workbench snapshot, registers two local JWT auth contexts, and performs read-only cross-role authorization comparison. The case is designed as the fast business-logic regression for BOLA/BFLA/tenant isolation. It should finish well under the configured 90 second ceiling on a local machine.

To let the existing Vulhub batch runner start the lab and dispatch known cases to this harness:

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test-vulhub-batch.ps1 `
  -Root labs\targets\vulhub\struts2\s2-045 `
  -BatchSize 1 `
  -MaxTargets 1 `
  -UseSmokeHarness `
  -SmokeActiveProof
```

For known labs, `test-vulhub-batch.ps1` matches `labPathHints` from `scripts/agent-lab-smoke-cases.json`, writes an agent smoke JSON report plus SQLite database into `data\vulhub-test-runs\<run-id>\`, and records `agent_smoke_passed` or `agent_smoke_failed` in `summary.jsonl`. Labs without a matching case continue to use the generic CLI pentest fallback.

The batch runner polls published HTTP ports until ready instead of sleeping a fixed amount of time, which keeps fast local labs moving while still allowing slower containers up to `-HttpReadyTimeoutSeconds`.

Do not run multiple Vulhub cases that bind the same host port in parallel. The runner writes each invocation to a unique report directory, but Docker port binding is still a shared local resource.

Use `pnpm lab:vulhub:matrix` for the known-case regression matrix. The matrix runs cases sequentially and, by default, requires images to already exist locally so failed registry pulls do not waste the run budget. Pass `-AllowPull` to `scripts\run-lab-smoke-matrix.ps1` when you explicitly want Docker to pull missing images.

The `operatingPicture` section is the smoke-test equivalent of a tester's live site map. It records the normalized endpoint map, query/body hints, auth state, allowed next action families, and actions blocked until stronger evidence exists. This is intentionally an evidence summary for the model and UI, not a fixed execution pipeline.

Design reference: mature scanners separate exploration from active audit. OWASP WSTG-INFO-06 requires mapping requests, methods, parameters, auth state, WebSockets, and notes before testing. Burp Scanner records crawl paths, request metadata, OpenAPI requests, and GraphQL operations in its site map. Katana exposes JS crawling, form extraction, similar-URL filtering, authenticated crawling, and endpoint/secrets classifiers. This harness uses those patterns for AegisProbe's own control plane without hardcoding lab-specific decisions into the agent.

External lab references checked on 2026-06-08:

- OWASP Juice Shop is useful as a single-container speed benchmark because it covers OWASP Top Ten-style web flaws and can be run with Docker on `127.0.0.1:3000`.
- OWASP crAPI is the better long-run API/business-logic benchmark because it intentionally covers API Top 10 risks including BOLA, BFLA, mass assignment, JWT issues, and excessive data exposure, but it is heavier because it uses Docker Compose/microservices.
- The local multi-role lab remains the fastest regression target because it isolates the exact behaviors AegisProbe must improve: endpoint discovery, anonymous/auth baseline separation, role/tenant comparison, and passive handling of mutation routes.
