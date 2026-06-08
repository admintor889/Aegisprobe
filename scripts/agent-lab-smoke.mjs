#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AuditStore } from "../packages/storage/dist/index.js";
import { MainAgent } from "../packages/core/dist/index.js";
import { newId, nowIso } from "../packages/shared/dist/index.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const parsed = {
    case: "vulhub-struts2-s2-045",
    cases: join(repoRoot, "scripts", "agent-lab-smoke-cases.json"),
    maxPages: 2,
    decisionIterations: 1,
    activeProof: false,
    startTarget: false,
    allowFail: false
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--case") parsed.case = requireValue(argv, ++index, arg);
    else if (arg === "--cases") parsed.cases = resolve(repoRoot, requireValue(argv, ++index, arg));
    else if (arg === "--target") parsed.target = requireValue(argv, ++index, arg);
    else if (arg === "--db") parsed.db = resolve(repoRoot, requireValue(argv, ++index, arg));
    else if (arg === "--out") parsed.out = resolve(repoRoot, requireValue(argv, ++index, arg));
    else if (arg === "--max-pages") parsed.maxPages = Number.parseInt(requireValue(argv, ++index, arg), 10);
    else if (arg === "--decision-iterations") parsed.decisionIterations = Number.parseInt(requireValue(argv, ++index, arg), 10);
    else if (arg === "--active-proof") parsed.activeProof = true;
    else if (arg === "--start-target") parsed.startTarget = true;
    else if (arg === "--allow-fail") parsed.allowFail = true;
    else if (arg === "--help" || arg === "-h") parsed.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return parsed;
}

function requireValue(argv, index, flag) {
  const value = argv[index];
  if (!value || value.startsWith("--")) {
    throw new Error(`${flag} requires a value`);
  }
  return value;
}

function usage() {
  return [
    "Usage: node scripts/agent-lab-smoke.mjs [options]",
    "",
    "Options:",
    "  --case <id>                  Smoke case id (default: vulhub-struts2-s2-045)",
    "  --target <url>               Override case target URL",
    "  --db <path>                  SQLite output path",
    "  --out <path>                 JSON report output path",
    "  --max-pages <n>              Browser recon page budget (default: 2)",
    "  --decision-iterations <n>    Queue items to execute after recon (default: 1)",
    "  --active-proof               Run the case's explicit non-destructive proof",
    "  --start-target               Start the case target from its local start config",
    "  --allow-fail                 Write report but exit 0 on failed assertions",
    "  -h, --help                   Show this help"
  ].join("\n");
}

function loadCase(filePath, id) {
  const raw = JSON.parse(readFileSync(filePath, "utf8"));
  const selected = raw.cases?.find((item) => item.id === id);
  if (!selected) {
    const available = raw.cases?.map((item) => item.id).join(", ") || "none";
    throw new Error(`Smoke case not found: ${id}. Available: ${available}`);
  }
  return selected;
}

function defaultOutputPaths(caseId) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const dir = join(repoRoot, "data", "lab-smoke");
  return {
    db: join(dir, `${caseId}-${stamp}.sqlite`),
    out: join(dir, `${caseId}-${stamp}.json`)
  };
}

function targetPathUrl(base, path) {
  return new URL(path || "/", base).href;
}

function uniqueStrings(values) {
  return [...new Set(values.filter((value) => typeof value === "string" && value.length > 0))];
}

function scopeFor(target, activeProof) {
  return {
    allowActiveProbing: Boolean(activeProof),
    allowCidrDiscovery: false,
    intensity: activeProof ? "active" : "safe",
    scanProfile: "quick",
    rateLimitPerSecond: 2,
    allowedTargets: [target],
    excludedTargets: []
  };
}

async function runSafeProof(caseSpec, target, store, sessionId, workflowId, agent) {
  const proof = caseSpec.safeProof;
  if (!proof) {
    return { status: "skipped", reason: "case has no safeProof" };
  }
  if (proof.kind === "responseStatusComparison") {
    return await runResponseStatusComparisonProof(caseSpec, target, store, sessionId, workflowId, proof);
  }
  if (proof.kind === "multiRoleAuthz") {
    return await runMultiRoleAuthzProof(caseSpec, target, store, sessionId, workflowId, proof, agent);
  }
  if (proof.kind !== "responseHeader") {
    throw new Error(`Unsupported safeProof kind: ${proof.kind}`);
  }

  const url = targetPathUrl(target, proof.path);
  const startedAt = nowIso();
  const response = await fetch(url, {
    method: proof.method || "GET",
    headers: proof.headers || {},
    redirect: "manual"
  });
  const headerName = proof.expectHeader.name;
  const actualHeader = response.headers.get(headerName);
  const passed = actualHeader === proof.expectHeader.value;
  const endedAt = nowIso();
  const summary = passed
    ? `Safe lab proof observed ${headerName}: ${actualHeader}`
    : `Safe lab proof did not observe ${headerName}: ${proof.expectHeader.value}`;
  const evidenceId = newId("evd");

  store.addSecurityToolRun({
    id: newId("run"),
    sessionId,
    workflowId,
    toolId: `lab-proof:${caseSpec.id}`,
    phase: "safe_validation",
    origin: "manual",
    status: passed ? "success" : "no_findings",
    inputKind: "url",
    inputCount: 1,
    outputSummary: summary,
    findingCount: passed ? 1 : 0,
    createdAt: startedAt,
    updatedAt: endedAt
  });
  store.addEvidence({
    id: evidenceId,
    sessionId,
    workflowId,
    source: `lab-proof:${caseSpec.id}`,
    kind: "http",
    summary,
    data: JSON.stringify({
      url,
      method: proof.method || "GET",
      status: response.status,
      contentType: response.headers.get("content-type"),
      expectedHeader: proof.expectHeader,
      actualHeader,
      destructiveActions: false,
      osCommandExecutionRequested: false,
      fileReadOrWriteRequested: false
    }, null, 2),
    createdAt: endedAt
  });

  if (passed && proof.finding) {
    store.upsertFinding({
      id: newId("fnd"),
      sessionId,
      workflowId,
      title: proof.finding.title,
      severity: proof.finding.severity || "high",
      confidence: "high",
      target: url,
      description: proof.finding.description,
      evidenceSummary: summary,
      remediation: proof.finding.remediation,
      state: "validated",
      dedupeKey: `lab-proof:${caseSpec.id}:${url}`,
      evidenceIds: [evidenceId],
      firstSeenAt: endedAt,
      lastSeenAt: endedAt,
      createdAt: endedAt,
      updatedAt: endedAt
    });
  }

  return {
    status: passed ? "validated" : "not_observed",
    url,
    responseStatus: response.status,
    expectedHeader: proof.expectHeader,
    actualHeader,
    evidenceId
  };
}

async function runMultiRoleAuthzProof(caseSpec, target, store, sessionId, workflowId, proof, agent) {
  if (!agent) {
    throw new Error("multiRoleAuthz proof requires an agent instance");
  }
  const startedAt = nowIso();
  const authContexts = [];
  for (const context of proof.authContexts || []) {
    const username = context.username || context.name;
    const password = context.password || `${username}123`;
    const response = await fetch(targetPathUrl(target, "/api/login"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const body = await response.json().catch(() => ({}));
    if (!body.token) {
      throw new Error(`Failed to authenticate local lab context ${context.name}: status ${response.status}`);
    }
    const registered = agent.addSecurityAuthContext(sessionId, {
      name: context.name,
      role: context.role,
      tenant: context.tenant,
      username,
      baseUrl: target,
      authorizationHeader: `Bearer ${body.token}`,
      notes: "Registered by local multi-role lab proof for read-only authorization comparison."
    });
    authContexts.push(registered);
  }
  if (authContexts.length < 2) {
    throw new Error("multiRoleAuthz proof requires at least two auth contexts.");
  }

  const beforeFindings = store.listFindings(sessionId).length;
  const withoutPolicy = await agent.executeBusinessLogicRoleComparison(sessionId, "next", authContexts[0].name, authContexts[1].name);
  const policyAgent = proof.expectedPolicy
    ? new MainAgent({
      store,
      approve: async () => false,
      provider: { complete: async () => "{\"message\":\"unused\",\"actions\":[],\"final\":true}" },
      projectRoot: repoRoot,
      expectedAuthorizationPolicy: proof.expectedPolicy
    })
    : undefined;
  const withPolicy = policyAgent
    ? await policyAgent.executeBusinessLogicRoleComparison(sessionId, "next", authContexts[0].name, authContexts[1].name)
    : "";
  const findings = store.listFindings(sessionId).slice(beforeFindings);
  const attempts = store.listSecurityValidationAttempts(sessionId, workflowId);
  const policyFinding = findings.find((finding) => /authorization policy violation/i.test(finding.title));
  const anyFinding = findings.at(-1);
  const validated = Boolean(policyFinding) || attempts.some((attempt) => attempt.status === "validated");
  const endedAt = nowIso();
  const evidenceId = newId("evd");
  const summary = validated
    ? `Read-only multi-role proof produced authorization evidence across ${authContexts.map((ctx) => ctx.name).join(" vs ")}.`
    : `Read-only multi-role proof completed without a validated policy finding.`;

  store.addSecurityToolRun({
    id: newId("run"),
    sessionId,
    workflowId,
    toolId: `lab-proof:${caseSpec.id}`,
    phase: "safe_validation",
    origin: "manual",
    status: validated ? "success" : "no_findings",
    inputKind: "auth-context",
    inputCount: authContexts.length,
    outputSummary: summary,
    findingCount: findings.length,
    createdAt: startedAt,
    updatedAt: endedAt
  });
  store.addEvidence({
    id: evidenceId,
    sessionId,
    workflowId,
    source: `lab-proof:${caseSpec.id}`,
    kind: "http",
    summary,
    data: JSON.stringify({
      authContexts: authContexts.map((ctx) => ({ name: ctx.name, role: ctx.role, tenant: ctx.tenant })),
      withoutPolicy: withoutPolicy.slice(0, 4000),
      withPolicy: withPolicy.slice(0, 4000),
      findings: findings.map((finding) => ({
        title: finding.title,
        severity: finding.severity,
        confidence: finding.confidence,
        state: finding.state
      })),
      destructiveActions: false,
      mutationRoutesReplayed: false
    }, null, 2),
    createdAt: endedAt
  });

  return {
    status: validated ? "validated" : "not_observed",
    authContexts: authContexts.map((ctx) => ({ name: ctx.name, role: ctx.role, tenant: ctx.tenant })),
    findingCount: findings.length,
    policyFinding: policyFinding ? {
      title: policyFinding.title,
      severity: policyFinding.severity,
      confidence: policyFinding.confidence,
      state: policyFinding.state
    } : undefined,
    latestFinding: anyFinding ? {
      title: anyFinding.title,
      severity: anyFinding.severity,
      confidence: anyFinding.confidence,
      state: anyFinding.state
    } : undefined,
    evidenceId
  };
}

async function runResponseStatusComparisonProof(caseSpec, target, store, sessionId, workflowId, proof) {
  const controlUrl = targetPathUrl(target, proof.control?.path || "/");
  const candidateUrl = targetPathUrl(target, proof.candidate?.path || "/");
  const startedAt = nowIso();
  const control = await fetch(controlUrl, {
    method: proof.control?.method || "GET",
    headers: proof.control?.headers || {},
    redirect: "manual"
  });
  const candidate = await fetch(candidateUrl, {
    method: proof.candidate?.method || "GET",
    headers: proof.candidate?.headers || {},
    redirect: "manual"
  });
  const candidateText = await safeResponseText(candidate);
  const expectedControl = proof.expect?.controlStatus;
  const expectedCandidate = proof.expect?.candidateStatus;
  const contains = proof.expect?.candidateBodyContains;
  const passed = (expectedControl === undefined || control.status === expectedControl)
    && (expectedCandidate === undefined || candidate.status === expectedCandidate)
    && (!contains || candidateText.includes(contains));
  const endedAt = nowIso();
  const summary = passed
    ? `Safe lab proof observed status transition ${control.status} -> ${candidate.status}`
    : `Safe lab proof expected status transition ${expectedControl ?? "*"} -> ${expectedCandidate ?? "*"}, observed ${control.status} -> ${candidate.status}`;
  const evidenceId = newId("evd");

  store.addSecurityToolRun({
    id: newId("run"),
    sessionId,
    workflowId,
    toolId: `lab-proof:${caseSpec.id}`,
    phase: "safe_validation",
    origin: "manual",
    status: passed ? "success" : "no_findings",
    inputKind: "url",
    inputCount: 2,
    outputSummary: summary,
    findingCount: passed ? 1 : 0,
    createdAt: startedAt,
    updatedAt: endedAt
  });
  store.addEvidence({
    id: evidenceId,
    sessionId,
    workflowId,
    source: `lab-proof:${caseSpec.id}`,
    kind: "http",
    summary,
    data: JSON.stringify({
      control: {
        url: controlUrl,
        method: proof.control?.method || "GET",
        status: control.status,
        contentType: control.headers.get("content-type")
      },
      candidate: {
        url: candidateUrl,
        method: proof.candidate?.method || "GET",
        status: candidate.status,
        contentType: candidate.headers.get("content-type"),
        bodyContainsExpectedText: contains ? candidateText.includes(contains) : undefined
      },
      destructiveActions: false,
      osCommandExecutionRequested: false,
      fileReadOrWriteRequested: false
    }, null, 2),
    createdAt: endedAt
  });

  if (passed && proof.finding) {
    store.upsertFinding({
      id: newId("fnd"),
      sessionId,
      workflowId,
      title: proof.finding.title,
      severity: proof.finding.severity || "high",
      confidence: "high",
      target: candidateUrl,
      description: proof.finding.description,
      evidenceSummary: summary,
      remediation: proof.finding.remediation,
      state: "validated",
      dedupeKey: `lab-proof:${caseSpec.id}:${candidateUrl}`,
      evidenceIds: [evidenceId],
      firstSeenAt: endedAt,
      lastSeenAt: endedAt,
      createdAt: endedAt,
      updatedAt: endedAt
    });
  }

  return {
    status: passed ? "validated" : "not_observed",
    control: { url: controlUrl, status: control.status },
    candidate: { url: candidateUrl, status: candidate.status },
    evidenceId
  };
}

async function safeResponseText(response) {
  try {
    return await response.clone().text();
  } catch {
    return "";
  }
}

function runAssertions(caseSpec, report) {
  const checks = [];
  const expect = caseSpec.expect || {};
  const auth = expect.auth || {};
  if (auth.login) {
    checks.push(check(`auth.login == ${auth.login}`, report.recon.authAssessment?.login === auth.login, report.recon.authAssessment?.login));
  }
  if (auth.authState) {
    checks.push(check(`auth.authState == ${auth.authState}`, report.recon.authAssessment?.authState === auth.authState, report.recon.authAssessment?.authState));
  }
  if (auth.authEndpointsEmpty) {
    checks.push(check("auth.authEndpoints is empty", (report.recon.authAssessment?.authEndpoints || []).length === 0, report.recon.authAssessment?.authEndpoints));
  }
  if (auth.loginObserved) {
    checks.push(check("auth.login is present or unknown", ["present", "unknown"].includes(report.recon.authAssessment?.login), report.recon.authAssessment?.login));
  }
  for (const item of expect.normalizedApiIncludes || []) {
    const endpoint = report.recon.normalizedApi.find((candidate) =>
      candidate.method === item.method && candidate.pathTemplate === item.pathTemplate
    );
    checks.push(check(`normalized API includes ${item.method} ${item.pathTemplate}`, Boolean(endpoint), endpoint));
    for (const signal of item.absentRiskSignals || []) {
      checks.push(check(`${item.method} ${item.pathTemplate} lacks risk signal ${signal}`, !endpoint?.riskSignals?.includes(signal), endpoint?.riskSignals));
    }
  }
  if (expect.queueBeforeFirstFallbackFor) {
    checks.push(check(`queueBefore[0].fallbackFor == ${expect.queueBeforeFirstFallbackFor}`, report.queue.before[0]?.fallbackFor === expect.queueBeforeFirstFallbackFor, report.queue.before[0]));
  }
  for (const title of expect.queueAfterAbsentTitles || []) {
    checks.push(check(`queueAfter lacks title ${title}`, !report.queue.after.some((item) => item.title === title), report.queue.after.map((item) => item.title)));
  }
  for (const path of expect.pagesVisitedIncludePaths || []) {
    checks.push(check(`pagesVisited includes ${path}`, report.recon.pagesVisited.some((url) => new URL(url).pathname === path), report.recon.pagesVisited));
  }
  if (expect.control?.stageIn) {
    checks.push(check(`control.stage in ${expect.control.stageIn.join(",")}`, expect.control.stageIn.includes(report.control.after.stage), report.control.after.stage));
  }
  if (Number.isFinite(expect.control?.minNormalizedApiEndpoints)) {
    checks.push(check(`control.normalizedApiEndpoints >= ${expect.control.minNormalizedApiEndpoints}`, report.control.after.evidenceCounts.normalizedApiEndpoints >= expect.control.minNormalizedApiEndpoints, report.control.after.evidenceCounts.normalizedApiEndpoints));
  }
  if (Number.isFinite(expect.control?.minRouteFrontier)) {
    checks.push(check(`control.routeFrontier >= ${expect.control.minRouteFrontier}`, report.control.after.routeFrontier.length >= expect.control.minRouteFrontier, report.control.after.routeFrontier));
  }
  for (const guard of expect.control?.decisionGuardIncludes || []) {
    checks.push(check(`control decision guard includes ${guard}`, report.control.after.decisionGuards.some((item) => item.includes(guard)), report.control.after.decisionGuards));
  }
  if (Number.isFinite(expect.operatingPicture?.minEndpointMap)) {
    checks.push(check(`operatingPicture.endpointMap >= ${expect.operatingPicture.minEndpointMap}`, report.operatingPicture.after.endpointMap.length >= expect.operatingPicture.minEndpointMap, report.operatingPicture.after.endpointMap));
  }
  for (const item of expect.operatingPicture?.endpointIncludes || []) {
    const endpoint = report.operatingPicture.after.endpointMap.find((candidate) =>
      candidate.method === item.method && candidate.pathTemplate === item.pathTemplate
    );
    checks.push(check(`operatingPicture endpoint includes ${item.method} ${item.pathTemplate}`, Boolean(endpoint), endpoint));
    for (const param of item.queryParams || []) {
      checks.push(check(`operatingPicture endpoint ${item.method} ${item.pathTemplate} query includes ${param}`, endpoint?.queryParams?.includes(param), endpoint?.queryParams));
    }
  }
  for (const frame of expect.operatingPicture?.decisionFrameIncludes || []) {
    checks.push(check(`operatingPicture decision frame includes ${frame}`, report.operatingPicture.after.decisionFrame.some((item) => item.includes(frame)), report.operatingPicture.after.decisionFrame));
  }
  for (const blocked of expect.operatingPicture?.blockedIncludes || []) {
    checks.push(check(`operatingPicture blocked boundary includes ${blocked}`, report.operatingPicture.after.blockedUntilEvidence.some((item) => item.includes(blocked)), report.operatingPicture.after.blockedUntilEvidence));
  }
  for (const blocked of expect.operatingPicture?.beforeBlockedIncludes || []) {
    checks.push(check(`operatingPicture before blocked boundary includes ${blocked}`, report.operatingPicture.before.blockedUntilEvidence.some((item) => item.includes(blocked)), report.operatingPicture.before.blockedUntilEvidence));
  }
  for (const action of expect.operatingPicture?.allowedActionIncludes || []) {
    checks.push(check(`operatingPicture allowed action includes ${action}`, report.operatingPicture.after.allowedNextActions.some((item) => item.includes(action)), report.operatingPicture.after.allowedNextActions));
  }
  for (const evidence of expect.operatingPicture?.authNextEvidenceIncludes || []) {
    checks.push(check(`operatingPicture auth next evidence includes ${evidence}`, report.operatingPicture.after.authState?.nextEvidenceNeeded?.some((item) => item.includes(evidence)), report.operatingPicture.after.authState?.nextEvidenceNeeded));
  }
  for (const evidence of expect.operatingPicture?.beforeAuthNextEvidenceIncludes || []) {
    checks.push(check(`operatingPicture before auth next evidence includes ${evidence}`, report.operatingPicture.before.authState?.nextEvidenceNeeded?.some((item) => item.includes(evidence)), report.operatingPicture.before.authState?.nextEvidenceNeeded));
  }
  for (const text of expect.expertSnapshotContains || []) {
    checks.push(check(`expert snapshot contains ${text}`, report.expertSnapshot?.excerpt?.includes(text), report.expertSnapshot));
  }
  if (Number.isFinite(expect.performance?.maxTotalMs)) {
    checks.push(check(`totalMs <= ${expect.performance.maxTotalMs}`, report.timings.totalMs <= expect.performance.maxTotalMs, report.timings.totalMs));
  }
  if (Number.isFinite(expect.performance?.maxReconMs)) {
    checks.push(check(`reconMs <= ${expect.performance.maxReconMs}`, report.timings.reconMs <= expect.performance.maxReconMs, report.timings.reconMs));
  }
  if (expect.redaction?.noHighEntropyParamHints) {
    const leaks = highEntropyParamHintLeaks(report);
    checks.push(check("redaction hides high-entropy parameter hints", leaks.length === 0, leaks));
  }
  return checks;
}

async function startTargetIfRequested(options, caseSpec) {
  if (!options.startTarget) return undefined;
  const config = caseSpec.start;
  if (!config) {
    throw new Error(`Case ${caseSpec.id} has no start config.`);
  }
  const readyUrl = config.readyUrl || caseSpec.target?.defaultUrl;
  if (readyUrl && await isHttpReady(readyUrl)) {
    return { alreadyRunning: true, stop: async () => undefined };
  }
  const command = config.command;
  const args = Array.isArray(config.args) ? config.args : [];
  const cwd = config.cwd ? resolve(repoRoot, config.cwd) : repoRoot;
  const child = spawn(command, args, {
    cwd,
    env: { ...process.env, ...(config.env || {}) },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true
  });
  const logs = [];
  child.stdout?.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr?.on("data", (chunk) => logs.push(String(chunk)));
  child.on("exit", (code, signal) => logs.push(`[target exited code=${code} signal=${signal}]`));
  if (readyUrl) {
    await waitForHttpReady(readyUrl, config.timeoutMs || 20_000, logs);
  }
  return {
    alreadyRunning: false,
    processId: child.pid,
    logs,
    stop: async () => {
      if (!child.killed) {
        child.kill();
        await new Promise((resolve) => setTimeout(resolve, 500));
      }
    }
  };
}

async function waitForHttpReady(url, timeoutMs, logs) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    if (await isHttpReady(url)) return;
    await new Promise((resolve) => setTimeout(resolve, 250));
  }
  throw new Error(`Target did not become ready at ${url} within ${timeoutMs}ms.\n${logs.join("").slice(-4000)}`);
}

async function isHttpReady(url) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 1500);
    try {
      const response = await fetch(url, { method: "GET", redirect: "manual", signal: controller.signal });
      return response.status > 0;
    } finally {
      clearTimeout(timeout);
    }
  } catch {
    return false;
  }
}

function check(name, passed, actual) {
  return { name, passed: Boolean(passed), actual };
}

function highEntropyParamHintLeaks(report) {
  const values = [];
  for (const endpoint of report.recon.normalizedApi || []) {
    values.push(...(endpoint.queryParams || []), ...(endpoint.bodyParamHints || []));
  }
  for (const endpoint of report.operatingPicture.after.endpointMap || []) {
    values.push(...(endpoint.queryParams || []), ...(endpoint.bodyParamHints || []));
  }
  for (const item of [...(report.queue.before || []), ...(report.queue.after || [])]) {
    values.push(item.target || "");
  }
  return values
    .flatMap((value) => String(value).match(/\b[a-f0-9]{16,}\b/gi) || [])
    .filter((value) => !/^api_[a-f0-9]+$/i.test(value))
    .slice(0, 10);
}

function summarizeRecon(recon) {
  return {
    pagesVisited: recon.pagesVisited,
    forms: recon.forms.map((form) => ({
      pageUrl: form.pageUrl,
      action: form.action,
      method: form.method,
      inputNames: form.inputNames,
      hasPassword: form.hasPassword,
      riskSignals: form.riskSignals
    })),
    networkRequestCount: recon.networkRequests.length,
    jsEndpointCount: recon.jsEndpoints.length,
    apiInventoryCount: recon.apiInventory.length,
    normalizedApi: (recon.normalizedApiEndpoints || []).map((endpoint) => ({
      method: endpoint.method,
      pathTemplate: endpoint.pathTemplate,
      examples: endpoint.examples,
      queryParams: endpoint.queryParams,
      bodyParamHints: endpoint.bodyParamHints,
      sources: endpoint.sources,
      authRequired: endpoint.authRequired,
      confidence: endpoint.confidence,
      riskSignals: endpoint.riskSignals
    })),
    authAssessment: recon.authAssessment
  };
}

function summarizeControlPlane(control) {
  return {
    stage: control.stage,
    summary: control.summary,
    evidenceCounts: control.evidenceCounts,
    routeFrontier: control.routeFrontier,
    gates: control.gates.map((gate) => ({
      id: gate.id,
      status: gate.status,
      priority: gate.priority,
      title: gate.title,
      nextAction: gate.nextAction
    })),
    nextBestActions: control.nextBestActions,
    decisionGuards: control.decisionGuards
  };
}

function summarizeOperatingPicture(picture) {
  return {
    stage: picture.stage,
    summary: picture.summary,
    authState: picture.authState,
    endpointMap: picture.endpointMap,
    evidenceGaps: picture.evidenceGaps,
    allowedNextActions: picture.allowedNextActions,
    blockedUntilEvidence: picture.blockedUntilEvidence,
    decisionFrame: picture.decisionFrame
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(usage());
    return;
  }
  for (const distPath of ["packages/core/dist/index.js", "packages/storage/dist/index.js", "packages/shared/dist/index.js"]) {
    if (!existsSync(join(repoRoot, distPath))) {
      throw new Error(`Missing ${distPath}. Run pnpm --filter @aegisprobe/core build first.`);
    }
  }

  const caseSpec = loadCase(options.cases, options.case);
  const target = options.target || caseSpec.target?.defaultUrl;
  if (!target) {
    throw new Error(`Case ${caseSpec.id} has no target.defaultUrl; pass --target`);
  }
  const defaults = defaultOutputPaths(caseSpec.id);
  const dbPath = options.db || defaults.db;
  const outPath = options.out || defaults.out;
  mkdirSync(dirname(dbPath), { recursive: true });
  mkdirSync(dirname(outPath), { recursive: true });

  const startedAtMs = Date.now();
  const targetProcess = await startTargetIfRequested(options, caseSpec);
  const store = new AuditStore(dbPath);
  try {
    const agent = new MainAgent({
      store,
      approve: async () => false,
      provider: { complete: async () => "{\"message\":\"unused\",\"actions\":[],\"final\":true}" },
      projectRoot: repoRoot
    });
    const sessionId = agent.createSession(`lab-smoke: ${caseSpec.id}`);
    const workflowId = newId("wf");
    const now = nowIso();
    store.upsertSecurityWorkflow({
      id: workflowId,
      sessionId,
      target: { kind: "url", raw: target, normalized: target },
      status: "running",
      currentPhase: "frontend",
      summary: `Agent lab smoke: ${caseSpec.name}`,
      createdAt: now,
      updatedAt: now
    });

    const scope = scopeFor(target, options.activeProof);
    const seedUrls = uniqueStrings([
      target,
      ...(caseSpec.target?.seedPaths || []).map((path) => targetPathUrl(target, path))
    ]);
    const reconStartedMs = Date.now();
    const reconResults = [];
    for (const seedUrl of seedUrls) {
      reconResults.push(await agent.reconWebApplication(sessionId, seedUrl, {
        maxPages: Number.isFinite(options.maxPages) ? options.maxPages : 2,
        analyzeJs: true
      }));
    }
    const recon = reconResults[reconResults.length - 1] || await agent.reconWebApplication(sessionId, target, {
      maxPages: Number.isFinite(options.maxPages) ? options.maxPages : 2,
      analyzeJs: true
    });
    const reconEndedMs = Date.now();
    const queueBefore = agent.buildSecurityDecisionQueue(sessionId, scope).items.slice(0, 8);
    const controlBefore = agent.buildWebPentestControlPlane(sessionId, workflowId);
    const operatingBefore = agent.buildWebPentestOperatingPicture(sessionId, workflowId);
    const decisionRuns = [];
    const decisionStartedMs = Date.now();
    for (let index = 0; index < Math.max(0, options.decisionIterations || 0); index += 1) {
      const result = await agent.executeSecurityDecisionQueueItem(sessionId, "next", scope);
      decisionRuns.push(result);
    }
    const decisionEndedMs = Date.now();
    const proofStartedMs = Date.now();
    const proof = options.activeProof
      ? await runSafeProof(caseSpec, target, store, sessionId, workflowId, agent)
      : { status: "skipped", reason: "run with --active-proof to execute the configured non-destructive proof" };
    const proofEndedMs = Date.now();
    const queueAfter = agent.buildSecurityDecisionQueue(sessionId, scope).items.slice(0, 8);
    const controlAfter = agent.buildWebPentestControlPlane(sessionId, workflowId);
    const operatingAfter = agent.buildWebPentestOperatingPicture(sessionId, workflowId);
    const expertSnapshot = agent.renderExpertSnapshot(sessionId);

    const report = {
      caseId: caseSpec.id,
      caseName: caseSpec.name,
      target,
      dbPath,
      sessionId,
      workflowId,
      scope,
      targetProcess: targetProcess ? {
        started: !targetProcess.alreadyRunning,
        alreadyRunning: Boolean(targetProcess.alreadyRunning),
        processId: targetProcess.processId
      } : undefined,
      timings: {
        reconMs: reconEndedMs - reconStartedMs,
        decisionMs: decisionEndedMs - decisionStartedMs,
        proofMs: proofEndedMs - proofStartedMs,
        totalMs: Date.now() - startedAtMs
      },
      recon: summarizeRecon(recon),
      queue: {
        before: queueBefore.map(summarizeQueueItem),
        after: queueAfter.map(summarizeQueueItem)
      },
      control: {
        before: summarizeControlPlane(controlBefore),
        after: summarizeControlPlane(controlAfter)
      },
      operatingPicture: {
        before: summarizeOperatingPicture(operatingBefore),
        after: summarizeOperatingPicture(operatingAfter)
      },
      decisionRuns,
      proof,
      expertSnapshot: {
        bytes: Buffer.byteLength(expertSnapshot, "utf8"),
        containsAccessExposure: expertSnapshot.includes("Access exposure map"),
        containsPayloadAffordances: expertSnapshot.includes("Payload affordances"),
        excerpt: expertSnapshot.slice(0, 4000)
      },
      storageSummary: {
        assets: store.listAssets(sessionId).length,
        evidence: store.listEvidence(sessionId).length,
        findings: store.listFindings(sessionId).map((finding) => ({
          title: finding.title,
          severity: finding.severity,
          confidence: finding.confidence,
          state: finding.state,
          target: finding.target
        })),
        toolRuns: store.listSecurityToolRuns(sessionId).map((run) => ({
          toolId: run.toolId,
          status: run.status,
          outputSummary: run.outputSummary
        }))
      }
    };
    report.assertions = runAssertions(caseSpec, report);
    report.passed = report.assertions.every((item) => item.passed) && (!options.activeProof || report.proof.status === "validated");
    writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    console.log(JSON.stringify({
      passed: report.passed,
      caseId: report.caseId,
      target: report.target,
      sessionId: report.sessionId,
      dbPath: report.dbPath,
      reportPath: outPath,
      timings: report.timings,
      normalizedApi: report.recon.normalizedApi,
      authAssessment: report.recon.authAssessment,
      control: {
        stage: report.control.after.stage,
        evidenceCounts: report.control.after.evidenceCounts,
        routeFrontier: report.control.after.routeFrontier.slice(0, 5),
        nextBestActions: report.control.after.nextBestActions.slice(0, 3)
      },
      queueAfter: report.queue.after,
      proof: report.proof,
      expertSnapshot: {
        bytes: report.expertSnapshot.bytes,
        containsAccessExposure: report.expertSnapshot.containsAccessExposure,
        containsPayloadAffordances: report.expertSnapshot.containsPayloadAffordances
      },
      failedAssertions: report.assertions.filter((item) => !item.passed).map((item) => item.name)
    }, null, 2));
    if (!report.passed && !options.allowFail) {
      process.exitCode = 1;
    }
  } finally {
    store.close();
    await targetProcess?.stop?.();
  }
}

function summarizeQueueItem(item) {
  return {
    id: item.id,
    priority: item.priority,
    phase: item.phase,
    actionType: item.actionType,
    title: item.title,
    fallbackFor: item.fallbackFor,
    blockedBy: item.blockedBy,
    target: item.target
  };
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
