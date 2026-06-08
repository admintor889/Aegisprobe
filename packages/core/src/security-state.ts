import { mkdirSync, writeFileSync } from "node:fs";
import { join as joinPath } from "node:path";
import { matchLocalCveKnowledge } from "@aegisprobe/security";
import { newId, nowIso, truncateForContext, type SecurityAsset, type SecurityFinding, type SecurityValidationCheck, type SubAgentRecord, type SubAgentRole, type TargetInput } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { sanitizePathSegment } from "./core-helpers.js";
import { buildAuthorizationBoundaryMatrix, buildAuthorizationValidationPlan } from "./security-business.js";
import { buildWebPentestControlPlane, renderWebPentestControlPlane } from "./web-pentest-control-plane.js";

const checkKeywords: Record<string, string[]> = {
  A01: ["access control", "idor", "admin", "authorization", "broken access"],
  A02: ["hsts", "strict-transport-security", "tls", "crypto", "mixed-content", "cryptographic"],
  A03: ["injection", "sqli", "sql", "xss", "ssti", "command injection"],
  A04: ["insecure design", "business logic", "predictable identifier", "abuse"],
  A05: ["misconfiguration", "content-security-policy", "x-frame-options", "source map", "debug", "server disclosure"],
  A06: ["cve", "advisory", "outdated", "vulnerable component", "version"],
  A07: ["authentication", "session", "cookie", "login", "password reset"],
  A08: ["integrity", "source map", "ci/cd", "dependency", "unsigned"],
  A09: ["logging", "monitoring", "error handling", "audit"],
  A10: ["ssrf", "webhook", "url fetch", "callback", "import url"],
  "BL-001": ["idor", "bola", "object id", "ownership", "invoice", "order", "ticket"],
  "BL-002": ["admin", "manage", "role", "function level", "hidden route"],
  "BL-003": ["mass assignment", "isadmin", "role", "property", "patch", "put"],
  "BL-004": ["workflow", "state transition", "bypass", "2fa", "kyc", "step"],
  "BL-005": ["price", "amount", "coupon", "discount", "refund", "credit"],
  "BL-006": ["race", "replay", "double", "idempotency", "redeem", "transfer"],
  "BL-007": ["password reset", "2fa", "otp", "invite", "email change", "recovery"],
  "BL-008": ["tenant", "orgid", "workspace", "projectid", "organization"],
  "BL-009": ["rate limit", "abuse", "business flow", "automation", "captcha"],
  "BL-010": ["upload", "download", "share", "delete", "signed url", "attachment"]
};

export function writeWorkflowEvidenceManifest(
  projectRoot: string,
  store: AuditStore,
  input: {
    sessionId: string;
    workflowId: string;
    target: TargetInput;
    coordinationPlan: { items: Array<{ priority: string; role: SubAgentRole; runMode: string; title: string; blockedReason?: string }> };
  }
): string {
  const dir = joinPath(projectRoot, "data", "runs", sanitizePathSegment(input.sessionId), sanitizePathSegment(input.workflowId));
  mkdirSync(dir, { recursive: true });
  const path = joinPath(dir, "workflow-evidence-manifest.md");
  const toolRuns = store.listSecurityToolRuns(input.sessionId, input.workflowId);
  const subagents = store.listSubAgents(input.sessionId);
  const authContexts = store.listSecurityAuthContexts(input.sessionId, input.workflowId);
  const validationAttempts = store.listSecurityValidationAttempts(input.sessionId, input.workflowId);
  const assets = store.listAssets(input.sessionId);
  const technologies = store.listTechnologies(input.sessionId);
  const findings = store.listFindings(input.sessionId);
  const cveMatches = store.listCveMatches(input.sessionId);
  const artifacts = toolRuns
    .flatMap((run) => [run.inputArtifact, run.outputArtifact])
    .filter((artifact): artifact is string => Boolean(artifact));
  const lines = [
    "# Workflow Evidence Manifest",
    "",
    `- Session: ${input.sessionId}`,
    `- Workflow: ${input.workflowId}`,
    `- Target: ${input.target.kind}:${input.target.normalized}`,
    "",
    "## Tool Runs",
    toolRuns.length > 0
      ? toolRuns.map((run) => [
        `- ${run.status} | ${run.origin} | ${run.phase} | ${run.toolId}`,
        run.command ? `  - command: ${run.command}` : undefined,
        run.outputSummary ? `  - summary: ${truncateForContext(run.outputSummary, 500).replace(/\r?\n/g, " ")}` : undefined,
        run.blockedReason ? `  - blocked: ${run.blockedReason}` : undefined,
        run.inputArtifact ? `  - input artifact: ${run.inputArtifact}` : undefined,
        run.outputArtifact ? `  - output artifact: ${run.outputArtifact}` : undefined
      ].filter(Boolean).join("\n")).join("\n")
      : "No tool runs recorded yet.",
    "",
    "## Frontend/API Evidence",
    renderFrontendEvidenceManifest(store, input.sessionId, input.workflowId),
    "",
    "## Subagent Coordination",
    subagents.length > 0
      ? subagents.map((agent: SubAgentRecord) => `- ${agent.status} | ${agent.role} | ${agent.description ?? "delegated task"} | tools:${agent.toolUseCount} | ${agent.outputPath ?? "no-output"}`).join("\n")
      : "No subagents recorded yet.",
    "",
    "## Recommended Subagent Plan",
    input.coordinationPlan.items.length > 0
      ? input.coordinationPlan.items.map((item) => `- ${item.priority} | ${item.role} | ${item.runMode} | ${item.title}${item.blockedReason ? ` | blocked:${item.blockedReason}` : ""}`).join("\n")
      : "No subagent delegation recommended.",
    "",
    "## Auth Contexts",
    authContexts.length > 0
      ? authContexts.map((context) => `- ${context.name} | role:${context.role ?? "unknown"} | user:${context.username ?? "unknown"} | base:${context.baseUrl ?? input.target.normalized} | cookies:${context.cookieHeader ? "yes" : "no"} | authz:${context.authorizationHeader ? "yes" : "no"} | storage:${context.storageStatePath ?? "none"}`).join("\n")
      : "No authenticated browser/session context registered yet.",
    "",
    "## Validation Attempts",
    validationAttempts.length > 0
      ? validationAttempts.map((attempt) => `- ${attempt.status}/${attempt.confidence} | ${attempt.targetKind}:${attempt.targetId} | ${attempt.targetTitle} | evidence:${attempt.evidenceIds.join(",") || "none"}`).join("\n")
      : "No validation attempts recorded yet.",
    "",
    "## Assets",
    assets.map((asset) => `- ${asset.kind} | ${asset.confidence} | ${asset.value} | ${asset.source}`).join("\n") || "No assets recorded yet.",
    "",
    "## Technologies",
    technologies.map((technology) => `- ${technology.target} | ${technology.name}${technology.version ? ` ${technology.version}` : ""} | ${technology.confidence} | ${technology.category ?? "unknown"}`).join("\n") || "No technologies recorded yet.",
    "",
    "## Findings",
    findings.map((finding) => `- ${finding.severity} | ${finding.target} | ${finding.title} | ${finding.confidence}`).join("\n") || "No findings recorded yet.",
    "",
    "## CVE Candidates",
    cveMatches.map((match) => `- ${match.severity} | ${match.target} | ${match.cveId} | ${match.confidence} | ${match.title}`).join("\n") || "No CVE candidates recorded yet.",
    "",
    "## Web Pentest Control Plane",
    renderWebPentestControlPlane(buildWebPentestControlPlane(store, input.sessionId, input.workflowId)),
    "",
    "## Artifact Paths",
    artifacts.length > 0 ? artifacts.map((artifact) => `- ${artifact}`).join("\n") : "No artifact files recorded yet."
  ];
  writeFileSync(path, `${lines.join("\n")}\n`, "utf8");
  return path;
}

function renderFrontendEvidenceManifest(store: AuditStore, sessionId: string, workflowId: string): string {
  const toolRuns = store
    .listSecurityToolRuns(sessionId, workflowId)
    .filter((run) => ["webapp-recon", "js-analyzer", "api-inventory-normalizer", "auth-surface-model"].includes(run.toolId));
  const assets = store.listAssets(sessionId).filter((asset) => !asset.workflowId || asset.workflowId === workflowId);
  const evidence = store.listEvidence(sessionId).filter((item) => !item.workflowId || item.workflowId === workflowId);
  const findings = store.listFindings(sessionId).filter((finding) => !finding.workflowId || finding.workflowId === workflowId);
  const authContexts = store.listSecurityAuthContexts(sessionId, workflowId);
  const roleComparisons = evidence.filter((item) => item.source.startsWith("business-logic:compare:"));
  const normalizedApiAssets = assets.filter((asset) => asset.source.includes("api-inventory-normalizer"));
  const jsAnalyzerEvidence = [...evidence].reverse().find((item) => item.source === "browser:js-analyzer");
  const authAssessmentEvidence = [...evidence].reverse().find((item) => item.source === "browser:auth-surface-model");
  const attackSurfaceFinding = findings.find((finding) => finding.title === "Web application attack surface inventory");
  const lines: string[] = [];

  lines.push(toolRuns.length > 0
    ? `- Tool state: ${toolRuns.map((run) => `${run.toolId}:${run.status}`).join(", ")}`
    : "- Tool state: no browser runtime recon tool runs recorded.");

  lines.push(normalizedApiAssets.length > 0 ? `- Normalized API endpoints: ${normalizedApiAssets.length}` : "- Normalized API endpoints: none recorded.");
  for (const endpoint of renderNormalizedApiAssets(normalizedApiAssets).slice(0, 20)) {
    lines.push(`  - ${endpoint}`);
  }

  if (jsAnalyzerEvidence) {
    lines.push(`- JS analyzer: ${renderJsAnalyzerEvidence(jsAnalyzerEvidence.data, jsAnalyzerEvidence.summary)}`);
  }
  const sourceMaps = assets.filter((asset) => asset.source.includes("js-analyzer:source-map"));
  if (sourceMaps.length > 0) {
    lines.push(`- Source maps: ${sourceMaps.length} candidate(s), ${sourceMaps.filter((asset) => parseJsonObject(asset.metadata)?.available === true).length} available.`);
  }

  const authAssessment = renderAuthAssessmentSummary(authAssessmentEvidence?.data);
  if (authAssessment) {
    lines.push(`- Auth model: ${authAssessment}`);
  } else {
    const authSurface = renderAuthSurfaceSummary(attackSurfaceFinding?.evidenceSummary);
    lines.push(authSurface ? `- Auth surface: ${authSurface}` : "- Auth surface: no login/auth surface model recorded.");
  }
  lines.push(authContexts.length > 0
    ? `- Auth contexts: ${authContexts.map((context) => `${context.name} role=${context.role ?? "unknown"} storage=${context.storageStatePath ? "yes" : "no"}`).join("; ")}`
    : "- Auth contexts: none; current testing state is anonymous.");
  if (roleComparisons.length > 0) {
    const latest = roleComparisons.at(-1);
    lines.push(`- Cross-role comparisons: ${roleComparisons.length}; latest=${latest ? truncateForContext(latest.summary, 300).replace(/\r?\n/g, " ") : "none"}`);
  }
  const authzMatrix = buildAuthorizationBoundaryMatrix(store, sessionId);
  if (authzMatrix.summary.total > 0) {
    lines.push(`- Authorization matrix: total=${authzMatrix.summary.total}, ready=${authzMatrix.summary.ready}, blocked=${authzMatrix.summary.blocked}, needsExample=${authzMatrix.summary.needsExample}, compared=${authzMatrix.summary.compared}.`);
    for (const item of authzMatrix.items.slice(0, 10)) {
      lines.push(`  - ${item.status} | score:${item.priorityScore} | ${item.method} ${item.pathTemplate} | categories:${item.categories.join(",") || "authz"} | next:${item.nextAction}`);
    }
    const authzPlan = buildAuthorizationValidationPlan(store, sessionId);
    lines.push(`- Authorization validation plan: ready=${authzPlan.summary.ready}, blocked=${authzPlan.summary.blocked}, needsExample=${authzPlan.summary.needsExample}, passive=${authzPlan.summary.passiveOnly}.`);
    for (const candidate of authzPlan.candidates.slice(0, 6)) {
      const refs = candidate.objectReferences.length > 0
        ? ` refs:${candidate.objectReferences.map((ref) => `${ref.location}:${ref.name}`).join(",")}`
        : "";
      const rationale = candidate.priorityRationale.length > 0 ? ` why:${candidate.priorityRationale.slice(0, 3).join(";")}` : "";
      lines.push(`  - ${candidate.status} | score:${candidate.priorityScore} | ${candidate.method} ${candidate.pathTemplate} | categories:${candidate.categories.join(",") || "authz"}${refs}${rationale}`);
    }
  }

  const riskAssets = normalizedApiAssets.filter((asset) => stringArray(parseJsonObject(asset.metadata)?.riskSignals).length > 0);
  if (riskAssets.length > 0) {
    lines.push(`- High-value/risk route candidates: ${riskAssets.slice(0, 12).map((asset) => {
      const meta = parseJsonObject(asset.metadata);
      return `${stringValue(meta?.method) ?? "ANY"} ${stringValue(meta?.pathTemplate) ?? pathFromAssetValue(asset.value)} (${stringArray(meta?.riskSignals).slice(0, 4).join(",")})`;
    }).join("; ")}`);
  }

  lines.push("- Decision note: treat this as attack-surface mapping evidence, not vulnerability proof. Active validation still requires scope and approval.");
  return lines.join("\n");
}

function renderNormalizedApiAssets(assets: SecurityAsset[]): string[] {
  return assets.map((asset) => {
    const meta = parseJsonObject(asset.metadata);
    const method = stringValue(meta?.method) ?? "ANY";
    const pathTemplate = stringValue(meta?.pathTemplate) ?? pathFromAssetValue(asset.value);
    const queryParams = stringArray(meta?.queryParams).slice(0, 6);
    const bodyHints = stringArray(meta?.bodyParamHints).slice(0, 6);
    const riskSignals = stringArray(meta?.riskSignals).slice(0, 6);
    const sources = stringArray(meta?.sources).slice(0, 6);
    return [
      `${method} ${pathTemplate}`,
      `auth:${stringValue(meta?.authRequired) ?? "unknown"}`,
      queryParams.length > 0 ? `query:${queryParams.join(",")}` : undefined,
      bodyHints.length > 0 ? `body:${bodyHints.join(",")}` : undefined,
      riskSignals.length > 0 ? `risk:${riskSignals.join(",")}` : undefined,
      sources.length > 0 ? `sources:${sources.join(",")}` : undefined
    ].filter(Boolean).join(" | ");
  });
}

function renderJsAnalyzerEvidence(data: string | undefined, fallbackSummary: string): string {
  const parsed = parseJsonObject(data);
  const summary = parseJsonObject(parsed?.summary);
  const parts = [
    numberValue(summary?.scriptCount) !== undefined ? `scripts=${numberValue(summary?.scriptCount)}` : undefined,
    numberValue(summary?.endpointCount) !== undefined ? `endpoints=${numberValue(summary?.endpointCount)}` : undefined,
    numberValue(summary?.highValueRouteCount) !== undefined ? `highValueRoutes=${numberValue(summary?.highValueRouteCount)}` : undefined,
    numberValue(summary?.graphqlCount) !== undefined ? `graphql=${numberValue(summary?.graphqlCount)}` : undefined,
    numberValue(summary?.websocketCount) !== undefined ? `websocket=${numberValue(summary?.websocketCount)}` : undefined,
    numberValue(summary?.sourceMapCount) !== undefined ? `sourceMaps=${numberValue(summary?.sourceMapCount)}` : undefined,
    numberValue(summary?.libraryCount) !== undefined ? `libraries=${numberValue(summary?.libraryCount)}` : undefined,
    numberValue(summary?.sensitiveSignalCount) !== undefined ? `sensitiveSignals=${numberValue(summary?.sensitiveSignalCount)}` : undefined
  ].filter(Boolean);
  return parts.length > 0 ? parts.join(", ") : truncateForContext(fallbackSummary, 300);
}

function renderAuthSurfaceSummary(evidenceSummary?: string): string | undefined {
  const parsed = parseJsonObject(evidenceSummary);
  const authSurface = parseJsonObject(parsed?.authSurface);
  if (!authSurface) return undefined;
  const loginPages = stringArray(authSurface.loginPages);
  const authEndpoints = stringArray(authSurface.authEndpoints);
  const passwordForms = Array.isArray(authSurface.passwordForms) ? authSurface.passwordForms : [];
  const notes = stringArray(authSurface.notes).slice(0, 2);
  return [
    `loginPages=${loginPages.length}`,
    loginPages[0] ? `first=${loginPages[0]}` : undefined,
    `authEndpoints=${authEndpoints.length}`,
    `passwordForms=${passwordForms.length}`,
    notes.length > 0 ? `notes=${notes.join(" | ")}` : undefined
  ].filter(Boolean).join(", ");
}

function renderAuthAssessmentSummary(data?: string): string | undefined {
  const parsed = parseJsonObject(data);
  const assessment = parseJsonObject(parsed?.assessment);
  if (!assessment) return undefined;
  const mechanisms = stringArray(assessment.sessionMechanisms);
  const riskSignals = stringArray(assessment.riskSignals);
  const nextEvidenceNeeded = stringArray(assessment.nextEvidenceNeeded).slice(0, 3);
  return [
    `state=${stringValue(assessment.authState) ?? "unknown"}`,
    `login=${stringValue(assessment.login) ?? "unknown"}`,
    mechanisms.length > 0 ? `mechanisms=${mechanisms.join(",")}` : undefined,
    `csrf=${stringValue(assessment.csrfSignals) ?? "unknown"}`,
    Array.isArray(assessment.highValueFlows) ? `highValueFlows=${assessment.highValueFlows.length}` : undefined,
    riskSignals.length > 0 ? `risk=${riskSignals.slice(0, 6).join(",")}` : undefined,
    nextEvidenceNeeded.length > 0 ? `needed=${nextEvidenceNeeded.join(" | ")}` : undefined
  ].filter(Boolean).join(", ");
}

function parseJsonObject(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) return value as Record<string, unknown>;
  if (typeof value !== "string" || value.trim().length === 0) return undefined;
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
}

function pathFromAssetValue(value: string): string {
  try {
    return new URL(value).pathname || value;
  } catch {
    return value;
  }
}

export function recordLocalCveMatches(
  store: AuditStore,
  sessionId: string,
  workflowId: string,
  projectRoot: string,
  addCveMatchDeduped: (match: {
    id: string;
    sessionId: string;
    workflowId: string;
    createdAt: string;
    target: string;
    technology: string;
    title: string;
    cveId?: string;
    severity: "info" | "low" | "medium" | "high" | "critical";
    confidence: "low" | "medium" | "high";
    rationale: string;
    source: string;
    cvssVector?: string;
    cvssScore?: number;
    references?: string[];
    affectedVersions?: string;
    fixedVersions?: string;
    evidenceSummary?: string;
  }) => void
): void {
  const existingKeys = new Set(store.listCveMatches(sessionId).map((match) => [
    match.workflowId ?? "",
    match.target,
    match.technology,
    match.cveId ?? match.title
  ].join("|").toLowerCase()));
  const matches = matchLocalCveKnowledge(store.listTechnologies(sessionId), projectRoot);
  for (const match of matches) {
    const key = [workflowId, match.target, match.technology, match.cveId ?? match.title].join("|").toLowerCase();
    if (existingKeys.has(key)) {
      continue;
    }
    existingKeys.add(key);
    addCveMatchDeduped({
      id: newId("cve"),
      sessionId,
      workflowId,
      createdAt: nowIso(),
      ...match
    });
  }
}

export function refreshSecurityCheckStatus(
  store: AuditStore,
  sessionId: string,
  workflowId: string,
  activeValidationBlocked: boolean
): void {
  const checks = store.listSecurityChecks(sessionId, workflowId);
  const findings = store.listFindings(sessionId);
  const cveMatches = store.listCveMatches(sessionId);
  const evidence = store.listEvidence(sessionId);
  const technologies = store.listTechnologies(sessionId);
  const assets = store.listAssets(sessionId);
  const corpus = [
    ...findings.map((item) => `${item.title} ${item.description} ${item.evidenceSummary ?? ""}`),
    ...cveMatches.map((item) => `${item.title} ${item.technology} ${item.rationale}`),
    ...evidence
      .filter((item) => item.source !== "owasp:validation_matrix" && item.source !== "business_logic:knowledge_base" && item.source !== "framework:knowledge_base")
      .map((item) => `${item.source} ${item.kind} ${item.summary} ${item.data ?? ""}`),
    ...technologies.map((item) => `${item.name} ${item.version ?? ""} ${item.category ?? ""} ${item.evidenceSummary ?? ""}`),
    ...assets.map((item) => `${item.kind} ${item.value} ${item.source} ${item.metadata ?? ""}`)
  ].join("\n").toLowerCase();

  for (const check of checks) {
    const match = matchCheckEvidence(check, corpus, findings, cveMatches);
    if (match) {
      store.updateSecurityCheckStatus(check.id, "observed", match.evidenceSummary, match.rationale);
      continue;
    }
    if (activeValidationBlocked && check.activeRequiresApproval) {
      store.updateSecurityCheckStatus(
        check.id,
        "blocked",
        undefined,
        "Active validation is disabled for this run; passive review may still continue."
      );
    }
  }
}

function matchCheckEvidence(
  check: SecurityValidationCheck,
  corpus: string,
  findings: SecurityFinding[],
  cveMatches: ReturnType<AuditStore["listCveMatches"]>
): { evidenceSummary: string; rationale: string } | undefined {
  const keywords = checkKeywords[check.checkId] ?? [check.title.toLowerCase()];
  if (!keywords.some((keyword) => corpus.includes(keyword))) {
    return undefined;
  }
  const finding = findings.find((item) => keywords.some((keyword) => [
    item.title,
    item.description,
    item.evidenceSummary ?? ""
  ].join(" ").toLowerCase().includes(keyword)));
  if (finding) {
    return {
      evidenceSummary: `${finding.severity}/${finding.confidence}: ${finding.title}`,
      rationale: `Matched stored finding ${finding.id}.`
    };
  }
  const cve = cveMatches.find((item) => check.checkId === "A06" && (item.cveId || item.title));
  if (cve) {
    return {
      evidenceSummary: `${cve.severity}/${cve.confidence}: ${cve.cveId ?? cve.title}`,
      rationale: `Matched stored CVE/advisory candidate ${cve.id}.`
    };
  }
  return {
    evidenceSummary: `Passive signal matched for ${check.title}.`,
    rationale: "Matched normalized evidence corpus; manual validation is still required."
  };
}

export function enrichFindingForStorage(finding: any, dedupeKeyFn: (f: any) => string, evidenceIds: string[] = []): any {
  const now = new Date().toISOString();
  return {
    ...finding,
    state: finding.state ?? "candidate",
    dedupeKey: finding.dedupeKey ?? dedupeKeyFn(finding),
    evidenceIds: [...new Set([...(finding.evidenceIds ?? []), ...evidenceIds])],
    firstSeenAt: finding.firstSeenAt ?? finding.createdAt ?? now,
    lastSeenAt: finding.lastSeenAt ?? finding.updatedAt ?? now
  };
}

export function reconcileFindingStates(store: any, sessionId: string): void {
  const attempts = store.listSecurityValidationAttempts(sessionId);
  for (const attempt of attempts) {
    if (attempt.targetKind !== "finding") continue;
    const state = attempt.status === "validated" ? "validated"
      : attempt.status === "ruled_out" ? "false_positive"
      : attempt.status === "blocked" ? "needs_validation" : "needs_validation";
    store.updateFindingState(attempt.targetId, state, attempt.evidenceIds, attempt.rationale);
  }
}
