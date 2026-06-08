import { buildAccessExposureMap, buildPayloadCandidateSet, buildPayloadRequestDraftSet, renderPayloadCandidateSet, type AccessExposureMap, type PenetrationGraph, type PentestScope, type PayloadRequestDraftSet } from "@aegisprobe/security";
import { truncateForContext, type SecurityAsset, type SecurityEvidence, type SecurityToolRun, type TargetInput } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";

export type ExpertWorkbenchContextInput = {
  store: AuditStore;
  sessionId: string;
  workflowId?: string;
  target: TargetInput;
  scope: PentestScope;
  graph?: PenetrationGraph;
  recentObservations?: string[];
};

export function buildExpertWorkbenchContext(input: ExpertWorkbenchContextInput): string {
  const evidence = filterByWorkflow(input.store.listEvidence(input.sessionId), input.workflowId);
  const assets = filterByWorkflow(input.store.listAssets(input.sessionId), input.workflowId);
  const technologies = filterByWorkflow(input.store.listTechnologies(input.sessionId), input.workflowId);
  const cveMatches = filterByWorkflow(input.store.listCveMatches(input.sessionId), input.workflowId);
  const findings = filterByWorkflow(input.store.listFindings(input.sessionId), input.workflowId);
  const toolRuns = input.store.listSecurityToolRuns(input.sessionId, input.workflowId);
  const authContexts = input.store.listSecurityAuthContexts(input.sessionId, input.workflowId);
  const validations = input.store.listSecurityValidationAttempts(input.sessionId, input.workflowId);
  const commands = input.store.listCommands(input.sessionId, 30);

  const payloadCandidates = buildPayloadCandidateSet({
    target: input.target,
    assets,
    evidence,
    technologies,
    cveMatches,
    authContexts,
    maxCandidates: 8,
    activeAllowed: input.scope.allowActiveProbing,
    marker: markerForSession(input.sessionId)
  });
  const payloadDrafts = buildPayloadRequestDraftSet({
    target: input.target,
    assets,
    evidence,
    technologies,
    cveMatches,
    authContexts,
    maxCandidates: 8,
    maxDrafts: 6,
    activeAllowed: input.scope.allowActiveProbing,
    marker: markerForSession(input.sessionId)
  });
  const accessMap = buildAccessExposureMap({
    target: input.target,
    assets,
    evidence,
    authContexts,
    maxItems: 12
  });

  const lines: string[] = [
    "=== EXPERT WORKBENCH CONTEXT (model-led, advisory only) ===",
    "Autonomy contract: this context is not a task queue and not a scan order. Use it as facts, memory, and affordances; choose your own next action from evidence.",
    `Target: ${input.target.kind}:${input.target.normalized}`,
    `Scope: active=${input.scope.allowActiveProbing} intensity=${input.scope.intensity} profile=${input.scope.scanProfile} maxDepth=${input.scope.maxDepth}`,
    "",
    renderExpertQuickIndex(payloadCandidates.candidates, payloadDrafts, accessMap, evidence, toolRuns, commands),
    "",
    renderAccessExposureSummary(accessMap),
    "",
    renderAssetAndSurfaceMap(assets, technologies, findings),
    "",
    renderAuthAndValidationState(authContexts, validations),
    "",
    renderFailureMemory(toolRuns, commands),
    "",
    renderRawEvidenceHighlights(evidence),
    "",
    "Payload affordances:",
    renderPayloadCandidateIndex(payloadCandidates.candidates),
    renderPayloadDraftIndex(payloadDrafts),
    renderPayloadCandidateSet(payloadCandidates),
    "",
    renderOpenHypotheses(input.graph),
    "",
    renderEvidenceIndex(evidence),
    "",
    renderRecentObservationHints(input.recentObservations ?? [])
  ];

  return truncateForContext(lines.filter((line) => line.trim().length > 0).join("\n"), 36_000);
}

function renderPayloadCandidateIndex(candidates: ReturnType<typeof buildPayloadCandidateSet>["candidates"]): string {
  if (candidates.length === 0) {
    return "Payload candidate index: none.";
  }
  return `Payload candidate index: ${candidates.map((candidate) => `${candidate.id}/${candidate.category}/risk:${candidate.risk}`).join("; ")}`;
}

function renderPayloadDraftIndex(set: PayloadRequestDraftSet): string {
  if (set.drafts.length === 0) {
    return "Payload request draft index: none.";
  }
  return `Payload request draft index: ${set.drafts.map((draft) => compactDraftLine(draft)).join("; ")}`;
}

function renderAccessExposureSummary(map: AccessExposureMap): string {
  const lines = [
    "Access exposure map:",
    `- Summary: total=${map.summary.total} public=${map.summary.publicObserved} authGated=${map.summary.authGatedObserved} unknown=${map.summary.unknownAuth} needAnon=${map.summary.needsAnonymousBaseline} roleReady=${map.summary.readyForRoleComparison} passiveMutation=${map.summary.passiveMutationOnly} highValue=${map.summary.highValue}`
  ];
  if (map.informationGaps.length > 0) {
    lines.push(`- Information gaps: ${map.informationGaps.slice(0, 4).join(" | ")}`);
  }
  for (const item of map.items.slice(0, 8)) {
    lines.push(`- ${item.state}/score:${item.priorityScore} ${item.method} ${item.pathTemplate ?? item.endpoint} auth=${item.authRequired}${item.status !== undefined ? ` status=${item.status}` : ""} need=${truncateForContext(item.informationNeed, 180)}`);
  }
  return lines.join("\n");
}

function renderExpertQuickIndex(
  candidates: ReturnType<typeof buildPayloadCandidateSet>["candidates"],
  draftSet: PayloadRequestDraftSet,
  accessMap: AccessExposureMap,
  evidence: SecurityEvidence[],
  toolRuns: SecurityToolRun[],
  commands: ReturnType<AuditStore["listCommands"]>
): string {
  const [rawEvidence] = pickRawEvidenceHighlights(evidence, 1);
  const failedTool = [...toolRuns].reverse().find((run) => ["blocked", "missing", "denied", "failed", "skipped"].includes(run.status) || (run.failureCategory && run.failureCategory !== "none"));
  const failedCommand = [...commands].reverse().find((command) => ["denied", "blocked", "failed"].includes(command.status) || (command.exitCode ?? 0) !== 0);
  const lines = ["Expert quick index:"];
  lines.push(rawEvidence
    ? `- Recent raw evidence: ${rawEvidence.id} raw=${truncateForContext(rawEvidence.data ?? "", 420).replace(/\r?\n/g, " ")}`
    : "- Recent raw evidence: none.");
  lines.push(failedCommand
    ? `- Recent failed command: ${truncateForContext(failedCommand.command, 180)}`
    : failedTool
      ? `- Recent failed tool: ${failedTool.toolId} status=${failedTool.status} failure=${failedTool.failureCategory ?? "none"}`
      : "- Recent failed attempt: none.");
  lines.push(accessMap.items.length > 0
    ? `- Access exposure: needAnon=${accessMap.summary.needsAnonymousBaseline} roleReady=${accessMap.summary.readyForRoleComparison} unknown=${accessMap.summary.unknownAuth} top=${accessMap.items.slice(0, 2).map((item) => `${item.state}/${item.method} ${truncateForContext(item.pathTemplate ?? item.endpoint, 80)}`).join("; ")}`
    : "- Access exposure: no endpoint map yet.");
  lines.push(draftSet.drafts.length > 0
    ? `- Request drafts: ${draftSet.drafts.slice(0, 2).map((draft) => compactDraftLine(draft)).join("; ")}`
    : "- Request drafts: none.");
  lines.push(candidates.length > 0
    ? `- Payload affordances: ${candidates.slice(0, 8).map((candidate) => candidate.id).join(", ")}`
    : "- Payload affordances: none.");
  return lines.join("\n");
}

function compactDraftLine(draft: PayloadRequestDraftSet["drafts"][number]): string {
  return `${draft.id}/${draft.candidateId}/${draft.recommendedTool}/${draft.method}`;
}

function renderAssetAndSurfaceMap(
  assets: SecurityAsset[],
  technologies: ReturnType<AuditStore["listTechnologies"]>,
  findings: ReturnType<AuditStore["listFindings"]>
): string {
  const urlAssets = assets.filter((asset) => asset.kind === "url");
  const usefulUrlAssets = urlAssets.filter(isUsefulSurfaceUrl);
  const urls = uniqueAssetsByValue(usefulUrlAssets).slice(-16);
  const suppressedUrlCount = Math.max(0, urlAssets.length - usefulUrlAssets.length);
  const services = assets.filter((asset) => ["service", "ip", "domain", "subdomain"].includes(asset.kind)).slice(-12);
  const highValueRoutes = assets
    .filter((asset) => asset.kind === "url" && highValueRouteText(asset).length > 0)
    .filter(isUsefulSurfaceUrl)
    .slice(-16);
  const lines = ["Surface facts:"];
  lines.push(urls.length > 0 ? `- URLs/endpoints observed (high-signal): ${urls.map((asset) => asset.value).join("; ")}` : "- URLs/endpoints observed (high-signal): none recorded.");
  if (suppressedUrlCount > 0) lines.push(`- Static/low-signal URL assets suppressed from model workbench: ${suppressedUrlCount}`);
  if (services.length > 0) lines.push(`- Services/assets: ${services.map((asset) => `${asset.kind}:${asset.value}`).join("; ")}`);
  if (technologies.length > 0) {
    lines.push(`- Technologies: ${technologies.slice(-12).map((tech) => `${tech.name}${tech.version ? ` ${tech.version}` : ""} (${tech.confidence})`).join("; ")}`);
  }
  if (highValueRoutes.length > 0) {
    lines.push("- High-value route signals:");
    for (const asset of highValueRoutes) lines.push(`  - ${asset.value}${highValueRouteText(asset)}`);
  }
  if (findings.length > 0) {
    lines.push(`- Findings so far: ${findings.slice(-8).map((finding) => `${finding.state ?? "candidate"}/${finding.severity}/${finding.confidence}:${finding.title}`).join("; ")}`);
  }
  return lines.join("\n");
}

function renderAuthAndValidationState(
  authContexts: ReturnType<AuditStore["listSecurityAuthContexts"]>,
  validations: ReturnType<AuditStore["listSecurityValidationAttempts"]>
): string {
  const lines = ["Auth and validation memory:"];
  if (authContexts.length === 0) {
    lines.push("- Auth contexts: none registered.");
  } else {
    lines.push("- Auth contexts:");
    for (const context of authContexts.slice(-12)) {
      lines.push(`  - ${context.name} role=${context.role ?? "unknown"} tenant=${context.tenant ?? "unknown"} user=${context.username ?? "unknown"} cookie=${context.cookieHeader ? "yes" : "no"} authz=${context.authorizationHeader ? "yes" : "no"} storage=${context.storageStatePath ? "yes" : "no"}`);
    }
  }
  if (validations.length > 0) {
    lines.push("- Validation attempts:");
    for (const attempt of validations.slice(-10)) {
      lines.push(`  - ${attempt.status}/${attempt.confidence} ${attempt.targetKind}:${attempt.targetTitle} evidence=${attempt.evidenceIds.join(",") || "none"} rationale=${truncateForContext(attempt.rationale, 240).replace(/\r?\n/g, " ")}`);
    }
  } else {
    lines.push("- Validation attempts: none recorded.");
  }
  return lines.join("\n");
}

function renderOpenHypotheses(graph?: PenetrationGraph): string {
  const lines = ["Hypothesis memory:"];
  if (!graph) {
    lines.push("- No graph loaded.");
    return lines.join("\n");
  }
  const active = graph.hypotheses.filter((hypothesis) => hypothesis.status === "open" || hypothesis.status === "claimed").slice(-12);
  const closed = graph.hypotheses.filter((hypothesis) => hypothesis.status === "failed" || hypothesis.status === "blocked").slice(-8);
  if (active.length === 0) lines.push("- Active hypotheses: none.");
  for (const hypothesis of active) {
    lines.push(`- ${hypothesis.status}/${hypothesis.priority}/${hypothesis.category}: ${truncateForContext(hypothesis.description, 260)} basedOn=${hypothesis.basedOn.join(",") || "none"}`);
  }
  if (closed.length > 0) {
    lines.push("- Failed or blocked hypotheses to avoid repeating blindly:");
    for (const hypothesis of closed) {
      lines.push(`  - ${hypothesis.status}/${hypothesis.category}: ${truncateForContext(hypothesis.description, 220)}`);
    }
  }
  return lines.join("\n");
}

function renderFailureMemory(
  toolRuns: SecurityToolRun[],
  commands: ReturnType<AuditStore["listCommands"]>
): string {
  const failedRuns = toolRuns
    .filter((run) => ["blocked", "missing", "denied", "failed", "skipped"].includes(run.status) || (run.failureCategory && run.failureCategory !== "none"))
    .slice(-12);
  const failedCommands = commands
    .filter((command) => ["denied", "blocked", "failed"].includes(command.status) || (command.exitCode ?? 0) !== 0)
    .slice(-10);
  const lines = ["Attempt and failure memory:"];
  if (failedRuns.length === 0 && failedCommands.length === 0) {
    lines.push("- No failed, blocked, or denied tool attempts recorded.");
    return lines.join("\n");
  }
  for (const run of failedRuns) {
    lines.push(`- toolRun ${run.toolId} status=${run.status} failure=${run.failureCategory ?? "none"} exit=${run.exitCode ?? "n/a"} blocked=${run.blockedReason ?? "none"} summary=${truncateForContext(run.outputSummary ?? "", 260).replace(/\r?\n/g, " ")}`);
  }
  for (const command of failedCommands) {
    lines.push(`- shell status=${command.status} risk=${command.risk} exit=${command.exitCode ?? "n/a"} cmd=${truncateForContext(command.command, 220)} summary=${truncateForContext(command.summary ?? "", 220).replace(/\r?\n/g, " ")}`);
  }
  return lines.join("\n");
}

function renderRawEvidenceHighlights(evidence: SecurityEvidence[]): string {
  const rawItems = pickRawEvidenceHighlights(evidence, 6);
  const lines = ["Raw evidence highlights:"];
  if (rawItems.length === 0) {
    lines.push("- No raw evidence snippets stored yet.");
    return lines.join("\n");
  }
  for (const item of rawItems) {
    lines.push(`- ${item.id} raw=${truncateForContext(item.data ?? "", 520).replace(/\r?\n/g, " ")}`);
  }
  return lines.join("\n");
}

function pickRawEvidenceHighlights(evidence: SecurityEvidence[], limit: number): SecurityEvidence[] {
  return evidence
    .map((item, index) => ({ item, index, score: rawEvidenceScore(item) }))
    .filter((entry) => entry.score > Number.NEGATIVE_INFINITY)
    .sort((left, right) => right.score - left.score || right.index - left.index)
    .slice(0, limit)
    .map((entry) => entry.item);
}

function rawEvidenceScore(item: SecurityEvidence): number {
  if (typeof item.data !== "string" || item.data.trim().length === 0) {
    return Number.NEGATIVE_INFINITY;
  }
  const haystack = `${item.kind} ${item.source} ${item.summary} ${item.data}`;
  let score = 0;
  if (/\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+\//i.test(item.data)) score += 8;
  if (/\/api\/|\/graphql\b|\/rest\b|\/v\d+\//i.test(haystack)) score += 6;
  if (/[?&][A-Za-z0-9_.-]+=/.test(item.data)) score += 5;
  if (/browser|network|request|response|curl|http/i.test(`${item.source} ${item.summary}`)) score += 4;
  if (/tenant|role|user|owner|order|invoice|account|admin|token|session/i.test(haystack)) score += 3;
  if (/^\s*\{/.test(item.data)) score -= 4;
  if (/blackboard|workflow|sessionId|decision queue|validation matrix/i.test(`${item.source} ${item.summary}`)) score -= 3;
  return score;
}

function renderEvidenceIndex(evidence: SecurityEvidence[]): string {
  const lines = ["Evidence index with raw snippets:"];
  if (evidence.length === 0) {
    lines.push("- No stored evidence yet.");
    return lines.join("\n");
  }
  for (const item of evidence.slice(-14)) {
    const raw = item.data ? ` raw=${truncateForContext(item.data, 700).replace(/\r?\n/g, " ")}` : "";
    lines.push(`- ${item.id} | ${item.kind} | ${item.source} | ${truncateForContext(item.summary, 260).replace(/\r?\n/g, " ")}${raw}`);
  }
  return lines.join("\n");
}

function renderRecentObservationHints(observations: string[]): string {
  if (observations.length === 0) {
    return "Recent turn observations: none.";
  }
  const lines = ["Recent turn observations, raw excerpt index:"];
  observations.slice(-4).forEach((observation, index) => {
    lines.push(`- obs${index + 1}: ${truncateForContext(observation, 1200).replace(/\r?\n/g, " ")}`);
  });
  return lines.join("\n");
}

function highValueRouteText(asset: SecurityAsset): string {
  const meta = parseJson(asset.metadata);
  const riskSignals = arrayOfStrings(meta?.riskSignals).slice(0, 5);
  const queryParams = arrayOfStrings(meta?.queryParams).slice(0, 5);
  const bodyHints = arrayOfStrings(meta?.bodyParamHints).slice(0, 5);
  const parts = [
    riskSignals.length > 0 ? ` risk=${riskSignals.join(",")}` : undefined,
    queryParams.length > 0 ? ` query=${queryParams.join(",")}` : undefined,
    bodyHints.length > 0 ? ` body=${bodyHints.join(",")}` : undefined
  ].filter(Boolean);
  return parts.length > 0 ? ` (${parts.join(" | ")})` : "";
}

function uniqueAssetsByValue(assets: SecurityAsset[]): SecurityAsset[] {
  const byValue = new Map<string, SecurityAsset>();
  for (const asset of assets) {
    byValue.set(asset.value.toLowerCase(), asset);
  }
  return [...byValue.values()];
}

function isUsefulSurfaceUrl(asset: SecurityAsset): boolean {
  const meta = parseJson(asset.metadata);
  const riskSignals = arrayOfStrings(meta?.riskSignals);
  if (riskSignals.some((signal) => /api|graphql|admin|auth|business|privileged|tenant|object|workflow|state-changing|upload|file|parameter/i.test(signal))) return true;
  const value = decodeURIComponentSafe(asset.value);
  if (looksLikeExpressionOrTextArtifact(value) || isStaticLikePath(value)) return false;
  return /\/(?:api|rest|graphql|admin|auth|login|signin|session|users?|orders?|accounts?|tenants?|profile|settings|upload|files?|search)(?:\/|\?|$)/i.test(value)
    || /[?&][A-Za-z][A-Za-z0-9_.-]{0,40}=/.test(value);
}

function looksLikeExpressionOrTextArtifact(value: string): boolean {
  if (/[(){};]/.test(value)) return true;
  if (/(?:^|\/)[+*][A-Za-z_$]/.test(value)) return true;
  if (/\.[A-Za-z_$][\w$]*\(/.test(value)) return true;
  if (/\.\.\.|\[[^\]]*\]|\btruncated\b/i.test(value)) return true;
  if (/(?:^|\/)(?:n|raw)(?:$|[/?#])/i.test(value)) return true;
  return false;
}

function isStaticLikePath(value: string): boolean {
  return /\.(?:m?js|map|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot)(?:$|[?#/])/i.test(value)
    || /\/(?:public\/static|static|assets|javascripts?|js|css|images?|img|fonts?|vendor|plugins?|datatable|datatables)(?:\/|$)/i.test(value);
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function filterByWorkflow<T extends { workflowId?: string }>(items: T[], workflowId?: string): T[] {
  return workflowId ? items.filter((item) => !item.workflowId || item.workflowId === workflowId) : items;
}

function parseJson(value: unknown): Record<string, unknown> | undefined {
  if (typeof value === "object" && value !== null && !Array.isArray(value)) return value as Record<string, unknown>;
  if (typeof value !== "string" || value.trim().length === 0) return undefined;
  try {
    const parsed = JSON.parse(value);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function arrayOfStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
}

function markerForSession(sessionId: string): string {
  return sessionId.replace(/[^a-zA-Z0-9]/g, "").slice(-10) || "session";
}
