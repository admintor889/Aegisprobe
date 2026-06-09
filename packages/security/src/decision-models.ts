import { existsSync } from "node:fs";
import { newId, nowIso, type FindingSeverity, type SecurityAsset, type SecurityAuthContext, type SecurityCveMatch, type SecurityEvidence, type SecurityFinding, type SecurityPhase, type SecurityTechnology, type SecurityToolRun, type SecurityToolRunStatus, type SecurityValidationAttempt, type SecurityValidationCheck, type SubAgentRecord, type SubAgentRole, type TargetInput, type SecurityWorkflowTask, type SecurityWorkflow } from "@aegisprobe/shared";
import type { SkillDefinition, SkillRegistry } from "@aegisprobe/skills";
import type {
  AdaptiveSecurityAction,
  BusinessLogicKnowledgeItem,
  BusinessLogicTestCase,
  BusinessLogicTestPlan,
  BusinessWorkflowCategory,
  BusinessWorkflowGraph,
  BusinessWorkflowGraphEdge,
  BusinessWorkflowGraphNode,
  BrowserInteractionPlan,
  AuthorizedValidationPlaybook,
  AuthorizedValidationStepKind,
  AuthorizedValidationStep,
  CveReconciliationPlan,
  PentestIntensity,
  PentestPipeline,
  PentestPipelineStep,
  PentestScope,
  SecurityAssetGraph,
  SecurityAssetGraphEdge,
  SecurityAssetGraphNode,
  SecurityClosureModel,
  SecurityDecisionQueue,
  SecurityDecisionQueueItem,
  SecurityDecisionSupervision,
  SecurityObjectiveAssessment,
  SecurityObjectiveId,
  SecurityObjectiveModel,
  SecurityObjectiveStatus,
  SecurityToolAdapter,
  SecurityToolCapability,
  SecurityToolInventoryItem,
  SecurityWorkflowPlan,
  SubAgentCoordinationPlan,
  SubAgentCoordinationPlanItem,
  SubAgentOperatingModel,
  ValidationClosureCandidate,
  ValidationClosurePlan,
  SecurityAttackPathModel,
  SecurityAttackPathStage,
  SkillExecutionPlan,
} from "./types.js";
import { uniqueStrings, uniqueBy, normalizeName, normalizeTargetForDedupe, stripVersion } from "./utils.js";
import { buildBusinessLogicKnowledgeBase } from "./knowledge-base.js";

function supportsHostnameEnumeration(target: { kind: string; normalized: string }): boolean {
  const host = safeHostname(target.normalized) ?? target.normalized.toLowerCase();
  return isPublicEnumeratableHostname(host);
}
import { inferPhase, roleForPhase } from "./pipeline-support.js";
// Using local utilities for getSecurityToolInventory, createDefaultPentestScope, supportsHostnameEnumeration
import { stringField, objectField, arrayField, numberField, severityField, servicePortProfiles, serviceProfileForPort } from "./normalizer.js";

export function buildSecurityAssetGraph(input: {
  target?: TargetInput;
  assets: SecurityAsset[];
  technologies: SecurityTechnology[];
  cveMatches: SecurityCveMatch[];
  findings: SecurityFinding[];
  evidence: SecurityEvidence[];
  toolRuns?: SecurityToolRun[];
  checks?: SecurityValidationCheck[];
}): SecurityAssetGraph {
  const nodes = new Map<string, SecurityAssetGraphNode>();
  const edges = new Map<string, SecurityAssetGraphEdge>();
  const assetValues = new Set<string>();
  const targetHost = input.target ? safeHostname(input.target.normalized) ?? input.target.normalized : undefined;

  for (const asset of input.assets) {
    const key = assetNodeKey(asset.kind, asset.value);
    assetValues.add(asset.value.toLowerCase());
    const existing = nodes.get(key);
    if (existing) {
      existing.sources = [...new Set([...existing.sources, asset.source])];
      if (asset.metadata) {
        existing.metadata = uniqueStrings([...existing.metadata, asset.metadata]).slice(0, 12);
      }
      existing.confidence = mergeConfidence(existing.confidence, asset.confidence);
      continue;
    }
    nodes.set(key, {
      id: key,
      kind: asset.kind,
      value: asset.value,
      confidence: asset.confidence,
      sources: [asset.source],
      metadata: asset.metadata ? [asset.metadata] : [],
      technologies: [],
      cveMatches: [],
      findings: [],
      evidenceCount: 0
    });
  }

  if (input.target && !assetValues.has(input.target.normalized.toLowerCase())) {
    const kind = input.target.kind === "url" ? "url" : input.target.kind === "domain" ? "domain" : undefined;
    if (kind) {
      const key = assetNodeKey(kind, input.target.normalized);
      nodes.set(key, {
        id: key,
        kind,
        value: input.target.normalized,
        confidence: "high",
        sources: ["target"],
        metadata: [],
        technologies: [],
        cveMatches: [],
        findings: [],
        evidenceCount: 0
      });
    }
  }

  const nodeList = [...nodes.values()];
  for (const parent of nodeList.filter((node) => node.kind === "domain" || node.kind === "subdomain")) {
    for (const child of nodeList.filter((node) => node.kind === "subdomain")) {
      if (child.id === parent.id) {
        continue;
      }
      if (child.value.toLowerCase().endsWith(`.${parent.value.toLowerCase()}`)) {
        addGraphEdge(edges, parent.id, child.id, "parent_domain");
      }
    }
  }

  for (const host of nodeList.filter((node) => node.kind === "domain" || node.kind === "subdomain")) {
    for (const url of nodeList.filter((node) => node.kind === "url")) {
      const urlHost = safeHostname(url.value);
      if (urlHost && (urlHost === host.value.toLowerCase() || urlHost.endsWith(`.${host.value.toLowerCase()}`))) {
        addGraphEdge(edges, host.id, url.id, "hosts_url");
      }
    }
  }

  for (const ip of nodeList.filter((node) => node.kind === "ip")) {
    for (const service of nodeList.filter((node) => node.kind === "service")) {
      if (service.value.toLowerCase().startsWith(`${ip.value.toLowerCase()}:`)) {
        addGraphEdge(edges, ip.id, service.id, "exposes_service");
      }
    }
  }

  for (const technology of input.technologies) {
    const node = matchTargetNode(nodes, technology.target);
    if (!node) {
      continue;
    }
    node.technologies.push({
      name: technology.name,
      version: technology.version,
      category: technology.category,
      confidence: technology.confidence,
      source: technology.source
    });
  }

  for (const match of input.cveMatches) {
    const node = matchTargetNode(nodes, match.target);
    if (!node) {
      continue;
    }
    node.cveMatches.push({
      cveId: match.cveId,
      title: match.title,
      severity: match.severity,
      confidence: match.confidence,
      source: match.source
    });
  }

  for (const finding of input.findings) {
    const node = matchTargetNode(nodes, finding.target);
    if (!node) {
      continue;
    }
    node.findings.push({
      title: finding.title,
      severity: finding.severity,
      confidence: finding.confidence,
      evidenceSummary: finding.evidenceSummary
    });
  }

  for (const item of input.evidence) {
    const content = `${item.summary}\n${item.data ?? ""}`.toLowerCase();
    for (const node of nodes.values()) {
      if (content.includes(node.value.toLowerCase())) {
        node.evidenceCount += 1;
      }
    }
  }

  const toolRuns = input.toolRuns ?? [];
  const checks = input.checks ?? [];
  const liveUrls = [...nodes.values()].filter((node) => node.kind === "url");
  const hosts = [...nodes.values()].filter((node) => node.kind === "domain" || node.kind === "subdomain");
  const canEnumerateHostnames = input.target ? supportsHostnameEnumeration(input.target) : true;
  const hasBrowserRecon = hasSuccessfulRun(toolRuns, "webapp-recon");
  const nextActions: string[] = [];
  if (canEnumerateHostnames && hosts.length <= 1 && !hasSuccessfulRun(toolRuns, "subfinder")) {
    nextActions.push("Run passive subdomain discovery with subfinder/amass, then feed discovered hosts into dnsx/httpx.");
  }
  if (canEnumerateHostnames && hosts.length > 0 && !hasSuccessfulRun(toolRuns, "dnsx")) {
    nextActions.push("Resolve discovered hosts with dnsx and persist IP/CNAME evidence into the asset graph.");
  }
  if (hosts.length > 0 && liveUrls.length === 0 && !hasSuccessfulRun(toolRuns, "httpx")) {
    nextActions.push("Probe resolved hosts with httpx to identify live URLs, status codes, titles, TLS, and technologies.");
  }
  if (liveUrls.length > 0 && !hasSuccessfulRun(toolRuns, "katana") && !hasBrowserRecon) {
    nextActions.push("Crawl live URLs with katana to collect frontend routes, JavaScript files, APIs, and source-map exposures.");
  }
  if ([...nodes.values()].some((node) => node.technologies.length > 0) && !hasSuccessfulRun(toolRuns, "nuclei-tech")) {
    nextActions.push("Run low-impact nuclei technology/exposure templates and local CVE matching against observed technologies.");
  }
  if (checks.some((check) => check.status === "blocked" && check.activeRequiresApproval)) {
    nextActions.push("Collect explicit active-testing authorization before running active OWASP validation or intrusive fuzzing.");
  }
  if (targetHost && nextActions.length === 0) {
    nextActions.push(`Review evidence for ${targetHost}, prioritize high-confidence findings, and request missing authentication/business-flow context.`);
  }

  return {
    nodes: [...nodes.values()].sort((a, b) => a.kind.localeCompare(b.kind) || a.value.localeCompare(b.value)),
    edges: [...edges.values()].sort((a, b) => `${a.from}:${a.to}`.localeCompare(`${b.from}:${b.to}`)),
    nextActions
  };
}

export function buildSecurityDecisionQueue(input: {
  target?: TargetInput;
  graph: SecurityAssetGraph;
  toolRuns: SecurityToolRun[];
  checks: SecurityValidationCheck[];
  authContexts?: SecurityAuthContext[];
  inventory?: SecurityToolInventoryItem[];
  scope?: PentestScope;
}): SecurityDecisionQueue {
  const items: SecurityDecisionQueueItem[] = [];
  const inventory = new Map((input.inventory ?? []).map((item) => [item.id, item]));
  const target = input.target?.normalized ?? input.graph.nodes[0]?.value ?? "unknown";
  const hosts = input.graph.nodes.filter((node) => node.kind === "domain" || node.kind === "subdomain");
  const urls = input.graph.nodes.filter((node) => node.kind === "url");
  const authContexts = input.authContexts ?? [];
  const normalizedApiUrls = urls.filter((node) => node.sources.some((source) => source.includes("api-inventory-normalizer")));
  const normalizedApiRoutes = normalizedApiUrls
    .map(normalizedApiRouteFromNode)
    .filter((route): route is DecisionApiRoute => Boolean(route))
    .sort(compareDecisionApiRoutes);
  const prioritizedApiRouteBriefs = normalizedApiRoutes.slice(0, 8).map(renderDecisionApiRouteBrief);
  const businessPlanningUrls = normalizedApiUrls.length > 0 ? normalizedApiUrls : urls;
  const hasAuthzPlanCoverage = input.toolRuns.some((run) => run.toolId === "authz-plan" && ["success", "no_findings"].includes(run.status));
  const authzPlanSummary = latestAuthzPlanSummary(input.toolRuns);
  const authzPlanHasComparableCandidates = authzPlanSummary
    ? authzPlanSummary.ready + authzPlanSummary.blocked + authzPlanSummary.needsExample > 0
    : true;
  const authzPlanNeedsAuthContexts = authzPlanSummary
    ? authzPlanSummary.blocked > 0 || authzPlanSummary.ready > 0
    : true;
  const authzPlanBlockedByRoleCoverage = Boolean(authzPlanSummary && authzPlanSummary.blocked > 0 && authContexts.length < 2);
  const authzPlanReadyForRoleCompare = Boolean(authzPlanSummary && authzPlanSummary.ready > 0 && authContexts.length >= 2);
  const authzPlanOnlyPassive = Boolean(authzPlanSummary && authzPlanSummary.total > 0 && !authzPlanHasComparableCandidates && authzPlanSummary.passive > 0);
  const scriptUrls = urls.filter((node) => node.sources.some((source) => /script|javascript|js-analyzer/i.test(source)) || /\.js(?:[?#]|$)/i.test(node.value));
  const technologies = input.graph.nodes.flatMap((node) => node.technologies.map((technology) => ({ node, technology })));
  const versionedTechnologies = technologies.filter(({ technology }) => Boolean(technology.version?.trim()));
  const cveCandidates = input.graph.nodes.flatMap((node) => node.cveMatches.map((match) => ({ node, match })));
  const findings = input.graph.nodes.flatMap((node) => node.findings.map((finding) => ({ node, finding })));
  const canEnumerateHostnames = input.target ? supportsHostnameEnumeration(input.target) : true;
  const hasBrowserRecon = hasSuccessfulRun(input.toolRuns, "webapp-recon");
  const businessSensitiveUrls = businessPlanningUrls.filter((node) => hasBusinessWorkflowSignal(node.value));
  const adminLikeUrls = urls.filter((node) => hasAdminSurfaceSignal(node.value));
  const authSurfaceNeedsContext = findings.some(({ finding }) => /Provide at least two approved roles|Capture an authorized Playwright storage-state|register cookie\/header auth context/i.test(`${finding.title} ${finding.evidenceSummary ?? ""}`));
  const hasValidatedAccessControlFinding = findings.some(({ finding }) =>
    /validated|confirmed|safe lab proof observed|lab proof validated/i.test(`${finding.title} ${finding.evidenceSummary ?? ""}`)
    && /authorization bypass|auth(?:entication)? bypass|unauthenticated (?:access|configuration export|admin|management|api)|privileged (?:route|surface|api|exposure)|BOLA|BFLA|IDOR/i.test(`${finding.title} ${finding.evidenceSummary ?? ""}`)
  );
  const serverImpactSignals = [
    ...cveCandidates.filter(({ match }) => match.severity === "critical" || match.severity === "high").map(({ match }) => match.cveId ?? match.title),
    ...findings.filter(({ finding }) => finding.severity === "critical" || finding.severity === "high").map(({ finding }) => finding.title),
    ...input.graph.nodes.filter((node) => node.kind === "service").map((node) => node.value)
  ];

  if (!hasValidatedAccessControlFinding && (businessSensitiveUrls.length > 0 || authSurfaceNeedsContext) && authContexts.length === 0 && (!hasAuthzPlanCoverage || authSurfaceNeedsContext || authzPlanNeedsAuthContexts)) {
    pushDecision(items, {
      priority: "critical",
      phase: "safe_validation",
      actionType: "manual",
      title: "Collect authenticated roles before business-impact testing",
      reason: "Business-logic and authorization bugs cannot be validated from scanner output alone; the agent needs at least two authorized test roles or a confirmed unauthenticated-only boundary.",
      target: prioritizedApiRouteBriefs.slice(0, 5).join(", ") || businessSensitiveUrls.map((node) => node.value).slice(0, 5).join(", ") || target,
      prerequisites: ["Written authorization", "Test accounts or captured browser storage states", "Role/tenant matrix", "No destructive workflow boundary"],
      expectedEvidence: ["Registered auth contexts", "Critical workflow list", "Expected role permissions"]
    }, inventory);
  }

  if (!hasValidatedAccessControlFinding && authzPlanBlockedByRoleCoverage && authContexts.length === 1) {
    pushDecision(items, {
      priority: "critical",
      score: 185,
      phase: "safe_validation",
      actionType: "manual",
      title: "Register a second approved role before authorization comparison",
      reason: `Authorization planning found ${authzPlanSummary?.blocked ?? 0} route(s) blocked by role coverage. One context is registered (${authContexts[0]?.name}:${authContexts[0]?.role ?? "unknown"}), so BOLA/BFLA/IDOR comparison needs a second approved user, role, or tenant before execution.`,
      target: prioritizedApiRouteBriefs.slice(0, 6).join(", ") || target,
      prerequisites: ["Written authorization for both roles/tenants", "Second test account or captured storage state", "Expected permission matrix", "Read-only comparison boundary"],
      expectedEvidence: ["Two distinct auth contexts", "Role/tenant labels", "Base URL alignment", "Expected access policy for high-value routes"]
    }, inventory);
  }

  if (!hasValidatedAccessControlFinding && authzPlanReadyForRoleCompare) {
    pushDecision(items, {
      priority: "critical",
      score: 190,
      phase: "safe_validation",
      actionType: "manual",
      title: "Run read-only cross-role authorization comparison",
      reason: `Authorization planning has ${authzPlanSummary?.ready ?? 0} ready candidate(s) and ${authContexts.length} approved contexts. Compare the highest-scored normalized API examples before additional scanner or CVE validation.`,
      target: prioritizedApiRouteBriefs.slice(0, 6).join(", ") || target,
      fallbackFor: "business-compare",
      prerequisites: ["Two approved auth contexts", "Concrete GET/HEAD API examples", "No mutation replay", "Expected role/tenant access policy"],
      expectedEvidence: ["Per-role status codes", "Redirect/content signatures", "Response hash comparison", "False-positive guard against scanner-only impact"]
    }, inventory);
  }

  if ((businessSensitiveUrls.length > 0 || adminLikeUrls.length > 0) && !hasSuccessfulRun(input.toolRuns, "objective-model") && (!hasAuthzPlanCoverage || !authzPlanOnlyPassive)) {
    pushDecision(items, {
      priority: "critical",
      phase: "safe_validation",
      actionType: "subagent",
      title: "Model goal path beyond scanner results",
      reason: "The graph exposes business or control-plane surfaces; a reasoning step should map how a bug could create business impact, admin control-plane impact, or server risk without executing destructive actions.",
      target: [...businessSensitiveUrls, ...adminLikeUrls].map((node) => node.value).slice(0, 8).join(", ") || target,
      fallbackFor: "objective-model",
      prerequisites: ["Current asset graph", "Known auth contexts if available", "Scope and stop conditions"],
      expectedEvidence: ["Impact hypotheses", "Business workflow assumptions", "Admin boundary assumptions", "Safe validation gates"]
    }, inventory);
  }

  if (serverImpactSignals.length > 0 && !input.scope?.allowActiveProbing) {
    pushDecision(items, {
      priority: "high",
      phase: "safe_validation",
      actionType: "authorization",
      title: "Gate server-impact validation behind explicit scope",
      reason: "Server-impact candidates exist, but privilege escalation, exploit validation, and intrusive probes require written active-testing scope and stop conditions.",
      target: serverImpactSignals.slice(0, 8).join(", "),
      blockedBy: "server-impact validation requires active authorization",
      prerequisites: ["Written active validation authorization", "Allowed host list", "Rate limit", "No persistence/no credential extraction boundary"],
      expectedEvidence: ["Approved validation boundary", "Non-destructive proof plan", "Rollback/stop conditions"]
    }, inventory);
  }

  if (canEnumerateHostnames && hosts.length <= 1 && !hasSuccessfulRun(input.toolRuns, "subfinder")) {
    pushDecision(items, {
      priority: "high",
      phase: "recon",
      actionType: "tool",
      title: "Expand passive subdomain coverage",
      reason: "The graph has only the root host; subdomain enumeration is required before meaningful attack-surface reasoning.",
      target,
      toolId: "subfinder",
      prerequisites: ["Authorized root domain scope"],
      expectedEvidence: ["Discovered subdomains with source metadata"]
    }, inventory);
  }

  if (canEnumerateHostnames && hasUnsuccessfulRun(input.toolRuns, "subfinder") && !hasSuccessfulRun(input.toolRuns, "amass")) {
    pushDecision(items, {
      priority: "medium",
      phase: "recon",
      actionType: "tool",
      title: "Fallback passive enumeration with Amass",
      reason: "subfinder did not produce a successful run; Amass passive mode can provide independent source coverage.",
      target,
      toolId: "amass",
      fallbackFor: "subfinder",
      prerequisites: ["Authorized root domain scope"],
      expectedEvidence: ["Alternative passive subdomain findings"]
    }, inventory);
  }

  if (canEnumerateHostnames && hosts.length > 0 && !hasSuccessfulRun(input.toolRuns, "dnsx")) {
    pushDecision(items, {
      priority: "high",
      phase: "asset_discovery",
      actionType: "tool",
      title: "Resolve hosts and enrich DNS records",
      reason: "Hostnames exist in the graph but DNS resolution evidence is incomplete.",
      target: hosts.map((node) => node.value).slice(0, 5).join(", "),
      toolId: "dnsx",
      prerequisites: ["Passive host list from target or enumeration"],
      expectedEvidence: ["A/AAAA/CNAME records", "Resolved IP assets"]
    }, inventory);
  }

  if (hosts.length > 0 && urls.length === 0 && !hasSuccessfulRun(input.toolRuns, "httpx")) {
    pushDecision(items, {
      priority: "high",
      phase: "fingerprint",
      actionType: "tool",
      title: "Probe live HTTP services",
      reason: "The graph has hosts but no live URL nodes; HTTP probing is the gateway to crawling, fingerprinting, and validation.",
      target: hosts.map((node) => node.value).slice(0, 5).join(", "),
      toolId: "httpx",
      prerequisites: ["Hostnames or IP services within scope"],
      expectedEvidence: ["Live URLs", "Status codes", "Titles", "Servers", "Technologies"]
    }, inventory);
  }

  if (hasUnsuccessfulRun(input.toolRuns, "httpx") && urls.length === 0) {
    pushDecision(items, {
      priority: "medium",
      phase: "fingerprint",
      actionType: "manual",
      title: "Fallback HTTP header probe",
      reason: "httpx was not successful; use the built-in low-risk HTTP header probe to collect minimal live-service evidence.",
      target,
      fallbackFor: "httpx",
      prerequisites: ["At least one URL or domain in scope"],
      expectedEvidence: ["HTTP status", "Security headers", "Server header"]
    }, inventory);
  }

  if (urls.length > 0 && !hasSuccessfulRun(input.toolRuns, "katana") && !hasBrowserRecon) {
    pushDecision(items, {
      priority: "medium",
      phase: "frontend",
      actionType: "tool",
      title: "Crawl live URLs for frontend/API surface",
      reason: "Live URLs exist, but there is no successful crawl evidence for JavaScript, routes, forms, or API endpoints.",
      target: urls.map((node) => node.value).slice(0, 5).join(", "),
      toolId: "katana",
      prerequisites: ["Live URL list"],
      expectedEvidence: ["Routes", "JavaScript files", "API endpoints", "Source-map exposures"]
    }, inventory);
  }

  if (urls.length > 0 && !hasSuccessfulRun(input.toolRuns, "webapp-recon")) {
    pushDecision(items, {
      priority: "high",
      phase: "frontend",
      actionType: "manual",
      title: "Build browser/JS/API application map",
      reason: "A mature web assessment first maps browser-visible pages, runtime network traffic, JavaScript-discovered endpoints, forms, and authentication surface before choosing vulnerability tests.",
      target: urls.map((node) => node.value).slice(0, 3).join(", "),
      fallbackFor: "webapp-recon",
      prerequisites: ["Playwright package installed", "Same-origin scope", "Read-only browsing", "No form submission"],
      expectedEvidence: ["Visited pages", "Runtime XHR/fetch requests", "JavaScript endpoint candidates", "API inventory", "Login/auth surface", "Source-map/secret-like frontend signals"]
    }, inventory);
  }

  if (hasSuccessfulRun(input.toolRuns, "webapp-recon") && !input.toolRuns.some((run) => run.toolId === "api-inventory-normalizer" && ["success", "no_findings"].includes(run.status))) {
    pushDecision(items, {
      priority: "high",
      phase: "frontend",
      actionType: "manual",
      title: "Normalize API inventory into route templates",
      reason: "Browser recon produced raw API/form targets; authorization and business-logic planning should use method/path templates, query parameters, body hints, and source clustering instead of raw URL lists.",
      target: urls.map((node) => node.value).slice(0, 5).join(", ") || target,
      fallbackFor: "api-inventory-normalizer",
      prerequisites: ["WebApp recon artifact", "No active probing", "Evidence-only route clustering"],
      expectedEvidence: ["Normalized API method/path templates", "Query parameter names", "Body parameter hints", "Auth/risk signals", "Source list per endpoint"]
    }, inventory);
  }

  if (scriptUrls.length > 0 && !input.toolRuns.some((run) => run.toolId === "js-analyzer" && ["success", "no_findings"].includes(run.status))) {
    pushDecision(items, {
      priority: "high",
      phase: "frontend",
      actionType: "manual",
      title: "Analyze JavaScript bundles for API and frontend evidence",
      reason: "JavaScript assets are observed, but no structured JS analyzer evidence exists yet. Mature web assessment should extract base URLs, API routes, GraphQL/WebSocket endpoints, source maps, frontend-sensitive hints, and library fingerprints before choosing validation paths.",
      target: scriptUrls.map((node) => node.value).slice(0, 5).join(", "),
      fallbackFor: "js-analyzer",
      prerequisites: ["Observed JavaScript asset URLs", "Same-origin scope", "Passive source retrieval only", "Secret-like values must be redacted"],
      expectedEvidence: ["JS endpoint candidates", "Base URL hints", "GraphQL/WebSocket endpoints", "Source-map metadata", "Frontend library fingerprints", "Redacted sensitive-signal candidates"]
    }, inventory);
  }

  if (hasSuccessfulRun(input.toolRuns, "webapp-recon") && !input.toolRuns.some((run) => run.toolId === "auth-surface-model" && ["success", "no_findings"].includes(run.status))) {
    pushDecision(items, {
      priority: "high",
      phase: "frontend",
      actionType: "manual",
      title: "Model authentication and session surface",
      reason: "Browser recon produced forms, storage, cookies, network requests, and normalized API routes; auth/session state should be summarized before role-aware business logic planning.",
      target,
      fallbackFor: "auth-surface-model",
      prerequisites: ["WebApp recon artifact", "No credential guessing", "Passive evidence only", "Secret-like values must stay redacted"],
      expectedEvidence: ["Auth state", "Session mechanisms", "CSRF signals", "Login/registration/recovery surface", "High-value auth and authorization flows", "Next account/context evidence needed"]
    }, inventory);
  }

  if (normalizedApiUrls.length > 0 && !input.toolRuns.some((run) => run.toolId === "authz-plan" && ["success", "no_findings"].includes(run.status))) {
    pushDecision(items, {
      priority: "critical",
      score: 170 + Math.min(30, normalizedApiRoutes[0]?.score ?? 0),
      phase: "safe_validation",
      actionType: "manual",
      title: "Generate authorization validation candidates from normalized API routes",
      reason: normalizedApiRoutes.length > 0
        ? `Normalized API routes exist with concrete insertion-point evidence; classify BOLA/BFLA/workflow candidates from the highest-value routes first: ${prioritizedApiRouteBriefs.slice(0, 4).join("; ")}.`
        : "Normalized API routes exist; before business-logic delegation or active validation, classify BOLA/BFLA/workflow candidates, object-reference locations, auth-context blockers, and passive-only mutation boundaries from evidence.",
      target: prioritizedApiRouteBriefs.join(", ") || normalizedApiUrls.map((node) => node.value).slice(0, 8).join(", ") || target,
      fallbackFor: "authz-plan",
      prerequisites: ["Normalized API route evidence", "No invented object IDs", "No mutation replay", "Approved auth contexts only when comparison is attempted"],
      expectedEvidence: [
        "BOLA/BFLA/workflow candidate list",
        "Object reference locations from path/query/body evidence",
        "Ready/blocked/passive status",
        "Required auth context and example gaps",
        "False-positive guards"
      ]
    }, inventory);
  }

  if (normalizedApiRoutes.length > 0 && hasAuthzPlanCoverage && (authzPlanSummary?.needsExample ?? 0) > 0) {
    pushDecision(items, {
      priority: "high",
      score: 140 + Math.min(25, normalizedApiRoutes[0]?.score ?? 0),
      phase: "frontend",
      actionType: "manual",
      title: "Collect concrete sample requests for API authorization candidates",
      reason: "The authorization plan found route templates that still lack replayable examples; collect browser/runtime request samples for the specific normalized routes before role comparison or payload testing.",
      target: prioritizedApiRouteBriefs.slice(0, 6).join(", ") || target,
      fallbackFor: "webapp-recon",
      prerequisites: ["Read-only browser/API observation", "Same-origin scope", "Do not invent object IDs or tokens", "Do not submit mutation requests"],
      expectedEvidence: ["Concrete sample URL/request for each candidate", "Observed query/body/header parameter names", "Response status/content type", "Auth/session requirement evidence"]
    }, inventory);
  }

  if (urls.length > 0 && !hasSuccessfulRun(input.toolRuns, "browser-forms") && !hasSuccessfulRun(input.toolRuns, "webapp-recon")) {
    pushDecision(items, {
      priority: "medium",
      phase: "frontend",
      actionType: "manual",
      title: "Explore browser-visible forms and same-origin flows",
      reason: "Crawler output does not capture DOM-only forms, client-side routing, or authenticated UI behavior. A Playwright read-only walk should inventory forms without submitting them.",
      target: urls.map((node) => node.value).slice(0, 3).join(", "),
      fallbackFor: "browser-forms",
      prerequisites: ["Playwright package installed", "Same-origin scope", "No form submission"],
      expectedEvidence: ["Visited page list", "Form actions/methods", "Input names/types", "Login/CSRF observations"]
    }, inventory);
  }

  if (urls.length > 0 && !hasSuccessfulRun(input.toolRuns, "nuclei-tech")) {
    const hasMappedWebEvidence = normalizedApiRoutes.length > 0 || scriptUrls.length > 0 || technologies.length > 0;
    pushDecision(items, {
      priority: hasMappedWebEvidence ? "medium" : "low",
      phase: "vulnerability_analysis",
      actionType: "tool",
      title: "Run low-impact template intelligence",
      reason: hasMappedWebEvidence
        ? "Mapped web/API/technology evidence exists; low-impact nuclei tags can enrich exposure and misconfiguration evidence without active exploit validation."
        : "Only a live URL is known. Treat low-impact template intelligence as lower priority until browser/API mapping or product fingerprint evidence exists.",
      target: urls.map((node) => node.value).slice(0, 5).join(", "),
      toolId: "nuclei-tech",
      prerequisites: ["Live URL list", "Approval for command execution", "Prefer mapped endpoints or product/version hints before broad template execution"],
      expectedEvidence: ["Technology templates", "Exposure templates", "Misconfiguration signals", "Negative evidence if no templates match"]
    }, inventory);
  }

  const serviceNodes = input.graph.nodes.filter((node) => node.kind === "service");
  if ((hosts.length > 0 || serviceNodes.length > 0) && !hasSuccessfulRun(input.toolRuns, "nmap")) {
    pushDecision(items, {
      priority: "medium",
      phase: "fingerprint",
      actionType: "tool",
      title: "Enrich open services with nmap version evidence",
      reason: "Service/version fingerprints improve CVE confidence, but the step is active and must stay approval-gated.",
      target: serviceNodes.map((node) => node.value).concat(hosts.map((node) => node.value)).slice(0, 5).join(", ") || target,
      toolId: "nmap",
      prerequisites: ["Explicit active scanning authorization", "Allowed host list", "Low retry and timeout settings"],
      expectedEvidence: ["Open service banners", "Product/version evidence", "Device/service exposure indicators"]
    }, inventory);
  }

  if (versionedTechnologies.length > 0 && cveCandidates.length === 0) {
    pushDecision(items, {
      priority: "medium",
      phase: "vulnerability_analysis",
      actionType: "manual",
      title: "Run local CVE/framework matching",
      reason: "Concrete product/version evidence is present but no CVE/advisory candidates are linked yet.",
      target: versionedTechnologies.map(({ technology }) => `${technology.name} ${technology.version}`).slice(0, 8).join(", "),
      prerequisites: ["Technology evidence with product and version", "Local advisory knowledge base"],
      expectedEvidence: ["CVE candidates", "Framework advisory candidates", "Confidence rationale"]
    }, inventory);
  } else if (technologies.length > 0 && cveCandidates.length === 0) {
    pushDecision(items, {
      priority: "low",
      phase: "fingerprint",
      actionType: "manual",
      title: "Collect concrete product/version evidence before CVE matching",
      reason: "Technology names without versions are insufficient evidence for targeted CVE matching; first confirm product/version from headers, runtime banners, package metadata, or source artifacts.",
      target: technologies.map(({ technology }) => technology.name).slice(0, 8).join(", "),
      blockedBy: "missing concrete product/version fingerprint",
      prerequisites: ["Observed technology name", "Evidence source that can expose product/version", "No CVE inference from name alone"],
      expectedEvidence: ["Product/version string", "Evidence source URL or artifact", "Confidence rationale for version parsing"]
    }, inventory);
  }

  if (cveCandidates.length > 0 && !input.scope?.allowActiveProbing) {
    pushDecision(items, {
      priority: "high",
      phase: "safe_validation",
      actionType: "authorization",
      title: "Request explicit active-validation authorization",
      reason: "CVE/advisory candidates exist, but exploit validation and active templates are blocked by the current scope.",
      target: cveCandidates.map(({ node }) => node.value).slice(0, 5).join(", "),
      blockedBy: "allowActiveProbing=false",
      prerequisites: ["Written authorization", "Allowed target list", "Rate limit", "Stop conditions"],
      expectedEvidence: ["Approval record", "Validation boundary"]
    }, inventory);
  }

  if ((cveCandidates.length > 0 || findings.some(({ finding }) => finding.severity !== "info")) && input.scope?.allowActiveProbing && !hasSuccessfulRun(input.toolRuns, "nuclei-owasp")) {
    pushDecision(items, {
      priority: cveCandidates.some(({ match }) => match.severity === "critical" || match.severity === "high") ? "critical" : "high",
      phase: "safe_validation",
      actionType: "tool",
      title: "Run approval-gated nuclei validation against candidate exposures",
      reason: "Candidate CVE or vulnerability evidence exists and the current scope allows active, rate-limited validation.",
      target: urls.map((node) => node.value).slice(0, 5).join(", ") || target,
      toolId: "nuclei-owasp",
      prerequisites: ["Explicit active validation authorization", "Allowed target list", "Rate limit", "Low-concurrency nuclei settings"],
      expectedEvidence: ["Validated template matches", "Negative validation evidence", "Template failure classification"]
    }, inventory);
  }

  const blockedActiveChecks = input.checks.filter((check) => check.status === "blocked" && check.activeRequiresApproval);
  if (blockedActiveChecks.length > 0 && !input.scope?.allowActiveProbing) {
    pushDecision(items, {
      priority: "medium",
      phase: "safe_validation",
      actionType: "authorization",
      title: "Unblock active OWASP validation only with scope approval",
      reason: `${blockedActiveChecks.length} validation checks require active testing authorization.`,
      target,
      blockedBy: "active validation disabled",
      prerequisites: ["Authorized testing level", "Request rate", "Account/test data boundaries"],
      expectedEvidence: ["Approved active checks", "Denied checks remain documented"]
    }, inventory);
  }

  const hasAuthOrRestrictedSurface = findings.some(({ finding }) => /401|403|restricted|auth|login/i.test(`${finding.title} ${finding.evidenceSummary ?? ""}`))
    || businessPlanningUrls.some((node) => /login|admin|account|user|api|\{id\}|\{uuid\}/i.test(node.value));
  const hasBusinessLogicCoverage = input.checks.some((check) => check.checkId.startsWith("BL-") && check.status === "observed");
  if ((urls.length > 0 || hasAuthOrRestrictedSurface) && !hasBusinessLogicCoverage && !authzPlanBlockedByRoleCoverage && (normalizedApiUrls.length === 0 || hasAuthzPlanCoverage) && (normalizedApiUrls.length === 0 || authzPlanHasComparableCandidates)) {
    pushDecision(items, {
      priority: "high",
      phase: "safe_validation",
      actionType: "subagent",
      title: normalizedApiUrls.length > 0 ? "Plan business-logic testing from normalized API routes" : "Plan business-logic testing from authenticated flows",
      reason: normalizedApiRoutes.length > 0
        ? `Normalized API method/path templates expose object-scoped, auth-sensitive, and workflow routes for role-aware planning; start from these evidence-backed routes: ${prioritizedApiRouteBriefs.slice(0, 5).join("; ")}.`
        : normalizedApiUrls.length > 0
          ? "Normalized API method/path templates expose object-scoped, auth-sensitive, and workflow routes for role-aware planning; scanners cannot validate business rules reliably."
        : "Business-logic bugs need roles, workflows, and expected authorization rules; scanners cannot validate them reliably.",
      target: prioritizedApiRouteBriefs.slice(0, 5).join(", ") || businessPlanningUrls.map((node) => node.value).slice(0, 5).join(", ") || target,
      prerequisites: ["Test accounts or captured traffic", "Role matrix", "Critical workflows", "No destructive actions"],
      expectedEvidence: ["Normalized API route evidence", "IDOR/BOLA hypotheses", "Function-level authorization matrix", "Workflow abuse cases", "Manual validation checklist"]
    }, inventory);
  }

  if (urls.length > 0 && hasUnsuccessfulRun(input.toolRuns, "katana") && !hasSuccessfulRun(input.toolRuns, "browser-forms")) {
    pushDecision(items, {
      priority: "medium",
      phase: "frontend",
      actionType: "manual",
      title: "Fallback DOM route and form inventory after crawler failure",
      reason: "katana did not produce usable crawl evidence; Playwright can still inventory same-origin pages and DOM forms without submitting data.",
      target: urls.map((node) => node.value).slice(0, 3).join(", "),
      fallbackFor: "katana",
      prerequisites: ["Playwright/browser available", "Same-origin URL list", "No form submission"],
      expectedEvidence: ["DOM-visible routes", "Form inventory", "Login and CSRF observations"]
    }, inventory);
  }

  if (findings.some(({ finding }) => finding.severity === "critical" || finding.severity === "high")) {
    pushDecision(items, {
      priority: "critical",
      phase: "reporting",
      actionType: "manual",
      title: "Triage high-impact findings before additional scanning",
      reason: "High-severity evidence should be confirmed, deduplicated, and bounded before expanding scan breadth.",
      target,
      prerequisites: ["Finding evidence", "Affected asset list"],
      expectedEvidence: ["Reproduction boundary", "Impact statement", "Remediation guidance"]
    }, inventory);
  }

  annotateDecisionAttempts(items, input.toolRuns);
  return {
    generatedAt: nowIso(),
    items: items.sort(compareDecisionQueueItems)
  };
}

export function buildSecurityDecisionSupervision(input: {
  queue: SecurityDecisionQueue;
  toolRuns: SecurityToolRun[];
  graph: SecurityAssetGraph;
  checks?: SecurityValidationCheck[];
}): SecurityDecisionSupervision {
  const progressSignals: string[] = [];
  const stallSignals: string[] = [];
  const recommendedActions: string[] = [];
  const suppressItemIds = new Set<string>();
  const toolRuns = [...input.toolRuns].sort((left, right) => left.createdAt.localeCompare(right.createdAt));
  const recentRuns = toolRuns.slice(-8);
  const repeatedTools: SecurityDecisionSupervision["repeatedTools"] = [];
  const byTool = new Map<string, SecurityToolRun[]>();

  for (const run of toolRuns) {
    byTool.set(run.toolId, [...(byTool.get(run.toolId) ?? []), run]);
  }
  for (const [toolId, runs] of byTool.entries()) {
    const unsuccessful = runs.filter((run) => ["failed", "blocked", "missing", "denied", "skipped", "no_findings"].includes(run.status));
    const successful = runs.some((run) => run.status === "success" && (run.findingCount ?? 0) > 0);
    if (runs.length >= 3 && unsuccessful.length >= 3 && !successful) {
      const last = runs.at(-1);
      if (last) {
        repeatedTools.push({
          toolId,
          attempts: runs.length,
          lastStatus: last.status,
          failureCategory: last.failureCategory
        });
      }
      for (const item of input.queue.items.filter((item) => item.toolId === toolId || item.fallbackFor === toolId)) {
        suppressItemIds.add(item.id);
      }
    }
  }

  const assetCount = input.graph.nodes.length;
  const findingCount = input.graph.nodes.reduce((total, node) => total + node.findings.length, 0);
  const cveCount = input.graph.nodes.reduce((total, node) => total + node.cveMatches.length, 0);
  const completedRuns = toolRuns.filter((run) => run.status === "success" || run.status === "no_findings").length;
  if (assetCount > 0) progressSignals.push(`${assetCount} asset graph node(s) available for planning.`);
  if (findingCount > 0) progressSignals.push(`${findingCount} finding candidate(s) are available for validation.`);
  if (cveCount > 0) progressSignals.push(`${cveCount} CVE/advisory candidate(s) are linked to observed technology.`);
  if (completedRuns > 0) progressSignals.push(`${completedRuns} completed/no-finding tool run(s) provide decision evidence.`);

  const recentNoProgress = recentRuns.length >= 4 && recentRuns.every((run) =>
    ["failed", "blocked", "missing", "denied", "skipped", "no_findings"].includes(run.status) && (run.findingCount ?? 0) === 0
  );
  if (recentNoProgress) {
    stallSignals.push("Recent tool runs did not add findings; switch strategy before repeating scanners.");
    recommendedActions.push("Pivot away from repeated scanner execution; run browser/API flow mapping or subagent review before scheduling more tools.");
  }
  if (repeatedTools.length > 0) {
    stallSignals.push(`Repeated low-value tool attempts: ${repeatedTools.map((tool) => `${tool.toolId}x${tool.attempts}`).join(", ")}.`);
  }
  const blockedActiveChecks = (input.checks ?? []).filter((check) => check.status === "blocked" && check.activeRequiresApproval);
  if (blockedActiveChecks.length > 0) {
    stallSignals.push(`${blockedActiveChecks.length} active validation check(s) are blocked by scope.`);
    recommendedActions.push("Keep active validation blocked until written scope allows it, or collect more passive/browser evidence for the same hypotheses.");
  }

  for (const tool of repeatedTools) {
    if (tool.failureCategory === "template_error") {
      recommendedActions.push(`Stop repeating ${tool.toolId}; sync templates or narrow template tags before retry.`);
    } else if (tool.failureCategory === "network_error") {
      recommendedActions.push(`Stop repeating ${tool.toolId}; lower concurrency, verify reachability, or use browser/header fallback.`);
    } else if (tool.lastStatus === "missing") {
      recommendedActions.push(`Install or configure ${tool.toolId} before scheduling it again.`);
    } else if (tool.lastStatus === "no_findings") {
      recommendedActions.push(`Treat ${tool.toolId} no-findings as negative evidence and pivot to browser/business-logic analysis.`);
    }
  }
  if (input.queue.items.some((item) => item.actionType === "subagent" && !item.blockedBy)) {
    recommendedActions.push("Use a role-specialized subagent to review scanner blind spots and define the next safe validation step.");
  }
  if (input.graph.nodes.some((node) => node.value.match(/\/(?:api|admin|account|order|user|graphql|swagger|openapi)(?:\/|\?|$)/i))) {
    recommendedActions.push("Prioritize authenticated browser/API flow mapping over broader unauthenticated scanning.");
  }
  if (recommendedActions.length === 0) {
    recommendedActions.push("Continue with the highest-scored unblocked decision queue item.");
  }

  const level: SecurityDecisionSupervision["level"] = repeatedTools.some((tool) => tool.attempts >= 5)
    ? "ask_user"
    : stallSignals.length > 0
      ? "reflect"
      : "continue";
  return {
    generatedAt: nowIso(),
    level,
    summary: level === "continue"
      ? "Decision loop can continue with current evidence."
      : "Decision loop needs strategy adjustment before repeating low-value actions.",
    progressSignals,
    stallSignals,
    repeatedTools,
    recommendedActions: [...new Set(recommendedActions)],
    suppressItemIds: [...suppressItemIds]
  };
}

export function buildSecurityObjectiveModel(input: {
  target?: TargetInput;
  graph: SecurityAssetGraph;
  queue: SecurityDecisionQueue;
  toolRuns: SecurityToolRun[];
  checks?: SecurityValidationCheck[];
  authContexts?: SecurityAuthContext[];
  scope?: PentestScope;
}): SecurityObjectiveModel {
  const target = input.target?.normalized ?? input.graph.nodes[0]?.value ?? "unknown";
  const urls = input.graph.nodes.filter((node) => node.kind === "url");
  const normalizedApiUrls = urls.filter((node) => node.sources.some((source) => source.includes("api-inventory-normalizer")));
  const businessPlanningUrls = normalizedApiUrls.length > 0 ? normalizedApiUrls : urls;
  const services = input.graph.nodes.filter((node) => node.kind === "service");
  const findings = input.graph.nodes.flatMap((node) => node.findings.map((finding) => ({ node, finding })));
  const cveMatches = input.graph.nodes.flatMap((node) => node.cveMatches.map((match) => ({ node, match })));
  const authContexts = input.authContexts ?? [];
  const checks = input.checks ?? [];
  const activeAllowed = Boolean(input.scope?.allowActiveProbing);

  const businessEvidence = uniqueStrings([
    ...businessPlanningUrls.filter((node) => hasBusinessWorkflowSignal(node.value)).map((node) => `business route: ${node.value}`),
    ...findings.filter(({ finding }) => /business|idor|bola|authorization|role|tenant|workflow|price|refund|order|payment/i.test(`${finding.title} ${finding.evidenceSummary ?? ""}`)).map(({ finding }) => `finding: ${finding.title}`),
    ...checks.filter((check) => check.checkId.startsWith("BL-") && check.status !== "pending").map((check) => `${check.status}: ${check.title}`),
    ...authContexts.map((context) => `auth context: ${context.name}${context.role ? ` (${context.role})` : ""}`)
  ]).slice(0, 10);
  const adminEvidence = uniqueStrings([
    ...businessPlanningUrls.filter((node) => hasAdminSurfaceSignal(node.value)).map((node) => `control-plane route: ${node.value}`),
    ...findings.filter(({ finding }) => /admin|login|auth|403|401|restricted|dashboard|console/i.test(`${finding.title} ${finding.evidenceSummary ?? ""}`)).map(({ finding }) => `finding: ${finding.title}`),
    ...input.graph.nodes.flatMap((node) => node.technologies)
      .filter((technology) => /shiro|spring security|cas|keycloak|oauth|sso|ruoyi|jeecg|cms/i.test(`${technology.name} ${technology.category ?? ""}`))
      .map((technology) => `auth/control technology: ${technology.name}${technology.version ? ` ${technology.version}` : ""}`),
    ...authContexts.filter((context) => /admin|manager|operator|staff|后台|管理/i.test(`${context.name} ${context.role ?? ""}`)).map((context) => `privileged auth context: ${context.name}`)
  ]).slice(0, 10);
  const serverEvidence = uniqueStrings([
    ...services.map((node) => `service: ${node.value}`),
    ...cveMatches.filter(({ match }) => match.severity === "critical" || match.severity === "high").map(({ match }) => `candidate: ${match.cveId ?? match.title} (${match.severity}/${match.confidence})`),
    ...findings.filter(({ finding }) => /rce|deserialization|upload|ssrf|path traversal|file write|shell|server|critical/i.test(`${finding.title} ${finding.evidenceSummary ?? ""}`)).map(({ finding }) => `finding: ${finding.title}`)
  ]).slice(0, 10);

  const business = buildObjectiveAssessment({
    id: "business_logic_impact",
    title: "Business logic impact",
    baseScore: 35,
    evidence: businessEvidence,
    hasAuthContext: authContexts.length > 0,
    activeAllowed,
    mappedQueueItemIds: input.queue.items.filter((item) => /business|role|workflow|auth/i.test(`${item.title} ${item.reason}`)).map((item) => item.id),
    contextBlockers: authContexts.length === 0 ? ["No authenticated user/role context is registered."] : [],
    activeBlockers: [],
    nextQuestions: [
      "Which workflows are in scope: order, payment, refund, invite, approval, tenant switching, file sharing, or admin operations?",
      "Can you provide at least two authorized test accounts with different roles or tenants?",
      "Which state-changing actions are explicitly forbidden during testing?"
    ],
    nextActions: [
      "Map critical workflow routes and required roles before running more scanners.",
      "Run read-only cross-role response comparison on high-value routes.",
      "Turn scanner and browser findings into business-rule hypotheses with explicit false-positive guards."
    ],
    validationBoundaries: [
      "Default to read-only requests and response comparison.",
      "Do not place orders, issue refunds, send emails, delete data, or change privileges without explicit active scope.",
      "Use test accounts and test data only."
    ]
  });
  const admin = buildObjectiveAssessment({
    id: "admin_control_plane",
    title: "Admin/control-plane access path",
    baseScore: 30,
    evidence: adminEvidence,
    hasAuthContext: authContexts.some((context) => /admin|manager|operator|staff|后台|管理/i.test(`${context.name} ${context.role ?? ""}`)),
    activeAllowed,
    mappedQueueItemIds: input.queue.items.filter((item) => /admin|auth|login|control|role/i.test(`${item.title} ${item.reason}`)).map((item) => item.id),
    contextBlockers: authContexts.length === 0 ? ["No login/session context is available for authenticated control-plane mapping."] : [],
    activeBlockers: [],
    nextQuestions: [
      "Is backend/admin testing authorized for this target?",
      "Do you have a low-privileged account and an admin/test-operator account for comparison?",
      "Are brute force, password reset testing, invite abuse, and privilege-change operations allowed or forbidden?"
    ],
    nextActions: [
      "Inventory login, admin, account, API, and permission-management routes with browser state.",
      "Build a function-level authorization matrix and compare low-privileged versus privileged responses.",
      "Prefer bypass and authorization evidence over credential guessing."
    ],
    validationBoundaries: [
      "No credential theft, password spraying, brute force, or session hijacking.",
      "No privilege changes or account takeover attempts without explicit written approval.",
      "Admin impact must be proven by authorized role comparison or non-destructive access-control evidence."
    ]
  });
  const server = buildObjectiveAssessment({
    id: "server_control_plane",
    title: "Server control-plane risk path",
    baseScore: 20,
    evidence: serverEvidence,
    hasAuthContext: true,
    activeAllowed,
    mappedQueueItemIds: input.queue.items.filter((item) => /cve|server|service|nmap|nuclei|validation|rce/i.test(`${item.title} ${item.reason}`)).map((item) => item.id),
    contextBlockers: [],
    activeBlockers: !activeAllowed && serverEvidence.length > 0 ? ["Server-impact validation is blocked until active scope is explicitly enabled."] : [],
    nextQuestions: [
      "Is active exploit validation allowed, and what proof level is acceptable without persistence or data access?",
      "Which hosts, ports, and environments are explicitly in scope?",
      "What are the stop conditions if a server-impact signal appears credible?"
    ],
    nextActions: [
      "Improve version confidence before any server-impact validation.",
      "Deduplicate CVE candidates and prefer exact product/version evidence.",
      "If authorized, run low-rate, non-destructive validation templates before any manual exploitation."
    ],
    validationBoundaries: [
      "No persistence, lateral movement, credential extraction, destructive payloads, or data exfiltration.",
      "Use non-destructive proof and stop after impact is established.",
      "Require explicit active authorization and rate limits."
    ]
  });
  const objectives = [business, admin, server].sort((left, right) => right.score - left.score);
  const attackPaths = buildAttackPathModels(objectives);
  const requiredUserContext = uniqueStrings(objectives.flatMap((objective) => objective.nextQuestions).slice(0, 8));
  const nextBestActions = uniqueStrings(objectives.flatMap((objective) => objective.nextActions).slice(0, 8));
  const overallStatus = deriveOverallObjectiveStatus(objectives);
  return {
    target,
    generatedAt: nowIso(),
    overallStatus,
    summary: summarizeObjectiveModel(objectives, overallStatus),
    objectives,
    attackPaths,
    nextBestActions,
    requiredUserContext
  };
}

export function buildBusinessWorkflowGraph(input: {
  target?: TargetInput;
  graph: SecurityAssetGraph;
  checks?: SecurityValidationCheck[];
  authContexts?: SecurityAuthContext[];
}): BusinessWorkflowGraph {
  const target = input.target?.normalized ?? input.graph.nodes[0]?.value ?? "unknown";
  const authContexts = input.authContexts ?? [];
  const urlNodes = input.graph.nodes.filter((node) => node.kind === "url");
  const normalizedApiNodes = urlNodes.filter((node) => node.sources.some((source) => source.includes("api-inventory-normalizer")));
  const urls = (normalizedApiNodes.length > 0 ? normalizedApiNodes : urlNodes).map((node) => node.value);
  const nodes = uniqueStrings(urls)
    .map((url): BusinessWorkflowGraphNode => {
      const category = categorizeBusinessWorkflow(url);
      const signals = workflowSignals(url);
      const sensitivity = workflowSensitivity(category, signals);
      return {
        id: `wf-${createStableSlug(url)}`,
        url,
        category,
        sensitivity,
        signals,
        requiredRoles: requiredRolesForWorkflow(category),
        stateInvariants: stateInvariantsForWorkflow(category, signals),
        safeValidationIdeas: safeValidationIdeasForWorkflow(category),
        activeValidationBoundaries: activeValidationBoundariesForWorkflow(category)
      };
    })
    .filter((node) => node.category !== "unknown" || node.signals.length > 0)
    .sort((left, right) => workflowSensitivityRank(right.sensitivity) - workflowSensitivityRank(left.sensitivity) || left.url.localeCompare(right.url));
  const edges: BusinessWorkflowGraphEdge[] = [];
  for (let leftIndex = 0; leftIndex < nodes.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < nodes.length; rightIndex += 1) {
      const left = nodes[leftIndex];
      const right = nodes[rightIndex];
      if (!left || !right) continue;
      if (left.category === right.category && left.category !== "unknown") {
        edges.push({
          from: left.id,
          to: right.id,
          relation: "same_category",
          rationale: `Both routes map to ${left.category} workflow coverage.`
        });
      } else if ((left.category === "admin" && right.category !== "admin") || (right.category === "admin" && left.category !== "admin")) {
        edges.push({
          from: left.id,
          to: right.id,
          relation: "admin_pivot",
          rationale: "Admin/control-plane route should be compared against business workflow authorization expectations."
        });
      } else if (left.signals.some((signal) => right.signals.includes(signal))) {
        edges.push({
          from: left.id,
          to: right.id,
          relation: "state_transition",
          rationale: "Routes share business-state signals and may belong to the same workflow state machine."
        });
      }
    }
  }
  const roleMatrix = authContexts.map((context) => ({
    role: context.role ?? context.name,
    contextName: context.name,
    baseUrl: context.baseUrl,
    coverage: uniqueStrings(nodes
      .filter((node) => context.baseUrl ? sameOriginOrPath(context.baseUrl, node.url) : true)
      .map((node) => node.category)) as BusinessWorkflowCategory[]
  }));
  const gaps: string[] = [];
  if (nodes.length === 0) gaps.push("No business workflow routes are mapped yet; run browser/form/API discovery first.");
  if (authContexts.length === 0) gaps.push("No authenticated context is available for role-aware business testing.");
  if (authContexts.length === 1) gaps.push("Only one role is registered; cross-role authorization comparison needs at least two contexts.");
  if (!nodes.some((node) => node.category === "commerce" || node.category === "approval" || node.category === "tenant")) {
    gaps.push("No high-value commerce, approval, or tenant workflow has been identified yet.");
  }
  const nextActions = uniqueStrings([
    authContexts.length < 2 ? "Register at least two authorized roles/tenants for read-only comparison." : "Run read-only cross-role comparison on high-sensitivity workflow nodes.",
    nodes.length === 0 ? "Run browser form exploration or crawler evidence import to build workflow nodes." : "Convert top workflow nodes into expected role/state rules before active testing.",
    "Capture no-submit browser request metadata for forms and buttons before any state-changing validation.",
    "Record expected business invariants: owner, tenant, amount, status transition, and approval role."
  ]);
  return {
    target,
    generatedAt: nowIso(),
    nodes,
    edges: uniqueBy(edges, (edge) => `${edge.from}:${edge.to}:${edge.relation}`),
    roleMatrix,
    gaps,
    nextActions
  };
}

export function buildBrowserInteractionPlan(input: {
  target?: TargetInput;
  workflowGraph: BusinessWorkflowGraph;
  authContexts?: SecurityAuthContext[];
}): BrowserInteractionPlan {
  const target = input.target?.normalized ?? input.workflowGraph.target;
  const authContexts = input.authContexts ?? [];
  const loginState: BrowserInteractionPlan["loginState"] = authContexts.length === 0
    ? "missing"
    : authContexts.length === 1
      ? "single_role"
      : "multi_role";
  const highValue = input.workflowGraph.nodes.filter((node) => node.sensitivity !== "low");
  const comparisons: BrowserInteractionPlan["multiRoleComparisons"] = [];
  for (let leftIndex = 0; leftIndex < authContexts.length; leftIndex += 1) {
    for (let rightIndex = leftIndex + 1; rightIndex < authContexts.length; rightIndex += 1) {
      const left = authContexts[leftIndex];
      const right = authContexts[rightIndex];
      if (!left || !right) continue;
      comparisons.push({
        left: left.name,
        right: right.name,
        categories: uniqueStrings(highValue.map((node) => node.category)).slice(0, 6) as BusinessWorkflowCategory[],
        reason: "Compare status, redirect, content hash, and sensitive UI/API availability without submitting forms."
      });
    }
  }
  const replayQueue = highValue.slice(0, 12).map((node) => ({
    routeId: node.id,
    category: node.category,
    requestClass: browserRequestClassForWorkflow(node),
    action: node.sensitivity === "high"
      ? "Capture request metadata and compare role-visible response signatures before any mutation."
      : "Read route with each registered role and compare status, redirect, and content hash.",
    requiredAuthorization: browserReplayAuthorizationForWorkflow(node)
  }));
  const gaps: string[] = [];
  if (authContexts.length === 0) gaps.push("No browser login/storage state is registered.");
  if (authContexts.length < 2) gaps.push("Multi-role browser comparison cannot run until another role is registered.");
  if (highValue.length === 0) gaps.push("No sensitive browser workflow nodes are available yet.");
  return {
    target,
    generatedAt: nowIso(),
    authContexts: authContexts.map((context) => ({
      name: context.name,
      role: context.role,
      username: context.username,
      baseUrl: context.baseUrl,
      storageStatePath: context.storageStatePath
    })),
    loginState,
    loginPlaybooks: authContexts.map((context) => ({
      authContextName: context.name,
      loginUrl: context.baseUrl,
      successSignal: context.storageStatePath
        ? "Storage state file exists and can be loaded before exploration."
        : "Manual login or imported cookie/header context is registered.",
      secretHandling: "Never persist plaintext passwords; store only storage-state path or redacted cookie/header metadata."
    })),
    noSubmitRequestClasses: [
      { method: "GET", disposition: "allow", reason: "Read-only navigation and static/API reads are allowed for same-origin scoped pages." },
      { method: "HEAD", disposition: "allow", reason: "Header-only reads are low impact and useful for fingerprinting." },
      { method: "OPTIONS", disposition: "capture_only", reason: "CORS/preflight metadata can be captured, but broad replay should be avoided." },
      { method: "POST", disposition: "capture_only", reason: "POST is captured for shape and endpoint mapping; submission is blocked by default." },
      { method: "PUT/PATCH/DELETE", disposition: "block", reason: "Mutation methods require explicit active authorization and test-data boundaries." }
    ],
    noSubmitCapture: [
      "Instrument request/response metadata and block form submission by default.",
      "Record form action, method, input names, CSRF token presence, and same-origin API calls.",
      "Capture screenshots only when useful; avoid storing sensitive page bodies by default."
    ],
    replayBoundaries: [
      "GET/HEAD and static resource requests are safe by default.",
      "POST/PUT/PATCH/DELETE, payment/refund/order/admin mutations require explicit active authorization.",
      "Never replay credential, password reset, destructive, or privilege-changing requests without written scope."
    ],
    multiRoleComparisons: comparisons,
    replayQueue,
    gaps,
    nextActions: uniqueStrings([
      authContexts.length === 0 ? "Capture or register a Playwright storage-state auth context." : "Run no-submit browser exploration with the registered auth context.",
      authContexts.length >= 2 ? "Run cross-role browser/API response comparison for high-sensitivity workflow nodes." : "Register a second authorized role for comparison.",
      "Build reusable login script metadata after a manual login is captured.",
      "Promote browser-observed sensitive actions into business workflow graph nodes."
    ])
  };
}

export function buildValidationClosurePlan(input: {
  objectiveModel: SecurityObjectiveModel;
  workflowGraph: BusinessWorkflowGraph;
  findings: SecurityFinding[];
  cveMatches: SecurityCveMatch[];
  evidence: SecurityEvidence[];
  attempts: SecurityValidationAttempt[];
  authContexts?: SecurityAuthContext[];
  scope?: PentestScope;
}): ValidationClosurePlan {
  const attempted = new Map(input.attempts.map((attempt) => [`${attempt.targetKind}:${attempt.targetId}`, attempt]));
  const evidenceFor = (needle: string): string[] => {
    const lower = needle.toLowerCase();
    return input.evidence
      .filter((item) => `${item.source}\n${item.summary}\n${item.data ?? ""}`.toLowerCase().includes(lower))
      .map((item) => item.id)
      .slice(0, 8);
  };
  const candidates: ValidationClosureCandidate[] = [];
  for (const finding of input.findings) {
    const attempt = attempted.get(`finding:${finding.id}`);
    const evidenceIds = uniqueStrings([...(finding.evidenceIds ?? []), ...evidenceFor(finding.title), ...evidenceFor(finding.target)]).slice(0, 8);
    candidates.push({
      id: `finding:${finding.id}`,
      kind: "finding",
      targetId: finding.id,
      title: finding.title,
      target: finding.target,
      priority: priorityForSeverity(finding.severity),
      confidence: finding.confidence,
      state: attempt ? validationStateFromAttempt(attempt) : evidenceIds.length > 0 ? "ready" : "needs_context",
      evidenceIds,
      verificationStrategy: strategyForFinding(finding),
      falsePositiveGuards: falsePositiveGuardsForTitle(`${finding.title} ${finding.description}`),
      nextAction: attempt ? `Review recorded validation ${attempt.id}.` : "Correlate independent evidence and run non-destructive reproduction where possible."
    });
  }
  for (const match of input.cveMatches) {
    const attempt = attempted.get(`cve:${match.id}`);
    const evidenceIds = uniqueStrings([...(evidenceFor(match.cveId ?? match.title)), ...evidenceFor(match.technology), ...evidenceFor(match.target)]).slice(0, 8);
    const blockedBy = !input.scope?.allowActiveProbing && (match.severity === "critical" || match.severity === "high")
      ? "active validation disabled"
      : undefined;
    candidates.push({
      id: `cve:${match.id}`,
      kind: "cve",
      targetId: match.id,
      title: match.cveId ? `${match.cveId} ${match.title}` : match.title,
      target: match.target,
      priority: priorityForSeverity(match.severity),
      confidence: match.confidence,
      state: attempt ? validationStateFromAttempt(attempt) : blockedBy ? "blocked" : match.confidence === "high" || evidenceIds.length >= 2 ? "ready" : "needs_context",
      evidenceIds,
      verificationStrategy: match.confidence === "high"
        ? "Confirm exact product/version and run approval-gated non-destructive template if scope allows."
        : "Collect stronger version evidence before active validation.",
      falsePositiveGuards: [
        "Require exact product and version or explicit template fingerprint.",
        "Suppress aliases and generic technology-only matches.",
        "Treat no-finding template output as negative evidence, not proof of absence."
      ],
      nextAction: blockedBy ? "Request active validation scope or keep as unvalidated candidate." : "Run version confirmation and non-destructive validation planning.",
      blockedBy
    });
  }
  for (const objective of input.objectiveModel.objectives) {
    if (objective.status === "validated_impact") continue;
    candidates.push({
      id: `objective:${objective.id}`,
      kind: "objective",
      targetId: objective.id,
      title: objective.title,
      target: input.objectiveModel.target,
      priority: objective.score >= 80 ? "critical" : objective.score >= 60 ? "high" : "medium",
      confidence: objective.confidence,
      state: objective.status === "blocked_by_scope" ? "blocked" : objective.status === "needs_context" ? "needs_context" : "ready",
      evidenceIds: [],
      verificationStrategy: objective.validationBoundaries.join(" "),
      falsePositiveGuards: objective.validationBoundaries,
      nextAction: objective.nextActions[0] ?? "Collect more objective evidence.",
      blockedBy: objective.status === "blocked_by_scope" ? objective.blockers[0] : undefined
    });
  }
  const sorted = uniqueBy(candidates, (candidate) => candidate.id)
    .sort((left, right) =>
      validationCandidateStateRank(left.state) - validationCandidateStateRank(right.state)
      || validationCandidateKindRank(left.kind) - validationCandidateKindRank(right.kind)
      || closurePriorityRank(left.priority) - closurePriorityRank(right.priority)
      || confidenceRankValue(right.confidence) - confidenceRankValue(left.confidence)
    );
  const next = sorted.find((candidate) => candidate.state === "ready") ?? sorted.find((candidate) => candidate.state === "needs_context") ?? sorted[0];
  const status: ValidationClosurePlan["status"] = sorted.length === 0
    ? "settled"
    : sorted.some((candidate) => candidate.state === "ready")
      ? "ready"
      : sorted.some((candidate) => candidate.state === "needs_context")
        ? "needs_context"
        : sorted.every((candidate) => candidate.state === "blocked")
          ? "blocked"
          : "settled";
  return {
    generatedAt: nowIso(),
    status,
    summary: next ? `Next validation candidate: ${next.title} (${next.state}/${next.confidence}).` : "No validation candidates remain.",
    candidates: sorted,
    nextCandidateId: next?.id,
    finalizationRules: [
      "Promote to validated only when at least two independent evidence sources or a scoped safe reproduction support impact.",
      "Mark false positive when version/routing/role evidence contradicts the candidate or a safe check disproves access.",
      "Keep as needs_validation when evidence is single-source, scanner-only, or missing expected business rules.",
      "Do not use destructive exploitation, credential theft, persistence, lateral movement, or data exfiltration as proof."
    ]
  };
}

export function buildAuthorizedValidationPlaybook(input: {
  target?: TargetInput;
  validationPlan: ValidationClosurePlan;
  workflowGraph: BusinessWorkflowGraph;
  browserPlan: BrowserInteractionPlan;
  cveReconciliation: CveReconciliationPlan;
  scope?: PentestScope;
  authContexts?: SecurityAuthContext[];
}): AuthorizedValidationPlaybook {
  const target = input.target?.normalized ?? input.workflowGraph.target;
  const activeAllowed = Boolean(input.scope?.allowActiveProbing);
  const mode: AuthorizedValidationPlaybook["mode"] = activeAllowed ? "active" : input.scope?.intensity === "passive" ? "passive" : "safe";
  const authContexts = input.authContexts ?? [];
  const steps = input.validationPlan.candidates
    .filter((candidate) => candidate.state === "ready" || candidate.state === "needs_context" || candidate.state === "blocked")
    .flatMap((candidate) => validationStepsForCandidate({
      candidate,
      target,
      activeAllowed,
      authContextCount: authContexts.length,
      workflowGraph: input.workflowGraph,
      browserPlan: input.browserPlan,
      cveReconciliation: input.cveReconciliation
    }))
    .sort(compareAuthorizedValidationSteps);
  const next = steps.find((step) => step.status === "ready") ?? steps.find((step) => step.status === "needs_context") ?? steps[0];
  const status: AuthorizedValidationPlaybook["status"] = steps.length === 0
    ? "empty"
    : steps.some((step) => step.status === "ready")
      ? "ready"
      : steps.some((step) => step.status === "needs_context")
        ? "needs_context"
        : "blocked";
  return {
    generatedAt: nowIso(),
    target,
    mode,
    status,
    summary: next
      ? `Next authorized validation step: ${next.title} (${next.status}/${next.risk}).`
      : "No authorized validation steps are available.",
    steps,
    nextStepId: next?.id,
    evidenceContract: [
      "Every validation step must produce target, timestamp, scope, method, observed result, and false-positive guard evidence.",
      "Validated findings require independent evidence or a scoped safe reproduction; scanner-only output remains needs_validation.",
      "Negative or no-finding tool output is recorded as evidence for confidence reduction, not silently discarded.",
      "Sensitive values are redacted; do not store credentials, raw tokens, private data, or full response bodies by default."
    ],
    globalStopConditions: [
      "Stop and ask the user if the next step would modify production data, change privileges, send messages, process payment/refund, or exceed rate/scope limits.",
      "Stop after proving impact at the agreed proof level; do not continue into persistence, lateral movement, credential extraction, or data exfiltration.",
      "Stop when target ownership or authorization boundary is unclear."
    ],
    prohibitedActions: prohibitedValidationActions()
  };
}

export function buildCveReconciliationPlan(input: {
  technologies: SecurityTechnology[];
  cveMatches: SecurityCveMatch[];
  attempts?: SecurityValidationAttempt[];
}): CveReconciliationPlan {
  const byKey = new Map<string, SecurityCveMatch[]>();
  for (const match of input.cveMatches) {
    const key = `${normalizeTargetForDedupe(match.target)}:${normalizeName(stripVersion(match.technology))}:${(match.cveId ?? match.title).toUpperCase()}`;
    byKey.set(key, [...(byKey.get(key) ?? []), match]);
  }
  const duplicateGroups: CveReconciliationPlan["duplicateGroups"] = [];
  const suppressedCandidates: string[] = [];
  for (const [key, matches] of byKey.entries()) {
    if (matches.length < 2) continue;
    const preferred = [...matches].sort((left, right) =>
      confidenceRankValue(right.confidence) - confidenceRankValue(left.confidence)
      || severityRankValue(right.severity) - severityRankValue(left.severity)
      || left.createdAt.localeCompare(right.createdAt)
    )[0];
    if (!preferred) continue;
    duplicateGroups.push({
      key,
      ids: matches.map((match) => match.id),
      preferredId: preferred.id,
      reason: "Same target, normalized technology, and CVE/advisory identity; keep highest confidence/severity candidate."
    });
    suppressedCandidates.push(...matches.filter((match) => match.id !== preferred.id).map((match) => match.id));
  }
  const versionGaps = input.cveMatches
    .filter((match) => match.confidence !== "high")
    .filter((match) => !input.technologies.some((technology) =>
      normalizeTargetForDedupe(technology.target) === normalizeTargetForDedupe(match.target)
      && normalizeName(technology.name) === normalizeName(stripVersion(match.technology))
      && Boolean(technology.version)
    ))
    .map((match) => ({
      cveId: match.cveId,
      technology: match.technology,
      target: match.target,
      reason: "No exact version evidence is linked to this candidate."
    }));
  const confidenceAdjustments = input.cveMatches
    .filter((match) => !suppressedCandidates.includes(match.id))
    .map((match) => {
      const relatedTechnology = input.technologies.find((technology) =>
        normalizeTargetForDedupe(technology.target) === normalizeTargetForDedupe(match.target)
        && normalizeName(technology.name) === normalizeName(stripVersion(match.technology))
        && Boolean(technology.version)
      );
      const attempted = input.attempts?.find((attempt) => attempt.targetKind === "cve" && attempt.targetId === match.id);
      const nextConfidence = attempted?.status === "ruled_out"
        ? "low"
        : attempted?.status === "validated"
          ? "high"
          : relatedTechnology && match.confidence === "medium"
            ? "high"
            : !relatedTechnology && match.confidence === "high"
              ? "medium"
              : match.confidence;
      return nextConfidence === match.confidence ? undefined : {
        candidateId: match.id,
        from: match.confidence,
        to: nextConfidence,
        reason: attempted?.status === "validated"
          ? "A scoped validation attempt confirmed the candidate."
          : attempted?.status === "ruled_out"
            ? "A scoped validation attempt ruled out the candidate."
            : relatedTechnology
              ? `Exact version evidence is linked: ${relatedTechnology.name} ${relatedTechnology.version}.`
              : "High confidence was downgraded because exact version evidence is missing."
      };
    })
    .filter((item): item is CveReconciliationPlan["confidenceAdjustments"][number] => Boolean(item));
  const validationReady = input.cveMatches
    .filter((match) => !suppressedCandidates.includes(match.id))
    .filter((match) => {
      const adjusted = confidenceAdjustments.find((item) => item.candidateId === match.id);
      return (adjusted?.to ?? match.confidence) === "high";
    })
    .map((match) => match.id);
  const status: CveReconciliationPlan["status"] = duplicateGroups.length > 0
    ? "dedupe_needed"
    : versionGaps.length > 0
      ? "needs_version_evidence"
      : validationReady.length > 0
        ? "validation_ready"
        : "clean";
  return {
    generatedAt: nowIso(),
    status,
    duplicateGroups,
    versionGaps,
    validationReady,
    suppressedCandidates: uniqueStrings(suppressedCandidates),
    confidenceAdjustments,
    nextActions: uniqueStrings([
      duplicateGroups.length > 0 ? "Suppress duplicate CVE candidates and preserve the highest-confidence record." : undefined,
      versionGaps.length > 0 ? "Run version-focused fingerprinting before scheduling CVE validation." : undefined,
      confidenceAdjustments.length > 0 ? "Apply CVE confidence adjustments before choosing the next active validation candidate." : undefined,
      validationReady.length > 0 ? "Prioritize high-confidence, version-backed CVEs for approval-gated non-destructive validation." : undefined,
      "Treat generic framework advisory reviews as prompts for fingerprinting, not confirmed vulnerabilities."
    ].filter((item): item is string => Boolean(item)))
  };
}

export function buildSubAgentOperatingModel(input: {
  subagents: SubAgentRecord[];
  queue: SecurityDecisionQueue;
  objectiveModel: SecurityObjectiveModel;
}): SubAgentOperatingModel {
  const capacity = {
    queued: input.subagents.filter((agent) => agent.status === "queued").length,
    running: input.subagents.filter((agent) => agent.status === "running").length,
    completed: input.subagents.filter((agent) => agent.status === "completed").length,
    failed: input.subagents.filter((agent) => agent.status === "failed").length
  };
  const roles: SubAgentRole[] = ["recon", "frontend", "fingerprint", "cve", "web_vuln", "reviewer"];
  const roleCoverage = roles.map((role) => {
    const roleAgents = input.subagents.filter((agent) => agent.role === role);
    const completed = roleAgents.filter((agent) => agent.status === "completed").length;
    const running = roleAgents.filter((agent) => agent.status === "running").length;
    const queued = roleAgents.filter((agent) => agent.status === "queued").length;
    return {
      role,
      completed,
      running,
      queued,
      gap: completed + running + queued === 0 && needsRoleForObjective(role, input.objectiveModel, input.queue)
        ? `No ${role} subagent has covered the current objective/queue evidence.`
        : undefined
    };
  });
  const retryQueue = input.subagents
    .filter((agent) => agent.status === "failed" && (agent.retryCount ?? 0) < (agent.maxRetries ?? 0))
    .map((agent) => agent.id);
  const arbitrationNeeds = detectSubAgentOperatingContradictions(input.subagents);
  const status: SubAgentOperatingModel["status"] = capacity.running > 0
    ? "healthy"
    : capacity.queued > 4
      ? "backlogged"
      : capacity.failed > 0 && retryQueue.length === 0
        ? "stalled"
        : capacity.queued + capacity.completed + capacity.failed === 0
          ? "idle"
          : "healthy";
  return {
    generatedAt: nowIso(),
    status,
    capacity,
    roleCoverage,
    retryQueue,
    arbitrationNeeds,
    nextActions: uniqueStrings([
      roleCoverage.some((role) => role.gap) ? "Enqueue missing role-specialized subagents for uncovered objective paths." : undefined,
      capacity.queued > 0 ? "Dispatch queued subagents with bounded concurrency and heartbeat recovery." : undefined,
      capacity.failed > 0 ? "Retry or arbitrate failed subagent outputs before trusting their conclusions." : undefined,
      arbitrationNeeds.length > 0 ? "Run reviewer arbitration to resolve contradictory subagent conclusions." : undefined,
      "Persist subagent outputs as evidence and feed them into objective scoring."
    ].filter((item): item is string => Boolean(item)))
  };
}

export function buildSecurityClosureModel(input: {
  target?: TargetInput;
  graph: SecurityAssetGraph;
  queue: SecurityDecisionQueue;
  toolRuns: SecurityToolRun[];
  checks: SecurityValidationCheck[];
  findings: SecurityFinding[];
  cveMatches: SecurityCveMatch[];
  evidence: SecurityEvidence[];
  technologies: SecurityTechnology[];
  attempts: SecurityValidationAttempt[];
  authContexts: SecurityAuthContext[];
  subagents: SubAgentRecord[];
  scope?: PentestScope;
}): SecurityClosureModel {
  const objectiveModel = buildSecurityObjectiveModel(input);
  const businessWorkflowGraph = buildBusinessWorkflowGraph(input);
  const browserPlan = buildBrowserInteractionPlan({
    target: input.target,
    workflowGraph: businessWorkflowGraph,
    authContexts: input.authContexts
  });
  const validationPlan = buildValidationClosurePlan({
    objectiveModel,
    workflowGraph: businessWorkflowGraph,
    findings: input.findings,
    cveMatches: input.cveMatches,
    evidence: input.evidence,
    attempts: input.attempts,
    authContexts: input.authContexts,
    scope: input.scope
  });
  const cveReconciliation = buildCveReconciliationPlan({
    technologies: input.technologies,
    cveMatches: input.cveMatches,
    attempts: input.attempts
  });
  const authorizedValidation = buildAuthorizedValidationPlaybook({
    target: input.target,
    validationPlan,
    workflowGraph: businessWorkflowGraph,
    browserPlan,
    cveReconciliation,
    scope: input.scope,
    authContexts: input.authContexts
  });
  const subAgentModel = buildSubAgentOperatingModel({
    subagents: input.subagents,
    queue: input.queue,
    objectiveModel
  });
  const nextBestActions = uniqueStrings([
    validationPlan.status === "ready" ? validationPlan.candidates.find((candidate) => candidate.id === validationPlan.nextCandidateId)?.nextAction : undefined,
    businessWorkflowGraph.gaps.length > 0 ? businessWorkflowGraph.nextActions[0] : undefined,
    browserPlan.gaps.length > 0 ? browserPlan.nextActions[0] : undefined,
    cveReconciliation.status !== "clean" ? cveReconciliation.nextActions[0] : undefined,
    authorizedValidation.status === "ready" ? authorizedValidation.steps.find((step) => step.id === authorizedValidation.nextStepId)?.title : undefined,
    subAgentModel.status !== "healthy" ? subAgentModel.nextActions[0] : undefined,
    ...objectiveModel.nextBestActions.slice(0, 3)
  ].filter((item): item is string => Boolean(item)));
  const status: SecurityClosureModel["status"] = validationPlan.status === "ready"
    ? "ready"
    : objectiveModel.overallStatus === "blocked_by_scope" || validationPlan.status === "blocked"
      ? "blocked"
      : objectiveModel.overallStatus === "needs_context" || validationPlan.status === "needs_context"
        ? "needs_context"
        : subAgentModel.status === "healthy" && subAgentModel.capacity.running > 0
          ? "running"
          : "settled";
  return {
    target: input.target?.normalized ?? input.graph.nodes[0]?.value ?? "unknown",
    generatedAt: nowIso(),
    status,
    summary: summarizeClosureModel(status, objectiveModel, validationPlan, businessWorkflowGraph),
    objectiveModel,
    validationPlan,
    businessWorkflowGraph,
    browserPlan,
    cveReconciliation,
    authorizedValidation,
    subAgentModel,
    nextBestActions
  };
}

export function buildSubAgentCoordinationPlan(input: {
  target?: TargetInput;
  graph: SecurityAssetGraph;
  queue: SecurityDecisionQueue;
  toolRuns: SecurityToolRun[];
  authContexts?: SecurityAuthContext[];
  subagents?: SubAgentRecord[];
}): SubAgentCoordinationPlan {
  const target = input.target?.normalized ?? input.graph.nodes[0]?.value ?? "unknown";
  const authContexts = input.authContexts ?? [];
  const subagents = input.subagents ?? [];
  const activeRoles = new Set(subagents.filter((agent) => agent.status === "running").map((agent) => agent.role));
  const completedRoles = new Set(subagents.filter((agent) => agent.status === "completed").map((agent) => agent.role));
  const urlNodes = input.graph.nodes.filter((node) => node.kind === "url");
  const normalizedApiNodes = urlNodes.filter((node) => node.sources.some((source) => source.includes("api-inventory-normalizer")));
  const urls = (normalizedApiNodes.length > 0 ? normalizedApiNodes : urlNodes).map((node) => node.value);
  const hosts = input.graph.nodes.filter((node) => node.kind === "domain" || node.kind === "subdomain").map((node) => node.value);
  const technologies = input.graph.nodes.flatMap((node) => node.technologies.map((technology) => `${technology.name}${technology.version ? ` ${technology.version}` : ""}`));
  const findings = input.graph.nodes.flatMap((node) => node.findings.map((finding) => finding.title));
  const cveMatches = input.graph.nodes.flatMap((node) => node.cveMatches.map((match) => match.cveId ?? match.title));
  const failedRuns = input.toolRuns.filter((run) => run.status === "failed" || run.status === "blocked" || run.status === "missing");
  const items: SubAgentCoordinationPlanItem[] = [];

  const push = (item: Omit<SubAgentCoordinationPlanItem, "id">): void => {
    const duplicateRole = activeRoles.has(item.role) || completedRoles.has(item.role);
    items.push({
      id: `sa-${items.length + 1}`,
      ...item,
      blockedReason: item.blockedReason ?? (duplicateRole ? `A ${item.role} subagent is already ${activeRoles.has(item.role) ? "running" : "completed"} for this session.` : undefined)
    });
  };

  if (hosts.length <= 1 || input.queue.items.some((item) => item.phase === "recon" || item.phase === "asset_discovery")) {
    push({
      priority: "high",
      role: "recon",
      title: "Coordinate asset expansion and fallback paths",
      rationale: "The asset graph is still shallow or recon queue items remain unresolved.",
      task: [
        `Target: ${target}`,
        "Review current asset graph and decision queue.",
        "Produce the next authorized passive recon actions, fallback choices when tools fail, and evidence needed before active probing."
      ].join("\n"),
      runMode: "background",
      contextHints: hosts.slice(0, 8),
      expectedOutput: ["asset gaps", "passive recon next actions", "tool fallback plan", "scope risks"]
    });
  }

  if (urls.length > 0 && input.queue.items.some((item) => item.phase === "frontend")) {
    push({
      priority: "medium",
      role: "frontend",
      title: "Map frontend/API attack surface",
      rationale: "Live URLs exist and frontend/API crawling or route analysis remains pending.",
      task: [
        `URLs: ${urls.slice(0, 10).join(", ")}`,
        "Identify routes, forms, JavaScript/API endpoints, source-map risks, hardcoded secrets, and auth assumptions from available evidence."
      ].join("\n"),
      runMode: "background",
      contextHints: urls.slice(0, 10),
      expectedOutput: ["route map", "API endpoint hypotheses", "secret/source-map checks", "auth boundary assumptions"]
    });
  }

  if (technologies.length > 0 && (cveMatches.length === 0 || input.queue.items.some((item) => item.phase === "vulnerability_analysis"))) {
    push({
      priority: "high",
      role: "cve",
      title: "Deduplicate and rank CVE/framework candidates",
      rationale: "Technology evidence exists and needs confidence-ranked vulnerability intelligence.",
      task: [
        `Technologies: ${technologies.slice(0, 20).join(", ")}`,
        `Current CVE candidates: ${cveMatches.slice(0, 20).join(", ") || "none"}`,
        "Separate exact version matches from weak fingerprint matches, deduplicate aliases, and propose safe validation evidence."
      ].join("\n"),
      runMode: "background",
      contextHints: technologies.slice(0, 20),
      expectedOutput: ["ranked CVE candidates", "confidence rationale", "dedupe decisions", "safe validation plan"]
    });
  }

  if (technologies.length === 0 || input.queue.items.some((item) => item.phase === "fingerprint")) {
    push({
      priority: "medium",
      role: "fingerprint",
      title: "Improve technology fingerprint confidence",
      rationale: "Fingerprint confidence is incomplete or HTTP/template tool runs still need interpretation.",
      task: [
        `Target: ${target}`,
        `Known technologies: ${technologies.slice(0, 20).join(", ") || "none"}`,
        "Infer stack hints from headers, titles, paths, template outputs, and tool failure categories. Recommend low-risk evidence to improve confidence."
      ].join("\n"),
      runMode: "background",
      contextHints: [...hosts, ...urls].slice(0, 10),
      expectedOutput: ["technology hypotheses", "version confidence", "missing evidence", "safe probe recommendations"]
    });
  }

  if (authContexts.length > 0 || urls.some((url) => /login|admin|account|user|order|tenant|api/i.test(url))) {
    push({
      priority: authContexts.length > 0 ? "high" : "medium",
      role: "web_vuln",
      title: "Plan authenticated business-logic validation",
      rationale: authContexts.length > 0
        ? "Authenticated contexts are available, so read-only role/workflow comparison can be planned."
        : "Business-sensitive routes are visible, but no authenticated context is registered yet.",
      task: [
        `Target: ${target}`,
        `Authenticated contexts: ${authContexts.map((context) => `${context.name}:${context.role ?? "unknown"}`).join(", ") || "none"}`,
        "Build a non-destructive business-logic test matrix for IDOR/BOLA, function-level auth, workflow abuse, session handling, and tenant separation."
      ].join("\n"),
      runMode: "foreground",
      contextHints: urls.slice(0, 10),
      expectedOutput: ["role matrix", "business-logic hypotheses", "read-only validation steps", "stop conditions"],
      blockedReason: authContexts.length === 0 ? "Register at least one authenticated context before execution; planning can continue." : undefined
    });
  }

  if (failedRuns.length > 0 || findings.some((title) => /critical|high|exposure|secret|admin/i.test(title))) {
    push({
      priority: findings.length > 0 ? "high" : "medium",
      role: "reviewer",
      title: "Review tool failures and evidence quality",
      rationale: "Failed or blocked tool runs need classification so the agent does not loop or overstate findings.",
      task: [
        `Failed runs: ${failedRuns.map((run) => `${run.toolId}:${run.failureCategory ?? run.status}`).join(", ") || "none"}`,
        `Findings: ${findings.slice(0, 20).join(", ") || "none"}`,
        "Identify which failures require fallback tools, which are true no-findings, and which findings need more evidence before reporting."
      ].join("\n"),
      runMode: "background",
      contextHints: failedRuns.map((run) => `${run.toolId}:${run.failureCategory ?? run.status}`),
      expectedOutput: ["failure triage", "false-positive risks", "fallback actions", "reporting readiness"]
    });
  }

  return {
    generatedAt: nowIso(),
    items: items.sort(compareCoordinationItems)
  };
}

export function buildBusinessLogicTestPlan(input: {
  target?: TargetInput;
  graph: SecurityAssetGraph;
  checks?: SecurityValidationCheck[];
  scope?: PentestScope;
  authContexts?: SecurityAuthContext[];
  knowledge?: BusinessLogicKnowledgeItem[];
  maxCases?: number;
}): BusinessLogicTestPlan {
  const knowledge = input.knowledge ?? buildBusinessLogicKnowledgeBase();
  const corpusItems = [
    ...input.graph.nodes.map((node) => node.value),
    ...input.graph.nodes.flatMap((node) => node.technologies.map((technology) => `${technology.name} ${technology.version ?? ""} ${technology.category ?? ""}`)),
    ...input.graph.nodes.flatMap((node) => node.findings.map((finding) => `${finding.title} ${finding.evidenceSummary ?? ""}`)),
    ...input.graph.nodes.flatMap((node) => node.cveMatches.map((match) => `${match.title} ${match.cveId ?? ""}`))
  ];
  const corpus = corpusItems.join("\n").toLowerCase();
  const normalizedApiHints = input.graph.nodes
    .filter((node) => node.kind === "url" && node.sources.some((source) => source.includes("api-inventory-normalizer")))
    .map((node) => node.value);
  const fallbackTargetHints = input.graph.nodes
    .filter((node) => node.kind === "url" || node.kind === "service" || node.kind === "subdomain")
    .map((node) => node.value);
  const targetHints = normalizedApiHints.length > 0
    ? uniqueStrings([...normalizedApiHints, ...fallbackTargetHints.filter((hint) => !/^https?:\/\//i.test(hint))])
    : fallbackTargetHints;
  const checks = input.checks ?? [];
  const observedChecks = new Set(checks.filter((check) => check.status === "observed" || check.status === "validated").map((check) => check.checkId));
  const candidates = knowledge.map((item) => {
    const matchedSignals = item.passiveSignals.filter((signal) => corpus.includes(signal.toLowerCase()));
    const routeKeywordScore = targetHints.filter((hint) => businessRouteKeywordFor(item).some((keyword) => hint.toLowerCase().includes(keyword))).length;
    const riskScore: Record<FindingSeverity, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
    const observedBonus = observedChecks.has(item.id) ? 3 : 0;
    return {
      item,
      matchedSignals,
      score: matchedSignals.length * 3 + routeKeywordScore * 2 + riskScore[item.risk] + observedBonus
    };
  });
  const selected = candidates
    .filter((candidate) => candidate.score > 0)
    .sort((a, b) => b.score - a.score || severityPriority(a.item.risk) - severityPriority(b.item.risk))
    .slice(0, input.maxCases ?? 8);
  const fallback = selected.length > 0
    ? selected
    : knowledge
      .filter((item) => ["BL-001", "BL-002", "BL-004", "BL-005", "BL-008"].includes(item.id))
      .map((item) => ({ item, matchedSignals: [], score: 0 }));
  const activeAllowed = Boolean(input.scope?.allowActiveProbing);
  const authContexts = input.authContexts ?? [];
  const hasAuthContext = authContexts.length > 0;
  return {
    target: input.target?.normalized ?? targetHints[0] ?? "unknown",
    generatedAt: nowIso(),
    requiresUserContext: !hasAuthContext,
    contextQuestions: [
      "Provide at least two test accounts with different roles/tenants, or confirm only unauthenticated passive planning is allowed.",
      "List critical business workflows such as login, checkout, refund, invite, file sharing, admin approval, or tenant switching.",
      "Define destructive-action boundaries: payments, refunds, emails, deletion, account lockout, and rate limits."
    ],
    authContexts: authContexts.map((context) => ({
      name: context.name,
      role: context.role,
      username: context.username,
      baseUrl: context.baseUrl
    })),
    testCases: fallback.map(({ item, matchedSignals }) => ({
      id: item.id,
      title: item.title,
      category: item.category,
      risk: item.risk,
      targetHints: selectBusinessTargetHints(targetHints, item),
      matchedSignals,
      prerequisites: [
        ...item.dataNeeded,
        "Explicit authorization for the named workflow and test accounts",
        "Stop condition for unexpected state change or production impact"
      ],
      safeSteps: item.safeTestIdeas,
      activeSteps: activeAllowed ? item.activeTestIdeas : [],
      evidenceToCollect: item.evidenceToCollect,
      falsePositiveGuards: item.falsePositiveGuards,
      blockedReason: !hasAuthContext
        ? "No authenticated session context is available; collect cookies/headers/storage-state before execution."
        : activeAllowed
          ? undefined
          : "Active mutation/replay validation is disabled; execute only safe read-only comparison steps."
    }))
  };
}

function validationStepsForCandidate(input: {
  candidate: ValidationClosureCandidate;
  target: string;
  activeAllowed: boolean;
  authContextCount: number;
  workflowGraph: BusinessWorkflowGraph;
  browserPlan: BrowserInteractionPlan;
  cveReconciliation: CveReconciliationPlan;
}): AuthorizedValidationStep[] {
  const candidate = input.candidate;
  const steps: AuthorizedValidationStep[] = [];
  const base = authorizedValidationBase(candidate);
  const workflowNodes = input.workflowGraph.nodes.filter((node) =>
    candidate.target.toLowerCase().includes(node.url.toLowerCase())
    || node.url.toLowerCase().includes(candidate.target.toLowerCase())
    || workflowSignals(`${candidate.title} ${candidate.target}`).some((signal) => node.signals.includes(signal))
  );
  const isBusiness = candidate.kind === "objective" && candidate.targetId === "business_logic_impact"
    || /idor|bola|business|tenant|role|authorization|order|payment|refund|approval|admin/i.test(`${candidate.title} ${candidate.target}`);
  const isCve = candidate.kind === "cve" || /cve|advisory|rce|deserialization|version/i.test(candidate.title);
  const isBrowserRelevant = isBusiness || workflowNodes.length > 0 || /login|admin|account|form|browser|api/i.test(`${candidate.title} ${candidate.target}`);

  steps.push({
    ...base,
    id: `${candidate.id}:evidence-review`,
    kind: "evidence_review",
    title: `Review evidence for ${candidate.title}`,
    status: candidate.evidenceIds.length > 0 ? "ready" : "needs_context",
    risk: "low",
    requiredAuthorization: ["Approved target scope"],
    requiredContext: candidate.evidenceIds.length > 0 ? [] : ["At least one evidence artifact linked to the candidate"],
    procedure: [
      "Collect linked evidence IDs, affected target, observed technology/route, and source tool or browser artifact.",
      "Check whether the candidate is duplicated, contradicted, or scanner-only.",
      "Decide whether the candidate can be safely validated or should remain needs_validation."
    ],
    expectedEvidence: ["Evidence inventory", "Candidate confidence note", "False-positive guard checklist"],
    proofStandard: ["Evidence supports the same target and same vulnerability hypothesis."],
    automationHint: "Use stored evidence, tool runs, asset graph, and CVE reconciliation before any live request."
  });

  if (isBrowserRelevant) {
    const hasEnoughRoles = input.authContextCount >= 2;
    steps.push({
      ...base,
      id: `${candidate.id}:browser-no-submit`,
      candidateId: candidate.id,
      kind: "no_submit_browser_capture",
      title: `Capture no-submit browser/API flow for ${candidate.title}`,
      target: candidate.target,
      status: input.authContextCount > 0 ? "ready" : "needs_context",
      risk: "low",
      requiredAuthorization: ["Approved browser exploration", "Same-origin target scope"],
      requiredContext: input.authContextCount > 0 ? [] : ["At least one registered auth context or imported storage state"],
      procedure: [
        "Load the registered storage state or redacted cookie/header context.",
        "Navigate high-value routes and instrument request metadata.",
        "Allow GET/HEAD, capture POST shape without submission, and block mutation methods.",
        "Promote observed sensitive actions into the workflow graph."
      ],
      expectedEvidence: ["Visited routes", "Form/action inventory", "Request method/url/body-shape metadata", "CSRF/session observations"],
      proofStandard: ["Sensitive workflow is mapped without performing state-changing actions."],
      automationHint: input.browserPlan.replayQueue.length > 0
        ? `Replay queue candidates: ${input.browserPlan.replayQueue.slice(0, 3).map((item) => `${item.category}:${item.requestClass}`).join(", ")}`
        : "Run Playwright no-submit exploration to create a replay queue."
    });
    steps.push({
      ...base,
      id: `${candidate.id}:role-compare`,
      kind: "read_only_role_compare",
      title: `Read-only role comparison for ${candidate.title}`,
      status: hasEnoughRoles ? "ready" : "needs_context",
      risk: "medium",
      requiredAuthorization: ["Approved test accounts", "Read-only role comparison scope"],
      requiredContext: hasEnoughRoles ? [] : ["Two authorized roles or tenants with expected permission rules"],
      procedure: [
        "Request the same high-value route with each authorized role.",
        "Compare status code, redirect target, content hash, visible object identifiers, and sensitive UI/API availability.",
        "Do not submit forms or change workflow state.",
        "Record expected versus observed access."
      ],
      expectedEvidence: ["Per-role response signature", "Expected permission matrix", "Access delta and impact note"],
      proofStandard: ["A lower-privileged or wrong-tenant role can read metadata it should not access, or access is correctly denied."],
      falsePositiveGuards: uniqueStrings([...base.falsePositiveGuards, ...workflowNodes.flatMap((node) => node.stateInvariants)]),
      automationHint: "Use safe authenticated GET probes and response hashes; do not store full sensitive response bodies."
    });
  }

  if (isCve) {
    const adjustment = input.cveReconciliation.confidenceAdjustments.find((item) => candidate.targetId === item.candidateId);
    const hasVersionGap = input.cveReconciliation.versionGaps.some((gap) =>
      candidate.title.includes(gap.cveId ?? "") || normalizeTargetForDedupe(candidate.target) === normalizeTargetForDedupe(gap.target)
    );
    steps.push({
      ...base,
      id: `${candidate.id}:version-confirmation`,
      kind: "version_confirmation",
      title: `Confirm product/version evidence for ${candidate.title}`,
      status: hasVersionGap || candidate.confidence !== "high" ? "needs_context" : "ready",
      risk: "low",
      requiredAuthorization: ["Approved fingerprinting scope"],
      requiredContext: hasVersionGap ? ["Exact product/version evidence or a high-confidence template fingerprint"] : [],
      procedure: [
        "Correlate headers, service banners, templates, Wappalyzer/WhatWeb/httpx evidence, and local framework knowledge.",
        "Apply CVE dedupe and confidence adjustments.",
        "Prefer exact version ranges over generic framework names."
      ],
      expectedEvidence: ["Product/version source", "CVE mapping rationale", "Confidence adjustment decision"],
      proofStandard: [adjustment ? `Confidence adjustment exists: ${adjustment.from} -> ${adjustment.to}.` : "Candidate is version-backed or explicitly remains a weak advisory hypothesis."],
      automationHint: "Use local CVE/nuclei knowledge and nmap/httpx/whatweb outputs; avoid exploit traffic."
    });
    steps.push({
      ...base,
      id: `${candidate.id}:non-destructive-template`,
      kind: "non_destructive_template",
      title: `Non-destructive validation for ${candidate.title}`,
      status: input.activeAllowed ? "ready" : "blocked",
      risk: candidate.priority === "critical" || candidate.priority === "high" ? "high" : "medium",
      requiredAuthorization: ["Explicit active-validation approval", "Allowed host list", "Rate limit", "Stop condition"],
      requiredContext: ["Exact target URL/host", "Candidate product/version or high-confidence fingerprint"],
      procedure: [
        "Select low-rate non-destructive templates or manual checks that do not write data.",
        "Run only against explicitly allowed targets.",
        "Record positive, negative, or inconclusive evidence and update candidate state.",
        "Stop immediately after proof level is met."
      ],
      expectedEvidence: ["Template/manual check ID", "Request boundary", "Result classification", "Candidate state transition"],
      proofStandard: ["A non-destructive check confirms impact, or a negative check reduces confidence without overclaiming absence."],
      blockedBy: input.activeAllowed ? undefined : "active validation disabled",
      automationHint: "nuclei-owasp may be scheduled only when allowActiveProbing=true and command approval is granted."
    });
  }

  if (candidate.kind === "objective" || isBusiness) {
    steps.push({
      ...base,
      id: `${candidate.id}:business-rule-check`,
      kind: "manual_business_rule_check",
      title: `Confirm business rule and proof boundary for ${candidate.title}`,
      status: workflowNodes.length > 0 && input.authContextCount > 0 ? "ready" : "needs_context",
      risk: "medium",
      requiredAuthorization: ["Named workflow authorization", "Test data boundary", "No destructive-action agreement"],
      requiredContext: [
        workflowNodes.length > 0 ? "" : "Mapped workflow route or API endpoint",
        input.authContextCount > 0 ? "" : "Authorized role/session context",
        "Expected business rule from the user or application owner"
      ].filter(Boolean),
      procedure: [
        "Write the expected invariant before testing: owner, tenant, amount, status transition, approval role, or file owner.",
        "Compare read-only observations against the expected rule.",
        "Escalate to active workflow replay only if scope explicitly permits mutation on test data."
      ],
      expectedEvidence: ["Expected invariant", "Observed role/tenant behavior", "Business impact classification"],
      proofStandard: ["Observed behavior violates an explicit business rule or remains a documented hypothesis pending owner input."],
      automationHint: workflowNodes.length > 0
        ? `Workflow nodes: ${workflowNodes.slice(0, 3).map((node) => `${node.category}:${node.url}`).join(", ")}`
        : "Build the business workflow graph from crawler/browser evidence first."
    });
  }

  return uniqueBy(steps, (step) => step.id);
}

function authorizedValidationBase(candidate: ValidationClosureCandidate): Omit<AuthorizedValidationStep, "id" | "kind" | "title" | "status" | "risk" | "requiredAuthorization" | "requiredContext" | "procedure" | "expectedEvidence" | "proofStandard"> {
  return {
    candidateId: candidate.id,
    target: candidate.target,
    falsePositiveGuards: candidate.falsePositiveGuards,
    stopConditions: [
      "Stop if the step would exceed the authorized target, rate, account, or workflow boundary.",
      "Stop if the only proof path requires destructive mutation, credential extraction, persistence, lateral movement, or data exfiltration.",
      "Stop when the agreed proof level is reached and record evidence instead of deepening impact."
    ],
    prohibitedActions: prohibitedValidationActions(),
    blockedBy: candidate.blockedBy
  };
}

function compareAuthorizedValidationSteps(left: AuthorizedValidationStep, right: AuthorizedValidationStep): number {
  const statusRank: Record<AuthorizedValidationStep["status"], number> = { ready: 0, needs_context: 1, blocked: 2 };
  const riskRank: Record<AuthorizedValidationStep["risk"], number> = { high: 0, medium: 1, low: 2 };
  const kindRank: Record<AuthorizedValidationStepKind, number> = {
    evidence_review: 0,
    no_submit_browser_capture: 1,
    read_only_role_compare: 2,
    manual_business_rule_check: 3,
    version_confirmation: 4,
    non_destructive_template: 5
  };
  return statusRank[left.status] - statusRank[right.status]
    || riskRank[left.risk] - riskRank[right.risk]
    || kindRank[left.kind] - kindRank[right.kind]
    || left.title.localeCompare(right.title);
}

function prohibitedValidationActions(): string[] {
  return [
    "Credential theft, password spraying, brute force, session hijacking, or secret use.",
    "Persistence, privilege changes, lateral movement, destructive payloads, or command execution for control.",
    "Production data modification, deletion, payment/refund/order placement, email/SMS sending, or account lockout without explicit written scope.",
    "Data exfiltration or bulk response-body storage beyond redacted proof metadata."
  ];
}

function buildObjectiveAssessment(input: {
  id: SecurityObjectiveId;
  title: string;
  baseScore: number;
  evidence: string[];
  hasAuthContext: boolean;
  activeAllowed: boolean;
  mappedQueueItemIds: string[];
  contextBlockers: string[];
  activeBlockers: string[];
  nextQuestions: string[];
  nextActions: string[];
  validationBoundaries: string[];
}): SecurityObjectiveAssessment {
  const score = Math.min(100, input.baseScore + input.evidence.length * 8 + input.mappedQueueItemIds.length * 3 + (input.hasAuthContext ? 12 : 0));
  const blockers = uniqueStrings([
    ...input.contextBlockers,
    ...input.activeBlockers,
    ...(input.evidence.length === 0 ? ["No concrete evidence has been mapped to this objective yet."] : [])
  ]);
  const status: SecurityObjectiveStatus = input.activeBlockers.length > 0
    ? "blocked_by_scope"
    : blockers.length > 0
      ? "needs_context"
      : input.evidence.some((item) => /validated/i.test(item))
        ? "validated_impact"
        : input.evidence.length >= 2
          ? "ready_for_safe_validation"
          : "collecting_evidence";
  const confidence: "low" | "medium" | "high" = score >= 75 && blockers.length === 0
    ? "high"
    : score >= 45
      ? "medium"
      : "low";
  return {
    id: input.id,
    title: input.title,
    status,
    score,
    confidence,
    evidence: input.evidence,
    blockers,
    nextQuestions: input.nextQuestions,
    nextActions: input.nextActions,
    validationBoundaries: input.validationBoundaries,
    mappedQueueItemIds: uniqueStrings(input.mappedQueueItemIds)
  };
}

function buildAttackPathModels(objectives: SecurityObjectiveAssessment[]): SecurityAttackPathModel[] {
  const byId = new Map(objectives.map((objective) => [objective.id, objective]));
  const business = byId.get("business_logic_impact");
  const admin = byId.get("admin_control_plane");
  const server = byId.get("server_control_plane");
  const paths: SecurityAttackPathModel[] = [];
  if (business && admin) {
    paths.push({
      id: "path-business-to-admin",
      title: "Business workflow to admin/control-plane impact",
      status: worseObjectiveStatus([business.status, admin.status]),
      score: Math.round((business.score * 0.6) + (admin.score * 0.4)),
      rationale: "Prioritize business and authorization reasoning before broad exploitation; this is where scanners are weakest.",
      stages: [
        objectiveStage(business, "Collect roles/workflows and run read-only cross-role comparison."),
        objectiveStage(admin, "Map backend/control-plane routes and prove authorization impact without credential attacks.")
      ],
      stopConditions: [
        "Stop if validation requires real payment/refund/deletion/privilege mutation without explicit scope.",
        "Stop if only credential guessing would advance the path."
      ]
    });
  }
  if (admin && server) {
    paths.push({
      id: "path-admin-to-server-risk",
      title: "Admin/control-plane exposure to server risk",
      status: worseObjectiveStatus([admin.status, server.status]),
      score: Math.round((admin.score * 0.5) + (server.score * 0.5)),
      rationale: "Server impact should be pursued only after control-plane exposure or strong server-side evidence is established.",
      stages: [
        objectiveStage(admin, "Confirm the admin boundary through authorized accounts or non-destructive access-control evidence."),
        objectiveStage(server, "Use version-confirmed CVE or misconfiguration evidence and keep validation non-destructive.")
      ],
      stopConditions: [
        "Stop before persistence, credential extraction, lateral movement, or data exfiltration.",
        "Stop and ask the user when active validation scope is missing."
      ]
    });
  }
  return paths.sort((left, right) => right.score - left.score);
}

function objectiveStage(objective: SecurityObjectiveAssessment, nextAction: string): SecurityAttackPathStage {
  return {
    objectiveId: objective.id,
    status: objective.status,
    evidence: objective.evidence.slice(0, 5),
    nextAction
  };
}

function worseObjectiveStatus(statuses: SecurityObjectiveStatus[]): SecurityObjectiveStatus {
  const order: SecurityObjectiveStatus[] = ["validated_impact", "ready_for_safe_validation", "collecting_evidence", "needs_context", "blocked_by_scope"];
  return statuses.sort((left, right) => order.indexOf(right) - order.indexOf(left))[0] ?? "collecting_evidence";
}

function deriveOverallObjectiveStatus(objectives: SecurityObjectiveAssessment[]): SecurityObjectiveStatus {
  if (objectives.some((objective) => objective.status === "validated_impact")) {
    return "validated_impact";
  }
  if (objectives.some((objective) => objective.status === "ready_for_safe_validation")) {
    return "ready_for_safe_validation";
  }
  if (objectives.some((objective) => objective.status === "needs_context")) {
    return "needs_context";
  }
  if (objectives.some((objective) => objective.status === "blocked_by_scope")) {
    return "blocked_by_scope";
  }
  return "collecting_evidence";
}

function summarizeObjectiveModel(objectives: SecurityObjectiveAssessment[], overallStatus: SecurityObjectiveStatus): string {
  const top = objectives[0];
  if (!top) {
    return "No objective evidence is available yet.";
  }
  if (overallStatus === "blocked_by_scope") {
    return `Top objective is ${top.title}, but scope blocks the next active validation step.`;
  }
  if (overallStatus === "needs_context") {
    return `Top objective is ${top.title}; user context is needed before meaningful validation.`;
  }
  return `Top objective is ${top.title} with ${top.confidence} confidence and score ${top.score}.`;
}

function hasBusinessWorkflowSignal(value: string): boolean {
  return /\/(?:api\/)?(?:order|orders|cart|checkout|pay|payment|refund|coupon|invoice|wallet|balance|transfer|invite|tenant|project|file|upload|approval|workflow|account|profile|user|users|role|roles)(?:\/|\?|$)/i.test(value);
}

function hasAdminSurfaceSignal(value: string): boolean {
  return /\/(?:admin|manage|manager|console|dashboard|backend|cms|system|sys|login|signin|auth|sso|oauth|user|users|role|roles|permission|permissions)(?:\/|\?|$)/i.test(value)
    || /(?:^|[./-])(?:admin|manage|backend|console|dashboard)(?:[./:-]|$)/i.test(value);
}

function createStableSlug(value: string): string {
  return value.toLowerCase().replace(/^https?:\/\//, "").replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 80) || "unknown";
}

function categorizeBusinessWorkflow(value: string): BusinessWorkflowCategory {
  const lower = value.toLowerCase();
  if (/\/(?:admin|manage|manager|console|dashboard|backend|cms|system|sys)(?:\/|\?|$)/i.test(lower)) return "admin";
  if (/\/(?:login|signin|signup|register|logout|auth|sso|oauth|password|reset|otp|2fa|mfa|session)(?:\/|\?|$)/i.test(lower)) return "identity";
  if (/\/(?:role|roles|permission|permissions|user|users|account|profile|member|invite)(?:\/|\?|$)/i.test(lower)) return "authorization";
  if (/\/(?:order|orders|cart|checkout|pay|payment|refund|coupon|invoice|wallet|balance|credit|transfer|withdraw|price|amount)(?:\/|\?|$)/i.test(lower)) return "commerce";
  if (/\/(?:approval|approve|reject|review|workflow|status|state|publish|submit|confirm)(?:\/|\?|$)/i.test(lower)) return "approval";
  if (/\/(?:tenant|org|organization|workspace|project|team)(?:\/|\?|$)/i.test(lower)) return "tenant";
  if (/\/(?:file|files|upload|download|attachment|export|import|share|media)(?:\/|\?|$)/i.test(lower)) return "file";
  if (/\/(?:api|graphql|rest|rpc|v\d+|swagger|openapi)(?:\/|\?|$)/i.test(lower)) return "api";
  return "unknown";
}

function workflowSignals(value: string): string[] {
  const signals: Array<[RegExp, string]> = [
    [/\/(?:\d{2,}|[0-9a-f-]{12,})(?:\/|\?|$)/i, "object-id"],
    [/\b(?:delete|remove|destroy|disable|revoke|refund|approve|reject|transfer|withdraw|pay|submit|confirm)\b/i, "state-changing-action"],
    [/\b(?:tenant|org|workspace|project|team)\b/i, "tenant-boundary"],
    [/\b(?:role|permission|admin|manager|user)\b/i, "authorization-boundary"],
    [/\b(?:price|amount|coupon|discount|credit|balance|invoice|payment)\b/i, "financial-invariant"],
    [/\b(?:upload|download|file|export|import|attachment|share)\b/i, "file-object"],
    [/\b(?:otp|2fa|mfa|password|reset|invite|email)\b/i, "identity-lifecycle"]
  ];
  return signals.filter(([pattern]) => pattern.test(value)).map(([, signal]) => signal);
}

function workflowSensitivity(category: BusinessWorkflowCategory, signals: string[]): "low" | "medium" | "high" {
  if (category === "commerce" || category === "approval" || category === "admin" || signals.includes("state-changing-action") || signals.includes("financial-invariant")) {
    return "high";
  }
  if (category === "authorization" || category === "tenant" || category === "file" || signals.length > 0) {
    return "medium";
  }
  return "low";
}

function workflowSensitivityRank(value: "low" | "medium" | "high"): number {
  return ({ low: 0, medium: 1, high: 2 })[value];
}

function requiredRolesForWorkflow(category: BusinessWorkflowCategory): string[] {
  switch (category) {
    case "admin":
      return ["low-privileged user", "admin/operator"];
    case "commerce":
      return ["buyer/customer", "different buyer/customer", "operator if available"];
    case "approval":
      return ["requester", "approver/reviewer"];
    case "tenant":
      return ["tenant A user", "tenant B user"];
    case "authorization":
      return ["low-privileged user", "privileged user"];
    case "file":
      return ["file owner", "non-owner"];
    case "identity":
      return ["same user session", "different user session"];
    case "api":
      return ["authenticated user", "unauthenticated context if allowed"];
    default:
      return ["authorized test user"];
  }
}

function safeValidationIdeasForWorkflow(category: BusinessWorkflowCategory): string[] {
  switch (category) {
    case "commerce":
      return ["Compare read-only order/payment/refund resource visibility across roles.", "Check amount/status fields for server-side authorization assumptions without mutation."];
    case "approval":
      return ["Map allowed state transitions per role.", "Compare read-only visibility of pending/approved/rejected objects."];
    case "tenant":
      return ["Compare tenant A and tenant B object reads.", "Check tenant identifiers in URLs, headers, and API responses."];
    case "admin":
      return ["Compare admin route status and content hash between low-privileged and admin contexts.", "Inventory admin-only APIs without submitting actions."];
    case "file":
      return ["Compare owner versus non-owner file metadata/download authorization with test files only."];
    case "authorization":
      return ["Build function-level authorization matrix from route/status/content signatures."];
    case "identity":
      return ["Map session, reset, invite, and OTP flows without triggering real account recovery actions."];
    default:
      return ["Collect request/response metadata and define expected business rules before validation."];
  }
}

function stateInvariantsForWorkflow(category: BusinessWorkflowCategory, signals: string[]): string[] {
  const invariants: string[] = [];
  if (category === "commerce" || signals.includes("financial-invariant")) {
    invariants.push("amount/price/discount/refund values must be server-authoritative and bound to the correct user/order state.");
  }
  if (category === "tenant" || signals.includes("tenant-boundary")) {
    invariants.push("tenant/org/workspace identifiers must not allow cross-tenant reads or writes.");
  }
  if (category === "authorization" || category === "admin" || signals.includes("authorization-boundary")) {
    invariants.push("low-privileged users must not access privileged functions, routes, or object metadata.");
  }
  if (category === "approval" || signals.includes("state-changing-action")) {
    invariants.push("state transitions must enforce actor role, current state, idempotency, and replay protection.");
  }
  if (category === "file" || signals.includes("file-object")) {
    invariants.push("file metadata/download/share actions must enforce owner, tenant, and share-scope boundaries.");
  }
  if (category === "identity" || signals.includes("identity-lifecycle")) {
    invariants.push("identity lifecycle flows must enforce token freshness, audience, one-time use, and rate limits.");
  }
  return invariants.length > 0 ? invariants : ["Expected business rule must be documented before validation."];
}

function activeValidationBoundariesForWorkflow(category: BusinessWorkflowCategory): string[] {
  const common = ["Use test accounts and test data only.", "Stop after non-destructive proof; do not deepen impact."];
  switch (category) {
    case "commerce":
      return [...common, "No real payment, refund, coupon redemption, transfer, withdrawal, or inventory mutation without explicit scope."];
    case "approval":
      return [...common, "No real approval/rejection/publish/disable workflow mutation without explicit scope."];
    case "admin":
    case "authorization":
      return [...common, "No privilege change, account takeover, credential reset, or user lockout without explicit scope."];
    case "file":
      return [...common, "Use only designated test files; no bulk downloads or private data access."];
    case "identity":
      return [...common, "No brute force, password spraying, account recovery abuse, or OTP exhaustion."];
    default:
      return common;
  }
}

function browserRequestClassForWorkflow(node: BusinessWorkflowGraphNode): BrowserInteractionPlan["replayQueue"][number]["requestClass"] {
  if (node.category === "identity" || node.signals.includes("identity-lifecycle")) return "credential";
  if (node.category === "admin" || node.category === "authorization") return "admin";
  if (node.signals.includes("state-changing-action") || node.category === "commerce" || node.category === "approval") return "state_changing";
  return "read_only";
}

function browserReplayAuthorizationForWorkflow(node: BusinessWorkflowGraphNode): string[] {
  const common = ["Approved target scope", "Registered auth context"];
  const requestClass = browserRequestClassForWorkflow(node);
  if (requestClass === "read_only") {
    return [...common, "Read-only comparison is allowed"];
  }
  return [...common, "Explicit active workflow replay approval", ...node.activeValidationBoundaries];
}

function sameOriginOrPath(baseUrl: string, url: string): boolean {
  try {
    const base = new URL(baseUrl);
    const candidate = new URL(url, baseUrl);
    return base.origin === candidate.origin || candidate.href.startsWith(base.href);
  } catch {
    return false;
  }
}

function priorityForSeverity(severity: FindingSeverity): "critical" | "high" | "medium" | "low" {
  if (severity === "critical") return "critical";
  if (severity === "high") return "high";
  if (severity === "medium") return "medium";
  return "low";
}

function validationStateFromAttempt(attempt: SecurityValidationAttempt): ValidationClosureCandidate["state"] {
  switch (attempt.status) {
    case "validated":
      return "validated";
    case "ruled_out":
      return "ruled_out";
    case "blocked":
      return "blocked";
    case "inconclusive":
    case "planned":
      return "needs_context";
  }
}

function strategyForFinding(finding: SecurityFinding): string {
  const text = `${finding.title} ${finding.description}`.toLowerCase();
  if (/business|idor|bola|role|tenant|authorization|restricted|admin/.test(text)) {
    return "Use read-only cross-role comparison and expected permission matrix before reporting.";
  }
  if (/header|misconfiguration|source map|javascript|secret|route/.test(text)) {
    return "Correlate passive evidence with browser/tool output and verify exposure boundaries.";
  }
  return "Collect at least one independent evidence source and avoid destructive reproduction.";
}

function falsePositiveGuardsForTitle(text: string): string[] {
  const guards = ["Require target and route evidence, not just scanner text."];
  if (/idor|bola|authorization|role|tenant|admin/i.test(text)) {
    guards.push("Confirm expected role/tenant policy with user-provided business rules.");
    guards.push("Compare authorized roles using test accounts only.");
  }
  if (/cve|version|outdated|rce|deserialization/i.test(text)) {
    guards.push("Require exact product/version or a high-confidence template fingerprint.");
  }
  if (/secret|token|credential/i.test(text)) {
    guards.push("Redact sensitive values and prove exposure without using the secret.");
  }
  return guards;
}

function validationCandidateStateRank(state: ValidationClosureCandidate["state"]): number {
  return ({ ready: 0, needs_context: 1, blocked: 2, validated: 3, ruled_out: 4 })[state];
}

function validationCandidateKindRank(kind: ValidationClosureCandidate["kind"]): number {
  return ({ finding: 0, business_logic: 1, cve: 2, tool_run: 3, objective: 4 })[kind];
}

function closurePriorityRank(priority: "critical" | "high" | "medium" | "low"): number {
  return ({ critical: 0, high: 1, medium: 2, low: 3 })[priority];
}

function confidenceRankValue(confidence: "low" | "medium" | "high"): number {
  return ({ low: 0, medium: 1, high: 2 })[confidence];
}

function severityRankValue(severity: FindingSeverity): number {
  return ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 })[severity];
}

function needsRoleForObjective(role: SubAgentRole, objectiveModel: SecurityObjectiveModel, queue: SecurityDecisionQueue): boolean {
  const text = [
    objectiveModel.summary,
    ...objectiveModel.objectives.flatMap((objective) => [objective.id, objective.title, ...objective.evidence, ...objective.nextActions]),
    ...queue.items.map((item) => `${item.phase} ${item.title} ${item.reason}`)
  ].join("\n").toLowerCase();
  switch (role) {
    case "recon":
      return /subdomain|asset|dns|host|recon/.test(text);
    case "frontend":
      return /frontend|browser|route|javascript|api|form/.test(text);
    case "fingerprint":
      return /fingerprint|technology|version|service/.test(text);
    case "cve":
      return /cve|advisory|vulnerab|version/.test(text);
    case "web_vuln":
      return /business|idor|auth|owasp|validation|admin/.test(text);
    case "reviewer":
      return /validated|finding|triage|report|contradiction/.test(text);
    default:
      return false;
  }
}

function detectSubAgentOperatingContradictions(subagents: SubAgentRecord[]): string[] {
  const summaries = subagents
    .filter((agent) => agent.status === "completed")
    .map((agent) => `${agent.role}:${agent.resultSummary ?? ""}`.toLowerCase());
  const contradictions: string[] = [];
  if (summaries.some((summary) => /\b(validated|confirmed|true positive)\b/.test(summary)) && summaries.some((summary) => /\b(false positive|ruled out|not vulnerable)\b/.test(summary))) {
    contradictions.push("completed subagents disagree on validated versus ruled-out status");
  }
  if (summaries.some((summary) => /auth|login|credential/.test(summary)) && summaries.some((summary) => /no auth required|anonymous|unauthenticated/.test(summary))) {
    contradictions.push("completed subagents disagree on authentication requirements");
  }
  if (summaries.some((summary) => /(critical|rce|admin|secret)/.test(summary) && !/(evidence|artifact|output)/.test(summary))) {
    contradictions.push("high-impact subagent claims need explicit evidence references");
  }
  return contradictions;
}

function summarizeClosureModel(
  status: SecurityClosureModel["status"],
  objectiveModel: SecurityObjectiveModel,
  validationPlan: ValidationClosurePlan,
  workflowGraph: BusinessWorkflowGraph
): string {
  if (status === "ready") {
    return `${validationPlan.summary} Objective focus: ${objectiveModel.objectives[0]?.title ?? "unknown"}.`;
  }
  if (status === "needs_context") {
    return `Needs user/auth/business context before stronger validation. Workflow nodes=${workflowGraph.nodes.length}.`;
  }
  if (status === "blocked") {
    return "Next meaningful validation is blocked by current scope or active-testing boundaries.";
  }
  if (status === "running") {
    return "Subagents or queued work are still producing evidence for the current objective.";
  }
  return "No immediate executable validation step remains; review report and unresolved gaps.";
}

function pushAdaptiveAction(
  actions: AdaptiveSecurityAction[],
  completedKeys: Set<string>,
  action: Omit<AdaptiveSecurityAction, "key">
): void {
  const values = limitInputs(action.inputValues, 50);
  if (values.length === 0) {
    return;
  }
  const key = adaptiveActionKey(action.toolId, action.inputKind, values);
  if (completedKeys.has(key.toLowerCase())) {
    return;
  }
  actions.push({
    ...action,
    inputValues: values,
    key
  });
}

function adaptiveActionKey(toolId: string, inputKind: string, values: string[]): string {
  return `${toolId}:${inputKind}:${values.map((item) => item.toLowerCase()).sort().join("|")}`;
}

function limitInputs(values: string[], maxInputs: number): string[] {
  const output: string[] = [];
  const seen = new Set<string>();
  for (const value of values) {
    const normalized = normalizeAdaptiveInput(value);
    if (!normalized) {
      continue;
    }
    const key = normalized.toLowerCase();
    if (seen.has(key)) {
      continue;
    }
    seen.add(key);
    output.push(normalized);
    if (output.length >= maxInputs) {
      break;
    }
  }
  return output;
}

function normalizeAdaptiveInput(value: string): string | undefined {
  const trimmed = value.trim().replace(/[),.;]+$/u, "");
  if (!trimmed) {
    return undefined;
  }
  if (/^https?:\/\//i.test(trimmed)) {
    return trimmed;
  }
  if (/^[a-z0-9.-]+\.[a-z]{2,}(?::\d{1,5})?$/i.test(trimmed) || /^\d{1,3}(?:\.\d{1,3}){3}(?::\d{1,5})?$/.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  return undefined;
}

function serviceToHttpCandidate(value: string): string | undefined {
  const match = value.match(/^(.+):(\d{1,5})$/);
  if (!match) {
    return undefined;
  }
  const host = match[1];
  const port = Number(match[2]);
  if (!Number.isInteger(port) || port <= 0 || port > 65535) {
    return undefined;
  }
  const profile = serviceProfileForPort(port);
  if (profile?.httpCandidate) {
    return `${profile.scheme ?? "http"}://${host}:${port}`;
  }
  return undefined;
}

function assetNodeKey(kind: SecurityAsset["kind"], value: string): string {
  return `${kind}:${value.toLowerCase()}`;
}

function addGraphEdge(
  edges: Map<string, SecurityAssetGraphEdge>,
  from: string,
  to: string,
  relation: SecurityAssetGraphEdge["relation"]
): void {
  const key = `${from}->${relation}->${to}`;
  if (!edges.has(key)) {
    edges.set(key, { from, to, relation });
  }
}

function mergeConfidence(left: SecurityAsset["confidence"], right: SecurityAsset["confidence"]): SecurityAsset["confidence"] {
  const order: Record<SecurityAsset["confidence"], number> = { low: 0, medium: 1, high: 2 };
  return order[right] > order[left] ? right : left;
}

function safeHostname(value: string): string | undefined {
  try {
    if (/^https?:\/\//i.test(value)) {
      return new URL(value).hostname.toLowerCase();
    }
  } catch {
    return undefined;
  }
  const withoutPort = value.replace(/:\d{1,5}$/u, "");
  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(withoutPort) || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(withoutPort)) {
    return withoutPort.toLowerCase();
  }
  return undefined;
}

function matchTargetNode(nodes: Map<string, SecurityAssetGraphNode>, target: string): SecurityAssetGraphNode | undefined {
  const lower = target.toLowerCase();
  for (const node of nodes.values()) {
    if (node.value.toLowerCase() === lower) {
      return node;
    }
  }
  const host = safeHostname(target);
  if (host) {
    for (const node of nodes.values()) {
      if (safeHostname(node.value) === host || node.value.toLowerCase() === host) {
        return node;
      }
    }
  }
  return undefined;
}

function hasSuccessfulRun(runs: SecurityToolRun[], toolId: string): boolean {
  return runs.some((run) => run.toolId === toolId && run.status === "success");
}

function hasUnsuccessfulRun(runs: SecurityToolRun[], toolId: string): boolean {
  return runs.some((run) => run.toolId === toolId && ["blocked", "missing", "denied", "failed", "skipped"].includes(run.status));
}

function isPublicEnumeratableHostname(host: string): boolean {
  const normalized = host.toLowerCase().replace(/\.$/u, "");
  if (!normalized || normalized === "localhost") return false;
  if (/^\d{1,3}(?:\.\d{1,3}){3}$/.test(normalized)) return false;
  if (/^\[[0-9a-f:]+\]$/i.test(normalized) || /^[0-9a-f:]+$/i.test(normalized)) return false;
  if (!normalized.includes(".")) return false;
  return /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(normalized);
}

type DecisionApiRoute = {
  method: string;
  pathTemplate: string;
  queryParams: string[];
  bodyParamHints: string[];
  riskSignals: string[];
  sources: string[];
  authRequired: string;
  confidence: "low" | "medium" | "high";
  examples: string[];
  score: number;
};

function normalizedApiRouteFromNode(node: SecurityAssetGraphNode): DecisionApiRoute | undefined {
  const metadata = node.metadata
    .map(parseJsonRecord)
    .find((item) => item && (typeof item.pathTemplate === "string" || typeof item.method === "string"));
  const pathTemplate = stringMetadata(metadata?.pathTemplate) ?? pathFromUrlLike(node.value);
  if (!pathTemplate) return undefined;
  const method = (stringMetadata(metadata?.method) ?? "GET").toUpperCase();
  const riskSignals = uniqueStrings([...stringArrayMetadata(metadata?.riskSignals), ...routeRiskSignals(pathTemplate, method)]);
  const queryParams = sanitizeDecisionParamHints(stringArrayMetadata(metadata?.queryParams)).sort();
  const bodyParamHints = sanitizeDecisionParamHints(stringArrayMetadata(metadata?.bodyParamHints)).sort();
  const sources = stringArrayMetadata(metadata?.sources).length > 0
    ? stringArrayMetadata(metadata?.sources).sort()
    : node.sources.filter((source) => source.includes("api-inventory-normalizer"));
  const authRequired = stringMetadata(metadata?.authRequired) ?? "unknown";
  return {
    method,
    pathTemplate,
    queryParams,
    bodyParamHints,
    riskSignals,
    sources,
    authRequired,
    confidence: node.confidence,
    examples: stringArrayMetadata(metadata?.examples).slice(0, 3),
    score: scoreDecisionApiRoute({
      method,
      pathTemplate,
      queryParams,
      bodyParamHints,
      riskSignals,
      sources,
      authRequired,
      confidence: node.confidence,
      examples: []
    })
  };
}

function compareDecisionApiRoutes(left: DecisionApiRoute, right: DecisionApiRoute): number {
  return right.score - left.score
    || confidenceRankValue(right.confidence) - confidenceRankValue(left.confidence)
    || right.riskSignals.length - left.riskSignals.length
    || left.pathTemplate.localeCompare(right.pathTemplate)
    || left.method.localeCompare(right.method);
}

function scoreDecisionApiRoute(route: Omit<DecisionApiRoute, "score">): number {
  let score = confidenceRankValue(route.confidence) * 10 + 10;
  if (route.sources.some((source) => /network|openapi|graphql/i.test(source))) score += 12;
  if (route.queryParams.length > 0) score += Math.min(10, route.queryParams.length * 2);
  if (route.bodyParamHints.length > 0) score += Math.min(12, route.bodyParamHints.length * 2);
  if (route.riskSignals.some((signal) => /privileged-route|admin|auth-gated/i.test(signal)) || hasAdminSurfaceSignal(route.pathTemplate)) score += 30;
  if (route.riskSignals.some((signal) => /object-or-tokenized-path|object-id/i.test(signal)) || /\{(?:id|uuid|token|email|slug)\}/i.test(route.pathTemplate)) score += 22;
  if (route.riskSignals.some((signal) => /business-workflow-route|workflow/i.test(signal)) || hasBusinessWorkflowSignal(route.pathTemplate)) score += 18;
  if (/^(?:POST|PUT|PATCH|DELETE)$/i.test(route.method) || route.riskSignals.some((signal) => /state-changing-method/i.test(signal))) score += 10;
  if (/graphql/i.test(route.pathTemplate) || route.riskSignals.some((signal) => /graphql/i.test(signal))) score += 10;
  if (route.authRequired === "likely") score += 8;
  if (route.riskSignals.some((signal) => /auth-surface/i.test(signal))) score -= 8;
  return Math.max(1, score);
}

function renderDecisionApiRouteBrief(route: DecisionApiRoute): string {
  const params = [
    route.queryParams.length > 0 ? `query=${route.queryParams.slice(0, 4).join("|")}` : undefined,
    route.bodyParamHints.length > 0 ? `body=${route.bodyParamHints.slice(0, 4).join("|")}` : undefined,
    route.riskSignals.length > 0 ? `risk=${route.riskSignals.slice(0, 4).join("|")}` : undefined,
    route.sources.length > 0 ? `src=${route.sources.slice(0, 3).join("|")}` : undefined
  ].filter((item): item is string => Boolean(item));
  return `${route.method} ${route.pathTemplate}${params.length > 0 ? ` (${params.join("; ")})` : ""}`;
}

function routeRiskSignals(pathTemplate: string, method: string): string[] {
  const signals: string[] = [];
  if (/^(?:POST|PUT|PATCH|DELETE)$/i.test(method)) signals.push("state-changing-method");
  if (hasAdminSurfaceSignal(pathTemplate)) signals.push("privileged-route");
  if (hasBusinessWorkflowSignal(pathTemplate)) signals.push("business-workflow-route");
  if (/\{(?:id|uuid|token|email|slug)\}/i.test(pathTemplate)) signals.push("object-or-tokenized-path");
  if (/graphql/i.test(pathTemplate)) signals.push("graphql-endpoint");
  return signals;
}

function parseJsonRecord(value: string | undefined): Record<string, unknown> | undefined {
  if (!value) return undefined;
  try {
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function stringMetadata(value: unknown): string | undefined {
  return typeof value === "string" && value.trim() ? value : undefined;
}

function stringArrayMetadata(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value.filter((item): item is string => typeof item === "string" && item.trim().length > 0);
}

function sanitizeDecisionParamHints(values: string[]): string[] {
  return uniqueStrings(values
    .map((value) => value.trim())
    .filter((value) => value.length > 0)
    .map((value) => looksSecretLikeDecisionParamHint(value) ? "[redacted-param-name]" : value));
}

function looksSecretLikeDecisionParamHint(value: string): boolean {
  const normalized = value.replace(/\[[^\]]+\]$/g, "");
  if (/^[a-f0-9]{16,}$/i.test(normalized)) return true;
  if (/^[A-Za-z0-9_-]{24,}$/.test(normalized) && /[0-9]/.test(normalized) && /[A-Za-z]/.test(normalized)) return true;
  if (/^eyJ[A-Za-z0-9_-]{12,}\.[A-Za-z0-9_-]{12,}/.test(normalized)) return true;
  return false;
}

function pathFromUrlLike(value: string): string | undefined {
  try {
    return new URL(value).pathname || "/";
  } catch {
    return value.startsWith("/") ? value : undefined;
  }
}

function annotateDecisionAttempts(items: SecurityDecisionQueueItem[], runs: SecurityToolRun[]): void {
  const noProgressStatuses: SecurityToolRunStatus[] = ["blocked", "missing", "denied", "failed", "skipped", "no_findings"];
  for (const item of items) {
    const relatedRuns = item.toolId
      ? runs.filter((run) => run.toolId === item.toolId)
      : runs.filter((run) => item.fallbackFor && run.toolId === item.fallbackFor);
    if (relatedRuns.length === 0) {
      continue;
    }
    const noProgressRuns = relatedRuns.filter((run) => noProgressStatuses.includes(run.status));
    const successfulEvidenceRun = relatedRuns.some((run) => run.status === "success" && ((run.findingCount ?? 0) > 0 || Boolean(run.outputArtifact) || Boolean(run.outputSummary?.trim())));
    item.attemptCount = relatedRuns.length;
    item.failureMemory = relatedRuns
      .filter((run) => noProgressStatuses.includes(run.status))
      .slice(-3)
      .map((run) => `${run.toolId}:${run.status}${run.failureCategory ? `/${run.failureCategory}` : ""}${run.outputSummary ? ` - ${run.outputSummary.split(/\r?\n/)[0]}` : ""}`);
    if (relatedRuns.length >= 3 && noProgressRuns.length >= 3 && !successfulEvidenceRun && !item.blockedBy) {
      const targetHint = item.target ? ` for ${item.target}` : "";
      item.blockedBy = `repeated ${item.toolId ?? item.fallbackFor} attempts${targetHint} did not add evidence`;
      item.reason = `${item.reason} Current blocker: the same evidence-free action has already been attempted ${relatedRuns.length} times; pivot to a different evidence source before retrying.`;
    }
    item.score = scoreDecisionItem(item);
    item.confidence = confidenceForDecision(item);
  }
}

function pushDecision(
  items: SecurityDecisionQueueItem[],
  item: Omit<SecurityDecisionQueueItem, "id">,
  inventory: Map<string, SecurityToolInventoryItem>
): void {
  const tool = item.toolId ? inventory.get(item.toolId) : undefined;
  const blockedBy = item.blockedBy ?? (item.toolId && tool && !tool.available ? `${item.toolId} binary unavailable` : undefined);
  const attemptCount = item.attemptCount ?? 0;
  const score = item.score ?? scoreDecisionItem({ ...item, blockedBy, attemptCount });
  const id = [
    item.priority,
    item.phase,
    item.actionType,
    item.toolId ?? "manual",
    item.title,
    item.target
  ].join(":").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 120);
  if (items.some((existing) => existing.id === id)) {
    return;
  }
  items.push({
    ...item,
    id,
    blockedBy,
    score,
    confidence: item.confidence ?? confidenceForDecision({ ...item, blockedBy, attemptCount }),
    attemptCount,
    failureMemory: item.failureMemory ?? []
  });
}

function latestAuthzPlanSummary(toolRuns: SecurityToolRun[]): { total: number; ready: number; blocked: number; needsExample: number; passive: number; compared: number } | undefined {
  const run = [...toolRuns]
    .reverse()
    .find((item) => item.toolId === "authz-plan" && ["success", "no_findings"].includes(item.status));
  const text = run?.outputSummary ?? "";
  if (!text) return undefined;
  const read = (name: string): number => {
    const match = text.match(new RegExp(`\\b${name}=([0-9]+)\\b`, "i"));
    return match ? Number.parseInt(match[1], 10) : 0;
  };
  return {
    total: read("total"),
    ready: read("ready"),
    blocked: read("blocked"),
    needsExample: read("needsExample"),
    passive: read("passive"),
    compared: read("compared")
  };
}

function compareDecisionQueueItems(left: SecurityDecisionQueueItem, right: SecurityDecisionQueueItem): number {
  const priority: Record<SecurityDecisionQueueItem["priority"], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3
  };
  const phase: Record<SecurityPhase, number> = {
    scope: 0,
    recon: 1,
    asset_discovery: 2,
    fingerprint: 3,
    frontend: 4,
    vulnerability_analysis: 5,
    safe_validation: 6,
    reporting: 7
  };
  return (Number(Boolean(left.blockedBy)) - Number(Boolean(right.blockedBy)))
    || ((right.score ?? 0) - (left.score ?? 0))
    || (priority[left.priority] - priority[right.priority])
    || (phase[left.phase] - phase[right.phase])
    || left.title.localeCompare(right.title);
}

function scoreDecisionItem(item: Omit<SecurityDecisionQueueItem, "id">): number {
  const priorityScore: Record<SecurityDecisionQueueItem["priority"], number> = {
    critical: 100,
    high: 80,
    medium: 55,
    low: 30
  };
  const phaseScore: Record<SecurityPhase, number> = {
    scope: 5,
    recon: 10,
    asset_discovery: 15,
    fingerprint: 20,
    frontend: 25,
    vulnerability_analysis: 30,
    safe_validation: 35,
    reporting: 20
  };
  const actionBonus = item.actionType === "tool" ? 10 : item.actionType === "subagent" ? 6 : item.actionType === "manual" ? 4 : 2;
  const fallbackPenalty = item.fallbackFor ? -6 : 0;
  const blockedPenalty = item.blockedBy ? -45 : 0;
  const retryPenalty = Math.min(item.attemptCount ?? 0, 5) * -8;
  const evidenceBonus = Math.min(item.expectedEvidence.length, 4) * 3;
  return Math.max(0, priorityScore[item.priority] + phaseScore[item.phase] + actionBonus + fallbackPenalty + blockedPenalty + retryPenalty + evidenceBonus);
}

function confidenceForDecision(item: Omit<SecurityDecisionQueueItem, "id">): "low" | "medium" | "high" {
  if (item.blockedBy) return "low";
  if (item.actionType === "authorization") return "high";
  if (item.prerequisites.length > 2 && item.expectedEvidence.length > 1) return "high";
  if (item.fallbackFor || item.attemptCount && item.attemptCount > 0) return "medium";
  return item.actionType === "tool" ? "high" : "medium";
}

function compareCoordinationItems(left: SubAgentCoordinationPlanItem, right: SubAgentCoordinationPlanItem): number {
  const priority: Record<SubAgentCoordinationPlanItem["priority"], number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3
  };
  const roleOrder: Record<SubAgentRole, number> = {
    recon: 0,
    fingerprint: 1,
    frontend: 2,
    cve: 3,
    web_vuln: 4,
    exploit: 5,
    reviewer: 6,
    explorer: 7,
    worker: 8,
    default: 9
  };
  return (priority[left.priority] - priority[right.priority])
    || (roleOrder[left.role] - roleOrder[right.role])
    || left.title.localeCompare(right.title);
}

function severityPriority(severity: FindingSeverity): number {
  const rank: Record<FindingSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  return rank[severity] ?? 9;
}

function businessRouteKeywordFor(item: BusinessLogicKnowledgeItem): string[] {
  const text = `${item.title} ${item.category} ${item.passiveSignals.join(" ")}`.toLowerCase();
  const keywords = new Set<string>();
  for (const word of ["admin", "manage", "user", "account", "order", "invoice", "ticket", "cart", "payment", "refund", "coupon", "credit", "transfer", "withdraw", "2fa", "otp", "invite", "tenant", "org", "workspace", "upload", "download", "share", "delete", "export", "api"]) {
    if (text.includes(word)) {
      keywords.add(word);
    }
  }
  return [...keywords];
}

function selectBusinessTargetHints(targetHints: string[], item: BusinessLogicKnowledgeItem): string[] {
  const keywords = businessRouteKeywordFor(item);
  const matched = targetHints.filter((hint) => keywords.some((keyword) => hint.toLowerCase().includes(keyword)));
  return (matched.length > 0 ? matched : targetHints).slice(0, 8);
}

function blockedReasonForAdapter(adapter: SecurityToolAdapter, scope: PentestScope): string | undefined {
  if (adapter.intensity === "active" && !scope.allowActiveProbing) {
    return "Active probing is disabled in the current pentest scope.";
  }
  if (adapter.capabilities.includes("cidr_discovery") && !scope.allowCidrDiscovery) {
    return "CIDR/C-segment discovery is disabled in the current pentest scope.";
  }
  return undefined;
}

function missingCommandReason(adapter: SecurityToolAdapter, scope: PentestScope): string {
  if (adapter.id === "nuclei-owasp" && scope.allowActiveProbing) {
    return "Generic nuclei validation is not auto-run; use focused template IDs or tags from the decision queue to avoid long, low-signal scans.";
  }
  if (adapter.id === "nuclei-snmp" && scope.allowActiveProbing) {
    return "SNMP nuclei validation requires the host to be reachable on UDP port 161. The adapter will probe SNMP using targeted template IDs.";
  }
  const active = adapter.intensity === "active" && !scope.allowActiveProbing
    ? " Active probing is disabled."
    : "";
  return `No executable command can be built for this adapter in the current scope.${active}`;
}

export function renderPentestPipelineMarkdown(pipeline: PentestPipeline): string {
  const scope = pipeline.scope;
  const lines = [
    `# Autonomous Pentest Plan: ${pipeline.target.normalized}`,
    "",
    "## Scope",
    `- allowed: ${scope.allowedTargets.join(", ")}`,
    `- excluded: ${scope.excludedTargets.join(", ")}`,
    `- intensity: ${scope.intensity}`,
    `- profile: ${scope.scanProfile}`,
    `- active probing: ${scope.allowActiveProbing ? "enabled" : "disabled"}`,
    `- C-segment discovery: ${scope.allowCidrDiscovery ? "enabled" : "disabled"}`,
    `- rate limit: ${scope.rateLimitPerSecond}/s`,
    "",
    "## Steps"
  ];
  for (const step of pipeline.steps) {
    lines.push(`- [${step.phase}] ${step.title} (${step.kind}, ${step.intensity})`);
    if (step.command) {
      lines.push(`  command: ${step.command}`);
    }
    if (step.blockedReason) {
      lines.push(`  blocked: ${step.blockedReason}`);
    }
  }
  return lines.join("\n");
}

type PhaseTemplate = {
  phase: SecurityPhase;
  title: string;
  description: string;
  role?: SubAgentRole;
  skillQuery: string;
  tools: string[];
};

const pentagiInspiredPhases: PhaseTemplate[] = [
  {
    phase: "scope",
    title: "Confirm scope and rules of engagement",
    description: "Identify the exact authorized target, excluded assets, intensity limits, and whether active probing is allowed before any network action.",
    role: "reviewer",
    skillQuery: "scope authorization rules engagement pentest",
    tools: []
  },
  {
    phase: "recon",
    title: "Passive reconnaissance plan",
    description: "Collect passive DNS, WHOIS, certificate, public search, and historical context. Convert uncertain observations into explicit follow-up questions.",
    role: "recon",
    skillQuery: "recon osint dns certificate subdomain",
    tools: ["subfinder", "amass", "crtsh", "whois", "dnsx"]
  },
  {
    phase: "asset_discovery",
    title: "Asset and attack-surface discovery",
    description: "Discover subdomains, HTTP services, related IP ranges, and exposed management surfaces. Keep execution approval-gated and rate-limited.",
    role: "recon",
    skillQuery: "asset discovery subdomain httpx katana port scan",
    tools: ["subfinder", "dnsx", "httpx", "katana", "nmap"]
  },
  {
    phase: "fingerprint",
    title: "Technology fingerprinting",
    description: "Infer frameworks, servers, versions, CDNs, WAFs, JavaScript frameworks, exposed headers, and confidence levels from gathered evidence.",
    role: "fingerprint",
    skillQuery: "fingerprint technology stack version headers waf",
    tools: ["httpx", "wappalyzer", "whatweb", "nmap"]
  },
  {
    phase: "frontend",
    title: "Frontend and client-side exposure review",
    description: "Review frontend assets for source maps, hidden routes, API endpoints, hardcoded keys, debug flags, and authorization assumptions.",
    role: "frontend",
    skillQuery: "frontend js source map api secret route exposure",
    tools: ["katana", "trufflehog", "gitleaks", "linkfinder"]
  },
  {
    phase: "vulnerability_analysis",
    title: "Vulnerability intelligence matching",
    description: "Map confirmed technologies and versions to local knowledge, skills, CVEs, advisories, and known misconfiguration patterns.",
    role: "cve",
    skillQuery: "cve vulnerability advisory version exploit database",
    tools: ["nuclei", "cve-search", "vulners", "sploitus"]
  },
  {
    phase: "safe_validation",
    title: "Safe validation and OWASP checks",
    description: "Validate likely issues with non-destructive checks only. Separate evidence-backed findings from hypotheses and require approval for active probes.",
    role: "web_vuln",
    skillQuery: "owasp top 10 xss sqli ssrf auth upload misconfiguration",
    tools: ["nuclei", "curl", "dirsearch"]
  },
  {
    phase: "reporting",
    title: "Findings, evidence, and remediation synthesis",
    description: "Normalize observations into findings with severity, confidence, affected target, evidence, reproduction boundary, and remediation.",
    role: "reviewer",
    skillQuery: "finding evidence remediation report pentest",
    tools: []
  }
];

export async function buildSecurityWorkflowPlan(
  sessionId: string,
  target: TargetInput,
  registry: SkillRegistry,
  options: { includeHighRisk?: boolean; skillsPerPhase?: number } = {}
): Promise<SecurityWorkflowPlan> {
  const now = nowIso();
  const workflow: SecurityWorkflow = {
    id: newId("swf"),
    sessionId,
    target,
    status: "pending",
    currentPhase: "scope",
    summary: `Authorized security workflow for ${target.kind}:${target.normalized}`,
    createdAt: now,
    updatedAt: now
  };

  const tasks: SecurityWorkflowTask[] = [];
  for (const template of pentagiInspiredPhases) {
    const skills = await registry.search(`${target.normalized} ${template.skillQuery}`, {
      limit: options.skillsPerPhase ?? 4,
      includeHighRisk: options.includeHighRisk ?? true
    });
    tasks.push({
      id: newId("stask"),
      workflowId: workflow.id,
      sessionId,
      phase: template.phase,
      title: template.title,
      description: template.description,
      recommendedRole: template.role,
      suggestedSkills: skills.map((skill) => skill.id),
      suggestedTools: template.tools,
      status: "pending",
      createdAt: now,
      updatedAt: now
    });
  }

  return {
    workflow,
    tasks,
    prompt: renderSecurityWorkflowPrompt(workflow, tasks)
  };
}

export async function buildSkillExecutionPlan(
  query: string,
  registry: SkillRegistry,
  options: { limit?: number; includeHighRisk?: boolean } = {}
): Promise<SkillExecutionPlan> {
  const matchedSkills = await registry.search(query, {
    limit: options.limit ?? 8,
    includeHighRisk: options.includeHighRisk ?? true
  });
  const tasks = matchedSkills.map((skill) => {
    const phase = inferPhase(skill);
    return {
      title: skill.name,
      phase,
      role: roleForPhase(phase),
      skillIds: [skill.id],
      tools: skill.tools,
      description: [
        skill.description,
        skill.workflow.length > 0 ? `Workflow: ${skill.workflow.join(" -> ")}` : undefined,
        skill.outputs.length > 0 ? `Expected outputs: ${skill.outputs.join(", ")}` : undefined
      ].filter(Boolean).join("\n")
    };
  });
  const prompt = [
    "Skill execution plan. Skills are guidance and never bypass approval.",
    "Compile each skill into policy-controlled tool, shell, file, or subagent actions.",
    ...tasks.map((task, index) => [
      `${index + 1}. ${task.title}`,
      `Phase: ${task.phase}`,
      task.role ? `Recommended role: ${task.role}` : undefined,
      task.tools.length > 0 ? `Tools: ${task.tools.join(", ")}` : undefined,
      `Description: ${task.description}`
    ].filter(Boolean).join("\n"))
  ].join("\n\n");
  return { query, matchedSkills, tasks, prompt };
}

export function renderSecurityWorkflowPrompt(workflow: SecurityWorkflow, tasks: SecurityWorkflowTask[]): string {
  return [
    "Pentagi-inspired security workflow is available for this session.",
    "Treat it as an orchestration map: scope -> recon -> asset discovery -> fingerprint -> frontend -> vulnerability intelligence -> safe validation -> findings.",
    "Do not execute active probes automatically. Convert each step into approved shell/tool actions or bounded subagents.",
    `Workflow: ${workflow.id}`,
    `Target: ${workflow.target.kind}:${workflow.target.normalized}`,
    ...tasks.map((task, index) => [
      `${index + 1}. [${task.phase}] ${task.title}`,
      `Description: ${task.description}`,
      task.recommendedRole ? `Recommended subagent: ${task.recommendedRole}` : undefined,
      task.suggestedSkills.length > 0 ? `Skills: ${task.suggestedSkills.join(", ")}` : undefined,
      task.suggestedTools.length > 0 ? `Candidate tools: ${task.suggestedTools.join(", ")}` : undefined
    ].filter(Boolean).join("\n"))
  ].join("\n\n");
}
