import { nowIso, type SecurityAsset, type SecurityAuthContext, type SecurityEvidence, type TargetInput } from "@aegisprobe/shared";
import type { AccessExposureItem, AccessExposureMap, AccessExposureState } from "./types.js";

export type AccessExposureMapInput = {
  target?: TargetInput;
  assets?: SecurityAsset[];
  evidence?: SecurityEvidence[];
  authContexts?: SecurityAuthContext[];
  maxItems?: number;
};

type EndpointEvidence = {
  id: string;
  endpoint: string;
  method: string;
  pathTemplate?: string;
  source: string;
  confidence: SecurityAsset["confidence"];
  status?: number;
  authRequired: AccessExposureItem["authRequired"];
  riskSignals: string[];
  queryParams: string[];
  bodyParamHints: string[];
  evidenceRefs: string[];
  anonymousBaseline?: AccessExposureItem["anonymousBaseline"];
  authenticatedBaselines: AccessExposureItem["authenticatedBaselines"];
};

export function buildAccessExposureMap(input: AccessExposureMapInput): AccessExposureMap {
  const authContexts = input.authContexts ?? [];
  const endpoints = collectEndpointEvidence(input.assets ?? [], input.evidence ?? [], input.target);
  const items = endpoints
    .map((endpoint) => exposureItemFromEndpoint(endpoint, authContexts))
    .sort((left, right) =>
      exposureStateRank(left.state) - exposureStateRank(right.state)
      || right.priorityScore - left.priorityScore
      || left.endpoint.localeCompare(right.endpoint)
    )
    .slice(0, clamp(input.maxItems ?? 30, 1, 120));

  return {
    generatedAt: nowIso(),
    target: input.target?.normalized,
    summary: {
      total: items.length,
      publicObserved: items.filter((item) => item.state === "public_observed").length,
      authGatedObserved: items.filter((item) => item.state === "auth_gated_observed").length,
      unknownAuth: items.filter((item) => item.state === "unknown_auth").length,
      needsAnonymousBaseline: items.filter((item) => item.state === "needs_anonymous_baseline").length,
      readyForRoleComparison: items.filter((item) => item.state === "ready_for_role_comparison").length,
      passiveMutationOnly: items.filter((item) => item.state === "passive_mutation_only").length,
      highValue: items.filter((item) => item.priorityScore >= 45).length
    },
    items,
    informationGaps: buildInformationGaps(items, authContexts.length),
    guardrails: [
      "This map is an information-gathering view, not a scan order.",
      "Use concrete browser/API evidence; do not invent paths, roles, tenants, object IDs, or policies.",
      "Anonymous baselines should be read-only GET/HEAD observations only.",
      "Role comparisons require approved auth contexts and expected policy before claiming impact.",
      "Mutation routes remain passive until explicit active authorization, disposable test data, and rollback boundaries exist."
    ]
  };
}

export function renderAccessExposureMap(map: AccessExposureMap): string {
  const lines = [
    `Access Exposure Map (${map.generatedAt})`,
    `Target: ${map.target ?? "unknown"}`,
    `Summary: total=${map.summary.total} public=${map.summary.publicObserved} authGated=${map.summary.authGatedObserved} unknown=${map.summary.unknownAuth} needAnon=${map.summary.needsAnonymousBaseline} roleReady=${map.summary.readyForRoleComparison} passiveMutation=${map.summary.passiveMutationOnly} highValue=${map.summary.highValue}`
  ];
  if (map.informationGaps.length > 0) {
    lines.push("Information gaps:");
    for (const gap of map.informationGaps) lines.push(`- ${gap}`);
  }
  if (map.items.length === 0) {
    lines.push("No endpoint exposure items yet.");
  } else {
    lines.push("Items:");
    for (const item of map.items) {
      lines.push(`- ${item.id} | ${item.state} | score:${item.priorityScore} | ${item.method} ${item.pathTemplate ?? item.endpoint}`);
      lines.push(`  endpoint: ${item.endpoint}`);
      lines.push(`  auth=${item.authRequired}${item.status !== undefined ? ` status=${item.status}` : ""} source=${item.source} confidence=${item.confidence}`);
      if (item.anonymousBaseline) {
        lines.push(`  anonymous baseline: status=${item.anonymousBaseline.status}${item.anonymousBaseline.bodyLength !== undefined ? ` length=${item.anonymousBaseline.bodyLength}` : ""}${item.anonymousBaseline.bodyHash ? ` hash=${item.anonymousBaseline.bodyHash}` : ""} evidence=${item.anonymousBaseline.evidenceRef}`);
      }
      if (item.authenticatedBaselines.length > 0) {
        lines.push(`  authenticated baselines: ${item.authenticatedBaselines.map((baseline) => `${baseline.authContextName ?? "auth"}=${baseline.status}${baseline.bodyLength !== undefined ? `/len:${baseline.bodyLength}` : ""}${baseline.bodyHash ? `/hash:${baseline.bodyHash}` : ""}`).join("; ")}`);
      }
      if (item.riskSignals.length > 0) lines.push(`  risk signals: ${item.riskSignals.join(", ")}`);
      if (item.queryParams.length > 0) lines.push(`  query params: ${item.queryParams.join(", ")}`);
      if (item.bodyParamHints.length > 0) lines.push(`  body hints: ${item.bodyParamHints.join(", ")}`);
      lines.push(`  information need: ${item.informationNeed}`);
      lines.push(`  safe observations: ${item.safeObservationIdeas.join("; ")}`);
      lines.push(`  rationale: ${item.priorityRationale.join("; ")}`);
      if (item.evidenceRefs.length > 0) lines.push(`  evidence refs: ${item.evidenceRefs.join(", ")}`);
    }
  }
  lines.push("Guardrails:");
  for (const guardrail of map.guardrails) lines.push(`- ${guardrail}`);
  return lines.join("\n");
}

function collectEndpointEvidence(
  assets: SecurityAsset[],
  evidence: SecurityEvidence[],
  target?: TargetInput
): EndpointEvidence[] {
  const endpoints: EndpointEvidence[] = [];
  for (const asset of assets) {
    if (asset.kind !== "url" && !/^https?:\/\//i.test(asset.value) && !asset.value.startsWith("/")) continue;
    const metadata = parseJsonObject(asset.metadata);
    const endpoint = absolutize(asset.value, target?.normalized) ?? asset.value;
    const method = stringValue(metadata?.method)?.toUpperCase() ?? "GET";
    const riskSignals = uniqueStrings([...stringArray(metadata?.riskSignals), ...routeRiskSignals(`${asset.value} ${metadata?.pathTemplate ?? ""}`)]);
    if (isLowValueAccessEndpoint(endpoint, method, riskSignals)) continue;
    endpoints.push({
      id: asset.id,
      endpoint,
      method,
      pathTemplate: stringValue(metadata?.pathTemplate) ?? pathTemplateFromEndpoint(endpoint),
      source: asset.source,
      confidence: asset.confidence,
      status: numberValue(metadata?.status),
      authRequired: authRequiredValue(metadata?.authRequired),
      riskSignals,
      queryParams: uniqueStrings([...queryNames(asset.value), ...stringArray(metadata?.queryParams)]),
      bodyParamHints: uniqueStrings(stringArray(metadata?.bodyParamHints)),
      evidenceRefs: [asset.id],
      authenticatedBaselines: []
    });
  }

  const requestLinePattern = /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s"'<>]+)/gi;
  for (const item of evidence.slice(-80)) {
    const raw = typeof item.data === "string" ? item.data : JSON.stringify(item.data ?? "");
    const fetchDetails = parseSafeFetchDetails(raw);
    if (fetchDetails) {
      const endpoint = absolutize(fetchDetails.url, target?.normalized) ?? fetchDetails.url;
      const riskSignals = routeRiskSignals(endpoint);
      if (isLowValueAccessEndpoint(endpoint, fetchDetails.method, riskSignals)) continue;
      endpoints.push({
        id: `fetch:${item.id}`,
        endpoint,
        method: fetchDetails.method,
        pathTemplate: pathTemplateFromEndpoint(endpoint),
        source: item.source,
        confidence: "high",
        status: fetchDetails.status,
        authRequired: authRequiredFromFetchDetails(fetchDetails),
        riskSignals,
        queryParams: queryNames(endpoint),
        bodyParamHints: [],
        evidenceRefs: [item.id],
        anonymousBaseline: fetchDetails.anonymous ? {
          status: fetchDetails.status,
          bodyLength: fetchDetails.bodyLength,
          bodyHash: fetchDetails.bodyHash,
          evidenceRef: item.id
        } : undefined,
        authenticatedBaselines: fetchDetails.anonymous ? [] : [{
          authContextName: fetchDetails.authContextName,
          status: fetchDetails.status,
          bodyLength: fetchDetails.bodyLength,
          bodyHash: fetchDetails.bodyHash,
          evidenceRef: item.id
        }]
      });
    }
    for (const match of raw.matchAll(requestLinePattern)) {
      const method = match[1]?.toUpperCase() ?? "GET";
      const endpoint = normalizeRequestLineEndpoint(match[2] ?? "", target?.normalized);
      if (!endpoint) continue;
      const riskSignals = routeRiskSignals(endpoint);
      if (isLowValueAccessEndpoint(endpoint, method, riskSignals)) continue;
      endpoints.push({
        id: `evidence:${item.id}:${endpoints.length + 1}`,
        endpoint,
        method,
        pathTemplate: pathTemplateFromEndpoint(endpoint),
        source: item.source,
        confidence: "medium",
        status: statusNearRequest(raw, match.index ?? 0),
        authRequired: authSignalNearRequest(raw, match.index ?? 0),
        riskSignals,
        queryParams: queryNames(endpoint),
        bodyParamHints: ["GET", "HEAD"].includes(method) ? [] : bodyHintsNearRequest(raw, match.index ?? 0),
        evidenceRefs: [item.id],
        authenticatedBaselines: []
      });
    }
  }

  return dedupeEndpoints(endpoints);
}

function exposureItemFromEndpoint(endpoint: EndpointEvidence, authContexts: SecurityAuthContext[]): AccessExposureItem {
  const state = exposureState(endpoint, authContexts.length);
  const priority = priorityForEndpoint(endpoint, state, authContexts.length);
  return {
    id: `access:${stableId(endpoint.method, endpoint.pathTemplate ?? endpoint.endpoint)}`,
    method: endpoint.method,
    endpoint: endpoint.endpoint,
    pathTemplate: endpoint.pathTemplate,
    source: endpoint.source,
    confidence: endpoint.confidence,
    state,
    authRequired: endpoint.authRequired,
    status: endpoint.status,
    anonymousBaseline: endpoint.anonymousBaseline,
    authenticatedBaselines: endpoint.authenticatedBaselines,
    riskSignals: endpoint.riskSignals,
    queryParams: endpoint.queryParams,
    bodyParamHints: endpoint.bodyParamHints,
    evidenceRefs: endpoint.evidenceRefs,
    priorityScore: priority.score,
    priorityRationale: priority.rationale,
    informationNeed: informationNeedFor(endpoint, state, authContexts.length),
    safeObservationIdeas: safeObservationIdeasFor(endpoint, state, authContexts)
  };
}

function exposureState(endpoint: EndpointEvidence, authContextCount: number): AccessExposureState {
  const readOnly = ["GET", "HEAD"].includes(endpoint.method);
  const highValue = routeRiskSignals(`${endpoint.endpoint} ${endpoint.pathTemplate ?? ""}`).length > 0 || endpoint.riskSignals.length > 0;
  if (!readOnly) return "passive_mutation_only";
  if (endpoint.anonymousBaseline && [401, 403].includes(endpoint.anonymousBaseline.status)) return "auth_gated_observed";
  if (endpoint.anonymousBaseline && endpoint.anonymousBaseline.status >= 200 && endpoint.anonymousBaseline.status < 300) return "public_observed";
  if (endpoint.status && [401, 403].includes(endpoint.status)) return "auth_gated_observed";
  if (endpoint.status && endpoint.status >= 200 && endpoint.status < 300 && endpoint.authRequired === "not_observed") return "public_observed";
  if (highValue && endpoint.authRequired !== "not_observed") return "needs_anonymous_baseline";
  if (authContextCount >= 2 && highValue) return "ready_for_role_comparison";
  return "unknown_auth";
}

function priorityForEndpoint(endpoint: EndpointEvidence, state: AccessExposureState, authContextCount: number): { score: number; rationale: string[] } {
  const rationale: string[] = [];
  let score = confidenceRank(endpoint.confidence) * 10 + 10;
  if (endpoint.source.includes("api-inventory-normalizer") || endpoint.source.includes("webapp-recon")) {
    score += 8;
    rationale.push("runtime or normalized API evidence");
  }
  if (endpoint.pathTemplate) {
    score += 6;
    rationale.push("path template available");
  }
  if (endpoint.queryParams.length > 0 || endpoint.bodyParamHints.length > 0) {
    score += 8;
    rationale.push("insertion points observed");
  }
  if (endpoint.riskSignals.length > 0) {
    score += endpoint.riskSignals.length * 5;
    rationale.push(`risk signals: ${endpoint.riskSignals.join(",")}`);
  }
  if (/\/(?:admin|manage|account|users?|orders?|tenant|invoice|payment|export|download|files?)(?:\/|\?|$)/i.test(endpoint.endpoint)) {
    score += 12;
    rationale.push("business/authz-sensitive route");
  }
  if (state === "ready_for_role_comparison") {
    score += 15;
    rationale.push(`${authContextCount} auth contexts available`);
  }
  if (state === "needs_anonymous_baseline") {
    score += 12;
    rationale.push("needs unauthenticated baseline");
  }
  if (state === "passive_mutation_only") {
    score -= 4;
    rationale.push("state-changing method; passive only");
  }
  if (endpoint.anonymousBaseline) {
    if (endpoint.anonymousBaseline.status > 0) {
      score += 8;
      rationale.push(`anonymous baseline status=${endpoint.anonymousBaseline.status}`);
    } else {
      score += 2;
      rationale.push("anonymous baseline inconclusive: request error or timeout");
    }
  }
  if (endpoint.authenticatedBaselines.length > 0) {
    score += 6;
    rationale.push(`authenticated baselines=${endpoint.authenticatedBaselines.map((baseline) => `${baseline.authContextName ?? "auth"}:${baseline.status}`).join(",")}`);
  }
  if (rationale.length === 0) rationale.push("endpoint requires auth/exposure characterization");
  return { score: Math.max(1, score), rationale };
}

function isLowValueAccessEndpoint(endpoint: string, method: string, riskSignals: string[]): boolean {
  if (hasAccessRiskSignals(riskSignals)) return false;
  let pathname = endpoint;
  try {
    pathname = new URL(endpoint).pathname;
  } catch {
    // Keep the raw value for relative paths.
  }
  const decoded = decodeURIComponentSafe(pathname);
  if (looksLikeExpressionOrTextArtifact(decoded)) return true;
  if (isStaticLikePath(pathname) || isStaticLikePath(decoded)) return true;
  return false;
}

function hasAccessRiskSignals(riskSignals: string[]): boolean {
  return riskSignals.some((signal) => /api|graphql|admin|auth|business|privileged|tenant|object|workflow/i.test(signal));
}

function normalizeRequestLineEndpoint(rawEndpoint: string, base?: string): string | undefined {
  const trimmed = rawEndpoint.trim().replace(/[),.;]+$/g, "");
  if (!/^(?:https?:\/\/|\/)/i.test(trimmed)) return undefined;
  if (/[\s"'<>\\]/.test(trimmed)) return undefined;
  const decodedRaw = decodeURIComponentSafe(trimmed);
  if (looksLikeExpressionOrTextArtifact(decodedRaw)) return undefined;

  const normalized = absolutize(trimmed, base) ?? trimmed;
  let pathname = normalized;
  try {
    pathname = new URL(normalized).pathname;
  } catch {
    // Keep the raw value for relative paths.
  }
  if (looksLikeExpressionOrTextArtifact(decodeURIComponentSafe(pathname))) return undefined;
  return normalized;
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

function informationNeedFor(endpoint: EndpointEvidence, state: AccessExposureState, authContextCount: number): string {
  switch (state) {
    case "public_observed":
      return "Confirm whether public access is intended and whether response contains sensitive business data.";
    case "auth_gated_observed":
      return "Keep the auth gate evidence; collect role/object comparison only with approved contexts.";
    case "ready_for_role_comparison":
      return "Collect read-only cross-role or cross-tenant response differences and compare with expected policy.";
    case "needs_anonymous_baseline":
      return "Collect an anonymous GET/HEAD baseline before treating authenticated success as access-control evidence.";
    case "passive_mutation_only":
      return "Record method, body fields, object references, and expected policy; do not replay without active authorization.";
    case "unknown_auth":
      return authContextCount > 0
        ? "Collect anonymous baseline and one authenticated baseline to classify exposure."
        : "Collect anonymous baseline and register approved auth context if the route appears sensitive.";
  }
}

function safeObservationIdeasFor(endpoint: EndpointEvidence, state: AccessExposureState, authContexts: SecurityAuthContext[]): string[] {
  const ideas: string[] = [];
  if (["GET", "HEAD"].includes(endpoint.method)) {
    if (endpoint.anonymousBaseline?.status === 0) {
      ideas.push(`retry anonymous_baseline_fetch ${endpoint.method} with timeout/error evidence, then compare with GET/HEAD variant if needed`);
    }
    if (state === "needs_anonymous_baseline" || state === "unknown_auth" || state === "public_observed") {
      if (!endpoint.anonymousBaseline) {
        ideas.push(`anonymous_baseline_fetch ${endpoint.method} for status, redirects, content type, body length/hash, and body excerpt`);
      }
    }
    if (authContexts.length > 0) {
      ideas.push(`authenticated ${endpoint.method} baseline with ${authContexts[0]?.name}`);
    }
    if (authContexts.length >= 2 && (state === "ready_for_role_comparison" || endpoint.riskSignals.length > 0)) {
      ideas.push(`read-only comparison between ${authContexts[0]?.name} and ${authContexts[1]?.name}`);
    }
  } else {
    ideas.push("capture form/API schema, body fields, CSRF/session requirements, and expected policy without replaying mutation");
  }
  if (endpoint.queryParams.length > 0) ideas.push(`parameter inventory: ${endpoint.queryParams.join(", ")}`);
  if (endpoint.bodyParamHints.length > 0) ideas.push(`body field inventory: ${endpoint.bodyParamHints.join(", ")}`);
  return uniqueStrings(ideas);
}

function buildInformationGaps(items: AccessExposureItem[], authContextCount: number): string[] {
  const gaps: string[] = [];
  if (items.length === 0) gaps.push("No runtime/API endpoint evidence is available; run browser-driven collection or import an API description.");
  if (items.some((item) => item.state === "needs_anonymous_baseline" || item.state === "unknown_auth")) {
    gaps.push("Anonymous baseline coverage is incomplete for one or more sensitive or unknown-auth endpoints.");
  }
  if (authContextCount < 1 && items.some((item) => item.priorityScore >= 35)) {
    gaps.push("No approved auth context is registered, so authenticated business-logic comparison is blocked.");
  }
  if (authContextCount < 2 && items.some((item) => /object|tenant|admin|privileged|business/i.test(item.riskSignals.join(" ")))) {
    gaps.push("Two approved roles/users/tenants are needed before BOLA/BFLA comparison.");
  }
  if (items.some((item) => item.state === "passive_mutation_only")) {
    gaps.push("State-changing routes are mapped only passively until active authorization and test-data boundaries are explicit.");
  }
  return gaps;
}

function authRequiredValue(value: unknown): AccessExposureItem["authRequired"] {
  return value === "likely" ? "likely" : value === "not_observed" || value === "false" || value === false ? "not_observed" : "unknown";
}

function authSignalFromText(value: string): AccessExposureItem["authRequired"] {
  if (/\b(?:401|403|unauthorized|forbidden|login required|auth required)\b/i.test(value)) return "likely";
  if (/\b(?:public|anonymous|unauthenticated)\b/i.test(value)) return "not_observed";
  return "unknown";
}

function authSignalNearRequest(raw: string, index: number): AccessExposureItem["authRequired"] {
  const status = statusNearRequest(raw, index);
  if (status && [401, 403].includes(status)) return "likely";
  const window = raw.slice(Math.max(0, index - 160), index + 300);
  if (/\b(?:unauthorized|forbidden|login required|auth required)\b/i.test(window)) return "likely";
  return "unknown";
}

type ParsedSafeFetchDetails = {
  url: string;
  method: "GET" | "HEAD";
  anonymous: boolean;
  authContextName?: string;
  status: number;
  bodyLength?: number;
  bodyHash?: string;
};

function parseSafeFetchDetails(raw: string): ParsedSafeFetchDetails | undefined {
  const parsed = parseJsonObject(raw) ?? parseJsonObject(extractJsonObjectText(raw));
  const url = stringValue(parsed?.url);
  const method = stringValue(parsed?.method)?.toUpperCase();
  const status = numberValue(parsed?.status);
  if (!url || (method !== "GET" && method !== "HEAD") || status === undefined) {
    return undefined;
  }
  const anonymous = parsed?.anonymous === true;
  return {
    url,
    method,
    anonymous,
    authContextName: stringValue(parsed?.authContextName ?? parsed?.authContext),
    status,
    bodyLength: numberValue(parsed?.bodyLength),
    bodyHash: stringValue(parsed?.bodyHash)
  };
}

function extractJsonObjectText(raw: string): string | undefined {
  const start = raw.indexOf("{");
  const end = raw.lastIndexOf("}");
  return start >= 0 && end > start ? raw.slice(start, end + 1) : undefined;
}

function authRequiredFromFetchDetails(details: ParsedSafeFetchDetails): AccessExposureItem["authRequired"] {
  if (details.anonymous && [401, 403].includes(details.status)) return "likely";
  if (details.anonymous && details.status >= 200 && details.status < 300) return "not_observed";
  if (!details.anonymous && details.status >= 200 && details.status < 300) return "likely";
  return "unknown";
}

function routeRiskSignals(value: string): string[] {
  const signals: string[] = [];
  if (/\/(?:admin|manage|console|settings|roles?|permissions?)(?:\/|\?|$)/i.test(value)) signals.push("privileged-route");
  if (/\/(?:account|users?|orders?|invoice|tenant|org|workspace|project|tickets?)(?:\/|\?|$)/i.test(value)) signals.push("object-or-tenant-route");
  if (/\/(?:refund|payment|price|coupon|checkout|credit|transfer)(?:\/|\?|$)/i.test(value)) signals.push("financial-workflow-route");
  if (/\/(?:login|signin|reset|password|session|token|oauth|sso|mfa|2fa|otp)(?:\/|\?|$)/i.test(value)) signals.push("auth-workflow-route");
  if (/\/(?:export|download|upload|file|attachment|share)(?:\/|\?|$)/i.test(value)) signals.push("data-lifecycle-route");
  return signals;
}

function statusNearRequest(raw: string, index: number): number | undefined {
  const window = raw.slice(Math.max(0, index - 300), index + 500);
  const status = /\bstatus(?:Code)?["':=\s]+(\d{3})\b/i.exec(window)?.[1]
    ?? /\bHTTP\/\d(?:\.\d)?\s+(\d{3})\b/i.exec(window)?.[1];
  return status ? Number(status) : undefined;
}

function bodyHintsNearRequest(raw: string, index: number): string[] {
  const lineEnd = raw.indexOf("\n", index);
  const currentLine = raw.slice(index, lineEnd >= 0 ? lineEnd : index + 350);
  const nextBlock = lineEnd >= 0 ? raw.slice(lineEnd + 1, lineEnd + 500) : "";
  const explicitBodyBlock = /^\s*(?:\{|\[|body\b|payload\b|form\b|json\b|content-type\b|application\/json\b)/i.test(nextBlock)
    ? nextBlock.split(/\r?\n/).slice(0, 4).join("\n")
    : "";
  const window = `${currentLine}\n${explicitBodyBlock}`.slice(0, 700);
  const hints = new Set<string>();
  for (const match of window.matchAll(/"([A-Za-z][A-Za-z0-9_.-]{1,40})"\s*:/g)) {
    if (match[1] && isUsefulBodyHintName(match[1])) hints.add(match[1]);
  }
  for (const match of window.matchAll(/\b([A-Za-z][A-Za-z0-9_.-]{1,40})=/g)) {
    if (match[1] && isUsefulBodyHintName(match[1])) hints.add(match[1]);
  }
  return [...hints].slice(0, 12);
}

function isUsefulBodyHintName(value: string): boolean {
  return !/^(?:id|src|source|target|risk|risksignals|score|priority|confidence|evidence|evidencerefs|phase|auth|public|total|summary|state|status|method|endpoint|url|kind|type|createdat|updatedat)$/i.test(value);
}

function queryNames(value: string): string[] {
  try {
    const url = new URL(value, "https://placeholder.invalid");
    return [...url.searchParams.keys()].filter(Boolean).slice(0, 12);
  } catch {
    return [];
  }
}

function pathTemplateFromEndpoint(value: string): string | undefined {
  try {
    const parsed = new URL(value);
    return parsed.pathname || undefined;
  } catch {
    return value.startsWith("/") ? value.split("?")[0] : undefined;
  }
}

function dedupeEndpoints(endpoints: EndpointEvidence[]): EndpointEvidence[] {
  const byKey = new Map<string, EndpointEvidence>();
  for (const endpoint of endpoints) {
    const key = `${endpoint.method}\u0000${endpoint.pathTemplate ?? endpoint.endpoint}`.toLowerCase();
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, endpoint);
      continue;
    }
    existing.riskSignals = uniqueStrings(existing.riskSignals.concat(endpoint.riskSignals));
    existing.queryParams = uniqueStrings(existing.queryParams.concat(endpoint.queryParams));
    existing.bodyParamHints = uniqueStrings(existing.bodyParamHints.concat(endpoint.bodyParamHints));
    existing.evidenceRefs = uniqueStrings(existing.evidenceRefs.concat(endpoint.evidenceRefs));
    existing.authenticatedBaselines = mergeAuthenticatedBaselines(existing.authenticatedBaselines, endpoint.authenticatedBaselines);
    existing.anonymousBaseline = preferredAnonymousBaseline(existing.anonymousBaseline, endpoint.anonymousBaseline);
    if (existing.anonymousBaseline) {
      existing.status = existing.anonymousBaseline.status;
    } else {
      existing.status ??= endpoint.status;
    }
    existing.authRequired = mergeAuthRequired(existing.authRequired, endpoint.authRequired);
    if (!existing.pathTemplate && endpoint.pathTemplate) existing.pathTemplate = endpoint.pathTemplate;
  }
  return [...byKey.values()];
}

function preferredAnonymousBaseline(
  current: AccessExposureItem["anonymousBaseline"],
  next: AccessExposureItem["anonymousBaseline"]
): AccessExposureItem["anonymousBaseline"] {
  if (!current) return next;
  if (!next) return current;
  const currentStrong = [200, 201, 204, 301, 302, 401, 403, 404].includes(current.status);
  const nextStrong = [200, 201, 204, 301, 302, 401, 403, 404].includes(next.status);
  return nextStrong && !currentStrong ? next : current;
}

function mergeAuthenticatedBaselines(
  current: AccessExposureItem["authenticatedBaselines"],
  next: AccessExposureItem["authenticatedBaselines"]
): AccessExposureItem["authenticatedBaselines"] {
  const byKey = new Map<string, AccessExposureItem["authenticatedBaselines"][number]>();
  for (const item of current.concat(next)) {
    const key = `${item.authContextName ?? "auth"}\u0000${item.status}\u0000${item.bodyHash ?? ""}`;
    byKey.set(key, item);
  }
  return [...byKey.values()].slice(0, 6);
}

function mergeAuthRequired(
  current: AccessExposureItem["authRequired"],
  next: AccessExposureItem["authRequired"]
): AccessExposureItem["authRequired"] {
  if (next === "not_observed") return "not_observed";
  if (current === "not_observed") return "not_observed";
  if (current === "unknown" && next !== "unknown") return next;
  return current;
}

function exposureStateRank(state: AccessExposureState): number {
  switch (state) {
    case "needs_anonymous_baseline": return 0;
    case "ready_for_role_comparison": return 1;
    case "unknown_auth": return 2;
    case "public_observed": return 3;
    case "auth_gated_observed": return 4;
    case "passive_mutation_only": return 5;
  }
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

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim().length > 0))].sort();
}

function confidenceRank(confidence: SecurityAsset["confidence"]): number {
  return { low: 0, medium: 1, high: 2 }[confidence];
}

function absolutize(value: string, base?: string): string | undefined {
  try {
    return new URL(value, base ?? "https://placeholder.invalid").toString();
  } catch {
    return undefined;
  }
}

function stableId(...parts: string[]): string {
  let hash = 0;
  for (const char of parts.join("|")) {
    hash = ((hash << 5) - hash + char.charCodeAt(0)) | 0;
  }
  return Math.abs(hash).toString(36);
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
