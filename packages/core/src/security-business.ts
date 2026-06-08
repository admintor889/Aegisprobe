import { buildBusinessLogicTestPlan as buildBusinessLogicTestPlanFromSecurity, createDefaultPentestScope, type BusinessLogicTestPlan } from "@aegisprobe/security";
import { newId, nowIso, truncateForContext, type ExpectedAuthorizationPolicy, type ExpectedAuthorizationRule, type SecurityAsset, type SecurityAuthContext, type SecurityFinding, type SecurityValidationAttempt } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { businessLogicProbeUrls, safeAuthenticatedFetch, safeAuthenticatedFetchDetails } from "./security-probes.js";

export type AuthorizationBoundaryMatrix = {
  generatedAt: string;
  target: string;
  authContextCount: number;
  summary: {
    total: number;
    ready: number;
    blocked: number;
    needsExample: number;
    compared: number;
  };
  items: AuthorizationBoundaryMatrixItem[];
};

export type AuthorizationBoundaryMatrixItem = {
  id: string;
  method: string;
  pathTemplate: string;
  examples: string[];
  riskSignals: string[];
  categories: Array<"BOLA" | "BFLA" | "workflow" | "auth-session" | "financial" | "data-lifecycle">;
  authRequired: string;
  priorityScore: number;
  priorityRationale: string[];
  status: "ready_for_comparison" | "blocked_needs_auth_contexts" | "needs_concrete_example" | "passive_only" | "compared";
  comparedByEvidenceIds: string[];
  nextAction: string;
};

export type AuthorizationValidationPlan = {
  generatedAt: string;
  target: string;
  authContextCount: number;
  summary: {
    total: number;
    ready: number;
    blocked: number;
    needsExample: number;
    passiveOnly: number;
    compared: number;
  };
  candidates: AuthorizationValidationCandidate[];
  guardrails: string[];
  nextActions: string[];
};

export type AuthorizationValidationCandidate = {
  id: string;
  method: string;
  pathTemplate: string;
  categories: AuthorizationBoundaryMatrixItem["categories"];
  authRequired: string;
  status:
    | "ready_for_readonly_comparison"
    | "blocked_needs_auth_contexts"
    | "needs_concrete_example"
    | "passive_only"
    | "compared";
  examples: string[];
  objectReferences: Array<{
    location: "path" | "query" | "body";
    name: string;
    evidence: string;
  }>;
  riskSignals: string[];
  priorityScore: number;
  priorityRationale: string[];
  safeProcedure: string[];
  approvalRequired?: "read-only-comparison" | "active-mutation";
  blockedReason?: string;
  expectedEvidence: string[];
  falsePositiveGuards: string[];
};

export function buildBusinessLogicTestPlan(
  store: AuditStore,
  sessionId: string,
  buildSecurityAssetGraph: (sessionId: string) => ReturnType<AuditStore["listAssets"]> extends never ? never : any
): BusinessLogicTestPlan {
  const latestWorkflow = store.listSecurityWorkflows(sessionId).at(-1);
  const target = latestWorkflow?.target;
  return buildBusinessLogicTestPlanFromSecurity({
    target,
    graph: buildSecurityAssetGraph(sessionId),
    checks: store.listSecurityChecks(sessionId),
    scope: target ? createDefaultPentestScope(target) : undefined,
    authContexts: store.listSecurityAuthContexts(sessionId, latestWorkflow?.id)
  });
}

export function buildAuthorizationValidationPlan(store: AuditStore, sessionId: string): AuthorizationValidationPlan {
  const latestWorkflow = store.listSecurityWorkflows(sessionId).at(-1);
  const workflowId = latestWorkflow?.id;
  const matrix = buildAuthorizationBoundaryMatrix(store, sessionId);
  const assetById = new Map(
    store
      .listAssets(sessionId)
      .filter((asset) => asset.source.includes("api-inventory-normalizer") && (!workflowId || !asset.workflowId || asset.workflowId === workflowId))
      .map((asset) => [asset.id, asset])
  );
  const candidates = matrix.items
    .map((item) => authorizationValidationCandidateFromMatrixItem(item, assetById.get(item.id)))
    .sort((left, right) =>
      authzValidationStatusRank(left.status) - authzValidationStatusRank(right.status)
      || right.priorityScore - left.priorityScore
      || right.categories.length - left.categories.length
      || right.objectReferences.length - left.objectReferences.length
      || left.pathTemplate.localeCompare(right.pathTemplate)
    );
  const ready = candidates.filter((item) => item.status === "ready_for_readonly_comparison").length;
  const blocked = candidates.filter((item) => item.status === "blocked_needs_auth_contexts").length;
  const needsExample = candidates.filter((item) => item.status === "needs_concrete_example").length;
  const passiveOnly = candidates.filter((item) => item.status === "passive_only").length;
  const compared = candidates.filter((item) => item.status === "compared").length;
  return {
    generatedAt: nowIso(),
    target: matrix.target,
    authContextCount: matrix.authContextCount,
    summary: {
      total: candidates.length,
      ready,
      blocked,
      needsExample,
      passiveOnly,
      compared
    },
    candidates,
    guardrails: [
      "Use browser/API evidence to select endpoints; do not invent paths, parameters, roles, tenants, or object identifiers.",
      "GET/HEAD examples may be compared across approved auth contexts; mutation methods stay passive until explicit active authorization and test-data boundaries exist.",
      "BOLA requires object-level proof: same function is reachable, but object ownership changes or cross-tenant access is observed.",
      "BFLA requires function-level proof: a lower-privileged context reaches a function it should not reach according to an expected role policy.",
      "Do not report scanner-only, single-role, or single-response parity as validated impact without expected permission evidence."
    ],
    nextActions: authorizationValidationNextActions({ ready, blocked, needsExample, passiveOnly, compared, authContextCount: matrix.authContextCount })
  };
}

export function addSecurityAuthContext(
  store: AuditStore,
  sessionId: string,
  input: Omit<SecurityAuthContext, "id" | "sessionId" | "workflowId" | "createdAt" | "updatedAt"> & { workflowId?: string }
): SecurityAuthContext {
  const latestWorkflow = store.listSecurityWorkflows(sessionId).at(-1);
  const now = nowIso();
  const context: SecurityAuthContext = {
    id: newId("auth"),
    sessionId,
    workflowId: input.workflowId ?? latestWorkflow?.id,
    name: input.name,
    baseUrl: input.baseUrl ?? latestWorkflow?.target.normalized,
    role: input.role,
    tenant: input.tenant,
    username: input.username,
    cookieHeader: input.cookieHeader,
    authorizationHeader: input.authorizationHeader,
    headersJson: input.headersJson,
    storageStatePath: input.storageStatePath,
    notes: input.notes,
    createdAt: now,
    updatedAt: now
  };
  store.addSecurityAuthContext(context);
  store.addEvidence({
    id: newId("evd"),
    sessionId,
    workflowId: context.workflowId,
    source: `auth-context:${context.name}`,
    kind: "note",
    summary: `Authenticated context registered: ${context.name}${context.role ? ` (${context.role})` : ""}${context.tenant ? ` tenant=${context.tenant}` : ""}.`,
    data: JSON.stringify({
      ...context,
      cookieHeader: context.cookieHeader ? "[redacted-cookie-header]" : undefined,
      authorizationHeader: context.authorizationHeader ? "[redacted-authorization-header]" : undefined
    }, null, 2),
    createdAt: nowIso()
  });
  return context;
}

export function buildAuthorizationBoundaryMatrix(store: AuditStore, sessionId: string): AuthorizationBoundaryMatrix {
  const latestWorkflow = store.listSecurityWorkflows(sessionId).at(-1);
  const workflowId = latestWorkflow?.id;
  const authContexts = store.listSecurityAuthContexts(sessionId, workflowId);
  const comparisonEvidence = comparisonEvidenceIndex(store, sessionId, workflowId);
  const items = store
    .listAssets(sessionId)
    .filter((asset) => asset.source.includes("api-inventory-normalizer") && (!workflowId || !asset.workflowId || asset.workflowId === workflowId))
    .map((asset) => authorizationMatrixItemFromAsset(asset, authContexts.length, comparisonEvidence))
    .filter((item): item is AuthorizationBoundaryMatrixItem => Boolean(item))
    .sort((left, right) =>
      matrixStatusRank(left.status) - matrixStatusRank(right.status)
      || right.priorityScore - left.priorityScore
      || right.categories.length - left.categories.length
      || left.pathTemplate.localeCompare(right.pathTemplate)
    );
  return {
    generatedAt: nowIso(),
    target: latestWorkflow?.target.normalized ?? "unknown",
    authContextCount: authContexts.length,
    summary: {
      total: items.length,
      ready: items.filter((item) => item.status === "ready_for_comparison").length,
      blocked: items.filter((item) => item.status === "blocked_needs_auth_contexts").length,
      needsExample: items.filter((item) => item.status === "needs_concrete_example").length,
      compared: items.filter((item) => item.status === "compared").length
    },
    items
  };
}

export async function executeBusinessLogicTest(
  store: AuditStore,
  sessionId: string,
  caseIdOrNext: string,
  authContextName: string | undefined,
  deps: {
    buildBusinessLogicTestPlan: (sessionId: string) => BusinessLogicTestPlan;
  }
): Promise<string> {
  const latestWorkflow = store.listSecurityWorkflows(sessionId).at(-1);
  const plan = deps.buildBusinessLogicTestPlan(sessionId);
  const authContexts = store.listSecurityAuthContexts(sessionId, latestWorkflow?.id);
  const authContext = authContextName
    ? authContexts.find((context) => context.name === authContextName || context.id === authContextName)
    : authContexts[0];
  if (!authContext) {
    return [
      "Business-logic execution is blocked: no authenticated context is available.",
      "Register login state first with `auth-context add` using cookie/header/storage-state evidence."
    ].join("\n");
  }
  const testCase = caseIdOrNext === "next"
    ? plan.testCases[0]
    : plan.testCases.find((item) => item.id === caseIdOrNext);
  if (!testCase) {
    return `Business-logic test case not found: ${caseIdOrNext}`;
  }

  const urls = testCase.targetHints.filter((hint) => /^https?:\/\//i.test(hint)).slice(0, 5);
  if (urls.length === 0 && authContext.baseUrl) {
    urls.push(authContext.baseUrl);
  }
  const observations: string[] = [];
  for (const url of urls) {
    observations.push(await safeAuthenticatedFetch(url, authContext));
  }
  const summary = [
    `Business logic safe execution: ${testCase.id} ${testCase.title}`,
    `Auth context: ${authContext.name}${authContext.role ? ` (${authContext.role})` : ""}`,
    ...observations
  ].join("\n");
  store.addEvidence({
    id: newId("evd"),
    sessionId,
    workflowId: latestWorkflow?.id,
    source: `business-logic:run:${testCase.id}`,
    kind: "http",
    summary: truncateForContext(summary, 1000),
    data: summary,
    createdAt: nowIso()
  });
  const checks = store.listSecurityChecks(sessionId, latestWorkflow?.id)
    .filter((check) => check.checkId === testCase.id || check.checkId === "A01" || check.checkId === "A04" || check.checkId === "A07");
  for (const check of checks) {
    store.updateSecurityCheckStatus(
      check.id,
      "observed",
      `Safe authenticated read-only probe executed for ${testCase.id}.`,
      "Authenticated context and route observations exist; active mutation/replay validation still requires explicit authorization."
    );
  }
  return summary;
}

function responseEvidenceForContext(
  name: string,
  result: Awaited<ReturnType<typeof safeAuthenticatedFetchDetails>>
): {
  name: string;
  status: number;
  statusText: string;
  contentType?: string;
  location?: string;
  bodyLength: number;
  bodyHash: string;
  bodyExcerpt?: string;
  bodyTruncated: boolean;
  responseHeaders: Record<string, string>;
  error?: string;
} {
  return {
    name,
    status: result.status,
    statusText: result.statusText,
    contentType: result.contentType,
    location: result.location,
    bodyLength: result.bodyLength,
    bodyHash: result.bodyHash,
    bodyExcerpt: result.bodyExcerpt,
    bodyTruncated: result.bodyTruncated,
    responseHeaders: result.responseHeaders,
    error: result.error
  };
}

export function evaluateComparisonAgainstPolicy(
  comparisons: Array<{
    url: string;
    method: string;
    pathTemplate?: string;
    left: { name: string; role?: string; tenant?: string };
    right: { name: string; role?: string; tenant?: string };
    sameStatus: boolean;
    sameSignature: boolean;
    leftStatus?: number;
    rightStatus?: number;
    leftBodyLength?: number;
    rightBodyLength?: number;
  }>,
  policy: ExpectedAuthorizationPolicy,
  leftSubject: { name: string; role?: string; tenant?: string },
  rightSubject: { name: string; role?: string; tenant?: string }
): {
  violations: Array<{ url: string; rule: ExpectedAuthorizationRule; subject: string; detail: string }>;
  compliant: Array<{ url: string; rule: ExpectedAuthorizationRule; subject: string }>;
  notCovered: string[];
  hasDenyViolation: boolean;
} {
  const violations: Array<{ url: string; rule: ExpectedAuthorizationRule; subject: string; detail: string }> = [];
  const compliant: Array<{ url: string; rule: ExpectedAuthorizationRule; subject: string }> = [];
  const notCovered: string[] = [];
  let hasDenyViolation = false;

  for (const comparison of comparisons) {
    const matchedRules = policy.rules.filter((rule) => {
      if (rule.method && rule.method.toUpperCase() !== "ANY" && rule.method.toUpperCase() !== comparison.method.toUpperCase()) {
        return false;
      }
      const routeLower = rule.route.toLowerCase();
      const targets = uniqueStrings([comparison.url, comparison.pathTemplate].filter((value): value is string => Boolean(value))).map((value) => value.toLowerCase());
      if (routeLower.includes("{id}") || routeLower.includes("{") ) {
        const templatePattern = routeLower
          .replace(/[.*+?^${}()|[\]\\]/g, "\\$&")
          .replace(/\\\{[^}]+\\\}/g, "[^/]+");
        return targets.some((target) => new RegExp(templatePattern).test(target));
      }
      return targets.some((target) => target.includes(routeLower) || routeLower.includes(target));
    });

    if (matchedRules.length === 0) {
      notCovered.push(comparison.url);
      continue;
    }

    for (const rule of matchedRules) {
      const subject = policy.subjects.find((s) => s.id === rule.subjectId);
      const matchesLeft = subjectMatchesContext(subject, leftSubject);
      const matchesRight = subjectMatchesContext(subject, rightSubject);

      if (rule.action === "deny") {
        const violator = matchesLeft && subjectAccessSucceeded(comparison, "left")
          ? leftSubject.name
          : matchesRight && subjectAccessSucceeded(comparison, "right")
            ? rightSubject.name
            : undefined;
        if (violator) {
          hasDenyViolation = true;
          violations.push({
            url: comparison.url,
            rule,
            subject: violator,
            detail: `Subject "${violator}" received a successful response on a route where policy rule "${rule.id}" (${rule.description ?? "deny rule"}) should have blocked access.`
          });
        }
      } else if (rule.action === "allow") {
        const allowedSubject = matchesLeft ? leftSubject.name : matchesRight ? rightSubject.name : undefined;
        const allowedSide = matchesLeft ? "left" : matchesRight ? "right" : undefined;
        if (allowedSubject && allowedSide && subjectAccessSucceeded(comparison, allowedSide)) {
          compliant.push({ url: comparison.url, rule, subject: allowedSubject });
        }
      }
    }
  }

  return { violations, compliant, notCovered, hasDenyViolation };
}

function subjectAccessSucceeded(
  comparison: {
    sameStatus: boolean;
    sameSignature: boolean;
    leftStatus?: number;
    rightStatus?: number;
    leftBodyLength?: number;
    rightBodyLength?: number;
  },
  side: "left" | "right"
): boolean {
  const status = side === "left" ? comparison.leftStatus : comparison.rightStatus;
  const bodyLength = side === "left" ? comparison.leftBodyLength : comparison.rightBodyLength;
  if (typeof status !== "number") {
    return comparison.sameStatus && comparison.sameSignature;
  }
  if (status < 200 || status >= 300) {
    return false;
  }
  return typeof bodyLength === "number" ? bodyLength > 0 || status === 204 : true;
}

function subjectMatchesContext(
  subject: { name?: string; role?: string; tenant?: string; username?: string } | undefined,
  context: { name: string; role?: string; tenant?: string }
): boolean {
  if (!subject) return false;
  if (subject.name && subject.name === context.name) return true;
  if (subject.role && subject.role === context.role) return true;
  if (subject.tenant && subject.tenant === context.tenant) return true;
  if (subject.username && subject.username === context.name) return true;
  return false;
}

export async function executeBusinessLogicRoleComparison(
  store: AuditStore,
  sessionId: string,
  caseIdOrNext: string,
  leftAuthName: string | undefined,
  rightAuthName: string | undefined,
  deps: {
    buildBusinessLogicTestPlan: (sessionId: string) => BusinessLogicTestPlan;
    enrichFindingForStorage: (finding: SecurityFinding, evidenceIds?: string[]) => SecurityFinding;
    recordValidationAttempt: (input: Omit<SecurityValidationAttempt, "id" | "createdAt" | "updatedAt">) => SecurityValidationAttempt;
    expectedAuthorizationPolicy?: ExpectedAuthorizationPolicy;
  }
): Promise<string> {
  const latestWorkflow = store.listSecurityWorkflows(sessionId).at(-1);
  const plan = deps.buildBusinessLogicTestPlan(sessionId);
  const authContexts = store.listSecurityAuthContexts(sessionId, latestWorkflow?.id);
  const left = leftAuthName
    ? authContexts.find((context) => context.name === leftAuthName || context.id === leftAuthName)
    : authContexts[0];
  const right = rightAuthName
    ? authContexts.find((context) => context.name === rightAuthName || context.id === rightAuthName)
    : authContexts.find((context) => context.id !== left?.id);
  if (!left || !right) {
    return "Business-logic comparison is blocked: register two authenticated contexts first, for example customer and admin/tester.";
  }
  const testCase = caseIdOrNext === "next"
    ? plan.testCases[0]
    : plan.testCases.find((item) => item.id === caseIdOrNext);
  if (!testCase) {
    return `Business-logic test case not found: ${caseIdOrNext}`;
  }
  const probeTargets = selectRoleComparisonProbeTargets(
    store,
    sessionId,
    latestWorkflow?.id,
    testCase,
    left.baseUrl ?? right.baseUrl ?? latestWorkflow?.target.normalized
  ).slice(0, 8);
  const urls = probeTargets.map((target) => target.url);
  const comparisons: string[] = [];
  const comparisonMatrix: Array<{
    url: string;
    source: string;
    method: string;
    pathTemplate?: string;
    riskSignals: string[];
    left: {
      name: string;
      status: number;
      statusText: string;
      contentType?: string;
      location?: string;
      bodyLength: number;
      bodyHash: string;
      bodyExcerpt?: string;
      bodyTruncated: boolean;
      responseHeaders: Record<string, string>;
      error?: string;
    };
    right: {
      name: string;
      status: number;
      statusText: string;
      contentType?: string;
      location?: string;
      bodyLength: number;
      bodyHash: string;
      bodyExcerpt?: string;
      bodyTruncated: boolean;
      responseHeaders: Record<string, string>;
      error?: string;
    };
    sameStatus: boolean;
    sameSignature: boolean;
    restrictedRoute: boolean;
  }> = [];
  let parityOnRestrictedPath = false;
  for (const target of probeTargets) {
    const leftResult = await safeAuthenticatedFetchDetails(target.url, left);
    const rightResult = await safeAuthenticatedFetchDetails(target.url, right);
    const sameStatus = leftResult.status === rightResult.status;
    const sameSignature = leftResult.bodyHash === rightResult.bodyHash && leftResult.bodyLength > 0;
    const restrictedRoute = /\/(?:admin|manage|account|user|order|tenant|approval|invoice|payment|api)(?:\/|\?|$)/i.test(target.url)
      || target.riskSignals.some((signal) => /admin|object|business|privileged|auth|tenant/i.test(signal));
    if (restrictedRoute && sameStatus && leftResult.status >= 200 && leftResult.status < 300 && sameSignature) {
      parityOnRestrictedPath = true;
    }
    comparisonMatrix.push({
      url: target.url,
      source: target.source,
      method: target.method,
      pathTemplate: target.pathTemplate,
      riskSignals: target.riskSignals,
      left: responseEvidenceForContext(left.name, leftResult),
      right: responseEvidenceForContext(right.name, rightResult),
      sameStatus,
      sameSignature,
      restrictedRoute
    });
    comparisons.push([
      `URL ${target.url}`,
      `source=${target.source}${target.pathTemplate ? ` template=${target.pathTemplate}` : ""}${target.riskSignals.length ? ` risk=${target.riskSignals.join(",")}` : ""}`,
      `${left.name}: status=${leftResult.status} ${leftResult.statusText} type=${leftResult.contentType ?? "unknown"} len=${leftResult.bodyLength} hash=${leftResult.bodyHash} excerpt=${truncateForContext(leftResult.bodyExcerpt ?? "", 220).replace(/\r?\n/g, " ")}`,
      `${right.name}: status=${rightResult.status} ${rightResult.statusText} type=${rightResult.contentType ?? "unknown"} len=${rightResult.bodyLength} hash=${rightResult.bodyHash} excerpt=${truncateForContext(rightResult.bodyExcerpt ?? "", 220).replace(/\r?\n/g, " ")}`,
      `sameStatus=${sameStatus} sameSignature=${sameSignature}`
    ].join("\n"));
  }
  const summary = [
    `Business logic role comparison: ${testCase.id} ${testCase.title}`,
    `Contexts: ${left.name}${left.role ? ` (${left.role})` : ""} vs ${right.name}${right.role ? ` (${right.role})` : ""}`,
    ...comparisons
  ].join("\n\n");
  const evidenceId = newId("evd");
  store.addEvidence({
    id: evidenceId,
    sessionId,
    workflowId: latestWorkflow?.id,
    source: `business-logic:compare:${testCase.id}`,
    kind: "http",
    summary: truncateForContext(summary, 1000),
    data: JSON.stringify({
      summary,
      caseId: testCase.id,
      title: testCase.title,
      contexts: {
        left: { name: left.name, role: left.role, username: left.username, baseUrl: left.baseUrl },
        right: { name: right.name, role: right.role, username: right.username, baseUrl: right.baseUrl }
      },
      comparisons: comparisonMatrix
    }, null, 2),
    createdAt: nowIso()
  });
  // ── Policy evaluation ────────────────────────────────────────────
  const policy = deps.expectedAuthorizationPolicy;
  const policyResult = policy
    ? evaluateComparisonAgainstPolicy(
        comparisonMatrix.map((cmp) => ({
          url: cmp.url,
          method: cmp.method,
          pathTemplate: cmp.pathTemplate,
          left: { name: left.name, role: left.role, tenant: left.tenant },
          right: { name: right.name, role: right.role, tenant: right.tenant },
          sameStatus: cmp.sameStatus,
          sameSignature: cmp.sameSignature,
          leftStatus: cmp.left.status,
          rightStatus: cmp.right.status,
          leftBodyLength: cmp.left.bodyLength,
          rightBodyLength: cmp.right.bodyLength
        })),
        policy,
        { name: left.name, role: left.role, tenant: left.tenant },
        { name: right.name, role: right.role, tenant: right.tenant }
      )
    : undefined;

  if (policyResult && policyResult.hasDenyViolation) {
    // Policy violation: a deny rule was bypassed — validated finding
    store.upsertFinding(deps.enrichFindingForStorage({
      id: newId("find"),
      sessionId,
      workflowId: latestWorkflow?.id,
      title: `Authorization policy violation: cross-role access bypass`,
      severity: "high",
      confidence: "high",
      target: urls.join(", "),
      description: [
        `Expected authorization policy "${policy!.name}" has deny rules that were bypassed by one or more subjects.`,
        ...policyResult.violations.map((v) => `- ${v.detail}`)
      ].join("\n"),
      evidenceSummary: `Evidence ${evidenceId}; policy ${policy!.id}; contexts ${left.name} and ${right.name}.`,
      remediation: "Enforce the expected authorization rules server-side. Add integration tests that assert each deny rule is enforced.",
      createdAt: nowIso(),
      updatedAt: nowIso()
    }, [evidenceId]));
    deps.recordValidationAttempt({
      sessionId,
      workflowId: latestWorkflow?.id,
      targetKind: "business_logic",
      targetId: testCase.id,
      targetTitle: testCase.title,
      method: "read-only role response comparison with expected policy",
      status: "validated",
      confidence: "high",
      rationale: `Expected authorization policy "${policy!.name}" deny rules were violated: ${policyResult.violations.map((v) => v.rule.id).join(", ")}.`,
      evidenceIds: [evidenceId]
    });
  } else if (policyResult && policyResult.notCovered.length > 0 && parityOnRestrictedPath) {
    // Policy present but routes not covered — candidate/inconclusive
    store.upsertFinding(deps.enrichFindingForStorage({
      id: newId("find"),
      sessionId,
      workflowId: latestWorkflow?.id,
      title: "Cross-role response parity on route not covered by expected policy",
      severity: "medium",
      confidence: "low",
      target: urls.join(", "),
      description: "Two authenticated roles received the same successful response signature on a restricted-looking route, but the route is not covered by the expected authorization policy. Manual review required.",
      evidenceSummary: `Evidence ${evidenceId}; policy ${policy!.id}; contexts ${left.name} and ${right.name}.`,
      remediation: "Add this route to the expected authorization policy and re-run the comparison to validate.",
      createdAt: nowIso(),
      updatedAt: nowIso()
    }, [evidenceId]));
    deps.recordValidationAttempt({
      sessionId,
      workflowId: latestWorkflow?.id,
      targetKind: "business_logic",
      targetId: testCase.id,
      targetTitle: testCase.title,
      method: "read-only role response comparison with partial policy coverage",
      status: "inconclusive",
      confidence: "low",
      rationale: `Response parity observed on routes not covered by the expected policy: ${policyResult.notCovered.join(", ")}.`,
      evidenceIds: [evidenceId]
    });
  } else if (parityOnRestrictedPath) {
    // No policy available — candidate/inconclusive only
    store.upsertFinding(deps.enrichFindingForStorage({
      id: newId("find"),
      sessionId,
      workflowId: latestWorkflow?.id,
      title: "Cross-role response parity on restricted route candidate",
      severity: "medium",
      confidence: "low",
      target: urls.join(", "),
      description: "Two authenticated roles received the same successful response signature on a route that appears authorization-sensitive. This is a business-logic candidate and must be validated with expected role policy before reporting.",
      evidenceSummary: `Evidence ${evidenceId}; contexts ${left.name} and ${right.name}.`,
      remediation: "Define the expected role matrix for the workflow, enforce object/function-level authorization server-side, and add regression tests for cross-role access.",
      createdAt: nowIso(),
      updatedAt: nowIso()
    }, [evidenceId]));
    deps.recordValidationAttempt({
      sessionId,
      workflowId: latestWorkflow?.id,
      targetKind: "business_logic",
      targetId: testCase.id,
      targetTitle: testCase.title,
      method: "read-only role response comparison",
      status: "inconclusive",
      confidence: "medium",
      rationale: "Response parity on restricted-looking routes requires expected-role policy confirmation.",
      evidenceIds: [evidenceId]
    });
  } else {
    deps.recordValidationAttempt({
      sessionId,
      workflowId: latestWorkflow?.id,
      targetKind: "business_logic",
      targetId: testCase.id,
      targetTitle: testCase.title,
      method: "read-only role response comparison",
      status: "validated",
      confidence: "low",
      rationale: "No restricted-route response parity was observed in the sampled read-only requests.",
      evidenceIds: [evidenceId]
    });
  }
  return summary;
}

type RoleComparisonProbeTarget = {
  url: string;
  source: string;
  method: string;
  pathTemplate?: string;
  riskSignals: string[];
};

function selectRoleComparisonProbeTargets(
  store: AuditStore,
  sessionId: string,
  workflowId: string | undefined,
  testCase: BusinessLogicTestPlan["testCases"][number],
  fallbackUrl: string | undefined
): RoleComparisonProbeTarget[] {
  const fromNormalizedApi = store
    .listAssets(sessionId)
    .filter((asset) => asset.source.includes("api-inventory-normalizer") && (!workflowId || !asset.workflowId || asset.workflowId === workflowId))
    .flatMap((asset) => probeTargetsFromNormalizedApiAsset(asset, testCase));
  const fallback = businessLogicProbeUrls(testCase.targetHints, fallbackUrl)
    .filter(isConcreteReadOnlyUrl)
    .map((url) => ({
      url,
      source: "business-logic-plan",
      method: "GET",
      riskSignals: routeRiskSignals(url)
    }));
  return uniqueProbeTargets([...fromNormalizedApi, ...fallback])
    .sort((left, right) => probeTargetScore(right, testCase) - probeTargetScore(left, testCase) || left.url.localeCompare(right.url));
}

function probeTargetsFromNormalizedApiAsset(asset: SecurityAsset, testCase: BusinessLogicTestPlan["testCases"][number]): RoleComparisonProbeTarget[] {
  const metadata = parseJsonObject(asset.metadata);
  const method = stringValue(metadata?.method)?.toUpperCase() ?? "GET";
  if (!["GET", "HEAD"].includes(method)) {
    return [];
  }
  const pathTemplate = stringValue(metadata?.pathTemplate);
  const riskSignals = stringArray(metadata?.riskSignals);
  const examples = stringArray(metadata?.examples);
  const urls = examples.length > 0 ? examples : [asset.value];
  return urls
    .filter(isConcreteReadOnlyUrl)
    .map((url) => ({
      url,
      source: "normalized-api-example",
      method,
      pathTemplate,
      riskSignals: [...new Set([...riskSignals, ...routeRiskSignals(`${pathTemplate ?? ""} ${url}`)])]
    }))
    .filter((target) => probeTargetScore(target, testCase) > 0);
}

function probeTargetScore(target: RoleComparisonProbeTarget, testCase: BusinessLogicTestPlan["testCases"][number]): number {
  const corpus = `${target.url} ${target.pathTemplate ?? ""} ${target.riskSignals.join(" ")}`.toLowerCase();
  const category = `${testCase.id} ${testCase.category} ${testCase.title}`.toLowerCase();
  let score = target.source === "normalized-api-example" ? 3 : 1;
  if (/admin|manage|role|permission|privileged/.test(corpus)) score += 6;
  if (/\{id\}|\/\d+(?:\/|\?|$)|uuid|object|tenant|org|workspace|account|user|order|invoice|project/.test(corpus)) score += 5;
  if (/refund|payment|price|coupon|credit|transfer|amount/.test(corpus)) score += 5;
  if (/reset|password|invite|email|mfa|2fa|otp|session|token/.test(corpus)) score += 4;
  if (/export|download|upload|file|attachment|share|delete/.test(corpus)) score += 4;
  if (target.riskSignals.length > 0) score += Math.min(target.riskSignals.length, 4);
  if (category.includes("idor") || category.includes("bola") || category.includes("ownership")) {
    if (/\/\d+(?:\/|\?|$)|\{id\}|object|tenant|order|account|user|invoice|project/.test(corpus)) score += 8;
  }
  if (category.includes("function") || category.includes("authorization")) {
    if (/admin|manage|role|permission|privileged/.test(corpus)) score += 8;
  }
  if (category.includes("workflow")) {
    if (/refund|approval|invite|reset|checkout|payment|export|download/.test(corpus)) score += 6;
  }
  return score;
}

function isConcreteReadOnlyUrl(url: string): boolean {
  if (!/^https?:\/\//i.test(url)) return false;
  if (/[{}]/.test(url)) return false;
  if (/%3c(?:redacted|value)%3e/i.test(url) || /<(?:redacted|value)/i.test(url)) return false;
  try {
    const parsed = new URL(url);
    return parsed.protocol === "http:" || parsed.protocol === "https:";
  } catch {
    return false;
  }
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

function uniqueProbeTargets(targets: RoleComparisonProbeTarget[]): RoleComparisonProbeTarget[] {
  const seen = new Set<string>();
  const out: RoleComparisonProbeTarget[] = [];
  for (const target of targets) {
    const key = target.url.toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    out.push(target);
  }
  return out;
}

function authorizationPriorityForEndpoint(input: {
  method: string;
  pathTemplate: string;
  riskSignals: string[];
  categories: AuthorizationBoundaryMatrixItem["categories"];
  authRequired: string;
  confidence: SecurityAsset["confidence"];
  source: string;
  sources: string[];
  examples: string[];
}): { score: number; rationale: string[] } {
  const text = `${input.method} ${input.pathTemplate} ${input.riskSignals.join(" ")} ${input.categories.join(" ")}`.toLowerCase();
  const rationale: string[] = [];
  let score = confidenceRank(input.confidence) * 10 + 10;

  if (input.source.includes("api-inventory-normalizer")) {
    score += 8;
    rationale.push("normalized API route evidence");
  }
  if (input.sources.some((source) => /network|openapi|graphql/i.test(source))) {
    score += 10;
    rationale.push("runtime traffic or API-description source");
  }
  if (input.examples.length > 0) {
    score += 8;
    rationale.push("concrete request example available");
  }
  if (input.authRequired === "likely") {
    score += 8;
    rationale.push("likely authenticated route");
  }
  if (input.categories.includes("BFLA")) {
    score += 22;
    rationale.push("function-level authorization candidate");
  }
  if (input.categories.includes("BOLA")) {
    score += 20;
    rationale.push("object/tenant authorization candidate");
  }
  if (input.categories.includes("workflow")) {
    score += 16;
    rationale.push("workflow bypass candidate");
  }
  if (input.categories.includes("financial")) {
    score += 18;
    rationale.push("financial/business-impact route");
  }
  if (input.categories.includes("data-lifecycle")) {
    score += 14;
    rationale.push("data lifecycle route");
  }
  if (/^(?:POST|PUT|PATCH|DELETE)$/i.test(input.method) || input.riskSignals.some((signal) => /state-changing-method/i.test(signal))) {
    score += 12;
    rationale.push("state-changing method; passive until explicit active scope");
  }
  if (/auth-surface|login|signin|session|token/.test(text)) {
    score -= 6;
    rationale.push("auth surface route; map behavior before authorization claims");
  }
  if (rationale.length === 0) {
    rationale.push("authorization-relevant normalized route");
  }

  return { score: Math.max(1, score), rationale };
}

function authorizationMatrixItemFromAsset(
  asset: SecurityAsset,
  authContextCount: number,
  comparisonEvidence: Map<string, string[]>
): AuthorizationBoundaryMatrixItem | undefined {
  const metadata = parseJsonObject(asset.metadata);
  const method = stringValue(metadata?.method)?.toUpperCase() ?? "GET";
  const pathTemplate = stringValue(metadata?.pathTemplate) ?? pathFromAssetValue(asset.value);
  const examples = stringArray(metadata?.examples).filter(isConcreteReadOnlyUrl);
  const riskSignals = uniqueStrings([...stringArray(metadata?.riskSignals), ...routeRiskSignals(pathTemplate)]);
  const categories = authorizationCategories(`${method} ${pathTemplate} ${riskSignals.join(" ")}`);
  if (categories.length === 0 && riskSignals.length === 0) {
    return undefined;
  }
  const priority = authorizationPriorityForEndpoint({
    method,
    pathTemplate,
    riskSignals,
    categories,
    authRequired: stringValue(metadata?.authRequired) ?? "unknown",
    confidence: asset.confidence,
    source: asset.source,
    sources: stringArray(metadata?.sources),
    examples
  });
  const comparedByEvidenceIds = uniqueStrings([
    ...(comparisonEvidence.get(pathTemplate) ?? []),
    ...examples.flatMap((example) => comparisonEvidence.get(example) ?? [])
  ]);
  const readOnly = ["GET", "HEAD"].includes(method);
  let status: AuthorizationBoundaryMatrixItem["status"];
  if (comparedByEvidenceIds.length > 0) {
    status = "compared";
  } else if (!readOnly) {
    status = "passive_only";
  } else if (examples.length === 0) {
    status = "needs_concrete_example";
  } else if (authContextCount < 2) {
    status = "blocked_needs_auth_contexts";
  } else {
    status = "ready_for_comparison";
  }
  return {
    id: asset.id,
    method,
    pathTemplate,
    examples,
    riskSignals,
    categories,
    authRequired: stringValue(metadata?.authRequired) ?? "unknown",
    priorityScore: priority.score,
    priorityRationale: priority.rationale,
    status,
    comparedByEvidenceIds,
    nextAction: nextAuthorizationMatrixAction(status, categories)
  };
}

function authorizationValidationCandidateFromMatrixItem(
  item: AuthorizationBoundaryMatrixItem,
  asset: SecurityAsset | undefined
): AuthorizationValidationCandidate {
  const metadata = parseJsonObject(asset?.metadata);
  const queryParams = stringArray(metadata?.queryParams);
  const bodyParamHints = stringArray(metadata?.bodyParamHints);
  const status = authorizationValidationStatus(item.status);
  const objectReferences = objectReferencesForEndpoint(item.pathTemplate, queryParams, bodyParamHints);
  const blockedReason = status === "blocked_needs_auth_contexts"
    ? "At least two approved auth contexts are required for cross-role or cross-tenant comparison."
    : status === "needs_concrete_example"
      ? "Route template has no concrete safe GET/HEAD example from browser or network evidence."
      : status === "passive_only"
        ? "State-changing or upload/data-lifecycle route is captured for planning only; active replay requires explicit authorization and test-data boundaries."
        : undefined;
  return {
    id: `authz:${item.id}`,
    method: item.method,
    pathTemplate: item.pathTemplate,
    categories: item.categories,
    authRequired: item.authRequired,
    status,
    examples: item.examples,
    objectReferences,
    riskSignals: item.riskSignals,
    priorityScore: item.priorityScore,
    priorityRationale: item.priorityRationale,
    safeProcedure: safeProcedureForAuthorizationCandidate(item, objectReferences),
    approvalRequired: status === "passive_only" ? "active-mutation" : status === "ready_for_readonly_comparison" ? "read-only-comparison" : undefined,
    blockedReason,
    expectedEvidence: expectedEvidenceForAuthorizationCandidate(item, objectReferences),
    falsePositiveGuards: falsePositiveGuardsForAuthorizationCandidate(item)
  };
}

function authorizationValidationStatus(status: AuthorizationBoundaryMatrixItem["status"]): AuthorizationValidationCandidate["status"] {
  switch (status) {
    case "ready_for_comparison": return "ready_for_readonly_comparison";
    case "blocked_needs_auth_contexts": return "blocked_needs_auth_contexts";
    case "needs_concrete_example": return "needs_concrete_example";
    case "passive_only": return "passive_only";
    case "compared": return "compared";
  }
}

function objectReferencesForEndpoint(pathTemplate: string, queryParams: string[], bodyParamHints: string[]): AuthorizationValidationCandidate["objectReferences"] {
  const refs: AuthorizationValidationCandidate["objectReferences"] = [];
  for (const match of pathTemplate.matchAll(/\{([^}]+)\}/g)) {
    refs.push({ location: "path", name: match[1], evidence: pathTemplate });
  }
  for (const name of queryParams) {
    if (looksObjectReferenceName(name)) {
      refs.push({ location: "query", name, evidence: `query:${name}` });
    }
  }
  for (const name of bodyParamHints) {
    const cleanName = name.replace(/^content-type:.+$/i, "").trim();
    if (cleanName && looksObjectReferenceName(cleanName)) {
      refs.push({ location: "body", name: cleanName, evidence: `body:${cleanName}` });
    }
  }
  return uniqueObjectReferences(refs);
}

function looksObjectReferenceName(name: string): boolean {
  return /(?:^|[_\-.])(?:id|uuid|user|account|tenant|org|workspace|project|order|invoice|payment|role|owner|member|resource|file|document|ticket)(?:$|[_\-.])/i.test(name)
    || /(?:userId|accountId|tenantId|orgId|workspaceId|projectId|orderId|invoiceId|roleId|ownerId|fileId|documentId|ticketId)$/i.test(name);
}

function uniqueObjectReferences(refs: AuthorizationValidationCandidate["objectReferences"]): AuthorizationValidationCandidate["objectReferences"] {
  const seen = new Set<string>();
  return refs.filter((ref) => {
    const key = `${ref.location}:${ref.name.toLowerCase()}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function safeProcedureForAuthorizationCandidate(
  item: AuthorizationBoundaryMatrixItem,
  objectReferences: AuthorizationValidationCandidate["objectReferences"]
): string[] {
  if (item.status === "compared") {
    return ["Review recorded comparison evidence and expected role policy before changing finding state."];
  }
  if (item.status === "passive_only") {
    return [
      "Keep this endpoint in the workflow map without replaying it.",
      "Ask for explicit active authorization, test data, and rollback boundaries before any mutation replay.",
      "Require a concrete approval record that names allowed methods, routes, test accounts, rate limits, stop conditions, and rollback owner.",
      "Prefer deriving expected policy from documentation or operator-provided role matrix first."
    ];
  }
  if (item.status === "needs_concrete_example") {
    return [
      "Collect a concrete GET/HEAD example from browser runtime network evidence or explicit API description examples.",
      "Do not synthesize object IDs or tenant values."
    ];
  }
  if (item.status === "blocked_needs_auth_contexts") {
    return [
      "Register at least two approved auth contexts with distinct roles, users, or tenants.",
      "Use only captured concrete examples for the first comparison.",
      "Compare status, stable response signature, and content-length/hash deltas before making any claim."
    ];
  }
  const procedures = [
    "Run read-only cross-role comparison using the concrete examples already captured.",
    "Compare status code, redirects, content type, body length, and stable response hash for each role."
  ];
  if (objectReferences.length > 0) {
    procedures.push("For BOLA, only substitute object identifiers when the alternate object value is captured from another approved context or operator-provided test fixture.");
  }
  if (item.categories.includes("BFLA")) {
    procedures.push("For BFLA, confirm the expected role policy before treating lower-privilege success as impact.");
  }
  return procedures;
}

function expectedEvidenceForAuthorizationCandidate(
  item: AuthorizationBoundaryMatrixItem,
  objectReferences: AuthorizationValidationCandidate["objectReferences"]
): string[] {
  const evidence = [
    "Normalized API endpoint metadata with source and concrete example.",
    "Auth context labels, roles, and scope notes without storing secrets.",
    "Per-role response signatures and redirect/status differences."
  ];
  if (objectReferences.length > 0) {
    evidence.push("Object reference provenance showing both original and alternate IDs came from approved evidence.");
  }
  if (item.categories.includes("BFLA")) {
    evidence.push("Expected function-level permission matrix or operator confirmation.");
  }
  if (!["GET", "HEAD"].includes(item.method)) {
    evidence.push("Explicit active authorization record naming permitted mutation methods, routes, test data, stop conditions, and rollback boundaries.");
    evidence.push("Before/after state proof from disposable or operator-approved test data only.");
  }
  return evidence;
}

function falsePositiveGuardsForAuthorizationCandidate(item: AuthorizationBoundaryMatrixItem): string[] {
  const guards = [
    "Ignore unauthenticated login redirects and generic error pages as access success.",
    "Treat equal 401/403 responses as no authorization bypass.",
    "Treat same response body across roles as inconclusive unless the content represents restricted data or action success."
  ];
  if (!["GET", "HEAD"].includes(item.method)) {
    guards.push("Do not infer mutation impact from route existence or form metadata alone.");
  }
  if (item.categories.includes("BOLA")) {
    guards.push("Do not call BOLA unless the accessed object belongs to another approved user or tenant.");
  }
  if (item.categories.includes("BFLA")) {
    guards.push("Do not call BFLA unless the lower-privilege role is proven unauthorized for that function.");
  }
  return guards;
}

function authzValidationStatusRank(status: AuthorizationValidationCandidate["status"]): number {
  switch (status) {
    case "ready_for_readonly_comparison": return 0;
    case "blocked_needs_auth_contexts": return 1;
    case "needs_concrete_example": return 2;
    case "passive_only": return 3;
    case "compared": return 4;
  }
}

function authorizationValidationNextActions(input: {
  ready: number;
  blocked: number;
  needsExample: number;
  passiveOnly: number;
  compared: number;
  authContextCount: number;
}): string[] {
  const actions: string[] = [];
  if (input.ready > 0) actions.push("Run read-only role comparison for the highest-risk ready candidate.");
  if (input.authContextCount < 2 && input.blocked > 0) actions.push("Register a second approved role, user, or tenant context before BOLA/BFLA validation.");
  if (input.needsExample > 0) actions.push("Use Browser Recon Runtime to capture concrete GET/HEAD examples for route templates.");
  if (input.passiveOnly > 0) actions.push("Keep mutation routes passive until active authorization and test-data boundaries are explicit.");
  if (actions.length === 0 && input.compared > 0) actions.push("Review comparison evidence against the expected permission matrix and close validated/ruled-out states.");
  return actions;
}

function comparisonEvidenceIndex(store: AuditStore, sessionId: string, workflowId: string | undefined): Map<string, string[]> {
  const index = new Map<string, string[]>();
  const evidence = store
    .listEvidence(sessionId)
    .filter((item) => item.source.startsWith("business-logic:compare:") && (!workflowId || !item.workflowId || item.workflowId === workflowId));
  for (const item of evidence) {
    const parsed = parseJsonObject(item.data);
    const comparisons = Array.isArray(parsed?.comparisons) ? parsed.comparisons : [];
    for (const comparison of comparisons) {
      const object = parseJsonObject(comparison);
      const url = stringValue(object?.url);
      const pathTemplate = stringValue(object?.pathTemplate);
      for (const key of [url, pathTemplate].filter((value): value is string => Boolean(value))) {
        index.set(key, uniqueStrings([...(index.get(key) ?? []), item.id]));
      }
    }
  }
  return index;
}

function authorizationCategories(value: string): AuthorizationBoundaryMatrixItem["categories"] {
  const categories = new Set<AuthorizationBoundaryMatrixItem["categories"][number]>();
  if (/\/\d+(?:\/|\?|$)|\{id\}|\{uuid\}|object|tenant|org|workspace|account|user|order|invoice|project/i.test(value)) categories.add("BOLA");
  if (/admin|manage|role|permission|privileged|settings/i.test(value)) categories.add("BFLA");
  if (/refund|approval|invite|reset|checkout|state|workflow/i.test(value)) categories.add("workflow");
  if (/login|signin|reset|password|session|token|oauth|sso|mfa|2fa|otp/i.test(value)) categories.add("auth-session");
  if (/refund|payment|price|coupon|checkout|credit|transfer|amount/i.test(value)) categories.add("financial");
  if (/export|download|upload|file|attachment|share|delete/i.test(value)) categories.add("data-lifecycle");
  return [...categories];
}

function nextAuthorizationMatrixAction(status: AuthorizationBoundaryMatrixItem["status"], categories: AuthorizationBoundaryMatrixItem["categories"]): string {
  if (status === "compared") return "Review comparison evidence and expected permission policy before reporting.";
  if (status === "ready_for_comparison") return `Run read-only cross-role comparison for ${categories.join("/") || "authorization"} boundary.`;
  if (status === "blocked_needs_auth_contexts") return "Register at least two authorized roles or tenants before comparison.";
  if (status === "needs_concrete_example") return "Collect a concrete safe GET/HEAD request example from browser/network evidence.";
  return "Keep passive until explicit active scope approves state-changing validation.";
}

function matrixStatusRank(status: AuthorizationBoundaryMatrixItem["status"]): number {
  switch (status) {
    case "ready_for_comparison": return 0;
    case "blocked_needs_auth_contexts": return 1;
    case "needs_concrete_example": return 2;
    case "passive_only": return 3;
    case "compared": return 4;
  }
}

function confidenceRank(confidence: SecurityAsset["confidence"]): number {
  return { low: 0, medium: 1, high: 2 }[confidence];
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

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim().length > 0))].sort();
}
