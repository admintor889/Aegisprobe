import { newId, nowIso, type SecurityValidationAttempt } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { validationPriorityRank } from "./core-helpers.js";

export type ValidationCandidate = {
  kind: SecurityValidationAttempt["targetKind"];
  id: string;
  workflowId?: string;
  title: string;
  target: string;
  priority: "critical" | "high" | "medium" | "low";
  method: string;
  evidenceIds: string[];
};

export function buildValidationCandidates(store: AuditStore, sessionId: string): ValidationCandidate[] {
  const attempts = store.listSecurityValidationAttempts(sessionId);
  const attemptedKeys = new Set(attempts.map((attempt) => `${attempt.targetKind}:${attempt.targetId}`));
  const evidence = store.listEvidence(sessionId);
  const evidenceFor = (needle: string): string[] => {
    const lower = needle.toLowerCase();
    return evidence
      .filter((item) => [
        item.source,
        item.summary,
        item.data ?? ""
      ].join("\n").toLowerCase().includes(lower))
      .map((item) => item.id)
      .slice(0, 8);
  };
  const findings = store.listFindings(sessionId)
    .filter((finding) => !attemptedKeys.has(`finding:${finding.id}`))
    .map((finding) => ({
      kind: "finding" as const,
      id: finding.id,
      workflowId: finding.workflowId,
      title: finding.title,
      target: finding.target,
      priority: finding.severity === "critical" || finding.severity === "high" ? "high" as const : finding.severity === "medium" ? "medium" as const : "low" as const,
      method: /header|source map|route|credential|restricted|protected/i.test(`${finding.title} ${finding.description}`)
        ? "correlate passive evidence and require scoped manual confirmation"
        : "review tool evidence and reproduce with non-destructive checks only",
      evidenceIds: [...new Set([
        ...evidenceFor(finding.id),
        ...evidenceFor(finding.title),
        ...evidenceFor(finding.target)
      ])].slice(0, 8)
    }));
  const cves = store.listCveMatches(sessionId)
    .filter((match) => !attemptedKeys.has(`cve:${match.id}`))
    .map((match) => ({
      kind: "cve" as const,
      id: match.id,
      workflowId: match.workflowId,
      title: match.cveId ? `${match.cveId} ${match.title}` : match.title,
      target: match.target,
      priority: match.severity === "critical" || match.severity === "high" ? "high" as const : match.severity === "medium" ? "medium" as const : "low" as const,
      method: match.confidence === "high"
        ? "confirm exact version evidence and run approval-gated non-destructive template if authorized"
        : "collect stronger fingerprint/version evidence before active validation",
      evidenceIds: [...new Set([
        ...evidenceFor(match.id),
        ...evidenceFor(match.cveId ?? match.title),
        ...evidenceFor(match.technology),
        ...evidenceFor(match.target)
      ])].slice(0, 8)
    }));
  return [...findings, ...cves].sort((left, right) => validationPriorityRank(left.priority) - validationPriorityRank(right.priority));
}

export function buildSecurityValidationPlan(store: AuditStore, sessionId: string): string {
  const candidates = buildValidationCandidates(store, sessionId);
  if (candidates.length === 0) {
    return "No validation candidates are available yet. Run recon/fingerprinting or import evidence first.";
  }
  return [
    "Security Validation Plan",
    ...candidates.slice(0, 20).map((candidate, index) => [
      `${index + 1}. ${candidate.kind}:${candidate.id} | ${candidate.priority} | ${candidate.title}`,
      `   target: ${candidate.target}`,
      `   method: ${candidate.method}`,
      `   evidence: ${candidate.evidenceIds.join(", ") || "none"}`
    ].join("\n"))
  ].join("\n");
}

export function recordValidationAttempt(
  store: AuditStore,
  input: Omit<SecurityValidationAttempt, "id" | "createdAt" | "updatedAt">
): SecurityValidationAttempt {
  const now = nowIso();
  const attempt: SecurityValidationAttempt = {
    id: newId("val"),
    createdAt: now,
    updatedAt: now,
    ...input
  };
  store.addSecurityValidationAttempt(attempt);
  store.addEvidence({
    id: newId("evd"),
    sessionId: input.sessionId,
    workflowId: input.workflowId,
    source: `validation:${input.targetKind}:${input.targetId}`,
    kind: "note",
    summary: `${input.status}/${input.confidence}: ${input.targetTitle}`,
    data: JSON.stringify(attempt, null, 2),
    createdAt: nowIso()
  });
  return attempt;
}

export function executeSecurityValidationAttempt(
  store: AuditStore,
  sessionId: string,
  targetIdOrNext = "next"
): string {
  const candidates = buildValidationCandidates(store, sessionId);
  const candidate = targetIdOrNext === "next"
    ? candidates[0]
    : candidates.find((item) => item.id === targetIdOrNext || `${item.kind}:${item.id}` === targetIdOrNext);
  if (!candidate) {
    return `No validation candidate found: ${targetIdOrNext}`;
  }
  const evidenceCount = candidate.evidenceIds.length;
  const status: SecurityValidationAttempt["status"] = evidenceCount >= 2 && candidate.priority !== "low"
    ? "validated"
    : evidenceCount > 0
      ? "inconclusive"
      : "blocked";
  const confidence: SecurityValidationAttempt["confidence"] = status === "validated" ? "medium" : "low";
  const rationale = status === "validated"
    ? "Multiple stored evidence records support this candidate; active exploitability still remains out of scope unless explicitly authorized."
    : status === "inconclusive"
      ? "Stored evidence supports the candidate, but more independent evidence is required before final reporting."
      : "No stored evidence is available for validation.";
  const attempt = recordValidationAttempt(store, {
    sessionId,
    workflowId: candidate.workflowId,
    targetKind: candidate.kind,
    targetId: candidate.id,
    targetTitle: candidate.title,
    method: candidate.method,
    status,
    confidence,
    rationale,
    evidenceIds: candidate.evidenceIds
  });
  if (candidate.kind === "finding") {
    store.updateFindingState(
      candidate.id,
      status === "validated" ? "validated" : "needs_validation",
      candidate.evidenceIds,
      rationale
    );
  }
  return [
    `Validation attempt recorded: ${attempt.id}`,
    `Target: ${candidate.kind}:${candidate.id} ${candidate.title}`,
    `Status: ${attempt.status}`,
    `Confidence: ${attempt.confidence}`,
    `Rationale: ${attempt.rationale}`
  ].join("\n");
}
