import { truncateForContext, type SecurityAsset, type SecurityAuthContext, type SecurityCveMatch, type SecurityEvidence, type SecurityFinding, type SecurityTechnology, type SecurityToolRun, type SecurityValidationAttempt, type SecurityValidationCheck, type SecurityWorkflow, type ShellCommandRecord } from "@aegisprobe/shared";
import type { BusinessLogicTestPlan, SecurityDecisionQueue, SubAgentCoordinationPlan } from "@aegisprobe/security";

type BuildSecurityReportInput = {
  sessionId: string;
  generatedAt: string;
  workflows: SecurityWorkflow[];
  checks: SecurityValidationCheck[];
  findings: SecurityFinding[];
  evidence: SecurityEvidence[];
  assets: SecurityAsset[];
  technologies: SecurityTechnology[];
  cveMatches: SecurityCveMatch[];
  commands: ShellCommandRecord[];
  toolRuns: SecurityToolRun[];
  authContexts: SecurityAuthContext[];
  validationAttempts: SecurityValidationAttempt[];
  decisionQueue: SecurityDecisionQueue;
  coordinationPlan: SubAgentCoordinationPlan;
  businessPlan: BusinessLogicTestPlan;
};

const severityOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };

export function buildSecurityReport(input: BuildSecurityReportInput): string {
  const sortedFindings = [...input.findings].sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));
  const sortedCves = [...input.cveMatches].sort((a, b) => (severityOrder[a.severity] ?? 9) - (severityOrder[b.severity] ?? 9));
  const nextActions = buildSecurityNextActions(input.checks, sortedFindings, sortedCves, input.assets, input.technologies);
  const lines = [
    "# AegisProbe Security Assessment Report",
    "",
    `Session: ${input.sessionId}`,
    `Generated: ${input.generatedAt}`,
    "",
    "## Scope",
    input.workflows.length > 0
      ? input.workflows.map((workflow) => `- ${workflow.target.kind}:${workflow.target.normalized} | ${workflow.status} | ${workflow.summary}`).join("\n")
      : "- No security workflow recorded.",
    "",
    "## Executive Summary",
    `- Assets recorded: ${input.assets.length}`,
    `- Technologies recorded: ${input.technologies.length}`,
    `- Findings recorded: ${input.findings.length}`,
    `- CVE/advisory candidates: ${input.cveMatches.length}`,
    `- Validation checks: ${input.checks.length}`,
    `- Security tool runs: ${input.toolRuns.length}`,
    `- Authenticated contexts: ${input.authContexts.length}`,
    `- Validation attempts: ${input.validationAttempts.length}`,
    `- Decision queue items: ${input.decisionQueue.items.length}`,
    `- Subagent coordination items: ${input.coordinationPlan.items.length}`,
    `- Business-logic test cases: ${input.businessPlan.testCases.length}`,
    `- Approved/successful commands: ${input.commands.filter((command) => command.status === "success").length}`,
    "",
    "## Prioritized Next Actions",
    nextActions.length > 0 ? nextActions.map((action, index) => `${index + 1}. ${action}`).join("\n") : "No immediate next actions derived from current evidence.",
    "",
    "## Decision Queue",
    input.decisionQueue.items.length > 0
      ? input.decisionQueue.items.slice(0, 12).map((item) => [
          `- ${item.priority} | ${item.phase} | ${item.actionType}${item.toolId ? ` | ${item.toolId}` : ""}: ${item.title}`,
          `  - Target: ${item.target}`,
          `  - Reason: ${item.reason}`,
          item.blockedBy ? `  - Blocked by: ${item.blockedBy}` : undefined,
          item.prerequisites.length > 0 ? `  - Prerequisites: ${item.prerequisites.join("; ")}` : undefined,
          item.expectedEvidence.length > 0 ? `  - Expected evidence: ${item.expectedEvidence.join("; ")}` : undefined
        ].filter(Boolean).join("\n")).join("\n")
      : "No decision queue items generated.",
    "",
    "## Tool Run Ledger",
    input.toolRuns.length > 0
      ? input.toolRuns.map((run) => `- ${run.status} | ${run.origin} | ${run.phase} | ${run.toolId}${run.failureCategory ? ` | class:${run.failureCategory}` : ""}${run.findingCount === undefined ? "" : ` | findings:${run.findingCount}`}${run.exitCode === undefined ? "" : ` | exit:${run.exitCode}`} | inputs:${run.inputCount}${run.inputArtifact ? ` | input:${run.inputArtifact}` : ""}${run.outputArtifact ? ` | output:${run.outputArtifact}` : ""}${run.blockedReason ? ` | blocked:${run.blockedReason}` : ""}`).join("\n")
      : "No security tool runs recorded.",
    "",
    "## Subagent Coordination Plan",
    input.coordinationPlan.items.length > 0
      ? input.coordinationPlan.items.map((item) => `- ${item.priority} | ${item.role} | ${item.runMode} | ${item.title}${item.blockedReason ? ` | blocked:${item.blockedReason}` : ""}`).join("\n")
      : "No subagent delegation recommended.",
    "",
    "## Authenticated Contexts",
    input.authContexts.length > 0
      ? input.authContexts.map((context) => `- ${context.name} | role:${context.role ?? "unknown"} | user:${context.username ?? "unknown"} | base:${context.baseUrl ?? "unknown"} | cookies:${context.cookieHeader ? "yes" : "no"} | authorization:${context.authorizationHeader ? "yes" : "no"} | storage:${context.storageStatePath ?? "none"}`).join("\n")
      : "No authenticated browser/session contexts registered.",
    "",
    "## Assets",
    input.assets.length > 0 ? input.assets.map((asset) => `- ${asset.kind} | ${asset.confidence} | ${asset.value} | ${asset.source}`).join("\n") : "No assets recorded.",
    "",
    "## Technologies",
    input.technologies.length > 0
      ? input.technologies.map((technology) => `- ${technology.target} | ${technology.name}${technology.version ? ` ${technology.version}` : ""} | ${technology.confidence}${technology.category ? ` | ${technology.category}` : ""}`).join("\n")
      : "No technologies recorded.",
    "",
    "## Findings",
    sortedFindings.length > 0
      ? sortedFindings.map((finding) => [
          `### ${finding.severity.toUpperCase()} ${finding.title}`,
          `- Target: ${finding.target}`,
          `- State: ${finding.state ?? "candidate"}`,
          `- Confidence: ${finding.confidence}`,
          `- Evidence: ${finding.evidenceSummary ?? "No evidence summary recorded."}`,
          `- Evidence IDs: ${finding.evidenceIds?.join(", ") || "none"}`,
          `- Description: ${finding.description}`,
          `- Remediation: ${finding.remediation ?? "Manual remediation analysis required."}`
        ].join("\n")).join("\n\n")
      : "No findings recorded.",
    "",
    "## CVE And Advisory Candidates",
    sortedCves.length > 0
      ? sortedCves.map((match) => `- ${match.severity}/${match.confidence} | ${match.target} | ${match.cveId ?? "no-cve"} | ${match.title} | ${match.rationale}`).join("\n")
      : "No CVE/advisory candidates recorded.",
    "",
    "## Validation Checklist",
    input.checks.length > 0
      ? input.checks.map((check) => `- ${check.checkId} | ${check.status} | ${check.title} | ${check.rationale ?? "No rationale."}`).join("\n")
      : "No validation checks recorded.",
    "",
    "## Validation Attempts",
    input.validationAttempts.length > 0
      ? input.validationAttempts.map((attempt) => `- ${attempt.status}/${attempt.confidence} | ${attempt.targetKind}:${attempt.targetId} | ${attempt.targetTitle} | ${attempt.method} | evidence:${attempt.evidenceIds.join(",") || "none"}`).join("\n")
      : "No validation attempts recorded.",
    "",
    "## Business Logic Test Plan",
    input.businessPlan.testCases.length > 0
      ? [
          "Required context:",
          ...input.businessPlan.contextQuestions.map((question) => `- ${question}`),
          "",
          ...input.businessPlan.testCases.slice(0, 10).map((testCase) => [
            `### ${testCase.id} ${testCase.title}`,
            `- Risk: ${testCase.risk}`,
            `- Category: ${testCase.category}`,
            testCase.targetHints.length > 0 ? `- Target hints: ${testCase.targetHints.join(", ")}` : undefined,
            testCase.blockedReason ? `- Blocked reason: ${testCase.blockedReason}` : undefined,
            `- Safe steps: ${testCase.safeSteps.join("; ")}`,
            `- Evidence: ${testCase.evidenceToCollect.join("; ")}`,
            `- False-positive guards: ${testCase.falsePositiveGuards.join("; ")}`
          ].filter(Boolean).join("\n")).join("\n\n")
        ].join("\n")
      : "No business-logic test cases generated.",
    "",
    "## Evidence Index",
    input.evidence.length > 0
      ? input.evidence.map((item) => `- ${item.id} | ${item.kind} | ${item.source} | ${truncateForContext(item.summary, 280).replace(/\r?\n/g, " ")}`).join("\n")
      : "No evidence recorded.",
    "",
    "## Safety Notes",
    "- This report contains candidate observations from an approval-gated workflow.",
    "- Active validation, exploitation, brute force, and out-of-scope scanning require explicit authorization.",
    "- CVE matches are candidates unless the report explicitly states that version and exploitability were validated.",
    "- Business-logic issues require user-provided workflow/account context; passive signals are hypotheses until validated in an authorized sandbox."
  ];
  return lines.join("\n");
}

function buildSecurityNextActions(
  checks: SecurityValidationCheck[],
  findings: SecurityFinding[],
  cveMatches: SecurityCveMatch[],
  assets: SecurityAsset[],
  technologies: SecurityTechnology[]
): string[] {
  const actions: string[] = [];
  if (assets.some((asset) => asset.kind === "subdomain" && asset.confidence !== "low")) {
    actions.push("Probe discovered subdomains with httpx/dnsx under the approved rate limit, then normalize live HTTP services.");
  }
  if (technologies.some((technology) => technology.version)) {
    actions.push("Validate version-backed technology fingerprints against local CVE/advisory candidates before reporting severity.");
  }
  if (cveMatches.length > 0) {
    actions.push("Review CVE/advisory candidates and decide whether non-destructive nuclei validation is authorized.");
  }
  if (findings.some((finding) => /source map|route|api|credential/i.test(`${finding.title} ${finding.description}`))) {
    actions.push("Ask the frontend subagent to correlate discovered JS/source-map/API routes with authentication assumptions and sensitive data exposure.");
  }
  if (checks.some((check) => check.status === "blocked")) {
    actions.push("Resolve blocked validation checks by confirming whether active probing is authorized, otherwise keep them as passive hypotheses.");
  }
  if (findings.length === 0 && assets.length > 0) {
    actions.push("Continue passive recon and fingerprinting; no evidence-backed findings exist yet.");
  }
  return [...new Set(actions)].slice(0, 8);
}
