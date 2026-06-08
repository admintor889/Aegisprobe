import { nowIso } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { buildSecurityReport as buildSecurityAssessmentReport } from "./security-report.js";

export function renderSecurityReportContent(
  store: AuditStore,
  sessionId: string,
  deps: {
    buildSecurityDecisionQueue: (sessionId: string) => ReturnType<AuditStore["listSecurityChecks"]> extends never ? never : any;
    buildSubAgentCoordinationPlan: (sessionId: string) => any;
    buildBusinessLogicTestPlan: (sessionId: string) => any;
  }
): string {
  return buildSecurityAssessmentReport({
    sessionId,
    generatedAt: nowIso(),
    workflows: store.listSecurityWorkflows(sessionId),
    checks: store.listSecurityChecks(sessionId),
    findings: store.listFindings(sessionId),
    evidence: store.listEvidence(sessionId),
    assets: store.listAssets(sessionId),
    technologies: store.listTechnologies(sessionId),
    cveMatches: store.listCveMatches(sessionId),
    commands: store.listCommands(sessionId, 100),
    toolRuns: store.listSecurityToolRuns(sessionId),
    authContexts: store.listSecurityAuthContexts(sessionId),
    validationAttempts: store.listSecurityValidationAttempts(sessionId),
    decisionQueue: deps.buildSecurityDecisionQueue(sessionId),
    coordinationPlan: deps.buildSubAgentCoordinationPlan(sessionId),
    businessPlan: deps.buildBusinessLogicTestPlan(sessionId)
  });
}
