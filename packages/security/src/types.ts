import type { SkillDefinition, SkillRegistry } from "@aegisprobe/skills";
import type { FindingSeverity, SecurityAsset, SecurityAuthContext, SecurityCveMatch, SecurityEvidence, SecurityFinding, SecurityPhase, SecurityTechnology, SecurityToolFailureCategory, SecurityToolRun, SecurityToolRunStatus, SecurityValidationAttempt, SecurityValidationCheck, SecurityWorkflow, SecurityWorkflowTask, SubAgentRecord, SubAgentRole, TargetInput } from "@aegisprobe/shared";

export type SecurityWorkflowPlan = {
  workflow: SecurityWorkflow;
  tasks: SecurityWorkflowTask[];
  prompt: string;
};

export type SkillExecutionPlan = {
  query: string;
  matchedSkills: SkillDefinition[];
  tasks: Array<{
    title: string;
    phase: SecurityPhase;
    role?: SubAgentRole;
    skillIds: string[];
    tools: string[];
    description: string;
  }>;
  prompt: string;
};

export type PentestIntensity = "passive" | "safe" | "active";
export type PentestScanProfile = "quick" | "deep";

export type PentestScope = {
  allowedTargets: string[];
  excludedTargets: string[];
  intensity: PentestIntensity;
  scanProfile: PentestScanProfile;
  allowActiveProbing: boolean;
  allowCidrDiscovery: boolean;
  rateLimitPerSecond: number;
  maxDepth: number;
  maxModelTurns?: number;
  notes: string[];
};

export type SecurityToolCapability =
  | "subdomain"
  | "dns"
  | "http_probe"
  | "crawler"
  | "fingerprint"
  | "cve"
  | "owasp"
  | "port_scan"
  | "content_discovery"
  | "cidr_discovery"
  | "snmp";

export type SecurityToolAdapter = {
  id: string;
  displayName: string;
  binary: string;
  repository: string;
  localSourceDir: string;
  localBinaryPath: string;
  capabilities: SecurityToolCapability[];
  phase: SecurityPhase;
  intensity: PentestIntensity;
  requiresActiveApproval: boolean;
  description: string;
  buildCommand: (target: TargetInput, scope: PentestScope) => string | undefined;
  buildCommandForInputFile?: (inputFile: string, scope: PentestScope) => string | undefined;
};

export type SecurityToolInventoryItem = {
  id: string;
  binary: string;
  repository: string;
  localSourceDir: string;
  localSourceAvailable: boolean;
  localBinaryPath: string;
  localBinaryAvailable: boolean;
  pathBinaryAvailable: boolean;
  available: boolean;
  capabilities: SecurityToolCapability[];
  phase: SecurityPhase;
  intensity: PentestIntensity;
  installCommand: string;
  notes: string[];
};

export type SecurityToolHealth = {
  id: string;
  binary: string;
  command: string;
  runnable: boolean;
  exitCode: number | null;
  summary: string;
};

export type SecurityToolDiscovery = {
  binary: string;
  displayName: string;
  path: string;
  version: string | null;
  available: boolean;
  category: "recon" | "dns" | "http" | "crawler" | "fingerprint" | "cve" | "port_scan" | "content_discovery" | "exploit" | "utility";
  installHint?: string;
};

export type PentestPipelineStep = {
  id: string;
  phase: SecurityPhase;
  title: string;
  description: string;
  kind: "builtin_probe" | "tool" | "subagent" | "manual";
  toolId?: string;
  command?: string;
  probe?: "basic_recon" | "dns" | "http_headers";
  role?: SubAgentRole;
  task?: string;
  intensity: PentestIntensity;
  required: boolean;
  blockedReason?: string;
};

export type PentestPipeline = {
  target: TargetInput;
  scope: PentestScope;
  steps: PentestPipelineStep[];
  adapters: SecurityToolAdapter[];
};

export type NormalizedSecurityObservation = {
  assets: Array<Omit<SecurityAsset, "id" | "sessionId" | "workflowId" | "createdAt">>;
  technologies: Array<Omit<SecurityTechnology, "id" | "sessionId" | "workflowId" | "createdAt">>;
  findings: Array<Omit<SecurityFinding, "id" | "sessionId" | "workflowId" | "createdAt" | "updatedAt">>;
  cveMatches: Array<Omit<SecurityCveMatch, "id" | "sessionId" | "workflowId" | "createdAt">>;
  notes: string[];
};

export type SecurityToolOutputClassification = {
  status: SecurityToolRunStatus;
  failureCategory: SecurityToolFailureCategory;
  findingCount: number;
  summary: string;
};

export type SecurityAssetGraphNode = {
  id: string;
  kind: SecurityAsset["kind"];
  value: string;
  confidence: SecurityAsset["confidence"];
  sources: string[];
  metadata: string[];
  technologies: Array<Pick<SecurityTechnology, "name" | "version" | "category" | "confidence" | "source">>;
  cveMatches: Array<Pick<SecurityCveMatch, "cveId" | "title" | "severity" | "confidence" | "source">>;
  findings: Array<Pick<SecurityFinding, "title" | "severity" | "confidence" | "evidenceSummary">>;
  evidenceCount: number;
};

export type SecurityAssetGraphEdge = {
  from: string;
  to: string;
  relation: "parent_domain" | "resolves_to" | "hosts_url" | "exposes_service";
};

export type SecurityAssetGraph = {
  nodes: SecurityAssetGraphNode[];
  edges: SecurityAssetGraphEdge[];
  nextActions: string[];
};

export type SecurityDecisionQueueItem = {
  id: string;
  priority: "critical" | "high" | "medium" | "low";
  score?: number;
  confidence?: "low" | "medium" | "high";
  phase: SecurityPhase;
  actionType: "tool" | "subagent" | "manual" | "authorization";
  title: string;
  reason: string;
  target: string;
  toolId?: string;
  fallbackFor?: string;
  blockedBy?: string;
  attemptCount?: number;
  failureMemory?: string[];
  prerequisites: string[];
  expectedEvidence: string[];
};

export type SecurityDecisionQueue = {
  generatedAt: string;
  items: SecurityDecisionQueueItem[];
};

export type SecurityDecisionSupervision = {
  generatedAt: string;
  level: "continue" | "reflect" | "ask_user" | "stop";
  summary: string;
  progressSignals: string[];
  stallSignals: string[];
  repeatedTools: Array<{
    toolId: string;
    attempts: number;
    lastStatus: SecurityToolRunStatus;
    failureCategory?: SecurityToolFailureCategory;
  }>;
  recommendedActions: string[];
  suppressItemIds: string[];
};

export type SecurityObjectiveId = "business_logic_impact" | "admin_control_plane" | "server_control_plane";

export type SecurityObjectiveStatus =
  | "needs_context"
  | "collecting_evidence"
  | "ready_for_safe_validation"
  | "blocked_by_scope"
  | "validated_impact";

export type SecurityObjectiveAssessment = {
  id: SecurityObjectiveId;
  title: string;
  status: SecurityObjectiveStatus;
  score: number;
  confidence: "low" | "medium" | "high";
  evidence: string[];
  blockers: string[];
  nextQuestions: string[];
  nextActions: string[];
  validationBoundaries: string[];
  mappedQueueItemIds: string[];
};

export type SecurityAttackPathStage = {
  objectiveId: SecurityObjectiveId;
  status: SecurityObjectiveStatus;
  evidence: string[];
  nextAction: string;
};

export type SecurityAttackPathModel = {
  id: string;
  title: string;
  status: SecurityObjectiveStatus;
  score: number;
  rationale: string;
  stages: SecurityAttackPathStage[];
  stopConditions: string[];
};

export type SecurityObjectiveModel = {
  target: string;
  generatedAt: string;
  overallStatus: SecurityObjectiveStatus;
  summary: string;
  objectives: SecurityObjectiveAssessment[];
  attackPaths: SecurityAttackPathModel[];
  nextBestActions: string[];
  requiredUserContext: string[];
};

export type BusinessWorkflowCategory =
  | "identity"
  | "authorization"
  | "commerce"
  | "approval"
  | "tenant"
  | "file"
  | "admin"
  | "api"
  | "unknown";

export type BusinessWorkflowGraphNode = {
  id: string;
  url: string;
  category: BusinessWorkflowCategory;
  sensitivity: "low" | "medium" | "high";
  signals: string[];
  requiredRoles: string[];
  stateInvariants: string[];
  safeValidationIdeas: string[];
  activeValidationBoundaries: string[];
};

export type BusinessWorkflowGraphEdge = {
  from: string;
  to: string;
  relation: "same_category" | "auth_boundary" | "state_transition" | "admin_pivot";
  rationale: string;
};

export type BusinessWorkflowGraph = {
  target: string;
  generatedAt: string;
  nodes: BusinessWorkflowGraphNode[];
  edges: BusinessWorkflowGraphEdge[];
  roleMatrix: Array<{
    role: string;
    contextName: string;
    baseUrl?: string;
    coverage: BusinessWorkflowCategory[];
  }>;
  gaps: string[];
  nextActions: string[];
};

export type ValidationClosureCandidate = {
  id: string;
  kind: SecurityValidationAttempt["targetKind"] | "objective";
  targetId: string;
  title: string;
  target: string;
  priority: "critical" | "high" | "medium" | "low";
  confidence: "low" | "medium" | "high";
  state: "ready" | "needs_context" | "blocked" | "validated" | "ruled_out";
  evidenceIds: string[];
  verificationStrategy: string;
  falsePositiveGuards: string[];
  nextAction: string;
  blockedBy?: string;
};

export type ValidationClosurePlan = {
  generatedAt: string;
  status: "needs_context" | "ready" | "blocked" | "settled";
  summary: string;
  candidates: ValidationClosureCandidate[];
  nextCandidateId?: string;
  finalizationRules: string[];
};

export type BrowserInteractionPlan = {
  target: string;
  generatedAt: string;
  authContexts: Array<Pick<SecurityAuthContext, "name" | "role" | "username" | "baseUrl" | "storageStatePath">>;
  loginState: "missing" | "single_role" | "multi_role";
  loginPlaybooks: Array<{
    authContextName: string;
    loginUrl?: string;
    usernameSelector?: string;
    passwordSelector?: string;
    submitSelector?: string;
    successSignal: string;
    secretHandling: string;
  }>;
  noSubmitRequestClasses: Array<{
    method: string;
    disposition: "allow" | "capture_only" | "block";
    reason: string;
  }>;
  noSubmitCapture: string[];
  replayBoundaries: string[];
  multiRoleComparisons: Array<{
    left: string;
    right: string;
    categories: BusinessWorkflowCategory[];
    reason: string;
  }>;
  replayQueue: Array<{
    routeId: string;
    category: BusinessWorkflowCategory;
    requestClass: "read_only" | "state_changing" | "credential" | "admin";
    action: string;
    requiredAuthorization: string[];
  }>;
  gaps: string[];
  nextActions: string[];
};

export type CveReconciliationPlan = {
  generatedAt: string;
  status: "clean" | "needs_version_evidence" | "dedupe_needed" | "validation_ready";
  duplicateGroups: Array<{
    key: string;
    ids: string[];
    preferredId: string;
    reason: string;
  }>;
  versionGaps: Array<{
    cveId?: string;
    technology: string;
    target: string;
    reason: string;
  }>;
  validationReady: string[];
  suppressedCandidates: string[];
  confidenceAdjustments: Array<{
    candidateId: string;
    from: "low" | "medium" | "high";
    to: "low" | "medium" | "high";
    reason: string;
  }>;
  nextActions: string[];
};

export type AuthorizedValidationStepKind =
  | "evidence_review"
  | "version_confirmation"
  | "read_only_role_compare"
  | "no_submit_browser_capture"
  | "non_destructive_template"
  | "manual_business_rule_check";

export type AuthorizedValidationStep = {
  id: string;
  candidateId: string;
  kind: AuthorizedValidationStepKind;
  title: string;
  target: string;
  status: "ready" | "needs_context" | "blocked";
  risk: "low" | "medium" | "high";
  requiredAuthorization: string[];
  requiredContext: string[];
  procedure: string[];
  expectedEvidence: string[];
  proofStandard: string[];
  falsePositiveGuards: string[];
  stopConditions: string[];
  prohibitedActions: string[];
  automationHint?: string;
  blockedBy?: string;
};

export type AuthorizedValidationPlaybook = {
  generatedAt: string;
  target: string;
  mode: "passive" | "safe" | "active";
  status: "ready" | "needs_context" | "blocked" | "empty";
  summary: string;
  steps: AuthorizedValidationStep[];
  nextStepId?: string;
  evidenceContract: string[];
  globalStopConditions: string[];
  prohibitedActions: string[];
};

export type SubAgentOperatingModel = {
  generatedAt: string;
  status: "idle" | "healthy" | "backlogged" | "stalled";
  capacity: {
    queued: number;
    running: number;
    completed: number;
    failed: number;
  };
  roleCoverage: Array<{
    role: SubAgentRole;
    completed: number;
    running: number;
    queued: number;
    gap?: string;
  }>;
  retryQueue: string[];
  arbitrationNeeds: string[];
  nextActions: string[];
};

export type SecurityClosureModel = {
  target: string;
  generatedAt: string;
  status: "needs_context" | "ready" | "blocked" | "running" | "settled";
  summary: string;
  objectiveModel: SecurityObjectiveModel;
  validationPlan: ValidationClosurePlan;
  businessWorkflowGraph: BusinessWorkflowGraph;
  browserPlan: BrowserInteractionPlan;
  cveReconciliation: CveReconciliationPlan;
  authorizedValidation: AuthorizedValidationPlaybook;
  subAgentModel: SubAgentOperatingModel;
  nextBestActions: string[];
};

export type SubAgentCoordinationPlanItem = {
  id: string;
  priority: "critical" | "high" | "medium" | "low";
  role: SubAgentRole;
  title: string;
  rationale: string;
  task: string;
  runMode: "foreground" | "background";
  contextHints: string[];
  expectedOutput: string[];
  blockedReason?: string;
};

export type SubAgentCoordinationPlan = {
  generatedAt: string;
  items: SubAgentCoordinationPlanItem[];
};

export type AdaptiveSecurityAction = {
  key: string;
  toolId: string;
  phase: SecurityPhase;
  title: string;
  description: string;
  inputKind: "host" | "url" | "service";
  inputValues: string[];
  intensity: PentestIntensity;
  requiresActiveApproval: boolean;
  blockedReason?: string;
};

export type OwaspValidationItem = {
  id: string;
  title: string;
  category: string;
  passiveSignals: string[];
  safeChecks: string[];
  activeRequiresApproval: boolean;
};

export type SecurityReportFinding = {
  title: string;
  severity: FindingSeverity;
  confidence: "low" | "medium" | "high";
  affectedTarget: string;
  evidence: string;
  reproductionBoundary: string;
  remediation: string;
};

export type NucleiTemplateKnowledge = {
  id: string;
  name: string;
  severity: FindingSeverity;
  path: string;
  cveIds: string[];
  cweIds: string[];
  tags: string[];
  references: string[];
  vendor?: string;
  product?: string;
  verified?: boolean;
  maxRequest?: number;
};

export type SecurityKnowledgeIndex = {
  schemaVersion: 1;
  generatedAt: string;
  source: "projectdiscovery/nuclei-templates";
  sourcePath: string;
  templateCount: number;
  cveTemplateCount: number;
  cveCount: number;
  templates: NucleiTemplateKnowledge[];
  cves: Array<{
    cveId: string;
    templateCount: number;
    severities: FindingSeverity[];
    products: string[];
    templates: string[];
  }>;
};

export type FrameworkKnowledgeProfile = {
  id: string;
  name: string;
  aliases: string[];
  categories: string[];
  ecosystem: "php" | "java" | "dotnet" | "node" | "python" | "go" | "cms" | "oa" | "admin" | "server" | "unknown";
  riskFocus: string[];
  fingerprintSignals: string[];
  cpe?: string;
  website?: string;
  sources: string[];
  templateCount: number;
  cveCount: number;
  cnvdCount: number;
  topCves: string[];
  topTemplates: string[];
  topTags: string[];
  verifiedTemplateCount: number;
};

export type FrameworkKnowledgeIndex = {
  schemaVersion: 1;
  generatedAt: string;
  sources: {
    wappalyzer?: string;
    nuclei?: string;
    curated: string;
  };
  wappalyzerTechnologyCount: number;
  profileCount: number;
  profiles: FrameworkKnowledgeProfile[];
};

export type BusinessLogicKnowledgeItem = {
  id: string;
  title: string;
  category: string;
  risk: FindingSeverity;
  owaspRefs: string[];
  apiRefs: string[];
  passiveSignals: string[];
  dataNeeded: string[];
  safeTestIdeas: string[];
  activeTestIdeas: string[];
  evidenceToCollect: string[];
  falsePositiveGuards: string[];
};

export type BusinessLogicTestCase = {
  id: string;
  title: string;
  category: string;
  risk: FindingSeverity;
  targetHints: string[];
  matchedSignals: string[];
  prerequisites: string[];
  safeSteps: string[];
  activeSteps: string[];
  evidenceToCollect: string[];
  falsePositiveGuards: string[];
  blockedReason?: string;
};

export type BusinessLogicTestPlan = {
  target: string;
  generatedAt: string;
  requiresUserContext: boolean;
  contextQuestions: string[];
  authContexts: Array<Pick<SecurityAuthContext, "name" | "role" | "username" | "baseUrl">>;
  testCases: BusinessLogicTestCase[];
};

export type SecurityKnowledgeSyncResult = {
  indexPath: string;
  businessLogicPath: string;
  frameworkKnowledgePath: string;
  templateCount: number;
  cveTemplateCount: number;
  cveCount: number;
  frameworkProfileCount: number;
};

export type SecurityKnowledgeSearchResult = {
  kind: "cve" | "template" | "framework" | "business_logic";
  id: string;
  title: string;
  severity?: FindingSeverity;
  source: string;
  summary: string;
};

export type FrameworkKnowledgeSeed = {
  name: string;
  aliases: string[];
  categories: string[];
  ecosystem: FrameworkKnowledgeProfile["ecosystem"];
  riskFocus: string[];
  fingerprintSignals: string[];
  cpe?: string;
  website?: string;
};

export type LocalAdvisoryRule = {
  products: string[];
  cveId: string;
  title: string;
  severity: FindingSeverity;
  confidence: "low" | "medium" | "high";
  minVersion?: string;
  belowVersion?: string;
  exactVersions?: string[];
  versionRange?: string;       // semver range spec like ">=1.2.3, <2.0.0"
  rangeLabel: string;
  matchWithoutVersion?: boolean;
  cvssVector?: string;          // CVSS 3.1 vector string
  cvssScore?: number;           // Pre-computed CVSS base score
  description?: string;         // CVE description
  references?: string[];         // Advisory references
};

export type PayloadCandidateRisk = "low" | "medium" | "high";

export type PayloadInsertionHint = {
  endpoint: string;
  method?: string;
  location: "query" | "body" | "path" | "header" | "auth_context" | "upload";
  name?: string;
  riskSignals: string[];
  evidenceRefs: string[];
};

export type PayloadCandidate = {
  id: string;
  category:
    | "xss_reflection"
    | "sql_injection"
    | "ssti"
    | "command_injection"
    | "path_traversal"
    | "ssrf"
    | "xxe"
    | "authz_object_reference"
    | "mass_assignment"
    | "parser_header_injection"
    | "file_upload";
  title: string;
  risk: PayloadCandidateRisk;
  targetHints: string[];
  insertionHints: PayloadInsertionHint[];
  payloads: string[];
  prerequisites: string[];
  expectedObservations: string[];
  falsePositiveGuards: string[];
  evidenceRefs: string[];
  requiresApproval: boolean;
  notes: string[];
};

export type PayloadCandidateSet = {
  generatedAt: string;
  mode: "advisory";
  focus?: string;
  summary: string;
  candidates: PayloadCandidate[];
  evidenceGaps: string[];
  guardrails: string[];
};

export type PayloadDraftExecutionGate =
  | "safe_readonly_fetch"
  | "http_get"
  | "approval_required"
  | "manual_review";

export type PayloadRequestDraft = {
  id: string;
  candidateId: string;
  category: PayloadCandidate["category"];
  title: string;
  risk: PayloadCandidateRisk;
  requiresApproval: boolean;
  recommendedTool: PayloadDraftExecutionGate;
  method: string;
  url: string;
  baselineUrl?: string;
  insertion: PayloadInsertionHint;
  payload: string;
  authContextNames: string[];
  bodyPreview?: string;
  headerPreview?: string[];
  toolUseHint: string;
  approvalReason?: string;
  expectedObservations: string[];
  falsePositiveGuards: string[];
  evidenceRefs: string[];
  notes: string[];
};

export type PayloadRequestDraftSet = {
  generatedAt: string;
  mode: "draft_only";
  focus?: string;
  summary: string;
  candidateSummary: string;
  evidenceGaps: string[];
  drafts: PayloadRequestDraft[];
  guardrails: string[];
};

export type AccessExposureState =
  | "public_observed"
  | "auth_gated_observed"
  | "unknown_auth"
  | "needs_anonymous_baseline"
  | "ready_for_role_comparison"
  | "passive_mutation_only";

export type AccessExposureItem = {
  id: string;
  method: string;
  endpoint: string;
  pathTemplate?: string;
  source: string;
  confidence: "low" | "medium" | "high";
  state: AccessExposureState;
  authRequired: "likely" | "unknown" | "not_observed";
  status?: number;
  anonymousBaseline?: {
    status: number;
    bodyLength?: number;
    bodyHash?: string;
    evidenceRef: string;
  };
  authenticatedBaselines: Array<{
    authContextName?: string;
    status: number;
    bodyLength?: number;
    bodyHash?: string;
    evidenceRef: string;
  }>;
  riskSignals: string[];
  queryParams: string[];
  bodyParamHints: string[];
  evidenceRefs: string[];
  priorityScore: number;
  priorityRationale: string[];
  informationNeed: string;
  safeObservationIdeas: string[];
};

export type AccessExposureMap = {
  generatedAt: string;
  target?: string;
  summary: {
    total: number;
    publicObserved: number;
    authGatedObserved: number;
    unknownAuth: number;
    needsAnonymousBaseline: number;
    readyForRoleComparison: number;
    passiveMutationOnly: number;
    highValue: number;
  };
  items: AccessExposureItem[];
  informationGaps: string[];
  guardrails: string[];
};
