import { randomUUID } from "node:crypto";
import { existsSync, statSync } from "node:fs";
import { readFile } from "node:fs/promises";
import { basename, extname, resolve, sep } from "node:path";

export type PermissionMode = "view" | "passive" | "safe" | "approval" | "autonomous" | "full";

export type TargetKind = "url" | "domain" | "file" | "text";

export type TargetInput = {
  kind: TargetKind;
  raw: string;
  normalized: string;
};

export type SecurityPhase =
  | "scope"
  | "recon"
  | "asset_discovery"
  | "fingerprint"
  | "frontend"
  | "vulnerability_analysis"
  | "safe_validation"
  | "reporting";

export type SecurityTaskStatus = "pending" | "running" | "completed" | "blocked" | "skipped";

export type SecurityCheckStatus = "pending" | "observed" | "validated" | "blocked" | "ruled_out";

export type SecurityWorkflow = {
  id: string;
  sessionId: string;
  target: TargetInput;
  status: SecurityTaskStatus;
  currentPhase: SecurityPhase;
  summary: string;
  createdAt: string;
  updatedAt: string;
};

export type SecurityWorkflowTask = {
  id: string;
  workflowId: string;
  sessionId: string;
  phase: SecurityPhase;
  title: string;
  description: string;
  recommendedRole?: SubAgentRole;
  suggestedSkills: string[];
  suggestedTools: string[];
  status: SecurityTaskStatus;
  createdAt: string;
  updatedAt: string;
};

export type SecurityToolRunStatus =
  | "planned"
  | "blocked"
  | "missing"
  | "denied"
  | "success"
  | "failed"
  | "skipped"
  | "no_findings";

export type SecurityToolRunOrigin = "pipeline" | "adaptive" | "manual";

export type SecurityToolFailureCategory =
  | "none"
  | "blocked"
  | "missing"
  | "user_denied"
  | "no_findings"
  | "template_error"
  | "network_error"
  | "rate_limited"
  | "auth_required"
  | "parse_error"
  | "tool_error";

export type SecurityToolRun = {
  id: string;
  sessionId: string;
  workflowId?: string;
  parentRunId?: string;
  toolId: string;
  phase: SecurityPhase;
  origin: SecurityToolRunOrigin;
  status: SecurityToolRunStatus;
  command?: string;
  inputKind?: "target" | "host" | "url" | "service" | "file";
  inputCount: number;
  inputArtifact?: string;
  outputArtifact?: string;
  outputSummary?: string;
  exitCode?: number;
  blockedReason?: string;
  failureCategory?: SecurityToolFailureCategory;
  findingCount?: number;
  createdAt: string;
  updatedAt: string;
};

export type SecurityValidationCheck = {
  id: string;
  sessionId: string;
  workflowId?: string;
  checkId: string;
  title: string;
  category: string;
  target: string;
  phase: SecurityPhase;
  status: SecurityCheckStatus;
  activeRequiresApproval: boolean;
  passiveSignals: string[];
  safeChecks: string[];
  evidenceSummary?: string;
  rationale?: string;
  createdAt: string;
  updatedAt: string;
};

export type FindingSeverity = "info" | "low" | "medium" | "high" | "critical";

export type SecurityFindingState =
  | "candidate"
  | "needs_validation"
  | "validated"
  | "false_positive"
  | "accepted_risk"
  | "fixed";

export type SecurityFinding = {
  id: string;
  sessionId: string;
  workflowId?: string;
  title: string;
  severity: FindingSeverity;
  confidence: "low" | "medium" | "high";
  target: string;
  description: string;
  evidenceSummary?: string;
  remediation?: string;
  state?: SecurityFindingState;
  dedupeKey?: string;
  evidenceIds?: string[];
  firstSeenAt?: string;
  lastSeenAt?: string;
  createdAt: string;
  updatedAt: string;
};

export type SecurityEvidence = {
  id: string;
  sessionId: string;
  workflowId?: string;
  findingId?: string;
  source: string;
  kind: "note" | "command" | "file" | "http" | "screenshot" | "tool";
  summary: string;
  data?: string;
  createdAt: string;
};

export type SecurityAsset = {
  id: string;
  sessionId: string;
  workflowId?: string;
  kind: "domain" | "subdomain" | "url" | "ip" | "service" | "cidr";
  value: string;
  source: string;
  confidence: "low" | "medium" | "high";
  metadata?: string;
  createdAt: string;
};

export type SecurityTechnology = {
  id: string;
  sessionId: string;
  workflowId?: string;
  target: string;
  name: string;
  version?: string;
  category?: string;
  source: string;
  confidence: "low" | "medium" | "high";
  evidenceSummary?: string;
  createdAt: string;
};

export type SecurityCveMatch = {
  id: string;
  sessionId: string;
  workflowId?: string;
  target: string;
  technology: string;
  cveId?: string;
  title: string;
  severity: FindingSeverity;
  confidence: "low" | "medium" | "high";
  rationale: string;
  source: string;
  createdAt: string;
};

export type SecurityValidationAttemptStatus =
  | "planned"
  | "validated"
  | "inconclusive"
  | "ruled_out"
  | "blocked";

export type SecurityValidationTargetKind = "finding" | "cve" | "business_logic" | "tool_run";

export type SecurityValidationAttempt = {
  id: string;
  sessionId: string;
  workflowId?: string;
  targetKind: SecurityValidationTargetKind;
  targetId: string;
  targetTitle: string;
  method: string;
  status: SecurityValidationAttemptStatus;
  confidence: "low" | "medium" | "high";
  rationale: string;
  evidenceIds: string[];
  createdAt: string;
  updatedAt: string;
};

export type SecurityAuthContext = {
  id: string;
  sessionId: string;
  workflowId?: string;
  name: string;
  baseUrl?: string;
  role?: string;
  tenant?: string;
  username?: string;
  cookieHeader?: string;
  authorizationHeader?: string;
  headersJson?: string;
  storageStatePath?: string;
  notes?: string;
  createdAt: string;
  updatedAt: string;
};

export type ExpectedAuthorizationSubject = {
  id: string;
  name: string;
  role?: string;
  tenant?: string;
  username?: string;
};

export type ExpectedAuthorizationRule = {
  id: string;
  description?: string;
  subjectId: string;
  /** Path template (e.g. /api/orders/{id}) or concrete path prefix. */
  route: string;
  /** HTTP method or "ANY" if not specified. */
  method?: string;
  action: "allow" | "deny";
  confidence: "high" | "medium" | "low";
};

export type ExpectedAuthorizationObjectRule = {
  id: string;
  description?: string;
  subjectId: string;
  /** Path template (e.g. /api/orders/{id}) or concrete path prefix. */
  route: string;
  /** HTTP method or "ANY" if not specified. */
  method?: string;
  objectReference: {
    location: "path" | "query" | "body";
    name: string;
  };
  expectedOwnership: "own" | "same-tenant" | "role-bound" | "none";
  action: "allow" | "deny";
  confidence: "high" | "medium" | "low";
};

export type ExpectedAuthorizationPolicy = {
  id: string;
  name: string;
  description?: string;
  subjects: ExpectedAuthorizationSubject[];
  rules: ExpectedAuthorizationRule[];
  objectRules?: ExpectedAuthorizationObjectRule[];
  createdAt: string;
};

export type BrowserFormCandidate = {
  pageUrl: string;
  action: string;
  method: string;
  inputNames: string[];
  inputTypes: string[];
  hasPassword: boolean;
  hasCsrfToken: boolean;
  riskSignals?: string[];
};

export type BrowserExplorationResult = {
  sessionId: string;
  workflowId?: string;
  startUrl: string;
  pagesVisited: string[];
  forms: BrowserFormCandidate[];
  links?: string[];
  scripts?: string[];
  apiEndpoints?: string[];
  sensitiveActions?: Array<{
    pageUrl: string;
    kind: "form" | "link" | "button" | "api";
    label: string;
    target: string;
    method?: string;
    riskSignals: string[];
  }>;
  storageSignals?: Array<{
    pageUrl: string;
    storage: "localStorage" | "sessionStorage" | "cookie";
    key: string;
    riskSignals: string[];
  }>;
  pageSummaries?: Array<{
    url: string;
    title: string;
    formCount: number;
    linkCount: number;
    scriptCount: number;
  }>;
  storageStatePath?: string;
  artifactPath: string;
  harArtifactPath?: string;
  evidenceId: string;
};

export type BrowserNetworkRequest = {
  pageUrl: string;
  url: string;
  method: string;
  resourceType: string;
  status?: number;
  contentType?: string;
  initiator?: string;
  requestHeaders?: Record<string, string>;
  responseHeaders?: Record<string, string>;
  requestBodyPreview?: string;
};

export type BrowserDomButton = {
  pageUrl: string;
  label: string;
  type: string;
  name?: string;
  id?: string;
  riskSignals: string[];
};

export type BrowserIframeCandidate = {
  pageUrl: string;
  src: string;
  name?: string;
  title?: string;
  sandbox?: string;
  riskSignals: string[];
};

export type BrowserStorageItem = {
  pageUrl: string;
  storage: "localStorage" | "sessionStorage" | "cookie";
  key: string;
  riskSignals: string[];
};

export type BrowserCookieSignal = {
  pageUrl: string;
  name: string;
  domain?: string;
  path?: string;
  httpOnly?: boolean;
  secure?: boolean;
  sameSite?: string;
  expires?: number;
  riskSignals: string[];
};

export type JsEndpointCandidate = {
  scriptUrl: string;
  value: string;
  normalizedUrl?: string;
  method?: string;
  confidence: "low" | "medium" | "high";
  riskSignals: string[];
};

export type JsSensitiveSignal = {
  scriptUrl: string;
  kind:
    | "secret-like-string"
    | "source-map"
    | "source-map-source"
    | "internal-host"
    | "debug-flag"
    | "cloud-storage"
    | "cdn-host"
    | "jwt-like"
    | "access-key-like"
    | "private-key-like"
    | "lazy-chunk"
    | "backup-file-candidate"
    | "well-known-endpoint";
  evidence: string;
  riskSignals: string[];
};

export type JsSourceMapSignal = {
  scriptUrl: string;
  mapUrl: string;
  available: boolean;
  sourceCount?: number;
  sourceContentCount?: number;
  recoveredEndpointCount?: number;
  recoveredSensitiveSignalCount?: number;
  sourcesSample: string[];
  sourcesWithContentSample?: string[];
  riskSignals: string[];
  error?: string;
};

export type JsLibrarySignal = {
  scriptUrl: string;
  name: string;
  version?: string;
  confidence: "low" | "medium" | "high";
  evidence: string;
  riskSignals: string[];
};

export type JsAnalysisSummary = {
  scriptCount: number;
  endpointCount: number;
  sensitiveSignalCount: number;
  sourceMapCount: number;
  libraryCount: number;
  highValueRouteCount: number;
  websocketCount: number;
  graphqlCount: number;
};

export type AuthSurfaceModel = {
  loginPages: string[];
  authEndpoints: string[];
  passwordForms: BrowserFormCandidate[];
  authStorageKeys: Array<{
    pageUrl: string;
    storage: "localStorage" | "sessionStorage" | "cookie";
    key: string;
  }>;
  notes: string[];
};

export type AuthSurfaceAssessment = {
  login: "present" | "not_observed" | "unknown";
  registration: "present" | "not_observed" | "unknown";
  passwordRecovery: "present" | "not_observed" | "unknown";
  oauthOrSso: "present" | "not_observed" | "unknown";
  mfaOrCaptcha: "present" | "not_observed" | "unknown";
  authState: "anonymous" | "authenticated" | "failed_login" | "unknown";
  sessionMechanisms: Array<"cookie" | "jwt" | "localStorage" | "sessionStorage" | "authorization-header" | "unknown">;
  csrfSignals: "present" | "missing_in_password_forms" | "not_applicable" | "unknown";
  loginPages: string[];
  authEndpoints: string[];
  highValueFlows: string[];
  riskSignals: string[];
  nextEvidenceNeeded: string[];
  confidence: "low" | "medium" | "high";
};

export type NormalizedApiEndpoint = {
  id: string;
  method: string;
  pathTemplate: string;
  examples: string[];
  queryParams: string[];
  bodyParamHints: string[];
  sources: Array<"form" | "script" | "network" | "resource" | "link" | "openapi" | "graphql">;
  authRequired: "unknown" | "likely" | "not_required";
  confidence: "low" | "medium" | "high";
  riskSignals: string[];
};

export type ApiDescriptionDocument = {
  url: string;
  kind: "openapi" | "graphql";
  source: "link" | "script" | "network" | "resource" | "manual";
  status?: number;
  contentType?: string;
  title?: string;
  operationCount?: number;
  error?: string;
  document?: unknown;
};

export type WebAppReconResult = BrowserExplorationResult & {
  networkRequests: BrowserNetworkRequest[];
  buttons?: BrowserDomButton[];
  iframes?: BrowserIframeCandidate[];
  storageItems?: BrowserStorageItem[];
  cookies?: BrowserCookieSignal[];
  jsEndpoints: JsEndpointCandidate[];
  jsSensitiveSignals: JsSensitiveSignal[];
  jsSourceMaps?: JsSourceMapSignal[];
  jsLibraries?: JsLibrarySignal[];
  jsAnalysisSummary?: JsAnalysisSummary;
  apiInventory: Array<{
    url: string;
    method?: string;
    source: "link" | "form" | "script" | "network" | "resource";
    confidence: "low" | "medium" | "high";
    riskSignals: string[];
  }>;
  apiDescriptionDocuments?: ApiDescriptionDocument[];
  normalizedApiEndpoints?: NormalizedApiEndpoint[];
  normalizedApiArtifactPath?: string;
  authSurface: AuthSurfaceModel;
  authAssessment?: AuthSurfaceAssessment;
  authAssessmentArtifactPath?: string;
};

export type PathAccessDecision = {
  allowed: boolean;
  absolutePath: string;
  reason?: string;
};

export type IntentExtraction = {
  userText: string;
  intent: string;
  targets: TargetInput[];
  filePaths: string[];
  constraints: string[];
  needsClarification: boolean;
  clarificationQuestion?: string;
};

export type WorkPriority = "critical" | "high" | "medium" | "low";

export type SubAgentStatus = "queued" | "running" | "completed" | "failed" | "closed" | "cancelled";

export type SubAgentRunMode = "foreground" | "background";

export type SubAgentRole =
  | "default"
  | "explorer"
  | "worker"
  | "reviewer"
  | "recon"
  | "frontend"
  | "fingerprint"
  | "cve"
  | "web_vuln"
  | "exploit";

export type SubAgentRecord = {
  id: string;
  sessionId: string;
  role: SubAgentRole;
  description?: string;
  task: string;
  status: SubAgentStatus;
  priority?: WorkPriority;
  runMode?: SubAgentRunMode;
  retryCount?: number;
  maxRetries?: number;
  parentAgentId?: string;
  contextPaths?: string[];
  resultSummary?: string;
  progressSummary?: string;
  toolUseCount: number;
  outputPath?: string;
  lastHeartbeatAt?: string;
  memoryKey?: string;
  createdAt: string;
  updatedAt: string;
};

export type TaskNodeStatus = "pending" | "running" | "completed" | "blocked" | "failed";

export type TaskTreeNode = {
  id: string;
  sessionId: string;
  workflowId?: string;
  parentId?: string;
  phase: SecurityPhase;
  title: string;
  goal: string;
  status: TaskNodeStatus;
  toolId?: string;
  evidenceIds: string[];
  findingIds: string[];
  summary: string;
  sortOrder: number;
  createdAt: string;
  updatedAt: string;
};

export type ContextFile = {
  path: string;
  content: string;
  truncated: boolean;
};

export type AgentPlan = {
  id: string;
  sessionId: string;
  goal: string;
  summary: string;
  steps: string[];
  suggestedCommands: string[];
  createdAt: string;
};

export type AgentAction =
  | {
      type: "shell";
      command: string;
      purpose: string;
    }
  | {
      type: "security_probe";
      target: string;
      probe: "basic_recon" | "dns" | "http_headers";
      purpose: string;
    }
  | {
      type: "ask_user";
      question: string;
      reason: string;
    }
  | {
      type: "subagent";
      role: SubAgentRole;
      description?: string;
      task: string;
      contextPaths?: string[];
      background?: boolean;
    }
  | {
      type: "read_file";
      path: string;
      purpose: string;
    }
  | {
      type: "list_files";
      path: string;
      purpose: string;
      recursive?: boolean;
    }
  | {
      type: "file_edit";
      operation: FileEditOperation;
      path: string;
      content?: string;
      oldText?: string;
      newText?: string;
      purpose: string;
    }
  | {
      type: "apply_patch";
      patch: string;
      purpose: string;
    }
  | {
      type: "none";
      purpose: string;
    }
  | {
      type: "mcp";
      tool: string;
      args: Record<string, unknown>;
      purpose: string;
    }
  | {
      type: "tool_use";
      tool_use: string;
      input: Record<string, unknown>;
      purpose: string;
    };

export type AgentDecision = {
  message: string;
  plan: string[];
  actions: AgentAction[];
  final: boolean;
};

export type TurnEventKind =
  | "turn_started"
  | "context_built"
  | "skill_context_built"
  | "security_workflow_built"
  | "decision_repair_requested"
  | "decision_repair_completed"
  | "agent_message"
  | "plan_created"
  | "tool_approval_requested"
  | "tool_approval_resolved"
  | "tool_started"
  | "tool_completed"
  | "tool_blocked"
  | "file_change_approval_requested"
  | "file_change_approval_resolved"
  | "file_change_started"
  | "file_change_completed"
  | "file_change_blocked"
  | "subagent_started"
  | "subagent_launched"
  | "subagent_progress"
  | "subagent_tool_started"
  | "subagent_tool_completed"
  | "subagent_tool_blocked"
  | "subagent_completed"
  | "subagent_failed"
  | "user_input_requested"
  | "turn_completed"
  | "turn_failed";

export type TurnEvent = {
  id: string;
  sessionId: string;
  turnId: string;
  kind: TurnEventKind;
  message: string;
  payload?: unknown;
  createdAt: string;
};

export type TurnResult = {
  sessionId: string;
  turnId: string;
  status: "completed" | "needs_input" | "failed";
  finalMessage: string;
  requestedInput?: {
    question: string;
    reason: string;
  };
  events: TurnEvent[];
};

export type ShellCommandRecord = {
  id: string;
  sessionId: string;
  command: string;
  risk: "low" | "medium" | "high" | "blocked";
  status: "pending" | "approved" | "denied" | "blocked" | "success" | "failed";
  summary?: string;
  exitCode?: number | null;
  createdAt: string;
  updatedAt: string;
};

export type FileEditOperation = "create" | "overwrite" | "append" | "string_replace" | "apply_patch";

export type FileChangeStatus = "pending" | "approved" | "denied" | "blocked" | "applied" | "failed";

export type FileChangeRecord = {
  id: string;
  sessionId: string;
  path: string;
  operation: FileEditOperation;
  status: FileChangeStatus;
  summary?: string;
  diff?: string;
  createdAt: string;
  updatedAt: string;
};

export type AgentObservation = {
  id: string;
  sessionId: string;
  source: string;
  summary: string;
  createdAt: string;
};

export type LabVirtualBoxVm = {
  name: string;
  uuid: string;
  state?: string;
  guestOs?: string;
  networkAdapters: string[];
  candidateIps: string[];
};

export function newId(prefix: string): string {
  return `${prefix}_${randomUUID()}`;
}

export function nowIso(): string {
  return new Date().toISOString();
}

const knownFileExtensions = new Set([
  ".bin",
  ".cfg",
  ".conf",
  ".csv",
  ".css",
  ".html",
  ".ini",
  ".java",
  ".js",
  ".jsx",
  ".json",
  ".lock",
  ".log",
  ".md",
  ".py",
  ".rs",
  ".scss",
  ".toml",
  ".ts",
  ".tsx",
  ".txt",
  ".xml",
  ".yaml",
  ".yml"
]);

const sensitiveBasenames = new Set([
  ".env",
  ".npmrc",
  ".pypirc",
  ".netrc",
  "credentials",
  "credentials.json",
  "id_rsa",
  "id_dsa",
  "id_ecdsa",
  "id_ed25519",
  "known_hosts"
]);

const sensitiveNamePatterns = [
  /^\.env\./i,
  /(^|[._-])(api[-_]?key|apikey|secret|token|password|passwd|credential|credentials)([._-]|$)/i,
  /\.(pem|key|p12|pfx)$/i
];

export function hasKnownFileExtension(value: string): boolean {
  return knownFileExtensions.has(extname(value.trim()).toLowerCase());
}

export function isPathInside(childPath: string, parentPath: string): boolean {
  const child = resolve(childPath);
  const parent = resolve(parentPath);
  const normalizedChild = process.platform === "win32" ? child.toLowerCase() : child;
  const normalizedParent = process.platform === "win32" ? parent.toLowerCase() : parent;
  return normalizedChild === normalizedParent || normalizedChild.startsWith(`${normalizedParent}${sep}`);
}

export function isSensitivePath(path: string): boolean {
  const name = basename(path).toLowerCase();
  return sensitiveBasenames.has(name) || sensitiveNamePatterns.some((pattern) => pattern.test(name));
}

export function validateReadablePath(path: string, cwd = process.cwd()): PathAccessDecision {
  const absolutePath = resolve(cwd, path);
  const workspaceRoot = resolve(cwd);

  if (!isPathInside(absolutePath, workspaceRoot)) {
    return {
      allowed: false,
      absolutePath,
      reason: `Path is outside the workspace root: ${workspaceRoot}`
    };
  }

  if (isSensitivePath(absolutePath)) {
    return {
      allowed: false,
      absolutePath,
      reason: "Path matches a sensitive-file deny rule."
    };
  }

  return { allowed: true, absolutePath };
}

export function validateWritablePath(path: string, cwd = process.cwd()): PathAccessDecision {
  const absolutePath = resolve(cwd, path);
  const workspaceRoot = resolve(cwd);

  if (!isPathInside(absolutePath, workspaceRoot)) {
    return {
      allowed: false,
      absolutePath,
      reason: `Path is outside the workspace root: ${workspaceRoot}`
    };
  }

  if (isSensitivePath(absolutePath)) {
    return {
      allowed: false,
      absolutePath,
      reason: "Path matches a sensitive-file deny rule."
    };
  }

  return { allowed: true, absolutePath };
}

export function parseTargetInput(input: string, cwd = process.cwd()): TargetInput {
  const trimmed = input.trim();
  if (/^https?:\/\//i.test(trimmed)) {
    return { kind: "url", raw: input, normalized: trimmed };
  }

  const pathDecision = validateReadablePath(trimmed, cwd);
  if (pathDecision.allowed && existsSync(pathDecision.absolutePath) && statSync(pathDecision.absolutePath).isFile()) {
    return { kind: "file", raw: input, normalized: pathDecision.absolutePath };
  }

  if (hasKnownFileExtension(trimmed)) {
    return { kind: "text", raw: input, normalized: trimmed };
  }

  if (/^[a-z0-9.-]+\.[a-z]{2,}$/i.test(trimmed)) {
    return { kind: "domain", raw: input, normalized: trimmed.toLowerCase() };
  }

  return { kind: "text", raw: input, normalized: trimmed };
}

export function extractUrlLikeTargets(input: string): TargetInput[] {
  const targets = new Map<string, TargetInput>();
  for (const match of input.matchAll(/\bhttps?:\/\/[^\s"'<>]+/gi)) {
    const raw = match[0].replace(/[),.;，。]+$/u, "");
    const target = parseTargetInput(raw);
    targets.set(`${target.kind}:${target.normalized}`, target);
  }
  for (const match of input.matchAll(/(?<![@\w.-])([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+)(?![\w.-])/gi)) {
    const raw = match[1].replace(/[),.;，。]+$/u, "");
    if (/^\d+\.\d+\.\d+\.\d+$/.test(raw) || hasKnownFileExtension(raw)) {
      continue;
    }
    const target = parseTargetInput(raw);
    if (target.kind === "domain") {
      targets.set(`${target.kind}:${target.normalized}`, target);
    }
  }
  return [...targets.values()];
}

export function extractFilePathMentions(input: string, cwd = process.cwd()): string[] {
  const candidates = new Set<string>();
  const patterns = [
    /(?:"([^"]+\.(?:bin|cfg|conf|csv|css|html|ini|java|js|jsx|json|lock|log|md|py|rs|scss|toml|ts|tsx|txt|xml|ya?ml))")/gi,
    /(?:'([^']+\.(?:bin|cfg|conf|csv|css|html|ini|java|js|jsx|json|lock|log|md|py|rs|scss|toml|ts|tsx|txt|xml|ya?ml))')/gi,
    /(?<![\w@:/\\.-])([A-Za-z0-9_.\\/:-]+\.(?:bin|cfg|conf|csv|css|html|ini|java|js|jsx|json|lock|log|md|py|rs|scss|toml|ts|tsx|txt|xml|ya?ml))(?![\w.-])/gi
  ];

  for (const pattern of patterns) {
    for (const match of input.matchAll(pattern)) {
      const raw = (match[1] ?? "").trim().replace(/[),.;]+$/u, "");
      if (!raw) {
        continue;
      }
      const decision = validateReadablePath(raw, cwd);
      if (decision.allowed && existsSync(decision.absolutePath) && statSync(decision.absolutePath).isFile()) {
        candidates.add(decision.absolutePath);
      }
    }
  }

  return [...candidates];
}

export async function readContextFile(path: string, maxBytes = 80_000): Promise<ContextFile> {
  const decision = validateReadablePath(path);
  if (!decision.allowed) {
    throw new Error(decision.reason ?? "Path is not allowed.");
  }
  const absolute = decision.absolutePath;
  const buffer = await readFile(absolute);
  const truncated = buffer.byteLength > maxBytes;
  const slice = truncated ? buffer.subarray(0, maxBytes) : buffer;
  return {
    path: absolute,
    content: slice.toString("utf8"),
    truncated
  };
}

export function summarizeOutput(output: string, maxLength = 1200): string {
  const sanitized = sanitizeObservationText(output);
  const signals = renderObservationSignals(sanitized);
  const compact = truncateLongLines([signals, sanitized.replace(/\s+\n/g, "\n").trim()].filter(Boolean).join("\n\n"), 360);
  if (compact.length <= maxLength) {
    return compact;
  }
  return `${compact.slice(0, maxLength)}\n...[truncated]`;
}

export function truncateForContext(input: string, maxLength = 50_000): string {
  if (input.length <= maxLength) {
    return input;
  }
  return `${input.slice(0, maxLength)}\n...[truncated]`;
}

export function truncateLongLines(input: string, maxLineLength = 800): string {
  return input.split(/\r?\n/).map((line) => {
    if (line.length <= maxLineLength) {
      return line;
    }
    return `${line.slice(0, maxLineLength)}...[line truncated ${line.length - maxLineLength} chars]`;
  }).join("\n");
}

export function sanitizeObservationText(input: string): string {
  return removeBinaryNoiseLines(sanitizeHttpBinaryBodies(input))
    .replace(/<style\b[^>]*>[\s\S]*?<\/style>/gi, "<style>[removed]</style>")
    .replace(/<script\b(?![^>]*\bsrc\s*=)[^>]*>[\s\S]*?<\/script>/gi, "<script>[removed inline script]</script>")
    .replace(/data:image\/[a-z0-9.+-]+;base64,[A-Za-z0-9+/=]+/gi, "data:image/[removed]");
}

function removeBinaryNoiseLines(input: string): string {
  let removed = false;
  const lines = input.split(/\r?\n/).filter((line) => {
    if (!looksBinary(line)) {
      return true;
    }
    removed = true;
    return false;
  });
  return removed ? `${lines.join("\n")}\n[binary noise lines removed]` : input;
}

function sanitizeHttpBinaryBodies(input: string): string {
  return input.replace(/(HTTP\/\d(?:\.\d)?[^\r\n]*(?:\r?\n(?!HTTP\/\d(?:\.\d)?)[^\r\n]*)*\r?\n\r?\n)([\s\S]*?)(?=HTTP\/\d(?:\.\d)?|$)/g, (match, headers: string, body: string) => {
    if (!body) {
      return match;
    }
    const lowerHeaders = headers.toLowerCase();
    if (/\bcontent-type:\s*(application\/octet-stream|application\/zip|application\/x-|image\/|audio\/|video\/)/i.test(lowerHeaders) || looksBinary(body)) {
      const contentLength = /content-length:\s*(\d+)/i.exec(headers)?.[1];
      const size = contentLength ? `${contentLength} bytes` : `${body.length} decoded chars`;
      return `${headers}[binary body removed: ${size}]`;
    }
    return match;
  });
}

function looksBinary(value: string): boolean {
  if (value.includes("\u0000")) {
    return true;
  }
  const sample = value.slice(0, 4096);
  if (!sample) {
    return false;
  }
  const control = sample.match(/[\u0001-\u0008\u000B\u000C\u000E-\u001F]/g)?.length ?? 0;
  const replacement = sample.match(/\uFFFD/g)?.length ?? 0;
  return control + replacement > Math.max(8, sample.length * 0.02);
}

function renderObservationSignals(input: string): string {
  const httpStatuses = uniqueMatches(input, /^HTTP\/[^\r\n]+/gim, 6);
  const titles = uniqueCaptureMatches(input, /<title\b[^>]*>([\s\S]*?)<\/title>/gi, 6).map(cleanHtmlText);
  const links = uniqueCaptureMatches(input, /\bhref\s*=\s*["']([^"']+)["']/gi, 30);
  const scripts = uniqueCaptureMatches(input, /\bsrc\s*=\s*["']([^"']+)["']/gi, 20);
  const forms = uniqueCaptureMatches(input, /\baction\s*=\s*["']([^"']+)["']/gi, 20);
  const headings = uniqueCaptureMatches(input, /<h[1-3]\b[^>]*>([\s\S]*?)<\/h[1-3]>/gi, 8).map(cleanHtmlText);

  const lines = [
    httpStatuses.length > 0 ? `HTTP: ${httpStatuses.join(" | ")}` : "",
    titles.length > 0 ? `Titles: ${titles.join(" | ")}` : "",
    headings.length > 0 ? `Headings: ${headings.join(" | ")}` : "",
    links.length > 0 ? `Links: ${links.join(" | ")}` : "",
    scripts.length > 0 ? `Scripts: ${scripts.join(" | ")}` : "",
    forms.length > 0 ? `Forms: ${forms.join(" | ")}` : ""
  ].filter(Boolean);
  return lines.length > 0 ? `Extracted signals:\n${lines.join("\n")}` : "";
}

function uniqueMatches(input: string, pattern: RegExp, limit: number): string[] {
  const out: string[] = [];
  for (const match of input.matchAll(pattern)) {
    const value = match[0]?.trim();
    if (value && !out.includes(value)) {
      out.push(value);
    }
    if (out.length >= limit) break;
  }
  return out;
}

function uniqueCaptureMatches(input: string, pattern: RegExp, limit: number): string[] {
  const out: string[] = [];
  for (const match of input.matchAll(pattern)) {
    const value = match[1]?.trim();
    if (value && !out.includes(value)) {
      out.push(value);
    }
    if (out.length >= limit) break;
  }
  return out;
}

function cleanHtmlText(input: string): string {
  return input
    .replace(/<[^>]+>/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 180);
}
