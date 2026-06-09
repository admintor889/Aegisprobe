import { existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { createHash } from "node:crypto";
import { dirname, join as joinPath, resolve } from "node:path";
import { CodexLikeContextManager, renderContextSnapshot, type ContextSnapshot } from "@aegisprobe/context";
import { OpenAICompatibleProvider, type DictPaths } from "@aegisprobe/provider";
import { McpManager } from "@aegisprobe/mcp";
import { EmptySkillRegistry, type SkillRegistry } from "@aegisprobe/skills";
import { buildAdaptiveSecurityActions, buildBusinessLogicKnowledgeBase, buildBusinessLogicTestPlan, buildOwaspValidationMatrix, buildPentestPipeline, buildPipelinePreflight, buildSecurityAssetGraph, buildSecurityClosureModel, buildSecurityDecisionQueue, buildSecurityDecisionSupervision, buildSecurityObjectiveModel, buildSecurityToolCommandForInputFile, buildSecurityValidationChecks, buildSecurityWorkflowPlan, buildSubAgentCoordinationPlan, classifySecurityToolOutput, createDefaultPentestScope, getSecurityToolInventory, loadFrameworkKnowledgeIndex, normalizeSecurityToolOutput, type BusinessLogicTestPlan, type NormalizedSecurityObservation, type PentestPipeline, type PentestScope, type PipelinePreflightReport, type SecurityAssetGraph, type SecurityClosureModel, type SecurityDecisionQueue, type SecurityDecisionQueueItem, type SecurityObjectiveModel, type SecurityToolInventoryItem, type SubAgentCoordinationPlan } from "@aegisprobe/security";
import { createPenetrationGraph, createGraphSnapshot, buildGraphContextPrompt, addEvidence, proposeHypothesis, concludeHypothesis, addOverride, getOpenHypotheses, getUnclaimedHypothesis, getRecentEvidence, type PenetrationGraph, type EvidenceKind, type HypothesisCategory, type OverrideKind } from "@aegisprobe/security";
import { planGraphDispatch, buildStigmergyDecisionContext } from "./subagent-stigmergy.js";
import { resolveV2Role, renderV2Prompt, v2RoleKeys } from "./subagent-roles-v2.js";
import {
  extractJsonObject as extractJsonObjectFromTools,
  parseAgentDecision,
  renderToolManifest as renderToolManifestFromTools,
  type AgentToolName
} from "@aegisprobe/tools";
import {
  extractFilePathMentions,
  newId,
  nowIso,
  parseTargetInput,
  truncateForContext,
  validateWritablePath,
  type AgentAction,
  type AgentDecision,
  type FileChangeRecord,
  type FileEditOperation,
  type AgentPlan,
  type ContextFile,
  type IntentExtraction,
  type ShellCommandRecord,
  type ExpectedAuthorizationPolicy,
  type SecurityAuthContext,
  type SecurityCveMatch,
  type SecurityEvidence,
  type SecurityFinding,
  type BrowserExplorationResult,
  type BrowserFormCandidate,
  type WebAppReconResult,
  type SecurityToolRun,
  type SecurityToolRunStatus,
  type SecurityValidationAttempt,
  type SecurityValidationCheck,
  type SecurityWorkflow,
  type SecurityWorkflowTask,
  type SubAgentRecord,
  type SubAgentRole,
  type TaskTreeNode,
  type TargetInput,
  type TurnEvent,
  type TurnEventKind,
  type TurnResult
} from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { buildSubAgentDigest, renderTaskTreeContext as renderTaskTreeContextFromHelpers, sanitizePathSegment, validationPriorityRank } from "./core-helpers.js";
import { buildContext as buildContextFromModule, buildContextSnapshot as buildContextSnapshotFromModule, compactConversationIfNeeded as compactConversationIfNeededFromModule, buildFileContexts as buildFileContextsFromModule, createPlan as createPlanFromModule, refreshSessionMemory as refreshSessionMemoryFromModule, renderRecentHistory as renderRecentHistoryFromModule, renderSkillContext as renderSkillContextFromModule, repairDecisionJson as repairDecisionJsonFromModule, sampleDecision as sampleDecisionFromModule, answerConversation as answerConversationFromModule } from "./conversation-orchestration.js"
import { parseDecisionLegacy as parseDecisionLegacyFromModule } from "./decision-parser.js";
import { summarizeContextsLocally as summarizeContextsLocallyFromUtils } from "./fallback-utils.js";
import { extractLocalConstraints as extractLocalConstraintsFromUtils, fallbackIntent as fallbackIntentFromUtils, isSecurityAssessmentIntent as isSecurityAssessmentIntentFromUtils, normalizeIntent as normalizeIntentFromUtils, parseIntentExtraction, sanitizeFilePaths as sanitizeFilePathsFromUtils, sanitizeTargets as sanitizeTargetsFromUtils } from "./intent-utils.js";
import { prepareApplyPatch, prepareFileEdit } from "./patch-utils.js";
import { executePentestPipeline as executePentestPipelineFromModule, resumePentestPipeline as resumePentestPipelineFromModule, type PauseState } from "./pentest-runtime.js";
import { buildExpertWorkbenchContext } from "./expert-workbench-context.js";
import { requestPentestDecision } from "./pentest-decision.js";
import { renderPromptPackTemplate } from "./prompt-pack.js";
import { executeDecisionToolItem as executeDecisionToolItemFromModule, executeSecurityClosureStep as executeSecurityClosureStepFromModule, executeSecurityDecisionItem as executeSecurityDecisionItemFromModule, runAdaptiveSecurityLoop as runAdaptiveSecurityLoopFromModule } from "./security-execution.js";
import { addSecurityAuthContext as addSecurityAuthContextFromModule, buildAuthorizationBoundaryMatrix as buildAuthorizationBoundaryMatrixFromModule, buildAuthorizationValidationPlan as buildAuthorizationValidationPlanFromModule, buildBusinessLogicTestPlan as buildBusinessLogicTestPlanFromModule, evaluateComparisonAgainstPolicy, executeBusinessLogicRoleComparison as executeBusinessLogicRoleComparisonFromModule, executeBusinessLogicTest as executeBusinessLogicTestFromModule } from "./security-business.js";
import { captureBrowserAuthContext as captureBrowserAuthContextFromModule, exploreBrowserForms as exploreBrowserFormsFromModule, reconWebApplication as reconWebApplicationFromModule } from "./security-browser.js";
import { buildHeaderFindings, recordTechnologyHints as recordTechnologyHintsFromModule } from "./security-observations.js";
import { businessLogicProbeUrls, executeSecurityProbeAction as executeSecurityProbeActionFromModule, safeAnonymousFetchDetails, safeAuthenticatedFetch, safeAuthenticatedFetchDetails, type SafeAuthenticatedFetchDetails, type SecurityProbe } from "./security-probes.js";
import { renderSecurityReportContent as renderSecurityReportContentFromModule } from "./security-report-context.js";
import { buildSecurityReport as buildSecurityAssessmentReport } from "./security-report.js";
import { recordLocalCveMatches as recordLocalCveMatchesFromModule, refreshSecurityCheckStatus as refreshSecurityCheckStatusFromModule, writeWorkflowEvidenceManifest as writeWorkflowEvidenceManifestFromModule } from "./security-state.js";
import { buildDecisionToolCommand as buildDecisionToolCommandFromModule, createSecurityToolRun as createSecurityToolRunFromModule, decisionItemInputs as decisionItemInputsFromModule, describeToolRunStatus as describeToolRunStatusFromModule, extractExitCode as extractExitCodeFromModule, finishSecurityToolRun as finishSecurityToolRunFromModule, inputKindForDecisionTool as inputKindForDecisionToolFromModule, recordNormalizedSecurityObservation as recordNormalizedSecurityObservationFromModule, recordPipelinePreflightToolRuns as recordPipelinePreflightToolRunsFromModule, roleForDecisionItem as roleForDecisionItemFromModule, writeAdaptiveInputFile as writeAdaptiveInputFileFromModule, writeToolOutputArtifact as writeToolOutputArtifactFromModule } from "./security-tooling.js";
import { buildSecurityValidationPlan as buildSecurityValidationPlanFromModule, buildValidationCandidates, executeSecurityValidationAttempt as executeSecurityValidationAttemptFromModule, recordValidationAttempt as recordValidationAttemptFromModule } from "./security-validation.js";
import { executeCommand as executeCommandFromModule, executeShellAction as executeShellActionFromModule, normalizeApproval as normalizeApprovalFromModule, resolveShellApproval as resolveShellApprovalFromModule, runApprovedCommand as runApprovedCommandFromModule } from "./shell-orchestration.js";
import { arbitrateSubAgentResults as arbitrateSubAgentResultsFromModule, dispatchSubAgentQueue as dispatchSubAgentQueueFromModule, enqueueBaselinePentestSubAgents as enqueueBaselinePentestSubAgentsFromModule, enqueueRecommendedSubAgents as enqueueRecommendedSubAgentsFromModule, enqueueSubAgent as enqueueSubAgentFromModule, enrichSubAgentTask as enrichSubAgentTaskFromModule, executeSubAgentAction as executeSubAgentActionFromModule, spawnSubAgent as spawnSubAgentFromModule, type SubAgentSpawnOptions, writeSubAgentDigestFile as writeSubAgentDigestFileFromModule } from "./subagent-orchestration.js";
import { createPipelineTaskTree as createPipelineTaskTreeFromModule, updatePipelineTaskNode as updatePipelineTaskNodeFromModule } from "./task-tree-runtime.js";
import { createToolHandlers as createToolHandlersFromModule, type AgentToolHandler } from "./tool-handlers.js";
import { executeDecisionTools as executeDecisionToolsFromModule } from "./tool-dispatch.js";
import { buildSecurityWorkflowContext as buildSecurityWorkflowContextFromModule } from "./security-workflow.js";
import { SubAgentRuntime, type SubAgentEmitter } from "./subagent-runtime.js";
import { runInput as runInputFromModule, runTurn as runTurnFromModule, understandUserInput as understandUserInputFromModule } from "./turn-orchestration.js";
import { executeListFilesAction as executeListFilesActionFromModule, executeReadFileAction as executeReadFileActionFromModule } from "./workspace-actions.js";
import { importApiDescriptionDocument as importApiDescriptionDocumentFromModule, type ApiDescriptionImportResult } from "./api-description-import.js";
import { buildWebPentestControlPlane as buildWebPentestControlPlaneFromModule, buildWebPentestOperatingPicture as buildWebPentestOperatingPictureFromModule } from "./web-pentest-control-plane.js";

export type ApprovalDecision = boolean | {
  approved: boolean;
  remember?: boolean;
};

export type ApprovalPrompt = (subject: string, detail: string) => Promise<ApprovalDecision>;

export type MainAgentOptions = {
  provider: OpenAICompatibleProvider;
  store: AuditStore;
  approve: ApprovalPrompt;
  skillRegistry?: SkillRegistry;
  dictPaths?: DictPaths;
  mcpManager?: McpManager;
  onEvent?: (event: TurnEvent) => void;
  projectRoot?: string;
  expectedAuthorizationPolicy?: ExpectedAuthorizationPolicy;
};

type NormalizedApproval = {
  approved: boolean;
  remembered: boolean;
};

export class MainAgent {
  private readonly contextManager = new CodexLikeContextManager();
  private readonly subAgentRuntime: SubAgentRuntime;
  private readonly toolHandlers: Record<AgentToolName, AgentToolHandler>;
  private readonly skillRegistry: SkillRegistry;
  private readonly graphCache = new Map<string, PenetrationGraph>();

  constructor(private readonly options: MainAgentOptions) {
    this.skillRegistry = options.skillRegistry ?? new EmptySkillRegistry();
    this.subAgentRuntime = new SubAgentRuntime({
      store: this.options.store,
      provider: this.options.provider,
      mcpManager: this.options.mcpManager,
      renderDictContext: () => this.renderDictContext(),
      renderSkillContext: async (query) => await this.renderSkillContext(query),
      buildFileContexts: async (filePaths) => await this.buildFileContexts(filePaths),
      summarizeContextsLocally: (contexts, heading) => this.summarizeContextsLocally(contexts, heading),
      executors: {
        readFile: async (sessionId, path, purpose) => await this.executeReadFileAction(sessionId, () => undefined, path, purpose),
        listFiles: async (sessionId, path, purpose, recursive) => await this.executeListFilesAction(sessionId, () => undefined, path, purpose, recursive),
        shell: async (sessionId, emit, command, purpose) => await this.executeShellAction(sessionId, emit as (kind: TurnEventKind, message: string, payload?: unknown) => void, command, purpose),
        securityProbe: async (sessionId, emit, target, probe, purpose) => await this.executeSecurityProbeAction(sessionId, emit as (kind: TurnEventKind, message: string, payload?: unknown) => void, target, probe, purpose),
        applyPatch: async (sessionId, emit, patch, purpose) => await this.executeApplyPatchAction(sessionId, emit as (kind: TurnEventKind, message: string, payload?: unknown) => void, patch, purpose)
      }
    });
    this.toolHandlers = createToolHandlersFromModule({
      mcpManager: this.options.mcpManager,
      executeSubAgentAction: async (sessionId, emit, role, description, task, contextPaths, background) =>
        await this.executeSubAgentAction(sessionId, emit, role, description, task, contextPaths, background),
      executeReadFileAction: async (sessionId, emit, path, purpose) =>
        await this.executeReadFileAction(sessionId, emit as (kind: TurnEventKind, message: string, payload?: unknown) => void, path, purpose),
      executeListFilesAction: async (sessionId, emit, path, purpose, recursive) =>
        await this.executeListFilesAction(sessionId, emit as (kind: TurnEventKind, message: string, payload?: unknown) => void, path, purpose, recursive),
      executeFileEditAction: async (sessionId, emit, action) =>
        await this.executeFileEditAction(sessionId, emit as (kind: TurnEventKind, message: string, payload?: unknown) => void, action),
      executeApplyPatchAction: async (sessionId, emit, patch, purpose) =>
        await this.executeApplyPatchAction(sessionId, emit as (kind: TurnEventKind, message: string, payload?: unknown) => void, patch, purpose),
      executeShellAction: async (sessionId, emit, command, purpose) =>
        await this.executeShellAction(sessionId, emit as (kind: TurnEventKind, message: string, payload?: unknown) => void, command, purpose),
      executeSecurityProbeAction: async (sessionId, emit, target, probe, purpose) =>
        await this.executeSecurityProbeAction(sessionId, emit as (kind: TurnEventKind, message: string, payload?: unknown) => void, target, probe, purpose)
    });
  }

  private projectRoot(): string {
    return this.options.projectRoot ?? process.cwd();
  }

  private emitLifecycleEvent(
    sessionId: string,
    turnId: string,
    kind: TurnEventKind,
    message: string,
    payload?: unknown
  ): void {
    const event: TurnEvent = {
      id: newId("evt"),
      sessionId,
      turnId,
      kind,
      message,
      payload,
      createdAt: nowIso()
    };
    this.options.store.addTurnEvent(event);
    this.options.onEvent?.(event);
  }

  createSession(title: string, mode = "safe"): string {
    return this.options.store.createSession(title, mode);
  }

  hasSession(sessionId: string): boolean {
    return this.options.store.hasSession(sessionId);
  }

  async understandUserInput(input: string, sessionId?: string): Promise<IntentExtraction> {
    return await understandUserInputFromModule({
      provider: this.options.provider,
      hasSession: (currentSessionId) => this.hasSession(currentSessionId),
      buildContextSnapshot: (currentSessionId, overrides) => this.buildContextSnapshot(currentSessionId, overrides),
      parseIntent: (currentInput, text) => this.parseIntent(currentInput, text),
      resolveIntentReferences: (intent, currentSessionId) => this.resolveIntentReferences(intent, currentSessionId),
      fallbackIntent: (currentInput) => this.fallbackIntent(currentInput)
    }, input, sessionId);
  }

  async runInput(sessionId: string, input: string): Promise<AgentPlan> {
    return await runInputFromModule({
      store: this.options.store,
      buildContext: async (target) => await this.buildContext(target),
      createPlan: async (currentSessionId, currentInput, target, contexts) =>
        await this.createPlan(currentSessionId, currentInput, target, contexts),
      refreshSessionMemory: (currentSessionId) => this.refreshSessionMemory(currentSessionId)
    }, sessionId, input);
  }

  async runTurn(sessionId: string, input: string, maxIterations = 999): Promise<TurnResult> {
    return await runTurnFromModule({
      provider: this.options.provider,
      store: this.options.store,
      onEvent: this.options.onEvent,
      hasSession: (currentSessionId) => this.hasSession(currentSessionId),
      understandUserInput: async (currentInput, currentSessionId) => await this.understandUserInput(currentInput, currentSessionId),
      buildContextSnapshot: (currentSessionId, overrides) => this.buildContextSnapshot(currentSessionId, overrides),
      parseIntent: (currentInput, text) => this.parseIntent(currentInput, text),
      resolveIntentReferences: (intent, currentSessionId) => this.resolveIntentReferences(intent, currentSessionId),
      fallbackIntent: (currentInput) => this.fallbackIntent(currentInput),
      buildContext: async (target) => await this.buildContext(target),
      buildFileContexts: async (filePaths) => await this.buildFileContexts(filePaths),
      createPlan: async (currentSessionId, currentInput, target, contexts) =>
        await this.createPlan(currentSessionId, currentInput, target, contexts),
      renderSkillContext: async (query) => await this.renderSkillContext(query),
      buildSecurityWorkflowContext: async (currentSessionId, intent, target, emit) =>
        await this.buildSecurityWorkflowContext(currentSessionId, intent, target, emit),
      answerConversation: async (currentSessionId, currentInput, contextSnapshot) =>
        await this.answerConversation(currentSessionId, currentInput, contextSnapshot),
      refreshSessionMemory: (currentSessionId) => this.refreshSessionMemory(currentSessionId),
      sampleDecision: async (currentSessionId, currentInput, target, contexts, observations, iteration, emit, skillContext, securityWorkflowContext, contextSnapshot) =>
        await this.sampleDecision(currentSessionId, currentInput, target, contexts, observations, iteration, emit, skillContext, securityWorkflowContext, contextSnapshot),
      executeDecisionTools: async (currentSessionId, emit, actions, defaultContextPaths) =>
        await this.executeDecisionTools(currentSessionId, emit, actions, defaultContextPaths)
    }, sessionId, input, maxIterations);
  }

  async executeSuggestedCommands(sessionId: string, commands: string[]): Promise<void> {
    for (const command of commands) {
      await this.executeCommand(sessionId, command);
    }
  }

  async executeSecurityProbe(
    sessionId: string,
    target: string,
    probe: "basic_recon" | "dns" | "http_headers" = "basic_recon"
  ): Promise<string> {
    return await this.executeSecurityProbeAction(sessionId, () => undefined, target, probe, "User requested a controlled security information-gathering probe.");
  }

  private pentestRuntimeDeps() {
    return {
      store: this.options.store,
      skillRegistry: this.skillRegistry,
      hasSession: (currentSessionId: string) => this.hasSession(currentSessionId),
      projectRoot: () => this.projectRoot(),
      emitLifecycleEvent: (currentSessionId: string, turnId: string, kind: TurnEventKind, message: string, payload?: unknown) =>
        this.emitLifecycleEvent(currentSessionId, turnId, kind, message, payload),
      buildContextSnapshot: (currentSessionId: string, overrides?: {
        currentInput?: string;
        currentTarget?: TargetInput;
        fileContexts?: [];
        turnObservations?: string[];
        skillContext?: string;
        securityWorkflowContext?: string;
      }) => this.buildContextSnapshot(currentSessionId, overrides),
      samplePentestDecision: async (
        currentSessionId: string,
        target: TargetInput,
        scope: PentestScope,
        preflight: PipelinePreflightReport,
        observations: string[],
        iteration: number,
        emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
        contextSnapshot: ContextSnapshot
      ) => await this.samplePentestDecision(currentSessionId, target, scope, preflight, observations, iteration, emit, contextSnapshot),
      executeDecisionTools: async (currentSessionId: string, emit: SubAgentEmitter, actions: AgentAction[], defaultContextPaths: string[]) =>
        await this.executeDecisionTools(currentSessionId, emit, actions, defaultContextPaths),
      buildSubAgentDigest: (currentSessionId: string) => this.buildSubAgentDigest(currentSessionId),
      initGraph: (currentSessionId: string, target: { kind: "url" | "hostname" | "ip"; value: string }) => {
        this.getOrInitGraph(currentSessionId, target);
      },
      getGraph: (currentSessionId: string) => this.getGraph(currentSessionId),
      renderGraphSummary: (currentSessionId: string) => this.renderGraphSummary(currentSessionId),
      addGraphEvidence: (
        currentSessionId: string,
        params: Parameters<MainAgent["addGraphEvidence"]>[1]
      ) => this.addGraphEvidence(currentSessionId, params),
      addGraphHypothesis: (
        currentSessionId: string,
        params: Parameters<MainAgent["addGraphHypothesis"]>[1]
      ) => this.addGraphHypothesis(currentSessionId, params),
      concludeGraphHypothesis: (currentSessionId: string, hypothesisId: string, evidenceId: string) =>
        this.concludeGraphHypothesis(currentSessionId, hypothesisId, evidenceId),
      dispatchSubAgentQueue: async (currentSessionId: string, options: { maxJobs?: number; concurrency?: number; recoverStaleAfterMs?: number }) =>
        await this.dispatchSubAgentQueue(currentSessionId, options),
      executeSecurityProbeAction: async (
        currentSessionId: string,
        emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
        target: string,
        probe: "basic_recon" | "dns" | "http_headers",
        purpose: string
      ) => await this.executeSecurityProbeAction(currentSessionId, emit, target, probe, purpose),
      recordTechnologyHints: (currentSessionId: string, workflowId: string, target: string, text: string, source: string) =>
        this.recordTechnologyHints(currentSessionId, workflowId, target, text, source),
      recordHeaderFindings: (currentSessionId: string, workflowId: string, target: string, summary: string) =>
        this.recordHeaderFindings(currentSessionId, workflowId, target, summary),
      buildSecurityDecisionQueueForScope: (currentSessionId: string, target: TargetInput | undefined, scope: PentestScope | undefined) =>
        this.buildSecurityDecisionQueueForScope(currentSessionId, target, scope),
      recordLocalCveMatches: (currentSessionId: string, workflowId: string) =>
        this.recordLocalCveMatches(currentSessionId, workflowId),
      refreshSecurityCheckStatus: (currentSessionId: string, workflowId: string, activeValidationBlocked: boolean) =>
        this.refreshSecurityCheckStatus(currentSessionId, workflowId, activeValidationBlocked)
    };
  }

  async resumePentestPipeline(
    sessionId: string,
    pauseState?: PauseState
  ): Promise<string> {
    return await resumePentestPipelineFromModule(this.pentestRuntimeDeps(), sessionId, pauseState);
  }

  async executePentestPipeline(
    sessionId: string,
    targetText: string,
    options: Partial<PentestScope> = {},
    pauseState?: PauseState
  ): Promise<string> {
    return await executePentestPipelineFromModule(this.pentestRuntimeDeps(), sessionId, targetText, options, pauseState);
  }

  listSubAgents(sessionId: string): SubAgentRecord[] {
    return this.options.store.listSubAgents(sessionId);
  }

  getSubAgent(agentId: string): SubAgentRecord | undefined {
    return this.options.store.getSubAgent(agentId);
  }

  closeSubAgent(sessionId: string, agentId: string): boolean {
    this.subAgentRuntime.abort(agentId);
    return this.options.store.closeSubAgent(sessionId, agentId);
  }

  async waitSubAgent(sessionId: string, agentId: string, timeoutMs = 60_000): Promise<SubAgentRecord | undefined> {
    return await this.subAgentRuntime.wait(sessionId, agentId, timeoutMs);
  }

  listFileChanges(sessionId: string): FileChangeRecord[] {
    return this.options.store.listFileChanges(sessionId);
  }

  listSecurityWorkflows(sessionId: string): SecurityWorkflow[] {
    return this.options.store.listSecurityWorkflows(sessionId);
  }

  listSecurityTasks(sessionId: string, workflowId?: string): SecurityWorkflowTask[] {
    return this.options.store.listSecurityTasks(sessionId, workflowId);
  }

  listSecurityToolRuns(sessionId: string, workflowId?: string): SecurityToolRun[] {
    return this.options.store.listSecurityToolRuns(sessionId, workflowId);
  }

  buildSecurityAssetGraph(sessionId: string): SecurityAssetGraph {
    const latestWorkflow = this.options.store.listSecurityWorkflows(sessionId).at(-1);
    return buildSecurityAssetGraph({
      target: latestWorkflow?.target,
      assets: this.options.store.listAssets(sessionId),
      technologies: this.options.store.listTechnologies(sessionId),
      cveMatches: this.options.store.listCveMatches(sessionId),
      findings: this.options.store.listFindings(sessionId),
      evidence: this.options.store.listEvidence(sessionId),
      toolRuns: this.options.store.listSecurityToolRuns(sessionId),
      checks: this.options.store.listSecurityChecks(sessionId)
    });
  }

  buildSecurityDecisionQueue(sessionId: string, scopeOverrides: Partial<PentestScope> = {}): SecurityDecisionQueue {
    const { target, scope } = this.latestSecurityWorkflowContext(sessionId, scopeOverrides);
    return this.buildSecurityDecisionQueueForScope(
      sessionId,
      target,
      scope ?? (target ? createDefaultPentestScope(target, scopeOverrides) : undefined)
    );
  }

  buildSecurityObjectiveModel(sessionId: string, scopeOverrides: Partial<PentestScope> = {}): SecurityObjectiveModel {
    const { target, scope } = this.latestSecurityWorkflowContext(sessionId, scopeOverrides);
    const graph = this.buildSecurityAssetGraph(sessionId);
    const queue = this.buildSecurityDecisionQueueForScope(
      sessionId,
      target,
      scope ?? (target ? createDefaultPentestScope(target, scopeOverrides) : undefined)
    );
    return buildSecurityObjectiveModel({
      target,
      graph,
      queue,
      toolRuns: this.options.store.listSecurityToolRuns(sessionId),
      checks: this.options.store.listSecurityChecks(sessionId),
      authContexts: this.options.store.listSecurityAuthContexts(sessionId),
      scope
    });
  }

  buildSecurityClosureModel(sessionId: string, scopeOverrides: Partial<PentestScope> = {}): SecurityClosureModel {
    const { workflow, target, scope } = this.latestSecurityWorkflowContext(sessionId, scopeOverrides);
    const effectiveScope = scope ?? (target ? createDefaultPentestScope(target, scopeOverrides) : undefined);
    const graph = this.buildSecurityAssetGraph(sessionId);
    const queue = this.buildSecurityDecisionQueueForScope(sessionId, target, effectiveScope);
    return buildSecurityClosureModel({
      target,
      graph,
      queue,
      toolRuns: this.options.store.listSecurityToolRuns(sessionId),
      checks: this.options.store.listSecurityChecks(sessionId, workflow?.id),
      findings: this.options.store.listFindings(sessionId),
      cveMatches: this.options.store.listCveMatches(sessionId),
      evidence: this.options.store.listEvidence(sessionId),
      technologies: this.options.store.listTechnologies(sessionId),
      attempts: this.options.store.listSecurityValidationAttempts(sessionId, workflow?.id),
      authContexts: this.options.store.listSecurityAuthContexts(sessionId, workflow?.id),
      subagents: this.options.store.listSubAgents(sessionId),
      scope: effectiveScope
    });
  }

  buildSubAgentCoordinationPlan(sessionId: string, scopeOverrides: Partial<PentestScope> = {}): SubAgentCoordinationPlan {
    const { target, scope } = this.latestSecurityWorkflowContext(sessionId, scopeOverrides);
    const graph = this.buildSecurityAssetGraph(sessionId);
    const queue = this.buildSecurityDecisionQueueForScope(
      sessionId,
      target,
      scope ?? (target ? createDefaultPentestScope(target, scopeOverrides) : undefined)
    );
    return buildSubAgentCoordinationPlan({
      target,
      graph,
      queue,
      toolRuns: this.options.store.listSecurityToolRuns(sessionId),
      authContexts: this.options.store.listSecurityAuthContexts(sessionId),
      subagents: this.options.store.listSubAgents(sessionId)
    });
  }

  async executeSecurityDecisionQueueItem(
    sessionId: string,
    itemIdOrNext: string | undefined = "next",
    scopeOverrides: Partial<PentestScope> = {}
  ): Promise<string> {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    const { workflow, target, scope } = this.latestSecurityWorkflowContext(sessionId, scopeOverrides);
    if (!workflow || !target || !scope) {
      throw new Error(`No security workflow found for session: ${sessionId}`);
    }

    const queue = this.buildSecurityDecisionQueue(sessionId, scopeOverrides);
    const requested = itemIdOrNext && itemIdOrNext !== "next"
      ? queue.items.find((item) => item.id === itemIdOrNext)
      : queue.items.find((item) => !item.blockedBy) ?? queue.items[0];
    if (!requested) {
      return "No executable security decision queue items remain.";
    }

    const result = await this.executeSecurityDecisionItem(sessionId, workflow.id, target, scope, requested);
    this.recordLocalCveMatches(sessionId, workflow.id);
    this.refreshSecurityCheckStatus(sessionId, workflow.id, !scope.allowActiveProbing);
    const updatedQueue = this.buildSecurityDecisionQueue(sessionId, scopeOverrides);
    this.options.store.addEvidence({
      id: newId("evd"),
      sessionId,
      workflowId: workflow.id,
      source: "decision:queue-run",
      kind: "note",
      summary: `Executed queue item ${requested.id}. Remaining items: ${updatedQueue.items.length}.`,
      data: JSON.stringify({ executed: requested, result, remaining: updatedQueue }, null, 2),
      createdAt: nowIso()
    });
    return [
      `Decision item executed: ${requested.id}`,
      result,
      `Remaining decision items: ${updatedQueue.items.length}`,
      updatedQueue.items[0] ? `Next: [${updatedQueue.items[0].priority}] ${updatedQueue.items[0].title}` : "Next: none"
    ].join("\n");
  }

  async runSecurityDecisionLoop(
    sessionId: string,
    options: Partial<PentestScope> & { maxIterations?: number } = {}
  ): Promise<string> {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    const maxIterations = Math.max(1, options.maxIterations ?? 50);
    const executed = new Set<string>();
    const lines = [`Security decision loop started. maxIterations=${maxIterations}`];
    for (let index = 0; index < maxIterations; index += 1) {
      const queue = this.buildSecurityDecisionQueue(sessionId, options);
      const graph = this.buildSecurityAssetGraph(sessionId);
      const supervision = buildSecurityDecisionSupervision({
        queue,
        graph,
        toolRuns: this.options.store.listSecurityToolRuns(sessionId),
        checks: this.options.store.listSecurityChecks(sessionId)
      });
      if (supervision.level !== "continue") {
        lines.push(`[${index + 1}] supervisor:${supervision.level}: ${supervision.summary}`);
        lines.push(`supervisor next: ${supervision.recommendedActions[0] ?? "review required"}`);
        this.options.store.addEvidence({
          id: newId("evd"),
          sessionId,
          workflowId: this.options.store.listSecurityWorkflows(sessionId).at(-1)?.id,
          source: "decision:supervisor",
          kind: "note",
          summary: `${supervision.level}: ${supervision.summary}`,
          data: JSON.stringify(supervision, null, 2),
          createdAt: nowIso()
        });
        if (supervision.level === "ask_user" || supervision.level === "stop") {
          break;
        }
      }
      const closure = this.buildSecurityClosureModel(sessionId, options);
      this.options.store.addEvidence({
        id: newId("evd"),
        sessionId,
        workflowId: this.options.store.listSecurityWorkflows(sessionId).at(-1)?.id,
        source: "decision:closure-model",
        kind: "note",
        summary: closure.summary,
        data: JSON.stringify(closure, null, 2),
        createdAt: nowIso()
      });
      const closureStep = await this.executeSecurityClosureStep(sessionId, closure);
      if (closureStep) {
        lines.push(`[${index + 1}] closure: ${closureStep.split(/\r?\n/)[0]}`);
        continue;
      }
      const suppressed = new Set(supervision.suppressItemIds);
      const next = queue.items.find((item) => !item.blockedBy && !executed.has(item.id) && !suppressed.has(item.id));
      if (!next) {
        const validationCandidates = buildValidationCandidates(this.options.store, sessionId);
        if (validationCandidates.length > 0) {
          const validation = this.executeSecurityValidationAttempt(sessionId, "next");
          lines.push(`[${index + 1}] validation: ${validation.split(/\r?\n/)[0]}`);
          continue;
        }
        lines.push(`[${index + 1}] no executable queue or validation item remains.`);
        break;
      }
      executed.add(next.id);
      const result = await this.executeSecurityDecisionQueueItem(sessionId, next.id, options);
      lines.push(`[${index + 1}] ${next.id}: ${next.title}`);
      lines.push(truncateForContext(result, 10_000));
    }
    this.reconcileFindingStates(sessionId);
    const remaining = this.buildSecurityDecisionQueue(sessionId, options).items.length;
    lines.push(`Decision loop finished. Remaining queue items: ${remaining}. Findings: ${this.options.store.listFindings(sessionId).length}.`);
    this.options.store.addEvidence({
      id: newId("evd"),
      sessionId,
      workflowId: this.options.store.listSecurityWorkflows(sessionId).at(-1)?.id,
      source: "decision:closed-loop",
      kind: "note",
      summary: truncateForContext(lines.join("\n"), 20_000),
      data: lines.join("\n"),
      createdAt: nowIso()
    });
    return lines.join("\n");
  }

  private buildSecurityDecisionQueueForScope(
    sessionId: string,
    target: TargetInput | undefined,
    scope: PentestScope | undefined
  ): SecurityDecisionQueue {
    const graph = this.buildSecurityAssetGraph(sessionId);
    return buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: this.options.store.listSecurityToolRuns(sessionId),
      checks: this.options.store.listSecurityChecks(sessionId),
      authContexts: this.options.store.listSecurityAuthContexts(sessionId),
      inventory: getSecurityToolInventory(this.projectRoot()),
      scope
    });
  }

  private async executeSecurityClosureStep(sessionId: string, closure: SecurityClosureModel): Promise<string | undefined> {
    return await executeSecurityClosureStepFromModule({
      store: this.options.store,
      executeSecurityValidationAttempt: (currentSessionId, targetIdOrNext) => this.executeSecurityValidationAttempt(currentSessionId, targetIdOrNext),
      executeBusinessLogicRoleComparison: async (currentSessionId, caseIdOrNext, leftAuthName, rightAuthName) =>
        await this.executeBusinessLogicRoleComparison(currentSessionId, caseIdOrNext, leftAuthName, rightAuthName),
      executeBusinessLogicTest: async (currentSessionId, caseIdOrNext, authContextName) =>
        await this.executeBusinessLogicTest(currentSessionId, caseIdOrNext, authContextName)
    }, sessionId, closure);
  }

  private latestSecurityWorkflowContext(
    sessionId: string,
    scopeOverrides: Partial<PentestScope> = {}
  ): { workflow?: SecurityWorkflow; target?: TargetInput; scope?: PentestScope } {
    const workflow = this.options.store.listSecurityWorkflows(sessionId).at(-1);
    const target = workflow?.target;
    if (!target) {
      return { workflow, target };
    }
    const storedScope = this.readStoredPentestScope(sessionId, workflow.id, target);
    return {
      workflow,
      target,
      scope: {
        ...storedScope,
        ...scopeOverrides,
        allowedTargets: scopeOverrides.allowedTargets ?? storedScope.allowedTargets
      }
    };
  }

  private readStoredPentestScope(sessionId: string, workflowId: string, target: TargetInput): PentestScope {
    const scopeAsset = this.options.store.listAssets(sessionId)
      .filter((asset) => asset.workflowId === workflowId && asset.source === "pentest_pipeline:scope")
      .at(-1);
    if (scopeAsset?.metadata) {
      try {
        return {
          ...createDefaultPentestScope(target),
          ...(JSON.parse(scopeAsset.metadata) as PentestScope)
        };
      } catch {
        return createDefaultPentestScope(target);
      }
    }
    return createDefaultPentestScope(target);
  }

  private async executeSecurityDecisionItem(
    sessionId: string,
    workflowId: string,
    target: TargetInput,
    scope: PentestScope,
    item: SecurityDecisionQueueItem
  ): Promise<string> {
    return await executeSecurityDecisionItemFromModule({
      store: this.options.store,
      executeSecurityProbeAction: async (currentSessionId, currentTarget, probe, purpose) =>
        await this.executeSecurityProbeAction(currentSessionId, () => undefined, currentTarget, probe, purpose),
      recordTechnologyHints: (currentSessionId, currentWorkflowId, currentTarget, text, source) =>
        this.recordTechnologyHints(currentSessionId, currentWorkflowId, currentTarget, text, source),
      recordHeaderFindings: (currentSessionId, currentWorkflowId, currentTarget, summary) =>
        this.recordHeaderFindings(currentSessionId, currentWorkflowId, currentTarget, summary),
      exploreBrowserForms: async (currentSessionId, startUrl, options) =>
        await this.exploreBrowserForms(currentSessionId, startUrl, options),
      reconWebApplication: async (currentSessionId, startUrl, options) =>
        await this.reconWebApplication(currentSessionId, startUrl, options),
      recordLocalCveMatches: (currentSessionId, currentWorkflowId) =>
        this.recordLocalCveMatches(currentSessionId, currentWorkflowId),
      writeWorkflowEvidenceManifest: (currentSessionId, currentWorkflowId, currentTarget) =>
        this.writeWorkflowEvidenceManifest(currentSessionId, currentWorkflowId, currentTarget),
      spawnSubAgent: async (currentSessionId, role, task, contextPaths, options) =>
        await this.spawnSubAgent(currentSessionId, role, task, contextPaths, options),
      readSubAgentOutput: (record) =>
        record.outputPath && existsSync(record.outputPath) ? readFileSync(record.outputPath, "utf8") : record.resultSummary,
      buildSecurityObjectiveModel: (currentSessionId, currentScope) =>
        this.buildSecurityObjectiveModel(currentSessionId, currentScope),
      buildAuthorizationValidationPlan: (currentSessionId) =>
        this.buildAuthorizationValidationPlan(currentSessionId),
      executeBusinessLogicRoleComparison: async (currentSessionId, caseIdOrNext, leftAuthName, rightAuthName) =>
        await this.executeBusinessLogicRoleComparison(currentSessionId, caseIdOrNext, leftAuthName, rightAuthName),
      executeDecisionToolItem: async (currentSessionId, currentWorkflowId, currentTarget, currentScope, currentItem) =>
        await this.executeDecisionToolItem(currentSessionId, currentWorkflowId, currentTarget, currentScope, currentItem)
    }, {
      sessionId,
      workflowId,
      target,
      scope,
      item
    });
  }

  private async executeDecisionToolItem(
    sessionId: string,
    workflowId: string,
    target: TargetInput,
    scope: PentestScope,
    item: SecurityDecisionQueueItem
  ): Promise<string> {
    return await executeDecisionToolItemFromModule({
      store: this.options.store,
      projectRoot: this.projectRoot(),
      executeShellAction: async (currentSessionId, emit, command, purpose) =>
        await this.executeShellAction(currentSessionId, emit, command, purpose),
      buildSecurityDecisionQueue: (currentSessionId, currentScope) => this.buildSecurityDecisionQueue(currentSessionId, currentScope),
      buildSecurityAssetGraph: (currentSessionId) => this.buildSecurityAssetGraph(currentSessionId),
      recordTechnologyHints: (currentSessionId, currentWorkflowId, currentTarget, text, source) =>
        this.recordTechnologyHints(currentSessionId, currentWorkflowId, currentTarget, text, source),
      recordNormalizedSecurityObservation: (currentSessionId, currentWorkflowId, observation) =>
        this.recordNormalizedSecurityObservation(currentSessionId, currentWorkflowId, observation)
    }, {
      sessionId,
      workflowId,
      target,
      scope,
      item
    });
  }

  buildBusinessLogicTestPlan(sessionId: string): BusinessLogicTestPlan {
    return buildBusinessLogicTestPlanFromModule(
      this.options.store,
      sessionId,
      (currentSessionId) => this.buildSecurityAssetGraph(currentSessionId)
    );
  }

  buildAuthorizationBoundaryMatrix(sessionId: string) {
    return buildAuthorizationBoundaryMatrixFromModule(this.options.store, sessionId);
  }

  buildAuthorizationValidationPlan(sessionId: string) {
    return buildAuthorizationValidationPlanFromModule(this.options.store, sessionId);
  }

  buildWebPentestControlPlane(sessionId: string, workflowId?: string) {
    return buildWebPentestControlPlaneFromModule(this.options.store, sessionId, workflowId);
  }

  buildWebPentestOperatingPicture(sessionId: string, workflowId?: string) {
    return buildWebPentestOperatingPictureFromModule(this.options.store, sessionId, workflowId);
  }

  addSecurityAuthContext(
    sessionId: string,
    input: Omit<SecurityAuthContext, "id" | "sessionId" | "workflowId" | "createdAt" | "updatedAt"> & { workflowId?: string }
  ): SecurityAuthContext {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return addSecurityAuthContextFromModule(this.options.store, sessionId, input);
  }

  async captureBrowserAuthContext(
    sessionId: string,
    url: string,
    options: { name: string; role?: string; username?: string; headed?: boolean; waitMs?: number } = { name: "browser" }
  ): Promise<SecurityAuthContext> {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return await captureBrowserAuthContextFromModule(
      this.options.store,
      this.projectRoot(),
      sessionId,
      url,
      options,
      {
        addSecurityAuthContext: (currentSessionId, input) => this.addSecurityAuthContext(currentSessionId, input)
      }
    );
  }

  async exploreBrowserForms(
    sessionId: string,
    authOrUrl?: string,
    options: { maxPages?: number; headed?: boolean } = {}
  ): Promise<BrowserExplorationResult> {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return await exploreBrowserFormsFromModule(
      this.options.store,
      this.projectRoot(),
      sessionId,
      authOrUrl,
      options,
      {
        createSecurityToolRun: (input) => this.createSecurityToolRun(input),
        finishSecurityToolRun: (run, status, update) => this.finishSecurityToolRun(run, status, update),
        enrichFindingForStorage: (finding, evidenceIds) => this.enrichFindingForStorage(finding, evidenceIds)
      }
    );
  }

  async reconWebApplication(
    sessionId: string,
    authOrUrl?: string,
    options: { maxPages?: number; headed?: boolean; analyzeJs?: boolean } = {}
  ): Promise<WebAppReconResult> {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return await reconWebApplicationFromModule(
      this.options.store,
      this.projectRoot(),
      sessionId,
      authOrUrl,
      options,
      {
        createSecurityToolRun: (input) => this.createSecurityToolRun(input),
        finishSecurityToolRun: (run, status, update) => this.finishSecurityToolRun(run, status, update),
        enrichFindingForStorage: (finding, evidenceIds) => this.enrichFindingForStorage(finding, evidenceIds)
      }
    );
  }

  async importApiDescriptionDocument(sessionId: string, source: string): Promise<ApiDescriptionImportResult> {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return await importApiDescriptionDocumentFromModule(
      this.options.store,
      this.projectRoot(),
      sessionId,
      source,
      {
        createSecurityToolRun: (input) => this.createSecurityToolRun(input),
        finishSecurityToolRun: (run, status, update) => this.finishSecurityToolRun(run, status, update)
      }
    );
  }

  listSecurityAuthContexts(sessionId: string): SecurityAuthContext[] {
    return this.options.store.listSecurityAuthContexts(sessionId);
  }

  async executeBusinessLogicTest(
    sessionId: string,
    caseIdOrNext = "next",
    authContextName?: string
  ): Promise<string> {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return await executeBusinessLogicTestFromModule(
      this.options.store,
      sessionId,
      caseIdOrNext,
      authContextName,
      {
        buildBusinessLogicTestPlan: (currentSessionId) => this.buildBusinessLogicTestPlan(currentSessionId)
      }
    );
  }

  async executeBusinessLogicRoleComparison(
    sessionId: string,
    caseIdOrNext = "next",
    leftAuthName?: string,
    rightAuthName?: string
  ): Promise<string> {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return await executeBusinessLogicRoleComparisonFromModule(
      this.options.store,
      sessionId,
      caseIdOrNext,
      leftAuthName,
      rightAuthName,
      {
        buildBusinessLogicTestPlan: (currentSessionId) => this.buildBusinessLogicTestPlan(currentSessionId),
        enrichFindingForStorage: (finding, evidenceIds) => this.enrichFindingForStorage(finding, evidenceIds),
        recordValidationAttempt: (input) => this.recordValidationAttempt(input),
        expectedAuthorizationPolicy: this.options.expectedAuthorizationPolicy
      }
    );
  }

  listSecurityValidationAttempts(sessionId: string): SecurityValidationAttempt[] {
    return this.options.store.listSecurityValidationAttempts(sessionId);
  }

  buildSecurityValidationPlan(sessionId: string): string {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return buildSecurityValidationPlanFromModule(this.options.store, sessionId);
  }

  executeSecurityValidationAttempt(sessionId: string, targetIdOrNext = "next"): string {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return executeSecurityValidationAttemptFromModule(this.options.store, sessionId, targetIdOrNext);
  }

  listFindings(sessionId: string): SecurityFinding[] {
    return this.options.store.listFindings(sessionId);
  }

  listEvidence(sessionId: string): SecurityEvidence[] {
    return this.options.store.listEvidence(sessionId);
  }

  recordReadOnlyFetchEvidence(sessionId: string, result: SafeAuthenticatedFetchDetails, authContextName?: string): void {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    const workflowId = this.options.store.listSecurityWorkflows(sessionId).at(-1)?.id;
    const source = authContextName ? "safe_readonly_fetch" : "anonymous_baseline_fetch";
    const status = result.status > 0 ? `status=${result.status}` : `error=${result.error ?? result.statusText}`;
    const html = result.htmlSurface;
    const htmlSummary = html
      ? ` title=${html.title ?? "(missing)"} forms=${html.forms.length} scripts=${html.scripts.length} links=${html.links.length}`
      : "";
    this.options.store.addEvidence({
      id: newId("evd"),
      sessionId,
      workflowId,
      source,
      kind: "tool",
      summary: `${source} ${result.method} ${result.url} ${status}${htmlSummary}`,
      data: JSON.stringify({
        ...result,
        authContextName
      }, null, 2),
      createdAt: nowIso()
    });
    if (html) {
      const urls = [
        ...html.forms.map((form) => ({ value: form.action, source: `${source}:form` })),
        ...html.scripts.map((value) => ({ value, source: `${source}:script` })),
        ...html.links.map((value) => ({ value, source: `${source}:link` }))
      ];
      const seen = new Set<string>();
      for (const item of urls) {
        if (!/^https?:\/\//i.test(item.value) || seen.has(item.value)) continue;
        seen.add(item.value);
        this.options.store.addAsset({
          id: newId("asset"),
          sessionId,
          workflowId,
          kind: "url",
          value: item.value,
          source: item.source,
          confidence: item.source.endsWith(":form") ? "high" : "medium",
          metadata: item.source.endsWith(":form")
            ? JSON.stringify(html.forms.find((form) => form.action === item.value) ?? {})
            : undefined,
          createdAt: nowIso()
        });
      }
    }
  }

  listAssets(sessionId: string) {
    return this.options.store.listAssets(sessionId);
  }

  listTargets(sessionId: string): TargetInput[] {
    return this.options.store.listTargets(sessionId);
  }

  latestSecurityTarget(sessionId: string): TargetInput | undefined {
    return this.latestSecurityWorkflowContext(sessionId).target;
  }

  listTechnologies(sessionId: string) {
    return this.options.store.listTechnologies(sessionId);
  }

  listCveMatches(sessionId: string) {
    return this.options.store.listCveMatches(sessionId);
  }

  listSecurityChecks(sessionId: string, workflowId?: string): SecurityValidationCheck[] {
    return this.options.store.listSecurityChecks(sessionId, workflowId);
  }

  renderSecurityReport(sessionId: string): string {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    return this.renderSecurityReportContent(sessionId);
  }

  renderExpertSnapshot(sessionId: string, scopeOverrides: Partial<PentestScope> = {}): string {
    if (!this.hasSession(sessionId)) {
      throw new Error(`Session not found: ${sessionId}`);
    }
    const { workflow, target, scope } = this.latestSecurityWorkflowContext(sessionId, scopeOverrides);
    const storedTarget = target ?? this.options.store.listTargets(sessionId).at(-1);
    if (!storedTarget) {
      return "No target recorded for this session. Run pentest first or add target evidence.";
    }
    const effectiveTarget: TargetInput = {
      kind: storedTarget.kind,
      raw: storedTarget.raw,
      normalized: storedTarget.normalized
    };
    const effectiveScope = scope ?? createDefaultPentestScope(effectiveTarget, scopeOverrides);
    const scopedEvidence = this.options.store
      .listEvidence(sessionId)
      .filter((item) => !workflow?.id || !item.workflowId || item.workflowId === workflow.id);
    const recentObservations = scopedEvidence
      .slice(-6)
      .map((item) => `${item.kind} | ${item.source} | ${item.summary}\n${item.data ?? ""}`);
    return buildExpertWorkbenchContext({
      store: this.options.store,
      sessionId,
      workflowId: workflow?.id,
      target: effectiveTarget,
      scope: effectiveScope,
      graph: this.getGraph(sessionId),
      recentObservations
    });
  }

  // ── Attack Graph (Evidence / Hypothesis model) ──

  initGraph(sessionId: string, target: { kind: "url" | "hostname" | "ip"; value: string }): PenetrationGraph {
    const graph = createPenetrationGraph({ sessionId, target });
    this.graphCache.set(sessionId, graph);
    this.persistGraphSnapshot(sessionId);
    return graph;
  }

  getGraph(sessionId: string): PenetrationGraph | undefined {
    return this.graphCache.get(sessionId) ?? this.loadGraphSnapshot(sessionId);
  }

  getOrInitGraph(sessionId: string, target?: { kind: "url" | "hostname" | "ip"; value: string }): PenetrationGraph {
    const existing = this.getGraph(sessionId);
    if (existing) return existing;
    if (!target) throw new Error('No graph for session ' + sessionId + ' and no target provided');
    return this.initGraph(sessionId, target);
  }

  addGraphEvidence(
    sessionId: string,
    params: { kind: EvidenceKind; description: string; source: { kind: string; toolId?: string; command?: string; role?: string; task?: string; reasoning?: string }; confidence?: 'confirmed' | 'high' | 'medium' | 'low'; derivedFrom?: string[]; tags?: string[] }
  ): string {
    const graph = this.getOrInitGraph(sessionId);
    const source: any = { kind: params.source.kind };
    if (params.source.toolId) { source.toolId = params.source.toolId; source.command = params.source.command ?? ''; }
    if (params.source.role) { source.role = params.source.role; source.task = params.source.task ?? ''; }
    if (params.source.reasoning) source.reasoning = params.source.reasoning;
    const { graph: updated, event } = addEvidence(graph, {
      kind: params.kind,
      description: params.description,
      source,
      confidence: params.confidence,
      derivedFrom: params.derivedFrom,
      tags: params.tags,
    });
    this.graphCache.set(sessionId, updated);
    this.persistGraphSnapshot(sessionId);
    return event.kind === 'evidence_added' ? event.node.id : '';
  }

  addGraphHypothesis(
    sessionId: string,
    params: { basedOn: string[]; description: string; category: HypothesisCategory; priority?: 'critical' | 'high' | 'medium' | 'low'; assignedRole?: string | null }
  ): string {
    const graph = this.getOrInitGraph(sessionId);
    const { graph: updated, event } = proposeHypothesis(graph, params);
    this.graphCache.set(sessionId, updated);
    this.persistGraphSnapshot(sessionId);
    return event.kind === 'hypothesis_proposed' ? event.node.id : '';
  }

  concludeGraphHypothesis(sessionId: string, hypothesisId: string, evidenceId: string): void {
    const graph = this.getOrInitGraph(sessionId);
    const { graph: updated } = concludeHypothesis(graph, hypothesisId, evidenceId);
    this.graphCache.set(sessionId, updated);
    this.persistGraphSnapshot(sessionId);
  }

  addGraphOverride(sessionId: string, content: string, kind = 'knowledge', relatesTo?: string): string {
    const graph = this.getOrInitGraph(sessionId);
    const { graph: updated, event } = addOverride(graph, {
      content,
      kind: kind as OverrideKind,
      relatesTo,
    });
    this.graphCache.set(sessionId, updated);
    this.persistGraphSnapshot(sessionId);
    return event.kind === 'override_added' ? 'Override ' + event.node.id + ' added: [' + event.node.kind + '] ' + event.node.content : 'Failed';
  }

  renderGraphState(sessionId: string): string {
    const graph = this.getGraph(sessionId);
    if (!graph) return 'No attack graph for session ' + sessionId + '.';
    const snapshot = createGraphSnapshot(graph);
    return snapshot.yaml;
  }

  renderGraphSummary(sessionId: string): string {
    const graph = this.getGraph(sessionId);
    if (!graph) return 'No attack graph for session ' + sessionId + '.';
    const snapshot = createGraphSnapshot(graph);
    return buildGraphContextPrompt(snapshot);
  }

  private persistGraphSnapshot(sessionId: string): void {
    const graph = this.graphCache.get(sessionId);
    if (!graph) return;
    const workflowId = this.options.store.listSecurityWorkflows(sessionId).at(-1)?.id;
    this.options.store.addEvidence({
      id: newId("evd"),
      sessionId,
      workflowId,
      source: "graph:blackboard",
      kind: "note",
      summary: `Blackboard snapshot v${graph.version}: evidence=${graph.evidence.length}, hypotheses=${graph.hypotheses.length}, overrides=${graph.overrides.length}`,
      data: JSON.stringify(graph),
      createdAt: nowIso()
    });
  }

  private loadGraphSnapshot(sessionId: string): PenetrationGraph | undefined {
    const snapshot = this.options.store.listEvidence(sessionId)
      .filter((item) => item.source === "graph:blackboard" && item.data)
      .at(-1);
    if (!snapshot?.data) return undefined;
    try {
      const parsed = JSON.parse(snapshot.data) as PenetrationGraph;
      if (parsed.sessionId !== sessionId || !parsed.target || !Array.isArray(parsed.evidence) || !Array.isArray(parsed.hypotheses)) {
        return undefined;
      }
      this.graphCache.set(sessionId, parsed);
      return parsed;
    } catch {
      return undefined;
    }
  }

  
    /** Graph-driven dispatch: analyze the graph and return spawn decisions. */
  planGraphDispatch(sessionId: string): string {
    const graph = this.getGraph(sessionId);
    if (!graph) return "No graph initialized. Run pentest first.";
    const decision = planGraphDispatch(graph);
    if (decision.spawn.length === 0) return decision.reason;
    const lines = [decision.reason];
    for (let i = 0; i < decision.spawn.length; i++) {
      const d = decision.spawn[i];
      lines.push((i + 1) + ". [" + d.priority + "] " + d.roleKey + ": " + d.task.slice(0, 120));
    }
    return lines.join("\n");
  }

  /** Build Stigmergy-style decision context for the LLM orchestrator. */
  buildGraphDecisionContext(sessionId: string): string {
    const graph = this.getGraph(sessionId);
    return buildStigmergyDecisionContext(graph);
  }

  /** List v2 simplified roles. */
  listV2Roles(): string {
    return v2RoleKeys().map((key) => {
      const def = resolveV2Role(key as any);
      return key + ": " + def.label + " — " + def.description + " (max " + def.maxIterations + " iterations, tools: " + def.tools.join(", ") + ")";
    }).join("\n");
  }

  getContextSnapshot(sessionId: string): ContextSnapshot {
    return this.buildContextSnapshot(sessionId);
  }

  renderContextSnapshot(sessionId: string): string {
    return renderContextSnapshot(this.getContextSnapshot(sessionId));
  }

  // 鈹€鈹€ Task Tree 鈹€鈹€

  getTaskTree(sessionId: string, workflowId?: string): TaskTreeNode[] {
    return this.options.store.getTaskNodes(sessionId, workflowId);
  }

  getActiveTaskContext(sessionId: string): TaskTreeNode[] {
    return this.options.store.getActiveTaskContext(sessionId);
  }

  renderTaskTreeContext(sessionId: string): string {
    return renderTaskTreeContextFromHelpers(this.getActiveTaskContext(sessionId));
  }

  renderDictContext(): string {
    const d = this.options.dictPaths;
    if (!d) return "";
    const lines = ["Available dictionaries for brute-force:"];
    if (d.password) lines.push(`  Password: ${d.password}`);
    if (d.username) lines.push(`  Username: ${d.username}`);
    if (d.directory) lines.push(`  Directory: ${d.directory}`);
    if (d.subdomain) lines.push(`  Subdomain: ${d.subdomain}`);
    if (d.api) lines.push(`  API: ${d.api}`);
    return lines.length > 1 ? lines.join("\n") : "";
  }

  private createPipelineTaskTree(
    sessionId: string,
    workflowId: string,
    pipeline: PentestPipeline
  ): TaskTreeNode[] {
    return createPipelineTaskTreeFromModule(this.options.store, sessionId, workflowId, pipeline);
  }

  private updatePipelineTaskNode(
    node: TaskTreeNode,
    status: TaskTreeNode["status"],
    summary: string,
    evidenceIds: string[] = [],
    findingIds: string[] = []
  ): void {
    updatePipelineTaskNodeFromModule(this.options.store, node, status, summary, evidenceIds, findingIds);
  }

  async spawnSubAgent(
    sessionId: string,
    role: SubAgentRole,
    task: string,
    contextPaths: string[] = [],
    options: SubAgentSpawnOptions = {}
  ): Promise<SubAgentRecord> {
    return await spawnSubAgentFromModule({
      store: this.options.store,
      runtime: this.subAgentRuntime
    }, sessionId, role, task, contextPaths, options);
  }

  // 鈹€鈹€ Subagent Intercommunication 鈹€鈹€

  buildSubAgentDigest(sessionId: string): string {
    return buildSubAgentDigest(this.options.store.listSubAgents(sessionId));
  }

  writeSubAgentDigestFile(sessionId: string): string {
    return writeSubAgentDigestFileFromModule(this.options.store, sessionId);
  }

  enrichSubAgentTask(sessionId: string, task: string): { task: string; contextPaths: string[] } {
    return enrichSubAgentTaskFromModule(this.options.store, sessionId, task);
  }

  async executeCommand(sessionId: string, command: string): Promise<void> {
    await executeCommandFromModule(this.options.store, this.options.approve, sessionId, command);
  }

  async enqueueSubAgent(
    sessionId: string,
    role: SubAgentRole,
    task: string,
    contextPaths: string[] = [],
    options: Omit<SubAgentSpawnOptions, "queued"> = {}
  ): Promise<SubAgentRecord> {
    return await enqueueSubAgentFromModule({
      store: this.options.store,
      runtime: this.subAgentRuntime
    }, sessionId, role, task, contextPaths, options);
  }

  async dispatchSubAgentQueue(sessionId: string, options: { maxJobs?: number; concurrency?: number; recoverStaleAfterMs?: number } = {}): Promise<string> {
    const summary = await dispatchSubAgentQueueFromModule({
      store: this.options.store,
      runtime: this.subAgentRuntime
    }, sessionId, options);
    if (!summary.startsWith("Subagent dispatcher claimed")) {
      return summary;
    }
    return `${summary}\n${this.arbitrateSubAgentResults(sessionId)}`;
  }

  async enqueueRecommendedSubAgents(sessionId: string, limit = 6): Promise<string> {
    return await enqueueRecommendedSubAgentsFromModule({
      store: this.options.store,
      runtime: this.subAgentRuntime,
      buildSubAgentCoordinationPlan: (currentSessionId) => this.buildSubAgentCoordinationPlan(currentSessionId),
      writeWorkflowEvidenceManifest: (currentSessionId, workflowId, target) => this.writeWorkflowEvidenceManifest(currentSessionId, workflowId, target),
      refreshSessionMemory: (currentSessionId) => this.refreshSessionMemory(currentSessionId)
    }, sessionId, limit);
  }

  private async enqueueBaselinePentestSubAgents(
    sessionId: string,
    workflowId: string,
    target: TargetInput
  ): Promise<SubAgentRecord[]> {
    return await enqueueBaselinePentestSubAgentsFromModule({
      store: this.options.store,
      runtime: this.subAgentRuntime,
      buildSubAgentCoordinationPlan: (currentSessionId) => this.buildSubAgentCoordinationPlan(currentSessionId),
      writeWorkflowEvidenceManifest: (currentSessionId, currentWorkflowId, currentTarget) =>
        this.writeWorkflowEvidenceManifest(currentSessionId, currentWorkflowId, currentTarget),
      refreshSessionMemory: (currentSessionId) => this.refreshSessionMemory(currentSessionId)
    }, sessionId, workflowId, target);
  }

  arbitrateSubAgentResults(sessionId: string): string {
    return arbitrateSubAgentResultsFromModule({
      store: this.options.store,
      refreshSessionMemory: (currentSessionId) => this.refreshSessionMemory(currentSessionId)
    }, sessionId);
  }

  private async executeDecisionTools(
    sessionId: string,
    emit: SubAgentEmitter,
    actions: AgentAction[],
    defaultContextPaths: string[]
  ): Promise<string[]> {
    return await executeDecisionToolsFromModule(this.toolHandlers, sessionId, emit, actions, defaultContextPaths);
  }

  private async executeShellAction(
    sessionId: string,
    emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
    command: string,
    purpose: string
  ): Promise<string> {
    return await executeShellActionFromModule(this.options.store, this.options.approve, sessionId, emit, command, purpose);
  }

  private async executeSecurityProbeAction(
    sessionId: string,
    emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
    target: string,
    probe: SecurityProbe,
    purpose: string
  ): Promise<string> {
    return executeSecurityProbeActionFromModule({
      store: this.options.store,
      approve: this.options.approve,
      normalizeApproval: (decision) => this.normalizeApproval(decision),
      sessionId,
      emit,
      target,
      probe,
      purpose
    });
  }

  private async executeReadFileAction(
    sessionId: string,
    emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
    path: string,
    purpose: string
  ): Promise<string> {
    return executeReadFileActionFromModule(this.options.store, sessionId, emit, path, purpose);
  }

  private async executeListFilesAction(
    sessionId: string,
    emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
    path: string,
    purpose: string,
    recursive: boolean
  ): Promise<string> {
    return executeListFilesActionFromModule(this.options.store, sessionId, emit, path, purpose, recursive);
  }

  private async executeApplyPatchAction(
    sessionId: string,
    emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
    patch: string,
    purpose: string
  ): Promise<string> {
    const createdAt = nowIso();
    const prepared = prepareApplyPatch(patch);
    const record: FileChangeRecord = {
      id: newId("chg"),
      sessionId,
      path: prepared.files.map((file) => file.path).join(", ") || "(invalid patch)",
      operation: "apply_patch",
      status: prepared.allowed ? "pending" : "blocked",
      summary: prepared.summary,
      diff: prepared.diff,
      createdAt,
      updatedAt: createdAt
    };
    this.options.store.addFileChange(record);

    if (!prepared.allowed) {
      this.options.store.addApproval(sessionId, "apply_patch", false, prepared.summary);
      emit("file_change_blocked", "Blocked apply_patch request.", {
        reason: prepared.summary,
        diff: prepared.diff
      });
      return `Blocked apply_patch request. Reason: ${prepared.summary}`;
    }

    emit("file_change_approval_requested", "Approval requested for apply_patch.", {
      purpose,
      files: prepared.files.map((file) => file.path),
      diff: prepared.diff
    });
    const approval = this.normalizeApproval(await this.options.approve(
      "Apply workspace patch",
      [
        `Purpose: ${purpose}`,
        `Files: ${prepared.files.map((file) => file.path).join(", ")}`,
        "Diff preview:",
        prepared.diff
      ].join("\n")
    ));
    this.options.store.addApproval(sessionId, "apply_patch", approval.approved, approval.remembered ? "Patch approved. Remember flag ignored for file edits." : "Patch approval decision.");
    emit("file_change_approval_resolved", approval.approved ? "Patch approved." : "Patch denied.", {
      approved: approval.approved,
      files: prepared.files.map((file) => file.path)
    });

    if (!approval.approved) {
      this.options.store.updateFileChange({ ...record, status: "denied", updatedAt: nowIso() });
      return "User denied apply_patch request.";
    }

    emit("file_change_started", "Applying workspace patch.", { files: prepared.files.map((file) => file.path) });
    try {
      for (const file of prepared.files) {
        if (file.originalPath && file.originalPath !== file.path && existsSync(file.originalPath)) {
          unlinkSync(file.originalPath);
        }
        if (file.after === null) {
          unlinkSync(file.path);
          continue;
        }
        mkdirSync(dirname(file.path), { recursive: true });
        writeFileSync(file.path, file.after, "utf8");
      }
      const applied: FileChangeRecord = {
        ...record,
        status: "applied",
        summary: `Applied patch to ${prepared.files.length} file(s).`,
        updatedAt: nowIso()
      };
      this.options.store.updateFileChange(applied);
      this.options.store.addObservation({
        id: newId("obs"),
        sessionId,
        source: "apply_patch",
        summary: applied.summary ?? "Patch applied.",
        createdAt: nowIso()
      });
      emit("file_change_completed", "Workspace patch applied.", { files: prepared.files.map((file) => file.path) });
      return `Patch applied to ${prepared.files.length} file(s).\n${prepared.diff}`;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.options.store.updateFileChange({ ...record, status: "failed", summary: message, updatedAt: nowIso() });
      emit("file_change_blocked", "Patch application failed.", { error: message });
      return `Patch application failed. ${message}`;
    }
  }

  private async executeFileEditAction(
    sessionId: string,
    emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
    action: Extract<AgentAction, { type: "file_edit" }>
  ): Promise<string> {
    const createdAt = nowIso();
    const prepared = prepareFileEdit(action);
    const record: FileChangeRecord = {
      id: newId("chg"),
      sessionId,
      path: prepared.absolutePath,
      operation: action.operation,
      status: prepared.allowed ? "pending" : "blocked",
      summary: prepared.summary,
      diff: prepared.diff,
      createdAt,
      updatedAt: createdAt
    };
    this.options.store.addFileChange(record);

    if (!prepared.allowed) {
      this.options.store.addApproval(sessionId, `file:${prepared.absolutePath}`, false, prepared.summary);
      emit("file_change_blocked", `Blocked file edit: ${prepared.absolutePath}`, {
        path: prepared.absolutePath,
        operation: action.operation,
        reason: prepared.summary
      });
      return `Blocked file edit: ${prepared.absolutePath}. Reason: ${prepared.summary}`;
    }

    emit("file_change_approval_requested", `Approval requested for file edit: ${prepared.absolutePath}`, {
      path: prepared.absolutePath,
      operation: action.operation,
      purpose: action.purpose,
      diff: prepared.diff
    });
    const approval = this.normalizeApproval(await this.options.approve(
      `Apply file edit (${action.operation})`,
      [
        `Path: ${prepared.absolutePath}`,
        `Purpose: ${action.purpose}`,
        "Diff preview:",
        prepared.diff || "(no textual diff)"
      ].join("\n")
    ));
    this.options.store.addApproval(sessionId, `file:${prepared.absolutePath}`, approval.approved, approval.remembered ? "File edit approved. Remember flag ignored for file edits." : "File edit approval decision.");
    emit("file_change_approval_resolved", approval.approved ? "File edit approved." : "File edit denied.", {
      path: prepared.absolutePath,
      approved: approval.approved
    });

    if (!approval.approved) {
      this.options.store.updateFileChange({ ...record, status: "denied", updatedAt: nowIso() });
      return `User denied file edit: ${prepared.absolutePath}`;
    }

    emit("file_change_started", `Applying file edit: ${prepared.absolutePath}`, {
      path: prepared.absolutePath,
      operation: action.operation
    });
    try {
      mkdirSync(dirname(prepared.absolutePath), { recursive: true });
      writeFileSync(prepared.absolutePath, prepared.after, "utf8");
      const applied: FileChangeRecord = {
        ...record,
        status: "applied",
        summary: `Applied ${action.operation} to ${prepared.absolutePath}.`,
        updatedAt: nowIso()
      };
      this.options.store.updateFileChange(applied);
      this.options.store.addObservation({
        id: newId("obs"),
        sessionId,
        source: `file:${prepared.absolutePath}`,
        summary: applied.summary ?? "File edit applied.",
        createdAt: nowIso()
      });
      emit("file_change_completed", `File edit applied: ${prepared.absolutePath}`, {
        path: prepared.absolutePath,
        operation: action.operation
      });
      return `File edit applied: ${prepared.absolutePath}\n${prepared.diff || "(no textual diff)"}`;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      this.options.store.updateFileChange({ ...record, status: "failed", summary: message, updatedAt: nowIso() });
      emit("file_change_blocked", `File edit failed: ${prepared.absolutePath}`, { path: prepared.absolutePath, error: message });
      return `File edit failed: ${prepared.absolutePath}. ${message}`;
    }
  }

  private async executeSubAgentAction(
    sessionId: string,
    emit: SubAgentEmitter,
    role: SubAgentRole,
    description: string | undefined,
    task: string,
    contextPaths: string[],
    background: boolean
  ): Promise<string> {
    return await executeSubAgentActionFromModule({
      store: this.options.store,
      runtime: this.subAgentRuntime
    }, sessionId, emit, role, description, task, contextPaths, background);
  }

  private async runApprovedCommand(record: ShellCommandRecord): Promise<{ exitCode: number; summary: string; output: string }> {
    return await runApprovedCommandFromModule(this.options.store, record);
  }

  private async resolveShellApproval(command: string, subject: string, detail: string): Promise<NormalizedApproval> {
    return await resolveShellApprovalFromModule(this.options.store, command, subject, detail, this.options.approve);
  }

  private normalizeApproval(decision: ApprovalDecision): NormalizedApproval {
    return normalizeApprovalFromModule(decision);
  }

  private isBinaryAvailable(binary: string): boolean {
    const command = process.platform === "win32" ? "where.exe" : "command";
    const args = process.platform === "win32" ? [binary] : ["-v", binary];
    const result = spawnSync(command, args, {
      windowsHide: true,
      stdio: "ignore"
    });
    return result.status === 0;
  }

  private createSecurityToolRun(input: Omit<SecurityToolRun, "id" | "status" | "createdAt" | "updatedAt"> & { status?: SecurityToolRunStatus }): SecurityToolRun {
    return createSecurityToolRunFromModule(this.options.store, input);
  }

  private finishSecurityToolRun(
    run: SecurityToolRun,
    status: SecurityToolRunStatus,
    update: Partial<Pick<SecurityToolRun, "command" | "inputArtifact" | "outputArtifact" | "outputSummary" | "exitCode" | "blockedReason" | "failureCategory" | "findingCount">> = {}
  ): SecurityToolRun {
    return finishSecurityToolRunFromModule(this.options.store, run, status, update);
  }

  private recordPipelinePreflightToolRuns(
    sessionId: string,
    workflowId: string,
    preflight: PipelinePreflightReport
  ): void {
    recordPipelinePreflightToolRunsFromModule(this.options.store, sessionId, workflowId, preflight);
  }

  private describeToolRunStatus(status: SecurityToolRunStatus): string {
    return describeToolRunStatusFromModule(status);
  }

  private extractExitCode(output: string): number | undefined {
    return extractExitCodeFromModule(output);
  }

  private recordNormalizedSecurityObservation(
    sessionId: string,
    workflowId: string,
    observation: NormalizedSecurityObservation
  ): void {
    recordNormalizedSecurityObservationFromModule(this.options.store, {
      sessionId,
      workflowId,
      observation,
      enrichFindingForStorage: (finding) => this.enrichFindingForStorage(finding),
      addCveMatchDeduped: (match) => this.addCveMatchDeduped(match)
    });
  }

  private enrichFindingForStorage(finding: SecurityFinding, evidenceIds: string[] = []): SecurityFinding {
    const now = nowIso();
    return {
      ...finding,
      state: finding.state ?? "candidate",
      dedupeKey: finding.dedupeKey ?? this.findingDedupeKey(finding),
      evidenceIds: [...new Set([...(finding.evidenceIds ?? []), ...evidenceIds])],
      firstSeenAt: finding.firstSeenAt ?? finding.createdAt ?? now,
      lastSeenAt: finding.lastSeenAt ?? finding.updatedAt ?? now
    };
  }

  private findingDedupeKey(finding: Pick<SecurityFinding, "title" | "target" | "severity">): string {
    return createHash("sha256")
      .update([finding.title, finding.target, finding.severity].map((value) => value.toLowerCase().trim()).join("\n"))
      .digest("hex")
      .slice(0, 24);
  }

  private reconcileFindingStates(sessionId: string): void {
    const attempts = this.options.store.listSecurityValidationAttempts(sessionId);
    for (const attempt of attempts) {
      if (attempt.targetKind !== "finding") {
        continue;
      }
      const state = attempt.status === "validated"
        ? "validated"
        : attempt.status === "ruled_out"
          ? "false_positive"
          : attempt.status === "blocked"
            ? "needs_validation"
            : "needs_validation";
      this.options.store.updateFindingState(attempt.targetId, state, attempt.evidenceIds, attempt.rationale);
    }
  }

  private addCveMatchDeduped(match: SecurityCveMatch): void {
    const key = this.cveMatchKey(match);
    const existing = this.options.store.listCveMatches(match.sessionId)
      .find((candidate) => this.cveMatchKey(candidate) === key);
    if (!existing) {
      this.options.store.addCveMatch(match);
      return;
    }
    if (
      this.severityRank(match.severity) > this.severityRank(existing.severity) ||
      this.confidenceRank(match.confidence) > this.confidenceRank(existing.confidence)
    ) {
      this.options.store.updateCveMatch({
        ...existing,
        ...match,
        id: existing.id,
        createdAt: existing.createdAt,
        rationale: `${existing.rationale} ${match.rationale}`,
        source: [...new Set([existing.source, match.source].flatMap((source) => source.split(/\s*\+\s*/)))].join(" + ")
      });
    }
  }

  private cveMatchKey(match: Pick<SecurityCveMatch, "target" | "technology" | "cveId" | "title">): string {
    return [
      match.target.toLowerCase().replace(/\/+$/u, ""),
      match.technology.toLowerCase().replace(/\s+\d+(?:\.\d+){0,3}.*$/u, "").replace(/[^a-z0-9]/g, ""),
      (match.cveId ?? match.title).toUpperCase()
    ].join("|");
  }

  private severityRank(severity: SecurityFinding["severity"]): number {
    return ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 })[severity];
  }

  private confidenceRank(confidence: SecurityFinding["confidence"]): number {
    return ({ low: 0, medium: 1, high: 2 })[confidence];
  }

  private async runAdaptiveSecurityLoop(
    sessionId: string,
    workflowId: string,
    target: TargetInput,
    scope: PentestScope,
    initialObservation: NormalizedSecurityObservation,
    toolInventory: Map<string, SecurityToolInventoryItem>,
    adaptiveKeys: Set<string>
  ): Promise<string[]> {
    return await runAdaptiveSecurityLoopFromModule({
      store: this.options.store,
      projectRoot: this.projectRoot(),
      emitLifecycleEvent: (currentSessionId, turnId, kind, message, payload) =>
        this.emitLifecycleEvent(currentSessionId, turnId, kind, message, payload),
      executeShellAction: async (currentSessionId, emit, command, purpose) =>
        await this.executeShellAction(currentSessionId, emit, command, purpose),
      recordTechnologyHints: (currentSessionId, currentWorkflowId, currentTarget, text, source) =>
        this.recordTechnologyHints(currentSessionId, currentWorkflowId, currentTarget, text, source),
      recordNormalizedSecurityObservation: (currentSessionId, currentWorkflowId, observation) =>
        this.recordNormalizedSecurityObservation(currentSessionId, currentWorkflowId, observation)
    }, {
      sessionId,
      workflowId,
      target,
      scope,
      initialObservation,
      toolInventory,
      adaptiveKeys
    });
  }

  private writeAdaptiveInputFile(sessionId: string, workflowId: string, toolId: string, values: string[]): string {
    return writeAdaptiveInputFileFromModule(this.projectRoot(), sessionId, workflowId, toolId, values);
  }

  private writeToolOutputArtifact(sessionId: string, workflowId: string, toolId: string | undefined, output: string): string {
    return writeToolOutputArtifactFromModule(this.projectRoot(), sessionId, workflowId, toolId, output);
  }

  private browserArtifactDir(sessionId: string, workflowId: string | undefined): string {
    return joinPath(
      this.projectRoot(),
      "data",
      "runs",
      sanitizePathSegment(sessionId),
      sanitizePathSegment(workflowId ?? "no-workflow"),
      "browser"
    );
  }

  private buildDecisionToolCommand(
    sessionId: string,
    workflowId: string,
    target: TargetInput,
    scope: PentestScope,
    item: SecurityDecisionQueueItem
  ): { command?: string; inputArtifact?: string } {
    return buildDecisionToolCommandFromModule(this.projectRoot(), sessionId, workflowId, target, scope, item);
  }

  private decisionItemInputs(item: SecurityDecisionQueueItem, target: TargetInput): string[] {
    return decisionItemInputsFromModule(item, target);
  }

  private inputKindForDecisionTool(toolId: string | undefined): SecurityToolRun["inputKind"] {
    return inputKindForDecisionToolFromModule(toolId);
  }

  private roleForDecisionItem(item: SecurityDecisionQueueItem): SubAgentRole {
    return roleForDecisionItemFromModule(item);
  }

  private writeWorkflowEvidenceManifest(sessionId: string, workflowId: string, target: TargetInput): string {
    return writeWorkflowEvidenceManifestFromModule(this.projectRoot(), this.options.store, {
      sessionId,
      workflowId,
      target,
      coordinationPlan: this.buildSubAgentCoordinationPlan(sessionId)
    });
  }

  private recordLocalCveMatches(sessionId: string, workflowId: string): void {
    recordLocalCveMatchesFromModule(
      this.options.store,
      sessionId,
      workflowId,
      this.projectRoot(),
      (match) => this.addCveMatchDeduped(match)
    );
  }

  private refreshSecurityCheckStatus(sessionId: string, workflowId: string, activeValidationBlocked: boolean): void {
    refreshSecurityCheckStatusFromModule(this.options.store, sessionId, workflowId, activeValidationBlocked);
  }

  private renderSecurityReportContent(sessionId: string): string {
    return renderSecurityReportContentFromModule(this.options.store, sessionId, {
      buildSecurityDecisionQueue: (currentSessionId) => this.buildSecurityDecisionQueue(currentSessionId),
      buildSubAgentCoordinationPlan: (currentSessionId) => this.buildSubAgentCoordinationPlan(currentSessionId),
      buildBusinessLogicTestPlan: (currentSessionId) => this.buildBusinessLogicTestPlan(currentSessionId)
    });
  }

  private recordValidationAttempt(input: Omit<SecurityValidationAttempt, "id" | "createdAt" | "updatedAt">): SecurityValidationAttempt {
    return recordValidationAttemptFromModule(this.options.store, input);
  }

  private recordTechnologyHints(
    sessionId: string,
    workflowId: string,
    target: string,
    text: string,
    source: string
  ): void {
    recordTechnologyHintsFromModule(this.options.store, { sessionId, workflowId, target, text, source });
  }

  private recordHeaderFindings(sessionId: string, workflowId: string, target: string, summary: string): void {
    for (const finding of buildHeaderFindings(target, summary)) {
      this.options.store.upsertFinding(this.enrichFindingForStorage({
        id: newId("find"),
        sessionId,
        workflowId,
        ...finding,
        createdAt: nowIso(),
        updatedAt: nowIso()
      }));
    }
  }

  private async buildContext(target: TargetInput): Promise<ContextFile[]> {
    return await buildContextFromModule(target);
  }

  private async buildFileContexts(filePaths: string[]): Promise<ContextFile[]> {
    return await buildFileContextsFromModule(filePaths);
  }

  private async answerConversation(sessionId: string, input: string, contextSnapshot: ContextSnapshot): Promise<string> {
    void sessionId;
    return await answerConversationFromModule(this.options.provider, input, contextSnapshot);
  }

  private parseIntent(input: string, text: string): IntentExtraction {
    return parseIntentExtraction(input, text, (value) => this.extractJsonObject(value));
  }

  private resolveIntentReferences(intent: IntentExtraction, sessionId?: string): IntentExtraction {
    if (!sessionId || intent.targets.length > 0) {
      return intent;
    }
    if (!/(瀹億杩欎釜|閭ｄ釜|鍒氭墠|涓婁竴涓獆涓婁竴鏉it|that|this|previous target|same target)/i.test(intent.userText)) {
      return intent;
    }
    const target = this.options.store
      .listTargets(sessionId, 20)
      .reverse()
      .find((candidate) => candidate.kind === "url" || candidate.kind === "domain");
    if (!target) {
      return intent;
    }
    return {
      ...intent,
      intent: this.normalizeIntent(intent.userText, intent.intent, [target], intent.filePaths),
      targets: [target],
      constraints: [...intent.constraints, "target resolved from prior session context"]
    };
  }

  private fallbackIntent(input: string): IntentExtraction {
    return fallbackIntentFromUtils(input);
  }

  private isSecurityAssessmentIntent(intent: string): boolean {
    return isSecurityAssessmentIntentFromUtils(intent);
  }

  private normalizeIntent(input: string, intent: string, targets: TargetInput[], filePaths: string[]): string {
    return normalizeIntentFromUtils(input, intent, targets, filePaths);
  }

  private sanitizeTargets(targets: TargetInput[], filePaths: string[]): TargetInput[] {
    return sanitizeTargetsFromUtils(targets, filePaths);
  }

  private sanitizeFilePaths(filePaths: string[]): string[] {
    return sanitizeFilePathsFromUtils(filePaths);
  }

  private extractLocalConstraints(input: string): string[] {
    return extractLocalConstraintsFromUtils(input);
  }

  private async createPlan(sessionId: string, input: string, target: TargetInput, contexts: ContextFile[]): Promise<AgentPlan> {
    return await createPlanFromModule(
      this.options.provider,
      this.options.store,
      (currentSessionId, overrides) => this.buildContextSnapshot(currentSessionId, overrides),
      sessionId,
      input,
      target,
      contexts
    );
  }

  private async sampleDecision(
    sessionId: string,
    input: string,
    target: TargetInput,
    contexts: ContextFile[],
    observations: string[],
    iteration: number,
    emit: SubAgentEmitter,
    skillContext: string,
    securityWorkflowContext: string,
    contextSnapshot: ContextSnapshot
  ): Promise<AgentDecision> {
    return await sampleDecisionFromModule(this.options.provider, {
      renderToolManifest: () => this.renderToolManifest(),
      parseDecision: (text) => this.parseDecision(text),
      repairDecisionJson: async (rawResponse, parseError) => await this.repairDecisionJson(rawResponse, parseError)
    }, {
      userInput: input,
      target,
      contexts,
      observations,
      iteration,
      emit,
      securityWorkflowContext,
      contextSnapshot
    });
  }

  private async repairDecisionJson(rawResponse: string, parseError: unknown): Promise<string> {
    return await repairDecisionJsonFromModule(this.options.provider, rawResponse, parseError);
  }

  private buildContextSnapshot(
    sessionId: string,
    overrides: {
      currentInput?: string;
      currentTarget?: TargetInput;
      fileContexts?: ContextFile[];
      turnObservations?: string[];
      skillContext?: string;
      securityWorkflowContext?: string;
    } = {}
  ): ContextSnapshot {
    return buildContextSnapshotFromModule(
      this.contextManager,
      this.options.store,
      sessionId,
      (currentSessionId) => this.renderTaskTreeContext(currentSessionId),
      overrides
    );
  }

  private refreshSessionMemory(sessionId: string): void {
    refreshSessionMemoryFromModule(this.options.store, sessionId);
  }

  private async renderSkillContext(query: string): Promise<string> {
    return await renderSkillContextFromModule(this.skillRegistry, query);
  }

  private async buildSecurityWorkflowContext(
    sessionId: string,
    intent: string,
    target: TargetInput,
    emit: SubAgentEmitter
  ): Promise<string> {
    return await buildSecurityWorkflowContextFromModule(this.options.store, this.skillRegistry, {
      sessionId,
      intent,
      target,
      isSecurityAssessmentIntent: (value) => this.isSecurityAssessmentIntent(value),
      emit
    });
  }

  private renderToolManifest(): string {
    return renderToolManifestFromTools();
  }

  private parseDecision(text: string): AgentDecision {
    return parseAgentDecision(text);
  }

  private parseDecisionLegacy(text: string): AgentDecision {
    return parseDecisionLegacyFromModule(
      text,
      (value) => this.extractJsonObject(value),
      (operation) => this.normalizeFileEditOperation(operation),
      (role) => this.normalizeSubAgentRole(role)
    );
  }

  private async samplePentestDecision(
    sessionId: string,
    target: TargetInput,
    scope: PentestScope,
    _preflight: PipelinePreflightReport,
    observations: string[],
    iteration: number,
    emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
    contextSnapshot: ContextSnapshot
  ): Promise<AgentDecision> {
    return requestPentestDecision({
      provider: this.options.provider,
      skillRegistry: this.skillRegistry,
      hasMcpManager: Boolean(this.options.mcpManager),
      parseDecision: (text) => this.parseDecision(text),
      repairDecisionJson: (rawResponse, parseError) => this.repairDecisionJson(rawResponse, parseError)
    }, {
      sessionId,
      target,
      scope,
      observations,
      iteration,
      emit,
      contextSnapshot
    });
  }

  private extractJsonObject(text: string): string {
    return extractJsonObjectFromTools(text);
  }

  private normalizeSubAgentRole(role: unknown): SubAgentRole {
    return role === "explorer" ||
      role === "worker" ||
      role === "reviewer" ||
      role === "recon" ||
      role === "frontend" ||
      role === "fingerprint" ||
      role === "cve" ||
      role === "web_vuln" ||
      role === "exploit" ||
      role === "default"
      ? role
      : "default";
  }

  private normalizeFileEditOperation(operation: unknown): FileEditOperation {
    return operation === "create" || operation === "overwrite" || operation === "append" || operation === "string_replace"
      ? operation
      : "string_replace";
  }

  private summarizeContextsLocally(contexts: ContextFile[], heading: string): string {
    return summarizeContextsLocallyFromUtils(contexts, heading);
  }

  // ── Interactive Conversation Turn ──

  /**
   * Run a single interactive conversation turn with streaming responses.
   * The LLM can call tools and the results are fed back automatically.
   * Respects the provided AbortSignal for user interrupts.
   */
  async *runConversationTurn(
    sessionId: string,
    userInput: string,
    options?: {
      signal?: AbortSignal;
      systemPrompt?: string;
      maxToolRounds?: number;
    }
  ): AsyncGenerator<import("./conversation-loop.js").ConversationTurnEvent> {
    const { runConversationTurn } = await import("./conversation-loop.js");

    // Build conversation history from store
    const history = (this.options.store.listConversationMessages?.(sessionId) ?? []).map((m) => ({
      ...m,
      role: m.role as "user" | "assistant" | "system" | "tool"
    }));
    const messages: import("./conversation-loop.js").ConversationMessage[] = [
      ...history,
      {
        id: newId("msg"),
        role: "user" as const,
        content: userInput,
        createdAt: nowIso()
      }
    ];

    // Persist the user message
    if (this.options.store.insertConversationMessage) {
      this.options.store.insertConversationMessage({
        id: messages[messages.length - 1].id,
        sessionId,
        role: "user",
        content: userInput,
        createdAt: messages[messages.length - 1].createdAt
      });
    }

    let accumulatedContent = "";
    const toolCallsForMessage: Array<{ id: string; name: string; arguments: string }> = [];
    const assistantMsgId = newId("msg");

    const emitter = (kind: string, message: string, _payload?: unknown) => {
      this.options.onEvent?.({ id: newId("evt"), sessionId, turnId: assistantMsgId, kind: kind as any, message, payload: _payload, createdAt: nowIso() });
    };

    for await (const event of runConversationTurn({
      provider: this.options.provider,
      store: this.options.store,
      mcpManager: this.options.mcpManager,
      messages,
      systemPrompt: options?.systemPrompt ?? renderPromptPackTemplate("conversation/interactive-system.md"),
      signal: options?.signal,
      maxToolRounds: options?.maxToolRounds,
      executeShell: async (command, purpose) => {
        const { executeShellAction } = await import("./shell-orchestration.js");
        const result = await executeShellAction(
          this.options.store,
          this.options.approve,
          sessionId,
          emitter,
          command,
          purpose
        );
        return result;
      },
      executeReadFile: async (path, purpose) => {
        const { executeReadFileAction } = await import("./workspace-actions.js");
        const result = await executeReadFileAction(this.options.store, sessionId, emitter, path, purpose);
        return result;
      },
      executeListFiles: async (path, recursive) => {
        const { executeListFilesAction } = await import("./workspace-actions.js");
        const result = await executeListFilesAction(this.options.store, sessionId, emitter, path, "list directory", recursive);
        return result;
      },
      executeSecurityProbe: async (target, probe) => {
        const { executeSecurityProbeAction } = await import("./security-probes.js");
        const result = await executeSecurityProbeAction({
          store: this.options.store,
          approve: this.options.approve,
          normalizeApproval: (d) => ({
            approved: typeof d === "boolean" ? d : d.approved,
            remembered: typeof d === "boolean" ? false : (d.remember ?? false)
          }),
          sessionId,
          emit: emitter,
          target,
          probe: probe as any,
          purpose: "security probe"
        });
        return result;
      },
      executeFofaSearch: async (query, size) => {
        const { loadConfig } = await import("@aegisprobe/provider");
        const config = loadConfig();
        const { fofaSearch } = await import("@aegisprobe/security");
        try {
          const result = await fofaSearch(query, config.fofa, size);
          if (result.results.length === 0) {
            return `FOFA search "${query}": No results found. Total: ${result.total}`;
          }
          const lines = result.results.map((r, i) =>
            `${i + 1}. ${r.host}:${r.port} | ${r.title || "(no title)"} | ${r.server || "(unknown server)"} | IP: ${r.ip}`
          );
          return `FOFA search "${query}": ${result.total} total results, showing top ${result.results.length}:\n${lines.join("\n")}`;
        } catch (err) {
          return `FOFA search error: ${err instanceof Error ? err.message : String(err)}`;
        }
      },
      executeWebFetch: async (url, purpose) => {
        try {
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), 15_000);
          const response = await fetch(url, {
            signal: controller.signal,
            headers: { "User-Agent": "AegisProbe/1.0 (security-assessment)" }
          });
          clearTimeout(timeout);
          if (!response.ok) {
            return `Web fetch ${url}: HTTP ${response.status} ${response.statusText}`;
          }
          const contentType = response.headers.get("content-type") ?? "";
          if (!contentType.includes("text/html") && !contentType.includes("text/plain") && !contentType.includes("application/json")) {
            return `Web fetch ${url}: Content-Type ${contentType}, size ~${response.headers.get("content-length") ?? "unknown"} bytes (non-text, not displayed)`;
          }
          const text = await response.text();
          // Strip HTML tags for readability, limit to 4000 chars
          const stripped = text.replace(/<script[^>]*>[\s\S]*?<\/script>/gi, "")
            .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, "")
            .replace(/<[^>]+>/g, " ")
            .replace(/&nbsp;/g, " ")
            .replace(/&amp;/g, "&")
            .replace(/&lt;/g, "<")
            .replace(/&gt;/g, ">")
            .replace(/&#?\w+;/g, " ")
            .replace(/\s{2,}/g, "\n")
            .trim()
            .slice(0, 4000);
          return `Web fetch ${url} (${response.status}):\n${stripped || "(empty or binary content)"}`;
        } catch (err) {
          return `Web fetch error for ${url}: ${err instanceof Error ? err.message : String(err)}`;
        }
      }
    })) {
      // Track tool calls for persistence
      if (event.kind === "text_delta") {
        accumulatedContent += event.content;
      }
      if (event.kind === "tool_call_end") {
        toolCallsForMessage.push({ id: event.id, name: event.name, arguments: event.arguments });
      }
      if (event.kind === "tool_execution_end") {
        // Persist tool result
        if (this.options.store.insertConversationMessage) {
          this.options.store.insertConversationMessage({
            id: newId("tool"),
            sessionId,
            role: "tool",
            content: event.result,
            toolCallId: event.id,
            createdAt: nowIso()
          });
        }
      }

      yield event;
    }

    // Persist the assistant message
    if (this.options.store.insertConversationMessage && accumulatedContent.trim()) {
      this.options.store.insertConversationMessage({
        id: assistantMsgId,
        sessionId,
        role: "assistant",
        content: accumulatedContent,
        toolCalls: toolCallsForMessage.length > 0 ? toolCallsForMessage : undefined,
        createdAt: nowIso()
      });
    }
  }

  /** Clear the conversation history for a session. */
  clearConversation(sessionId: string): void {
    this.options.store.clearConversationMessages?.(sessionId);
  }
}

import { browserNavigate, browserWait, browserFill, browserClick, browserUpload, browserScreenshot, browserGetContent, browserClose, loadOptionalPlaywright, launchChromiumBrowser, normalizeBrowserUrl, isApiLikeBrowserUrl, browserRiskSignals, uniqueBrowserActions, uniqueStorageSignals, emptyNormalizedSecurityObservation } from "./browser-automation.js";
export { browserNavigate, browserWait, browserFill, browserClick, browserUpload, browserScreenshot, browserGetContent, browserClose, loadOptionalPlaywright } from "./browser-automation.js";
export {
  buildAuthorizationBoundaryMatrix,
  buildAuthorizationValidationPlan,
  type AuthorizationBoundaryMatrix,
  type AuthorizationBoundaryMatrixItem,
  type AuthorizationValidationPlan,
  type AuthorizationValidationCandidate
} from "./security-business.js";
export {
  buildWebPentestControlPlane,
  buildWebPentestOperatingPicture,
  renderWebPentestControlPlane,
  renderWebPentestOperatingPicture,
  type WebPentestControlPlane,
  type WebPentestOperatingPicture,
  type WebPentestOperatingEndpoint,
  type WebPentestReadinessGate
} from "./web-pentest-control-plane.js";
export {
  importApiDescriptionDocument,
  type ApiDescriptionImportResult
} from "./api-description-import.js";
export {
  safeAnonymousFetchDetails,
  safeAuthenticatedFetch,
  safeAuthenticatedFetchDetails,
  businessLogicProbeUrls,
  collectWebPortMatrixProbe,
  runBuiltInSecurityProbe
} from "./security-probes.js";
export type { SafeAuthenticatedFetchDetails, SafeReadOnlyMethod, WebPortMatrixProbe, WebPortMatrixEntry } from "./security-probes.js";
export type { ConversationTurnEvent } from "./conversation-loop.js";
