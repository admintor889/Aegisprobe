import { buildAdaptiveSecurityActions, buildSecurityDecisionSupervision, buildSecurityToolCommandForInputFile, classifySecurityToolOutput, getSecurityToolInventory, normalizeSecurityToolOutput, type NormalizedSecurityObservation, type PentestScope, type SecurityAssetGraph, type SecurityClosureModel, type SecurityDecisionQueue, type SecurityDecisionQueueItem, type SecurityObjectiveModel, type SecurityToolInventoryItem } from "@aegisprobe/security";
import { newId, nowIso, truncateForContext, type SubAgentRecord, type TargetInput, type TurnEventKind } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { emptyNormalizedSecurityObservation } from "./browser-automation.js";
import { buildDecisionToolCommand, createSecurityToolRun, decisionItemInputs, describeToolRunStatus, extractExitCode, finishSecurityToolRun, inputKindForDecisionTool, roleForDecisionItem, writeAdaptiveInputFile, writeToolOutputArtifact } from "./security-tooling.js";

type ClosureDependencies = {
  store: AuditStore;
  executeSecurityValidationAttempt: (sessionId: string, targetIdOrNext?: string) => string;
  executeBusinessLogicRoleComparison: (sessionId: string, caseIdOrNext?: string, leftAuthName?: string, rightAuthName?: string) => Promise<string>;
  executeBusinessLogicTest: (sessionId: string, caseIdOrNext?: string, authContextName?: string) => Promise<string>;
};

export async function executeSecurityClosureStep(
  deps: ClosureDependencies,
  sessionId: string,
  closure: SecurityClosureModel
): Promise<string | undefined> {
  if (closure.validationPlan.status !== "ready" || !closure.validationPlan.nextCandidateId) {
    return undefined;
  }
  const candidate = closure.validationPlan.candidates.find((item) => item.id === closure.validationPlan.nextCandidateId);
  if (!candidate || candidate.blockedBy || candidate.state !== "ready") {
    return undefined;
  }
  if (candidate.kind === "finding" || candidate.kind === "cve" || candidate.kind === "business_logic" || candidate.kind === "tool_run") {
    return deps.executeSecurityValidationAttempt(sessionId, `${candidate.kind}:${candidate.targetId}`);
  }
  if (candidate.kind !== "objective") {
    return undefined;
  }
  const authContexts = deps.store.listSecurityAuthContexts(sessionId);
  if (candidate.targetId === "business_logic_impact" && authContexts.length >= 2) {
    return await deps.executeBusinessLogicRoleComparison(sessionId, "next", authContexts[0]?.name, authContexts[1]?.name);
  }
  if ((candidate.targetId === "business_logic_impact" || candidate.targetId === "admin_control_plane") && authContexts.length >= 1) {
    return await deps.executeBusinessLogicTest(sessionId, "next", authContexts[0]?.name);
  }
  return undefined;
}

type AdaptiveLoopDependencies = {
  store: AuditStore;
  projectRoot: string;
  emitLifecycleEvent: (sessionId: string, turnId: string, kind: TurnEventKind, message: string, payload?: unknown) => void;
  executeShellAction: (
    sessionId: string,
    emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
    command: string,
    purpose: string
  ) => Promise<string>;
  recordTechnologyHints: (sessionId: string, workflowId: string, target: string, text: string, source: string) => void;
  recordNormalizedSecurityObservation: (sessionId: string, workflowId: string, observation: NormalizedSecurityObservation) => void;
};

type AdaptiveLoopInput = {
  sessionId: string;
  workflowId: string;
  target: TargetInput;
  scope: PentestScope;
  initialObservation: NormalizedSecurityObservation;
  toolInventory: Map<string, SecurityToolInventoryItem>;
  adaptiveKeys: Set<string>;
};

export async function runAdaptiveSecurityLoop(
  deps: AdaptiveLoopDependencies,
  input: AdaptiveLoopInput
): Promise<string[]> {
  const summaries: string[] = [];
  const queue: NormalizedSecurityObservation[] = [input.initialObservation];
  let executedRuns = 0;
  const maxAdaptiveRuns = 2;

  while (queue.length > 0 && executedRuns < maxAdaptiveRuns) {
    const observation = queue.shift();
    if (!observation) {
      break;
    }
    const actions = buildAdaptiveSecurityActions(observation, input.target, input.scope, {
      completedKeys: input.adaptiveKeys,
      maxInputsPerAction: 10
    });

    for (const action of actions) {
      if (executedRuns >= maxAdaptiveRuns) {
        summaries.push("[adaptive] Run limit reached; remaining follow-up actions were recorded for manual continuation.");
        return summaries;
      }

      input.adaptiveKeys.add(action.key);
      const toolRun = createSecurityToolRun(deps.store, {
        sessionId: input.sessionId,
        workflowId: input.workflowId,
        toolId: action.toolId,
        phase: action.phase,
        origin: "adaptive",
        inputKind: action.inputKind,
        inputCount: action.inputValues.length
      });
      deps.store.addEvidence({
        id: newId("evd"),
        sessionId: input.sessionId,
        workflowId: input.workflowId,
        source: "adaptive:decision",
        kind: "note",
        summary: `${action.title}: ${action.inputValues.length} ${action.inputKind} input(s).`,
        data: JSON.stringify(action, null, 2),
        createdAt: nowIso()
      });

      if (action.blockedReason) {
        finishSecurityToolRun(deps.store, toolRun, "blocked", {
          blockedReason: action.blockedReason,
          outputSummary: `Blocked by scope: ${action.blockedReason}`
        });
        deps.store.addEvidence({
          id: newId("evd"),
          sessionId: input.sessionId,
          workflowId: input.workflowId,
          source: `adaptive:${action.toolId}`,
          kind: "tool",
          summary: `Adaptive action blocked by scope: ${action.blockedReason}`,
          data: JSON.stringify(action, null, 2),
          createdAt: nowIso()
        });
        summaries.push(`[adaptive:${action.phase}] ${action.title}: blocked by scope.`);
        continue;
      }

      const inventory = input.toolInventory.get(action.toolId);
      if (!inventory || !inventory.available) {
        finishSecurityToolRun(deps.store, toolRun, "missing", {
          blockedReason: "Tool binary is unavailable.",
          outputSummary: `${action.toolId} binary is unavailable.`
        });
        deps.store.addEvidence({
          id: newId("evd"),
          sessionId: input.sessionId,
          workflowId: input.workflowId,
          source: `adaptive:${action.toolId}`,
          kind: "tool",
          summary: `Adaptive action recorded but ${action.toolId} binary is unavailable.`,
          data: JSON.stringify({ action, inventory }, null, 2),
          createdAt: nowIso()
        });
        summaries.push(`[adaptive:${action.phase}] ${action.title}: binary unavailable; action recorded.`);
        continue;
      }

      const inputFile = writeAdaptiveInputFile(deps.projectRoot, input.sessionId, input.workflowId, action.toolId, action.inputValues);
      const command = buildSecurityToolCommandForInputFile(action.toolId, inputFile, input.scope, deps.projectRoot);
      if (!command) {
        finishSecurityToolRun(deps.store, toolRun, "skipped", {
          inputArtifact: inputFile,
          outputSummary: "No executable command was generated for this adaptive action."
        });
        deps.store.addEvidence({
          id: newId("evd"),
          sessionId: input.sessionId,
          workflowId: input.workflowId,
          source: `adaptive:${action.toolId}`,
          kind: "tool",
          summary: "Adaptive action has no executable command in the current scope.",
          data: JSON.stringify({ action, inputFile }, null, 2),
          createdAt: nowIso()
        });
        summaries.push(`[adaptive:${action.phase}] ${action.title}: no command generated.`);
        continue;
      }

      deps.store.updateSecurityWorkflowStatus(input.workflowId, "running", action.phase, `Running adaptive ${action.title}`);
      const output = await deps.executeShellAction(input.sessionId, (kind, message, payload) => {
        deps.emitLifecycleEvent(input.sessionId, `adaptive:${input.workflowId}`, kind, message, payload);
      }, command, action.description);
      const outputArtifact = writeToolOutputArtifact(deps.projectRoot, input.sessionId, input.workflowId, action.toolId, output);
      const normalized = output.startsWith("User denied command:")
        ? emptyNormalizedSecurityObservation()
        : normalizeSecurityToolOutput(action.toolId, output, input.target);
      const exitCode = extractExitCode(output);
      const classification = classifySecurityToolOutput(action.toolId, output, normalized, exitCode);
      finishSecurityToolRun(deps.store, toolRun, classification.status, {
        command,
        inputArtifact: inputFile,
        outputArtifact,
        outputSummary: `${classification.summary}\n${truncateForContext(output, 10_000)}`,
        exitCode,
        failureCategory: classification.failureCategory,
        findingCount: classification.findingCount
      });
      deps.store.addEvidence({
        id: newId("evd"),
        sessionId: input.sessionId,
        workflowId: input.workflowId,
        source: `adaptive:${action.toolId}`,
        kind: "tool",
        summary: truncateForContext(output, 1000),
        data: output,
        createdAt: nowIso()
      });

      if (output.startsWith("User denied command:")) {
        summaries.push(`[adaptive:${action.phase}] ${action.title}: denied.`);
        continue;
      }

      deps.recordTechnologyHints(input.sessionId, input.workflowId, input.target.normalized, output, `adaptive:${action.toolId}`);
      deps.recordNormalizedSecurityObservation(input.sessionId, input.workflowId, normalized);
      queue.push(normalized);
      executedRuns += 1;
      summaries.push(`[adaptive:${action.phase}] ${action.title}: ${describeToolRunStatus(classification.status)}.`);
    }
  }

  return summaries;
}

type DecisionToolDependencies = {
  store: AuditStore;
  projectRoot: string;
  executeShellAction: (
    sessionId: string,
    emit: (kind: TurnEventKind, message: string, payload?: unknown) => void,
    command: string,
    purpose: string
  ) => Promise<string>;
  buildSecurityDecisionQueue: (sessionId: string, scope: PentestScope) => SecurityDecisionQueue;
  buildSecurityAssetGraph: (sessionId: string) => SecurityAssetGraph;
  recordTechnologyHints: (sessionId: string, workflowId: string, target: string, text: string, source: string) => void;
  recordNormalizedSecurityObservation: (sessionId: string, workflowId: string, observation: NormalizedSecurityObservation) => void;
};

type ExecuteDecisionToolItemInput = {
  sessionId: string;
  workflowId: string;
  target: TargetInput;
  scope: PentestScope;
  item: SecurityDecisionQueueItem;
};

export async function executeDecisionToolItem(
  deps: DecisionToolDependencies,
  input: ExecuteDecisionToolItemInput
): Promise<string> {
  const toolId = input.item.toolId;
  if (!toolId) {
    return "Tool decision item has no tool id.";
  }
  const inventory = new Map(getSecurityToolInventory(deps.projectRoot).map((tool) => [tool.id, tool]));
  const tool = inventory.get(toolId);
  const run = createSecurityToolRun(deps.store, {
    sessionId: input.sessionId,
    workflowId: input.workflowId,
    toolId,
    phase: input.item.phase,
    origin: "manual",
    inputKind: inputKindForDecisionTool(input.item.toolId),
    inputCount: decisionItemInputs(input.item, input.target).length
  });

  if (input.item.blockedBy) {
    finishSecurityToolRun(deps.store, run, "blocked", {
      blockedReason: input.item.blockedBy,
      outputSummary: `Decision queue item is blocked: ${input.item.blockedBy}`
    });
    return `Tool decision is blocked: ${input.item.blockedBy}`;
  }
  if (!tool?.available) {
    finishSecurityToolRun(deps.store, run, "missing", {
      blockedReason: "Tool binary is unavailable.",
      outputSummary: `${toolId} binary is unavailable.`
    });
    return `${toolId} binary is unavailable.`;
  }

  const commandPlan = buildDecisionToolCommand(deps.projectRoot, input.sessionId, input.workflowId, input.target, input.scope, input.item);
  if (!commandPlan.command) {
    finishSecurityToolRun(deps.store, run, "skipped", {
      inputArtifact: commandPlan.inputArtifact,
      outputSummary: "No executable command was generated for this decision item."
    });
    return `No executable command generated for ${input.item.toolId}.`;
  }

  const output = await deps.executeShellAction(input.sessionId, () => undefined, commandPlan.command, input.item.reason);
  const outputArtifact = writeToolOutputArtifact(deps.projectRoot, input.sessionId, input.workflowId, toolId, output);
  const normalized = output.startsWith("User denied command:")
    ? emptyNormalizedSecurityObservation()
    : normalizeSecurityToolOutput(toolId, output, input.target);
  const exitCode = extractExitCode(output);
  const classification = classifySecurityToolOutput(toolId, output, normalized, exitCode);
  finishSecurityToolRun(deps.store, run, classification.status, {
    command: commandPlan.command,
    inputArtifact: commandPlan.inputArtifact,
    outputArtifact,
    outputSummary: `${classification.summary}\n${truncateForContext(output, 10_000)}`,
    exitCode,
    failureCategory: classification.failureCategory,
    findingCount: classification.findingCount
  });
  deps.store.addEvidence({
    id: newId("evd"),
    sessionId: input.sessionId,
    workflowId: input.workflowId,
    source: `decision:tool:${toolId}`,
    kind: "tool",
    summary: truncateForContext(output, 20_000),
    data: JSON.stringify({ item: input.item, inputArtifact: commandPlan.inputArtifact, outputArtifact, output }, null, 2),
    createdAt: nowIso()
  });

  if (!output.startsWith("User denied command:")) {
    deps.recordTechnologyHints(input.sessionId, input.workflowId, input.target.normalized, output, `decision:${toolId}`);
    deps.recordNormalizedSecurityObservation(input.sessionId, input.workflowId, normalized);
  }

  const supervisor = buildSecurityDecisionSupervision({
    queue: deps.buildSecurityDecisionQueue(input.sessionId, input.scope),
    graph: deps.buildSecurityAssetGraph(input.sessionId),
    toolRuns: deps.store.listSecurityToolRuns(input.sessionId),
    checks: deps.store.listSecurityChecks(input.sessionId)
  });
  if (supervisor.level !== "continue") {
    deps.store.addEvidence({
      id: newId("evd"),
      sessionId: input.sessionId,
      workflowId: input.workflowId,
      source: `decision:tool-reflector:${toolId}`,
      kind: "note",
      summary: `${supervisor.level}: ${supervisor.recommendedActions[0] ?? supervisor.summary}`,
      data: JSON.stringify(supervisor, null, 2),
      createdAt: nowIso()
    });
  }

  return `${toolId} ${describeToolRunStatus(classification.status)} (${classification.failureCategory}). Output artifact: ${outputArtifact}`;
}

type DecisionItemDependencies = {
  store: AuditStore;
  executeSecurityProbeAction: (sessionId: string, target: string, probe: "http_headers", purpose: string) => Promise<string>;
  recordTechnologyHints: (sessionId: string, workflowId: string, target: string, text: string, source: string) => void;
  recordHeaderFindings: (sessionId: string, workflowId: string, target: string, summary: string) => void;
  exploreBrowserForms: (sessionId: string, startUrl: string, options: { maxPages: number }) => Promise<{ pagesVisited: string[]; forms: unknown[]; artifactPath: string }>;
  reconWebApplication: (sessionId: string, startUrl: string, options: { maxPages: number }) => Promise<{ pagesVisited: string[]; forms: unknown[]; apiInventory: unknown[]; jsEndpoints: unknown[]; networkRequests: unknown[]; artifactPath: string }>;
  recordLocalCveMatches: (sessionId: string, workflowId: string) => void;
  writeWorkflowEvidenceManifest: (sessionId: string, workflowId: string, target: TargetInput) => string;
  spawnSubAgent: (sessionId: string, role: ReturnType<typeof roleForDecisionItem>, task: string, contextPaths: string[], options: { description: string }) => Promise<SubAgentRecord>;
  readSubAgentOutput: (record: SubAgentRecord) => string | undefined;
  buildSecurityObjectiveModel: (sessionId: string, scope: PentestScope) => SecurityObjectiveModel;
  buildAuthorizationValidationPlan: (sessionId: string) => unknown;
  executeBusinessLogicRoleComparison: (sessionId: string, caseIdOrNext?: string, leftAuthName?: string, rightAuthName?: string) => Promise<string>;
  executeDecisionToolItem: (sessionId: string, workflowId: string, target: TargetInput, scope: PentestScope, item: SecurityDecisionQueueItem) => Promise<string>;
};

type ExecuteSecurityDecisionItemInput = {
  sessionId: string;
  workflowId: string;
  target: TargetInput;
  scope: PentestScope;
  item: SecurityDecisionQueueItem;
};

export async function executeSecurityDecisionItem(
  deps: DecisionItemDependencies,
  input: ExecuteSecurityDecisionItemInput
): Promise<string> {
  deps.store.updateSecurityWorkflowStatus(input.workflowId, "running", input.item.phase, `Executing decision queue item: ${input.item.title}`);

  if (input.item.actionType === "authorization") {
    const approved = input.scope.allowActiveProbing;
    deps.store.addEvidence({
      id: newId("evd"),
      sessionId: input.sessionId,
      workflowId: input.workflowId,
      source: "decision:authorization",
      kind: "note",
      summary: approved
        ? `Active validation authorization recorded for: ${input.item.title}`
        : `Authorization still required for: ${input.item.title}`,
      data: JSON.stringify({ item: input.item, scope: input.scope }, null, 2),
      createdAt: nowIso()
    });
    return approved
      ? "Active validation authorization was recorded for this queue execution scope."
      : "This queue item requires explicit active scope. Re-run with --active after confirming written authorization.";
  }

  if (input.item.actionType === "manual") {
    if (input.item.fallbackFor === "httpx") {
      const observation = await deps.executeSecurityProbeAction(input.sessionId, input.target.normalized, "http_headers", input.item.reason);
      deps.recordTechnologyHints(input.sessionId, input.workflowId, input.target.normalized, observation, "decision:fallback_probe");
      deps.recordHeaderFindings(input.sessionId, input.workflowId, input.target.normalized, observation);
      return `Manual fallback probe completed.\n${truncateForContext(observation, 10_000)}`;
    }
    if (input.item.fallbackFor === "webapp-recon") {
      const startUrl = decisionItemInputs(input.item, input.target).find((value) => /^https?:\/\//i.test(value)) ?? input.target.normalized;
      try {
        const result = await deps.reconWebApplication(input.sessionId, startUrl, { maxPages: 10 });
        return `WebApp recon completed. pages=${result.pagesVisited.length} forms=${result.forms.length} api=${result.apiInventory.length} jsEndpoints=${result.jsEndpoints.length} network=${result.networkRequests.length} artifact=${result.artifactPath}`;
      } catch (error) {
        return recordBlockedManualDecision(deps, input, "webapp-recon", error);
      }
    }
    if (input.item.fallbackFor === "browser-forms" || input.item.fallbackFor === "katana") {
      const startUrl = decisionItemInputs(input.item, input.target).find((value) => /^https?:\/\//i.test(value)) ?? input.target.normalized;
      try {
        const result = await deps.exploreBrowserForms(input.sessionId, startUrl, { maxPages: input.item.fallbackFor === "katana" ? 8 : 5 });
        return input.item.fallbackFor === "katana"
          ? `Crawler fallback browser exploration completed. pages=${result.pagesVisited.length} forms=${result.forms.length} artifact=${result.artifactPath}`
          : `Browser form exploration completed. pages=${result.pagesVisited.length} forms=${result.forms.length} artifact=${result.artifactPath}`;
      } catch (error) {
        return recordBlockedManualDecision(deps, input, input.item.fallbackFor, error);
      }
    }
    if (input.item.fallbackFor === "auth-surface-model") {
      deps.store.addEvidence({
        id: newId("evd"),
        sessionId: input.sessionId,
        workflowId: input.workflowId,
        source: "decision:manual:auth-surface-model",
        kind: "note",
        summary: "Auth surface model generation requires the integrated read-only webapp-recon artifact.",
        data: JSON.stringify({
          item: input.item,
          nextAction: "Run webapp-recon again on the in-scope URL; it now emits auth-surface-model automatically without submitting forms or guessing credentials."
        }, null, 2),
        createdAt: nowIso()
      });
      return "Auth surface model is generated by webapp-recon. Run the read-only webapp-recon fallback for this target; no credential guessing or form submission was attempted.";
    }
    if (input.item.fallbackFor === "authz-plan") {
      const plan = deps.buildAuthorizationValidationPlan(input.sessionId);
      const summary = summarizeAuthorizationValidationPlan(plan);
      const run = createSecurityToolRun(deps.store, {
        sessionId: input.sessionId,
        workflowId: input.workflowId,
        toolId: "authz-plan",
        phase: input.item.phase,
        origin: "manual",
        status: "success",
        inputKind: "target",
        inputCount: 1,
        outputSummary: summary,
        findingCount: authorizationValidationPlanFindingCount(plan)
      });
      deps.store.addEvidence({
        id: newId("evd"),
        sessionId: input.sessionId,
        workflowId: input.workflowId,
        source: `decision:authz-plan:${run.id}`,
        kind: "tool",
        summary,
        data: JSON.stringify({ item: input.item, plan }, null, 2),
        createdAt: nowIso()
      });
      return summary;
    }
    if (input.item.fallbackFor === "business-compare") {
      const authContexts = deps.store.listSecurityAuthContexts(input.sessionId, input.workflowId);
      if (authContexts.length < 2) {
        return "Read-only role comparison is blocked: register two approved auth contexts first.";
      }
      return await deps.executeBusinessLogicRoleComparison(input.sessionId, "next", authContexts[0]?.name, authContexts[1]?.name);
    }
    if (/local CVE|framework/i.test(input.item.title)) {
      deps.recordLocalCveMatches(input.sessionId, input.workflowId);
      return "Local CVE/framework matching completed and stored as candidate evidence.";
    }
    deps.store.addEvidence({
      id: newId("evd"),
      sessionId: input.sessionId,
      workflowId: input.workflowId,
      source: "decision:manual",
      kind: "note",
      summary: input.item.title,
      data: JSON.stringify(input.item, null, 2),
      createdAt: nowIso()
    });
    return `Manual decision item recorded: ${input.item.title}`;
  }

  if (input.item.actionType === "subagent") {
    const evidenceManifest = deps.writeWorkflowEvidenceManifest(input.sessionId, input.workflowId, input.target);
    const role = roleForDecisionItem(input.item);
    const record = await deps.spawnSubAgent(input.sessionId, role, [
      input.item.title,
      input.item.reason,
      `Target: ${input.item.target}`,
      `Use workflow evidence manifest first: ${evidenceManifest}`,
      "Return evidence-backed hypotheses, missing user context, safe validation steps, and stop conditions."
    ].join("\n"), [evidenceManifest], {
      description: input.item.title
    });
    deps.store.addEvidence({
      id: newId("evd"),
      sessionId: input.sessionId,
      workflowId: input.workflowId,
      source: `decision:subagent:${record.role}:${record.id}`,
      kind: "note",
      summary: record.resultSummary ?? record.progressSummary ?? "Decision subagent completed without a textual result.",
      data: deps.readSubAgentOutput(record) ?? record.resultSummary,
      createdAt: nowIso()
    });
    if (input.item.fallbackFor === "objective-model") {
      const objective = deps.buildSecurityObjectiveModel(input.sessionId, input.scope);
      const objectiveRun = createSecurityToolRun(deps.store, {
        sessionId: input.sessionId,
        workflowId: input.workflowId,
        toolId: "objective-model",
        phase: input.item.phase,
        origin: "manual",
        status: "success",
        inputKind: "target",
        inputCount: 1,
        outputSummary: objective.summary,
        findingCount: objective.objectives.filter((objectiveItem) => objectiveItem.evidence.length > 0).length
      });
      deps.store.addEvidence({
        id: newId("evd"),
        sessionId: input.sessionId,
        workflowId: input.workflowId,
        source: `decision:objective-model:${objectiveRun.id}`,
        kind: "note",
        summary: objective.summary,
        data: JSON.stringify(objective, null, 2),
        createdAt: nowIso()
      });
    }
    return `Subagent ${record.id} (${record.role}) finished with status ${record.status}.`;
  }

  if (input.item.actionType === "tool" && input.item.toolId) {
    return await deps.executeDecisionToolItem(input.sessionId, input.workflowId, input.target, input.scope, input.item);
  }

  return `Decision item type is not executable yet: ${input.item.actionType}`;
}

function summarizeAuthorizationValidationPlan(plan: unknown): string {
  const object = plan && typeof plan === "object" && !Array.isArray(plan) ? plan as Record<string, unknown> : {};
  const summary = object.summary && typeof object.summary === "object" && !Array.isArray(object.summary) ? object.summary as Record<string, unknown> : {};
  const candidates = Array.isArray(object.candidates) ? object.candidates : [];
  const ready = numberValue(summary.ready) ?? 0;
  const blocked = numberValue(summary.blocked) ?? 0;
  const needsExample = numberValue(summary.needsExample) ?? 0;
  const passiveOnly = numberValue(summary.passiveOnly) ?? 0;
  const compared = numberValue(summary.compared) ?? 0;
  const lines = [
    `Authorization validation plan generated: total=${numberValue(summary.total) ?? candidates.length} ready=${ready} blocked=${blocked} needsExample=${needsExample} passive=${passiveOnly} compared=${compared}.`
  ];
  for (const candidate of candidates.slice(0, 8)) {
    const candidateObject = candidate && typeof candidate === "object" && !Array.isArray(candidate) ? candidate as Record<string, unknown> : {};
    lines.push(`- ${stringValue(candidateObject.status) ?? "unknown"} | ${stringValue(candidateObject.method) ?? "ANY"} ${stringValue(candidateObject.pathTemplate) ?? "unknown"} | categories:${stringArray(candidateObject.categories).join(",") || "authz"}`);
  }
  return truncateForContext(lines.join("\n"), 2000);
}

function authorizationValidationPlanFindingCount(plan: unknown): number {
  const object = plan && typeof plan === "object" && !Array.isArray(plan) ? plan as Record<string, unknown> : {};
  const candidates = Array.isArray(object.candidates) ? object.candidates : [];
  return candidates.filter((candidate) => {
    const candidateObject = candidate && typeof candidate === "object" && !Array.isArray(candidate) ? candidate as Record<string, unknown> : {};
    return stringValue(candidateObject.status) === "ready_for_readonly_comparison";
  }).length;
}

function numberValue(value: unknown): number | undefined {
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function stringArray(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
}

function recordBlockedManualDecision(
  deps: DecisionItemDependencies,
  input: ExecuteSecurityDecisionItemInput,
  toolId: string,
  error: unknown
): string {
  const message = error instanceof Error ? error.message : String(error);
  deps.store.addEvidence({
    id: newId("evd"),
    sessionId: input.sessionId,
    workflowId: input.workflowId,
    source: `decision:manual-blocked:${toolId}`,
    kind: "note",
    summary: `${toolId} decision item blocked by local tool/runtime availability.`,
    data: JSON.stringify({
      item: input.item,
      toolId,
      reason: message
    }, null, 2),
    createdAt: nowIso()
  });
  return `${toolId} decision item blocked by local tool/runtime availability: ${truncateForContext(message, 1000)}`;
}
