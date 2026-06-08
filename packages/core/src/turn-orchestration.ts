import { type ContextSnapshot } from "@aegisprobe/context";
import { newId, nowIso, parseTargetInput, type AgentPlan, type ContextFile, type IntentExtraction, type TargetInput, type TurnEvent, type TurnEventKind, type TurnResult } from "@aegisprobe/shared";
import type { OpenAICompatibleProvider } from "@aegisprobe/provider";
import type { AuditStore } from "@aegisprobe/storage";
import type { SubAgentEmitter } from "./subagent-runtime.js";
import { renderPromptPackTemplate } from "./prompt-pack.js";

type TurnDependencies = {
  provider: OpenAICompatibleProvider;
  store: AuditStore;
  onEvent?: (event: TurnEvent) => void;
  hasSession: (sessionId: string) => boolean;
  buildContextSnapshot: (sessionId: string, overrides?: {
    currentInput?: string;
    currentTarget?: TargetInput;
    fileContexts?: ContextFile[];
    turnObservations?: string[];
    skillContext?: string;
    securityWorkflowContext?: string;
  }) => ContextSnapshot;
  parseIntent: (input: string, text: string) => IntentExtraction;
  resolveIntentReferences: (intent: IntentExtraction, sessionId?: string) => IntentExtraction;
  fallbackIntent: (input: string) => IntentExtraction;
  buildContext: (target: TargetInput) => Promise<ContextFile[]>;
  buildFileContexts: (filePaths: string[]) => Promise<ContextFile[]>;
  createPlan: (sessionId: string, input: string, target: TargetInput, contexts: ContextFile[]) => Promise<AgentPlan>;
  renderSkillContext: (query: string) => Promise<string>;
  buildSecurityWorkflowContext: (
    sessionId: string,
    intent: string,
    target: TargetInput,
    emit: SubAgentEmitter
  ) => Promise<string>;
  answerConversation: (sessionId: string, input: string, contextSnapshot: ContextSnapshot) => Promise<string>;
  refreshSessionMemory: (sessionId: string) => void;
  sampleDecision: (
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
  ) => Promise<import("@aegisprobe/shared").AgentDecision>;
  executeDecisionTools: (
    sessionId: string,
    emit: SubAgentEmitter,
    actions: import("@aegisprobe/shared").AgentAction[],
    defaultContextPaths: string[]
  ) => Promise<string[]>;
};

export async function understandUserInput(
  deps: Pick<TurnDependencies, "provider" | "hasSession" | "buildContextSnapshot" | "parseIntent" | "resolveIntentReferences" | "fallbackIntent">,
  input: string,
  sessionId?: string
): Promise<IntentExtraction> {
  try {
    const existingContext = sessionId && deps.hasSession(sessionId)
      ? deps.buildContextSnapshot(sessionId, { currentInput: input }).prompt
      : "No existing session context.";
    const response = await deps.provider.complete([
      {
        role: "system",
        content: renderPromptPackTemplate("conversation/intent-system.md")
      },
      {
        role: "user",
        content: renderPromptPackTemplate("conversation/intent-user.md", {
          SESSION_CONTEXT: existingContext,
          USER_INPUT: input
        })
      }
    ]);
    return deps.resolveIntentReferences(deps.parseIntent(input, response), sessionId);
  } catch {
    return deps.resolveIntentReferences(deps.fallbackIntent(input), sessionId);
  }
}

export async function runInput(
  deps: Pick<TurnDependencies, "store" | "buildContext" | "createPlan" | "refreshSessionMemory">,
  sessionId: string,
  input: string
): Promise<AgentPlan> {
  deps.store.addMessage(sessionId, "user", input);
  const target = parseTargetInput(input);
  deps.store.addTarget(sessionId, target);
  const contexts = await deps.buildContext(target);
  const plan = await deps.createPlan(sessionId, input, target, contexts);
  deps.store.addPlan(plan);
  deps.store.addMessage(sessionId, "assistant", `${plan.summary}\n\n${plan.steps.map((step, index) => `${index + 1}. ${step}`).join("\n")}`);
  deps.refreshSessionMemory(sessionId);
  return plan;
}

export async function runTurn(
  deps: TurnDependencies & {
    understandUserInput: (input: string, sessionId?: string) => Promise<IntentExtraction>;
  },
  sessionId: string,
  input: string,
  maxIterations = 999
): Promise<TurnResult> {
  const turnId = deps.store.createTurn(sessionId);
  const events: TurnEvent[] = [];
  const emit: SubAgentEmitter = (kind, message, payload) => {
    const event: TurnEvent = {
      id: newId("evt"),
      sessionId,
      turnId,
      kind: kind as TurnEventKind,
      message,
      payload,
      createdAt: nowIso()
    };
    events.push(event);
    deps.store.addTurnEvent(event);
    deps.onEvent?.(event);
  };

  try {
    emit("turn_started", "Turn started.", { input });
    deps.store.addMessage(sessionId, "user", input);
    const intent = await deps.understandUserInput(input, sessionId);
    const target = intent.targets[0] ?? parseTargetInput(input);
    deps.store.addTarget(sessionId, target);
    for (const extraTarget of intent.targets.slice(1)) {
      deps.store.addTarget(sessionId, extraTarget);
    }

    const contexts = [
      ...(await deps.buildContext(target)),
      ...(await deps.buildFileContexts(intent.filePaths))
    ];
    emit("context_built", "Context built for current turn.", {
      intent,
      target,
      files: contexts.map((ctx) => ({ path: ctx.path, truncated: ctx.truncated, bytes: ctx.content.length }))
    });
    const skillContext = await deps.renderSkillContext([
      input,
      intent.intent,
      intent.constraints.join(" "),
      target.normalized,
      contexts.map((ctx) => ctx.path).join(" ")
    ].join("\n"));
    emit("skill_context_built", "Relevant skill context built for current turn.", { skillContext });
    const securityWorkflowContext = await deps.buildSecurityWorkflowContext(sessionId, intent.intent, target, emit);
    let contextSnapshot = deps.buildContextSnapshot(sessionId, {
      currentInput: input,
      currentTarget: target,
      fileContexts: contexts,
      skillContext,
      securityWorkflowContext
    });
    emit("context_built", "Codex-like context snapshot prepared.", {
      approxTokens: contextSnapshot.stats.approxTokens,
      maxTokens: contextSnapshot.stats.maxTokens,
      totalMessages: contextSnapshot.stats.totalMessages,
      includedMessages: contextSnapshot.stats.includedMessages,
      sections: contextSnapshot.sections.map((section: { title: string }) => section.title)
    });

    if (intent.intent === "conversation" && intent.targets.length === 0 && intent.filePaths.length === 0) {
      const message = await deps.answerConversation(sessionId, input, contextSnapshot);
      deps.store.addMessage(sessionId, "assistant", message);
      emit("agent_message", message);
      emit("turn_completed", "Conversation turn completed.", { intent });
      deps.store.updateTurnStatus(turnId, "completed");
      deps.refreshSessionMemory(sessionId);
      return {
        sessionId,
        turnId,
        status: "completed",
        finalMessage: message,
        events
      };
    }

    if (intent.needsClarification && intent.clarificationQuestion) {
      emit("user_input_requested", intent.clarificationQuestion, {
        question: intent.clarificationQuestion,
        reason: "The agent could not extract enough task detail from the conversation."
      });
      deps.store.updateTurnStatus(turnId, "needs_input");
      deps.refreshSessionMemory(sessionId);
      return {
        sessionId,
        turnId,
        status: "needs_input",
        finalMessage: `I need one clarification before continuing: ${intent.clarificationQuestion}`,
        requestedInput: {
          question: intent.clarificationQuestion,
          reason: "The agent could not extract enough task detail from the conversation."
        },
        events
      };
    }

    const observations: string[] = [];
    let finalMessage = "";
    let lastPlan: AgentPlan | undefined;

    for (let iteration = 0; iteration < maxIterations; iteration += 1) {
      contextSnapshot = deps.buildContextSnapshot(sessionId, {
        currentInput: input,
        currentTarget: target,
        fileContexts: contexts,
        turnObservations: observations,
        skillContext,
        securityWorkflowContext
      });
      const decision = await deps.sampleDecision(sessionId, input, target, contexts, observations, iteration, emit, skillContext, securityWorkflowContext, contextSnapshot);
      finalMessage = decision.message;
      deps.store.addMessage(sessionId, "assistant", decision.message);
      emit("agent_message", decision.message, { iteration });

      if (decision.plan.length > 0) {
        lastPlan = {
          id: newId("plan"),
          sessionId,
          goal: input,
          summary: decision.message,
          steps: decision.plan,
          suggestedCommands: decision.actions
            .filter((action) => action.type === "shell")
            .map((action) => action.command),
          createdAt: nowIso()
        };
        deps.store.addPlan(lastPlan);
        emit("plan_created", "Agent produced a plan.", { steps: decision.plan });
      }

      const userInputAction = decision.actions.find((action) => action.type === "ask_user");
      if (userInputAction?.type === "ask_user") {
        emit("user_input_requested", userInputAction.question, {
          question: userInputAction.question,
          reason: userInputAction.reason
        });
        deps.store.updateTurnStatus(turnId, "needs_input");
        deps.refreshSessionMemory(sessionId);
        return {
          sessionId,
          turnId,
          status: "needs_input",
          finalMessage: decision.message,
          requestedInput: {
            question: userInputAction.question,
            reason: userInputAction.reason
          },
          events
        };
      }

      const toolObservations = await deps.executeDecisionTools(sessionId, emit, decision.actions, intent.filePaths);
      if (toolObservations.length > 0) {
        observations.push(...toolObservations);
        continue;
      }

      if (decision.final || decision.actions.filter((action) => action.type !== "none").length === 0) {
        emit("turn_completed", "Turn completed without further tool calls.", { final: decision.final });
        deps.store.updateTurnStatus(turnId, "completed");
        deps.refreshSessionMemory(sessionId);
        return { sessionId, turnId, status: "completed", finalMessage, events };
      }
    }

    const completed = finalMessage || lastPlan?.summary || "Turn completed after reaching the iteration limit.";
    emit("turn_completed", "Turn completed after reaching the iteration limit.", { maxIterations });
    deps.store.updateTurnStatus(turnId, "completed");
    deps.refreshSessionMemory(sessionId);
    return { sessionId, turnId, status: "completed", finalMessage: completed, events };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    emit("turn_failed", message);
    deps.store.updateTurnStatus(turnId, "failed");
    throw error;
  }
}
