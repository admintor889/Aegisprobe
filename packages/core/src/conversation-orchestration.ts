import { CodexLikeContextManager, updateSessionMemory, type ContextMessage, type ContextSnapshot } from "@aegisprobe/context";
import { MissingProviderKeyError, type OpenAICompatibleProvider } from "@aegisprobe/provider";
import { type SkillRegistry } from "@aegisprobe/skills";
import { buildMainDecisionSystemPrompt, buildMainDecisionUserPrompt } from "./decision-prompts.js";
import { buildFallbackDecision, buildFallbackPlan } from "./fallback-utils.js";
import { inferIntent, stepsFromText } from "./intent-utils.js";
import { nowIso, readContextFile, truncateForContext, type AgentDecision, type AgentPlan, type ContextFile, type TargetInput, type TurnEventKind } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { renderPromptPackTemplate } from "./prompt-pack.js";

export async function buildContext(target: TargetInput): Promise<ContextFile[]> {
  if (target.kind !== "file") {
    return [];
  }
  return [await readContextFile(target.normalized)];
}

export async function buildFileContexts(filePaths: string[]): Promise<ContextFile[]> {
  const contexts: ContextFile[] = [];
  for (const filePath of filePaths) {
    try {
      contexts.push(await readContextFile(filePath));
    } catch {
      // Missing or inaccessible files should not prevent normal conversation.
    }
  }
  return contexts;
}

export async function answerConversation(
  provider: OpenAICompatibleProvider,
  input: string,
  contextSnapshot: ContextSnapshot
): Promise<string> {
  try {
    const response = await provider.complete([
      {
        role: "system",
        content: renderPromptPackTemplate("conversation/answer-system.md")
      },
      {
        role: "user",
        content: renderPromptPackTemplate("conversation/answer-user.md", {
          SESSION_CONTEXT: contextSnapshot.prompt,
          USER_INPUT: input
        })
      }
    ]);
    return response || "I am AegisProbe, a Codex-like terminal assistant.";
  } catch {
    return "I am AegisProbe, a Codex-like terminal assistant. You can chat normally or give me a task, URL, domain, or file path.";
  }
}

export async function createPlan(
  provider: OpenAICompatibleProvider,
  store: AuditStore,
  buildSnapshot: (sessionId: string, overrides?: {
    currentInput?: string;
    currentTarget?: TargetInput;
    fileContexts?: ContextFile[];
    turnObservations?: string[];
    skillContext?: string;
    securityWorkflowContext?: string;
  }) => ContextSnapshot,
  sessionId: string,
  input: string,
  target: TargetInput,
  contexts: ContextFile[]
): Promise<AgentPlan> {
  const fallback = buildFallbackPlan(sessionId, input, target);
  try {
    const providerText = await provider.complete([
      {
        role: "system",
        content: renderPromptPackTemplate("conversation/plan-system.md")
      },
      {
        role: "user",
        content: renderPromptPackTemplate("conversation/plan-user.md", {
          SESSION_CONTEXT: buildSnapshot(sessionId, { currentInput: input, currentTarget: target, fileContexts: contexts }).prompt,
          USER_INPUT: input,
          TARGET_KIND: target.kind,
          TARGET: target.normalized,
          FILE_CONTEXT: contexts.length > 0
            ? contexts.map((ctx) => `FILE ${ctx.path}\n${ctx.content}`).join("\n\n")
            : "No file context."
        })
      }
    ]);
    return {
      ...fallback,
      summary: providerText || fallback.summary,
      steps: stepsFromText(providerText) ?? fallback.steps
    };
  } catch (error) {
    if (error instanceof MissingProviderKeyError) {
      return {
        ...fallback,
        summary: `${fallback.summary}\n\nProvider is not configured: ${error.message}`
      };
    }
    return {
      ...fallback,
      summary: `${fallback.summary}\n\nProvider request failed; using local fallback plan. ${(error as Error).message}`
    };
  }
}

export async function repairDecisionJson(
  provider: OpenAICompatibleProvider,
  rawResponse: string,
  parseError: unknown
): Promise<string> {
  return await provider.complete([
    {
      role: "system",
      content: renderPromptPackTemplate("conversation/json-repair-system.md")
    },
    {
      role: "user",
      content: renderPromptPackTemplate("conversation/json-repair-user.md", {
        PARSE_ERROR: parseError instanceof Error ? parseError.message : String(parseError),
        RAW_RESPONSE: rawResponse
      })
    }
  ]);
}

export async function sampleDecision(
  provider: OpenAICompatibleProvider,
  deps: {
    renderToolManifest: () => string;
    parseDecision: (text: string) => AgentDecision;
    repairDecisionJson: (rawResponse: string, parseError: unknown) => Promise<string>;
  },
  input: {
    userInput: string;
    target: TargetInput;
    contexts: ContextFile[];
    observations: string[];
    iteration: number;
    emit: (kind: TurnEventKind, message: string, payload?: unknown) => void;
    securityWorkflowContext: string;
    contextSnapshot: ContextSnapshot;
  }
): Promise<AgentDecision> {
  try {
    const response = await provider.complete([
      {
        role: "system",
        content: buildMainDecisionSystemPrompt(deps.renderToolManifest())
      },
      {
        role: "user",
        content: buildMainDecisionUserPrompt({
          contextSnapshotPrompt: input.contextSnapshot.prompt,
          userInput: input.userInput,
          target: input.target,
          contexts: input.contexts,
          observations: input.observations,
          securityWorkflowContext: input.securityWorkflowContext,
          iteration: input.iteration
        })
      }
    ]);
    try {
      return deps.parseDecision(response);
    } catch (parseError) {
      input.emit("decision_repair_requested", "Provider returned malformed decision JSON; requesting one repair attempt.", {
        iteration: input.iteration,
        error: parseError instanceof Error ? parseError.message : String(parseError)
      });
      const repaired = await deps.repairDecisionJson(response, parseError);
      input.emit("decision_repair_completed", "Provider decision JSON repair completed.", { iteration: input.iteration });
      const repairedDecision = deps.parseDecision(repaired);
      if (isRepairFailureDecision(repairedDecision)) {
        throw new Error(`Decision repair failed: ${repairedDecision.message}`);
      }
      return repairedDecision;
    }
  } catch (error) {
    return buildFallbackDecision({
      userInput: input.userInput,
      target: input.target,
      contexts: input.contexts,
      observations: input.observations,
      error,
      inferredIntent: inferIntent(input.userInput),
      securityWorkflowContext: input.securityWorkflowContext
    });
  }
}

function isRepairFailureDecision(decision: AgentDecision): boolean {
  return decision.final
    && decision.actions.length === 0
    && /\b(?:original response not provided|unable to repair|cannot repair|failed to repair|repair failed)\b/i.test(decision.message);
}

export function buildContextSnapshot(
  contextManager: CodexLikeContextManager,
  store: AuditStore,
  sessionId: string,
  renderTaskTreeContext: (sessionId: string) => string,
  overrides: {
    currentInput?: string;
    currentTarget?: TargetInput;
    fileContexts?: ContextFile[];
    turnObservations?: string[];
    skillContext?: string;
    securityWorkflowContext?: string;
    compactedMessages?: ContextMessage[];
  } = {}
): ContextSnapshot {
  const rawMessages = store.listMessages(sessionId, 240);
  const messages = overrides.compactedMessages ?? rawMessages;
  
  return contextManager.build({
    sessionId,
    memory: store.getSessionMemory(sessionId),
    messages,
    targets: store.listTargets(sessionId, 50),
    plans: store.listPlans(sessionId, 20),
    observations: store.listObservations(sessionId, 30),
    commands: store.listCommands(sessionId, 20),
    fileChanges: store.listFileChanges(sessionId, 20),
    subagents: store.listSubAgents(sessionId),
    securityWorkflows: store.listSecurityWorkflows(sessionId),
    findings: store.listFindings(sessionId),
    evidence: store.listEvidence(sessionId),
    assets: store.listAssets(sessionId),
    technologies: store.listTechnologies(sessionId),
    cveMatches: store.listCveMatches(sessionId),
    securityChecks: store.listSecurityChecks(sessionId),
    taskTreeContext: renderTaskTreeContext(sessionId),
    ...overrides
  });
}

export async function compactConversationIfNeeded(
  provider: OpenAICompatibleProvider,
  store: AuditStore,
  sessionId: string,
  messages: ContextMessage[],
  maxTotalTokens = 32_000
): Promise<ContextMessage[]> {
  let totalTokens = 0;
  for (const msg of messages) {
    totalTokens += Math.ceil(msg.content.length / 4);
  }
  if (totalTokens < maxTotalTokens) return messages;

  // Keep last ~30% of messages verbatim, summarize the rest
  const recentCount = Math.max(4, Math.floor(messages.length * 0.3));
  const recentMessages = messages.slice(-recentCount);
  const oldMessages = messages.slice(0, messages.length - recentCount);
  if (oldMessages.length <= 3) return messages;

  const oldText = oldMessages
    .map((m) => `[${m.role}]: ${m.content.slice(0, 2000)}`)
    .join("\n---\n");

  try {
    const summary = await provider.complete([
      {
        role: "system",
        content: renderPromptPackTemplate("conversation/compact-system.md")
      },
      {
        role: "user",
        content: renderPromptPackTemplate("conversation/compact-user.md", {
          MESSAGE_COUNT: String(oldMessages.length),
          OLD_TEXT: oldText
        })
      }
    ], { fast: true });

    const compacted = (summary || "").trim() || `PREVIOUS CONTEXT: ${oldMessages.length} earlier messages.`;
    const compactMessage: ContextMessage = {
      role: "user",
      content: compacted,
      createdAt: new Date().toISOString()
    };

    return [compactMessage, ...recentMessages];
  } catch {
    // If LLM call fails, keep recent messages only
    return recentMessages;
  }
}

export function refreshSessionMemory(store: AuditStore, sessionId: string): void {
  const memory = updateSessionMemory({
    sessionId,
    previous: store.getSessionMemory(sessionId),
    messages: store.listMessages(sessionId, 120),
    observations: store.listObservations(sessionId, 30),
    plans: store.listPlans(sessionId, 20),
    fileChanges: store.listFileChanges(sessionId, 20),
    commands: store.listCommands(sessionId, 20),
    subagents: store.listSubAgents(sessionId)
  });
  store.upsertSessionMemory(memory);
}

export async function renderSkillContext(skillRegistry: SkillRegistry, query: string): Promise<string> {
  try {
    return await skillRegistry.renderPrompt(query, {
      limit: 6,
      includeHighRisk: true
    });
  } catch (error) {
    return `Skill registry unavailable: ${error instanceof Error ? error.message : String(error)}`;
  }
}

export function renderRecentHistory(store: AuditStore, sessionId: string): string {
  const messages = store.getRecentMessages(sessionId, 16);
  if (messages.length === 0) {
    return "No recent conversation.";
  }
  return messages
    .map((message) => `${message.role}: ${truncateForContext(message.content, 1000)}`)
    .join("\n");
}
