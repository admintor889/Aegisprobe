import type { ContextFile, TargetInput } from "@aegisprobe/shared";
import type { PentestScope } from "@aegisprobe/security";
import { truncateForContext } from "@aegisprobe/shared";
import { renderToolDefinitions } from "./tool-definitions.js";
import { renderPentestSystemPromptFromPack, renderPentestUserPromptFromPack, renderPromptPackTemplate } from "./prompt-pack.js";

export function buildMainDecisionSystemPrompt(toolManifest: string): string {
  return renderPromptPackTemplate("main-decision/system.md", {
    TOOL_MANIFEST: toolManifest
  });
}

export function buildMainDecisionUserPrompt(input: {
  contextSnapshotPrompt: string;
  userInput: string;
  target: TargetInput;
  contexts: ContextFile[];
  observations: string[];
  securityWorkflowContext: string;
  iteration: number;
}): string {
  return truncateForContext(renderPromptPackTemplate("main-decision/user.md", {
    SESSION_CONTEXT: input.contextSnapshotPrompt,
    USER_INPUT: input.userInput,
    TARGET_KIND: input.target.kind,
    TARGET: input.target.normalized,
    FILE_CONTEXT: input.contexts.length > 0
      ? input.contexts.map((ctx) => `FILE ${ctx.path}\n${ctx.content}`).join("\n\n")
      : "No file context.",
    OBSERVATIONS: input.observations.length > 0
      ? input.observations.join("\n\n")
      : "No observations yet.",
    SECURITY_WORKFLOW_CONTEXT: input.securityWorkflowContext,
    ITERATION: String(input.iteration)
  }));
}

export function buildPentestDecisionSystemPrompt(input: {
  skillContext: string;
  hasMcpManager: boolean;
}): string {
  return renderPentestSystemPromptFromPack({
    skillContext: input.skillContext,
    hasMcpManager: input.hasMcpManager,
    controlledTools: renderToolDefinitions()
  });
}

export function buildPentestDecisionUserPrompt(input: {
  target: TargetInput;
  scope: PentestScope;
  iteration: number;
  observations: string[];
  contextSnapshotPrompt: string;
}): string {
  return truncateForContext(renderPentestUserPromptFromPack({
    target: input.target.normalized,
    active: String(input.scope.allowActiveProbing),
    profile: input.scope.scanProfile,
    iteration: String(input.iteration + 1),
    latestObservations: input.observations.length > 0
      ? input.observations.slice(-8).join("\n\n")
      : "No observations yet.",
    sessionContext: input.contextSnapshotPrompt.slice(0, 8000)
  }));
}
