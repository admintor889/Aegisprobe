import { canExecuteActionsInParallel, executableActions } from "@aegisprobe/tools";
import type { AgentAction } from "@aegisprobe/shared";

export type ToolActionHandler = (
  sessionId: string,
  emit: (kind: string, message: string, payload?: unknown) => void,
  action: AgentAction,
  defaultContextPaths: string[]
) => Promise<string>;

export async function executeDecisionTools(
  handlers: Record<string, ToolActionHandler>,
  sessionId: string,
  emit: (kind: string, message: string, payload?: unknown) => void,
  actions: AgentAction[],
  defaultContextPaths: string[]
): Promise<string[]> {
  const toolActions = executableActions(actions);
  if (toolActions.length === 0) {
    return [];
  }

  const hasForegroundSubAgent = toolActions.some((action) =>
    action.type === "subagent" && !Boolean(action.background)
  );
  if (!hasForegroundSubAgent && canExecuteActionsInParallel(toolActions)) {
    return await Promise.all(toolActions.map((action) =>
      handlers[action.type](sessionId, emit, action, defaultContextPaths)
    ));
  }

  const observations: string[] = [];
  for (const action of toolActions) {
    const handler = handlers[action.type];
    observations.push(await handler(sessionId, emit, action, defaultContextPaths));
  }
  return observations;
}
