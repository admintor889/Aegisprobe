import type { AgentAction, AgentDecision, FileEditOperation, SubAgentRole } from "@aegisprobe/shared";

export function parseDecisionLegacy(
  text: string,
  extractJsonObject: (text: string) => string,
  normalizeFileEditOperation: (operation: unknown) => FileEditOperation,
  normalizeSubAgentRole: (role: unknown) => SubAgentRole
): AgentDecision {
  const jsonText = extractJsonObject(text);
  const parsed = JSON.parse(jsonText) as Partial<AgentDecision>;
  const actions: AgentAction[] = [];
  if (Array.isArray(parsed.actions)) {
    for (const action of parsed.actions) {
      const raw = action && typeof action === "object" ? action as Record<string, unknown> : undefined;
      if (
        raw &&
        raw.type === "shell" &&
        typeof raw.command === "string"
      ) {
        actions.push({
          type: "shell",
          command: raw.command,
          purpose: typeof (action as { purpose?: unknown }).purpose === "string"
            ? (action as { purpose: string }).purpose
            : "Model requested shell command."
        });
        continue;
      }

      const toolUse = typeof raw?.tool_use === "string"
        ? raw.tool_use
        : typeof raw?.tool === "string"
          ? raw.tool
          : undefined;
      if (
        raw &&
        raw.type === "tool_use" &&
        toolUse
      ) {
        actions.push({
          type: "tool_use",
          tool_use: toolUse,
          input: typeof raw.input === "object" && raw.input !== null
            ? raw.input as Record<string, unknown>
            : {},
          purpose: typeof (action as { purpose?: unknown }).purpose === "string"
            ? (action as { purpose: string }).purpose
            : `Model requested controlled tool ${toolUse}.`
        });
        continue;
      }

      if (
        action &&
        typeof action === "object" &&
        (action as { type?: unknown }).type === "security_probe" &&
        typeof (action as { target?: unknown }).target === "string"
      ) {
        const probe = (action as { probe?: unknown }).probe;
        actions.push({
          type: "security_probe",
          target: (action as { target: string }).target,
          probe: probe === "dns" || probe === "http_headers" || probe === "basic_recon" ? probe : "basic_recon",
          purpose: typeof (action as { purpose?: unknown }).purpose === "string"
            ? (action as { purpose: string }).purpose
            : "Model requested a controlled security information-gathering probe."
        });
        continue;
      }

      if (
        action &&
        typeof action === "object" &&
        (action as { type?: unknown }).type === "ask_user" &&
        typeof (action as { question?: unknown }).question === "string"
      ) {
        actions.push({
          type: "ask_user",
          question: (action as { question: string }).question,
          reason: typeof (action as { reason?: unknown }).reason === "string"
            ? (action as { reason: string }).reason
            : "The agent needs more information to continue safely."
        });
      }

      if (
        action &&
        typeof action === "object" &&
        (action as { type?: unknown }).type === "read_file" &&
        typeof (action as { path?: unknown }).path === "string"
      ) {
        actions.push({
          type: "read_file",
          path: (action as { path: string }).path,
          purpose: typeof (action as { purpose?: unknown }).purpose === "string"
            ? (action as { purpose: string }).purpose
            : "Model requested a workspace file read."
        });
        continue;
      }

      if (
        action &&
        typeof action === "object" &&
        (action as { type?: unknown }).type === "list_files" &&
        typeof (action as { path?: unknown }).path === "string"
      ) {
        actions.push({
          type: "list_files",
          path: (action as { path: string }).path,
          recursive: Boolean((action as { recursive?: unknown }).recursive),
          purpose: typeof (action as { purpose?: unknown }).purpose === "string"
            ? (action as { purpose: string }).purpose
            : "Model requested a workspace directory listing."
        });
        continue;
      }

      if (
        action &&
        typeof action === "object" &&
        (action as { type?: unknown }).type === "file_edit" &&
        typeof (action as { path?: unknown }).path === "string"
      ) {
        actions.push({
          type: "file_edit",
          operation: normalizeFileEditOperation((action as { operation?: unknown }).operation),
          path: (action as { path: string }).path,
          content: typeof (action as { content?: unknown }).content === "string"
            ? (action as { content: string }).content
            : undefined,
          oldText: typeof (action as { oldText?: unknown }).oldText === "string"
            ? (action as { oldText: string }).oldText
            : undefined,
          newText: typeof (action as { newText?: unknown }).newText === "string"
            ? (action as { newText: string }).newText
            : undefined,
          purpose: typeof (action as { purpose?: unknown }).purpose === "string"
            ? (action as { purpose: string }).purpose
            : "Model requested a workspace file edit."
        });
        continue;
      }

      if (
        action &&
        typeof action === "object" &&
        (action as { type?: unknown }).type === "apply_patch" &&
        typeof (action as { patch?: unknown }).patch === "string"
      ) {
        actions.push({
          type: "apply_patch",
          patch: (action as { patch: string }).patch,
          purpose: typeof (action as { purpose?: unknown }).purpose === "string"
            ? (action as { purpose: string }).purpose
            : "Model requested a workspace patch."
        });
        continue;
      }

      if (
        action &&
        typeof action === "object" &&
        (action as { type?: unknown }).type === "subagent" &&
        typeof (action as { task?: unknown }).task === "string"
      ) {
        actions.push({
          type: "subagent",
          role: normalizeSubAgentRole((action as { role?: unknown }).role),
          task: (action as { task: string }).task,
          contextPaths: Array.isArray((action as { contextPaths?: unknown }).contextPaths)
            ? (action as { contextPaths: unknown[] }).contextPaths.filter((path): path is string => typeof path === "string")
            : undefined,
          background: Boolean((action as { background?: unknown; runInBackground?: unknown }).background ?? (action as { runInBackground?: unknown }).runInBackground)
        });
      }
    }
  }
  return {
    message: typeof parsed.message === "string" ? parsed.message : "Agent produced a decision.",
    plan: Array.isArray(parsed.plan) ? parsed.plan.filter((item): item is string => typeof item === "string") : [],
    actions,
    final: Boolean(parsed.final)
  };
}
