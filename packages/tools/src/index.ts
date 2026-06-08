import type { AgentAction, AgentDecision, FileEditOperation, SubAgentRole } from "@aegisprobe/shared";

export type AgentToolName = Exclude<AgentAction["type"], "ask_user" | "none">;

export type ToolDefinition = {
  name: AgentToolName | "ask_user";
  description: string;
  approval: "none" | "shell" | "file_change" | "network";
  parallelSafe: boolean;
};

export type SubAgentToolDecision = {
  message: string;
  actions: Array<
    | Extract<AgentAction, { type: "read_file" }>
    | Extract<AgentAction, { type: "list_files" }>
    | Extract<AgentAction, { type: "apply_patch" }>
    | Extract<AgentAction, { type: "shell" }>
    | Extract<AgentAction, { type: "security_probe" }>
    | Extract<AgentAction, { type: "mcp" }>
  >;
  final: boolean;
};

export const defaultToolDefinitions: ToolDefinition[] = [
  {
    name: "mcp",
    description: "Call MCP (Model Context Protocol) tools — browser automation via Playwright, external APIs, etc.",
    approval: "none",
    parallelSafe: true
  },
  {
    name: "list_files",
    description: "Inspect workspace directories without shell approval.",
    approval: "none",
    parallelSafe: true
  },
  {
    name: "read_file",
    description: "Read allowed workspace files without shell approval.",
    approval: "none",
    parallelSafe: true
  },
  {
    name: "apply_patch",
    description: "Make Codex-style workspace file changes through approval.",
    approval: "file_change",
    parallelSafe: false
  },
  {
    name: "file_edit",
    description: "Legacy structured file edit path; prefer apply_patch for model edits.",
    approval: "file_change",
    parallelSafe: false
  },
  {
    name: "security_probe",
    description: "Run built-in low-risk DNS/HTTP information collection and store evidence.",
    approval: "network",
    parallelSafe: false
  },
  {
    name: "shell",
    description: "Run PowerShell commands through policy and approval.",
    approval: "shell",
    parallelSafe: false
  },
  {
    name: "subagent",
    description: "Delegate bounded analysis to concurrent workers.",
    approval: "none",
    parallelSafe: true
  },
  {
    name: "ask_user",
    description: "Request missing user information.",
    approval: "none",
    parallelSafe: false
  }
];

export function renderToolManifest(definitions: ToolDefinition[] = defaultToolDefinitions): string {
  return definitions
    .map((definition) => {
      const approval = definition.approval === "none" ? "" : ` Approval: ${definition.approval}.`;
      const parallel = definition.parallelSafe ? " Parallel-safe." : "";
      return `- ${definition.name}: ${definition.description}${approval}${parallel}`;
    })
    .join("\n");
}

export function parseAgentDecision(text: string): AgentDecision {
  const jsonText = extractJsonObject(text);
  const parsed = JSON.parse(jsonText) as Partial<AgentDecision>;
  return {
    message: typeof parsed.message === "string" ? parsed.message : "Agent produced a decision.",
    plan: Array.isArray(parsed.plan) ? parsed.plan.filter((item): item is string => typeof item === "string") : [],
    actions: parseAgentActions(parsed.actions),
    final: Boolean(parsed.final)
  };
}

export function parseSubAgentToolDecision(text: string): SubAgentToolDecision | undefined {
  try {
    const jsonText = extractJsonObject(text);
    const parsed = JSON.parse(jsonText) as Partial<SubAgentToolDecision>;
    const actions = parseAgentActions(parsed.actions).filter((
      action
    ): action is SubAgentToolDecision["actions"][number] =>
      action.type === "read_file" || action.type === "list_files" || action.type === "apply_patch"
      || action.type === "shell" || action.type === "security_probe" || action.type === "mcp"
    );
    if (typeof parsed.message !== "string" && actions.length === 0 && !parsed.final) {
      return undefined;
    }
    return {
      message: typeof parsed.message === "string" ? parsed.message : "",
      actions,
      final: Boolean(parsed.final)
    };
  } catch {
    return undefined;
  }
}

export function extractJsonObject(text: string): string {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i)?.[1];
  const candidate = fenced ?? text;
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) {
    throw new Error("Provider did not return a JSON object decision.");
  }
  return candidate.slice(start, end + 1);
}

export function executableActions(actions: AgentAction[]): Array<Exclude<AgentAction, { type: "ask_user" | "none" }>> {
  return actions.filter((action): action is Exclude<AgentAction, { type: "ask_user" | "none" }> =>
    action.type !== "ask_user" && action.type !== "none"
  );
}

const PARALLEL_SAFE_ACTION_TYPES = new Set<AgentAction["type"]>(["subagent", "read_file", "list_files", "mcp"]);

export function canExecuteActionsInParallel(actions: Array<Exclude<AgentAction, { type: "ask_user" | "none" }>>): boolean {
  return actions.length > 0 && actions.every((action) => PARALLEL_SAFE_ACTION_TYPES.has(action.type));
}

export function splitParallelAndSequential(
  actions: Array<Exclude<AgentAction, { type: "ask_user" | "none" }>>
): { parallel: Array<Exclude<AgentAction, { type: "ask_user" | "none" }>>; sequential: Array<Exclude<AgentAction, { type: "ask_user" | "none" }>> } {
  const parallel: typeof actions = [];
  const sequential: typeof actions = [];
  for (const action of actions) {
    if (PARALLEL_SAFE_ACTION_TYPES.has(action.type)) {
      parallel.push(action);
    } else {
      sequential.push(action);
    }
  }
  return { parallel, sequential };
}

function parseAgentActions(rawActions: unknown): AgentAction[] {
  const actions: AgentAction[] = [];
  if (!Array.isArray(rawActions)) {
    return actions;
  }

  for (const action of rawActions) {
    if (!action || typeof action !== "object") {
      continue;
    }
    const raw = action as Record<string, unknown>;

    const type = raw.type;
    if (type === "shell" && typeof raw.command === "string") {
      actions.push({
        type: "shell",
        command: raw.command,
        purpose: stringField(action, "purpose", "Model requested shell command.")
      });
      continue;
    }

    if (type === "security_probe" && typeof (action as { target?: unknown }).target === "string") {
      const probe = (action as { probe?: unknown }).probe;
      actions.push({
        type: "security_probe",
        target: (action as { target: string }).target,
        probe: probe === "dns" || probe === "http_headers" || probe === "basic_recon" ? probe : "basic_recon",
        purpose: stringField(action, "purpose", "Model requested a controlled security information-gathering probe.")
      });
      continue;
    }

    if (type === "ask_user" && typeof (action as { question?: unknown }).question === "string") {
      actions.push({
        type: "ask_user",
        question: (action as { question: string }).question,
        reason: stringField(action, "reason", "The agent needs more information to continue safely.")
      });
      continue;
    }

    if (type === "read_file" && typeof (action as { path?: unknown }).path === "string") {
      actions.push({
        type: "read_file",
        path: (action as { path: string }).path,
        purpose: stringField(action, "purpose", "Model requested a workspace file read.")
      });
      continue;
    }

    if (type === "list_files" && typeof (action as { path?: unknown }).path === "string") {
      actions.push({
        type: "list_files",
        path: (action as { path: string }).path,
        recursive: Boolean((action as { recursive?: unknown }).recursive),
        purpose: stringField(action, "purpose", "Model requested a workspace directory listing.")
      });
      continue;
    }

    if (type === "file_edit" && typeof (action as { path?: unknown }).path === "string") {
      actions.push({
        type: "file_edit",
        operation: normalizeFileEditOperation((action as { operation?: unknown }).operation),
        path: (action as { path: string }).path,
        content: optionalStringField(action, "content"),
        oldText: optionalStringField(action, "oldText"),
        newText: optionalStringField(action, "newText"),
        purpose: stringField(action, "purpose", "Model requested a workspace file edit.")
      });
      continue;
    }

    if (type === "apply_patch" && typeof (action as { patch?: unknown }).patch === "string") {
      actions.push({
        type: "apply_patch",
        patch: (action as { patch: string }).patch,
        purpose: stringField(action, "purpose", "Model requested a workspace patch.")
      });
      continue;
    }

    if (type === "mcp" && typeof (action as { tool?: unknown }).tool === "string") {
      actions.push({
        type: "mcp",
        tool: (action as { tool: string }).tool,
        args: typeof (action as { args?: unknown }).args === "object" && (action as { args?: unknown }).args !== null
          ? (action as { args: Record<string, unknown> }).args
          : {},
        purpose: stringField(action, "purpose", "Model requested an MCP tool call.")
      });
      continue;
    }

    const toolUse = typeof raw.tool_use === "string"
      ? raw.tool_use
      : typeof raw.tool === "string"
        ? raw.tool
        : undefined;
    if (type === "tool_use" && toolUse) {
      actions.push({
        type: "tool_use",
        tool_use: toolUse,
        input: typeof raw.input === "object" && raw.input !== null
          ? raw.input as Record<string, unknown>
          : {},
        purpose: stringField(action, "purpose", `Model requested controlled tool ${toolUse}.`)
      });
      continue;
    }

    const task = typeof (action as { task?: unknown }).task === "string"
      ? (action as { task: string }).task
      : typeof (action as { prompt?: unknown }).prompt === "string"
        ? (action as { prompt: string }).prompt
        : undefined;
    if (type === "subagent" && task) {
      actions.push({
        type: "subagent",
        role: normalizeSubAgentRole((action as { role?: unknown; subagent_type?: unknown }).role ?? (action as { subagent_type?: unknown }).subagent_type),
        description: optionalStringField(action, "description"),
        task,
        contextPaths: Array.isArray((action as { contextPaths?: unknown }).contextPaths)
          ? (action as { contextPaths: unknown[] }).contextPaths.filter((path): path is string => typeof path === "string")
          : undefined,
        background: Boolean(
          (action as { background?: unknown; runInBackground?: unknown; run_in_background?: unknown }).background ??
          (action as { runInBackground?: unknown }).runInBackground ??
          (action as { run_in_background?: unknown }).run_in_background
        )
      });
    }
  }

  return actions;
}

function normalizeSubAgentRole(role: unknown): SubAgentRole {
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

function normalizeFileEditOperation(operation: unknown): FileEditOperation {
  return operation === "create" || operation === "overwrite" || operation === "append" || operation === "string_replace"
    ? operation
    : "string_replace";
}

function stringField(source: object, field: string, fallback: string): string {
  const value = (source as Record<string, unknown>)[field];
  return typeof value === "string" ? value : fallback;
}

function optionalStringField(source: object, field: string): string | undefined {
  const value = (source as Record<string, unknown>)[field];
  return typeof value === "string" ? value : undefined;
}
