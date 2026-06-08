// ── Tool Handler Registry ──
// Dependency-injected handler factory for all agent tool types.
//
// Design pattern (Dependency Injection):
//   Each handler is a thin adapter that validates the action type and delegates
//   to an injected implementation function. This keeps the tool dispatch logic
//   decoupled from MainAgent's internal wiring.
//
//   MainAgent constructor injects its private methods as dependencies:
//     createToolHandlers({ executeShellAction: this.executeShellAction, ... })
//   The handler adapts the generic (sessionId, emit, action) signature to the
//   specific implementation signature.
//
//   This pattern allows the same handler registry to be used by both MainAgent
//   and SubAgentRuntime without code duplication.

import type { McpManager } from "@aegisprobe/mcp";
import type { AgentAction, SubAgentRole } from "@aegisprobe/shared";
import type { AgentToolName } from "@aegisprobe/tools";
import type { SubAgentEmitter } from "./subagent-runtime.js";

/** Handler function signature: receives session, emitter, action, and context paths. */
export type AgentToolHandler = (
  sessionId: string,
  emit: SubAgentEmitter,
  action: AgentAction,
  defaultContextPaths: string[]
) => Promise<string>;

/** Dependencies that each handler needs to function. Injected by MainAgent constructor. */
type ToolHandlerDependencies = {
  mcpManager?: McpManager;
  executeSubAgentAction: (
    sessionId: string,
    emit: SubAgentEmitter,
    role: SubAgentRole,
    description: string | undefined,
    task: string,
    contextPaths: string[],
    background: boolean
  ) => Promise<string>;
  executeReadFileAction: (sessionId: string, emit: SubAgentEmitter, path: string, purpose: string) => Promise<string>;
  executeListFilesAction: (sessionId: string, emit: SubAgentEmitter, path: string, purpose: string, recursive: boolean) => Promise<string>;
  executeFileEditAction: (sessionId: string, emit: SubAgentEmitter, action: Extract<AgentAction, { type: "file_edit" }>) => Promise<string>;
  executeApplyPatchAction: (sessionId: string, emit: SubAgentEmitter, patch: string, purpose: string) => Promise<string>;
  executeShellAction: (sessionId: string, emit: SubAgentEmitter, command: string, purpose: string) => Promise<string>;
  executeSecurityProbeAction: (
    sessionId: string,
    emit: SubAgentEmitter,
    target: string,
    probe: Extract<AgentAction, { type: "security_probe" }>["probe"],
    purpose: string
  ) => Promise<string>;
};

export function createToolHandlers(deps: ToolHandlerDependencies): Record<AgentToolName, AgentToolHandler> {
  return {
    subagent: async (sessionId, emit, action, defaultContextPaths) => {
      if (action.type !== "subagent") {
        throw new Error("Invalid subagent action.");
      }
      return await deps.executeSubAgentAction(
        sessionId,
        emit,
        action.role,
        action.description,
        action.task,
        action.contextPaths ?? defaultContextPaths,
        Boolean(action.background)
      );
    },
    read_file: async (sessionId, emit, action) => {
      if (action.type !== "read_file") {
        throw new Error("Invalid read_file action.");
      }
      return await deps.executeReadFileAction(sessionId, emit, action.path, action.purpose);
    },
    list_files: async (sessionId, emit, action) => {
      if (action.type !== "list_files") {
        throw new Error("Invalid list_files action.");
      }
      return await deps.executeListFilesAction(sessionId, emit, action.path, action.purpose, Boolean(action.recursive));
    },
    file_edit: async (sessionId, emit, action) => {
      if (action.type !== "file_edit") {
        throw new Error("Invalid file_edit action.");
      }
      return await deps.executeFileEditAction(sessionId, emit, action);
    },
    apply_patch: async (sessionId, emit, action) => {
      if (action.type !== "apply_patch") {
        throw new Error("Invalid apply_patch action.");
      }
      return await deps.executeApplyPatchAction(sessionId, emit, action.patch, action.purpose);
    },
    shell: async (sessionId, emit, action) => {
      if (action.type !== "shell") {
        throw new Error("Invalid shell action.");
      }
      return await deps.executeShellAction(sessionId, emit, action.command, action.purpose);
    },
    security_probe: async (sessionId, emit, action) => {
      if (action.type !== "security_probe") {
        throw new Error("Invalid security_probe action.");
      }
      return await deps.executeSecurityProbeAction(sessionId, emit, action.target, action.probe, action.purpose);
    },
    mcp: async (sessionId, emit, action) => {
      void sessionId;
      if (action.type !== "mcp") throw new Error("Invalid mcp action.");
      if (!deps.mcpManager) return "MCP is not configured. Enable mcp in config.yaml.";
      const result = await deps.mcpManager.callTool(action.tool, action.args);
      emit("tool_completed", `MCP tool ${action.tool} completed.`, { tool: action.tool, result: result.slice(0, 500) });
      return `MCP ${action.tool}: ${result}`;
    },
    tool_use: async () => {
      throw new Error("tool_use actions must be resolved into concrete controlled actions before dispatch.");
    }
  };
}
