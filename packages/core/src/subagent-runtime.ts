import { mkdirSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { dirname, resolve } from "node:path";
import { MissingProviderKeyError, type OpenAICompatibleProvider } from "@aegisprobe/provider";
import { type McpManager } from "@aegisprobe/mcp";
import { type AgentAction, type ContextFile, type SubAgentRecord, type SubAgentRole, nowIso, extractFilePathMentions, newId, truncateForContext } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { parseSubAgentToolDecision as parseSubAgentToolDecisionFromTools, type SubAgentToolDecision } from "@aegisprobe/tools";
import type { SubAgentRoleDefinition } from "./subagent-roles.js";
import { subAgentRoleDefinitions } from "./subagent-roles.js";
import { formatToolResult, renderToolResult } from "./tool-result.js";
import { isWindowsShell } from "@aegisprobe/shell";
import { renderPromptPackTemplate } from "./prompt-pack.js";

export type SubAgentEmitter = (kind: string, message: string, payload?: unknown) => void;

export type SubAgentRunResult = {
  summary: string;
  toolUseCount: number;
  observations: string[];
};

export type SubAgentProgress = {
  message: string;
  phase: "started" | "thinking" | "tool_started" | "tool_completed" | "tool_blocked" | "completed";
  iteration?: number;
  toolUseCount: number;
};

type SubAgentToolExecutors = {
  readFile: (sessionId: string, path: string, purpose: string) => Promise<string>;
  listFiles: (sessionId: string, path: string, purpose: string, recursive: boolean) => Promise<string>;
  shell: (sessionId: string, emit: SubAgentEmitter, command: string, purpose: string) => Promise<string>;
  securityProbe: (
    sessionId: string,
    emit: SubAgentEmitter,
    target: string,
    probe: "basic_recon" | "dns" | "http_headers",
    purpose: string
  ) => Promise<string>;
  applyPatch: (sessionId: string, emit: SubAgentEmitter, patch: string, purpose: string) => Promise<string>;
};

export type SubAgentRuntimeDependencies = {
  store: AuditStore;
  provider: OpenAICompatibleProvider;
  mcpManager?: McpManager;
  renderDictContext: () => string;
  renderSkillContext: (query: string) => Promise<string>;
  buildFileContexts: (filePaths: string[]) => Promise<ContextFile[]>;
  summarizeContextsLocally: (contexts: ContextFile[], heading: string) => string;
  executors: SubAgentToolExecutors;
};

export class SubAgentRuntime {
  private readonly backgroundSubAgents = new Map<string, Promise<void>>();
  private readonly subAgentControllers = new Map<string, AbortController>();

  constructor(private readonly deps: SubAgentRuntimeDependencies) {}

  initializeOutput(record: SubAgentRecord): SubAgentRecord {
    const outputPath = record.outputPath ?? this.outputPath(record);
    this.deps.store.setSubAgentOutputPath(record.id, outputPath);
    const withOutput = { ...record, outputPath };
    this.writeOutput(withOutput, record.status, record.status === "queued" ? "Subagent is queued." : "Subagent is running.");
    return withOutput;
  }

  describeTask(role: SubAgentRole, task: string): string {
    const firstLine = task.split(/\r?\n/).find((line) => line.trim())?.trim() ?? "Delegated task";
    return `${subAgentRoleDefinitions[role].label}: ${firstLine.slice(0, 80)}`;
  }

  memoryKey(role: SubAgentRole, task: string): string {
    return `${role}:${createHash("sha256").update(task).digest("hex").slice(0, 12)}`;
  }

  deliverableTypeForRole(role: SubAgentRole): string | undefined {
    const map: Record<string, string> = {
      recon: "attack_surface",
      fingerprint: "service_enumeration",
      frontend: "entry_points",
      cve: "cve_matches",
      web_vuln: "web_findings",
      exploit: "exploitation_results"
    };
    return map[role];
  }

  defaultPriorityForRole(role: SubAgentRole): "critical" | "high" | "medium" | "low" {
    switch (role) {
      case "recon":
      case "cve":
      case "web_vuln":
      case "exploit":
        return "high";
      case "frontend":
      case "fingerprint":
      case "reviewer":
      case "worker":
        return "medium";
      case "explorer":
      case "default":
        return "low";
    }
  }

  trackBackground(agentId: string, run: Promise<string>): void {
    const tracked = run
      .then(() => undefined)
      .catch(() => undefined)
      .finally(() => {
        this.backgroundSubAgents.delete(agentId);
      });
    this.backgroundSubAgents.set(agentId, tracked);
  }

  abort(agentId: string): void {
    this.subAgentControllers.get(agentId)?.abort();
  }

  async wait(sessionId: string, agentId: string, timeoutMs = 60_000): Promise<SubAgentRecord | undefined> {
    const started = Date.now();
    const tracked = this.backgroundSubAgents.get(agentId);
    if (tracked) {
      await Promise.race([
        tracked,
        new Promise((resolve) => setTimeout(resolve, timeoutMs))
      ]);
      const record = this.deps.store.getSubAgent(agentId);
      return record?.sessionId === sessionId ? record : undefined;
    }

    while (Date.now() - started < timeoutMs) {
      const record = this.deps.store.getSubAgent(agentId);
      if (!record || record.sessionId !== sessionId) {
        return undefined;
      }
      if (record.status !== "running") {
        return record;
      }
      await new Promise((resolve) => setTimeout(resolve, 250));
    }
    const record = this.deps.store.getSubAgent(agentId);
    return record?.sessionId === sessionId ? record : undefined;
  }

  async runRecord(
    record: SubAgentRecord,
    definition: SubAgentRoleDefinition,
    task: string,
    contextPaths: string[],
    emit?: SubAgentEmitter,
    background = false,
    onReady?: () => void
  ): Promise<string> {
    const controller = new AbortController();
    this.subAgentControllers.set(record.id, controller);
    const timeoutMs = subAgentTimeoutMs(record.role, background);
    const timeout = setTimeout(() => {
      controller.abort(new Error(`Subagent timed out after ${timeoutMs}ms.`));
    }, timeoutMs);
    const progress = (update: SubAgentProgress) => {
      this.deps.store.updateSubAgentProgress(record.id, update.message, update.toolUseCount);
      const latest = this.deps.store.getSubAgent(record.id) ?? record;
      this.writeOutput(latest, "running", update.message);
      emit?.("subagent_progress", `Subagent progress: ${record.id}`, {
        id: record.id,
        phase: update.phase,
        iteration: update.iteration,
        toolUseCount: update.toolUseCount,
        message: update.message
      });
    };

    try {
      this.deps.store.heartbeatSubAgent(record.id, "Subagent execution started.", record.toolUseCount ?? 0);
      const contexts = await this.deps.buildFileContexts([...new Set([...(record.contextPaths ?? contextPaths), ...extractFilePathMentions(task)])]);
      const result = await this.run(
        record.sessionId,
        record.role,
        definition,
        task,
        contexts,
        background,
        controller.signal,
        progress,
        emit,
        onReady
      );
      if (this.deps.store.getSubAgent(record.id)?.status === "closed") {
        this.writeOutput(record, "closed", "Subagent completed after it was closed; result was discarded.");
        return `Subagent ${record.id} (${record.role}) completed after it was closed; result was discarded.`;
      }

      const obsSummary = result.observations.length > 0
        ? result.observations.slice(0, 20).map((item) => truncateForContext(item, 50_000)).join("\n")
        : "";
      const enrichedSummary = [result.summary, obsSummary ? `\nKey findings from tool outputs:\n${obsSummary}` : ""].filter(Boolean).join("\n");
      this.deps.store.updateSubAgentProgress(record.id, "Subagent completed.", result.toolUseCount);
      const completed = this.deps.store.getSubAgent(record.id) ?? { ...record, toolUseCount: result.toolUseCount };
      this.writeOutput(completed, "completed", enrichedSummary);
      this.deps.store.updateSubAgent(record.id, "completed", enrichedSummary);
      const deliverableType = this.deliverableTypeForRole(record.role);
      if (deliverableType) {
        this.deps.store.saveDeliverable(record.sessionId, record.role, deliverableType, {
          role: record.role,
          summary: result.summary,
          observations: result.observations.slice(0, 5),
          toolUseCount: result.toolUseCount
        }, result.summary.slice(0, 500));
      }
      this.deps.store.addObservation({
        id: newId("obs"),
        sessionId: record.sessionId,
        source: `subagent:${record.id}`,
        summary: enrichedSummary,
        createdAt: nowIso()
      });
      emit?.("subagent_completed", `Subagent completed: ${record.id}`, {
        id: record.id,
        role: record.role,
        toolUseCount: result.toolUseCount,
        summary: enrichedSummary
      });
      return `Subagent ${record.id} (${record.role}) completed.\n${enrichedSummary}`;
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (this.deps.store.getSubAgent(record.id)?.status !== "closed") {
        this.writeOutput(record, "failed", message);
        this.deps.store.updateSubAgent(record.id, "failed", message);
        if (this.deps.store.retrySubAgent(record.id, message)) {
          this.writeOutput({ ...record, status: "queued", progressSummary: `Retry queued: ${message}` }, "queued", `Retry queued after failure: ${message}`);
          emit?.("subagent_progress", `Subagent retry queued: ${record.id}`, { id: record.id, role: record.role, error: message });
          return `Subagent ${record.id} (${record.role}) failed and was re-queued for retry.\n${message}`;
        }
      } else {
        this.writeOutput(record, "closed", "Subagent was closed before completion.");
      }
      emit?.("subagent_failed", `Subagent failed: ${record.id}`, { id: record.id, role: record.role, error: message });
      return `Subagent ${record.id} (${record.role}) failed.\n${message}`;
    } finally {
      clearTimeout(timeout);
      this.subAgentControllers.delete(record.id);
    }
  }

  private outputPath(record: SubAgentRecord): string {
    return resolve("data", "subagents", record.sessionId, `${record.id}.md`);
  }

  private writeOutput(record: SubAgentRecord, status: string, body: string): void {
    const outputPath = record.outputPath ?? this.outputPath(record);
    mkdirSync(dirname(outputPath), { recursive: true });
    writeFileSync(outputPath, [
      `# Subagent ${record.id}`,
      "",
      `- Session: ${record.sessionId}`,
      `- Role: ${record.role}`,
      record.description ? `- Description: ${record.description}` : undefined,
      `- Status: ${status}`,
      `- Priority: ${record.priority ?? "medium"}`,
      `- Run mode: ${record.runMode ?? "foreground"}`,
      `- Retry: ${record.retryCount ?? 0}/${record.maxRetries ?? 0}`,
      `- Tool uses: ${record.toolUseCount ?? 0}`,
      record.lastHeartbeatAt ? `- Last heartbeat: ${record.lastHeartbeatAt}` : undefined,
      `- Updated: ${nowIso()}`,
      "",
      "## Task",
      "",
      record.task,
      "",
      "## Output",
      "",
      body
    ].filter((line): line is string => line !== undefined).join("\n"), "utf8");
  }

  private describeToolAction(action: SubAgentToolDecision["actions"][number]): string {
    const toolAction = action as AgentAction;
    if (toolAction.type === "apply_patch") {
      return "apply_patch: workspace patch";
    }
    if (toolAction.type === "shell") {
      return `shell: ${(toolAction as Extract<AgentAction, { type: "shell" }>).command.slice(0, 120)}`;
    }
    if (toolAction.type === "security_probe") {
      return `security_probe: ${(toolAction as Extract<AgentAction, { type: "security_probe" }>).target}`;
    }
    if (toolAction.type === "read_file" || toolAction.type === "list_files") {
      return `${toolAction.type}: ${(toolAction as Extract<AgentAction, { type: "read_file" | "list_files" }>).path}`;
    }
    return `${toolAction.type}`;
  }

  private async run(
    sessionId: string,
    role: SubAgentRole,
    definition: SubAgentRoleDefinition,
    task: string,
    contexts: ContextFile[],
    background: boolean,
    signal?: AbortSignal,
    onProgress?: (progress: SubAgentProgress) => void,
    emit?: SubAgentEmitter,
    onReady?: () => void
  ): Promise<SubAgentRunResult> {
    const observations: string[] = [];
    let toolUseCount = 0;
    const allowedTools = new Set(background ? definition.backgroundTools : definition.foregroundTools);
    const toolManifest = [...allowedTools].map((tool) => `- ${tool}`).join("\n");
    const dictContext = this.deps.renderDictContext();
    const skillContext = await this.deps.renderSkillContext([
      role,
      task,
      contexts.map((ctx) => `${ctx.path}\n${ctx.content.slice(0, 1000)}`).join("\n\n")
    ].join("\n\n"));
    const roleGuidance = renderPromptPackTemplate(definition.promptFile);
    const shellGuidance = allowedTools.has("shell")
      ? renderPromptPackTemplate(isWindowsShell() ? "subagents/shell/windows.md" : "subagents/shell/linux.md")
      : "";
    const mcpGuidance = allowedTools.has("mcp") ? renderPromptPackTemplate("subagents/mcp.md") : "";
    const actionFormat = renderPromptPackTemplate(allowedTools.has("mcp") ? "subagents/action-format-mcp.md" : "subagents/action-format-basic.md");

    try {
      onProgress?.({
        phase: "started",
        toolUseCount,
        message: `${definition.label} started. Allowed tools:\n${toolManifest}`
      });
      for (let iteration = 0; iteration < definition.maxIterations; iteration += 1) {
        if (signal?.aborted) {
          return {
            summary: `Subagent ${role} stopped because its runtime budget was exhausted.`,
            toolUseCount,
            observations
          };
        }
        onProgress?.({
          phase: "thinking",
          iteration: iteration + 1,
          toolUseCount,
          message: [
            `Iteration ${iteration + 1}/${definition.maxIterations} is running.`,
            observations.length > 0 ? `Latest observation:\n${observations.at(-1)}` : "No tool observations yet."
          ].join("\n\n")
        });
        const deliverables = this.deps.store.listDeliverables(sessionId);
        const deliverableContext = deliverables.length > 0
          ? `Available findings from previous agents:\n${deliverables.map((item) => `  [${item.type}] from ${item.role}: ${item.summary.slice(0, 200)}`).join("\n")}\nRead these with read_file data/subagents/... if you need full context.`
          : "No deliverables from other agents yet.";
        const systemPrompt = renderPromptPackTemplate("subagents/runtime-system.md", {
          ROLE_LABEL: definition.label,
          ROLE_GUIDANCE: roleGuidance,
          DELIVERABLE_CONTEXT: deliverableContext,
          SKILL_CONTEXT: skillContext.slice(0, 500),
          DICT_CONTEXT: dictContext ? dictContext.slice(0, 300) : "",
          TOOL_MANIFEST: toolManifest,
          SHELL_GUIDANCE: shellGuidance,
          MCP_GUIDANCE: mcpGuidance,
          ACTION_FORMAT: actionFormat
        });
        const initialContext = contexts.length > 0
          ? contexts.map((ctx) => `FILE ${ctx.path}\n${ctx.content}`).join("\n\n")
          : "No initial file context.";
        const observationContext = observations.length > 0
          ? observations.join("\n\n")
          : "No tool observations yet.";
        const userPrompt = renderPromptPackTemplate("subagents/runtime-user.md", {
          TASK: task,
          CONTEXT_FILES: initialContext,
          OBSERVATIONS: observationContext,
          ITERATION: String(iteration)
        });
        const completion = this.deps.provider.complete([
          {
            role: "system",
            content: systemPrompt
          },
          {
            role: "user",
            content: truncateForContext(userPrompt)
          }
        ], { signal, jsonMode: true, fast: false });
        onReady?.();
        onReady = undefined;
        const response = await completion;
        const decision = parseSubAgentToolDecisionFromTools(response);
        if (!decision) {
          const summary = response || "Subagent completed with no additional output.";
          onProgress?.({ phase: "completed", toolUseCount, message: summary });
          return { summary, toolUseCount, observations };
        }
        if (decision.actions.length === 0 || decision.final) {
          const summary = decision.message || "Subagent completed with no additional output.";
          onProgress?.({ phase: "completed", toolUseCount, message: summary });
          return { summary, toolUseCount, observations };
        }
        onProgress?.({
          phase: "tool_started",
          iteration: iteration + 1,
          toolUseCount,
          message: [
            decision.message || `Subagent requested ${decision.actions.length} tool action(s).`,
            ...decision.actions.map((action) => `- ${this.describeToolAction(action)}`)
          ].join("\n")
        });
        for (const action of decision.actions) {
          if (signal?.aborted) {
            return {
              summary: `Subagent ${role} stopped because its runtime budget was exhausted.`,
              toolUseCount,
              observations
            };
          }
          if (!allowedTools.has(action.type)) {
            const blocked = `Subagent tool blocked: ${action.type} is not allowed for ${role}${background ? " background" : ""} runs.`;
            observations.push(blocked);
            emit?.("subagent_tool_blocked", blocked, { role, tool: action.type, background });
            onProgress?.({ phase: "tool_blocked", iteration: iteration + 1, toolUseCount, message: blocked });
            continue;
          }
          toolUseCount += 1;
          emit?.("subagent_tool_started", `Subagent tool started: ${action.type}`, {
            role,
            tool: action.type,
            purpose: action.purpose
          });
          let observation: string;
          if (action.type === "read_file") {
            observation = await this.deps.executors.readFile(sessionId, action.path, action.purpose);
          } else if (action.type === "list_files") {
            observation = await this.deps.executors.listFiles(sessionId, action.path, action.purpose, Boolean(action.recursive));
          } else if (action.type === "shell" && "command" in action) {
            const raw = await this.deps.executors.shell(sessionId, emit ?? (() => undefined), action.command, action.purpose);
            observation = renderToolResult(formatToolResult("shell", action.command, raw));
          } else if (action.type === "security_probe" && "target" in action && "probe" in action) {
            const raw = await this.deps.executors.securityProbe(sessionId, emit ?? (() => undefined), action.target, action.probe, action.purpose);
            observation = renderToolResult(formatToolResult("security_probe", `${action.probe} ${action.target}`, raw));
          } else if (action.type === "mcp" && "tool" in action && "args" in action) {
            if (!this.deps.mcpManager) {
              observation = JSON.stringify({ tool: "mcp", action: action.tool, status: "error", hint: "MCP not configured." });
            } else {
              const mcpResult = await withTimeout(
                this.deps.mcpManager.callTool(action.tool, action.args),
                30_000,
                `MCP ${action.tool} timed out after 30000ms.`
              );
              observation = renderToolResult(formatToolResult("mcp", action.tool, mcpResult));
            }
          } else {
            observation = await this.deps.executors.applyPatch(sessionId, emit ?? (() => undefined), action.patch ?? "", action.purpose);
          }
          observations.push(observation);
          emit?.("subagent_tool_completed", `Subagent tool completed: ${action.type}`, {
            role,
            tool: action.type,
            toolUseCount,
            observation
          });
          onProgress?.({
            phase: "tool_completed",
            iteration: iteration + 1,
            toolUseCount,
            message: `Completed ${action.type}.\n${observation}`
          });
          if (signal?.aborted) {
            return {
              summary: `Subagent ${role} stopped because its runtime budget was exhausted.`,
              toolUseCount,
              observations
            };
          }
        }
      }
      const summary = observations.length > 0
        ? `Subagent reached its tool iteration limit. Last observation:\n${observations.at(-1)}`
        : "Subagent reached its iteration limit without producing findings.";
      return { summary, toolUseCount, observations };
    } catch (error) {
      const err = error instanceof Error ? error : new Error(String(error));
      const isProviderError = err instanceof MissingProviderKeyError || /provider|fetch|network|abort|timeout|rate.?limit/i.test(err.message);
      if (isProviderError) {
        return {
          summary: `Subagent ${role} FAILED (provider error): ${err.message}. This subagent did NOT complete its task.`,
          toolUseCount,
          observations
        };
      }
      if (contexts.length > 0) {
        return {
          summary: this.deps.summarizeContextsLocally(contexts, `Subagent ${role} local fallback (non-provider error: ${err.message}) for task: ${task}`),
          toolUseCount,
          observations
        };
      }
      return { summary: `Subagent ${role} failed: ${err.message}`, toolUseCount, observations };
    }
  }
}

function subAgentTimeoutMs(role: SubAgentRole, background: boolean): number {
  if (background) return 90_000;
  switch (role) {
    case "recon":
    case "frontend":
    case "cve":
    case "web_vuln":
    case "exploit":
      return 150_000;
    default:
      return 120_000;
  }
}

async function withTimeout<T>(work: Promise<T>, timeoutMs: number, message: string): Promise<T> {
  let timeout: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      work,
      new Promise<T>((_, reject) => {
        timeout = setTimeout(() => reject(new Error(message)), timeoutMs);
      })
    ]);
  } finally {
    if (timeout) clearTimeout(timeout);
  }
}
