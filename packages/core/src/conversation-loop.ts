// ── Interactive Conversation Loop ──
// Replaces the autonomous pentest pipeline with an interactive turn-based loop.
//
// Pattern inspiration from Claude Code's query.ts:
//   1. Take user message + conversation history
//   2. Stream LLM response (text + tool calls)
//   3. Execute tools, feed results back, continue
//   4. Respect AbortSignal for user interrupts
//   5. Yield events for the UI to display

import type { ChatMessage, OpenAICompatibleProvider, StreamEvent } from "@aegisprobe/provider";
import type { McpManager } from "@aegisprobe/mcp";
import type { AuditStore } from "@aegisprobe/storage";
import { nowIso, newId } from "@aegisprobe/shared";
import { renderPromptPackTemplate } from "./prompt-pack.js";

// ── Types ──

export type ConversationMessage = {
  id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  /** Tool call ID (for tool results) */
  toolCallId?: string;
  /** Tool calls made by the assistant in this message */
  toolCalls?: Array<{ id: string; name: string; arguments: string }>;
  createdAt: string;
};

export type ConversationTurnEvent =
  | { kind: "text_start" }
  | { kind: "text_delta"; content: string }
  | { kind: "text_end" }
  | { kind: "tool_call_start"; id: string; name: string }
  | { kind: "tool_call_delta"; id: string; arguments: string }
  | { kind: "tool_call_end"; id: string; name: string; arguments: string }
  | { kind: "tool_execution_start"; id: string; name: string }
  | { kind: "tool_execution_end"; id: string; result: string; error?: boolean }
  | { kind: "turn_complete"; stopReason: string }
  | { kind: "turn_aborted" }
  | { kind: "turn_error"; error: string };

export type ConversationLoopOptions = {
  provider: OpenAICompatibleProvider;
  store: AuditStore;
  mcpManager?: McpManager;
  /** Current conversation messages (user + assistant + tool results) */
  messages: ConversationMessage[];
  /** System prompt for the agent personality */
  systemPrompt: string;
  /** Abort signal for user interrupt */
  signal?: AbortSignal;
  /** Tool executors */
  executeShell: (command: string, purpose: string) => Promise<string>;
  executeReadFile: (path: string, purpose: string) => Promise<string>;
  executeListFiles: (path: string, recursive: boolean) => Promise<string>;
  executeSecurityProbe: (target: string, probe: string) => Promise<string>;
  executeFofaSearch: (query: string, size?: number) => Promise<string>;
  executeWebFetch: (url: string, purpose: string) => Promise<string>;
  /** Max tool call rounds per turn (safety limit) */
  maxToolRounds?: number;
};

// ── Tool definitions for the LLM ──

const CONVERSATION_TOOLS = [
  {
    type: "function" as const,
    function: {
      name: "execute_shell",
      description:
        "Execute a shell command (PowerShell on Windows, bash on Linux). Use for file operations, running tools, git, npm, etc. Commands are subject to safety policy checks.",
      parameters: {
        type: "object" as const,
        properties: {
          command: { type: "string", description: "The full shell command to execute" },
          purpose: { type: "string", description: "Why this command is needed (one sentence)" }
        },
        required: ["command", "purpose"]
      }
    }
  },
  {
    type: "function" as const,
    function: {
      name: "read_file",
      description: "Read the contents of a file from the workspace. Returns file content with line numbers.",
      parameters: {
        type: "object" as const,
        properties: {
          path: { type: "string", description: "Path to the file (relative to project root or absolute)" },
          purpose: { type: "string", description: "Why you need to read this file" }
        },
        required: ["path", "purpose"]
      }
    }
  },
  {
    type: "function" as const,
    function: {
      name: "list_directory",
      description: "List files and subdirectories in a directory.",
      parameters: {
        type: "object" as const,
        properties: {
          path: { type: "string", description: "Directory path to list" },
          recursive: { type: "boolean", description: "Whether to list recursively", default: false }
        },
        required: ["path"]
      }
    }
  },
  {
    type: "function" as const,
    function: {
      name: "security_probe",
      description: "Perform a security probe: DNS lookups, HTTP header checks, or basic recon on a target.",
      parameters: {
        type: "object" as const,
        properties: {
          target: { type: "string", description: "URL or hostname to probe" },
          probe: {
            type: "string",
            description: "Probe type: basic_recon, dns, or http_headers",
            enum: ["basic_recon", "dns", "http_headers"]
          }
        },
        required: ["target", "probe"]
      }
    }
  },
  {
    type: "function" as const,
    function: {
      name: "fofa_search",
      description:
        "Search FOFA (network space search engine) for internet-connected assets. Use FOFA query syntax like domain=\"whu.edu.cn\", title=\"login\", server=\"nginx\", port=\"8080\", etc. Returns hosts with IP, port, title, and server info. Perfect for discovering subdomains, exposed services, and attack surface mapping.",
      parameters: {
        type: "object" as const,
        properties: {
          query: {
            type: "string",
            description: "FOFA query string, e.g. domain=\"whu.edu.cn\" or title=\"管理系统\" || cert=\"whu.edu.cn\""
          },
          size: {
            type: "number",
            description: "Max results to return (default 50, max 200)"
          }
        },
        required: ["query"]
      }
    }
  },
  {
    type: "function" as const,
    function: {
      name: "web_fetch",
      description:
        "Fetch the content of a URL and return visible text (scripts, styles, nav stripped). Use for analyzing web pages, checking technologies, finding endpoints, reading documentation, or verifying vulnerabilities. Returns text content of the page.",
      parameters: {
        type: "object" as const,
        properties: {
          url: { type: "string", description: "Full URL to fetch (http:// or https://)" },
          purpose: { type: "string", description: "Why you are fetching this URL" }
        },
        required: ["url", "purpose"]
      }
    }
  }
];

// ── System Prompt ──

function defaultConversationSystemPrompt(): string {
  return renderPromptPackTemplate("conversation/default-system.md");
}

// ── Core Loop ──

/**
 * Run a single conversation turn.
 *
 * Takes the user's input + conversation history, streams the LLM response,
 * executes any requested tools, feeds results back, and continues until
 * the LLM produces a natural stop or the abort signal fires.
 */
export async function* runConversationTurn(
  options: ConversationLoopOptions
): AsyncGenerator<ConversationTurnEvent> {
  const {
    provider,
    messages,
    systemPrompt,
    signal,
    executeShell,
    executeReadFile,
    executeListFiles,
    executeSecurityProbe,
    executeFofaSearch,
    executeWebFetch,
    maxToolRounds = 10
  } = options;

  // Build the API message array
  const apiMessages: ChatMessage[] = [
    { role: "system", content: systemPrompt || defaultConversationSystemPrompt() },
  ];
  for (const m of messages) {
    if (m.role === "system") continue; // system prompt already injected
    if (m.role === "tool") {
      apiMessages.push({
        role: "tool",
        content: m.content || "",
        tool_call_id: m.toolCallId ?? ""
      });
    } else if (m.role === "assistant" && m.toolCalls && m.toolCalls.length > 0) {
      apiMessages.push({
        role: "assistant",
        content: m.content || null,
        tool_calls: m.toolCalls.map((tc) => ({
          id: tc.id,
          type: "function" as const,
          function: { name: tc.name, arguments: tc.arguments }
        }))
      });
    } else {
      apiMessages.push({
        role: (m.role === "assistant" ? "assistant" : "user") as "assistant" | "user",
        content: m.content || ""
      });
    }
  }

  // Track accumulated response for this turn
  let accumulatedText = "";
  let accumulatedToolCalls: Array<{ id: string; name: string; arguments: string }> = [];

  for (let round = 0; round < maxToolRounds; round++) {
    // Check for abort before API call
    if (signal?.aborted) {
      yield { kind: "turn_aborted" };
      return;
    }

    accumulatedText = "";
    accumulatedToolCalls = [];

    try {
      let hasYieldedTextStart = false;
      const pendingToolCalls = new Map<number, { id: string; name: string; arguments: string }>();

      for await (const event of provider.streamComplete(apiMessages, {
        signal,
        tools: CONVERSATION_TOOLS,
        toolChoice: "auto"
      })) {
        // Check abort during streaming
        if (signal?.aborted) {
          yield { kind: "turn_aborted" };
          return;
        }

        switch (event.kind) {
          case "text_delta": {
            if (!hasYieldedTextStart) {
              yield { kind: "text_start" };
              hasYieldedTextStart = true;
            }
            accumulatedText += event.content;
            yield { kind: "text_delta", content: event.content };
            break;
          }

          case "tool_call_delta": {
            // Track tool call arguments
            if (event.id) {
              const idx = pendingToolCalls.size;
              let tc = [...pendingToolCalls.values()].find((t) => t.id === event.id);
              if (!tc) {
                tc = { id: event.id, name: event.name, arguments: "" };
                pendingToolCalls.set(idx, tc);
              }
              if (event.name) tc.name = event.name;
              tc.arguments += event.arguments;
            }
            break;
          }

          case "tool_call_finished": {
            accumulatedToolCalls.push({
              id: event.id,
              name: event.name,
              arguments: event.arguments
            });
            yield { kind: "tool_call_end", id: event.id, name: event.name, arguments: event.arguments };
            break;
          }

          case "message_stop": {
            if (hasYieldedTextStart) {
              yield { kind: "text_end" };
            }

            if (event.stopReason === "aborted") {
              yield { kind: "turn_aborted" };
              return;
            }

            // If there are no tool calls, the turn is complete
            if (accumulatedToolCalls.length === 0) {
              yield { kind: "turn_complete", stopReason: event.stopReason };
              return;
            }
            break;
          }

          case "error": {
            yield { kind: "turn_error", error: event.error };
            return;
          }
        }
      }

      // If no tool calls were accumulated, we're done
      if (accumulatedToolCalls.length === 0) {
        yield { kind: "turn_complete", stopReason: "end" };
        return;
      }

      // Execute tools and feed results back
      const toolResults: Array<{ toolCallId: string; role: "tool"; content: string }> = [];

      for (const tc of accumulatedToolCalls) {
        if (signal?.aborted) {
          yield { kind: "turn_aborted" };
          return;
        }

        yield { kind: "tool_execution_start", id: tc.id, name: tc.name };

        let result: string;
        let isError = false;

        try {
          const args = safeJsonParse(tc.arguments);

          switch (tc.name) {
            case "execute_shell": {
              result = await executeShell(String(args.command ?? ""), String(args.purpose ?? ""));
              break;
            }
            case "read_file": {
              result = await executeReadFile(String(args.path ?? ""), String(args.purpose ?? ""));
              break;
            }
            case "list_directory": {
              result = await executeListFiles(String(args.path ?? ""), Boolean(args.recursive));
              break;
            }
            case "security_probe": {
              result = await executeSecurityProbe(String(args.target ?? ""), String(args.probe ?? "basic_recon"));
              break;
            }
            case "fofa_search": {
              result = await executeFofaSearch(String(args.query ?? ""), args.size ? Number(args.size) : undefined);
              break;
            }
            case "web_fetch": {
              result = await executeWebFetch(String(args.url ?? ""), String(args.purpose ?? ""));
              break;
            }
            default: {
              result = `Unknown tool: ${tc.name}`;
              isError = true;
            }
          }
        } catch (err) {
          result = `Tool execution error: ${err instanceof Error ? err.message : String(err)}`;
          isError = true;
        }

        yield { kind: "tool_execution_end", id: tc.id, result, error: isError };

        toolResults.push({
          toolCallId: tc.id,
          role: "tool",
          content: isError ? `Error: ${result}` : result
        });
      }

      // Add assistant message (with tool calls) + tool results to apiMessages for next round
      apiMessages.push({
        role: "assistant",
        content: accumulatedText || null,
        tool_calls: accumulatedToolCalls.map((tc) => ({
          id: tc.id,
          type: "function" as const,
          function: { name: tc.name, arguments: tc.arguments }
        }))
      });

      for (const tr of toolResults) {
        apiMessages.push({
          role: "tool",
          content: tr.content,
          tool_call_id: tr.toolCallId
        });
      }

      // Continue loop for next round of tool calls
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      if (message.includes("abort") || signal?.aborted) {
        yield { kind: "turn_aborted" };
      } else {
        yield { kind: "turn_error", error: message };
      }
      return;
    }
  }

  // Max rounds reached
  yield {
    kind: "turn_complete",
    stopReason: `max_tool_rounds (${maxToolRounds})`
  };
}

function safeJsonParse(text: string): Record<string, unknown> {
  try {
    return JSON.parse(text);
  } catch {
    return {};
  }
}
