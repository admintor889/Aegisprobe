import type { ChatMessage, OpenAICompatibleProvider, ToolDefinition } from "@aegisprobe/provider";
import type { AgentToolEnvelope } from "./agent-tool-envelope.js";
import { createAgentToolEnvelope, renderAgentToolEnvelope } from "./agent-tool-envelope.js";

export type ConversationMessage = {
  id: string;
  role: "user" | "assistant" | "system" | "tool";
  content: string;
  reasoningContent?: string;
  toolCallId?: string;
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

export type AgentThreadToolContext = {
  signal?: AbortSignal;
};

export type AgentThreadTool = {
  definition: ToolDefinition;
  execute: (
    args: Record<string, unknown>,
    context: AgentThreadToolContext
  ) => Promise<AgentToolEnvelope>;
};

export type ConversationLoopOptions = {
  provider: OpenAICompatibleProvider;
  messages: ConversationMessage[];
  systemPrompt: string;
  tools: AgentThreadTool[];
  signal?: AbortSignal;
  maxActiveContextChars?: number;
  fullToolResultsToKeep?: number;
  onMessage?: (message: Omit<ConversationMessage, "id" | "createdAt">) => void;
};

export async function* runConversationTurn(
  options: ConversationLoopOptions
): AsyncGenerator<ConversationTurnEvent> {
  const apiMessages = buildApiMessages(options.systemPrompt, options.messages);
  const toolDefinitions = options.tools.map((tool) => tool.definition);
  const toolsByName = new Map(options.tools.map((tool) => [tool.definition.function.name, tool]));

  // No hard round limit — the model decides when to stop by producing
  // text without further tool calls. The context window and token budget
  // provide natural back-pressure; compaction handles long sessions.
  while (true) {
    if (options.signal?.aborted) {
      yield { kind: "turn_aborted" };
      return;
    }

    let accumulatedText = "";
    let accumulatedReasoning = "";
    const accumulatedToolCalls: Array<{ id: string; name: string; arguments: string }> = [];
    let textStarted = false;
    let textEnded = false;
    let stopReason = "end";
    const announcedToolCalls = new Set<string>();
    const completedToolCalls = new Set<string>();

    try {
      const requestMessages = boundActiveToolContext(
        apiMessages,
        options.maxActiveContextChars ?? 180_000,
        options.fullToolResultsToKeep ?? 4
      );
      for await (const event of options.provider.streamComplete(requestMessages, {
        signal: options.signal,
        tools: toolDefinitions,
        toolChoice: "auto"
      })) {
        if (options.signal?.aborted) {
          yield { kind: "turn_aborted" };
          return;
        }

        if (event.kind === "text_delta") {
          if (!textStarted) {
            textStarted = true;
            yield { kind: "text_start" };
          }
          accumulatedText += event.content;
          yield { kind: "text_delta", content: event.content };
          continue;
        }

        if (event.kind === "reasoning_delta") {
          accumulatedReasoning += event.content;
          continue;
        }

        if (event.kind === "tool_call_finished") {
          if (completedToolCalls.has(event.id)) {
            continue;
          }
          completedToolCalls.add(event.id);
          if (!announcedToolCalls.has(event.id)) {
            announcedToolCalls.add(event.id);
            yield { kind: "tool_call_start", id: event.id, name: event.name };
          }
          accumulatedToolCalls.push({
            id: event.id,
            name: event.name,
            arguments: event.arguments
          });
          yield {
            kind: "tool_call_end",
            id: event.id,
            name: event.name,
            arguments: event.arguments
          };
          continue;
        }

        if (event.kind === "tool_call_delta") {
          if (event.id && !announcedToolCalls.has(event.id)) {
            announcedToolCalls.add(event.id);
            yield { kind: "tool_call_start", id: event.id, name: event.name };
          }
          if (event.id && event.arguments) {
            yield { kind: "tool_call_delta", id: event.id, arguments: event.arguments };
          }
          continue;
        }

        if (event.kind === "message_stop") {
          stopReason = event.stopReason;
          if (textStarted && !textEnded) {
            textEnded = true;
            yield { kind: "text_end" };
          }
          if (event.stopReason === "aborted") {
            yield { kind: "turn_aborted" };
            return;
          }
          continue;
        }

        if (event.kind === "error") {
          yield { kind: "turn_error", error: event.error };
          return;
        }
      }

      if (textStarted && !textEnded) {
        yield { kind: "text_end" };
      }
      const assistantMessage = {
        role: "assistant" as const,
        content: accumulatedText,
        ...(accumulatedToolCalls.length > 0 && accumulatedReasoning
          ? { reasoningContent: accumulatedReasoning }
          : {}),
        ...(accumulatedToolCalls.length > 0 ? { toolCalls: accumulatedToolCalls } : {})
      };
      if (accumulatedText || accumulatedToolCalls.length > 0) {
        options.onMessage?.(assistantMessage);
      }

      if (accumulatedToolCalls.length === 0) {
        yield { kind: "turn_complete", stopReason };
        return;
      }

      apiMessages.push({
        role: "assistant",
        content: accumulatedText || null,
        ...(accumulatedReasoning ? { reasoning_content: accumulatedReasoning } : {}),
        tool_calls: accumulatedToolCalls.map((toolCall) => ({
          id: toolCall.id,
          type: "function",
          function: { name: toolCall.name, arguments: toolCall.arguments }
        }))
      });

      for (const toolCall of accumulatedToolCalls) {
        if (options.signal?.aborted) {
          yield { kind: "turn_aborted" };
          return;
        }

        yield { kind: "tool_execution_start", id: toolCall.id, name: toolCall.name };
        const envelope = await executeToolCall(
          toolsByName,
          toolCall.name,
          toolCall.arguments,
          options.signal
        );
        const rendered = renderAgentToolEnvelope(envelope);
        options.onMessage?.({
          role: "tool",
          content: rendered,
          toolCallId: toolCall.id
        });
        apiMessages.push({
          role: "tool",
          content: rendered,
          tool_call_id: toolCall.id
        });
        yield {
          kind: "tool_execution_end",
          id: toolCall.id,
          result: rendered,
          error: envelope.status !== "success"
        };
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      if (options.signal?.aborted || /abort/i.test(message)) {
        yield { kind: "turn_aborted" };
      } else {
        yield { kind: "turn_error", error: message };
      }
      return;
    }
  }

  // Unreachable — the while(true) loop exits via return when the model
  // produces text without tool calls, or via turn_aborted/turn_error.
}

export function boundActiveToolContext(
  messages: ChatMessage[],
  maxChars: number,
  fullToolResultsToKeep: number
): ChatMessage[] {
  const bounded = messages.map((message) => ({
    ...message,
    ...(message.tool_calls ? {
      tool_calls: message.tool_calls.map((toolCall) => ({
        ...toolCall,
        function: { ...toolCall.function }
      }))
    } : {})
  }));
  if (chatMessageChars(bounded) <= maxChars) {
    return bounded;
  }

  const toolIndexes = bounded
    .map((message, index) => message.role === "tool" ? index : -1)
    .filter((index) => index >= 0);
  const initiallyCollapsible = toolIndexes.slice(0, Math.max(0, toolIndexes.length - fullToolResultsToKeep));
  const remaining = toolIndexes.slice(initiallyCollapsible.length);

  for (const index of initiallyCollapsible.concat(remaining)) {
    const message = bounded[index];
    if (!message || message.role !== "tool" || typeof message.content !== "string") continue;
    message.content = collapseToolEnvelope(message.content);
    if (chatMessageChars(bounded) <= maxChars) break;
  }
  return bounded;
}

function collapseToolEnvelope(content: string): string {
  try {
    const envelope = JSON.parse(content) as Record<string, unknown>;
    const metadata = isRecord(envelope.metadata) ? envelope.metadata : {};
    const rawArtifact = isRecord(metadata.rawArtifact) ? metadata.rawArtifact : undefined;
    if (!rawArtifact) return content;
    return JSON.stringify({
      version: envelope.version,
      tool: envelope.tool,
      status: envelope.status,
      startedAt: envelope.startedAt,
      endedAt: envelope.endedAt,
      durationMs: envelope.durationMs,
      exitCode: envelope.exitCode,
      stdout: "",
      stderr: "",
      artifacts: envelope.artifacts,
      truncated: envelope.truncated,
      metadata: {
        ...metadata,
        activeContext: "Preview omitted after it was observed. Exact bytes remain available through rawArtifact and artifact_read."
      }
    });
  } catch {
    return content;
  }
}

function chatMessageChars(messages: ChatMessage[]): number {
  return messages.reduce((sum, message) =>
    sum
    + (message.content?.length ?? 0)
    + (message.reasoning_content?.length ?? 0)
    + (message.tool_calls ? JSON.stringify(message.tool_calls).length : 0),
  0);
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function buildApiMessages(systemPrompt: string, messages: ConversationMessage[]): ChatMessage[] {
  const apiMessages: ChatMessage[] = [{ role: "system", content: systemPrompt }];
  for (const message of messages) {
    if (message.role === "system") {
      apiMessages.push({ role: "system", content: message.content });
    } else if (message.role === "tool") {
      apiMessages.push({
        role: "tool",
        content: message.content,
        tool_call_id: message.toolCallId ?? ""
      });
    } else if (message.role === "assistant" && message.toolCalls?.length) {
      apiMessages.push({
        role: "assistant",
        content: message.content || null,
        ...(message.reasoningContent ? { reasoning_content: message.reasoningContent } : {}),
        tool_calls: message.toolCalls.map((toolCall) => ({
          id: toolCall.id,
          type: "function",
          function: { name: toolCall.name, arguments: toolCall.arguments }
        }))
      });
    } else {
      apiMessages.push({
        role: message.role,
        content: message.content
      });
    }
  }
  return apiMessages;
}

async function executeToolCall(
  toolsByName: Map<string, AgentThreadTool>,
  name: string,
  rawArguments: string,
  signal?: AbortSignal
): Promise<AgentToolEnvelope> {
  const startedAt = new Date().toISOString();
  const tool = toolsByName.get(name);
  if (!tool) {
    return createAgentToolEnvelope({
      tool: name,
      status: "error",
      startedAt,
      stderr: `Unknown tool: ${name}`
    });
  }

  let args: Record<string, unknown>;
  try {
    const parsed = JSON.parse(rawArguments || "{}");
    args = parsed && typeof parsed === "object" && !Array.isArray(parsed)
      ? parsed as Record<string, unknown>
      : {};
  } catch (error) {
    return createAgentToolEnvelope({
      tool: name,
      status: "error",
      startedAt,
      stderr: `Invalid tool arguments: ${error instanceof Error ? error.message : String(error)}`,
      metadata: { rawArguments }
    });
  }

  try {
    return await tool.execute(args, { signal });
  } catch (error) {
    return createAgentToolEnvelope({
      tool: name,
      status: signal?.aborted ? "timeout" : "error",
      startedAt,
      stderr: error instanceof Error ? error.stack ?? error.message : String(error)
    });
  }
}
