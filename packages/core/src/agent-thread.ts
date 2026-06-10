import type { OpenAICompatibleProvider } from "@aegisprobe/provider";
import { newId, nowIso } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import {
  runConversationTurn,
  type AgentThreadTool,
  type ConversationMessage,
  type ConversationTurnEvent
} from "./conversation-loop.js";
import { renderPromptPackTemplate } from "./prompt-pack.js";

export type AgentThreadOptions = {
  provider: OpenAICompatibleProvider;
  store: AuditStore;
  sessionId: string;
  systemPrompt: string;
  tools: AgentThreadTool[];
  compactionThresholdChars?: number;
  retainedContextChars?: number;
  maxActiveContextChars?: number;
  fullToolResultsToKeep?: number;
};

export type AgentThreadTurnOptions = {
  signal?: AbortSignal;
};

export class AgentThread {
  constructor(private readonly options: AgentThreadOptions) {}

  async *run(
    userInput: string,
    turnOptions: AgentThreadTurnOptions = {}
  ): AsyncGenerator<ConversationTurnEvent> {
    await this.compactIfNeeded(turnOptions.signal);
    const history = this.loadMessages();
    const userMessage: ConversationMessage = {
      id: newId("msg"),
      role: "user",
      content: userInput,
      createdAt: nowIso()
    };
    this.persistMessage(userMessage);

    for await (const event of runConversationTurn({
      provider: this.options.provider,
      messages: [...history, userMessage],
      systemPrompt: this.options.systemPrompt,
      tools: this.options.tools,
      signal: turnOptions.signal,
      maxActiveContextChars: this.options.maxActiveContextChars,
      fullToolResultsToKeep: this.options.fullToolResultsToKeep,
      onMessage: (message) => {
        this.persistMessage({
          ...message,
          id: newId(message.role === "tool" ? "tool" : "msg"),
          createdAt: nowIso()
        });
      }
    })) {
      yield event;
    }
  }

  clear(): void {
    this.options.store.clearConversationMessages(this.options.sessionId);
  }

  private loadMessages(): ConversationMessage[] {
    return this.options.store.listConversationMessages(this.options.sessionId, 2_000)
      .map((message) => ({
        ...message,
        role: message.role as ConversationMessage["role"]
      }));
  }

  private persistMessage(message: ConversationMessage): void {
    this.options.store.insertConversationMessage({
      ...message,
      sessionId: this.options.sessionId
    });
  }

  private async compactIfNeeded(signal?: AbortSignal): Promise<void> {
    const threshold = this.options.compactionThresholdChars ?? 140_000;
    const retainedChars = this.options.retainedContextChars ?? 60_000;
    const messages = this.loadMessages();
    const totalChars = messages.reduce((sum, message) => sum + messageChars(message), 0);
    if (totalChars < threshold || messages.length < 12) {
      return;
    }

    const splitIndex = findCompactionSplit(messages, retainedChars);
    if (splitIndex <= 0 || splitIndex >= messages.length) {
      return;
    }

    const oldMessages = messages.slice(0, splitIndex);
    const retainedMessages = messages.slice(splitIndex);
    const oldText = oldMessages.map(renderMessageForSummary).join("\n\n");
    const summary = await this.options.provider.complete([
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
    ], { signal, fast: true });

    const summaryMessage: ConversationMessage = {
      id: newId("summary"),
      role: "system",
      content: summary,
      createdAt: oldMessages.at(-1)?.createdAt ?? nowIso()
    };
    this.options.store.replaceConversationMessages(
      this.options.sessionId,
      [summaryMessage, ...retainedMessages]
    );
  }
}

function findCompactionSplit(messages: ConversationMessage[], retainedChars: number): number {
  let chars = 0;
  let candidate = messages.length;
  for (let index = messages.length - 1; index >= 0; index -= 1) {
    chars += messageChars(messages[index]!);
    if (chars > retainedChars) {
      candidate = index + 1;
      break;
    }
  }

  if (candidate >= messages.length) {
    return messages.length;
  }

  // Prefer to split at the next user message — always a clean API boundary.
  for (let index = candidate; index < messages.length; index += 1) {
    if (messages[index]!.role === "user") {
      return index;
    }
  }

  // No user message ahead. To prevent orphaned tool messages (a tool result
  // without its preceding assistant+tool_calls), skip past any leading tool
  // messages to the next non-tool message. This matches Codex and Claude Code
  // compaction behaviour where the split never breaks tool-call/tool-result
  // pairing.
  for (let index = candidate; index < messages.length; index += 1) {
    if (messages[index]!.role !== "tool") {
      return index;
    }
  }

  // All retained messages are tool results — include them in the summary
  // rather than sending orphaned tool messages to the API.
  return messages.length;
}

function renderMessageForSummary(message: ConversationMessage): string {
  const toolCalls = message.toolCalls?.length
    ? `\ntool_calls=${JSON.stringify(message.toolCalls)}`
    : "";
  const toolCallId = message.toolCallId ? ` tool_call_id=${message.toolCallId}` : "";
  return `[${message.role}${toolCallId}]\n${message.content}${toolCalls}`;
}

function toolCallChars(message: ConversationMessage): number {
  return message.toolCalls ? JSON.stringify(message.toolCalls).length : 0;
}

function messageChars(message: ConversationMessage): number {
  return message.content.length
    + (message.reasoningContent?.length ?? 0)
    + toolCallChars(message);
}
