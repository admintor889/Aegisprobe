import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import type { ChatMessage, OpenAICompatibleProvider, StreamEvent } from "@aegisprobe/provider";
import { AuditStore } from "@aegisprobe/storage";
import { AgentThread } from "./agent-thread.js";
import { AgentArtifactStore } from "./agent-artifacts.js";
import { createAgentToolEnvelope } from "./agent-tool-envelope.js";
import { boundActiveToolContext, type AgentThreadTool } from "./conversation-loop.js";

describe("AgentThread", () => {
  const workspaces: string[] = [];
  const stores: AuditStore[] = [];

  afterEach(() => {
    for (const store of stores.splice(0)) store.close();
    for (const workspace of workspaces.splice(0)) {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("persists assistant tool calls before their raw tool results", async () => {
    const { store, sessionId } = createStore();
    const provider = streamingProvider([
      [
        { kind: "tool_call_finished", id: "call-1", name: "echo_raw", arguments: "{\"value\":\"hello\"}" },
        { kind: "tool_call_finished", id: "call-1", name: "echo_raw", arguments: "{\"value\":\"hello\"}" },
        { kind: "message_stop", stopReason: "tool_calls" }
      ],
      [
        { kind: "text_delta", content: "Observed the raw result." },
        { kind: "message_stop", stopReason: "stop" }
      ]
    ]);
    let executions = 0;
    const tool: AgentThreadTool = {
      definition: {
        type: "function",
        function: {
          name: "echo_raw",
          description: "Return a raw value.",
          parameters: {
            type: "object",
            properties: { value: { type: "string" } },
            required: ["value"]
          }
        }
      },
      execute: async (args) => {
        executions += 1;
        return createAgentToolEnvelope({
          tool: "echo_raw",
          status: "success",
          startedAt: new Date().toISOString(),
          exitCode: 0,
          stdout: String(args.value),
          stderr: ""
        });
      }
    };
    const thread = new AgentThread({
      provider,
      store,
      sessionId,
      systemPrompt: "test system",
      tools: [tool]
    });

    for await (const _event of thread.run("inspect this")) {
      // Consume the turn.
    }

    const messages = store.listConversationMessages(sessionId);
    expect(messages.map((message) => message.role)).toEqual([
      "user",
      "assistant",
      "tool",
      "assistant"
    ]);
    expect(messages[1]?.toolCalls?.[0]).toMatchObject({ id: "call-1", name: "echo_raw" });
    expect(JSON.parse(messages[2]!.content)).toMatchObject({
      tool: "echo_raw",
      status: "success",
      exitCode: 0,
      stdout: "hello",
      stderr: ""
    });
    expect(messages[2]?.toolCallId).toBe("call-1");
    expect(executions).toBe(1);
  });

  it("compacts old turns into a system briefing while retaining recent complete turns", async () => {
    const { store, sessionId } = createStore();
    for (let index = 0; index < 14; index += 1) {
      store.insertConversationMessage({
        id: `old-${index}`,
        sessionId,
        role: index % 2 === 0 ? "user" : "assistant",
        content: `${index}:${"x".repeat(40)}`,
        createdAt: new Date(1_700_000_000_000 + index).toISOString()
      });
    }
    const captured: ChatMessage[][] = [];
    const provider = {
      complete: async () => "PREVIOUS CONTEXT: retained factual summary",
      streamComplete: async function* (messages: ChatMessage[]) {
        captured.push(messages);
        yield { kind: "text_delta", content: "continued" } satisfies StreamEvent;
        yield { kind: "message_stop", stopReason: "stop" } satisfies StreamEvent;
      }
    } as unknown as OpenAICompatibleProvider;
    const thread = new AgentThread({
      provider,
      store,
      sessionId,
      systemPrompt: "test system",
      tools: [],
      compactionThresholdChars: 200,
      retainedContextChars: 160
    });

    for await (const _event of thread.run("new input")) {
      // Consume the turn.
    }

    const messages = store.listConversationMessages(sessionId);
    expect(messages[0]).toMatchObject({
      role: "system",
      content: "PREVIOUS CONTEXT: retained factual summary"
    });
    expect(captured[0]?.[0]).toEqual({ role: "system", content: "test system" });
    expect(captured[0]?.[1]).toEqual({
      role: "system",
      content: "PREVIOUS CONTEXT: retained factual summary"
    });
    expect(messages.at(-2)).toMatchObject({ role: "user", content: "new input" });
    expect(messages.at(-1)).toMatchObject({ role: "assistant", content: "continued" });
  });

  it("replays provider reasoning state across tool rounds and later user turns", async () => {
    const { store, sessionId } = createStore();
    const captured: ChatMessage[][] = [];
    const rounds: StreamEvent[][] = [
      [
        { kind: "reasoning_delta", content: "retain this exact state" },
        { kind: "tool_call_finished", id: "call-1", name: "echo_raw", arguments: "{}" },
        { kind: "message_stop", stopReason: "tool_calls" }
      ],
      [
        { kind: "text_delta", content: "first answer" },
        { kind: "message_stop", stopReason: "stop" }
      ],
      [
        { kind: "text_delta", content: "second answer" },
        { kind: "message_stop", stopReason: "stop" }
      ]
    ];
    const provider = {
      streamComplete: async function* (messages: ChatMessage[]) {
        captured.push(messages);
        const events = rounds.shift();
        if (!events) throw new Error("No streaming round queued.");
        for (const event of events) yield event;
      }
    } as unknown as OpenAICompatibleProvider;
    const tool: AgentThreadTool = {
      definition: {
        type: "function",
        function: {
          name: "echo_raw",
          description: "Return an observation.",
          parameters: { type: "object", properties: {} }
        }
      },
      execute: async () => createAgentToolEnvelope({
        tool: "echo_raw",
        status: "success",
        startedAt: new Date().toISOString(),
        stdout: "ok"
      })
    };
    const thread = new AgentThread({
      provider,
      store,
      sessionId,
      systemPrompt: "test system",
      tools: [tool]
    });

    for await (const _event of thread.run("first")) {}
    for await (const _event of thread.run("second")) {}

    const toolRoundAssistant = captured[1]?.find((message) => message.role === "assistant" && message.tool_calls);
    const laterTurnAssistant = captured[2]?.find((message) => message.role === "assistant" && message.tool_calls);
    expect(toolRoundAssistant?.reasoning_content).toBe("retain this exact state");
    expect(laterTurnAssistant?.reasoning_content).toBe("retain this exact state");
    expect(store.listConversationMessages(sessionId).find((message) => message.toolCalls)?.reasoningContent)
      .toBe("retain this exact state");
  });

  it("preserves exact large output and bounds older active previews", () => {
    const workspace = mkdtempSync(join(tmpdir(), "aegisprobe-artifact-"));
    workspaces.push(workspace);
    const artifacts = new AgentArtifactStore(workspace, "session-1");
    const original = `${"A".repeat(40_000)}middle${"Z".repeat(40_000)}`;
    const preserved = artifacts.preserve(createAgentToolEnvelope({
      tool: "large_result",
      status: "success",
      startedAt: new Date().toISOString(),
      stdout: original
    }));
    const reference = preserved.metadata?.rawArtifact as { path: string };
    const rawEnvelope = JSON.parse(readFileSync(reference.path, "utf8")) as { stdout: string };
    expect(rawEnvelope.stdout).toBe(original);
    expect(preserved.stdout.length).toBeLessThan(original.length);

    const messages: ChatMessage[] = [
      { role: "system", content: "system" },
      { role: "tool", tool_call_id: "old", content: JSON.stringify(preserved) },
      {
        role: "tool",
        tool_call_id: "recent",
        content: JSON.stringify({ ...preserved, stdout: "recent full result" })
      }
    ];
    const bounded = boundActiveToolContext(messages, 6_000, 1);
    expect(bounded[1]?.content).toContain("Preview omitted after it was observed");
    expect(bounded[2]?.content).toContain("recent full result");
  });

  function createStore(): { store: AuditStore; sessionId: string } {
    const workspace = mkdtempSync(join(tmpdir(), "aegisprobe-thread-"));
    workspaces.push(workspace);
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    return { store, sessionId: store.createSession("thread test", "safe") };
  }
});

function streamingProvider(rounds: StreamEvent[][]): OpenAICompatibleProvider {
  return {
    streamComplete: async function* () {
      const events = rounds.shift();
      if (!events) throw new Error("No streaming round queued.");
      for (const event of events) yield event;
    }
  } as unknown as OpenAICompatibleProvider;
}
