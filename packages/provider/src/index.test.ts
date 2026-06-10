import { afterEach, describe, expect, it, vi } from "vitest";
import { OpenAICompatibleProvider, type ChatMessage } from "./index.js";

describe("OpenAICompatibleProvider streaming reasoning state", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
    delete process.env.TEST_PROVIDER_KEY;
  });

  it("emits reasoning_content and sends replayed state unchanged", async () => {
    process.env.TEST_PROVIDER_KEY = "test";
    let requestBody: Record<string, unknown> | undefined;
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      requestBody = JSON.parse(String(init?.body)) as Record<string, unknown>;
      const sse = [
        'data: {"choices":[{"delta":{"reasoning_content":"inspect evidence"}}]}',
        'data: {"choices":[{"delta":{"tool_calls":[{"index":0,"id":"call-1","function":{"name":"lookup","arguments":"{}"}}]},"finish_reason":"tool_calls"}]}',
        "data: [DONE]",
        ""
      ].join("\n");
      return new Response(sse, {
        status: 200,
        headers: { "content-type": "text/event-stream" }
      });
    }));
    const provider = new OpenAICompatibleProvider({
      type: "openai-compatible",
      baseURL: "https://provider.example",
      apiKeyEnv: "TEST_PROVIDER_KEY",
      model: "test-model",
      fastModel: "test-fast",
      timeoutMs: 5_000,
      maxTokens: 1_000,
      fastMaxTokens: 500,
      maxRetries: 0,
      retryDelayMs: 0
    });
    const messages: ChatMessage[] = [{
      role: "assistant",
      content: null,
      reasoning_content: "prior exact state",
      tool_calls: [{
        id: "prior-call",
        type: "function",
        function: { name: "prior_tool", arguments: "{}" }
      }]
    }];

    const events = [];
    for await (const event of provider.streamComplete(messages)) {
      events.push(event);
    }

    expect(events).toContainEqual({ kind: "reasoning_delta", content: "inspect evidence" });
    expect((requestBody?.messages as ChatMessage[])[0]?.reasoning_content).toBe("prior exact state");
  });
});
