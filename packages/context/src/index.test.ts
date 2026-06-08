import { describe, expect, it } from "vitest";
import { CodexLikeContextManager, updateSessionMemory, type ContextMessage } from "./index.js";

describe("CodexLikeContextManager", () => {
  it("keeps recent conversation and durable memory in the snapshot", () => {
    const messages: ContextMessage[] = [
      { role: "user", content: "记住: 项目代号是 omega-context", createdAt: "2026-05-24T00:00:00.000Z" },
      { role: "assistant", content: "已记录。", createdAt: "2026-05-24T00:00:01.000Z" }
    ];
    const memory = updateSessionMemory({ sessionId: "ses_test", messages });
    const snapshot = new CodexLikeContextManager().build({
      sessionId: "ses_test",
      memory,
      messages,
      maxTokens: 2_000
    });

    expect(snapshot.prompt).toContain("omega-context");
    expect(snapshot.sections.map((section) => section.title)).toContain("Session Memory");
    expect(snapshot.stats.includedMessages).toBe(2);
  });

  it("packs sections by priority when the context budget is tight", () => {
    const messages = Array.from({ length: 40 }, (_, index): ContextMessage => ({
      role: index % 2 === 0 ? "user" : "assistant",
      content: `message-${index} ${"x".repeat(400)}`,
      createdAt: `2026-05-24T00:00:${String(index).padStart(2, "0")}.000Z`
    }));
    const snapshot = new CodexLikeContextManager().build({
      sessionId: "ses_budget",
      memory: {
        sessionId: "ses_budget",
        summary: "critical summary",
        pinnedFacts: ["critical fact"],
        openTasks: ["critical task"],
        updatedAt: "2026-05-24T00:00:00.000Z"
      },
      messages,
      skillContext: "low priority " + "y".repeat(20_000),
      maxTokens: 1_200
    });

    expect(snapshot.prompt).toContain("critical fact");
    expect(snapshot.sections.map((section) => section.title)).toContain("Conversation History");
    expect(snapshot.stats.approxTokens).toBeGreaterThan(0);
  });
});
