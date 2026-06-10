import { describe, expect, it } from "vitest";
import {
  ToolTranscriptStore,
  formatToolCompletion,
  formatToolStart
} from "./terminal-ui.js";

describe("terminal tool transcript", () => {
  it("renders shell commands as Codex-like running rows", () => {
    const lines = formatToolStart({
      name: "execute_shell",
      arguments: JSON.stringify({
        command: "Get-NetIPConfiguration | Format-List",
        purpose: "inspect network state"
      })
    });

    expect(lines).toEqual([
      "\u2022 Running Get-NetIPConfiguration | Format-List"
    ]);
  });

  it("keeps successful output folded in compact mode", () => {
    const result = JSON.stringify({
      version: 1,
      tool: "execute_shell",
      status: "success",
      startedAt: "2026-06-10T00:00:00.000Z",
      endedAt: "2026-06-10T00:00:01.250Z",
      durationMs: 1250,
      exitCode: 0,
      stdout: "private output\nsecond line",
      stderr: "",
      artifacts: [],
      truncated: {
        stdout: false,
        stderr: false,
        stdoutBytes: 26,
        stderrBytes: 0
      }
    });
    const record = {
      id: "call-1",
      name: "execute_shell",
      arguments: "{}",
      result,
      startedAt: 0,
      endedAt: 1250
    };

    expect(formatToolCompletion(record, "compact").join("\n")).not.toContain("private output");
    expect(formatToolCompletion(record, "full").join("\n")).toContain("private output");
  });

  it("expands the original tool envelope on demand", () => {
    const store = new ToolTranscriptStore();
    store.rememberCall("call-1", "web_search", JSON.stringify({ query: "ActiveMQ advisory" }));
    store.complete("call-1", JSON.stringify({
      version: 1,
      tool: "web_search",
      status: "success",
      startedAt: "2026-06-10T00:00:00.000Z",
      endedAt: "2026-06-10T00:00:00.100Z",
      durationMs: 100,
      stdout: "raw provider response",
      stderr: "",
      artifacts: ["artifact.json"],
      truncated: {
        stdout: false,
        stderr: false,
        stdoutBytes: 21,
        stderrBytes: 0
      },
      metadata: {
        source: "provider"
      }
    }));

    const expanded = store.render("last");
    expect(expanded).toContain("raw provider response");
    expect(expanded).toContain("\"metadata\"");
    expect(expanded).toContain("\"source\": \"provider\"");
  });
});
