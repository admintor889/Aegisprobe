import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createRequire } from "node:module";
import { createServer, type Server } from "node:http";
import { createServer as createTcpServer, type AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { AuditStore } from "@aegisprobe/storage";
import type { SkillRegistry } from "@aegisprobe/skills";
import type { ChatMessage, CompleteOptions, OpenAICompatibleProvider } from "@aegisprobe/provider";
import { MainAgent, collectWebPortMatrixProbe, safeAnonymousFetchDetails, safeAuthenticatedFetchDetails } from "./index.js";
import { buildToolCommand, renderToolDefinitions } from "./tool-definitions.js";

const requireFromTest = createRequire(import.meta.url);

function providerFrom(responses: string[]): OpenAICompatibleProvider {
  return {
    complete: async () => {
      const response = responses.shift();
      if (response === undefined) {
        throw new Error("No fake provider response queued.");
      }
      return response;
    }
  } as unknown as OpenAICompatibleProvider;
}

function providerWithCapture(responses: string[], calls: ChatMessage[][]): OpenAICompatibleProvider {
  return {
    complete: async (messages: ChatMessage[], _options?: CompleteOptions) => {
      calls.push(messages);
      const response = responses.shift();
      if (response === undefined) {
        throw new Error("No fake provider response queued.");
      }
      return response;
    }
  } as unknown as OpenAICompatibleProvider;
}

function staticSkillRegistry(prompt: string): SkillRegistry {
  return {
    list: async () => [],
    get: async () => undefined,
    search: async () => [],
    renderPrompt: async () => prompt
  };
}

function capturingSkillRegistry(prompt: string, calls: Array<{ query: string; options: unknown }>): SkillRegistry {
  return {
    list: async () => [],
    get: async () => undefined,
    search: async () => [],
    renderPrompt: async (query, options) => {
      calls.push({ query, options });
      return prompt;
    }
  };
}

describe("MainAgent apply_patch protocol", () => {
  let originalCwd: string;
  let workspace: string;
  let stores: AuditStore[];

  beforeEach(() => {
    originalCwd = process.cwd();
    workspace = mkdtempSync(join(tmpdir(), "aegisprobe-core-"));
    stores = [];
    process.chdir(workspace);
  });

  afterEach(() => {
    for (const store of stores) {
      store.close();
    }
    process.chdir(originalCwd);
    rmSync(workspace, { recursive: true, force: true });
  });

  it("carries prior conversation and durable memory into the next turn", async () => {
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const calls: ChatMessage[][] = [];
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerWithCapture([
        '{"intent":"conversation","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        "I will remember alpha-ctx.",
        '{"intent":"conversation","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        "The code name was alpha-ctx."
      ], calls)
    });

    const sessionId = agent.createSession("context memory test");
    await agent.runTurn(sessionId, "记住: 测试代号是 alpha-ctx");
    const result = await agent.runTurn(sessionId, "上一句话说的代号是什么？");
    const snapshot = agent.getContextSnapshot(sessionId);

    expect(result.finalMessage).toContain("alpha-ctx");
    expect(snapshot.prompt).toContain("alpha-ctx");
    expect(calls.at(-1)?.map((message) => message.content).join("\n")).toContain("alpha-ctx");
  });

  it("applies an approved Codex-style add-file patch", async () => {
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Create the requested file.",
          plan: ["Create a file through apply_patch."],
          actions: [
            {
              type: "apply_patch",
              purpose: "Create a test note.",
              patch: "*** Begin Patch\n*** Add File: notes/example.txt\n+hello\n+world\n*** End Patch"
            }
          ],
          final: false
        }),
        '{"message":"File created.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("patch test");
    const result = await agent.runTurn(sessionId, "Create notes/example.txt");

    expect(result.status).toBe("completed");
    expect(readFileSync(join(workspace, "notes", "example.txt"), "utf8")).toBe("hello\nworld\n");
    expect(result.events.some((event) => event.kind === "file_change_approval_requested")).toBe(true);
    expect(result.events.some((event) => event.kind === "file_change_completed")).toBe(true);
  });

  it("applies an approved Codex-style update patch", async () => {
    writeFileSync(join(workspace, "sample.txt"), "alpha\nbeta\ngamma\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Update the file.",
          plan: ["Patch sample.txt."],
          actions: [
            {
              type: "apply_patch",
              purpose: "Replace beta.",
              patch: "*** Begin Patch\n*** Update File: sample.txt\n@@\n alpha\n-beta\n+delta\n gamma\n*** End Patch"
            }
          ],
          final: false
        }),
        '{"message":"File updated.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("patch update test");
    const result = await agent.runTurn(sessionId, "Change beta to delta in sample.txt");

    expect(result.status).toBe("completed");
    expect(readFileSync(join(workspace, "sample.txt"), "utf8")).toBe("alpha\ndelta\ngamma\n");
  });

  it("stores unified diff previews for approved patches", async () => {
    writeFileSync(join(workspace, "diff.txt"), "one\ntwo\nthree\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Patch the file.",
          plan: ["Patch diff.txt."],
          actions: [
            {
              type: "apply_patch",
              purpose: "Update diff preview.",
              patch: "*** Begin Patch\n*** Update File: diff.txt\n@@\n one\n-two\n+TWO\n three\n*** End Patch"
            }
          ],
          final: false
        }),
        '{"message":"File updated.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("unified diff test");
    await agent.runTurn(sessionId, "Change two to TWO in diff.txt");
    const [change] = store.listFileChanges(sessionId);

    expect(change.diff).toContain("@@ -1,3 +1,3 @@");
    expect(change.diff).toContain("-two");
    expect(change.diff).toContain("+TWO");
  });

  it("repairs malformed provider decision JSON once before falling back", async () => {
    writeFileSync(join(workspace, "repair.txt"), "before\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        "I will patch it: {malformed",
        JSON.stringify({
          message: "Repaired decision.",
          plan: ["Patch repair.txt."],
          actions: [
            {
              type: "apply_patch",
              purpose: "Exercise JSON repair.",
              patch: "*** Begin Patch\n*** Update File: repair.txt\n@@\n-before\n+after\n*** End Patch"
            }
          ],
          final: false
        }),
        '{"message":"Repaired patch complete.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("decision repair test");
    const result = await agent.runTurn(sessionId, "Patch repair.txt despite malformed first decision");

    expect(result.status).toBe("completed");
    expect(readFileSync(join(workspace, "repair.txt"), "utf8")).toBe("after\n");
    expect(result.events.some((event) => event.kind === "decision_repair_requested")).toBe(true);
    expect(result.events.some((event) => event.kind === "decision_repair_completed")).toBe(true);
  });

  it("blocks patches outside the workspace", async () => {
    const outside = join(tmpdir(), `aegisprobe-outside-${Date.now()}.txt`);
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Try an unsafe patch.",
          plan: ["Attempt unsafe patch."],
          actions: [
            {
              type: "apply_patch",
              purpose: "Unsafe path test.",
              patch: `*** Begin Patch\n*** Add File: ${outside}\n+blocked\n*** End Patch`
            }
          ],
          final: false
        }),
        '{"message":"Patch was blocked.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("patch block test");
    const result = await agent.runTurn(sessionId, "Write outside the workspace");

    expect(result.status).toBe("completed");
    expect(existsSync(outside)).toBe(false);
    expect(result.events.some((event) => event.kind === "file_change_blocked")).toBe(true);
  });

  it("applies a Codex-style move patch", async () => {
    writeFileSync(join(workspace, "old.txt"), "from\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Move and update the file.",
          plan: ["Patch and move the file."],
          actions: [
            {
              type: "apply_patch",
              purpose: "Move old.txt to new/location.txt.",
              patch: "*** Begin Patch\n*** Update File: old.txt\n*** Move to: new/location.txt\n@@\n-from\n+to\n*** End Patch"
            }
          ],
          final: false
        }),
        '{"message":"File moved.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("patch move test");
    await agent.runTurn(sessionId, "Move old.txt");

    expect(existsSync(join(workspace, "old.txt"))).toBe(false);
    expect(readFileSync(join(workspace, "new", "location.txt"), "utf8")).toBe("to\n");
  });

  it("applies a Codex-style delete patch", async () => {
    writeFileSync(join(workspace, "obsolete.txt"), "remove me\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Delete the file.",
          plan: ["Delete obsolete.txt."],
          actions: [
            {
              type: "apply_patch",
              purpose: "Delete obsolete file.",
              patch: "*** Begin Patch\n*** Delete File: obsolete.txt\n*** End Patch"
            }
          ],
          final: false
        }),
        '{"message":"File deleted.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("patch delete test");
    await agent.runTurn(sessionId, "Delete obsolete.txt");

    expect(existsSync(join(workspace, "obsolete.txt"))).toBe(false);
  });

  it("supports End of File and pure-addition update hunks", async () => {
    writeFileSync(join(workspace, "tail.txt"), "first\nsecond", "utf8");
    writeFileSync(join(workspace, "append.txt"), "base\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Patch two files.",
          plan: ["Patch EOF and append-only hunks."],
          actions: [
            {
              type: "apply_patch",
              purpose: "Exercise Codex patch hunk variants.",
              patch: "*** Begin Patch\n*** Update File: tail.txt\n@@\n first\n-second\n+second updated\n*** End of File\n*** Update File: append.txt\n@@\n+added line 1\n+added line 2\n*** End Patch"
            }
          ],
          final: false
        }),
        '{"message":"Files patched.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("patch eof test");
    await agent.runTurn(sessionId, "Patch EOF cases");

    expect(readFileSync(join(workspace, "tail.txt"), "utf8")).toBe("first\nsecond updated\n");
    expect(readFileSync(join(workspace, "append.txt"), "utf8")).toBe("base\nadded line 1\nadded line 2\n");
  });

  it("supports a move-only Codex-style patch", async () => {
    writeFileSync(join(workspace, "move-only.txt"), "same\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Move without editing.",
          plan: ["Move the file."],
          actions: [
            {
              type: "apply_patch",
              purpose: "Move file only.",
              patch: "*** Begin Patch\n*** Update File: move-only.txt\n*** Move to: moved/move-only.txt\n*** End Patch"
            }
          ],
          final: false
        }),
        '{"message":"Moved.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("patch move only test");
    await agent.runTurn(sessionId, "Move move-only.txt");

    expect(existsSync(join(workspace, "move-only.txt"))).toBe(false);
    expect(readFileSync(join(workspace, "moved", "move-only.txt"), "utf8")).toBe("same\n");
  });

  it("blocks moving a patch over an existing destination", async () => {
    writeFileSync(join(workspace, "source.txt"), "source\n", "utf8");
    writeFileSync(join(workspace, "dest.txt"), "dest\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Attempt unsafe move.",
          plan: ["Move over existing file."],
          actions: [
            {
              type: "apply_patch",
              purpose: "Destination collision test.",
              patch: "*** Begin Patch\n*** Update File: source.txt\n*** Move to: dest.txt\n@@\n-source\n+changed\n*** End Patch"
            }
          ],
          final: false
        }),
        '{"message":"Move blocked.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("patch move collision test");
    const result = await agent.runTurn(sessionId, "Move source over dest");

    expect(result.events.some((event) => event.kind === "file_change_blocked")).toBe(true);
    expect(readFileSync(join(workspace, "source.txt"), "utf8")).toBe("source\n");
    expect(readFileSync(join(workspace, "dest.txt"), "utf8")).toBe("dest\n");
  });

  it("reads workspace files through the controlled read_file action without shell approval", async () => {
    writeFileSync(join(workspace, "readme.txt"), "visible context\n", "utf8");
    let approvalCalls = 0;
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => {
        approvalCalls += 1;
        return true;
      },
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Read the file.",
          plan: ["Inspect readme.txt."],
          actions: [
            {
              type: "read_file",
              path: "readme.txt",
              purpose: "Inspect requested file."
            }
          ],
          final: false
        }),
        '{"message":"The file contains visible context.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("read file test");
    const result = await agent.runTurn(sessionId, "Read readme.txt");

    expect(result.status).toBe("completed");
    expect(approvalCalls).toBe(0);
    expect(result.events.some((event) => event.kind === "tool_completed" && event.message.includes("File read completed"))).toBe(true);
  });

  it("lists workspace files through the controlled list_files action", async () => {
    writeFileSync(join(workspace, "a.txt"), "a\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => false,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "List files.",
          plan: ["Inspect the workspace root."],
          actions: [
            {
              type: "list_files",
              path: ".",
              recursive: false,
              purpose: "Inspect workspace."
            }
          ],
          final: false
        }),
        '{"message":"Workspace listed.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("list files test");
    const result = await agent.runTurn(sessionId, "List files");

    expect(result.status).toBe("completed");
    expect(result.events.some((event) => event.kind === "tool_completed" && event.message.includes("Directory listing completed"))).toBe(true);
  });

  it("executes mixed tool actions in model order through the tool registry", async () => {
    writeFileSync(join(workspace, "mixed.txt"), "before\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Read and patch in one decision.",
          plan: ["Read the file.", "Patch the file."],
          actions: [
            {
              type: "read_file",
              path: "mixed.txt",
              purpose: "Inspect before editing."
            },
            {
              type: "apply_patch",
              purpose: "Update mixed.txt.",
              patch: "*** Begin Patch\n*** Update File: mixed.txt\n@@\n-before\n+after\n*** End Patch"
            }
          ],
          final: false
        }),
        '{"message":"Mixed tools complete.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("mixed tool registry test");
    const result = await agent.runTurn(sessionId, "Read then patch mixed.txt");

    expect(result.status).toBe("completed");
    expect(readFileSync(join(workspace, "mixed.txt"), "utf8")).toBe("after\n");
    expect(result.events.filter((event) => event.kind === "tool_completed")).toHaveLength(1);
    expect(result.events.filter((event) => event.kind === "file_change_completed")).toHaveLength(1);
  });

  it("runs multiple foreground subagents from one decision and records their observations", async () => {
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}',
        JSON.stringify({
          message: "Delegate independent checks.",
          plan: ["Run two subagents in parallel."],
          actions: [
            { type: "subagent", role: "explorer", task: "Find relevant files." },
            { type: "subagent", role: "reviewer", task: "Review likely risks." }
          ],
          final: false
        }),
        "Explorer result.",
        "Reviewer result.",
        '{"message":"Delegated checks complete.","plan":[],"actions":[],"final":true}'
      ])
    });

    const sessionId = agent.createSession("subagent parallel test");
    const result = await agent.runTurn(sessionId, "Delegate independent checks");
    const subagents = store.listSubAgents(sessionId);

    expect(result.status).toBe("completed");
    expect(subagents).toHaveLength(2);
    expect(subagents.every((subagent) => subagent.status === "completed")).toBe(true);
    expect(subagents.map((subagent) => subagent.resultSummary)).toEqual(["Explorer result.", "Reviewer result."]);
  });

  it("launches background subagents without blocking the parent turn", async () => {
    let decisionCalls = 0;
    let resolveSubagent: ((value: string) => void) | undefined;
    const provider = {
      complete: async (messages: Array<{ role: string; content: string }>) => {
        const system = messages[0]?.content ?? "";
        if (system.includes("extract structured intent")) {
          return '{"intent":"task","targets":[],"filePaths":[],"constraints":[],"needsClarification":false}';
        }
        if (system.includes("subagent inside AegisProbe")) {
          return await new Promise<string>((resolve) => {
            resolveSubagent = resolve;
          });
        }
        decisionCalls += 1;
        if (decisionCalls === 1) {
          return JSON.stringify({
            message: "Launch long-running check.",
            plan: ["Start a background subagent."],
            actions: [
              { type: "subagent", role: "explorer", task: "Long-running exploration.", background: true }
            ],
            final: false
          });
        }
        return '{"message":"Background subagent launched.","plan":[],"actions":[],"final":true}';
      }
    } as unknown as OpenAICompatibleProvider;
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider
    });

    const sessionId = agent.createSession("subagent background test");
    const result = await agent.runTurn(sessionId, "Start a background check");
    const [running] = store.listSubAgents(sessionId);

    expect(result.status).toBe("completed");
    expect(running.status).toBe("running");
    expect(result.events.some((event) => event.kind === "subagent_launched")).toBe(true);

    resolveSubagent?.("Background result.");
    await new Promise((resolve) => setTimeout(resolve, 25));

    const [completed] = store.listSubAgents(sessionId);
    expect(completed.status).toBe("completed");
    expect(completed.resultSummary).toBe("Background result.");
  });

  it("writes subagent output files and can wait for completion", async () => {
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom(["Subagent file output."])
    });

    const sessionId = agent.createSession("subagent output test");
    const record = await agent.spawnSubAgent(sessionId, "explorer", "Produce a saved result.");
    const waited = await agent.waitSubAgent(sessionId, record.id, 100);

    expect(waited?.status).toBe("completed");
    expect(waited?.outputPath).toBeTruthy();
    expect(existsSync(waited?.outputPath ?? "")).toBe(true);
    expect(readFileSync(waited?.outputPath ?? "", "utf8")).toContain("Subagent file output.");
  });

  it("lets a subagent gather read-only context before producing a final result", async () => {
    writeFileSync(join(workspace, "subagent-context.txt"), "subagent visible context\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        JSON.stringify({
          message: "Need context.",
          actions: [
            {
              type: "read_file",
              path: "subagent-context.txt",
              purpose: "Read delegated context."
            }
          ],
          final: false
        }),
        "Final subagent finding uses the visible context."
      ])
    });

    const sessionId = agent.createSession("subagent readonly tool test");
    const record = await agent.spawnSubAgent(sessionId, "explorer", "Inspect subagent-context.txt");

    expect(record.status).toBe("completed");
    expect(record.resultSummary).toContain("visible context");
    expect(readFileSync(record.outputPath ?? "", "utf8")).toContain("Final subagent finding");
  });

  it("closes a running subagent and discards its late result", async () => {
    let abortSeen = false;
    let providerStarted: (() => void) | undefined;
    const providerStartedPromise = new Promise<void>((resolve) => {
      providerStarted = resolve;
    });
    const provider = {
      complete: async (_messages: ChatMessage[], options?: CompleteOptions) => {
        providerStarted?.();
        return await new Promise<string>((resolve, reject) => {
          options?.signal?.addEventListener("abort", () => {
            abortSeen = true;
            reject(new Error("aborted"));
          }, { once: true });
          setTimeout(() => resolve("Late result."), 1000);
        });
      }
    } as unknown as OpenAICompatibleProvider;
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider
    });

    const sessionId = agent.createSession("subagent close test");
    const running = await agent.spawnSubAgent(sessionId, "explorer", "Long running task.", [], { background: true });
    await providerStartedPromise;
    const closed = agent.closeSubAgent(sessionId, running.id);
    await agent.waitSubAgent(sessionId, running.id, 500);
    const record = store.getSubAgent(running.id);

    expect(closed).toBe(true);
    expect(abortSeen).toBe(true);
    expect(record?.status).toBe("closed");
    expect(record?.resultSummary).toBeUndefined();
  });

  it("lets a foreground worker subagent apply approved patches through parent policy", async () => {
    writeFileSync(join(workspace, "worker-target.txt"), "before\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom([
        JSON.stringify({
          message: "Need to patch the delegated file.",
          actions: [
            {
              type: "apply_patch",
              purpose: "Apply delegated worker edit.",
              patch: "*** Begin Patch\n*** Update File: worker-target.txt\n@@\n-before\n+after\n*** End Patch"
            }
          ],
          final: false
        }),
        "Worker completed the approved edit."
      ])
    });

    const sessionId = agent.createSession("worker subagent patch test");
    const record = await agent.spawnSubAgent(sessionId, "worker", "Update worker-target.txt from before to after.");
    const changes = agent.listFileChanges(sessionId);

    expect(record.status).toBe("completed");
    expect(record.toolUseCount).toBe(1);
    expect(readFileSync(join(workspace, "worker-target.txt"), "utf8")).toBe("after\n");
    expect(changes).toHaveLength(1);
    expect(changes[0]?.status).toBe("applied");
    expect(readFileSync(record.outputPath ?? "", "utf8")).toContain("- Tool uses: 1");
  });

  it("blocks approval-gated tools for background worker subagents", async () => {
    writeFileSync(join(workspace, "background-worker.txt"), "before\n", "utf8");
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => {
        throw new Error("background worker should not request approval");
      },
      provider: providerFrom([
        JSON.stringify({
          message: "Try to patch in background.",
          actions: [
            {
              type: "apply_patch",
              purpose: "This should be blocked.",
              patch: "*** Begin Patch\n*** Update File: background-worker.txt\n@@\n-before\n+after\n*** End Patch"
            }
          ],
          final: false
        }),
        "Patch was blocked because background workers are read-only."
      ])
    });

    const sessionId = agent.createSession("background worker policy test");
    const running = await agent.spawnSubAgent(sessionId, "worker", "Attempt a background edit.", [], { background: true });
    const completed = await agent.waitSubAgent(sessionId, running.id, 1000);

    expect(completed?.status).toBe("completed");
    expect(completed?.toolUseCount).toBe(0);
    expect(completed?.resultSummary).toContain("background workers are read-only");
    expect(readFileSync(join(workspace, "background-worker.txt"), "utf8")).toBe("before\n");
    expect(agent.listFileChanges(sessionId)).toHaveLength(0);
  });

  it("runs security-focused subagent roles", async () => {
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => true,
      provider: providerFrom(["Frontend routes reviewed."])
    });

    const sessionId = agent.createSession("security role subagent test");
    const record = await agent.spawnSubAgent(sessionId, "frontend", "Inspect frontend routes for exposed APIs.");

    expect(record.status).toBe("completed");
    expect(record.role).toBe("frontend");
    expect(record.description).toContain("Frontend Security Analyst");
    expect(record.resultSummary).toContain("Frontend routes reviewed");
  });

  it("exposes bounded port_probe before heavyweight nmap service detection", () => {
    const manifest = renderToolDefinitions();
    expect(manifest).toContain('"name": "port_probe"');
    expect(manifest).toContain("Prefer this before nmap");

    const portProbe = buildToolCommand("port_probe", {
      target: "172.168.20.210",
      ports: "80,443,8080,8443",
      timeoutMs: "2000"
    });
    expect(portProbe).toBe("naabu -host '172.168.20.210' -ports '80,443,8080,8443' -silent -timeout 2000");

    const nmap = buildToolCommand("nmap_scan", {
      target: "172.168.20.210",
      ports: "80,443"
    });
    expect(nmap).toContain("--host-timeout 45s");
    expect(nmap).toContain("--max-retries 1");
  });

  it("returns high-fidelity safe authenticated fetch details without leaking response cookies", async () => {
    const server = await new Promise<{ server: Server; url: string }>((resolve) => {
      const instance = createServer((request, response) => {
        response.statusCode = request.headers.cookie?.includes("sid=test") ? 200 : 401;
        response.setHeader("Content-Type", "application/json");
        response.setHeader("Set-Cookie", "server_sid=secret-value; HttpOnly");
        response.end(JSON.stringify({ ok: response.statusCode === 200, owner: "alice", tenant: "tenant-a" }));
      });
      instance.listen(0, "127.0.0.1", () => {
        const address = instance.address();
        if (!address || typeof address === "string") {
          throw new Error("Failed to bind local test server.");
        }
        resolve({ server: instance, url: `http://127.0.0.1:${address.port}/api/orders/1001?search=alpha` });
      });
    });

    try {
      const details = await safeAuthenticatedFetchDetails(server.url, {
        id: "ctx1",
        sessionId: "s1",
        name: "alice",
        role: "customer",
        cookieHeader: "sid=test",
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      });

      expect(details.status).toBe(200);
      expect(details.contentType).toContain("application/json");
      expect(details.bodyExcerpt).toContain('"owner":"alice"');
      expect(details.bodyHash).not.toBe("0");
      expect(details.bodyTruncated).toBe(false);
      expect(details.responseHeaders["set-cookie"]).toContain("[redacted]");
      expect(details.responseHeaders["set-cookie"]).not.toContain("secret-value");
    } finally {
      await new Promise<void>((resolve) => server.server.close(() => resolve()));
    }
  }, 30_000);

  it("collects anonymous GET and HEAD baselines without sending credentials", async () => {
    const seen: Array<{ method?: string; cookie?: string }> = [];
    const server = await new Promise<{ server: Server; url: string }>((resolve) => {
      const instance = createServer((request, response) => {
        seen.push({ method: request.method, cookie: request.headers.cookie });
        response.statusCode = request.headers.cookie ? 401 : 200;
        response.setHeader("Content-Type", "application/json");
        response.end(request.method === "HEAD" ? undefined : JSON.stringify({ public: true, route: request.url }));
      });
      instance.listen(0, "127.0.0.1", () => {
        const address = instance.address();
        if (!address || typeof address === "string") {
          throw new Error("Failed to bind local test server.");
        }
        resolve({ server: instance, url: `http://127.0.0.1:${address.port}/api/public/orders` });
      });
    });

    try {
      const getDetails = await safeAnonymousFetchDetails(server.url, "GET");
      const headDetails = await safeAnonymousFetchDetails(server.url, "HEAD");

      expect(getDetails.anonymous).toBe(true);
      expect(getDetails.method).toBe("GET");
      expect(getDetails.status).toBe(200);
      expect(getDetails.bodyExcerpt).toContain('"public":true');
      expect(headDetails.method).toBe("HEAD");
      expect(headDetails.status).toBe(200);
      expect(headDetails.bodyLength).toBe(0);
      expect(seen.map((item) => item.method)).toEqual(["GET", "HEAD"]);
      expect(seen.some((item) => item.cookie)).toBe(false);
    } finally {
      await new Promise<void>((resolve) => server.server.close(() => resolve()));
    }
  }, 30_000);

  it("collects a short web port matrix with HTTP response evidence", async () => {
    const server = await new Promise<{ server: Server; url: string; port: number }>((resolve) => {
      const instance = createServer((_request, response) => {
        response.statusCode = 200;
        response.setHeader("Content-Type", "text/html; charset=utf-8");
        response.end("<title>Matrix App</title>");
      });
      instance.listen(0, "127.0.0.1", () => {
        const address = instance.address();
        if (!address || typeof address === "string") {
          throw new Error("Failed to bind local test server.");
        }
        resolve({ server: instance, url: `http://127.0.0.1:${address.port}/`, port: address.port });
      });
    });

    try {
      const matrix = await collectWebPortMatrixProbe(server.url);
      const targetEntry = matrix.entries.find((entry) => entry.port === server.port);

      expect(targetEntry).toMatchObject({
        tcp: "open",
        http: "response",
        status: 200,
        title: "Matrix App"
      });
      expect(matrix.interpretation.join("\n")).toContain("HTTP response observed");
    } finally {
      await new Promise<void>((resolve) => server.server.close(() => resolve()));
    }
  }, 30_000);

  it("surfaces TCP-open but HTTP-nonresponsive ports without broad scanner assumptions", async () => {
    const tcp = await new Promise<{ server: ReturnType<typeof createTcpServer>; url: string; port: number }>((resolve) => {
      const instance = createTcpServer((socket) => {
        socket.setTimeout(2_500);
        socket.on("timeout", () => socket.destroy());
      });
      instance.listen(0, "127.0.0.1", () => {
        const address = instance.address() as AddressInfo;
        resolve({ server: instance, url: `http://127.0.0.1:${address.port}/`, port: address.port });
      });
    });

    try {
      const matrix = await collectWebPortMatrixProbe(tcp.url);
      const targetEntry = matrix.entries.find((entry) => entry.port === tcp.port);

      expect(targetEntry?.tcp).toBe("open");
      expect(targetEntry?.http).not.toBe("response");
      expect(matrix.interpretation.join("\n")).toContain("TCP open but HTTP");
    } finally {
      await new Promise<void>((resolve) => tcp.server.close(() => resolve()));
    }
  }, 30_000);

  it("extracts HTML surface from anonymous fetch and records form assets", async () => {
    const server = await new Promise<{ server: Server; url: string }>((resolve) => {
      const instance = createServer((request, response) => {
        response.statusCode = 200;
        response.setHeader("Content-Type", "text/html; charset=utf-8");
        response.end(`<!doctype html>
          <html>
            <head>
              <title>Login Portal</title>
              <script src="/static/app.js"></script>
              <link rel="stylesheet" href="/static/app.css">
            </head>
            <body>
              <form action="/home/login/loginon.html" method="post">
                <input name="username" type="text">
                <input name="password" type="password">
                <button name="submit" type="submit">Log in</button>
              </form>
            </body>
          </html>`);
      });
      instance.listen(0, "127.0.0.1", () => {
        const address = instance.address();
        if (!address || typeof address === "string") {
          throw new Error("Failed to bind local test server.");
        }
        resolve({ server: instance, url: `http://127.0.0.1:${address.port}/home/Login/login` });
      });
    });
    const store = new AuditStore(join(workspace, "html-surface.sqlite"));
    stores.push(store);
    const agent = new MainAgent({ store, approve: async () => false, provider: providerFrom([]) });

    try {
      const sessionId = agent.createSession("html surface fetch test");
      const details = await safeAnonymousFetchDetails(server.url, "GET");
      agent.recordReadOnlyFetchEvidence(sessionId, details);

      expect(details.htmlSurface?.title).toBe("Login Portal");
      expect(details.htmlSurface?.forms[0]?.method).toBe("POST");
      expect(details.htmlSurface?.forms[0]?.action).toContain("/home/login/loginon.html");
      expect(details.htmlSurface?.forms[0]?.fields.map((field) => field.name)).toEqual(["username", "password", "submit"]);

      const evidence = store.listEvidence(sessionId);
      expect(evidence.at(-1)?.summary).toContain("forms=1");
      const assets = store.listAssets(sessionId);
      expect(assets.some((asset) => asset.value.endsWith("/home/login/loginon.html") && asset.source.endsWith(":form"))).toBe(true);
      expect(assets.some((asset) => asset.value.endsWith("/static/app.js") && asset.source.endsWith(":script"))).toBe(true);
    } finally {
      await new Promise<void>((resolve) => server.server.close(() => resolve()));
    }
  }, 30_000);

  it("builds authorization validation candidates from normalized API evidence without replaying mutations", async () => {
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => false,
      provider: providerFrom([])
    });
    const sessionId = agent.createSession("authz validation plan test");
    const workflowId = "workflow_authz_plan";
    const createdAt = "2026-06-06T00:00:00.000Z";
    store.upsertSecurityWorkflow({
      id: workflowId,
      sessionId,
      target: {
        kind: "url",
        raw: "https://example.com/app",
        normalized: "https://example.com/app"
      },
      status: "running",
      currentPhase: "frontend",
      summary: "Scoped web application target.",
      createdAt,
      updatedAt: createdAt
    });
    store.addAsset({
      id: "asset_admin_user",
      sessionId,
      workflowId,
      kind: "url",
      value: "https://example.com/api/admin/users/{id}",
      source: "browser:api-inventory-normalizer",
      confidence: "high",
      metadata: JSON.stringify({
        method: "GET",
        pathTemplate: "/api/admin/users/{id}",
        examples: ["https://example.com/api/admin/users/42?include=roles&tenantId=t1"],
        queryParams: ["include", "tenantId"],
        bodyParamHints: [],
        riskSignals: ["privileged-route", "object-or-tokenized-path"],
        authRequired: "likely"
      }),
      createdAt
    });
    store.addAsset({
      id: "asset_refund",
      sessionId,
      workflowId,
      kind: "url",
      value: "https://example.com/api/orders/{id}/refund",
      source: "browser:api-inventory-normalizer",
      confidence: "high",
      metadata: JSON.stringify({
        method: "POST",
        pathTemplate: "/api/orders/{id}/refund",
        examples: ["https://example.com/api/orders/1001/refund"],
        queryParams: [],
        bodyParamHints: ["orderId", "amount", "reason"],
        riskSignals: ["business-workflow-route", "state-changing-method"],
        authRequired: "likely"
      }),
      createdAt
    });
    store.addAsset({
      id: "asset_customer_order",
      sessionId,
      workflowId,
      kind: "url",
      value: "https://example.com/api/orders/{id}",
      source: "browser:api-inventory-normalizer",
      confidence: "high",
      metadata: JSON.stringify({
        method: "GET",
        pathTemplate: "/api/orders/{id}",
        examples: ["https://example.com/api/orders/1001"],
        queryParams: [],
        bodyParamHints: [],
        riskSignals: ["object-or-tokenized-path"],
        authRequired: "likely"
      }),
      createdAt
    });

    const blockedPlan = agent.buildAuthorizationValidationPlan(sessionId);
    const adminCandidate = blockedPlan.candidates.find((item) => item.pathTemplate === "/api/admin/users/{id}");
    const refundCandidate = blockedPlan.candidates.find((item) => item.pathTemplate === "/api/orders/{id}/refund");
    const orderCandidate = blockedPlan.candidates.find((item) => item.pathTemplate === "/api/orders/{id}");

    expect(blockedPlan.summary.blocked).toBe(2);
    expect(blockedPlan.summary.passiveOnly).toBe(1);
    expect(adminCandidate?.status).toBe("blocked_needs_auth_contexts");
    expect(adminCandidate?.categories).toEqual(expect.arrayContaining(["BOLA", "BFLA"]));
    expect(adminCandidate?.priorityScore).toBeGreaterThan(orderCandidate?.priorityScore ?? 0);
    expect(adminCandidate?.priorityRationale.join(" ")).toContain("function-level authorization");
    expect(adminCandidate?.objectReferences).toEqual(expect.arrayContaining([
      expect.objectContaining({ location: "path", name: "id" }),
      expect.objectContaining({ location: "query", name: "tenantId" })
    ]));
    expect(refundCandidate?.status).toBe("passive_only");
    expect(refundCandidate?.approvalRequired).toBe("active-mutation");
    expect(refundCandidate?.blockedReason).toContain("State-changing");
    expect(refundCandidate?.safeProcedure.join(" ")).toContain("explicit active authorization");

    agent.addSecurityAuthContext(sessionId, { name: "user-a", role: "customer", baseUrl: "https://example.com" });
    agent.addSecurityAuthContext(sessionId, { name: "admin", role: "admin", baseUrl: "https://example.com" });
    const readyPlan = agent.buildAuthorizationValidationPlan(sessionId);

    expect(readyPlan.summary.ready).toBe(2);
    expect(readyPlan.candidates[0]?.pathTemplate).toBe("/api/admin/users/{id}");
    expect(readyPlan.candidates.find((item) => item.pathTemplate === "/api/admin/users/{id}")?.status).toBe("ready_for_readonly_comparison");
    expect(readyPlan.candidates.find((item) => item.pathTemplate === "/api/orders/{id}")?.status).toBe("ready_for_readonly_comparison");
    expect(readyPlan.candidates.find((item) => item.pathTemplate === "/api/orders/{id}/refund")?.status).toBe("passive_only");
    expect(readyPlan.guardrails.some((item) => item.includes("do not invent paths"))).toBe(true);

    const queueBefore = agent.buildSecurityDecisionQueue(sessionId);
    expect(queueBefore.items[0]?.fallbackFor).toBe("authz-plan");

    const runSummary = await agent.executeSecurityDecisionQueueItem(sessionId);
    const queueAfter = agent.buildSecurityDecisionQueue(sessionId);

    expect(runSummary).toContain("Authorization validation plan generated");
    expect(store.listSecurityToolRuns(sessionId).some((run) => run.toolId === "authz-plan" && run.status === "success")).toBe(true);
    expect(store.listEvidence(sessionId).some((item) => item.source.startsWith("decision:authz-plan:"))).toBe(true);
    expect(queueAfter.items[0]?.fallbackFor).not.toBe("authz-plan");
  });

  it("validates local multi-role authorization with policy while keeping mutations approval-gated", async () => {
    type LabApp = {
      listen: (port: number, host: string, callback: () => void) => Server;
      locals: { state: { hits: string[] } };
    };
    const lab = requireFromTest(join(originalCwd, "..", "..", "labs", "targets", "local-multirole-app", "server.js")) as { createApp: () => LabApp };
    const app = lab.createApp();
    const server = await new Promise<Server>((resolve) => {
      const started = app.listen(0, "127.0.0.1", () => resolve(started));
    });
    const address = server.address() as AddressInfo;
    const baseUrl = `http://127.0.0.1:${address.port}`;
    const login = async (username: string, password: string): Promise<string> => {
      const response = await fetch(`${baseUrl}/api/login`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ username, password })
      });
      const body = await response.json() as { token?: string };
      if (!body.token) {
        throw new Error(`Login failed for ${username}`);
      }
      return body.token;
    };

    try {
      const aliceToken = await login("alice", "alice123");
      const adminToken = await login("admin", "admin123");
      app.locals.state.hits = [];

      const store = new AuditStore(join(workspace, "audit.sqlite"));
      stores.push(store);
      const agent = new MainAgent({
        store,
        approve: async () => false,
        provider: providerFrom([]),
        expectedAuthorizationPolicy: {
          id: "policy-local-authz",
          name: "Local role policy",
          subjects: [
            { id: "subject-customer", name: "customer", role: "customer" },
            { id: "subject-admin", name: "admin", role: "admin" }
          ],
          rules: [
            {
              id: "deny-customer-admin",
              description: "Customers must not access admin user APIs.",
              subjectId: "subject-customer",
              route: "/api/admin/",
              method: "GET",
              action: "deny",
              confidence: "high"
            }
          ],
          objectRules: [
            {
              id: "orders-own-tenant",
              description: "Customers may only read their own tenant orders.",
              subjectId: "subject-customer",
              route: "/api/orders/{id}",
              method: "GET",
              objectReference: { location: "path", name: "id" },
              expectedOwnership: "same-tenant",
              action: "allow",
              confidence: "medium"
            }
          ],
          createdAt: "2026-06-07T00:00:00.000Z"
        }
      });
      const sessionId = agent.createSession("local multirole authz test");
      const workflowId = "workflow_local_multirole_authz";
      const createdAt = "2026-06-07T00:00:00.000Z";
      store.upsertSecurityWorkflow({
        id: workflowId,
        sessionId,
        target: { kind: "url", raw: baseUrl, normalized: baseUrl },
        status: "running",
        currentPhase: "safe_validation",
        summary: "Local multi-role target under test.",
        createdAt,
        updatedAt: createdAt
      });
      for (const asset of [
        {
          id: "asset_local_admin_user",
          value: `${baseUrl}/api/admin/users/{id}`,
          metadata: {
            method: "GET",
            pathTemplate: "/api/admin/users/{id}",
            examples: [`${baseUrl}/api/admin/users/1`],
            queryParams: [],
            bodyParamHints: [],
            riskSignals: ["privileged-route", "object-or-tokenized-path"],
            authRequired: "likely"
          }
        },
        {
          id: "asset_local_order",
          value: `${baseUrl}/api/orders/{id}`,
          metadata: {
            method: "GET",
            pathTemplate: "/api/orders/{id}",
            examples: [`${baseUrl}/api/orders/102?include=items`],
            queryParams: ["include"],
            bodyParamHints: [],
            riskSignals: ["object-or-tokenized-path", "tenant-route"],
            authRequired: "likely"
          }
        },
        {
          id: "asset_local_user_patch",
          value: `${baseUrl}/api/users/{id}`,
          metadata: {
            method: "PATCH",
            pathTemplate: "/api/users/{id}",
            examples: [`${baseUrl}/api/users/1`],
            queryParams: [],
            bodyParamHints: ["role", "tenant", "email"],
            riskSignals: ["state-changing-method", "mass-assignment-candidate"],
            authRequired: "likely"
          }
        }
      ]) {
        store.addAsset({
          id: asset.id,
          sessionId,
          workflowId,
          kind: "url",
          value: asset.value,
          source: "browser:api-inventory-normalizer",
          confidence: "high",
          metadata: JSON.stringify(asset.metadata),
          createdAt
        });
      }
      agent.addSecurityAuthContext(sessionId, {
        name: "alice",
        role: "customer",
        tenant: "tenant-a",
        username: "alice",
        baseUrl,
        authorizationHeader: `Bearer ${aliceToken}`
      });
      agent.addSecurityAuthContext(sessionId, {
        name: "admin",
        role: "admin",
        username: "admin",
        baseUrl,
        authorizationHeader: `Bearer ${adminToken}`
      });

      const plan = agent.buildAuthorizationValidationPlan(sessionId);
      const patchCandidate = plan.candidates.find((item) => item.pathTemplate === "/api/users/{id}");

      expect(plan.summary.ready).toBeGreaterThan(0);
      expect(patchCandidate?.status).toBe("passive_only");
      expect(patchCandidate?.approvalRequired).toBe("active-mutation");
      expect(patchCandidate?.expectedEvidence.join(" ")).toContain("Explicit active authorization record");
      expect(patchCandidate?.safeProcedure.join(" ")).toContain("rollback boundaries");

      const compare = await agent.executeBusinessLogicRoleComparison(sessionId, "next", "alice", "admin");
      const attempts = agent.listSecurityValidationAttempts(sessionId);
      const findings = agent.listFindings(sessionId);
      const hits = app.locals.state.hits;

      expect(compare).toContain("/api/admin/users/1");
      expect(attempts.some((attempt) => attempt.status === "validated" && attempt.method.includes("expected policy"))).toBe(true);
      expect(findings.some((finding) => finding.title.includes("Authorization policy violation"))).toBe(true);
      expect(hits).toContain("GET /api/admin/users/1");
      expect(hits).toContain("GET /api/orders/102");
      expect(hits.some((hit) => hit.startsWith("PATCH "))).toBe(false);
      expect(hits.some((hit) => hit.startsWith("POST /api/orders/"))).toBe(false);
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  }, 60_000);

  it("imports explicit API descriptions into normalized API evidence under scope control", async () => {
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => false,
      provider: providerFrom([])
    });
    const sessionId = agent.createSession("api description import test");
    const workflowId = "workflow_api_import";
    const createdAt = "2026-06-06T00:00:00.000Z";
    store.upsertSecurityWorkflow({
      id: workflowId,
      sessionId,
      target: {
        kind: "url",
        raw: "https://example.com/app",
        normalized: "https://example.com/app"
      },
      status: "running",
      currentPhase: "frontend",
      summary: "Scoped web application target.",
      createdAt,
      updatedAt: createdAt
    });
    const specPath = join(workspace, "openapi.json");
    writeFileSync(specPath, JSON.stringify({
      openapi: "3.0.0",
      info: {
        title: "Scoped API",
        version: "1.0.0"
      },
      servers: [
        { url: "/api/v2" }
      ],
      paths: {
        "/admin/users/{id}": {
          get: {
            parameters: [
              { name: "include", in: "query", schema: { type: "string" } }
            ]
          },
          patch: {
            requestBody: {
              content: {
                "application/json": {
                  schema: {
                    type: "object",
                    properties: {
                      role: { type: "string" },
                      profile: {
                        type: "object",
                        properties: {
                          email: { type: "string" }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
      }
    }), "utf8");

    const result = await agent.importApiDescriptionDocument(sessionId, specPath);
    store.addAsset({
      id: "asset_duplicate_get_admin_user",
      sessionId,
      workflowId,
      kind: "url",
      value: "https://example.com/api/v2/admin/users/{id}",
      source: "browser:api-inventory-normalizer:duplicate",
      confidence: "high",
      metadata: JSON.stringify({
        method: "GET",
        pathTemplate: "/api/v2/admin/users/{id}",
        queryParams: ["include"],
        riskSignals: ["privileged-route"],
        sources: ["openapi"]
      }),
      createdAt
    });
    const assets = store.listAssets(sessionId);
    const evidence = store.listEvidence(sessionId);
    const matrix = agent.buildAuthorizationBoundaryMatrix(sessionId);
    const control = agent.buildWebPentestControlPlane(sessionId, workflowId);
    const picture = agent.buildWebPentestOperatingPicture(sessionId, workflowId);

    expect(result.apiDescriptionDocuments[0]?.source).toBe("manual");
    expect(result.normalizedApiEndpoints.some((endpoint) => endpoint.method === "GET" && endpoint.pathTemplate === "/api/v2/admin/users/{id}" && endpoint.queryParams.includes("include"))).toBe(true);
    expect(result.normalizedApiEndpoints.some((endpoint) => endpoint.method === "PATCH" && endpoint.bodyParamHints.includes("profile.email"))).toBe(true);
    expect(existsSync(result.artifactPath)).toBe(true);
    expect(evidence.some((item) => item.source === "manual:api-description-import" && item.summary.includes("normalized endpoints=2"))).toBe(true);
    expect(assets.some((item) => item.source === "browser:api-inventory-normalizer" && item.value === "https://example.com/api/v2/admin/users/{id}")).toBe(true);
    expect(matrix.items.some((item) => item.pathTemplate === "/api/v2/admin/users/{id}" && item.method === "GET")).toBe(true);
    expect(control.evidenceCounts.normalizedApiEndpoints).toBeGreaterThanOrEqual(2);
    expect(control.evidenceCounts.apiDescriptionDocuments).toBeGreaterThanOrEqual(1);
    expect(control.routeFrontier.some((item) => item.pathTemplate === "/api/v2/admin/users/{id}" && item.score > 50)).toBe(true);
    expect(control.routeFrontier.filter((item) => item.method === "GET" && item.pathTemplate === "/api/v2/admin/users/{id}")).toHaveLength(1);
    expect(control.routeFrontier.some((item) => item.nextAction.includes("approved role contexts") || item.nextAction.includes("safe mutation boundary"))).toBe(true);
    expect(picture.endpointMap.some((item) => item.method === "GET" && item.pathTemplate === "/api/v2/admin/users/{id}" && item.queryParams.includes("include"))).toBe(true);
    expect(picture.endpointMap.some((item) => item.method === "PATCH" && item.bodyParamHints.includes("profile.email"))).toBe(true);
    expect(picture.allowedNextActions.join(" ")).toContain("normalized routes");
    expect(picture.blockedUntilEvidence.join(" ")).toContain("Cross-role");
    expect(picture.authState.nextEvidenceNeeded.join(" ")).toContain("Register two approved auth contexts");
    expect(picture.decisionFrame.join(" ")).toContain("not from a fixed phase list");

    agent.addSecurityAuthContext(sessionId, { name: "customer-a", role: "customer", baseUrl: "https://example.com" });
    const oneContextPicture = agent.buildWebPentestOperatingPicture(sessionId, workflowId);
    expect(oneContextPicture.authState.nextEvidenceNeeded.join(" ")).toContain("Register one additional approved role");

    agent.addSecurityAuthContext(sessionId, { name: "admin-a", role: "admin", baseUrl: "https://example.com" });
    const twoContextPicture = agent.buildWebPentestOperatingPicture(sessionId, workflowId);
    expect(twoContextPicture.authState.nextEvidenceNeeded.join(" ")).toContain("Run read-only cross-role comparison");
  });

  it("rejects explicit API description URLs outside the current target origin", async () => {
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const agent = new MainAgent({
      store,
      approve: async () => false,
      provider: providerFrom([])
    });
    const sessionId = agent.createSession("api description scope test");
    const createdAt = "2026-06-06T00:00:00.000Z";
    store.upsertSecurityWorkflow({
      id: "workflow_api_scope",
      sessionId,
      target: {
        kind: "url",
        raw: "https://example.com",
        normalized: "https://example.com"
      },
      status: "running",
      currentPhase: "frontend",
      summary: "Scoped web application target.",
      createdAt,
      updatedAt: createdAt
    });

    await expect(agent.importApiDescriptionDocument(sessionId, "https://api.example.net/openapi.json"))
      .rejects.toThrow(/same-origin/);
    expect(store.listEvidence(sessionId).some((item) => item.source === "manual:api-description-import")).toBe(false);
  });

  it("evaluates comparison against authorization policy — deny violation", async () => {
    const { evaluateComparisonAgainstPolicy } = await import("./security-business.js");
    const policy = {
      id: "p1",
      name: "Test Policy",
      subjects: [
        { id: "s1", name: "customer", role: "customer" }
      ],
      rules: [
        {
          id: "r1",
          description: "Customers denied from admin",
          subjectId: "s1",
          route: "/api/admin/",
          method: "GET",
          action: "deny" as const,
          confidence: "high" as const
        }
      ],
      createdAt: "2025-01-01"
    };
    const comparisons = [{
      url: "http://localhost/api/admin/users",
      method: "GET",
      pathTemplate: "/api/admin/users/{id}",
      left: { name: "customer-a", role: "customer" },
      right: { name: "admin", role: "admin" },
      sameStatus: true,
      sameSignature: true
    }];
    const result = evaluateComparisonAgainstPolicy(
      comparisons, policy,
      { name: "customer-a", role: "customer" },
      { name: "admin", role: "admin" }
    );
    expect(result.hasDenyViolation).toBe(true);
    expect(result.violations.length).toBe(1);
    expect(result.violations[0].subject).toBe("customer-a");
  });

  it("does not treat denied responses as authorization policy violations", async () => {
    const { evaluateComparisonAgainstPolicy } = await import("./security-business.js");
    const policy = {
      id: "p1b",
      name: "Test Policy",
      subjects: [
        { id: "s1", name: "customer", role: "customer" }
      ],
      rules: [
        {
          id: "r1",
          description: "Customers denied from admin",
          subjectId: "s1",
          route: "/api/admin/",
          method: "GET",
          action: "deny" as const,
          confidence: "high" as const
        }
      ],
      createdAt: "2025-01-01"
    };
    const comparisons = [{
      url: "http://localhost/api/admin/users",
      method: "GET",
      pathTemplate: "/api/admin/users/{id}",
      left: { name: "customer-a", role: "customer" },
      right: { name: "admin", role: "admin" },
      sameStatus: false,
      sameSignature: false,
      leftStatus: 403,
      rightStatus: 200,
      leftBodyLength: 40,
      rightBodyLength: 200
    }];
    const result = evaluateComparisonAgainstPolicy(
      comparisons, policy,
      { name: "customer-a", role: "customer" },
      { name: "admin", role: "admin" }
    );
    expect(result.hasDenyViolation).toBe(false);
    expect(result.violations.length).toBe(0);
  });

  it("evaluates comparison against authorization policy — allow rule, no violation", async () => {
    const { evaluateComparisonAgainstPolicy } = await import("./security-business.js");
    const policy = {
      id: "p2",
      name: "Allow Policy",
      subjects: [
        { id: "s1", name: "customer", role: "customer" }
      ],
      rules: [
        {
          id: "r1",
          description: "Customers allowed to orders",
          subjectId: "s1",
          route: "/api/orders/",
          method: "GET",
          action: "allow" as const,
          confidence: "high" as const
        }
      ],
      createdAt: "2025-01-01"
    };
    const comparisons = [{
      url: "http://localhost/api/orders/101",
      method: "GET",
      pathTemplate: "/api/orders/{id}",
      left: { name: "customer-a", role: "customer" },
      right: { name: "customer-b", role: "customer" },
      sameStatus: true,
      sameSignature: true
    }];
    const result = evaluateComparisonAgainstPolicy(
      comparisons, policy,
      { name: "customer-a", role: "customer" },
      { name: "customer-b", role: "customer" }
    );
    expect(result.hasDenyViolation).toBe(false);
    expect(result.violations.length).toBe(0);
    expect(result.compliant.some((c) => c.subject === "customer-a")).toBe(true);
  });

  it("evaluates comparison against authorization policy — not covered by policy", async () => {
    const { evaluateComparisonAgainstPolicy } = await import("./security-business.js");
    const policy = {
      id: "p3",
      name: "Narrow Policy",
      subjects: [
        { id: "s1", name: "customer", role: "customer" }
      ],
      rules: [
        {
          id: "r1",
          description: "Only covers orders",
          subjectId: "s1",
          route: "/api/orders/",
          method: "GET",
          action: "allow" as const,
          confidence: "high" as const
        }
      ],
      createdAt: "2025-01-01"
    };
    const comparisons = [{
      url: "http://localhost/api/admin/users",
      method: "GET",
      pathTemplate: "/api/admin/users/{id}",
      left: { name: "customer-a", role: "customer" },
      right: { name: "admin", role: "admin" },
      sameStatus: true,
      sameSignature: true
    }];
    const result = evaluateComparisonAgainstPolicy(
      comparisons, policy,
      { name: "customer-a", role: "customer" },
      { name: "admin", role: "admin" }
    );
    expect(result.hasDenyViolation).toBe(false);
    expect(result.notCovered).toContain("http://localhost/api/admin/users");
  });
});
