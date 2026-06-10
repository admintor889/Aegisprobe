import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it, vi } from "vitest";
import { AuditStore } from "@aegisprobe/storage";
import { buildAgentThreadTools } from "./agent-thread-tools.js";
import { assertPublicResearchUrl, searchPublicWeb } from "./web-research.js";

describe("Agent thread tool infrastructure", () => {
  const workspaces: string[] = [];
  const stores: AuditStore[] = [];

  afterEach(() => {
    vi.unstubAllGlobals();
    for (const store of stores.splice(0)) store.close();
    for (const workspace of workspaces.splice(0)) {
      rmSync(workspace, { recursive: true, force: true });
    }
  });

  it("records HTTP observations for later tools and preserves the exact raw envelope", async () => {
    const workspace = createWorkspace();
    const store = new AuditStore(join(workspace, "audit.sqlite"));
    stores.push(store);
    const sessionId = store.createSession("tool state", "safe");
    vi.stubGlobal("fetch", vi.fn(async () => new Response(
      JSON.stringify({ items: [], reflected: "sample" }),
      {
        status: 200,
        headers: {
          "content-type": "application/json",
          "x-test": "raw-header"
        }
      }
    )));
    const tools = buildAgentThreadTools({
      sessionId,
      store,
      projectRoot: workspace,
      approve: async () => true,
      emit: () => undefined,
      executeSecurityProbe: async () => "",
      reconWebApplication: async () => {
        throw new Error("not used");
      }
    });
    const http = tools.find((tool) => tool.definition.function.name === "http_request");
    const payloads = tools.find((tool) => tool.definition.function.name === "payload_candidates");
    if (!http || !payloads) throw new Error("Expected tools were not registered.");

    const envelope = await http.execute({
      url: "https://example.test/api/search?q=sample",
      method: "GET"
    }, {});
    const candidates = await payloads.execute({
      target: "https://example.test",
      focus: "search parameter"
    }, {});

    const evidence = store.listEvidence(sessionId);
    const assets = store.listAssets(sessionId);
    const rawArtifact = envelope.metadata?.rawArtifact as { path: string };
    const exact = JSON.parse(readFileSync(rawArtifact.path, "utf8")) as { stdout: string };
    const candidateSet = JSON.parse(candidates.stdout) as { candidates: unknown[] };
    expect(evidence.some((item) =>
      item.source === "agent-tool:http_request"
      && item.data?.includes("REQUEST GET https://example.test/api/search?q=sample")
    )).toBe(true);
    expect(assets).toEqual(expect.arrayContaining([
      expect.objectContaining({
        kind: "url",
        value: "https://example.test/api/search?q=sample",
        source: "agent-tool:http_request"
      })
    ]));
    expect(candidateSet.candidates.length).toBeGreaterThan(0);
    expect(exact.stdout).toContain("x-test: raw-header");
    expect(exact.stdout).toContain('"reflected":"sample"');
  });

  it("isolates public-web research from local and metadata networks", async () => {
    await expect(assertPublicResearchUrl(new URL("http://127.0.0.1/"))).rejects.toThrow(/non-public/i);
    await expect(assertPublicResearchUrl(new URL("http://169.254.169.254/latest/meta-data/")))
      .rejects.toThrow(/non-public/i);
    await expect(assertPublicResearchUrl(new URL("file:///etc/passwd"))).rejects.toThrow(/protocol/i);
  });

  it("returns structured links while preserving the raw search response", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response([
      '<?xml version="1.0"?><rss><channel><item>',
      "<title>Apache advisory</title>",
      "<link>https://activemq.apache.org/security-advisories.data/CVE-2026-34197-announcement.txt</link>",
      "<description>ActiveMQ Jolokia RCE advisory</description>",
      "</item></channel></rss>"
    ].join(""), { status: 200 })));

    const result = await searchPublicWeb("CVE-2026-34197", {
      enabled: true,
      searchProvider: "bing-rss",
      searchEndpoint: "https://1.1.1.1/search",
      maxResults: 10,
      timeoutMs: 5_000,
      maxFetchBytes: 100_000,
      maxRetries: 0,
      userAgent: "test"
    }, 5);

    expect(result.results).toEqual([{
      title: "Apache advisory",
      url: "https://activemq.apache.org/security-advisories.data/CVE-2026-34197-announcement.txt",
      snippet: "ActiveMQ Jolokia RCE advisory"
    }]);
    expect(result.rawResponse).toContain("<rss>");
  });

  function createWorkspace(): string {
    const workspace = mkdtempSync(join(tmpdir(), "aegisprobe-tools-"));
    workspaces.push(workspace);
    mkdirSync(join(workspace, "configs"), { recursive: true });
    writeFileSync(join(workspace, "configs", "config.yaml"), [
      "provider:",
      "  type: openai-compatible",
      "  baseURL: https://provider.invalid",
      "  apiKeyEnv: TEST_PROVIDER_KEY",
      "  model: test-model",
      "webResearch:",
      "  enabled: true"
    ].join("\n"));
    mkdirSync(join(workspace, "configs", "prompt-packs", "pentest-expert", "conversation"), { recursive: true });
    const sourceSemantics = join(
      process.cwd(),
      "..",
      "..",
      "configs",
      "prompt-packs",
      "pentest-expert",
      "conversation",
      "tool-semantics.json"
    );
    writeFileSync(
      join(workspace, "configs", "prompt-packs", "pentest-expert", "conversation", "tool-semantics.json"),
      readFileSync(sourceSemantics, "utf8")
    );
    return workspace;
  }
});
