import { readFile, writeFile } from "node:fs/promises";
import { resolve } from "node:path";
import type { ToolDefinition } from "@aegisprobe/provider";
import { loadConfig } from "@aegisprobe/provider";
import {
  CveMatchEngine,
  buildPayloadCandidateSet,
  buildPayloadRequestDraftSet,
  fingerprint,
  fofaSearch,
  normalizeApiInventory
} from "@aegisprobe/security";
import { newId, nowIso, parseTargetInput, validateReadablePath, validateWritablePath, type WebAppReconResult } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { AgentArtifactStore } from "./agent-artifacts.js";
import { createAgentToolEnvelope, type AgentToolEnvelope } from "./agent-tool-envelope.js";
import type { AgentThreadTool } from "./conversation-loop.js";
import { loadPromptPackJson } from "./prompt-pack.js";
import { executeShellActionEnvelope, type ApprovalDecisionLike, type ShellEventEmitter } from "./shell-orchestration.js";
import { executeListFilesAction, executeReadFileAction } from "./workspace-actions.js";
import { fetchPublicWeb, searchPublicWeb } from "./web-research.js";

export type AgentThreadToolsOptions = {
  sessionId: string;
  store: AuditStore;
  projectRoot: string;
  approve: (subject: string, detail: string) => Promise<ApprovalDecisionLike>;
  emit: ShellEventEmitter;
  executeSecurityProbe: (target: string, probe: string) => Promise<string>;
  reconWebApplication: (
    target?: string,
    options?: { maxPages?: number; headed?: boolean; analyzeJs?: boolean }
  ) => Promise<WebAppReconResult>;
};

export function buildAgentThreadTools(options: AgentThreadToolsOptions): AgentThreadTool[] {
  const descriptions = loadPromptPackJson<Record<string, string>>("conversation/tool-semantics.json");
  const artifactStore = new AgentArtifactStore(options.projectRoot, options.sessionId);
  const webResearch = loadConfig(resolve(options.projectRoot, "configs", "config.yaml")).webResearch;
  const tools = [
    tool(descriptions, "execute_shell", {
      command: { type: "string" },
      purpose: { type: "string" }
    }, ["command", "purpose"], async (args) => {
      return executeShellActionEnvelope(
        options.store,
        options.approve,
        options.sessionId,
        options.emit,
        text(args.command),
        text(args.purpose)
      );
    }),

    tool(descriptions, "read_file", {
      path: { type: "string" },
      purpose: { type: "string" }
    }, ["path"], async (args) => {
      const startedAt = nowIso();
      const path = text(args.path);
      const decision = validateReadablePath(path);
      if (!decision.allowed) {
        return createAgentToolEnvelope({
          tool: "read_file",
          status: "blocked",
          startedAt,
          stderr: decision.reason ?? "Path is not readable.",
          metadata: { path }
        });
      }
      try {
        const content = await readFile(decision.absolutePath);
        return createAgentToolEnvelope({
          tool: "read_file",
          status: "success",
          startedAt,
          stdout: content.toString("utf8"),
          artifacts: [decision.absolutePath],
          metadata: {
            path: decision.absolutePath,
            purpose: text(args.purpose),
            bytes: content.byteLength
          }
        });
      } catch (error) {
        return createAgentToolEnvelope({
          tool: "read_file",
          status: "error",
          startedAt,
          stderr: errorText(error),
          metadata: { path: decision.absolutePath }
        });
      }
    }),

    tool(descriptions, "write_file", {
      path: { type: "string" },
      content: { type: "string" },
      purpose: { type: "string" }
    }, ["path", "content"], async (args) => {
      const startedAt = nowIso();
      const path = text(args.path);
      const contentRaw = text(args.content);
      const purpose = text(args.purpose);
      const decision = validateWritablePath(path);
      if (!decision.allowed) {
        return createAgentToolEnvelope({
          tool: "write_file",
          status: "blocked",
          startedAt,
          stderr: decision.reason ?? "Path is not writable.",
          metadata: { path, purpose }
        });
      }
      // Require human approval for all file writes (defense-in-depth).
      const approval = await options.approve(
        `Write file: ${decision.absolutePath}`,
        `Purpose: ${purpose}\nPath: ${decision.absolutePath}\nSize: ${contentRaw.length} bytes`
      );
      const approved = typeof approval === "boolean" ? approval : approval.approved;
      if (!approved) {
        return createAgentToolEnvelope({
          tool: "write_file",
          status: "blocked",
          startedAt,
          stderr: "User denied the file write.",
          metadata: { path: decision.absolutePath, purpose }
        });
      }
      try {
        await writeFile(decision.absolutePath, contentRaw, "utf8");
        return createAgentToolEnvelope({
          tool: "write_file",
          status: "success",
          startedAt,
          stdout: `Wrote ${contentRaw.length} bytes to ${decision.absolutePath}`,
          artifacts: [decision.absolutePath],
          metadata: {
            path: decision.absolutePath,
            purpose,
            bytes: contentRaw.length
          }
        });
      } catch (error) {
        return createAgentToolEnvelope({
          tool: "write_file",
          status: "error",
          startedAt,
          stderr: errorText(error),
          metadata: { path: decision.absolutePath, purpose }
        });
      }
    }),

    tool(descriptions, "artifact_read", {
      path: { type: "string" },
      offset: { type: "number" },
      maxBytes: { type: "number" }
    }, ["path"], async (args) => {
      const startedAt = nowIso();
      try {
        const result = artifactStore.read(
          text(args.path),
          numberValue(args.offset, 0),
          numberValue(args.maxBytes, 32_000)
        );
        return createAgentToolEnvelope({
          tool: "artifact_read",
          status: "success",
          startedAt,
          stdout: JSON.stringify(result),
          artifacts: [result.path],
          metadata: {
            path: result.path,
            offset: result.offset,
            returnedBytes: result.returnedBytes,
            totalBytes: result.totalBytes,
            eof: result.eof
          }
        });
      } catch (error) {
        return createAgentToolEnvelope({
          tool: "artifact_read",
          status: "error",
          startedAt,
          stderr: errorText(error),
          metadata: { path: text(args.path) }
        });
      }
    }),

    tool(descriptions, "list_directory", {
      path: { type: "string" },
      recursive: { type: "boolean" }
    }, ["path"], async (args) => {
      const startedAt = nowIso();
      const output = await executeListFilesAction(
        options.store,
        options.sessionId,
        options.emit,
        text(args.path) || ".",
        "agent-requested directory listing",
        Boolean(args.recursive)
      );
      return createAgentToolEnvelope({
        tool: "list_directory",
        status: /^Blocked|failed:/i.test(output) ? "error" : "success",
        startedAt,
        stdout: output,
        metadata: { path: text(args.path) || ".", recursive: Boolean(args.recursive) }
      });
    }),

    tool(descriptions, "http_request", {
      url: { type: "string" },
      method: { type: "string" },
      headers: { type: "object", additionalProperties: { type: "string" } },
      body: { type: "string" },
      timeoutMs: { type: "number" }
    }, ["url"], async (args, context) => {
      return executeHttpRequest(options, args, context.signal);
    }),

    tool(descriptions, "security_probe", {
      target: { type: "string" },
      probe: { type: "string", enum: ["basic_recon", "dns", "http_headers"] }
    }, ["target", "probe"], async (args) => {
      const startedAt = nowIso();
      try {
        const output = await options.executeSecurityProbe(text(args.target), text(args.probe) || "basic_recon");
        return createAgentToolEnvelope({
          tool: "security_probe",
          status: "success",
          startedAt,
          stdout: output,
          metadata: { target: text(args.target), probe: text(args.probe) }
        });
      } catch (error) {
        return createAgentToolEnvelope({
          tool: "security_probe",
          status: "error",
          startedAt,
          stderr: errorText(error),
          metadata: { target: text(args.target), probe: text(args.probe) }
        });
      }
    }),

    tool(descriptions, "web_recon", {
      target: { type: "string" },
      maxPages: { type: "number" },
      analyzeJs: { type: "boolean" },
      headed: { type: "boolean" }
    }, ["target"], async (args) => {
      const startedAt = nowIso();
      try {
        const result = await options.reconWebApplication(text(args.target), {
          maxPages: numberValue(args.maxPages, 10),
          analyzeJs: args.analyzeJs !== false,
          headed: Boolean(args.headed)
        });
        const normalizedApiEndpoints = result.normalizedApiEndpoints ?? normalizeApiInventory(result);
        return createAgentToolEnvelope({
          tool: "web_recon",
          status: "success",
          startedAt,
          stdout: JSON.stringify({ ...result, normalizedApiEndpoints }),
          artifacts: [
            result.artifactPath,
            result.harArtifactPath,
            result.normalizedApiArtifactPath
          ].filter((value): value is string => Boolean(value)),
          metadata: {
            target: result.startUrl,
            pagesVisited: result.pagesVisited.length,
            normalizedApiEndpoints: normalizedApiEndpoints.length
          }
        });
      } catch (error) {
        return createAgentToolEnvelope({
          tool: "web_recon",
          status: "error",
          startedAt,
          stderr: errorText(error),
          metadata: { target: text(args.target) }
        });
      }
    }),

    tool(descriptions, "fingerprint", {
      url: { type: "string" },
      headers: { type: "object", additionalProperties: { type: "string" } },
      html: { type: "string" },
      statusCode: { type: "number" }
    }, ["url"], async (args, context) => {
      return executeFingerprint(options, args, context.signal);
    }),

    tool(descriptions, "cve_lookup", {
      target: { type: "string" },
      technologies: {
        type: "array",
        items: {
          type: "object",
          properties: {
            name: { type: "string" },
            version: { type: "string" },
            evidenceSummary: { type: "string" }
          },
          required: ["name"]
        }
      }
    }, ["target"], async (args) => {
      const startedAt = nowIso();
      const target = text(args.target) || latestTarget(options.store, options.sessionId)?.normalized || "";
      const explicit = Array.isArray(args.technologies)
        ? args.technologies
          .filter(isRecord)
          .map((item) => ({
            target,
            name: text(item.name),
            version: text(item.version) || undefined,
            evidenceSummary: text(item.evidenceSummary) || undefined
          }))
          .filter((item) => item.name)
        : [];
      const technologies = explicit.length > 0
        ? explicit
        : options.store.listTechnologies(options.sessionId);
      try {
        const result = await new CveMatchEngine(options.projectRoot).buildExploitChains(technologies, target);
        const existing = options.store.listCveMatches(options.sessionId);
        for (const chain of result.chains) {
          if (existing.some((match) =>
            match.target === target
            && match.technology === chain.technology
            && match.cveId === chain.cveId
          )) {
            continue;
          }
          options.store.addCveMatch({
            id: newId("cve"),
            sessionId: options.sessionId,
            target,
            technology: chain.technology,
            cveId: chain.cveId,
            title: chain.title,
            severity: chain.severity,
            confidence: chain.confidence === "confirmed" ? "high" : chain.confidence,
            rationale: chain.rationale,
            source: chain.source,
            relevanceScore: chain.matchRelevance,
            createdAt: nowIso()
          });
        }
        return createAgentToolEnvelope({
          tool: "cve_lookup",
          status: "success",
          startedAt,
          stdout: JSON.stringify(result),
          metadata: { target, technologyCount: technologies.length, chainCount: result.chains.length }
        });
      } catch (error) {
        return createAgentToolEnvelope({
          tool: "cve_lookup",
          status: "error",
          startedAt,
          stderr: errorText(error),
          metadata: { target, technologyCount: technologies.length }
        });
      }
    }),

    tool(descriptions, "payload_candidates", {
      target: { type: "string" },
      focus: { type: "string" },
      marker: { type: "string" },
      maxCandidates: { type: "number" }
    }, [], async (args) => {
      const startedAt = nowIso();
      const target = resolveTarget(options.store, options.sessionId, text(args.target));
      const result = buildPayloadCandidateSet({
        target,
        assets: options.store.listAssets(options.sessionId),
        evidence: options.store.listEvidence(options.sessionId),
        technologies: options.store.listTechnologies(options.sessionId),
        cveMatches: options.store.listCveMatches(options.sessionId),
        authContexts: options.store.listSecurityAuthContexts(options.sessionId),
        focus: text(args.focus) || undefined,
        marker: text(args.marker) || undefined,
        maxCandidates: numberValue(args.maxCandidates, 12)
      });
      return createAgentToolEnvelope({
        tool: "payload_candidates",
        status: "success",
        startedAt,
        stdout: JSON.stringify(result),
        metadata: { candidateCount: result.candidates.length }
      });
    }),

    tool(descriptions, "payload_request_drafts", {
      target: { type: "string" },
      focus: { type: "string" },
      marker: { type: "string" },
      maxDrafts: { type: "number" }
    }, [], async (args) => {
      const startedAt = nowIso();
      const target = resolveTarget(options.store, options.sessionId, text(args.target));
      const result = buildPayloadRequestDraftSet({
        target,
        assets: options.store.listAssets(options.sessionId),
        evidence: options.store.listEvidence(options.sessionId),
        technologies: options.store.listTechnologies(options.sessionId),
        cveMatches: options.store.listCveMatches(options.sessionId),
        authContexts: options.store.listSecurityAuthContexts(options.sessionId),
        focus: text(args.focus) || undefined,
        marker: text(args.marker) || undefined,
        maxDrafts: numberValue(args.maxDrafts, 12)
      });
      return createAgentToolEnvelope({
        tool: "payload_request_drafts",
        status: "success",
        startedAt,
        stdout: JSON.stringify(result),
        metadata: { draftCount: result.drafts.length }
      });
    }),

    tool(descriptions, "graph_query", {
      kinds: {
        type: "array",
        items: {
          type: "string",
          enum: ["targets", "assets", "technologies", "cves", "evidence", "findings", "auth_contexts"]
        }
      }
    }, [], async (args) => {
      const startedAt = nowIso();
      const requested = new Set(
        Array.isArray(args.kinds) ? args.kinds.map(text) : []
      );
      const include = (kind: string) => requested.size === 0 || requested.has(kind);
      const snapshot = {
        ...(include("targets") ? { targets: options.store.listTargets(options.sessionId) } : {}),
        ...(include("assets") ? { assets: options.store.listAssets(options.sessionId) } : {}),
        ...(include("technologies") ? { technologies: options.store.listTechnologies(options.sessionId) } : {}),
        ...(include("cves") ? { cves: options.store.listCveMatches(options.sessionId) } : {}),
        ...(include("evidence") ? { evidence: options.store.listEvidence(options.sessionId) } : {}),
        ...(include("findings") ? { findings: options.store.listFindings(options.sessionId) } : {}),
        ...(include("auth_contexts") ? { authContexts: options.store.listSecurityAuthContexts(options.sessionId) } : {})
      };
      return createAgentToolEnvelope({
        tool: "graph_query",
        status: "success",
        startedAt,
        stdout: JSON.stringify(snapshot),
        metadata: { kinds: [...requested] }
      });
    }),

    tool(descriptions, "web_search", {
      query: { type: "string" },
      maxResults: { type: "number" }
    }, ["query"], async (args, context) => {
      const startedAt = nowIso();
      try {
        const result = await searchPublicWeb(
          text(args.query),
          webResearch,
          numberValue(args.maxResults, webResearch.maxResults),
          context.signal
        );
        return createAgentToolEnvelope({
          tool: "web_search",
          status: "success",
          startedAt,
          stdout: JSON.stringify(result),
          metadata: {
            query: result.query,
            provider: result.provider,
            statusCode: result.status,
            resultCount: result.results.length
          }
        });
      } catch (error) {
        return createAgentToolEnvelope({
          tool: "web_search",
          status: "error",
          startedAt,
          stderr: errorText(error),
          metadata: { query: text(args.query) }
        });
      }
    }),

    tool(descriptions, "web_fetch", {
      url: { type: "string" }
    }, ["url"], async (args, context) => {
      const startedAt = nowIso();
      try {
        const result = await fetchPublicWeb(text(args.url), webResearch, context.signal);
        return createAgentToolEnvelope({
          tool: "web_fetch",
          status: "success",
          startedAt,
          stdout: JSON.stringify(result),
          metadata: {
            url: result.requestedUrl,
            responseUrl: result.finalUrl,
            statusCode: result.status,
            contentType: result.contentType,
            bytes: result.bytes,
            bodyTruncatedAtFetchLimit: result.truncated
          }
        });
      } catch (error) {
        return createAgentToolEnvelope({
          tool: "web_fetch",
          status: "error",
          startedAt,
          stderr: errorText(error),
          metadata: { url: text(args.url) }
        });
      }
    }),

    tool(descriptions, "fofa_search", {
      query: { type: "string" },
      size: { type: "number" }
    }, ["query"], async (args) => {
      const startedAt = nowIso();
      try {
        const result = await fofaSearch(text(args.query), loadConfig().fofa, numberValue(args.size, 50));
        return createAgentToolEnvelope({
          tool: "fofa_search",
          status: "success",
          startedAt,
          stdout: JSON.stringify(result),
          metadata: { query: text(args.query), returned: result.results.length, total: result.total }
        });
      } catch (error) {
        return createAgentToolEnvelope({
          tool: "fofa_search",
          status: "error",
          startedAt,
          stderr: errorText(error),
          metadata: { query: text(args.query) }
        });
      }
    })
  ];
  return tools.map((candidate) => ({
    definition: candidate.definition,
    execute: async (args, context) => {
      const rawEnvelope = await candidate.execute(args, context);
      const envelope = preserveToolEnvelope(artifactStore, rawEnvelope);
      recordAgentToolObservation(
        options,
        candidate.definition.function.name,
        args,
        rawEnvelope,
        envelope
      );
      return envelope;
    }
  }));
}

function tool(
  descriptions: Record<string, string>,
  name: string,
  properties: Record<string, unknown>,
  required: string[],
  execute: AgentThreadTool["execute"]
): AgentThreadTool {
  const description = descriptions[name];
  if (!description) {
    throw new Error(`Tool semantics are missing from the prompt pack: ${name}`);
  }
  const definition: ToolDefinition = {
    type: "function",
    function: {
      name,
      description,
      parameters: {
        type: "object",
        properties,
        ...(required.length > 0 ? { required } : {})
      }
    }
  };
  return { definition, execute };
}

async function executeHttpRequest(
  options: AgentThreadToolsOptions,
  args: Record<string, unknown>,
  signal?: AbortSignal
): Promise<AgentToolEnvelope> {
  const startedAt = nowIso();
  const url = text(args.url);
  const method = (text(args.method) || "GET").toUpperCase();
  const headers = stringRecord(args.headers);
  const body = text(args.body) || undefined;
  const timeoutMs = Math.max(1_000, Math.min(numberValue(args.timeoutMs, 20_000), 120_000));

  if (!["GET", "HEAD", "OPTIONS"].includes(method)) {
    const decision = await options.approve(
      `Send ${method} request`,
      `${method} ${url}\n\nThe request may change target state.`
    );
    const approved = typeof decision === "boolean" ? decision : decision.approved;
    if (!approved) {
      return createAgentToolEnvelope({
        tool: "http_request",
        status: "blocked",
        startedAt,
        stderr: "User denied the non-read-only HTTP request.",
        metadata: { url, method }
      });
    }
  }

  const controller = new AbortController();
  const abort = () => controller.abort();
  signal?.addEventListener("abort", abort, { once: true });
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetch(url, {
      method,
      headers,
      body: method === "GET" || method === "HEAD" ? undefined : body,
      signal: controller.signal,
      redirect: "manual"
    });
    const responseBody = method === "HEAD" ? "" : await response.text();
    const rawHeaders = [...response.headers.entries()]
      .map(([key, value]) => `${key}: ${value}`)
      .join("\n");
    return createAgentToolEnvelope({
      tool: "http_request",
      status: "success",
      startedAt,
      stdout: `HTTP ${response.status} ${response.statusText}\n${rawHeaders}\n\n${responseBody}`,
      metadata: {
        url,
        method,
        statusCode: response.status,
        statusText: response.statusText,
        responseUrl: response.url
      }
    });
  } catch (error) {
    return createAgentToolEnvelope({
      tool: "http_request",
      status: controller.signal.aborted ? "timeout" : "error",
      startedAt,
      stderr: errorText(error),
      metadata: { url, method, timeoutMs }
    });
  } finally {
    clearTimeout(timer);
    signal?.removeEventListener("abort", abort);
  }
}

async function executeFingerprint(
  options: AgentThreadToolsOptions,
  args: Record<string, unknown>,
  signal?: AbortSignal
): Promise<AgentToolEnvelope> {
  const startedAt = nowIso();
  const url = text(args.url);
  let headers = stringRecord(args.headers);
  let html = text(args.html);
  let statusCode = numberValue(args.statusCode, 0) || undefined;

  try {
    if (!html && Object.keys(headers).length === 0) {
      const response = await fetch(url, {
        signal,
        headers: { "user-agent": "AegisProbe/1.0" }
      });
      statusCode = response.status;
      headers = Object.fromEntries(response.headers.entries());
      html = await response.text();
    }
    const result = fingerprint({
      url,
      statusCode,
      headers,
      html,
      scriptSrc: extractScriptSources(html, url)
    }, options.projectRoot);
    const existing = options.store.listTechnologies(options.sessionId);
    for (const technology of result.technologies) {
      if (existing.some((item) =>
        item.target === url
        && item.name === technology.name
        && item.version === technology.version
      )) {
        continue;
      }
      options.store.addTechnology({
        id: newId("tech"),
        sessionId: options.sessionId,
        target: url,
        name: technology.name,
        version: technology.version,
        category: technology.categories.join(", "),
        source: "agent-tool:fingerprint",
        confidence: technology.confidence >= 80 ? "high" : technology.confidence >= 50 ? "medium" : "low",
        evidenceSummary: technology.evidence.join("; "),
        createdAt: nowIso()
      });
    }
    return createAgentToolEnvelope({
      tool: "fingerprint",
      status: "success",
      startedAt,
      stdout: JSON.stringify({
        observation: { url, statusCode, headers, html },
        result
      }),
      metadata: { url, matchCount: result.matchCount }
    });
  } catch (error) {
    return createAgentToolEnvelope({
      tool: "fingerprint",
      status: "error",
      startedAt,
      stderr: errorText(error),
      metadata: { url }
    });
  }
}

function resolveTarget(store: AuditStore, sessionId: string, targetText: string) {
  if (targetText) {
    return parseTargetInput(targetText);
  }
  return latestTarget(store, sessionId);
}

function latestTarget(store: AuditStore, sessionId: string) {
  return store.listTargets(sessionId).at(-1);
}

function extractScriptSources(html: string, baseUrl: string): string[] {
  const sources: string[] = [];
  for (const match of html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["']/gi)) {
    try {
      sources.push(new URL(match[1]!, baseUrl).toString());
    } catch {
      sources.push(match[1]!);
    }
  }
  return sources;
}

function preserveToolEnvelope(
  artifactStore: AgentArtifactStore,
  envelope: AgentToolEnvelope
): AgentToolEnvelope {
  try {
    return artifactStore.preserve(envelope);
  } catch (error) {
    return {
      ...envelope,
      metadata: {
        ...envelope.metadata,
        artifactError: errorText(error)
      }
    };
  }
}

function recordAgentToolObservation(
  options: AgentThreadToolsOptions,
  toolName: string,
  args: Record<string, unknown>,
  rawEnvelope: AgentToolEnvelope,
  renderedEnvelope: AgentToolEnvelope
): void {
  if (toolName === "graph_query" || toolName === "artifact_read") {
    return;
  }

  const rawArtifact = isRecord(renderedEnvelope.metadata?.rawArtifact)
    ? renderedEnvelope.metadata.rawArtifact
    : undefined;
  const status = rawEnvelope.status;
  const metadata = rawEnvelope.metadata ?? {};
  const url = text(metadata.url) || text(args.url) || text(args.target);
  const method = (text(metadata.method) || text(args.method) || "GET").toUpperCase();
  const statusCode = numberValue(metadata.statusCode, 0);
  const summaryParts = [
    `${toolName} ${status}`,
    url ? `${method} ${url}` : "",
    statusCode ? `HTTP ${statusCode}` : "",
    rawArtifact && typeof rawArtifact.path === "string" ? `raw=${rawArtifact.path}` : ""
  ].filter(Boolean);

  let data = JSON.stringify({
    tool: toolName,
    status,
    metadata,
    rawArtifact,
    stdoutPreview: rawEnvelope.stdout.slice(0, 24_000),
    stderrPreview: rawEnvelope.stderr.slice(0, 8_000)
  });
  if (toolName === "http_request") {
    data = [
      `REQUEST ${method} ${url}`,
      text(args.body) ? `BODY\n${text(args.body).slice(0, 16_000)}` : "",
      "RESPONSE",
      rawEnvelope.stdout.slice(0, 32_000),
      rawArtifact ? `RAW_ARTIFACT ${JSON.stringify(rawArtifact)}` : ""
    ].filter(Boolean).join("\n");
    recordHttpAsset(options, url, method, args);
  }

  options.store.addEvidence({
    id: newId("evidence"),
    sessionId: options.sessionId,
    source: `agent-tool:${toolName}`,
    kind: toolName === "http_request" || toolName === "web_fetch" ? "http" : "tool",
    summary: summaryParts.join(" | "),
    data,
    createdAt: nowIso()
  });
}

function recordHttpAsset(
  options: AgentThreadToolsOptions,
  url: string,
  method: string,
  args: Record<string, unknown>
): void {
  if (!url) return;
  let normalized: string;
  try {
    normalized = new URL(url).toString();
  } catch {
    return;
  }
  const existing = options.store.listAssets(options.sessionId);
  const bodyParamHints = requestBodyFieldNames(text(args.body));
  const queryParams = [...new URL(normalized).searchParams.keys()];
  const metadata = JSON.stringify({
    method,
    queryParams,
    bodyParamHints,
    sourceTool: "http_request"
  });
  const duplicate = existing.some((asset) =>
    asset.kind === "url"
    && asset.value === normalized
    && parseAssetMethod(asset.metadata) === method
  );
  if (duplicate) return;
  options.store.addAsset({
    id: newId("asset"),
    sessionId: options.sessionId,
    kind: "url",
    value: normalized,
    source: "agent-tool:http_request",
    confidence: "high",
    metadata,
    createdAt: nowIso()
  });
}

function requestBodyFieldNames(body: string): string[] {
  if (!body.trim()) return [];
  try {
    const parsed = JSON.parse(body) as unknown;
    return isRecord(parsed) ? Object.keys(parsed).slice(0, 40) : [];
  } catch {
    try {
      return [...new URLSearchParams(body).keys()].slice(0, 40);
    } catch {
      return [];
    }
  }
}

function parseAssetMethod(metadata: string | undefined): string {
  if (!metadata) return "";
  try {
    const parsed = JSON.parse(metadata) as { method?: unknown };
    return text(parsed.method).toUpperCase();
  } catch {
    return "";
  }
}

function text(value: unknown): string {
  return typeof value === "string" ? value : value == null ? "" : String(value);
}

function numberValue(value: unknown, fallback: number): number {
  const parsed = typeof value === "number" ? value : Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

function stringRecord(value: unknown): Record<string, string> {
  if (!isRecord(value)) {
    return {};
  }
  return Object.fromEntries(
    Object.entries(value).map(([key, item]) => [key, text(item)])
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return Boolean(value) && typeof value === "object" && !Array.isArray(value);
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.stack ?? error.message : String(error);
}
