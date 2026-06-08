import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join as joinPath, resolve as resolvePath } from "node:path";
import { normalizeApiInventory } from "@aegisprobe/security";
import { newId, nowIso, truncateForContext, type ApiDescriptionDocument, type NormalizedApiEndpoint, type SecurityToolRun, type WebAppReconResult } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { sanitizePathSegment } from "./core-helpers.js";

const MAX_API_DESCRIPTION_BYTES = 2_000_000;
const API_DESCRIPTION_FETCH_TIMEOUT_MS = 10_000;

export type ApiDescriptionImportResult = {
  sessionId: string;
  workflowId?: string;
  source: string;
  artifactPath: string;
  apiDescriptionDocuments: ApiDescriptionDocument[];
  normalizedApiEndpoints: NormalizedApiEndpoint[];
};

export function importApiDescriptionDocument(
  store: AuditStore,
  projectRoot: string,
  sessionId: string,
  source: string,
  deps: {
    createSecurityToolRun: (input: Omit<SecurityToolRun, "id" | "status" | "createdAt" | "updatedAt"> & { status?: SecurityToolRun["status"] }) => SecurityToolRun;
    finishSecurityToolRun: (
      run: SecurityToolRun,
      status: SecurityToolRun["status"],
      update?: Partial<Pick<SecurityToolRun, "command" | "inputArtifact" | "outputArtifact" | "outputSummary" | "exitCode" | "blockedReason" | "failureCategory" | "findingCount">>
    ) => SecurityToolRun;
  }
): Promise<ApiDescriptionImportResult> {
  return importApiDescriptionDocumentAsync(store, projectRoot, sessionId, source, deps);
}

async function importApiDescriptionDocumentAsync(
  store: AuditStore,
  projectRoot: string,
  sessionId: string,
  source: string,
  deps: {
    createSecurityToolRun: (input: Omit<SecurityToolRun, "id" | "status" | "createdAt" | "updatedAt"> & { status?: SecurityToolRun["status"] }) => SecurityToolRun;
    finishSecurityToolRun: (
      run: SecurityToolRun,
      status: SecurityToolRun["status"],
      update?: Partial<Pick<SecurityToolRun, "command" | "inputArtifact" | "outputArtifact" | "outputSummary" | "exitCode" | "blockedReason" | "failureCategory" | "findingCount">>
    ) => SecurityToolRun;
  }
): Promise<ApiDescriptionImportResult> {
  const workflow = store.listSecurityWorkflows(sessionId).at(-1);
  const targetUrl = workflow?.target.normalized;
  const startUrl = targetUrl && /^https?:\/\//i.test(targetUrl) ? targetUrl : undefined;
  if (!startUrl) {
    throw new Error("API description import requires a current http(s) security workflow target for scope control.");
  }
  const run = deps.createSecurityToolRun({
    sessionId,
    workflowId: workflow?.id,
    toolId: "api-description-import",
    phase: "frontend",
    origin: "manual",
    inputKind: /^https?:\/\//i.test(source) ? "url" : "file",
    inputCount: 1
  });

  const dir = joinPath(projectRoot, "data", "runs", sanitizePathSegment(sessionId), sanitizePathSegment(workflow?.id ?? "no-workflow"), "browser");
  mkdirSync(dir, { recursive: true });
  const artifactPath = joinPath(dir, `api-description-import-${Date.now()}.json`);
  const redactedSource = /^https?:\/\//i.test(source) ? redactSensitiveUrl(source) : source;

  try {
    const document = await loadApiDescriptionDocument(source, startUrl);
    const syntheticRecon = syntheticReconResult(sessionId, workflow?.id, startUrl ?? document.url, document);
    const normalizedApiEndpoints = normalizeApiInventory(syntheticRecon);
    const result: ApiDescriptionImportResult = {
      sessionId,
      workflowId: workflow?.id,
      source: redactedSource,
      artifactPath,
      apiDescriptionDocuments: [document],
      normalizedApiEndpoints
    };

    writeFileSync(artifactPath, JSON.stringify({
      sessionId,
      workflowId: workflow?.id,
      source: redactedSource,
      generatedAt: nowIso(),
      apiDescriptionDocuments: result.apiDescriptionDocuments.map((item) => apiDescriptionDocumentSummary(item)),
      endpoints: normalizedApiEndpoints
    }, null, 2), "utf8");

    deps.finishSecurityToolRun(run, normalizedApiEndpoints.length > 0 ? "success" : "no_findings", {
      inputArtifact: /^https?:\/\//i.test(source) ? undefined : resolvePath(source),
      outputArtifact: artifactPath,
      outputSummary: `Imported ${document.kind} API description from explicit source and normalized ${normalizedApiEndpoints.length} endpoint(s).`,
      findingCount: normalizedApiEndpoints.filter((endpoint) => endpoint.riskSignals.length > 0).length,
      failureCategory: normalizedApiEndpoints.length > 0 ? "none" : "no_findings"
    });

    store.addEvidence({
      id: newId("evd"),
      sessionId,
      workflowId: workflow?.id,
      source: "manual:api-description-import",
      kind: "tool",
      summary: `Imported ${document.kind} API description from explicit source; normalized endpoints=${normalizedApiEndpoints.length}.`,
      data: JSON.stringify({
        artifactPath,
        source: redactedSource,
        apiDescriptionDocuments: result.apiDescriptionDocuments.map((item) => apiDescriptionDocumentSummary(item)),
        endpoints: normalizedApiEndpoints.slice(0, 100)
      }, null, 2),
      createdAt: nowIso()
    });

    store.addAsset({
      id: newId("asset"),
      sessionId,
      workflowId: workflow?.id,
      kind: "url",
      value: document.url,
      source: `manual:api-description:${document.kind}`,
      confidence: document.error ? "medium" : "high",
      metadata: JSON.stringify(apiDescriptionDocumentSummary(document)),
      createdAt: nowIso()
    });

    for (const endpoint of normalizedApiEndpoints) {
      store.addAsset({
        id: newId("asset"),
        sessionId,
        workflowId: workflow?.id,
        kind: "url",
        value: normalizedEndpointAssetValue(startUrl ?? document.url, endpoint.pathTemplate),
        source: "browser:api-inventory-normalizer",
        confidence: endpoint.confidence,
        metadata: JSON.stringify({
          method: endpoint.method,
          pathTemplate: endpoint.pathTemplate,
          queryParams: endpoint.queryParams,
          bodyParamHints: endpoint.bodyParamHints,
          sources: endpoint.sources,
          authRequired: endpoint.authRequired,
          riskSignals: endpoint.riskSignals,
          examples: endpoint.examples
        }),
        createdAt: nowIso()
      });
    }

    return result;
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    deps.finishSecurityToolRun(run, "failed", {
      outputArtifact: artifactPath,
      outputSummary: `API description import failed: ${message}`,
      blockedReason: message,
      failureCategory: "parse_error"
    });
    writeFileSync(artifactPath, JSON.stringify({
      sessionId,
      workflowId: workflow?.id,
      source: redactedSource,
      generatedAt: nowIso(),
      error: message
    }, null, 2), "utf8");
    throw error;
  }
}

async function loadApiDescriptionDocument(source: string, targetUrl: string): Promise<ApiDescriptionDocument> {
  if (/^https?:\/\//i.test(source)) {
    if (!isSameOrigin(source, targetUrl)) {
      throw new Error(`API description URL must be same-origin as current target (${targetUrl}).`);
    }
    if (/\/graphql(?:\/|\?|$)/i.test(new URL(source).pathname)) {
      return {
        url: redactSensitiveUrl(source),
        kind: "graphql",
        source: "manual",
        title: "Explicit GraphQL endpoint",
        operationCount: 1
      };
    }
    const response = await fetchWithTimeout(source);
    const status = response.status;
    const contentType = response.headers.get("content-type") ?? undefined;
    if (!response.ok) {
      throw new Error(`HTTP ${status} while fetching API description.`);
    }
    const text = await readResponseTextLimited(response, MAX_API_DESCRIPTION_BYTES);
    return parseOpenApiDocument(text, redactSensitiveUrl(source), "manual", status, contentType);
  }

  const absolute = isAbsolute(source) ? source : resolvePath(source);
  if (!existsSync(absolute)) {
    throw new Error(`API description file not found: ${absolute}`);
  }
  const text = readFileSync(absolute, "utf8");
  if (Buffer.byteLength(text, "utf8") > MAX_API_DESCRIPTION_BYTES) {
    throw new Error(`API description file exceeds ${MAX_API_DESCRIPTION_BYTES} bytes.`);
  }
  return parseOpenApiDocument(text, targetUrl, "manual", undefined, undefined);
}

async function fetchWithTimeout(url: string): Promise<Response> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), API_DESCRIPTION_FETCH_TIMEOUT_MS);
  try {
    return await fetch(url, { signal: controller.signal });
  } catch (error) {
    if (error instanceof Error && error.name === "AbortError") {
      throw new Error(`Timed out after ${API_DESCRIPTION_FETCH_TIMEOUT_MS}ms while fetching API description.`);
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

async function readResponseTextLimited(response: Response, maxBytes: number): Promise<string> {
  const length = response.headers.get("content-length");
  if (length && Number(length) > maxBytes) {
    throw new Error(`API description response exceeds ${maxBytes} bytes.`);
  }
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > maxBytes) {
    throw new Error(`API description response exceeds ${maxBytes} bytes.`);
  }
  return text;
}

function parseOpenApiDocument(
  text: string,
  url: string,
  source: ApiDescriptionDocument["source"],
  status?: number,
  contentType?: string
): ApiDescriptionDocument {
  const trimmed = text.trim();
  if (!trimmed.startsWith("{")) {
    throw new Error("Only JSON OpenAPI/Swagger documents are supported for explicit import.");
  }
  const document = redactJsonValue(JSON.parse(trimmed));
  const object = parseJsonObject(document);
  const paths = parseJsonObject(object?.paths);
  return {
    url,
    kind: "openapi",
    source,
    status,
    contentType,
    title: openApiTitle(object),
    operationCount: countOpenApiOperations(paths),
    document
  };
}

function syntheticReconResult(sessionId: string, workflowId: string | undefined, startUrl: string, document: ApiDescriptionDocument): WebAppReconResult {
  return {
    sessionId,
    workflowId,
    startUrl,
    pagesVisited: [],
    forms: [],
    artifactPath: "",
    evidenceId: newId("evd"),
    networkRequests: [],
    buttons: [],
    iframes: [],
    storageItems: [],
    cookies: [],
    jsEndpoints: [],
    jsSensitiveSignals: [],
    apiInventory: [],
    apiDescriptionDocuments: [document],
    authSurface: {
      loginPages: [],
      authEndpoints: [],
      passwordForms: [],
      authStorageKeys: [],
      notes: []
    }
  };
}

function normalizedEndpointAssetValue(startUrl: string, pathTemplate: string): string {
  try {
    return `${new URL(startUrl).origin}${pathTemplate.startsWith("/") ? pathTemplate : `/${pathTemplate}`}`;
  } catch {
    return pathTemplate;
  }
}

function apiDescriptionDocumentSummary(document: ApiDescriptionDocument): Omit<ApiDescriptionDocument, "document"> {
  return {
    url: document.url,
    kind: document.kind,
    source: document.source,
    status: document.status,
    contentType: document.contentType,
    title: document.title,
    operationCount: document.operationCount,
    error: document.error
  };
}

function countOpenApiOperations(paths: Record<string, unknown> | undefined): number {
  if (!paths) return 0;
  const methods = new Set(["get", "post", "put", "patch", "delete", "head", "options", "trace"]);
  let count = 0;
  for (const pathItem of Object.values(paths)) {
    const object = parseJsonObject(pathItem);
    if (!object) continue;
    count += Object.keys(object).filter((key) => methods.has(key.toLowerCase())).length;
  }
  return count;
}

function openApiTitle(document: Record<string, unknown> | undefined): string | undefined {
  const info = parseJsonObject(document?.info);
  const title = info?.title;
  return typeof title === "string" && title.length > 0 ? title : undefined;
}

function parseJsonObject(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function redactJsonValue(value: unknown, keyName = ""): unknown {
  if (Array.isArray(value)) {
    return value.map((item) => redactJsonValue(item, keyName));
  }
  if (value && typeof value === "object") {
    const output: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value as Record<string, unknown>)) {
      output[key] = redactJsonValue(child, key);
    }
    return output;
  }
  if (keyName && isSensitiveName(keyName)) {
    const text = value == null ? "" : String(value);
    return `<redacted:${text.length}>`;
  }
  return typeof value === "string" ? truncateForContext(value, 2000) : value;
}

function redactSensitiveUrl(value: string): string {
  try {
    const url = new URL(value);
    for (const key of [...url.searchParams.keys()]) {
      if (isSensitiveName(key)) {
        const current = url.searchParams.get(key) ?? "";
        url.searchParams.set(key, `<redacted:${current.length}>`);
      }
    }
    return url.href.replace(/%3Credacted%3A(\d+)%3E/gi, "<redacted:$1>");
  } catch {
    return value;
  }
}

function isSensitiveName(name: string): boolean {
  return /(?:pass(?:word)?|passwd|pwd|secret|token|jwt|bearer|authorization|auth|api[_-]?key|access[_-]?key|client[_-]?secret|session|cookie|csrf|xsrf|nonce|otp|mfa|2fa|code|ak|sk)/i.test(name);
}

function isSameOrigin(left: string, right: string): boolean {
  try {
    return new URL(left).origin === new URL(right).origin;
  } catch {
    return false;
  }
}
