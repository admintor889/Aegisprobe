import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join as joinPath } from "node:path";
import { newId, nowIso, truncateForContext, type ApiDescriptionDocument, type BrowserCookieSignal, type BrowserDomButton, type BrowserExplorationResult, type BrowserFormCandidate, type BrowserIframeCandidate, type BrowserNetworkRequest, type BrowserStorageItem, type JsEndpointCandidate, type JsLibrarySignal, type JsSensitiveSignal, type JsSourceMapSignal, type SecurityAuthContext, type SecurityFinding, type SecurityToolRun, type WebAppReconResult } from "@aegisprobe/shared";
import { analyzeJavaScriptAsset, buildAuthSurfaceAssessment, buildJavaScriptBundleAnalysis, normalizeApiInventory, sourceMapUrlForScript, type JavaScriptAssetAnalysis } from "@aegisprobe/security";
import type { AuditStore } from "@aegisprobe/storage";
import { browserRiskSignals, emptyNormalizedSecurityObservation, isApiLikeBrowserUrl, launchChromiumBrowser, loadOptionalPlaywright, normalizeBrowserUrl, uniqueBrowserActions, uniqueStorageSignals } from "./browser-automation.js";
import { sanitizePathSegment } from "./core-helpers.js";
import { recordTechnologyHints } from "./security-observations.js";
import { buildWebPentestControlPlane } from "./web-pentest-control-plane.js";

function browserArtifactDir(projectRoot: string, sessionId: string, workflowId: string | undefined): string {
  return joinPath(
    projectRoot,
    "data",
    "runs",
    sanitizePathSegment(sessionId),
    sanitizePathSegment(workflowId ?? "no-workflow"),
    "browser"
  );
}

function isSameOriginUrl(value: string, origin: string): boolean {
  try {
    return new URL(value).origin === origin;
  } catch {
    return false;
  }
}

function isStaticNoiseUrl(value: string): boolean {
  return /\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot|map)(?:[?#]|$)/i.test(value);
}

function endpointConfidence(value: string, riskSignals: string[]): "low" | "medium" | "high" {
  if (/\/(?:api|graphql|rest|rpc|v\d+|oauth|auth|admin|manage|actuator|swagger|openapi)(?:\/|\?|$)/i.test(value)) {
    return "high";
  }
  if (riskSignals.length > 0 || /^https?:\/\//i.test(value)) {
    return "medium";
  }
  return "low";
}

function normalizeEndpointCandidate(value: string, baseUrl: string, origin: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("data:") || trimmed.startsWith("mailto:") || trimmed.startsWith("tel:")) {
    return undefined;
  }
  const normalized = normalizeBrowserUrl(trimmed, baseUrl);
  if (!/^https?:\/\//i.test(normalized)) {
    return undefined;
  }
  if (!isSameOriginUrl(normalized, origin) || isStaticNoiseUrl(normalized)) {
    return undefined;
  }
  return normalized;
}

function normalizedEndpointAssetValue(startUrl: string, pathTemplate: string): string {
  try {
    return `${new URL(startUrl).origin}${pathTemplate.startsWith("/") ? pathTemplate : `/${pathTemplate}`}`;
  } catch {
    return pathTemplate;
  }
}

function isSensitiveHeaderName(name: string): boolean {
  return /^(?:authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token|x-xsrf-token|access-token|refresh-token|id-token)$/i.test(name)
    || /(?:secret|token|password|passwd|session|credential|api[_-]?key)/i.test(name);
}

function isSensitiveParamName(name: string): boolean {
  return /(?:pass(?:word)?|passwd|pwd|secret|token|jwt|bearer|authorization|auth|api[_-]?key|access[_-]?key|client[_-]?secret|session|cookie|csrf|xsrf|nonce|otp|mfa|2fa|code|ak|sk)/i.test(name);
}

function redactHeaderValue(name: string, value: string): string {
  if (isSensitiveHeaderName(name)) {
    return `<redacted:${value.length}>`;
  }
  return truncateForContext(value, 500);
}

function redactHeaders(headers: Record<string, string> | undefined): Record<string, string> | undefined {
  if (!headers) {
    return undefined;
  }
  const output: Record<string, string> = {};
  for (const [name, value] of Object.entries(headers)) {
    output[name.toLowerCase()] = redactHeaderValue(name, String(value));
  }
  return output;
}

function redactSensitiveUrl(value: string): string {
  try {
    const url = new URL(value);
    for (const key of [...url.searchParams.keys()]) {
      if (isSensitiveParamName(key)) {
        const current = url.searchParams.get(key) ?? "";
        url.searchParams.set(key, `<redacted:${current.length}>`);
      }
    }
    return url.href;
  } catch {
    return value;
  }
}

function technologyHintTextFromRecon(result: WebAppReconResult): string {
  return JSON.stringify({
    startUrl: result.startUrl,
    pagesVisited: result.pagesVisited,
    forms: result.forms.map((form) => ({
      pageUrl: form.pageUrl,
      action: form.action,
      method: form.method,
      inputNames: form.inputNames,
      inputTypes: form.inputTypes,
      label: (form as BrowserFormCandidate & { label?: string }).label,
      riskSignals: form.riskSignals
    })),
    network: result.networkRequests.map((request) => ({
      url: request.url,
      method: request.method,
      status: request.status,
      contentType: request.contentType,
      requestHeaders: request.requestHeaders,
      responseHeaders: request.responseHeaders,
      initiator: request.initiator
    })),
    apiInventory: result.apiInventory,
    normalizedApiEndpoints: result.normalizedApiEndpoints
  });
}

function sanitizeHarArtifact(path: string): void {
  if (!existsSync(path)) {
    return;
  }
  try {
    const har = JSON.parse(readFileSync(path, "utf8")) as any;
    for (const entry of har?.log?.entries ?? []) {
      if (entry.request) {
        entry.request.url = redactSensitiveUrl(String(entry.request.url ?? ""));
        redactHarNameValueArray(entry.request.headers, "header");
        redactHarNameValueArray(entry.request.cookies, "cookie");
        redactHarNameValueArray(entry.request.queryString, "query");
        if (entry.request.postData?.text) {
          entry.request.postData.text = redactRequestBodyPreview(entry.request.postData.text);
          redactHarNameValueArray(entry.request.postData.params, "query");
        }
      }
      if (entry.response) {
        redactHarNameValueArray(entry.response.headers, "header");
        redactHarNameValueArray(entry.response.cookies, "cookie");
      }
    }
    writeFileSync(path, JSON.stringify(har), "utf8");
  } catch {
    // HAR is supplementary evidence; keep recon results even if best-effort sanitization fails.
  }
}

function redactHarNameValueArray(items: unknown, kind: "header" | "cookie" | "query"): void {
  if (!Array.isArray(items)) {
    return;
  }
  for (const item of items) {
    if (!item || typeof item !== "object") {
      continue;
    }
    const record = item as { name?: string; value?: string };
    const name = String(record.name ?? "");
    const value = String(record.value ?? "");
    if (kind === "header" && isSensitiveHeaderName(name)) {
      record.value = `<redacted:${value.length}>`;
    } else if (kind === "cookie" || isSensitiveParamName(name)) {
      record.value = `<redacted:${value.length}>`;
    }
  }
}

function redactRequestBodyPreview(value: string | undefined | null): string {
  const raw = value ?? "";
  if (!raw.trim()) {
    return "";
  }
  const trimmed = raw.trim();
  if (trimmed.startsWith("{") || trimmed.startsWith("[")) {
    try {
      return truncateForContext(JSON.stringify(redactJsonValue(JSON.parse(trimmed))), 500);
    } catch {
      return truncateForContext(raw, 500);
    }
  }
  try {
    const params = new URLSearchParams(raw);
    let hasParams = false;
    for (const key of [...params.keys()]) {
      hasParams = true;
      if (isSensitiveParamName(key)) {
        const current = params.get(key) ?? "";
        params.set(key, `<redacted:${current.length}>`);
      }
    }
    if (hasParams) {
      return truncateForContext(params.toString(), 500);
    }
  } catch {
    // Fall through to generic truncation.
  }
  return truncateForContext(raw, 500);
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
  if (keyName && isSensitiveParamName(keyName)) {
    const text = value == null ? "" : String(value);
    return `<redacted:${text.length}>`;
  }
  return value;
}

function isApiDescriptionUrl(value: string): boolean {
  try {
    const url = new URL(value);
    return /(?:^|\/)(?:swagger|openapi|api-docs)(?:[-_.]?(?:json|ya?ml))?(?:\/|$)|\.(?:json|ya?ml)$/i.test(url.pathname)
      && /swagger|openapi|api-docs/i.test(`${url.pathname} ${url.search}`);
  } catch {
    return false;
  }
}

function isGraphqlEndpointUrl(value: string): boolean {
  try {
    return /\/graphql(?:\/|\?|$)/i.test(new URL(value).pathname);
  } catch {
    return false;
  }
}

function candidateApiDescriptionUrls(input: {
  origin: string;
  links: Iterable<string>;
  scripts: Iterable<string>;
  apiInventory: WebAppReconResult["apiInventory"];
  networkRequests: BrowserNetworkRequest[];
}): Array<Pick<ApiDescriptionDocument, "url" | "kind" | "source">> {
  const candidates: Array<Pick<ApiDescriptionDocument, "url" | "kind" | "source">> = [];
  const addCandidate = (url: string, source: ApiDescriptionDocument["source"]) => {
    if (!isSameOriginUrl(url, input.origin)) return;
    if (isGraphqlEndpointUrl(url)) {
      candidates.push({ url: redactSensitiveUrl(url), kind: "graphql", source });
    } else if (isApiDescriptionUrl(url)) {
      candidates.push({ url: redactSensitiveUrl(url), kind: "openapi", source });
    }
  };
  for (const url of input.links) addCandidate(url, "link");
  for (const url of input.scripts) addCandidate(url, "script");
  for (const item of input.apiInventory) addCandidate(item.url, item.source === "form" ? "link" : item.source);
  for (const request of input.networkRequests) addCandidate(request.url, "network");
  return uniqueBy(candidates, (item) => `${item.kind}:${item.url}`);
}

async function collectApiDescriptionDocuments(input: {
  context: any;
  origin: string;
  links: Iterable<string>;
  scripts: Iterable<string>;
  apiInventory: WebAppReconResult["apiInventory"];
  networkRequests: BrowserNetworkRequest[];
}): Promise<ApiDescriptionDocument[]> {
  const documents: ApiDescriptionDocument[] = [];
  for (const candidate of candidateApiDescriptionUrls(input).slice(0, 20)) {
    if (candidate.kind === "graphql") {
      documents.push({
        ...candidate,
        title: "Observed GraphQL endpoint",
        operationCount: 1
      });
      continue;
    }
    try {
      const response = await input.context.request.get(candidate.url, { timeout: 10_000 });
      const contentType = response.headers()?.["content-type"];
      const status = response.status();
      if (!response.ok()) {
        documents.push({ ...candidate, status, contentType, error: `HTTP ${status}` });
        continue;
      }
      const text = await response.text();
      if (text.length > 2_000_000) {
        documents.push({ ...candidate, status, contentType, error: `API description too large: ${text.length} bytes` });
        continue;
      }
      const trimmed = text.trim();
      if (!trimmed.startsWith("{")) {
        documents.push({ ...candidate, status, contentType, error: "Only JSON OpenAPI documents are parsed automatically." });
        continue;
      }
      const document = redactJsonValue(JSON.parse(trimmed));
      const object = document && typeof document === "object" && !Array.isArray(document) ? document as Record<string, unknown> : undefined;
      const paths = object?.paths && typeof object.paths === "object" && !Array.isArray(object.paths) ? object.paths as Record<string, unknown> : undefined;
      documents.push({
        ...candidate,
        status,
        contentType,
        title: typeof object?.info === "object" && object.info && "title" in object.info ? String((object.info as Record<string, unknown>).title ?? "") : undefined,
        operationCount: countOpenApiOperations(paths),
        document
      });
    } catch (error) {
      documents.push({ ...candidate, error: error instanceof Error ? error.message : String(error) });
    }
  }
  return documents;
}

function countOpenApiOperations(paths: Record<string, unknown> | undefined): number {
  if (!paths) return 0;
  const methods = new Set(["get", "post", "put", "patch", "delete", "head", "options", "trace"]);
  let count = 0;
  for (const pathItem of Object.values(paths)) {
    if (!pathItem || typeof pathItem !== "object" || Array.isArray(pathItem)) continue;
    count += Object.keys(pathItem).filter((key) => methods.has(key.toLowerCase())).length;
  }
  return count;
}

async function fetchSourceMapCandidate(context: any, scriptUrl: string, content: string, origin: string): Promise<{ mapUrl: string; content?: string; error?: string } | undefined> {
  const mapUrl = sourceMapUrlForScript(scriptUrl, content, origin);
  if (!mapUrl) {
    return undefined;
  }
  if (!isSameOriginUrl(mapUrl, origin)) {
    return { mapUrl, error: "source map is outside same-origin scope" };
  }
  try {
    const response = await context.request.get(mapUrl, { timeout: 10_000 });
    if (!response.ok()) {
      return { mapUrl, error: `HTTP ${response.status()}` };
    }
    const text = await response.text();
    if (text.length > 2_000_000) {
      return { mapUrl, error: `source map too large: ${text.length} bytes` };
    }
    return { mapUrl, content: text };
  } catch (error) {
    return { mapUrl, error: error instanceof Error ? error.message : String(error) };
  }
}

function extractJsEndpointCandidates(scriptUrl: string, content: string, origin: string): { endpoints: JsEndpointCandidate[]; signals: JsSensitiveSignal[] } {
  const endpoints: JsEndpointCandidate[] = [];
  const signals: JsSensitiveSignal[] = [];
  const seenEndpoints = new Set<string>();
  const stringRegex = /["'`]((?:https?:\/\/|wss?:\/\/|\/)[^"'`<>{}\s]{2,})["'`]/g;
  let match: RegExpExecArray | null;
  while ((match = stringRegex.exec(content)) !== null) {
    const raw = match[1];
    const normalizedUrl = normalizeEndpointCandidate(raw, scriptUrl, origin);
    if (!normalizedUrl) {
      continue;
    }
    const riskSignals = browserRiskSignals([raw, normalizedUrl]);
    if (!isApiLikeBrowserUrl(normalizedUrl) && riskSignals.length === 0 && !/\/[a-z0-9_-]+\/[a-z0-9_-]+/i.test(new URL(normalizedUrl).pathname)) {
      continue;
    }
    const key = `${scriptUrl}:${normalizedUrl}`;
    if (seenEndpoints.has(key)) {
      continue;
    }
    seenEndpoints.add(key);
    endpoints.push({
      scriptUrl,
      value: redactSensitiveUrl(normalizeBrowserUrl(raw, scriptUrl)),
      normalizedUrl: redactSensitiveUrl(normalizedUrl),
      confidence: endpointConfidence(normalizedUrl, riskSignals),
      riskSignals
    });
  }

  const methodRegex = /\b(fetch|axios\.(?:get|post|put|patch|delete)|\$\.(?:get|post|ajax))\s*\(\s*["'`]([^"'`]+)["'`]/gi;
  while ((match = methodRegex.exec(content)) !== null) {
    const methodCall = match[1].toLowerCase();
    const raw = match[2];
    const normalizedUrl = normalizeEndpointCandidate(raw, scriptUrl, origin);
    if (!normalizedUrl) {
      continue;
    }
    const method = methodCall.includes("post") ? "POST"
      : methodCall.includes("put") ? "PUT"
      : methodCall.includes("patch") ? "PATCH"
      : methodCall.includes("delete") ? "DELETE"
      : undefined;
    const riskSignals = browserRiskSignals([raw, normalizedUrl, method ?? ""]);
    const key = `${scriptUrl}:${method ?? ""}:${normalizedUrl}`;
    if (seenEndpoints.has(key)) {
      continue;
    }
    seenEndpoints.add(key);
    endpoints.push({
      scriptUrl,
      value: redactSensitiveUrl(normalizeBrowserUrl(raw, scriptUrl)),
      normalizedUrl: redactSensitiveUrl(normalizedUrl),
      method,
      confidence: method ? "high" : endpointConfidence(normalizedUrl, riskSignals),
      riskSignals
    });
  }

  const sourceMap = content.match(/sourceMappingURL=([^\s]+)/i)?.[1];
  if (sourceMap) {
    signals.push({
      scriptUrl,
      kind: "source-map",
      evidence: sourceMap.slice(0, 300),
      riskSignals: ["source-map"]
    });
  }

  const sensitiveRegex = /\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|authorization|bearer|client[_-]?secret|jwt|password)\b\s*[:=]\s*["'`]([^"'`]{8,})["'`]/gi;
  while ((match = sensitiveRegex.exec(content)) !== null) {
    signals.push({
      scriptUrl,
      kind: "secret-like-string",
      evidence: `${match[0].split(/[=:]/)[0].trim()}=<redacted:${match[1].length}>`,
      riskSignals: ["sensitive-token"]
    });
    if (signals.length > 50) {
      break;
    }
  }

  const internalHostRegex = /\b(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|internal|staging|dev)\b/gi;
  const internalMatches = [...content.matchAll(internalHostRegex)].slice(0, 20);
  for (const item of internalMatches) {
    signals.push({
      scriptUrl,
      kind: "internal-host",
      evidence: item[0],
      riskSignals: ["internal-host"]
    });
  }

  if (/\b(?:debug|devtools|mock|testMode|bypassAuth)\b\s*[:=]\s*(?:true|1|["'`]true["'`])/i.test(content)) {
    signals.push({
      scriptUrl,
      kind: "debug-flag",
      evidence: "debug/dev/test flag pattern detected",
      riskSignals: ["debug-flag"]
    });
  }

  return { endpoints, signals };
}

function uniqueBy<T>(items: T[], key: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const value = key(item);
    if (seen.has(value)) {
      return false;
    }
    seen.add(value);
    return true;
  });
}

export async function captureBrowserAuthContext(
  store: AuditStore,
  projectRoot: string,
  sessionId: string,
  url: string,
  options: { name: string; role?: string; username?: string; headed?: boolean; waitMs?: number },
  deps: {
    addSecurityAuthContext: (
      sessionId: string,
      input: Omit<SecurityAuthContext, "id" | "sessionId" | "workflowId" | "createdAt" | "updatedAt"> & { workflowId?: string }
    ) => SecurityAuthContext;
  }
): Promise<SecurityAuthContext> {
  const playwright = await loadOptionalPlaywright();
  const latestWorkflow = store.listSecurityWorkflows(sessionId).at(-1);
  const dir = browserArtifactDir(projectRoot, sessionId, latestWorkflow?.id);
  mkdirSync(dir, { recursive: true });
  const storageStatePath = joinPath(dir, `${sanitizePathSegment(options.name)}-storage-state.json`);
  const browser = await launchChromiumBrowser(playwright, { headless: options.headed === false });
  try {
    const context = await browser.newContext();
    const page = await context.newPage();
    await page.goto(url, { waitUntil: "domcontentloaded", timeout: 30_000 });
    await page.waitForTimeout(Math.max(1_000, Math.min(options.waitMs ?? 60_000, 10 * 60_000)));
    await context.storageState({ path: storageStatePath });
    const authContext = deps.addSecurityAuthContext(sessionId, {
      name: options.name,
      role: options.role,
      username: options.username,
      baseUrl: url,
      storageStatePath,
      notes: "Captured from Playwright browser session. Secrets are kept in the local storage-state artifact."
    });
    store.addEvidence({
      id: newId("evd"),
      sessionId,
      workflowId: latestWorkflow?.id,
      source: `browser:auth-capture:${options.name}`,
      kind: "file",
      summary: `Playwright storage state captured for auth context ${options.name}.`,
      data: JSON.stringify({ url, storageStatePath, role: options.role, username: options.username }, null, 2),
      createdAt: nowIso()
    });
    return authContext;
  } finally {
    await browser.close();
  }
}

export async function reconWebApplication(
  store: AuditStore,
  projectRoot: string,
  sessionId: string,
  authOrUrl: string | undefined,
  options: { maxPages?: number; headed?: boolean; analyzeJs?: boolean } = {},
  deps: {
    createSecurityToolRun: (input: Omit<SecurityToolRun, "id" | "status" | "createdAt" | "updatedAt"> & { status?: SecurityToolRun["status"] }) => SecurityToolRun;
    finishSecurityToolRun: (
      run: SecurityToolRun,
      status: SecurityToolRun["status"],
      update?: Partial<Pick<SecurityToolRun, "command" | "inputArtifact" | "outputArtifact" | "outputSummary" | "exitCode" | "blockedReason" | "failureCategory" | "findingCount">>
    ) => SecurityToolRun;
    enrichFindingForStorage: (finding: SecurityFinding, evidenceIds?: string[]) => SecurityFinding;
  }
): Promise<WebAppReconResult> {
  const playwright = await loadOptionalPlaywright();
  const latestWorkflow = store.listSecurityWorkflows(sessionId).at(-1);
  const authContexts = store.listSecurityAuthContexts(sessionId, latestWorkflow?.id);
  const authContext = authOrUrl
    ? authContexts.find((context) => context.name === authOrUrl || context.id === authOrUrl)
    : authContexts.find((context) => Boolean(context.storageStatePath)) ?? authContexts[0];
  const startUrl = /^https?:\/\//i.test(authOrUrl ?? "")
    ? authOrUrl as string
    : authContext?.baseUrl ?? latestWorkflow?.target.normalized;
  if (!startUrl || !/^https?:\/\//i.test(startUrl)) {
    throw new Error("Web application reconnaissance requires a URL target or an auth context with baseUrl.");
  }

  const maxPages = Math.max(1, Math.min(options.maxPages ?? 10, 40));
  const dir = browserArtifactDir(projectRoot, sessionId, latestWorkflow?.id);
  mkdirSync(dir, { recursive: true });
  const artifactPath = joinPath(dir, `webapp-recon-${Date.now()}.json`);
  const harArtifactPath = joinPath(dir, `webapp-recon-${Date.now()}.har`);
  const run = deps.createSecurityToolRun({
    sessionId,
    workflowId: latestWorkflow?.id,
    toolId: "webapp-recon",
    phase: "frontend",
    origin: "manual",
    inputKind: "url",
    inputCount: 1
  });

  const browser = await launchChromiumBrowser(playwright, { headless: options.headed !== true });
  let context: any;
  try {
    const contextOptions = authContext?.storageStatePath && existsSync(authContext.storageStatePath)
      ? { storageState: authContext.storageStatePath, ignoreHTTPSErrors: true, recordHar: { path: harArtifactPath, content: "omit" } }
      : { ignoreHTTPSErrors: true, recordHar: { path: harArtifactPath, content: "omit" } };
    context = await browser.newContext(contextOptions);
    const page = await context.newPage();
    const origin = new URL(startUrl).origin;
    const queue = [startUrl];
    const visited = new Set<string>();
    const forms: BrowserFormCandidate[] = [];
    const links = new Set<string>();
    const scripts = new Set<string>();
    const apiEndpoints = new Set<string>();
    const sensitiveActions: NonNullable<BrowserExplorationResult["sensitiveActions"]> = [];
    const storageSignals: NonNullable<BrowserExplorationResult["storageSignals"]> = [];
    const pageSummaries: NonNullable<BrowserExplorationResult["pageSummaries"]> = [];
    const networkRequests: BrowserNetworkRequest[] = [];
    const buttons: BrowserDomButton[] = [];
    const iframes: BrowserIframeCandidate[] = [];
    const storageItems: BrowserStorageItem[] = [];

    page.on("request", (request: any) => {
      const url = request.url();
      if (!isSameOriginUrl(url, origin) || isStaticNoiseUrl(url)) {
        return;
      }
      const redactedUrl = redactSensitiveUrl(url);
      networkRequests.push({
        pageUrl: page.url(),
        url: redactedUrl,
        method: request.method(),
        resourceType: request.resourceType(),
        initiator: request.frame()?.url?.(),
        requestHeaders: redactHeaders(request.headers?.()),
        requestBodyPreview: redactRequestBodyPreview(request.postData?.())
      });
    });
    page.on("response", (response: any) => {
      const request = response.request();
      const url = redactSensitiveUrl(request.url());
      const item = [...networkRequests].reverse().find((candidate) => candidate.url === url && candidate.method === request.method());
      if (!item) {
        return;
      }
      item.status = response.status();
      item.contentType = response.headers()?.["content-type"];
      item.responseHeaders = redactHeaders(response.headers?.());
    });

    while (queue.length > 0 && visited.size < maxPages) {
      const current = queue.shift();
      if (!current || visited.has(current)) {
        continue;
      }
      visited.add(current);
      await page.goto(current, { waitUntil: "domcontentloaded", timeout: 30_000 }).catch(() => undefined);
      await page.waitForLoadState("networkidle", { timeout: 7_000 }).catch(() => undefined);
      const snapshot = await page.evaluate(() => {
        const doc = (globalThis as any).document;
        const loc = (globalThis as any).location;
        const textOf = (node: any) => (node?.innerText || node?.textContent || node?.getAttribute?.("aria-label") || node?.getAttribute?.("title") || "").trim();
        const storageKeys = (storageName: "localStorage" | "sessionStorage") => {
          try {
            const storage = (globalThis as any)[storageName];
            const keys = [];
            for (let index = 0; index < storage.length; index += 1) {
              const key = storage.key(index);
              if (key) keys.push(key);
            }
            return keys;
          } catch {
            return [];
          }
        };
        const formItems = [...doc.querySelectorAll("form")].map((form: any) => {
          const inputs = [...form.querySelectorAll("input, textarea, select")] as any[];
          const inputNames = inputs.map((input) => input.getAttribute("name") || input.getAttribute("id") || input.getAttribute("type") || "unnamed");
          const inputTypes = inputs.map((input) => input.getAttribute("type") || input.tagName.toLowerCase());
          return {
            action: form.getAttribute("action") || loc.href,
            method: (form.getAttribute("method") || "GET").toUpperCase(),
            inputNames,
            inputTypes,
            hasPassword: inputTypes.some((type) => type.toLowerCase() === "password"),
            hasCsrfToken: inputNames.some((name) => /csrf|xsrf|token|nonce/i.test(name)),
            label: textOf(form).slice(0, 120)
          };
        });
        const links = [...doc.querySelectorAll("a[href]")]
          .map((anchor: any) => ({ href: anchor.href, label: textOf(anchor).slice(0, 120) }))
          .filter(Boolean);
        const scripts = [...doc.querySelectorAll("script[src]")]
          .map((script: any) => script.src)
          .filter(Boolean);
        const resources = ((globalThis as any).performance?.getEntriesByType?.("resource") ?? [])
          .map((entry: any) => entry.name)
          .filter(Boolean);
        const buttons = [...doc.querySelectorAll("button, input[type=button], input[type=submit], [role=button]")]
          .map((button: any) => ({
            label: textOf(button) || button.getAttribute?.("value") || button.getAttribute?.("name") || "button",
            type: button.getAttribute?.("type") || button.tagName?.toLowerCase?.() || "button",
            name: button.getAttribute?.("name") || undefined,
            id: button.getAttribute?.("id") || undefined
          }));
        const iframes = [...doc.querySelectorAll("iframe")]
          .map((frame: any) => ({
            src: frame.src || frame.getAttribute?.("src") || "",
            name: frame.getAttribute?.("name") || undefined,
            title: frame.getAttribute?.("title") || undefined,
            sandbox: frame.getAttribute?.("sandbox") || undefined
          }))
          .filter((frame) => frame.src || frame.name || frame.title);
        const cookieKeys = () => {
          try {
            return String(doc.cookie || "").split(";").map((item) => item.split("=")[0]?.trim()).filter(Boolean);
          } catch {
            return [];
          }
        };
        const storage = {
          localStorage: storageKeys("localStorage"),
          sessionStorage: storageKeys("sessionStorage"),
          cookieKeys: cookieKeys()
        };
        return { forms: formItems, links, scripts, resources, buttons, iframes, storage, title: doc.title };
      }) as {
        forms: Array<Omit<BrowserFormCandidate, "pageUrl" | "riskSignals"> & { label?: string }>;
        links: Array<{ href: string; label: string }>;
        scripts: string[];
        resources: string[];
        buttons: Array<{ label: string; type: string; name?: string; id?: string }>;
        iframes: Array<{ src: string; name?: string; title?: string; sandbox?: string }>;
        storage: { localStorage: string[]; sessionStorage: string[]; cookieKeys: string[] };
        title: string;
      };

      pageSummaries.push({
        url: current,
        title: snapshot.title,
        formCount: snapshot.forms.length,
        linkCount: snapshot.links.length,
        scriptCount: snapshot.scripts.length
      });

      for (const form of snapshot.forms) {
        const action = redactSensitiveUrl(normalizeBrowserUrl(form.action, current));
        const riskSignals = browserRiskSignals([action, form.method, form.inputNames.join(" "), form.label ?? ""]);
        forms.push({ pageUrl: current, ...form, action, riskSignals });
        if (riskSignals.length > 0 || form.hasPassword) {
          sensitiveActions.push({
            pageUrl: current,
            kind: "form",
            label: form.label || `${form.method} form`,
            target: action,
            method: form.method,
            riskSignals: form.hasPassword ? [...new Set([...riskSignals, "auth-surface"])] : riskSignals
          });
        }
      }

      for (const script of [...snapshot.scripts, ...snapshot.resources]) {
        const normalizedRaw = normalizeBrowserUrl(script, current);
        const normalized = redactSensitiveUrl(normalizedRaw);
        if (!isSameOriginUrl(normalized, origin)) {
          continue;
        }
        if (normalized.match(/\.js(?:[?#]|$)/i)) {
          scripts.add(normalized);
        }
        if (isApiLikeBrowserUrl(normalized)) {
          apiEndpoints.add(normalized);
        }
      }

      for (const link of snapshot.links) {
        const normalized = redactSensitiveUrl(normalizeBrowserUrl(link.href, current));
        links.add(normalized);
        const riskSignals = browserRiskSignals([normalized, link.label]);
        if (isApiLikeBrowserUrl(normalized)) {
          apiEndpoints.add(normalized);
        }
        if (riskSignals.length > 0) {
          sensitiveActions.push({
            pageUrl: current,
            kind: "link",
            label: link.label || normalized,
            target: normalized,
            riskSignals
          });
        }
        const normalizedNoHash = normalized.split("#")[0] ?? normalized;
        if (isSameOriginUrl(normalizedNoHash, origin) && !visited.has(normalizedNoHash) && queue.length < maxPages * 4 && !isStaticNoiseUrl(normalizedNoHash)) {
          queue.push(normalizedNoHash);
        }
      }

      for (const button of snapshot.buttons) {
        const riskSignals = browserRiskSignals([button.label, button.type, button.name ?? "", button.id ?? ""]);
        buttons.push({
          pageUrl: current,
          label: button.label,
          type: button.type,
          name: button.name,
          id: button.id,
          riskSignals
        });
        if (riskSignals.length > 0) {
          sensitiveActions.push({
            pageUrl: current,
            kind: "button",
            label: button.label,
            target: current,
            riskSignals
          });
        }
      }

      for (const frame of snapshot.iframes) {
        const normalized = frame.src ? normalizeBrowserUrl(frame.src, current) : "";
        const riskSignals = browserRiskSignals([normalized, frame.name ?? "", frame.title ?? "", frame.sandbox ?? ""]);
        iframes.push({
          pageUrl: current,
          src: normalized,
          name: frame.name,
          title: frame.title,
          sandbox: frame.sandbox,
          riskSignals
        });
      }

      for (const [storageName, keys] of [
        ["localStorage", snapshot.storage.localStorage],
        ["sessionStorage", snapshot.storage.sessionStorage],
        ["cookie", snapshot.storage.cookieKeys]
      ] as const) {
        for (const key of keys) {
          const riskSignals = browserRiskSignals([key]);
          storageItems.push({ pageUrl: current, storage: storageName, key, riskSignals });
          if (riskSignals.length > 0) {
            storageSignals.push({ pageUrl: current, storage: storageName, key, riskSignals });
          }
        }
      }
    }

    const jsEndpoints: JsEndpointCandidate[] = [];
    const jsSensitiveSignals: JsSensitiveSignal[] = [];
    const jsSourceMaps: JsSourceMapSignal[] = [];
    const jsLibraries: JsLibrarySignal[] = [];
    const jsAssetAnalyses: JavaScriptAssetAnalysis[] = [];
    let jsAnalysisArtifactPath: string | undefined;
    let jsAnalysisSummary: WebAppReconResult["jsAnalysisSummary"] | undefined;
    let jsAnalyzerRun: SecurityToolRun | undefined;
    if (options.analyzeJs !== false) {
      jsAnalyzerRun = deps.createSecurityToolRun({
        sessionId,
        workflowId: latestWorkflow?.id,
        parentRunId: run.id,
        toolId: "js-analyzer",
        phase: "frontend",
        origin: "manual",
        inputKind: "url",
        inputCount: scripts.size
      });
      for (const scriptUrl of [...scripts].slice(0, 40)) {
        try {
          const response = await context.request.get(scriptUrl, { timeout: 12_000 });
          if (!response.ok()) {
            continue;
          }
          const content = await response.text();
          const sourceMap = await fetchSourceMapCandidate(context, scriptUrl, content.slice(0, 2_000_000), origin);
          const analysis = analyzeJavaScriptAsset({
            scriptUrl,
            content: content.slice(0, 2_000_000),
            origin,
            sourceMap
          });
          jsAssetAnalyses.push(analysis);
          jsEndpoints.push(...analysis.endpoints);
          jsSensitiveSignals.push(...analysis.sensitiveSignals);
          jsSourceMaps.push(...analysis.sourceMaps);
          jsLibraries.push(...analysis.libraries);
        } catch {
          continue;
        }
      }
      const bundleAnalysis = buildJavaScriptBundleAnalysis(jsAssetAnalyses);
      jsAnalysisSummary = bundleAnalysis.summary;
      jsAnalysisArtifactPath = joinPath(dir, `js-analyzer-${Date.now()}.json`);
      writeFileSync(jsAnalysisArtifactPath, JSON.stringify({
        sessionId,
        workflowId: latestWorkflow?.id,
        generatedAt: nowIso(),
        scripts: [...scripts].slice(0, 40),
        summary: bundleAnalysis.summary,
        endpoints: bundleAnalysis.endpoints,
        sensitiveSignals: bundleAnalysis.sensitiveSignals,
        sourceMaps: bundleAnalysis.sourceMaps,
        libraries: bundleAnalysis.libraries,
        baseUrls: uniqueBy(bundleAnalysis.assets.flatMap((asset) => asset.baseUrls), (value) => value)
      }, null, 2), "utf8");
      deps.finishSecurityToolRun(jsAnalyzerRun, bundleAnalysis.assets.length > 0 ? "success" : "no_findings", {
        outputArtifact: jsAnalysisArtifactPath,
        outputSummary: `JS analyzer processed ${bundleAnalysis.summary.scriptCount} scripts, extracted endpoints=${bundleAnalysis.summary.endpointCount}, sensitiveSignals=${bundleAnalysis.summary.sensitiveSignalCount}, sourceMaps=${bundleAnalysis.summary.sourceMapCount}, libraries=${bundleAnalysis.summary.libraryCount}.`,
        findingCount: bundleAnalysis.summary.sensitiveSignalCount + bundleAnalysis.libraries.filter((library) => library.riskSignals.length > 0).length,
        failureCategory: bundleAnalysis.assets.length > 0 ? "none" : "no_findings"
      });
    }

    for (const endpoint of jsEndpoints) {
      if (endpoint.normalizedUrl) {
        apiEndpoints.add(endpoint.normalizedUrl);
      }
    }
    for (const request of networkRequests) {
      if (isApiLikeBrowserUrl(request.url) || request.resourceType === "xhr" || request.resourceType === "fetch") {
        apiEndpoints.add(request.url);
      }
    }

    const cookies: BrowserCookieSignal[] = [];
    try {
      const cookieItems = await context.cookies([...visited]);
      for (const cookie of cookieItems) {
        const riskSignals = browserRiskSignals([cookie.name, cookie.domain ?? "", cookie.path ?? ""]);
        cookies.push({
          pageUrl: startUrl,
          name: cookie.name,
          domain: cookie.domain,
          path: cookie.path,
          httpOnly: cookie.httpOnly,
          secure: cookie.secure,
          sameSite: cookie.sameSite,
          expires: cookie.expires,
          riskSignals
        });
      }
    } catch {
      // Cookie access can fail on unusual browser contexts; storage keys above remain best-effort evidence.
    }

    const apiInventory: WebAppReconResult["apiInventory"] = uniqueBy<WebAppReconResult["apiInventory"][number]>([
      ...[...apiEndpoints].map((url) => ({
        url,
        source: "resource" as const,
        confidence: endpointConfidence(url, browserRiskSignals([url])),
        riskSignals: browserRiskSignals([url])
      })),
      ...forms.map((form) => ({
        url: form.action,
        method: form.method,
        source: "form" as const,
        confidence: form.hasPassword || form.riskSignals?.length ? "medium" as const : "low" as const,
        riskSignals: form.riskSignals ?? []
      })),
      ...jsEndpoints.filter((endpoint) => endpoint.normalizedUrl).map((endpoint) => ({
        url: endpoint.normalizedUrl as string,
        method: endpoint.method,
        source: "script" as const,
        confidence: endpoint.confidence,
        riskSignals: endpoint.riskSignals
      })),
      ...networkRequests.filter((request) => request.resourceType === "xhr" || request.resourceType === "fetch" || isApiLikeBrowserUrl(request.url)).map((request) => ({
        url: request.url,
        method: request.method,
        source: "network" as const,
        confidence: "high" as const,
        riskSignals: browserRiskSignals([request.url, request.method])
      }))
    ], (item) => `${item.source}:${item.method ?? ""}:${item.url}`);

    const apiDescriptionDocuments = await collectApiDescriptionDocuments({
      context,
      origin,
      links,
      scripts,
      apiInventory,
      networkRequests
    });

    const authSurface = {
      loginPages: uniqueBy([...visited].filter((url) => /login|signin|auth|account|admin/i.test(url)), (url) => url),
      authEndpoints: uniqueBy(apiInventory.filter((item) => /login|signin|logout|register|reset|password|oauth|sso|token|session|auth/i.test(item.url)).map((item) => item.url), (url) => url),
      passwordForms: forms.filter((form) => form.hasPassword),
      authStorageKeys: uniqueBy(storageSignals.filter((signal) => signal.riskSignals.includes("sensitive-token")).map((signal) => ({
        pageUrl: signal.pageUrl,
        storage: signal.storage,
        key: signal.key
      })), (item) => `${item.pageUrl}:${item.storage}:${item.key}`),
      notes: [
        forms.some((form) => form.hasPassword && !form.hasCsrfToken) ? "Password form found without an obvious CSRF-like field; validate server-side CSRF/session behavior before reporting." : "",
        apiInventory.some((item) => /admin|manage|console/i.test(item.url)) ? "Privileged route candidates found; map required roles before active authorization testing." : "",
        jsSensitiveSignals.some((signal) => signal.kind === "secret-like-string") ? "Secret-like frontend strings found; values were redacted and require manual false-positive review." : ""
      ].filter(Boolean)
    };

    const result: WebAppReconResult = {
      sessionId,
      workflowId: latestWorkflow?.id,
      startUrl,
      pagesVisited: [...visited],
      forms,
      links: [...links],
      scripts: [...scripts],
      apiEndpoints: [...apiEndpoints],
      sensitiveActions: uniqueBrowserActions(sensitiveActions),
      storageSignals: uniqueStorageSignals(storageSignals),
      pageSummaries,
      storageStatePath: authContext?.storageStatePath,
      artifactPath,
      harArtifactPath,
      evidenceId: newId("evd"),
      networkRequests: uniqueBy(networkRequests, (request) => `${request.method}:${request.url}:${request.resourceType}:${request.status ?? ""}`),
      buttons: uniqueBy(buttons, (button) => `${button.pageUrl}:${button.type}:${button.name ?? ""}:${button.id ?? ""}:${button.label}`),
      iframes: uniqueBy(iframes, (frame) => `${frame.pageUrl}:${frame.src}:${frame.name ?? ""}:${frame.title ?? ""}`),
      storageItems: uniqueBy(storageItems, (item) => `${item.pageUrl}:${item.storage}:${item.key}`),
      cookies: uniqueBy(cookies, (cookie) => `${cookie.domain ?? ""}:${cookie.path ?? ""}:${cookie.name}`),
      jsEndpoints: uniqueBy(jsEndpoints, (endpoint) => `${endpoint.method ?? ""}:${endpoint.normalizedUrl ?? endpoint.value}:${endpoint.scriptUrl}`),
      jsSensitiveSignals: uniqueBy(jsSensitiveSignals, (signal) => `${signal.scriptUrl}:${signal.kind}:${signal.evidence}`),
      jsSourceMaps: uniqueBy(jsSourceMaps, (sourceMap) => `${sourceMap.scriptUrl}:${sourceMap.mapUrl}`),
      jsLibraries: uniqueBy(jsLibraries, (library) => `${library.scriptUrl}:${library.name}:${library.version ?? ""}`),
      jsAnalysisSummary,
      apiInventory,
      apiDescriptionDocuments,
      authSurface
    };

    const normalizedApiRun = deps.createSecurityToolRun({
      sessionId,
      workflowId: latestWorkflow?.id,
      parentRunId: run.id,
      toolId: "api-inventory-normalizer",
      phase: "frontend",
      origin: "manual",
      inputKind: "file",
      inputCount: result.apiInventory.length + apiDescriptionDocuments.length,
      inputArtifact: artifactPath
    });
    const normalizedApiEndpoints = normalizeApiInventory(result);
    const normalizedApiArtifactPath = joinPath(dir, `webapp-api-inventory-${Date.now()}.json`);
    result.normalizedApiEndpoints = normalizedApiEndpoints;
    result.normalizedApiArtifactPath = normalizedApiArtifactPath;
    writeFileSync(normalizedApiArtifactPath, JSON.stringify({
      sessionId,
      workflowId: latestWorkflow?.id,
      sourceArtifact: artifactPath,
      generatedAt: nowIso(),
      apiDescriptionDocuments: apiDescriptionDocuments.map((document) => ({
        url: document.url,
        kind: document.kind,
        source: document.source,
        status: document.status,
        contentType: document.contentType,
        title: document.title,
        operationCount: document.operationCount,
        error: document.error
      })),
      endpoints: normalizedApiEndpoints
    }, null, 2), "utf8");
    deps.finishSecurityToolRun(normalizedApiRun, normalizedApiEndpoints.length > 0 ? "success" : "no_findings", {
      outputArtifact: normalizedApiArtifactPath,
      outputSummary: `API inventory normalizer grouped ${result.apiInventory.length} raw entries and ${apiDescriptionDocuments.length} API description document(s) into ${normalizedApiEndpoints.length} method/path templates.`,
      findingCount: normalizedApiEndpoints.filter((endpoint) => endpoint.riskSignals.length > 0).length,
      failureCategory: normalizedApiEndpoints.length > 0 ? "none" : "no_findings"
    });

    const authAssessmentRun = deps.createSecurityToolRun({
      sessionId,
      workflowId: latestWorkflow?.id,
      parentRunId: run.id,
      toolId: "auth-surface-model",
      phase: "frontend",
      origin: "manual",
      inputKind: "file",
      inputCount: result.authSurface.loginPages.length + result.authSurface.authEndpoints.length + result.authSurface.passwordForms.length,
      inputArtifact: artifactPath
    });
    const authAssessment = buildAuthSurfaceAssessment(result);
    const authAssessmentArtifactPath = joinPath(dir, `auth-surface-model-${Date.now()}.json`);
    result.authAssessment = authAssessment;
    result.authAssessmentArtifactPath = authAssessmentArtifactPath;
    writeFileSync(authAssessmentArtifactPath, JSON.stringify({
      sessionId,
      workflowId: latestWorkflow?.id,
      sourceArtifact: artifactPath,
      generatedAt: nowIso(),
      assessment: authAssessment
    }, null, 2), "utf8");
    deps.finishSecurityToolRun(authAssessmentRun, authAssessment.confidence === "low" && authAssessment.login === "not_observed" ? "no_findings" : "success", {
      outputArtifact: authAssessmentArtifactPath,
      outputSummary: `Auth surface model: state=${authAssessment.authState}, login=${authAssessment.login}, mechanisms=${authAssessment.sessionMechanisms.join(",")}, highValueFlows=${authAssessment.highValueFlows.length}.`,
      findingCount: authAssessment.riskSignals.length,
      failureCategory: authAssessment.confidence === "low" && authAssessment.login === "not_observed" ? "no_findings" : "none"
    });

    writeFileSync(artifactPath, JSON.stringify(result, null, 2), "utf8");
    deps.finishSecurityToolRun(run, result.pagesVisited.length > 0 ? "success" : "no_findings", {
      outputArtifact: artifactPath,
      outputSummary: `WebApp recon visited ${result.pagesVisited.length} pages, observed ${result.networkRequests.length} network requests, captured buttons=${result.buttons?.length ?? 0}, iframes=${result.iframes?.length ?? 0}, storageKeys=${result.storageItems?.length ?? 0}, cookies=${result.cookies?.length ?? 0}, extracted ${result.jsEndpoints.length} JS endpoints, inventoried ${result.apiInventory.length} raw API/form targets, parsed ${apiDescriptionDocuments.length} API description document(s), normalized ${normalizedApiEndpoints.length} API route templates, and modeled auth state=${authAssessment.authState}.`,
      findingCount: result.jsSensitiveSignals.length + result.authSurface.passwordForms.filter((form) => !form.hasCsrfToken).length,
      failureCategory: result.pagesVisited.length > 0 ? "none" : "no_findings"
    });
    recordTechnologyHints(store, {
      sessionId,
      workflowId: latestWorkflow?.id ?? "no-workflow",
      target: startUrl,
      text: technologyHintTextFromRecon(result),
      source: "browser:webapp-recon"
    });

    store.addEvidence({
      id: result.evidenceId,
      sessionId,
      workflowId: latestWorkflow?.id,
      source: "browser:webapp-recon",
      kind: "tool",
      summary: `WebApp recon mapped pages=${result.pagesVisited.length}, scripts=${result.scripts?.length ?? 0}, apiInventory=${result.apiInventory.length}, apiDescriptions=${apiDescriptionDocuments.length}, network=${result.networkRequests.length}, buttons=${result.buttons?.length ?? 0}, iframes=${result.iframes?.length ?? 0}, storageKeys=${result.storageItems?.length ?? 0}, cookies=${result.cookies?.length ?? 0}.`,
      data: JSON.stringify(result, null, 2),
      createdAt: nowIso()
    });

    const jsAnalyzerEvidenceId = jsAnalysisArtifactPath ? newId("evd") : undefined;
    if (jsAnalyzerEvidenceId && result.jsAnalysisSummary) {
      store.addEvidence({
        id: jsAnalyzerEvidenceId,
        sessionId,
        workflowId: latestWorkflow?.id,
        source: "browser:js-analyzer",
        kind: "tool",
        summary: `JS analyzer processed scripts=${result.jsAnalysisSummary.scriptCount}, endpoints=${result.jsAnalysisSummary.endpointCount}, sensitiveSignals=${result.jsAnalysisSummary.sensitiveSignalCount}, sourceMaps=${result.jsAnalysisSummary.sourceMapCount}, libraries=${result.jsAnalysisSummary.libraryCount}.`,
        data: JSON.stringify({
          artifactPath: jsAnalysisArtifactPath,
          summary: result.jsAnalysisSummary,
          endpoints: result.jsEndpoints.slice(0, 100),
          sensitiveSignals: result.jsSensitiveSignals.slice(0, 100),
          sourceMaps: result.jsSourceMaps?.slice(0, 50) ?? [],
          libraries: result.jsLibraries?.slice(0, 50) ?? []
        }, null, 2),
        createdAt: nowIso()
      });
    }

    const normalizedApiEvidenceId = newId("evd");
    store.addEvidence({
      id: normalizedApiEvidenceId,
      sessionId,
      workflowId: latestWorkflow?.id,
      source: "browser:api-inventory-normalizer",
      kind: "tool",
      summary: `Normalized API inventory grouped ${result.apiInventory.length} raw entries and ${apiDescriptionDocuments.length} API description document(s) into ${normalizedApiEndpoints.length} method/path templates.`,
      data: JSON.stringify({
        artifactPath: normalizedApiArtifactPath,
        apiDescriptionDocuments: apiDescriptionDocuments.map((document) => ({
          url: document.url,
          kind: document.kind,
          source: document.source,
          status: document.status,
          contentType: document.contentType,
          title: document.title,
          operationCount: document.operationCount,
          error: document.error
        })),
        endpoints: normalizedApiEndpoints.slice(0, 100)
      }, null, 2),
      createdAt: nowIso()
    });

    const authAssessmentEvidenceId = newId("evd");
    store.addEvidence({
      id: authAssessmentEvidenceId,
      sessionId,
      workflowId: latestWorkflow?.id,
      source: "browser:auth-surface-model",
      kind: "tool",
      summary: `Auth surface model state=${authAssessment.authState}, login=${authAssessment.login}, mechanisms=${authAssessment.sessionMechanisms.join(",")}, csrf=${authAssessment.csrfSignals}, highValueFlows=${authAssessment.highValueFlows.length}.`,
      data: JSON.stringify({
        artifactPath: authAssessmentArtifactPath,
        assessment: authAssessment
      }, null, 2),
      createdAt: nowIso()
    });

    for (const pageUrl of result.pagesVisited) {
      store.addAsset({
        id: newId("asset"),
        sessionId,
        workflowId: latestWorkflow?.id,
        kind: "url",
        value: pageUrl,
        source: "browser:webapp-recon:page",
        confidence: "medium",
        metadata: JSON.stringify({ startUrl }),
        createdAt: nowIso()
      });
    }
    for (const item of result.apiInventory) {
      store.addAsset({
        id: newId("asset"),
        sessionId,
        workflowId: latestWorkflow?.id,
        kind: "url",
        value: item.url,
        source: `browser:webapp-recon:${item.source}`,
        confidence: item.confidence,
        metadata: JSON.stringify({ method: item.method, riskSignals: item.riskSignals }),
        createdAt: nowIso()
      });
    }
    for (const document of apiDescriptionDocuments) {
      store.addAsset({
        id: newId("asset"),
        sessionId,
        workflowId: latestWorkflow?.id,
        kind: "url",
        value: document.url,
        source: `browser:api-description:${document.kind}`,
        confidence: document.error ? "medium" : "high",
        metadata: JSON.stringify({
          kind: document.kind,
          source: document.source,
          status: document.status,
          contentType: document.contentType,
          title: document.title,
          operationCount: document.operationCount,
          error: document.error
        }),
        createdAt: nowIso()
      });
    }
    for (const endpoint of normalizedApiEndpoints) {
      store.addAsset({
        id: newId("asset"),
        sessionId,
        workflowId: latestWorkflow?.id,
        kind: "url",
        value: normalizedEndpointAssetValue(startUrl, endpoint.pathTemplate),
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
    for (const scriptUrl of result.scripts ?? []) {
      store.addAsset({
        id: newId("asset"),
        sessionId,
        workflowId: latestWorkflow?.id,
        kind: "url",
        value: scriptUrl,
        source: "browser:webapp-recon:script",
        confidence: "medium",
        metadata: JSON.stringify({ assetType: "javascript" }),
        createdAt: nowIso()
      });
    }
    for (const sourceMap of result.jsSourceMaps ?? []) {
      store.addAsset({
        id: newId("asset"),
        sessionId,
        workflowId: latestWorkflow?.id,
        kind: "url",
        value: sourceMap.mapUrl,
        source: "browser:js-analyzer:source-map",
        confidence: sourceMap.available ? "high" : "medium",
        metadata: JSON.stringify({
          scriptUrl: sourceMap.scriptUrl,
          available: sourceMap.available,
          sourceCount: sourceMap.sourceCount,
          sourcesSample: sourceMap.sourcesSample,
          riskSignals: sourceMap.riskSignals,
          error: sourceMap.error
        }),
        createdAt: nowIso()
      });
    }

    if (result.apiInventory.length > 0 || result.jsSensitiveSignals.length > 0 || result.authSurface.passwordForms.length > 0) {
      store.upsertFinding(deps.enrichFindingForStorage({
        id: newId("find"),
        sessionId,
        workflowId: latestWorkflow?.id,
        title: "Web application attack surface inventory",
        severity: result.jsSensitiveSignals.length > 0 ? "low" : "info",
        confidence: "medium",
        target: startUrl,
        description: "Browser-driven reconnaissance mapped frontend routes, runtime network requests, JavaScript endpoints, and authentication surface. These are evidence-backed review targets, not confirmed vulnerabilities.",
        evidenceSummary: JSON.stringify({
          apiInventory: result.apiInventory.slice(0, 30),
          authSurface: {
            loginPages: result.authSurface.loginPages,
            authEndpoints: result.authSurface.authEndpoints,
            passwordForms: result.authSurface.passwordForms.map((form) => ({ pageUrl: form.pageUrl, action: form.action, method: form.method, csrf: form.hasCsrfToken })),
            notes: result.authSurface.notes
          },
          authAssessment: result.authAssessment,
          browserSurface: {
            buttons: result.buttons?.slice(0, 30).map((button) => ({ pageUrl: button.pageUrl, label: button.label, type: button.type, name: button.name, id: button.id, riskSignals: button.riskSignals })),
            iframes: result.iframes?.slice(0, 20),
            storageItems: result.storageItems?.slice(0, 50),
            cookies: result.cookies?.slice(0, 50)
          },
          jsAnalysisSummary: result.jsAnalysisSummary,
          jsSensitiveSignals: result.jsSensitiveSignals.slice(0, 20),
          jsSourceMaps: result.jsSourceMaps?.slice(0, 20),
          jsLibraries: result.jsLibraries?.slice(0, 20)
        }).slice(0, 10_000),
        remediation: "Use this inventory to prioritize endpoint authorization, input validation, sensitive data exposure, and business workflow testing with authorized accounts.",
        createdAt: nowIso(),
        updatedAt: nowIso()
      }, [result.evidenceId, normalizedApiEvidenceId, authAssessmentEvidenceId]));
    }

    if (authAssessment.login === "present" || authAssessment.sessionMechanisms.some((mechanism) => mechanism !== "unknown") || authAssessment.highValueFlows.length > 0 || authAssessment.riskSignals.length > 0) {
      store.upsertFinding(deps.enrichFindingForStorage({
        id: newId("find"),
        sessionId,
        workflowId: latestWorkflow?.id,
        title: "Authentication and session surface model",
        severity: authAssessment.riskSignals.length > 0 ? "low" : "info",
        confidence: authAssessment.confidence,
        target: startUrl,
        description: "Browser and API evidence was normalized into authentication state, session mechanism, CSRF, and high-value flow signals. These are planning signals for authorized account-based testing, not vulnerability proof.",
        evidenceSummary: JSON.stringify({
          artifactPath: authAssessmentArtifactPath,
          assessment: authAssessment
        }).slice(0, 10_000),
        remediation: "Register authorized test accounts or Playwright storage states, define expected role/tenant/object boundaries, and validate auth/session behavior only within approved scope.",
        createdAt: nowIso(),
        updatedAt: nowIso()
      }, [authAssessmentEvidenceId]));
    }

    if (jsAnalyzerEvidenceId && ((result.jsSourceMaps?.length ?? 0) > 0 || (result.jsLibraries?.some((library) => library.riskSignals.length > 0) ?? false) || result.jsSensitiveSignals.length > 0)) {
      store.upsertFinding(deps.enrichFindingForStorage({
        id: newId("find"),
        sessionId,
        workflowId: latestWorkflow?.id,
        title: "Frontend JavaScript analysis signals",
        severity: result.jsSensitiveSignals.length > 0 ? "low" : "info",
        confidence: "medium",
        target: startUrl,
        description: "Static JavaScript analysis extracted API routes, frontend-sensitive hints, source-map metadata, and client library fingerprints. These are evidence-backed review candidates, not confirmed vulnerabilities.",
        evidenceSummary: JSON.stringify({
          artifactPath: jsAnalysisArtifactPath,
          summary: result.jsAnalysisSummary,
          sensitiveSignals: result.jsSensitiveSignals.slice(0, 30),
          sourceMaps: result.jsSourceMaps?.slice(0, 30),
          libraries: result.jsLibraries?.filter((library) => library.riskSignals.length > 0).slice(0, 30)
        }).slice(0, 10_000),
        remediation: "Review exposed frontend source maps, remove debug/test flags from production bundles, avoid embedding client-side secrets, and validate library versions against authoritative advisories before reporting.",
        createdAt: nowIso(),
        updatedAt: nowIso()
      }, [jsAnalyzerEvidenceId]));
    }

    if (normalizedApiEndpoints.length > 0) {
      store.upsertFinding(deps.enrichFindingForStorage({
        id: newId("find"),
        sessionId,
        workflowId: latestWorkflow?.id,
        title: "Normalized API route inventory",
        severity: "info",
        confidence: normalizedApiEndpoints.some((endpoint) => endpoint.confidence === "high") ? "high" : "medium",
        target: startUrl,
        description: "Observed browser, form, JavaScript, and runtime network evidence was clustered into low-cardinality API method/path templates. This inventory guides authorization and business-logic planning; it is not a vulnerability by itself.",
        evidenceSummary: JSON.stringify({
          artifactPath: normalizedApiArtifactPath,
          endpointCount: normalizedApiEndpoints.length,
          endpoints: normalizedApiEndpoints.slice(0, 30).map((endpoint) => ({
            method: endpoint.method,
            pathTemplate: endpoint.pathTemplate,
            queryParams: endpoint.queryParams,
            bodyParamHints: endpoint.bodyParamHints,
            sources: endpoint.sources,
            authRequired: endpoint.authRequired,
            confidence: endpoint.confidence,
            riskSignals: endpoint.riskSignals
          }))
        }).slice(0, 10_000),
        remediation: "Use normalized API templates to build a role-aware authorization matrix, identify object-scoped routes, and plan non-destructive business-logic validation within approved scope.",
        createdAt: nowIso(),
        updatedAt: nowIso()
      }, [normalizedApiEvidenceId]));
    }

    const controlPlane = buildWebPentestControlPlane(store, sessionId, latestWorkflow?.id);
    const controlPlaneArtifactPath = joinPath(dir, `web-pentest-control-plane-${Date.now()}.json`);
    writeFileSync(controlPlaneArtifactPath, JSON.stringify({
      sessionId,
      workflowId: latestWorkflow?.id,
      generatedFrom: {
        webappReconArtifact: artifactPath,
        normalizedApiArtifact: normalizedApiArtifactPath,
        authAssessmentArtifact: authAssessmentArtifactPath,
        jsAnalysisArtifact: jsAnalysisArtifactPath
      },
      controlPlane
    }, null, 2), "utf8");
    store.addEvidence({
      id: newId("evd"),
      sessionId,
      workflowId: latestWorkflow?.id,
      source: "web:control-plane",
      kind: "note",
      summary: [
        `Web pentest control plane stage=${controlPlane.stage}`,
        `normalizedApi=${controlPlane.evidenceCounts.normalizedApiEndpoints}`,
        `jsAssets=${controlPlane.evidenceCounts.scriptAssets}`,
        `authContexts=${controlPlane.evidenceCounts.authContexts}`,
        `next=${truncateForContext(controlPlane.nextBestActions[0] ?? controlPlane.summary, 240)}`
      ].join("; "),
      data: JSON.stringify({
        artifactPath: controlPlaneArtifactPath,
        controlPlane
      }, null, 2),
      createdAt: nowIso()
    });

    return result;
  } catch (error) {
    deps.finishSecurityToolRun(run, "failed", {
      outputSummary: error instanceof Error ? error.message : String(error),
      failureCategory: "tool_error"
    });
    throw error;
  } finally {
    if (context) {
      await context.close().catch(() => undefined);
    }
    sanitizeHarArtifact(harArtifactPath);
    await browser.close();
  }
}

export async function exploreBrowserForms(
  store: AuditStore,
  projectRoot: string,
  sessionId: string,
  authOrUrl: string | undefined,
  options: { maxPages?: number; headed?: boolean },
  deps: {
    createSecurityToolRun: (input: Omit<SecurityToolRun, "id" | "status" | "createdAt" | "updatedAt"> & { status?: SecurityToolRun["status"] }) => SecurityToolRun;
    finishSecurityToolRun: (
      run: SecurityToolRun,
      status: SecurityToolRun["status"],
      update?: Partial<Pick<SecurityToolRun, "command" | "inputArtifact" | "outputArtifact" | "outputSummary" | "exitCode" | "blockedReason" | "failureCategory" | "findingCount">>
    ) => SecurityToolRun;
    enrichFindingForStorage: (finding: SecurityFinding, evidenceIds?: string[]) => SecurityFinding;
  }
): Promise<BrowserExplorationResult> {
  const playwright = await loadOptionalPlaywright();
  const latestWorkflow = store.listSecurityWorkflows(sessionId).at(-1);
  const authContexts = store.listSecurityAuthContexts(sessionId, latestWorkflow?.id);
  const authContext = authOrUrl
    ? authContexts.find((context) => context.name === authOrUrl || context.id === authOrUrl)
    : authContexts.find((context) => Boolean(context.storageStatePath)) ?? authContexts[0];
  const startUrl = /^https?:\/\//i.test(authOrUrl ?? "")
    ? authOrUrl as string
    : authContext?.baseUrl ?? latestWorkflow?.target.normalized;
  if (!startUrl || !/^https?:\/\//i.test(startUrl)) {
    throw new Error("Browser form exploration requires a URL target or an auth context with baseUrl.");
  }
  const maxPages = Math.max(1, Math.min(options.maxPages ?? 8, 30));
  const dir = browserArtifactDir(projectRoot, sessionId, latestWorkflow?.id);
  mkdirSync(dir, { recursive: true });
  const artifactPath = joinPath(dir, `browser-forms-${Date.now()}.json`);
  const run = deps.createSecurityToolRun({
    sessionId,
    workflowId: latestWorkflow?.id,
    toolId: "browser-forms",
    phase: "frontend",
    origin: "manual",
    inputKind: "url",
    inputCount: 1
  });
  const browser = await launchChromiumBrowser(playwright, { headless: options.headed !== true });
  try {
    const contextOptions = authContext?.storageStatePath && existsSync(authContext.storageStatePath)
      ? { storageState: authContext.storageStatePath }
      : {};
    const context = await browser.newContext(contextOptions);
    const page = await context.newPage();
    const origin = new URL(startUrl).origin;
    const queue = [startUrl];
    const visited = new Set<string>();
    const forms: BrowserFormCandidate[] = [];
    const links = new Set<string>();
    const scripts = new Set<string>();
    const apiEndpoints = new Set<string>();
    const sensitiveActions: NonNullable<BrowserExplorationResult["sensitiveActions"]> = [];
    const storageSignals: NonNullable<BrowserExplorationResult["storageSignals"]> = [];
    const pageSummaries: NonNullable<BrowserExplorationResult["pageSummaries"]> = [];
    while (queue.length > 0 && visited.size < maxPages) {
      const current = queue.shift();
      if (!current || visited.has(current)) {
        continue;
      }
      visited.add(current);
      await page.goto(current, { waitUntil: "domcontentloaded", timeout: 30_000 }).catch(() => undefined);
      await page.waitForLoadState("networkidle", { timeout: 5_000 }).catch(() => undefined);
      const snapshot = await page.evaluate(() => {
        const doc = (globalThis as any).document;
        const loc = (globalThis as any).location;
        const textOf = (node: any) => (node?.innerText || node?.textContent || node?.getAttribute?.("aria-label") || node?.getAttribute?.("title") || "").trim();
        const storageKeys = (storageName: "localStorage" | "sessionStorage") => {
          try {
            const storage = (globalThis as any)[storageName];
            const keys = [];
            for (let index = 0; index < storage.length; index += 1) {
              const key = storage.key(index);
              if (key) keys.push(key);
            }
            return keys;
          } catch {
            return [];
          }
        };
        const formItems = [...doc.querySelectorAll("form")].map((form: any) => {
          const inputs = [...form.querySelectorAll("input, textarea, select")] as any[];
          const inputNames = inputs.map((input) => input.getAttribute("name") || input.getAttribute("id") || input.getAttribute("type") || "unnamed");
          const inputTypes = inputs.map((input) => input.getAttribute("type") || input.tagName.toLowerCase());
          return {
            action: form.getAttribute("action") || loc.href,
            method: (form.getAttribute("method") || "GET").toUpperCase(),
            inputNames,
            inputTypes,
            hasPassword: inputTypes.some((type) => type.toLowerCase() === "password"),
            hasCsrfToken: inputNames.some((name) => /csrf|xsrf|token|nonce/i.test(name)),
            label: textOf(form).slice(0, 120)
          };
        });
        const links = [...doc.querySelectorAll("a[href]")]
          .map((anchor: any) => ({ href: anchor.href, label: textOf(anchor).slice(0, 120) }))
          .filter(Boolean);
        const scripts = [...doc.querySelectorAll("script[src]")]
          .map((script: any) => script.src)
          .filter(Boolean);
        const resources = ((globalThis as any).performance?.getEntriesByType?.("resource") ?? [])
          .map((entry: any) => entry.name)
          .filter(Boolean);
        const buttons = [...doc.querySelectorAll("button, input[type=button], input[type=submit], [role=button]")]
          .map((button: any) => ({
            label: textOf(button) || button.getAttribute?.("value") || button.getAttribute?.("name") || "button",
            type: button.getAttribute?.("type") || button.tagName?.toLowerCase?.() || "button"
          }));
        const cookieKeys = () => {
          try {
            return String(doc.cookie || "").split(";").map((item) => item.split("=")[0]?.trim()).filter(Boolean);
          } catch {
            return [];
          }
        };
        const storage = {
          localStorage: storageKeys("localStorage"),
          sessionStorage: storageKeys("sessionStorage"),
          cookieKeys: cookieKeys()
        };
        return { forms: formItems, links, scripts, resources, buttons, storage, title: doc.title };
      }) as {
        forms: Array<Omit<BrowserFormCandidate, "pageUrl" | "riskSignals"> & { label?: string }>;
        links: Array<{ href: string; label: string }>;
        scripts: string[];
        resources: string[];
        buttons: Array<{ label: string; type: string }>;
        storage: { localStorage: string[]; sessionStorage: string[]; cookieKeys: string[] };
        title: string;
      };
      pageSummaries.push({
        url: current,
        title: snapshot.title,
        formCount: snapshot.forms.length,
        linkCount: snapshot.links.length,
        scriptCount: snapshot.scripts.length
      });
      for (const form of snapshot.forms) {
        const action = normalizeBrowserUrl(form.action, current);
        const riskSignals = browserRiskSignals([action, form.method, form.inputNames.join(" "), form.label ?? ""]);
        forms.push({ pageUrl: current, ...form, action, riskSignals });
        if (riskSignals.length > 0) {
          sensitiveActions.push({
            pageUrl: current,
            kind: "form",
            label: form.label || `${form.method} form`,
            target: action,
            method: form.method,
            riskSignals
          });
        }
        if (form.hasPassword) {
          store.upsertFinding(deps.enrichFindingForStorage({
            id: newId("find"),
            sessionId,
            workflowId: latestWorkflow?.id,
            title: form.hasCsrfToken ? "Login form inventory candidate" : "Login form without obvious CSRF token candidate",
            severity: form.hasCsrfToken ? "info" : "low",
            confidence: "low",
            target: current,
            description: "Playwright read-only exploration identified a password form. Missing CSRF-like fields are only a candidate until framework protections and request behavior are reviewed.",
            evidenceSummary: `form action=${action} method=${form.method} inputs=${form.inputNames.join(",")}`,
            remediation: "Validate CSRF/session protections in an authorized test account and enforce server-side anti-CSRF where required.",
            createdAt: nowIso(),
            updatedAt: nowIso()
          }));
        }
      }
      for (const script of [...snapshot.scripts, ...snapshot.resources]) {
        const normalized = normalizeBrowserUrl(script, current);
        if (!normalized.startsWith(origin)) {
          continue;
        }
        if (normalized.match(/\.js(?:[?#]|$)/i)) {
          scripts.add(normalized);
        }
        if (isApiLikeBrowserUrl(normalized)) {
          apiEndpoints.add(normalized);
          sensitiveActions.push({
            pageUrl: current,
            kind: "api",
            label: "browser resource",
            target: normalized,
            riskSignals: browserRiskSignals([normalized])
          });
        }
      }
      for (const link of snapshot.links) {
        const normalized = normalizeBrowserUrl(link.href, current);
        links.add(normalized);
        const riskSignals = browserRiskSignals([normalized, link.label]);
        if (isApiLikeBrowserUrl(normalized)) {
          apiEndpoints.add(normalized);
        }
        if (riskSignals.length > 0) {
          sensitiveActions.push({
            pageUrl: current,
            kind: "link",
            label: link.label || normalized,
            target: normalized,
            riskSignals
          });
        }
        if (normalized.startsWith(origin) && !visited.has(normalized) && queue.length < maxPages * 3) {
          queue.push(normalized.split("#")[0] ?? normalized);
        }
      }
      for (const button of snapshot.buttons) {
        const riskSignals = browserRiskSignals([button.label, button.type]);
        if (riskSignals.length > 0) {
          sensitiveActions.push({
            pageUrl: current,
            kind: "button",
            label: button.label,
            target: current,
            riskSignals
          });
        }
      }
      for (const [storageName, keys] of [
        ["localStorage", snapshot.storage.localStorage],
        ["sessionStorage", snapshot.storage.sessionStorage],
        ["cookie", snapshot.storage.cookieKeys]
      ] as const) {
        for (const key of keys) {
          const riskSignals = browserRiskSignals([key]);
          if (riskSignals.length > 0) {
            storageSignals.push({ pageUrl: current, storage: storageName, key, riskSignals });
          }
        }
      }
    }
    const result: BrowserExplorationResult = {
      sessionId,
      workflowId: latestWorkflow?.id,
      startUrl,
      pagesVisited: [...visited],
      forms,
      links: [...links],
      scripts: [...scripts],
      apiEndpoints: [...apiEndpoints],
      sensitiveActions: uniqueBrowserActions(sensitiveActions),
      storageSignals: uniqueStorageSignals(storageSignals),
      pageSummaries,
      storageStatePath: authContext?.storageStatePath,
      artifactPath,
      evidenceId: newId("evd")
    };
    writeFileSync(artifactPath, JSON.stringify(result, null, 2), "utf8");
    deps.finishSecurityToolRun(run, forms.length > 0 ? "success" : "no_findings", {
      outputArtifact: artifactPath,
      outputSummary: `Playwright visited ${result.pagesVisited.length} pages and found ${forms.length} forms.`,
      findingCount: forms.filter((form) => form.hasPassword && !form.hasCsrfToken).length,
      failureCategory: forms.length > 0 ? "none" : "no_findings"
    });
    store.addEvidence({
      id: result.evidenceId,
      sessionId,
      workflowId: latestWorkflow?.id,
      source: "browser:forms",
      kind: "tool",
      summary: `Playwright read-only form exploration visited ${result.pagesVisited.length} pages and found ${forms.length} forms.`,
      data: JSON.stringify(result, null, 2),
      createdAt: nowIso()
    });
    for (const pageUrl of result.pagesVisited) {
      store.addAsset({
        id: newId("asset"),
        sessionId,
        workflowId: latestWorkflow?.id,
        kind: "url",
        value: pageUrl,
        source: "browser:forms",
        confidence: "medium",
        metadata: JSON.stringify({ startUrl }),
        createdAt: nowIso()
      });
    }
    for (const apiUrl of result.apiEndpoints ?? []) {
      store.addAsset({
        id: newId("asset"),
        sessionId,
        workflowId: latestWorkflow?.id,
        kind: "url",
        value: apiUrl,
        source: "browser:api-endpoint",
        confidence: "high",
        metadata: JSON.stringify({ startUrl, discoveredBy: "Playwright resource/link inventory" }),
        createdAt: nowIso()
      });
    }
    for (const scriptUrl of result.scripts ?? []) {
      store.addAsset({
        id: newId("asset"),
        sessionId,
        workflowId: latestWorkflow?.id,
        kind: "url",
        value: scriptUrl,
        source: "browser:script",
        confidence: "medium",
        metadata: JSON.stringify({ startUrl, assetType: "javascript" }),
        createdAt: nowIso()
      });
    }
    if ((result.sensitiveActions?.length ?? 0) > 0 || (result.storageSignals?.length ?? 0) > 0) {
      store.upsertFinding(deps.enrichFindingForStorage({
        id: newId("find"),
        sessionId,
        workflowId: latestWorkflow?.id,
        title: "Browser-discovered sensitive workflow/API candidates",
        severity: "info",
        confidence: "medium",
        target: startUrl,
        description: "Read-only browser exploration found sensitive-looking links, forms, buttons, API endpoints, or storage keys. Treat these as workflow mapping evidence for authorization and business-logic review, not confirmed vulnerabilities.",
        evidenceSummary: JSON.stringify({
          sensitiveActions: result.sensitiveActions?.slice(0, 15),
          storageSignals: result.storageSignals?.slice(0, 15),
          apiEndpoints: result.apiEndpoints?.slice(0, 20)
        }).slice(0, 10_000),
        remediation: "Use authorized test accounts to validate expected role and state-transition controls before reporting impact.",
        createdAt: nowIso(),
        updatedAt: nowIso()
      }, [result.evidenceId]));
    }
    return result;
  } catch (error) {
    deps.finishSecurityToolRun(run, "failed", {
      outputSummary: error instanceof Error ? error.message : String(error),
      failureCategory: "tool_error"
    });
    throw error;
  } finally {
    await browser.close();
  }
}
