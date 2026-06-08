import { type JsAnalysisSummary, type JsEndpointCandidate, type JsLibrarySignal, type JsSensitiveSignal, type JsSourceMapSignal } from "@aegisprobe/shared";
import { uniqueBy, uniqueStrings } from "./utils.js";

export type JavaScriptAssetAnalysis = {
  scriptUrl: string;
  endpoints: JsEndpointCandidate[];
  sensitiveSignals: JsSensitiveSignal[];
  sourceMaps: JsSourceMapSignal[];
  libraries: JsLibrarySignal[];
  baseUrls: string[];
};

export type JavaScriptBundleAnalysis = {
  assets: JavaScriptAssetAnalysis[];
  endpoints: JsEndpointCandidate[];
  sensitiveSignals: JsSensitiveSignal[];
  sourceMaps: JsSourceMapSignal[];
  libraries: JsLibrarySignal[];
  summary: JsAnalysisSummary;
};

type SourceMapFetchResult = {
  mapUrl: string;
  content?: string;
  error?: string;
};

type SourceMapAnalysis = {
  signals: JsSourceMapSignal[];
  endpoints: JsEndpointCandidate[];
  sensitiveSignals: JsSensitiveSignal[];
};

export function analyzeJavaScriptAsset(input: {
  scriptUrl: string;
  content: string;
  origin: string;
  sourceMap?: SourceMapFetchResult;
}): JavaScriptAssetAnalysis {
  const content = input.content.slice(0, 2_000_000);
  const baseUrls = extractBaseUrls(input.scriptUrl, content, input.origin);
  const sourceMapAnalysis = analyzeSourceMap(input.scriptUrl, content, input.origin, baseUrls, input.sourceMap);
  const endpoints = uniqueBy(
    [
      ...extractEndpointCandidates(input.scriptUrl, content, input.origin, baseUrls),
      ...sourceMapAnalysis.endpoints
    ],
    (endpoint) => `${endpoint.scriptUrl}:${endpoint.method ?? ""}:${endpoint.normalizedUrl ?? endpoint.value}`
  );
  const frontendDiscoverySignals = extractFrontendDiscoverySignals(input.scriptUrl, content, input.origin, baseUrls, endpoints, sourceMapAnalysis.signals);
  const sensitiveSignals = uniqueBy(
    [
      ...extractSensitiveSignals(input.scriptUrl, content),
      ...sourceMapAnalysis.sensitiveSignals,
      ...frontendDiscoverySignals
    ],
    (signal) => `${signal.scriptUrl}:${signal.kind}:${signal.evidence}`
  ).slice(0, 400);
  const sourceMaps = sourceMapAnalysis.signals;
  const libraries = extractLibrarySignals(input.scriptUrl, content);

  return {
    scriptUrl: input.scriptUrl,
    endpoints,
    sensitiveSignals,
    sourceMaps,
    libraries,
    baseUrls
  };
}

export function buildJavaScriptBundleAnalysis(assets: JavaScriptAssetAnalysis[]): JavaScriptBundleAnalysis {
  const endpoints = uniqueBy(assets.flatMap((asset) => asset.endpoints), (endpoint) => `${endpoint.scriptUrl}:${endpoint.method ?? ""}:${endpoint.normalizedUrl ?? endpoint.value}`);
  const sensitiveSignals = uniqueBy(assets.flatMap((asset) => asset.sensitiveSignals), (signal) => `${signal.scriptUrl}:${signal.kind}:${signal.evidence}`);
  const sourceMaps = uniqueBy(assets.flatMap((asset) => asset.sourceMaps), (sourceMap) => `${sourceMap.scriptUrl}:${sourceMap.mapUrl}`);
  const libraries = uniqueBy(assets.flatMap((asset) => asset.libraries), (library) => `${library.scriptUrl}:${library.name}:${library.version ?? ""}:${library.evidence}`);
  return {
    assets,
    endpoints,
    sensitiveSignals,
    sourceMaps,
    libraries,
    summary: {
      scriptCount: assets.length,
      endpointCount: endpoints.length,
      sensitiveSignalCount: sensitiveSignals.length,
      sourceMapCount: sourceMaps.length,
      libraryCount: libraries.length,
      highValueRouteCount: endpoints.filter((endpoint) => endpoint.riskSignals.some((signal) => /admin|debug|auth|business|graphql/i.test(signal))).length,
      websocketCount: endpoints.filter((endpoint) => /^wss?:\/\//i.test(endpoint.normalizedUrl ?? endpoint.value)).length,
      graphqlCount: endpoints.filter((endpoint) => endpoint.riskSignals.includes("graphql-endpoint")).length
    }
  };
}

export function sourceMapUrlForScript(scriptUrl: string, content: string, origin: string): string | undefined {
  const match = content.match(/sourceMappingURL=([^\s"'<>]+)/i)?.[1];
  if (!match || /^data:/i.test(match)) {
    return undefined;
  }
  const normalized = normalizeCandidateUrl(match, scriptUrl, origin);
  return normalized;
}

function extractEndpointCandidates(scriptUrl: string, content: string, origin: string, baseUrls: string[]): JsEndpointCandidate[] {
  const endpoints: JsEndpointCandidate[] = [];
  const seen = new Set<string>();
  const add = (raw: string, method?: string, extraSignals: string[] = []): void => {
    const candidates = candidateUrlsForRaw(raw, scriptUrl, origin, baseUrls);
    for (const normalizedUrl of candidates) {
      const riskSignals = uniqueStrings([...routeRiskSignals(normalizedUrl), ...extraSignals]).sort();
      if (!isEndpointLike(normalizedUrl, riskSignals)) {
        continue;
      }
      const key = `${method ?? ""}:${normalizedUrl}`;
      if (seen.has(key)) {
        continue;
      }
      seen.add(key);
      endpoints.push({
        scriptUrl,
        value: redactSensitiveUrl(normalizedUrl),
        normalizedUrl: redactSensitiveUrl(normalizedUrl),
        method,
        confidence: endpointConfidence(normalizedUrl, method, riskSignals),
        riskSignals
      });
    }
  };

  for (const match of content.matchAll(/["'`]((?:https?:\/\/|wss?:\/\/|\/)[^"'`<>{}\s]{2,})["'`]/g)) {
    add(match[1]);
  }
  for (const match of content.matchAll(/\b(fetch|axios\.(?:get|post|put|patch|delete)|\$\.(?:get|post|ajax))\s*\(\s*["'`]([^"'`]+)["'`]/gi)) {
    const call = match[1].toLowerCase();
    const method = call.includes("post") ? "POST"
      : call.includes("put") ? "PUT"
      : call.includes("patch") ? "PATCH"
      : call.includes("delete") ? "DELETE"
      : call.includes("get") ? "GET"
      : undefined;
    add(match[2], method, ["runtime-request-call"]);
  }
  for (const match of content.matchAll(/\b(?:url|uri|endpoint|path|route|baseURL|baseUrl|apiUrl|graphql|wsUrl|socketUrl)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi)) {
    const label = match[0].split(/[=:]/)[0] ?? "";
    add(match[1], undefined, label.toLowerCase().includes("graphql") ? ["graphql-endpoint"] : []);
  }
  return endpoints;
}

function extractBaseUrls(scriptUrl: string, content: string, origin: string): string[] {
  const urls: string[] = [];
  for (const match of content.matchAll(/\b(?:baseURL|baseUrl|apiBase|apiRoot|serverUrl|backendUrl)\s*[:=]\s*["'`]([^"'`]+)["'`]/gi)) {
    const normalized = normalizeCandidateUrl(match[1], scriptUrl, origin);
    if (normalized) {
      urls.push(normalized.replace(/[?#].*$/u, "").replace(/\/?$/u, "/"));
    }
  }
  return uniqueStrings(urls).slice(0, 20);
}

function extractSensitiveSignals(scriptUrl: string, content: string): JsSensitiveSignal[] {
  const signals: JsSensitiveSignal[] = [];
  const push = (kind: JsSensitiveSignal["kind"], evidence: string, riskSignals: string[]): void => {
    signals.push({ scriptUrl, kind, evidence, riskSignals: uniqueStrings(riskSignals).sort() });
  };

  for (const match of content.matchAll(/\b(?:api[_-]?key|access[_-]?token|refresh[_-]?token|secret|authorization|bearer|client[_-]?secret|jwt|password)\b\s*[:=]\s*["'`]([^"'`]{8,})["'`]/gi)) {
    const key = match[0].split(/[=:]/)[0]?.trim() ?? "secret-like";
    push("secret-like-string", `${key}=<redacted:${match[1].length}>`, ["sensitive-token"]);
    if (signals.length > 100) break;
  }
  for (const match of content.matchAll(/\beyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{8,}\b/g)) {
    push("jwt-like", `jwt=<redacted:${match[0].length}>`, ["jwt-like", "sensitive-token"]);
  }
  for (const match of content.matchAll(/\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g)) {
    push("access-key-like", `${match[0].slice(0, 4)}<redacted:${match[0].length - 4}>`, ["cloud-access-key-like"]);
  }
  for (const match of content.matchAll(/-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{20,8000}?-----END [A-Z0-9 ]*PRIVATE KEY-----/g)) {
    push("private-key-like", `private-key=<redacted:${match[0].length}>`, ["private-key-like", "sensitive-token"]);
  }
  for (const match of content.matchAll(/\b(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|internal|staging|dev)\b/gi)) {
    push("internal-host", match[0], ["internal-host"]);
  }
  for (const match of content.matchAll(/\b[a-z0-9.-]+\.(?:s3\.amazonaws\.com|oss-[a-z0-9-]+\.aliyuncs\.com|cos\.[a-z0-9-]+\.myqcloud\.com|blob\.core\.windows\.net)\b/gi)) {
    push("cloud-storage", match[0], ["cloud-storage"]);
  }
  for (const match of content.matchAll(/\b[a-z0-9.-]+\.(?:cloudfront\.net|cloudflare\.com|akamaihd\.net|fastly\.net|cdn\.[a-z0-9.-]+)\b/gi)) {
    push("cdn-host", match[0], ["cdn-host"]);
  }
  if (/\b(?:debug|devtools|mock|testMode|bypassAuth)\b\s*[:=]\s*(?:true|1|["'`]true["'`])/i.test(content)) {
    push("debug-flag", "debug/dev/test flag pattern detected", ["debug-flag"]);
  }
  return uniqueBy(signals, (signal) => `${signal.kind}:${signal.evidence}:${signal.scriptUrl}`).slice(0, 200);
}

function analyzeSourceMap(scriptUrl: string, content: string, origin: string, baseUrls: string[], fetched?: SourceMapFetchResult): SourceMapAnalysis {
  const mapUrl = fetched?.mapUrl ?? sourceMapUrlForScript(scriptUrl, content, origin);
  if (!mapUrl) {
    return { signals: [], endpoints: [], sensitiveSignals: [] };
  }
  if (!fetched?.content) {
    return {
      signals: [{
        scriptUrl,
        mapUrl,
        available: false,
        sourcesSample: [],
        riskSignals: ["source-map"],
        error: fetched?.error
      }],
      endpoints: [],
      sensitiveSignals: []
    };
  }
  try {
    const parsed = JSON.parse(fetched.content) as { sources?: unknown; sourcesContent?: unknown };
    const sources = Array.isArray(parsed.sources) ? parsed.sources.filter((item): item is string => typeof item === "string") : [];
    const sourceContents = Array.isArray(parsed.sourcesContent)
      ? parsed.sourcesContent
          .map((item, index) => ({ content: typeof item === "string" ? item : undefined, source: sources[index] ?? `source-${index}` }))
          .filter((item): item is { content: string; source: string } => Boolean(item.content))
          .slice(0, 50)
      : [];
    const recoveredEndpoints: JsEndpointCandidate[] = [];
    const recoveredSensitiveSignals: JsSensitiveSignal[] = [];
    const sourceSignals: JsSensitiveSignal[] = [];

    for (const source of sources.slice(0, 50)) {
      sourceSignals.push({
        scriptUrl,
        kind: "source-map-source",
        evidence: truncateJsEvidence(source, 140),
        riskSignals: uniqueStrings(["source-map-source", ...routeRiskSignals(source)]).sort()
      });
    }

    for (const source of sourceContents) {
      const virtualScriptUrl = sourceMapVirtualScriptUrl(scriptUrl, source.source);
      const recoveredContent = source.content.slice(0, 250_000);
      const recoveredBaseUrls = uniqueStrings([...baseUrls, ...extractBaseUrls(virtualScriptUrl, recoveredContent, origin)]);
      recoveredEndpoints.push(
        ...extractEndpointCandidates(virtualScriptUrl, recoveredContent, origin, recoveredBaseUrls)
          .map((endpoint) => ({
            ...endpoint,
            riskSignals: uniqueStrings([...endpoint.riskSignals, "source-map-recovered-source"]).sort()
          }))
      );
      recoveredSensitiveSignals.push(
        ...extractSensitiveSignals(virtualScriptUrl, recoveredContent)
          .map((signal) => ({
            ...signal,
            riskSignals: uniqueStrings([...signal.riskSignals, "source-map-recovered-source"]).sort()
          }))
      );
    }

    const signal: JsSourceMapSignal = {
      scriptUrl,
      mapUrl,
      available: true,
      sourceCount: sources.length,
      sourceContentCount: sourceContents.length,
      recoveredEndpointCount: uniqueBy(recoveredEndpoints, (endpoint) => `${endpoint.method ?? ""}:${endpoint.normalizedUrl ?? endpoint.value}`).length,
      recoveredSensitiveSignalCount: uniqueBy(recoveredSensitiveSignals, (item) => `${item.kind}:${item.evidence}:${item.scriptUrl}`).length,
      sourcesSample: sources.slice(0, 50),
      sourcesWithContentSample: sourceContents.map((item) => item.source).slice(0, 25),
      riskSignals: uniqueStrings([
        "source-map",
        ...(sourceContents.length > 0 ? ["source-map-source-content"] : []),
        ...sources.flatMap((source) => routeRiskSignals(source)),
        ...recoveredEndpoints.flatMap((endpoint) => endpoint.riskSignals)
      ]).slice(0, 30)
    };
    return {
      signals: [signal],
      endpoints: uniqueBy(recoveredEndpoints, (endpoint) => `${endpoint.scriptUrl}:${endpoint.method ?? ""}:${endpoint.normalizedUrl ?? endpoint.value}`).slice(0, 200),
      sensitiveSignals: uniqueBy(
        [...sourceSignals, ...recoveredSensitiveSignals],
        (signal) => `${signal.scriptUrl}:${signal.kind}:${signal.evidence}`
      ).slice(0, 200)
    };
  } catch {
    return {
      signals: [{
        scriptUrl,
        mapUrl,
        available: true,
        sourcesSample: [],
        riskSignals: ["source-map"],
        error: "source map was fetched but could not be parsed as JSON"
      }],
      endpoints: [],
      sensitiveSignals: []
    };
  }
}

function sourceMapVirtualScriptUrl(scriptUrl: string, source: string): string {
  const normalizedSource = source.trim().replace(/\\/g, "/");
  if (!normalizedSource) {
    return scriptUrl;
  }
  if (/^https?:\/\//i.test(normalizedSource)) {
    return normalizedSource;
  }

  try {
    const base = new URL(scriptUrl);
    if (normalizedSource.startsWith("/")) {
      return new URL(normalizedSource, base.origin).href;
    }

    const sourcePath = normalizedSource
      .replace(/^[a-z][a-z0-9+.-]*:\/\/\/?/i, "")
      .replace(/^(?:\.\/)+/u, "")
      .replace(/^\/+/u, "");
    return new URL(sourcePath || `source-${encodeURIComponent(normalizedSource)}`, scriptUrl).href;
  } catch {
    return scriptUrl;
  }
}

function truncateJsEvidence(value: string, maxLength: number): string {
  const redacted = redactSensitiveUrl(value)
    .replace(/([?&](?:pass(?:word)?|secret|token|jwt|bearer|authorization|auth|api[_-]?key|access[_-]?key|client[_-]?secret|session|cookie|csrf|xsrf|nonce|otp|mfa|2fa|code|ak|sk)=)[^&#\s]+/gi, "$1<redacted>")
    .replace(/\s+/g, " ")
    .trim();
  if (redacted.length <= maxLength) {
    return redacted;
  }
  return `${redacted.slice(0, Math.max(0, maxLength - 3))}...`;
}

function extractFrontendDiscoverySignals(
  scriptUrl: string,
  content: string,
  origin: string,
  baseUrls: string[],
  endpoints: JsEndpointCandidate[],
  sourceMaps: JsSourceMapSignal[]
): JsSensitiveSignal[] {
  const signals: JsSensitiveSignal[] = [];
  const push = (kind: JsSensitiveSignal["kind"], evidence: string, riskSignals: string[]): void => {
    signals.push({
      scriptUrl,
      kind,
      evidence: redactSensitiveUrl(evidence),
      riskSignals: uniqueStrings(riskSignals).sort()
    });
  };

  const chunkCandidates = new Set<string>();
  for (const match of content.matchAll(/\bimport\s*\(\s*["'`]([^"'`]{1,180}\.(?:m?js)(?:\?[^"'`]*)?)["'`]\s*\)/gi)) {
    const normalized = normalizeCandidateUrl(match[1], scriptUrl, origin);
    if (normalized && isJavaScriptAssetPath(normalized)) chunkCandidates.add(normalized);
  }
  for (const match of content.matchAll(/["'`]([^"'`]{1,180}(?:chunk|lazy|route|page|admin|vendor)[^"'`]{0,120}\.(?:m?js)(?:\?[^"'`]*)?)["'`]/gi)) {
    const normalized = normalizeCandidateUrl(match[1], scriptUrl, origin);
    if (normalized && isJavaScriptAssetPath(normalized)) chunkCandidates.add(normalized);
  }
  for (const match of content.matchAll(/__webpack_require__\.u\s*=\s*(?:function\s*)?\(?\s*([a-zA-Z_$][\w$]*)?\s*\)?\s*=>?\s*["'`]([^"'`]{0,120})["'`]\s*\+\s*[^;]{0,180}\+\s*["'`]([^"'`]{0,80}\.js(?:\?[^"'`]*)?)["'`]/g)) {
    const prefix = match[2] ?? "";
    const suffix = match[3] ?? "";
    const normalized = normalizeCandidateUrl(`${prefix}{chunk-id}${suffix}`, scriptUrl, origin);
    if (normalized) chunkCandidates.add(normalized);
  }

  for (const chunk of [...chunkCandidates].slice(0, 40)) {
    push("lazy-chunk", chunk, ["webpack-lazy-chunk", "passive-discovery-lead"]);
  }

  for (const candidate of backupFileCandidates(scriptUrl, content, origin, baseUrls, endpoints, sourceMaps).slice(0, 60)) {
    push("backup-file-candidate", candidate, ["adjacent-file-variant", "passive-discovery-lead", "requires-scope-before-fetch"]);
  }

  return uniqueBy(signals, (signal) => `${signal.kind}:${signal.evidence}:${signal.scriptUrl}`).slice(0, 160);
}

function backupFileCandidates(
  scriptUrl: string,
  content: string,
  origin: string,
  baseUrls: string[],
  endpoints: JsEndpointCandidate[],
  sourceMaps: JsSourceMapSignal[]
): string[] {
  const seeds = new Set<string>();
  for (const value of [scriptUrl, ...baseUrls]) {
    const normalized = normalizeCandidateUrl(value, scriptUrl, origin);
    if (normalized) seeds.add(normalized);
  }
  for (const endpoint of endpoints) {
    const normalized = normalizeCandidateUrl(endpoint.normalizedUrl ?? endpoint.value, scriptUrl, origin);
    if (normalized) seeds.add(normalized);
  }
  for (const sourceMap of sourceMaps) {
    for (const source of [...sourceMap.sourcesSample, ...(sourceMap.sourcesWithContentSample ?? [])]) {
      const normalized = normalizeCandidateUrl(source, scriptUrl, origin);
      if (normalized) seeds.add(normalized);
    }
  }
  for (const match of content.matchAll(/["'`]((?:https?:\/\/|\/|\.\.?\/)[^"'`<>{}\s]{2,180}\.(?:json|ya?ml|xml|env|config|conf|ini|txt|log|sql|php|jsp|aspx?|rb|py|ts|tsx|jsx|m?js|map))(?:[?#][^"'`]*)?["'`]/gi)) {
    const normalized = normalizeCandidateUrl(match[1], scriptUrl, origin);
    if (normalized) seeds.add(normalized);
  }

  const suffixes = [".bak", ".backup", ".old", ".orig", ".save", ".swp", ".tmp", ".disabled", "~", ".~"];
  const candidates = new Set<string>();
  for (const seed of seeds) {
    let parsed: URL;
    try {
      parsed = new URL(seed);
    } catch {
      continue;
    }
    if (parsed.origin !== origin || !isBackupSeedPath(parsed.pathname)) {
      continue;
    }
    parsed.search = "";
    parsed.hash = "";
    const base = parsed.href;
    for (const suffix of suffixes) {
      candidates.add(`${base}${suffix}`);
    }
  }
  return [...candidates];
}

function isBackupSeedPath(pathname: string): boolean {
  if (/\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot)(?:$|[?#])/i.test(pathname)) return false;
  if (/\.(?:m?js|map|ts|tsx|jsx)(?:$|[?#])/i.test(pathname)) {
    return /\/(?:config|settings|admin|debug|internal|api|app|main|bundle|chunk|route)(?:[./_-]|$)/i.test(pathname)
      || /(?:config|settings|admin|debug|internal|api|app|main|bundle|chunk|route)[^/]*\.(?:m?js|map|ts|tsx|jsx)(?:$|[?#])/i.test(pathname);
  }
  if (/\.(?:json|ya?ml|xml|env|config|conf|ini|txt|log|sql|php|jsp|aspx?|rb|py|ts|tsx|jsx|m?js|map)(?:$|[?#])/i.test(pathname)) return true;
  return /\/(?:config|settings|admin|debug|internal|backup|uploads?|exports?|reports?)(?:\/|$)/i.test(pathname);
}

function looksLikeJavaScriptExpressionFragment(value: string): boolean {
  return /[(){};]/.test(value) || /(?:^|\/)[+*][A-Za-z_$]/.test(value) || /\.[A-Za-z_$][\w$]*\(/.test(value);
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function isJavaScriptAssetPath(value: string): boolean {
  try {
    return /\.(?:m?js)(?:$|[?#])/i.test(new URL(value).pathname);
  } catch {
    return /\.(?:m?js)(?:$|[?#])/i.test(value);
  }
}

function extractLibrarySignals(scriptUrl: string, content: string): JsLibrarySignal[] {
  const libraries: JsLibrarySignal[] = [];
  const rules: Array<{ name: string; pattern: RegExp; version?: (match: RegExpMatchArray) => string | undefined; risk?: (version?: string) => string[] }> = [
    { name: "jQuery", pattern: /jQuery(?: JavaScript Library)? v?(\d+\.\d+\.\d+)/i, version: (m) => m[1], risk: (v) => versionLessThan(v, "3.5.0") ? ["retire-style-outdated-library-candidate"] : [] },
    { name: "Lodash", pattern: /lodash(?:\.js)?[^\n]{0,80}?VERSION["']?\s*[:=]\s*["'](\d+\.\d+\.\d+)["']/i, version: (m) => m[1], risk: (v) => versionLessThan(v, "4.17.21") ? ["retire-style-outdated-library-candidate"] : [] },
    { name: "Axios", pattern: /axios\/(\d+\.\d+\.\d+)|axios\.VERSION\s*=\s*["'](\d+\.\d+\.\d+)["']/i, version: (m) => m[1] ?? m[2], risk: (v) => versionLessThan(v, "1.6.0") ? ["retire-style-review-library-version"] : [] },
    { name: "Moment.js", pattern: /moment(?:\.js)?[^\n]{0,80}?version\s*[:=]\s*["'](\d+\.\d+\.\d+)["']/i, version: (m) => m[1], risk: () => ["retire-style-review-library-version"] },
    { name: "Vue.js", pattern: /Vue\.version\s*=\s*["'](\d+\.\d+\.\d+)["']|vue(?:\.runtime)?(?:\.min)?\.js/i, version: (m) => m[1], risk: () => [] },
    { name: "React", pattern: /React\.version\s*=\s*["'](\d+\.\d+\.\d+)["']|react(?:\.production)?(?:\.min)?\.js/i, version: (m) => m[1], risk: () => [] },
    { name: "AngularJS", pattern: /angular\.version\.full\s*=\s*["'](\d+\.\d+\.\d+)["']|angular\.js/i, version: (m) => m[1], risk: (v) => !v || versionLessThan(v, "1.8.3") ? ["retire-style-outdated-library-candidate"] : [] }
  ];
  for (const rule of rules) {
    const match = content.match(rule.pattern);
    if (!match) {
      continue;
    }
    const version = rule.version?.(match);
    const riskSignals = rule.risk?.(version) ?? [];
    libraries.push({
      scriptUrl,
      name: rule.name,
      version,
      confidence: version ? "high" : "medium",
      evidence: version ? `${rule.name} ${version}` : `${rule.name} signature`,
      riskSignals
    });
  }
  return uniqueBy(libraries, (library) => `${library.name}:${library.version ?? ""}:${library.scriptUrl}`);
}

function candidateUrlsForRaw(raw: string, scriptUrl: string, origin: string, baseUrls: string[]): string[] {
  const values = [normalizeCandidateUrl(raw, scriptUrl, origin)];
  if (/^[a-z0-9._~/-]+(?:\?|$)/i.test(raw) && !raw.startsWith("/") && !/^[a-z][a-z0-9+.-]*:/i.test(raw)) {
    for (const baseUrl of baseUrls) {
      values.push(normalizeCandidateUrl(raw, baseUrl, origin));
    }
  }
  return uniqueStrings(values.filter((value): value is string => Boolean(value)));
}

function normalizeCandidateUrl(value: string, baseUrl: string, origin: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed || trimmed.startsWith("#") || trimmed.startsWith("data:") || trimmed.startsWith("mailto:") || trimmed.startsWith("tel:")) {
    return undefined;
  }
  if (looksLikeJavaScriptExpressionFragment(trimmed)) {
    return undefined;
  }
  try {
    const normalized = new URL(trimmed, baseUrl).href;
    const parsed = new URL(normalized);
    if (!/^https?:|^wss?:/i.test(parsed.protocol)) {
      return undefined;
    }
    if ((parsed.protocol === "http:" || parsed.protocol === "https:") && parsed.origin !== origin) {
      return undefined;
    }
    if (looksLikeJavaScriptExpressionFragment(decodeURIComponentSafe(parsed.pathname))) {
      return undefined;
    }
    if (/\.(?:png|jpe?g|gif|svg|ico|css|woff2?|ttf|eot)(?:[?#]|$)/i.test(parsed.pathname)) {
      return undefined;
    }
    return normalized;
  } catch {
    return undefined;
  }
}

function isEndpointLike(value: string, riskSignals: string[]): boolean {
  if (/^wss?:\/\//i.test(value)) return true;
  try {
    const pathname = new URL(value).pathname;
    if (looksLikeJavaScriptExpressionFragment(decodeURIComponentSafe(pathname))) {
      return false;
    }
    if (/\.(?:m?js|map)(?:$|[?#])/i.test(pathname) && !riskSignals.some((signal) => /api|graphql|admin|auth|business|debug/i.test(signal))) {
      return false;
    }
    if (riskSignals.length > 0) return true;
    return /\/[a-z0-9_-]+\/[a-z0-9_-]+/i.test(pathname);
  } catch {
    if (riskSignals.length > 0) return true;
    return false;
  }
}

function routeRiskSignals(value: string): string[] {
  const lower = value.toLowerCase();
  const signals: string[] = [];
  if (/^wss?:\/\//i.test(value)) signals.push("websocket-endpoint");
  if (/\/(?:api|rest|rpc|v\d+|openapi|swagger)(?:\/|\?|$)/i.test(lower)) signals.push("api-endpoint");
  if (/\/graphql(?:\/|\?|$)?/i.test(lower)) signals.push("graphql-endpoint");
  if (/\/(?:admin|manage|console|roles?|permissions?)(?:\/|\?|$)/i.test(lower)) signals.push("admin-route");
  if (/\/(?:debug|devtools|mock|actuator|internal)(?:\/|\?|$)/i.test(lower)) signals.push("debug-route");
  if (/\/(?:login|signin|logout|register|reset|password|oauth|sso|token|session|auth)(?:\/|\?|$)/i.test(lower)) signals.push("auth-surface");
  if (/\/(?:order|cart|payment|refund|coupon|invoice|checkout|tenant|org|workspace|invite|approval|upload|download|share|export)(?:\/|\?|$)/i.test(lower)) signals.push("business-workflow-route");
  if (/[?&](?:token|access_token|api_key|secret|session|csrf|xsrf)=/i.test(value)) signals.push("sensitive-parameter-name");
  return signals;
}

function endpointConfidence(value: string, method: string | undefined, riskSignals: string[]): "low" | "medium" | "high" {
  if (method || riskSignals.some((signal) => /api|graphql|websocket|admin|auth/.test(signal))) return "high";
  if (riskSignals.length > 0 || /^https?:\/\//i.test(value)) return "medium";
  return "low";
}

function redactSensitiveUrl(value: string): string {
  try {
    const url = new URL(value);
    for (const key of [...url.searchParams.keys()]) {
      if (/(?:pass(?:word)?|secret|token|jwt|bearer|authorization|auth|api[_-]?key|access[_-]?key|client[_-]?secret|session|cookie|csrf|xsrf|nonce|otp|mfa|2fa|code|ak|sk)/i.test(key)) {
        const current = url.searchParams.get(key) ?? "";
        url.searchParams.set(key, `<redacted:${current.length}>`);
      }
    }
    return url.href;
  } catch {
    return value;
  }
}

function versionLessThan(version: string | undefined, minimum: string): boolean {
  if (!version) return false;
  const left = version.split(".").map((part) => Number.parseInt(part, 10) || 0);
  const right = minimum.split(".").map((part) => Number.parseInt(part, 10) || 0);
  for (let index = 0; index < Math.max(left.length, right.length); index += 1) {
    const l = left[index] ?? 0;
    const r = right[index] ?? 0;
    if (l !== r) return l < r;
  }
  return false;
}
