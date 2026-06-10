import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { AppConfig } from "@aegisprobe/provider";

export type WebSearchResult = {
  title: string;
  url: string;
  snippet: string;
};

export async function searchPublicWeb(
  query: string,
  config: AppConfig["webResearch"],
  requestedResults: number,
  signal?: AbortSignal
): Promise<{
  query: string;
  provider: string;
  status: number;
  results: WebSearchResult[];
  rawResponse: string;
}> {
  if (!config.enabled) {
    throw new Error("Web research is disabled by configuration.");
  }
  const endpoint = new URL(config.searchEndpoint);
  endpoint.searchParams.set("q", query);
  if (config.searchProvider === "bing-rss") {
    endpoint.searchParams.set("format", "rss");
  }
  await assertPublicResearchUrl(endpoint);
  const response = await fetchWithPublicRedirects(endpoint, {
    signal,
    timeoutMs: config.timeoutMs,
    userAgent: config.userAgent,
    maxBytes: config.maxFetchBytes,
    maxRetries: config.maxRetries
  });
  const rawResponse = response.body.toString("utf8");
  const limit = Math.max(1, Math.min(requestedResults, config.maxResults));
  return {
    query,
    provider: config.searchProvider,
    status: response.status,
    results: (
      config.searchProvider === "bing-rss"
        ? parseBingRssResults(rawResponse)
        : parseDuckDuckGoResults(rawResponse)
    ).slice(0, limit),
    rawResponse
  };
}

export async function fetchPublicWeb(
  url: string,
  config: AppConfig["webResearch"],
  signal?: AbortSignal
): Promise<{
  requestedUrl: string;
  finalUrl: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  contentType: string;
  bytes: number;
  truncated: boolean;
  extractedText: string;
  body: string;
}> {
  if (!config.enabled) {
    throw new Error("Web research is disabled by configuration.");
  }
  const response = await fetchWithPublicRedirects(new URL(url), {
    signal,
    timeoutMs: config.timeoutMs,
    userAgent: config.userAgent,
    maxBytes: config.maxFetchBytes,
    maxRetries: config.maxRetries
  });
  const contentType = response.headers["content-type"] ?? "";
  const body = response.body.toString("utf8");
  return {
    requestedUrl: url,
    finalUrl: response.url,
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
    contentType,
    bytes: response.body.length,
    truncated: response.truncated,
    extractedText: /html|xml/i.test(contentType) ? htmlToText(body) : body,
    body
  };
}

async function fetchWithPublicRedirects(
  initialUrl: URL,
  options: {
    signal?: AbortSignal;
    timeoutMs: number;
    userAgent: string;
    maxBytes: number;
    maxRetries: number;
  }
): Promise<{
  url: string;
  status: number;
  statusText: string;
  headers: Record<string, string>;
  body: Buffer;
  truncated: boolean;
}> {
  let current = initialUrl;
  for (let redirect = 0; redirect <= 5; redirect += 1) {
    await assertPublicResearchUrl(current);
    const controller = new AbortController();
    const abort = () => controller.abort();
    options.signal?.addEventListener("abort", abort, { once: true });
    const timer = setTimeout(() => controller.abort(), options.timeoutMs);
    try {
      const response = await fetchWithRetries(current, controller.signal, options);
      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location) throw new Error(`Redirect ${response.status} omitted Location.`);
        current = new URL(location, current);
        continue;
      }
      const { bytes, truncated } = await readResponseLimit(response, options.maxBytes);
      return {
        url: response.url || current.toString(),
        status: response.status,
        statusText: response.statusText,
        headers: Object.fromEntries(response.headers.entries()),
        body: bytes,
        truncated
      };
    } finally {
      clearTimeout(timer);
      options.signal?.removeEventListener("abort", abort);
    }
  }
  throw new Error("Too many web research redirects.");
}

async function fetchWithRetries(
  url: URL,
  signal: AbortSignal,
  options: { userAgent: string; maxRetries: number }
): Promise<Response> {
  let lastError: unknown;
  for (let attempt = 0; attempt <= options.maxRetries; attempt += 1) {
    if (attempt > 0) {
      await delay(300 * (2 ** (attempt - 1)), signal);
    }
    try {
      const response = await fetch(url, {
        method: "GET",
        redirect: "manual",
        signal,
        headers: {
          accept: "text/html,application/xhtml+xml,application/json,text/plain;q=0.9,*/*;q=0.5",
          "user-agent": options.userAgent
        }
      });
      if ((response.status === 429 || response.status >= 500) && attempt < options.maxRetries) {
        await response.body?.cancel();
        continue;
      }
      return response;
    } catch (error) {
      lastError = error;
      if (signal.aborted || attempt >= options.maxRetries) throw error;
    }
  }
  throw lastError;
}

async function delay(ms: number, signal: AbortSignal): Promise<void> {
  await new Promise<void>((resolveDelay, rejectDelay) => {
    const onAbort = () => {
      clearTimeout(timer);
      rejectDelay(new Error("Web research request aborted."));
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolveDelay();
    }, ms);
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

async function readResponseLimit(
  response: Response,
  maxBytes: number
): Promise<{ bytes: Buffer; truncated: boolean }> {
  const reader = response.body?.getReader();
  if (!reader) return { bytes: Buffer.alloc(0), truncated: false };
  const chunks: Buffer[] = [];
  let total = 0;
  let truncated = false;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const chunk = Buffer.from(value);
    const remaining = maxBytes - total;
    if (remaining <= 0) {
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(chunk.subarray(0, remaining));
    total += Math.min(chunk.length, remaining);
    if (chunk.length > remaining || total >= maxBytes) {
      truncated = true;
      await reader.cancel();
      break;
    }
  }
  return { bytes: Buffer.concat(chunks), truncated };
}

export async function assertPublicResearchUrl(url: URL): Promise<void> {
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error(`Unsupported web research protocol: ${url.protocol}`);
  }
  if (url.username || url.password) {
    throw new Error("Credential-bearing web research URLs are not allowed.");
  }
  const hostname = url.hostname.replace(/^\[|\]$/g, "").toLowerCase();
  if (hostname === "localhost" || hostname.endsWith(".localhost") || hostname === "metadata.google.internal") {
    throw new Error(`Web research cannot access local or metadata host: ${hostname}`);
  }
  const addresses = isIP(hostname)
    ? [{ address: hostname, family: isIP(hostname) }]
    : await lookup(hostname, { all: true, verbatim: true });
  if (addresses.length === 0) {
    throw new Error(`Web research host did not resolve: ${hostname}`);
  }
  const localUsesSyntheticProxyAddresses = !isIP(hostname)
    && addresses.every((entry) => isSyntheticProxyIpv4(entry.address));
  const validatedAddresses = localUsesSyntheticProxyAddresses
    ? await resolvePublicDns(hostname)
    : addresses.map((entry) => entry.address);
  for (const address of validatedAddresses) {
    if (!isPublicIp(address)) {
      throw new Error(`Web research resolved to a non-public address: ${address}`);
    }
  }
}

async function resolvePublicDns(hostname: string): Promise<string[]> {
  const endpoints = [
    `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(hostname)}&type=A`,
    `https://dns.google/resolve?name=${encodeURIComponent(hostname)}&type=A`
  ];
  let lastError: unknown;
  for (const endpoint of endpoints) {
    try {
      const response = await fetch(endpoint, {
        signal: AbortSignal.timeout(8_000),
        headers: { accept: "application/dns-json" }
      });
      if (!response.ok) throw new Error(`DoH returned ${response.status}`);
      const data = await response.json() as {
        Answer?: Array<{ type?: number; data?: string }>;
      };
      const addresses = (data.Answer ?? [])
        .filter((answer) => answer.type === 1 && typeof answer.data === "string")
        .map((answer) => answer.data!);
      if (addresses.length > 0) return addresses;
    } catch (error) {
      lastError = error;
    }
  }
  throw new Error(`Could not validate proxy-resolved public host ${hostname}: ${errorText(lastError)}`);
}

function isPublicIp(address: string): boolean {
  const normalized = address.toLowerCase();
  if (normalized.includes(":")) {
    if (normalized === "::" || normalized === "::1") return false;
    if (/^(?:fc|fd|fe8|fe9|fea|feb)/i.test(normalized.replace(/^0+/, ""))) return false;
    const mapped = /::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(normalized)?.[1];
    return mapped ? isPublicIpv4(mapped) : true;
  }
  return isPublicIpv4(normalized);
}

function isPublicIpv4(address: string): boolean {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => !Number.isInteger(part) || part < 0 || part > 255)) {
    return false;
  }
  const [a, b] = parts as [number, number, number, number];
  if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
  if (a === 100 && b >= 64 && b <= 127) return false;
  if (a === 169 && b === 254) return false;
  if (a === 172 && b >= 16 && b <= 31) return false;
  if (a === 192 && b === 168) return false;
  if (a === 198 && (b === 18 || b === 19)) return false;
  return !(a === 192 && b === 0);
}

function isSyntheticProxyIpv4(address: string): boolean {
  const [a, b] = address.split(".").map(Number);
  return a === 198 && (b === 18 || b === 19);
}

function parseDuckDuckGoResults(html: string): WebSearchResult[] {
  const results: WebSearchResult[] = [];
  const links = [...html.matchAll(/<a\b([^>]*)>([\s\S]*?)<\/a>/gi)]
    .filter((match) => /\b(?:result__a|result-link)\b/i.test(attributeValue(match[1] ?? "", "class")));
  for (let index = 0; index < links.length; index += 1) {
    const link = links[index]!;
    const href = attributeValue(link[1] ?? "", "href");
    const blockEnd = links[index + 1]?.index ?? html.length;
    const block = html.slice((link.index ?? 0) + link[0].length, blockEnd);
    const snippet = /class=["'][^"']*\b(?:result__snippet|result-snippet)\b[^"']*["'][^>]*>([\s\S]*?)<\/(?:a|div|td)>/i.exec(block)?.[1] ?? "";
    const url = unwrapDuckDuckGoUrl(decodeHtml(href));
    if (!/^https?:\/\//i.test(url)) continue;
    results.push({
      title: htmlToText(link[2] ?? ""),
      url,
      snippet: htmlToText(snippet)
    });
  }
  return dedupeResults(results);
}

function attributeValue(attributes: string, name: string): string {
  const match = new RegExp(`\\b${name}\\s*=\\s*["']([^"']*)["']`, "i").exec(attributes);
  return match?.[1] ?? "";
}

function parseBingRssResults(xml: string): WebSearchResult[] {
  const results: WebSearchResult[] = [];
  for (const match of xml.matchAll(/<item>([\s\S]*?)<\/item>/gi)) {
    const item = match[1] ?? "";
    const title = xmlElement(item, "title");
    const url = xmlElement(item, "link");
    const snippet = xmlElement(item, "description");
    if (!/^https?:\/\//i.test(url)) continue;
    results.push({
      title: htmlToText(title),
      url,
      snippet: htmlToText(snippet)
    });
  }
  return dedupeResults(results);
}

function xmlElement(xml: string, name: string): string {
  const match = new RegExp(`<${name}>([\\s\\S]*?)</${name}>`, "i").exec(xml);
  return (match?.[1] ?? "").replace(/^<!\[CDATA\[|\]\]>$/g, "");
}

function unwrapDuckDuckGoUrl(value: string): string {
  try {
    const url = new URL(value, "https://duckduckgo.com");
    return url.searchParams.get("uddg") ?? url.toString();
  } catch {
    return value;
  }
}

function htmlToText(value: string): string {
  return decodeHtml(
    value
      .replace(/<script\b[\s\S]*?<\/script>/gi, " ")
      .replace(/<style\b[\s\S]*?<\/style>/gi, " ")
      .replace(/<[^>]+>/g, " ")
  ).replace(/\s+/g, " ").trim();
}

function decodeHtml(value: string): string {
  return value
    .replace(/&amp;/gi, "&")
    .replace(/&quot;/gi, "\"")
    .replace(/&#39;|&apos;/gi, "'")
    .replace(/&lt;/gi, "<")
    .replace(/&gt;/gi, ">")
    .replace(/&#x2F;/gi, "/")
    .replace(/&#x([0-9a-f]+);/gi, (_, code: string) => String.fromCodePoint(Number.parseInt(code, 16)))
    .replace(/&#(\d+);/g, (_, code: string) => String.fromCodePoint(Number(code)));
}

function dedupeResults(results: WebSearchResult[]): WebSearchResult[] {
  const seen = new Set<string>();
  return results.filter((result) => {
    if (seen.has(result.url)) return false;
    seen.add(result.url);
    return true;
  });
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
