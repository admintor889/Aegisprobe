import { existsSync, readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { resolve4, resolve6, resolveCname } from "node:dns/promises";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { connect as netConnect } from "node:net";
import { newId, nowIso, parseTargetInput, type SecurityAuthContext, type TargetInput, type TurnEventKind } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";

export type ToolEventEmitter = (kind: TurnEventKind, message: string, payload?: unknown) => void;

export type SecurityProbe = "basic_recon" | "dns" | "http_headers";

export type ProbeApprovalDecision = boolean | {
  approved: boolean;
  remember?: boolean;
};

export type NormalizedProbeApproval = {
  approved: boolean;
  remembered: boolean;
};

export type SafeReadOnlyMethod = "GET" | "HEAD";

export type SafeAuthenticatedFetchDetails = {
  url: string;
  method: SafeReadOnlyMethod;
  anonymous: boolean;
  authContextName?: string;
  timeoutMs?: number;
  status: number;
  statusText: string;
  contentType?: string;
  location?: string;
  responseHeaders: Record<string, string>;
  bodyLength: number;
  bodyHash: string;
  bodyExcerpt?: string;
  bodyTruncated: boolean;
  htmlSurface?: HtmlSurfaceSummary;
  headerSignature: string;
  error?: string;
};

export type HtmlSurfaceSummary = {
  title?: string;
  forms: HtmlFormSurface[];
  scripts: string[];
  links: string[];
};

export type HtmlFormSurface = {
  method: string;
  action: string;
  fields: Array<{ name: string; type?: string }>;
};

export type WebPortMatrixEntry = {
  url: string;
  host: string;
  port: number;
  scheme: "http" | "https";
  tcp: "open" | "closed" | "timeout" | "error";
  http: "response" | "silent" | "timeout" | "tls_error" | "connection_error" | "not_checked";
  status?: number;
  statusText?: string;
  contentType?: string;
  title?: string;
  error?: string;
  elapsedMs: number;
};

export type WebPortMatrixProbe = {
  target: string;
  entries: WebPortMatrixEntry[];
  interpretation: string[];
};

type ExecuteSecurityProbeActionInput = {
  store: AuditStore;
  approve: (subject: string, detail: string) => Promise<ProbeApprovalDecision>;
  normalizeApproval: (decision: ProbeApprovalDecision) => NormalizedProbeApproval;
  sessionId: string;
  emit: ToolEventEmitter;
  target: string;
  probe: SecurityProbe;
  purpose: string;
};

export async function executeSecurityProbeAction(input: ExecuteSecurityProbeActionInput): Promise<string> {
  const parsed = parseTargetInput(input.target);
  if (parsed.kind !== "url" && parsed.kind !== "domain") {
    input.emit("tool_blocked", `Blocked security probe target: ${input.target}`, {
      reason: "security_probe only accepts URL or domain targets."
    });
    return `Blocked security probe: unsupported target ${input.target}`;
  }

  input.emit("tool_approval_requested", `Approval requested for security probe: ${input.probe} ${parsed.normalized}`, {
    target: parsed,
    probe: input.probe,
    purpose: input.purpose
  });
  const approval = input.normalizeApproval(await input.approve(
    `Run security probe (${input.probe})`,
    [
      `Target: ${parsed.kind}:${parsed.normalized}`,
      `Purpose: ${input.purpose}`,
      "This uses built-in DNS/HTTP information collection only. No brute force, exploit, or scanner is run."
    ].join("\n")
  ));
  input.store.addApproval(
    input.sessionId,
    `security_probe:${input.probe}:${parsed.normalized}`,
    approval.approved,
    approval.remembered ? "Remembered approval requested for probe." : input.purpose
  );
  input.emit("tool_approval_resolved", approval.approved ? "Security probe approved." : "Security probe denied.", {
    target: parsed,
    probe: input.probe,
    approved: approval.approved
  });
  if (!approval.approved) {
    return `User denied security probe: ${input.probe} ${parsed.normalized}`;
  }

  input.emit("tool_started", `Running security probe: ${input.probe} ${parsed.normalized}`, {
    target: parsed,
    probe: input.probe
  });
  const summary = await runBuiltInSecurityProbe(parsed, input.probe);
  input.store.addObservation({
    id: newId("obs"),
    sessionId: input.sessionId,
    source: `security_probe:${input.probe}:${parsed.normalized}`,
    summary,
    createdAt: nowIso()
  });
  input.store.addEvidence({
    id: newId("evd"),
    sessionId: input.sessionId,
    source: `security_probe:${input.probe}:${parsed.normalized}`,
    kind: input.probe === "dns" ? "note" : "http",
    summary,
    data: summary,
    createdAt: nowIso()
  });
  input.emit("tool_completed", `Security probe completed: ${input.probe} ${parsed.normalized}`, {
    target: parsed,
    probe: input.probe,
    summary
  });
  return summary;
}

export async function runBuiltInSecurityProbe(target: TargetInput, probe: SecurityProbe): Promise<string> {
  const host = target.kind === "url" ? new URL(target.normalized).hostname : target.normalized;
  const sections: string[] = [];
  const hostIsIp = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(host);
  if (probe === "dns" || probe === "basic_recon") {
    if (hostIsIp) {
      sections.push(`DNS probe skipped: ${host} is an IP address, not a hostname.`);
    } else {
      sections.push(await collectDnsProbe(host));
    }
  }
  if (probe === "http_headers" || probe === "basic_recon") {
    const url = target.kind === "url" ? target.normalized : `https://${target.normalized}`;
    if (probe === "basic_recon") {
      sections.push(await collectHttpLandingPageProbe(url));
    }
    sections.push(await collectHttpHeaderProbe(url));
    if (probe === "basic_recon") {
      sections.push(renderWebPortMatrixProbe(await collectWebPortMatrixProbe(url)));
    }
  }
  return sections.join("\n\n");
}

export async function collectDnsProbe(host: string): Promise<string> {
  const parts = [`DNS probe for ${host}`];
  const collect = async (label: string, fn: () => Promise<string[]>) => {
    try {
      const values = await fn();
      parts.push(`${label}: ${values.length > 0 ? values.join(", ") : "(none)"}`);
    } catch (error) {
      parts.push(`${label}: unavailable (${error instanceof Error ? error.message : String(error)})`);
    }
  };
  await collect("A", () => resolve4(host));
  await collect("AAAA", () => resolve6(host));
  await collect("CNAME", () => resolveCname(host));
  return parts.join("\n");
}

export async function collectHttpHeaderProbe(url: string): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 3_000);
  try {
    const response = await fetch(url, {
      method: "HEAD",
      redirect: "manual",
      signal: controller.signal
    });
    const interestingHeaders = [
      "server",
      "content-type",
      "location",
      "strict-transport-security",
      "content-security-policy",
      "x-frame-options",
      "x-content-type-options",
      "referrer-policy",
      "permissions-policy",
      "set-cookie"
    ];
    const headerLines = interestingHeaders
      .map((name) => `${name}: ${response.headers.get(name) ?? "(missing)"}`);
    return [
      `HTTP header probe for ${url}`,
      `status: ${response.status} ${response.statusText}`,
      `final-url: ${response.url}`,
      ...headerLines
    ].join("\n");
  } catch (error) {
    return `HTTP header probe for ${url}\nerror: ${error instanceof Error ? error.message : String(error)}`;
  } finally {
    clearTimeout(timeout);
  }
}

export async function collectHttpLandingPageProbe(url: string): Promise<string> {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 5_000);
  try {
    const response = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal
    });
    const contentType = response.headers.get("content-type") ?? "";
    if (!/text\/html|application\/xhtml\+xml/i.test(contentType)) {
      return [
        `HTTP landing page probe for ${url}`,
        `status: ${response.status} ${response.statusText}`,
        `content-type: ${contentType || "(missing)"}`,
        "body-scan: skipped non-HTML response"
      ].join("\n");
    }
    const body = (await response.text()).slice(0, 200_000);
    const surface = extractHtmlSurface(url, body, contentType);
    return [
      `HTTP landing page probe for ${url}`,
      `status: ${response.status} ${response.statusText}`,
      `content-type: ${contentType}`,
      surface?.title ? `title: ${surface.title}` : "title: (missing)",
      surface?.forms.length ? `forms: ${surface.forms.map((form) => `${form.method} ${form.action} fields=${form.fields.map((field) => field.name).join("|") || "none"}`).join("; ")}` : "forms: (none)",
      surface?.scripts.length ? `scripts: ${surface.scripts.join(", ")}` : "scripts: (none)",
      surface?.links.length ? `links: ${surface.links.join(", ")}` : "links: (none)"
    ].join("\n");
  } catch (error) {
    return `HTTP landing page probe for ${url}\nerror: ${error instanceof Error ? error.message : String(error)}`;
  } finally {
    clearTimeout(timeout);
  }
}

export async function collectWebPortMatrixProbe(url: string): Promise<WebPortMatrixProbe> {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (error) {
    return {
      target: url,
      entries: [],
      interpretation: [`web-port-matrix unavailable: ${error instanceof Error ? error.message : String(error)}`]
    };
  }

  const host = parsed.hostname;
  const targetPort = Number.parseInt(parsed.port || (parsed.protocol === "https:" ? "443" : "80"), 10);
  const candidatePorts = uniqueNumbers([
    targetPort,
    parsed.protocol === "https:" ? 443 : 80,
    443,
    3000,
    5000,
    5050,
    8000,
    8080,
    8443,
    9090
  ]).slice(0, 10);
  const entries: WebPortMatrixEntry[] = [];
  for (const port of candidatePorts) {
    const scheme = schemeForMatrixProbe(parsed.protocol, targetPort, port);
    const matrixUrl = `${scheme}://${formatHostForUrl(host)}:${port}/`;
    entries.push(await collectWebPortMatrixEntry(matrixUrl, host, port, scheme));
  }
  return {
    target: url,
    entries,
    interpretation: interpretWebPortMatrix(entries, targetPort)
  };
}

function renderWebPortMatrixProbe(probe: WebPortMatrixProbe): string {
  const lines = [`Web port/HTTP matrix for ${probe.target}`];
  if (probe.entries.length === 0) {
    lines.push("entries: (none)");
  } else {
    for (const entry of probe.entries) {
      const parts = [
        `${entry.scheme}:${entry.port}`,
        `tcp=${entry.tcp}`,
        `http=${entry.http}`,
        entry.status ? `status=${entry.status} ${entry.statusText ?? ""}`.trim() : undefined,
        entry.contentType ? `type=${entry.contentType}` : undefined,
        entry.title ? `title=${entry.title}` : undefined,
        entry.error ? `error=${entry.error}` : undefined,
        `elapsed=${entry.elapsedMs}ms`
      ].filter((part): part is string => Boolean(part));
      lines.push(`- ${parts.join(" | ")}`);
    }
  }
  if (probe.interpretation.length > 0) {
    lines.push("interpretation:");
    for (const item of probe.interpretation) {
      lines.push(`- ${item}`);
    }
  }
  return lines.join("\n");
}

async function collectWebPortMatrixEntry(
  url: string,
  host: string,
  port: number,
  scheme: "http" | "https"
): Promise<WebPortMatrixEntry> {
  const startedAt = Date.now();
  const tcp = await probeTcp(host, port, 1_000);
  if (tcp !== "open") {
    return {
      url,
      host,
      port,
      scheme,
      tcp,
      http: "not_checked",
      elapsedMs: Date.now() - startedAt
    };
  }
  try {
    const response = await safeHttpReadOnlyRequest(url, headersForAnonymousBaseline(), "GET", 8_192, 1_800);
    const surface = extractHtmlSurface(url, response.body, response.headers["content-type"]);
    return {
      url,
      host,
      port,
      scheme,
      tcp,
      http: "response",
      status: response.status,
      statusText: response.statusText,
      contentType: response.headers["content-type"],
      title: surface?.title,
      elapsedMs: Date.now() - startedAt
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return {
      url,
      host,
      port,
      scheme,
      tcp,
      http: classifyHttpProbeError(message),
      error: shortError(message),
      elapsedMs: Date.now() - startedAt
    };
  }
}

async function probeTcp(host: string, port: number, timeoutMs: number): Promise<WebPortMatrixEntry["tcp"]> {
  return await new Promise((resolvePromise) => {
    let settled = false;
    const finish = (value: WebPortMatrixEntry["tcp"]) => {
      if (!settled) {
        settled = true;
        socket.destroy();
        resolvePromise(value);
      }
    };
    const socket = netConnect({ host, port });
    socket.setTimeout(timeoutMs);
    socket.once("connect", () => finish("open"));
    socket.once("timeout", () => finish("timeout"));
    socket.once("error", (error) => {
      const code = typeof (error as Error & { code?: unknown }).code === "string"
        ? (error as Error & { code: string }).code
        : "";
      finish(code === "ECONNREFUSED" || code === "EHOSTUNREACH" || code === "ENETUNREACH" ? "closed" : "error");
    });
  });
}

function interpretWebPortMatrix(entries: WebPortMatrixEntry[], targetPort: number): string[] {
  const open = entries.filter((entry) => entry.tcp === "open");
  const responses = open.filter((entry) => entry.http === "response");
  const silent = open.filter((entry) => entry.http !== "response");
  const interpretation: string[] = [];
  if (responses.length > 0) {
    interpretation.push(`HTTP response observed on ${responses.map((entry) => `${entry.scheme}:${entry.port}${entry.status ? `(${entry.status})` : ""}`).join(", ")}.`);
  }
  if (responses.some((entry) => entry.port !== targetPort)) {
    interpretation.push("Responding non-target ports are same-host observations only; use them only when the assessment scope allows host-level service expansion beyond the target URL.");
  }
  if (open.length >= 4 && responses.length === 0) {
    interpretation.push("Multiple TCP ports accepted connections but no HTTP response was observed; treat this as possible tarpit/all-open filtering or non-HTTP listeners before broad scanner escalation.");
  } else if (silent.length > 0) {
    interpretation.push(`TCP open but HTTP silent/error on ${silent.map((entry) => `${entry.scheme}:${entry.port}`).join(", ")}; validate protocol/banner before assuming a web app.`);
  }
  if (!entries.some((entry) => entry.port === targetPort && entry.http === "response") && responses.length > 0) {
    interpretation.push(`Target port ${targetPort} did not return the clearest HTTP evidence; prefer the responding service URL for browser recon and payload draft context.`);
  }
  if (open.length === 0) {
    interpretation.push("No candidate web port accepted a TCP connection in the short matrix probe.");
  }
  return interpretation;
}

function classifyHttpProbeError(message: string): WebPortMatrixEntry["http"] {
  if (/timed out|timeout|aborted/i.test(message)) return "timeout";
  if (/ssl|tls|wrong version number|certificate|EPROTO/i.test(message)) return "tls_error";
  if (/socket hang up|empty reply|ECONNRESET|Parse Error/i.test(message)) return "silent";
  return "connection_error";
}

function schemeForMatrixProbe(targetProtocol: string, targetPort: number, port: number): "http" | "https" {
  if (port === targetPort && targetProtocol === "https:") return "https";
  if (port === 443 || port === 8443) return "https";
  return "http";
}

function formatHostForUrl(host: string): string {
  return host.includes(":") && !host.startsWith("[") ? `[${host}]` : host;
}

function uniqueNumbers(values: number[]): number[] {
  const out: number[] = [];
  for (const value of values) {
    if (Number.isFinite(value) && value > 0 && value <= 65_535 && !out.includes(value)) {
      out.push(value);
    }
  }
  return out;
}

function shortError(message: string): string {
  return message.replace(/\s+/g, " ").slice(0, 180);
}

function firstCapture(input: string, pattern: RegExp): string | undefined {
  return pattern.exec(input)?.[1]?.trim();
}

function uniqueCaptures(input: string, pattern: RegExp, limit: number): string[] {
  const out: string[] = [];
  for (const match of input.matchAll(pattern)) {
    const value = match[1]?.trim();
    if (value && !out.includes(value)) {
      out.push(value);
    }
    if (out.length >= limit) {
      break;
    }
  }
  return out;
}

function cleanHtmlText(input: string): string {
  return input.replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim().slice(0, 180);
}

function extractHtmlSurface(baseUrl: string, body: string, contentType?: string): HtmlSurfaceSummary | undefined {
  if (!/text\/html|application\/xhtml\+xml/i.test(contentType ?? "")) {
    return undefined;
  }
  const title = firstCapture(body, /<title\b[^>]*>([\s\S]*?)<\/title>/i);
  return {
    title: title ? cleanHtmlText(title) : undefined,
    forms: extractHtmlForms(baseUrl, body).slice(0, 20),
    scripts: uniqueCaptures(body, /\bsrc\s*=\s*["']([^"']+\.js(?:[?#][^"']*)?)["']/gi, 30)
      .map((value) => resolveSurfaceUrl(baseUrl, value))
      .filter((value): value is string => Boolean(value)),
    links: uniqueCaptures(body, /\bhref\s*=\s*["']([^"']+)["']/gi, 30)
      .map((value) => resolveSurfaceUrl(baseUrl, value))
      .filter((value): value is string => Boolean(value))
  };
}

function extractHtmlForms(baseUrl: string, body: string): HtmlFormSurface[] {
  const forms: HtmlFormSurface[] = [];
  for (const match of body.matchAll(/<form\b([^>]*)>([\s\S]*?)<\/form>/gi)) {
    const attrs = match[1] ?? "";
    const inner = match[2] ?? "";
    const rawAction = firstCapture(attrs, /\baction\s*=\s*["']([^"']*)["']/i) ?? baseUrl;
    const action = resolveSurfaceUrl(baseUrl, rawAction) ?? baseUrl;
    const method = (firstCapture(attrs, /\bmethod\s*=\s*["']?([a-zA-Z]+)["']?/i) ?? "GET").toUpperCase();
    const fields = extractFormFields(inner);
    forms.push({ method, action, fields });
    if (forms.length >= 20) break;
  }
  return forms;
}

function extractFormFields(formHtml: string): Array<{ name: string; type?: string }> {
  const fields: Array<{ name: string; type?: string }> = [];
  for (const input of formHtml.matchAll(/<(input|textarea|select|button)\b([^>]*)>/gi)) {
    const tag = (input[1] ?? "").toLowerCase();
    const attrs = input[2] ?? "";
    const name = firstCapture(attrs, /\bname\s*=\s*["']([^"']+)["']/i);
    if (!name || fields.some((field) => field.name === name)) continue;
    const type = tag === "input"
      ? (firstCapture(attrs, /\btype\s*=\s*["']?([^"'\s>]+)["']?/i) ?? "text").toLowerCase()
      : tag;
    fields.push({ name, type });
    if (fields.length >= 40) break;
  }
  return fields;
}

function resolveSurfaceUrl(baseUrl: string, value: string): string | undefined {
  const trimmed = value.trim();
  if (!trimmed || trimmed === "#" || /^(?:javascript|mailto|tel):/i.test(trimmed)) {
    return undefined;
  }
  try {
    return new URL(trimmed, baseUrl).toString();
  } catch {
    return trimmed;
  }
}

export async function safeAuthenticatedFetch(url: string, authContext: SecurityAuthContext): Promise<string> {
  const headers = headersForAuthContext(authContext);
  try {
    const response = await safeHttpGet(url, headers);
    const interestingHeaders = ["content-type", "location", "set-cookie", "cache-control", "x-frame-options"];
    const headerSummary = interestingHeaders
      .map((name) => `${name}: ${response.headers[name] ?? "(missing)"}`)
      .join("; ");
    return [
      `GET ${url}`,
      `status: ${response.status} ${response.statusText}`,
      `auth-context: ${authContext.name}`,
      `headers: ${headerSummary}`
    ].join("\n");
  } catch (error) {
    return `GET ${url}\nerror: ${error instanceof Error ? error.message : String(error)}\nauth-context: ${authContext.name}`;
  }
}

export async function safeAuthenticatedFetchDetails(
  url: string,
  authContext: SecurityAuthContext,
  method: SafeReadOnlyMethod = "GET",
  timeoutMs = 5_000
): Promise<SafeAuthenticatedFetchDetails> {
  const headers = headersForAuthContext(authContext);
  try {
    const response = await safeHttpReadOnlyRequest(url, headers, method, 128_000, timeoutMs);
    const responseHeaders = selectedResponseHeaders(response.headers);
    const htmlSurface = method === "GET" ? extractHtmlSurface(url, response.body, response.headers["content-type"]) : undefined;
    return {
      url,
      method,
      anonymous: false,
      authContextName: authContext.name,
      timeoutMs,
      status: response.status,
      statusText: response.statusText,
      contentType: response.headers["content-type"],
      location: response.headers.location,
      responseHeaders,
      bodyLength: response.body.length,
      bodyHash: createHash("sha256").update(response.body).digest("hex").slice(0, 16),
      bodyExcerpt: response.body ? responseExcerpt(response.body, response.headers["content-type"]) : undefined,
      bodyTruncated: response.bodyTruncated,
      htmlSurface,
      headerSignature: ["content-type", "location", "cache-control"]
        .map((name) => `${name}:${response.headers[name] ?? ""}`)
        .join("|")
    };
  } catch (error) {
    return {
      url,
      method,
      anonymous: false,
      authContextName: authContext.name,
      timeoutMs,
      status: 0,
      statusText: "FETCH_ERROR",
      responseHeaders: {},
      bodyLength: 0,
      bodyHash: "0",
      bodyTruncated: false,
      headerSignature: "",
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

export async function safeAnonymousFetchDetails(
  url: string,
  method: SafeReadOnlyMethod = "GET",
  timeoutMs = 5_000
): Promise<SafeAuthenticatedFetchDetails> {
  const headers = headersForAnonymousBaseline();
  try {
    const response = await safeHttpReadOnlyRequest(url, headers, method, 128_000, timeoutMs);
    const responseHeaders = selectedResponseHeaders(response.headers);
    const htmlSurface = method === "GET" ? extractHtmlSurface(url, response.body, response.headers["content-type"]) : undefined;
    return {
      url,
      method,
      anonymous: true,
      timeoutMs,
      status: response.status,
      statusText: response.statusText,
      contentType: response.headers["content-type"],
      location: response.headers.location,
      responseHeaders,
      bodyLength: response.body.length,
      bodyHash: createHash("sha256").update(response.body).digest("hex").slice(0, 16),
      bodyExcerpt: response.body ? responseExcerpt(response.body, response.headers["content-type"]) : undefined,
      bodyTruncated: response.bodyTruncated,
      htmlSurface,
      headerSignature: ["content-type", "location", "cache-control"]
        .map((name) => `${name}:${response.headers[name] ?? ""}`)
        .join("|")
    };
  } catch (error) {
    return {
      url,
      method,
      anonymous: true,
      timeoutMs,
      status: 0,
      statusText: "FETCH_ERROR",
      responseHeaders: {},
      bodyLength: 0,
      bodyHash: "0",
      bodyTruncated: false,
      headerSignature: "",
      error: error instanceof Error ? error.message : String(error)
    };
  }
}

export async function safeHttpGet(
  url: string,
  headers: Record<string, string>,
  maxBodyBytes = 16_384,
  timeoutMs = 5_000
): Promise<{ status: number; statusText: string; headers: Record<string, string>; body: string; bodyTruncated: boolean }> {
  return safeHttpReadOnlyRequest(url, headers, "GET", maxBodyBytes, timeoutMs);
}

export async function safeHttpReadOnlyRequest(
  url: string,
  headers: Record<string, string>,
  method: SafeReadOnlyMethod = "GET",
  maxBodyBytes = 16_384,
  timeoutMs = 5_000
): Promise<{ status: number; statusText: string; headers: Record<string, string>; body: string; bodyTruncated: boolean }> {
  return await new Promise((resolvePromise, reject) => {
    let settled = false;
    const finish = (result: { status: number; statusText: string; headers: Record<string, string>; body: string; bodyTruncated: boolean }) => {
      if (!settled) {
        settled = true;
        resolvePromise(result);
      }
    };
    const fail = (error: Error) => {
      if (!settled) {
        settled = true;
        reject(error);
      }
    };
    let parsed: URL;
    try {
      parsed = new URL(url);
    } catch (error) {
      fail(error instanceof Error ? error : new Error(String(error)));
      return;
    }
    const transport = parsed.protocol === "https:" ? httpsRequest : httpRequest;
    const request = transport(parsed, {
      method,
      headers,
      timeout: timeoutMs
    }, (response) => {
      const chunks: Buffer[] = [];
      let total = 0;
      let truncated = false;
      response.on("data", (chunk: Buffer) => {
        if (total >= maxBodyBytes) {
          truncated = true;
          return;
        }
        const remaining = maxBodyBytes - total;
        const clipped = chunk.length > remaining ? chunk.subarray(0, remaining) : chunk;
        chunks.push(clipped);
        total += clipped.length;
        if (chunk.length > remaining) {
          truncated = true;
        }
      });
      response.on("end", () => {
        finish({
          status: response.statusCode ?? 0,
          statusText: response.statusMessage ?? "",
          headers: Object.fromEntries(Object.entries(response.headers).map(([key, value]) => [
            key.toLowerCase(),
            Array.isArray(value) ? value.join(", ") : value ?? ""
          ])),
          body: Buffer.concat(chunks).toString("utf8"),
          bodyTruncated: truncated
        });
      });
      response.on("error", fail);
    });
    request.on("timeout", () => {
      request.destroy(new Error(`Request timed out after ${timeoutMs}ms`));
    });
    request.on("error", fail);
    request.end();
  });
}

export function businessLogicProbeUrls(targetHints: string[], fallbackUrl: string | undefined): string[] {
  const urls = targetHints.filter((hint) => /^https?:\/\//i.test(hint));
  if (urls.length === 0 && fallbackUrl) {
    urls.push(fallbackUrl);
  }
  return [...new Set(urls)];
}

export function headersForAuthContext(authContext: SecurityAuthContext): Record<string, string> {
  const headers: Record<string, string> = {};
  headers["User-Agent"] = "AegisProbe safe business-logic probe";
  headers.Connection = "close";
  if (authContext.cookieHeader) {
    headers.Cookie = authContext.cookieHeader;
  }
  if (authContext.authorizationHeader) {
    headers.Authorization = authContext.authorizationHeader;
  }
  if (authContext.headersJson) {
    try {
      const parsed = JSON.parse(authContext.headersJson) as Record<string, unknown>;
      for (const [key, value] of Object.entries(parsed)) {
        if (typeof value === "string" && key.toLowerCase() !== "host") {
          headers[key] = value;
        }
      }
    } catch {
      // Invalid optional headers are ignored; the raw value remains audited in auth context metadata.
    }
  }
  const storageCookie = cookieHeaderFromStorageState(authContext.storageStatePath);
  if (storageCookie && !headers.Cookie) {
    headers.Cookie = storageCookie;
  }
  return headers;
}

export function headersForAnonymousBaseline(): Record<string, string> {
  return {
    "User-Agent": "AegisProbe anonymous baseline probe",
    Connection: "close"
  };
}

function selectedResponseHeaders(headers: Record<string, string>): Record<string, string> {
  const selected = [
    "content-type",
    "content-length",
    "location",
    "cache-control",
    "x-frame-options",
    "x-content-type-options",
    "access-control-allow-origin",
    "server",
    "x-powered-by",
    "set-cookie"
  ];
  const out: Record<string, string> = {};
  for (const name of selected) {
    const value = headers[name];
    if (!value) continue;
    out[name] = name === "set-cookie" ? redactSetCookie(value) : value;
  }
  return out;
}

function responseExcerpt(body: string, contentType: string | undefined): string | undefined {
  if (!body) return undefined;
  const normalizedContentType = contentType?.toLowerCase() ?? "";
  const looksText = !normalizedContentType
    || /json|xml|html|text|javascript|x-www-form-urlencoded|graphql|problem\+json/i.test(normalizedContentType);
  if (!looksText && likelyBinary(body)) {
    return "[non-text response body omitted]";
  }
  return body.replace(/\u0000/g, "").slice(0, 2_000);
}

function likelyBinary(value: string): boolean {
  const sample = value.slice(0, 512);
  if (sample.length === 0) return false;
  const controlChars = [...sample].filter((char) => {
    const code = char.charCodeAt(0);
    return code < 9 || (code > 13 && code < 32);
  }).length;
  return controlChars / sample.length > 0.1;
}

function redactSetCookie(value: string): string {
  return value
    .split(/,\s*(?=[^;,]+=)/)
    .map((cookie) => {
      const [name] = cookie.split("=", 1);
      return `${name || "cookie"}=[redacted]`;
    })
    .join(", ");
}

export function cookieHeaderFromStorageState(path: string | undefined): string | undefined {
  if (!path || !existsSync(path)) {
    return undefined;
  }
  try {
    const parsed = JSON.parse(readFileSync(path, "utf8")) as { cookies?: Array<{ name?: string; value?: string }> };
    const cookies = parsed.cookies
      ?.filter((cookie) => cookie.name && cookie.value)
      .map((cookie) => `${cookie.name}=${cookie.value}`)
      .join("; ");
    return cookies || undefined;
  } catch {
    return undefined;
  }
}
