// Structured Tool Definitions (Claude Code-style)
// Each tool has a name, description, JSON Schema for inputs, and a command builder.
// The model selects a tool by name and provides typed inputs; the framework
// validates, constructs the actual shell command, and executes it.
//
// Inspired by: Claude Code tool_use blocks, Cairn's Worker container tool access.

export type ToolDef = {
  name: string;
  description: string;
  inputSchema: {
    type: "object";
    properties: Record<string, { type: string; description: string; enum?: string[] }>;
    required: string[];
  };
  /** Build the shell command from typed inputs. Returns null if command can't be built. */
  buildCommand?: (input: Record<string, unknown>) => string | null;
};

// Core Tools

const TOOL_BASH: ToolDef = {
  name: "bash",
  description: "Execute a local PowerShell-compatible command only when no typed tool fits. Do not use for ordinary HTTP GET/HEAD; typed web/API tools preserve evidence better.",
  inputSchema: {
    type: "object",
    properties: {
      command: { type: "string", description: "The full bash command to execute" },
      purpose: { type: "string", description: "Why you are running this command" },
    },
    required: ["command"],
  },
};

const TOOL_HTTP_GET: ToolDef = {
  name: "http_get",
  description: "Make a read-only anonymous HTTP GET observation. In an active session this records structured evidence like status, headers, body hash/excerpt, title, forms, scripts, and links. Prefer anonymous_baseline_fetch when you need to name the baseline explicitly.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
      url: { type: "string", description: "Full URL including scheme (http://IP:PORT/path)" },
      followRedirects: { type: "string", description: "Follow HTTP redirects (true/false)", enum: ["false", "true"] },
    },
    required: ["url"],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    const url = input.url as string;
    if (sessionId && url) {
      return `node apps/cli/dist/index.js anonymous-fetch ${quotePowerShellArg(sessionId)} ${quotePowerShellArg(url)} --method GET`;
    }
    const follow = input.followRedirects === "true" ? "-L " : "";
    return `curl.exe -s -i --max-time 10 ${follow}${quotePowerShellArg(url)}`;
  },
};

const TOOL_NMAP: ToolDef = {
  name: "nmap_scan",
  description: "Scan for service versions after a smaller port probe has identified candidate ports. Avoid broad top-port nmap scans on slow or unreachable hosts; prefer port_probe first for quick reachability.",
  inputSchema: {
    type: "object",
    properties: {
      target: { type: "string", description: "Target IP address or hostname" },
      ports: { type: "string", description: "Port range: 'top1000', 'top100', or specific like '22,80,443,5050,8080'" },
      udp: { type: "string", description: "Scan UDP instead of TCP (true/false)", enum: ["false", "true"] },
    },
    required: ["target"],
  },
  buildCommand: (input) => {
    const target = input.target as string;
    const udp = input.udp === "true" ? "-sU" : "-sV";
    const ports = (input.ports as string) || "top1000";
    if (ports.startsWith("top")) {
      const n = ports.replace("top", "");
      return `nmap ${udp} --top-ports ${n} --host-timeout 45s --max-retries 1 ${target} 2>&1`;
    }
    return `nmap ${udp} -p ${ports} --host-timeout 45s --max-retries 1 ${target} 2>&1`;
  },
};

const TOOL_PORT_PROBE: ToolDef = {
  name: "port_probe",
  description: "Quick bounded TCP port confirmation with naabu. Prefer this before nmap when HTTP times out or when checking a short list of common web ports.",
  inputSchema: {
    type: "object",
    properties: {
      target: { type: "string", description: "Target IP address or hostname" },
      ports: { type: "string", description: "Comma-separated ports or naabu preset such as top-100. Default: 80,443,8080,8443" },
      timeoutMs: { type: "string", description: "Per-probe timeout in milliseconds, usually 1000-3000" },
    },
    required: ["target"],
  },
  buildCommand: (input) => {
    const target = stringInput(input.target);
    if (!target) return null;
    const ports = stringInput(input.ports) ?? "80,443,8080,8443";
    const timeout = boundedIntegerInput(input.timeoutMs, 300, 10_000, 2000);
    return `naabu -host ${quotePowerShellArg(target)} -ports ${quotePowerShellArg(ports)} -silent -timeout ${timeout}`;
  },
};

const TOOL_NUCLEI: ToolDef = {
  name: "nuclei_scan",
  description: "Run a targeted nuclei validation only when capability evidence shows nuclei is available and product/version evidence justifies it.",
  inputSchema: {
    type: "object",
    properties: {
      target: { type: "string", description: "Target URL or IP:PORT (e.g. http://IP:5050 or IP:161)" },
      tags: { type: "string", description: "Template tags to filter (e.g. 'snmp', 'pgadmin,struts')" },
      severity: { type: "string", description: "Minimum severity", enum: ["info", "medium", "high", "critical"] },
    },
    required: ["target", "tags"],
  },
  buildCommand: (input) => {
    const target = input.target as string;
    const tags = (input.tags as string) || "";
    const sev = (input.severity as string) || "high,critical";
    return `nuclei -u ${quotePowerShellArg(target)} -tags ${quotePowerShellArg(tags)} -severity ${quotePowerShellArg(sev)} -silent -timeout 10 2>&1`;
  },
};

const TOOL_PYTHON: ToolDef = {
  name: "python_run",
  description: "Execute a Python script or one-liner. Use for: exploit scripts, custom enumeration, data processing.",
  inputSchema: {
    type: "object",
    properties: {
      script: { type: "string", description: "Python code or script path to execute" },
      purpose: { type: "string", description: "Why you are running this" },
    },
    required: ["script"],
  },
  buildCommand: (input) => {
    const script = input.script as string;
    return `python3 -c "${script.replace(/"/g, '\\"')}" 2>&1`;
  },
};

// All Tools Registry

const TOOL_WEBAPP_RECON: ToolDef = {
  name: "webapp_recon",
  description: "Run integrated read-only Browser Recon Runtime for an in-scope URL. Collects DOM, forms, JS assets, runtime network, storage, cookies, API inventory, normalized API, and auth surface.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
      url: { type: "string", description: "In-scope URL or auth context name/id to recon" },
      maxPages: { type: "string", description: "Maximum same-origin pages to visit, usually 10" },
      analyzeJs: { type: "string", description: "Run JS analyzer (true/false)", enum: ["true", "false"] },
    },
    required: ["url"],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    const url = stringInput(input.url);
    if (!sessionId || !url) return null;
    const maxPages = boundedIntegerInput(input.maxPages, 1, 50, 10);
    const noJs = input.analyzeJs === "false" ? " --no-js" : "";
    return `node apps/cli/dist/index.js webapp-recon ${quotePowerShellArg(sessionId)} ${quotePowerShellArg(url)} --max-pages ${maxPages}${noJs}`;
  },
};

const TOOL_EXPERT_SNAPSHOT: ToolDef = {
  name: "expert_snapshot",
  description: "Render a read-only expert workbench snapshot from existing session evidence. It summarizes raw observations, endpoint exposure, auth context state, payload affordances, request drafts, failures, and evidence gaps without sending requests or prescribing a task order.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
    },
    required: [],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    if (!sessionId) return null;
    return `node apps/cli/dist/index.js expert-snapshot ${quotePowerShellArg(sessionId)}`;
  },
};

const TOOL_API_DESCRIPTION_IMPORT: ToolDef = {
  name: "api_description_import",
  description: "Import an explicit OpenAPI JSON document or same-origin GraphQL endpoint supplied by evidence/operator into normalized API inventory. Does not guess common paths.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
      source: { type: "string", description: "Explicit OpenAPI JSON file/URL or same-origin GraphQL endpoint URL" },
    },
    required: ["source"],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    const source = stringInput(input.source);
    if (!sessionId || !source) return null;
    return `node apps/cli/dist/index.js api-description-import ${quotePowerShellArg(sessionId)} ${quotePowerShellArg(source)}`;
  },
};

const TOOL_AUTHZ_MATRIX: ToolDef = {
  name: "authz_matrix",
  description: "Render the authorization boundary matrix derived from normalized API and approved auth context evidence.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
    },
    required: [],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    if (!sessionId) return null;
    return `node apps/cli/dist/index.js authz-matrix ${quotePowerShellArg(sessionId)}`;
  },
};

const TOOL_AUTHZ_PLAN: ToolDef = {
  name: "authz_plan",
  description: "Render evidence-driven BOLA/BFLA/workflow authorization validation candidates from normalized API evidence. Planning only; does not send requests.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
    },
    required: [],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    if (!sessionId) return null;
    return `node apps/cli/dist/index.js authz-plan ${quotePowerShellArg(sessionId)}`;
  },
};

const TOOL_BUSINESS_PLAN: ToolDef = {
  name: "business_plan",
  description: "Render the safe business-logic testing plan derived from normalized API, auth model, and authorization matrix evidence.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
    },
    required: [],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    if (!sessionId) return null;
    return `node apps/cli/dist/index.js business-plan ${quotePowerShellArg(sessionId)}`;
  },
};

const TOOL_ACCESS_EXPOSURE_MAP: ToolDef = {
  name: "access_exposure_map",
  description: "Render an information-gathering map for anonymous exposure, auth gates, high-value routes, and authorization-sensitive endpoints. This does not send requests; it tells the model where anonymous baselines, auth baselines, role comparisons, or passive mutation review are still needed.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
      maxItems: { type: "string", description: "Maximum exposure items to render, usually 20-30" },
    },
    required: [],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    if (!sessionId) return null;
    return `node apps/cli/dist/index.js access-map ${quotePowerShellArg(sessionId)} --limit ${boundedIntegerInput(input.maxItems, 1, 120, 30)}`;
  },
};

const TOOL_PAYLOAD_CANDIDATES: ToolDef = {
  name: "payload_candidates",
  description: "Generate advisory payload/probe candidates from the current session evidence. This does not send requests, execute payloads, or decide the next action; it gives the model context-aware input options with prerequisites, risk, and expected observations.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
      focus: { type: "string", description: "Optional vulnerability focus such as xss, sqli, ssti, ssrf, authz, mass_assignment, upload, command_injection" },
      maxCandidates: { type: "string", description: "Maximum candidates to render, usually 8-12" },
      activeAllowed: { type: "string", description: "Whether active probing is currently allowed (true/false)", enum: ["true", "false"] },
    },
    required: [],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    if (!sessionId) return null;
    const args = [`node apps/cli/dist/index.js payload-candidates ${quotePowerShellArg(sessionId)}`];
    const focus = stringInput(input.focus);
    if (focus) args.push(`--focus ${quotePowerShellArg(focus)}`);
    args.push(`--limit ${boundedIntegerInput(input.maxCandidates, 1, 40, 12)}`);
    if (input.activeAllowed === "true") args.push("--active");
    return args.join(" ");
  },
};

const TOOL_PAYLOAD_REQUEST_DRAFTS: ToolDef = {
  name: "payload_request_drafts",
  description: "Generate reviewable HTTP request drafts from payload candidates and insertion-point evidence. This does not send requests or execute payloads; it shows baseline/probe URLs, body previews, auth context hints, approval gates, and expected observations so the model can decide what to do.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
      focus: { type: "string", description: "Optional vulnerability focus such as xss, sqli, ssti, ssrf, authz, mass_assignment, upload, command_injection" },
      maxDrafts: { type: "string", description: "Maximum drafts to render, usually 8-12" },
      activeAllowed: { type: "string", description: "Whether active probing is currently allowed (true/false)", enum: ["true", "false"] },
    },
    required: [],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    if (!sessionId) return null;
    const args = [`node apps/cli/dist/index.js payload-drafts ${quotePowerShellArg(sessionId)}`];
    const focus = stringInput(input.focus);
    if (focus) args.push(`--focus ${quotePowerShellArg(focus)}`);
    args.push(`--limit ${boundedIntegerInput(input.maxDrafts, 1, 60, 12)}`);
    if (input.activeAllowed === "true") args.push("--active");
    return args.join(" ");
  },
};

const TOOL_SAFE_READONLY_FETCH: ToolDef = {
  name: "safe_readonly_fetch",
  description: "Make a read-only (GET/HEAD) HTTP request using a registered auth context. Use when you want to test how a specific endpoint responds with a specific user's credentials; this is the primary method for discovering BOLA/IDOR/BFLA. The auth context's cookie/authorization header is injected automatically. Returns status, selected response headers, content type, body length/hash, and a limited raw body excerpt for comparison.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
      url: { type: "string", description: "Full URL including scheme (http://IP:PORT/path). Must be within scope." },
      authContextName: { type: "string", description: "Name or id of a registered auth context (e.g. 'alice', 'customer-a')" },
      method: { type: "string", description: "HTTP method (GET or HEAD only)", enum: ["GET", "HEAD"] },
    },
    required: ["url", "authContextName"],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    const url = stringInput(input.url);
    const authContextName = stringInput(input.authContextName);
    if (!sessionId || !url || !authContextName) return null;
    const method = stringInput(input.method) ?? "GET";
    if (!["GET", "HEAD"].includes(method.toUpperCase())) return null;
    return `node apps/cli/dist/index.js safe-fetch ${quotePowerShellArg(sessionId)} ${quotePowerShellArg(url)} ${quotePowerShellArg(authContextName)} --method ${method.toUpperCase()}`;
  },
};

const TOOL_ANONYMOUS_BASELINE_FETCH: ToolDef = {
  name: "anonymous_baseline_fetch",
  description: "Make a read-only anonymous GET/HEAD request for unauthorized-access baseline evidence. Use this before claiming missing authorization or before comparing authenticated-only responses. Returns selected response headers, content type, body length/hash, and a limited raw body excerpt.",
  inputSchema: {
    type: "object",
    properties: {
      sessionId: { type: "string", description: "Current AegisProbe session id. The runtime fills this automatically when omitted." },
      url: { type: "string", description: "Full URL including scheme (http://IP:PORT/path). Must be within scope." },
      method: { type: "string", description: "HTTP method (GET or HEAD only)", enum: ["GET", "HEAD"] },
    },
    required: ["url"],
  },
  buildCommand: (input) => {
    const sessionId = stringInput(input.sessionId);
    const url = stringInput(input.url);
    if (!sessionId || !url) return null;
    const method = stringInput(input.method) ?? "GET";
    if (!["GET", "HEAD"].includes(method.toUpperCase())) return null;
    return `node apps/cli/dist/index.js anonymous-fetch ${quotePowerShellArg(sessionId)} ${quotePowerShellArg(url)} --method ${method.toUpperCase()}`;
  },
};

export const SECURITY_TOOLS: ToolDef[] = [
  TOOL_EXPERT_SNAPSHOT,
  TOOL_WEBAPP_RECON,
  TOOL_API_DESCRIPTION_IMPORT,
  TOOL_SAFE_READONLY_FETCH,
  TOOL_ANONYMOUS_BASELINE_FETCH,
  TOOL_AUTHZ_MATRIX,
  TOOL_AUTHZ_PLAN,
  TOOL_BUSINESS_PLAN,
  TOOL_ACCESS_EXPOSURE_MAP,
  TOOL_PAYLOAD_CANDIDATES,
  TOOL_PAYLOAD_REQUEST_DRAFTS,
  TOOL_HTTP_GET,
  TOOL_PORT_PROBE,
  TOOL_NMAP,
  TOOL_NUCLEI,
  TOOL_PYTHON,
  TOOL_BASH, // fallback; always last so the model prefers typed tools
];

/**
 * Build a bash command from a tool call (name + input).
 * Returns null if the tool is not recognized or input is invalid.
 */
export function buildToolCommand(name: string, input: Record<string, unknown>): string | null {
  const tool = SECURITY_TOOLS.find(t => t.name === name);
  if (!tool) return null;
  if (tool.buildCommand) return tool.buildCommand(input);

  // Fallback: bash tool uses the raw command
  if (name === "bash") {
    const cmd = input.command as string;
    if (!cmd) return null;
    return cmd;
  }

  return null;
}

/**
 * Render all tool definitions as a Claude Code-style JSON block for the system prompt.
 */
export function renderToolDefinitions(): string {
  const tools = SECURITY_TOOLS.map(t => ({
    name: t.name,
    description: t.description,
    input_schema: t.inputSchema,
  }));
  return JSON.stringify(tools, null, 2);
}

function stringInput(value: unknown): string | undefined {
  return typeof value === "string" && value.trim().length > 0 ? value.trim() : undefined;
}

function boundedIntegerInput(value: unknown, min: number, max: number, fallback: number): number {
  const parsed = Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(parsed)) return fallback;
  return Math.min(max, Math.max(min, parsed));
}

function quotePowerShellArg(value: string): string {
  return `'${value.replace(/'/g, "''")}'`;
}
