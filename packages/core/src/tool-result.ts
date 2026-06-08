// ── Tool Result Formatter ──
// Wraps raw tool outputs in structured JSON so the model receives typed
// success/error/hint signals instead of ambiguous raw text.
//
// Inspired by Claude Code's structured tool_use result blocks:
//   - Every result has a status: "success" | "error" | "timeout" | "empty"
//   - Errors include a "hint" telling the model what went wrong and how to fix it
//   - The model sees typed data, not raw shell output, reducing syntax-error loops

export type ToolResultStatus = "success" | "error" | "timeout" | "empty" | "blocked";

export type ToolResult = {
  tool: string;
  action: string; // short description of what was attempted
  status: ToolResultStatus;
  exitCode?: number;
  summary: string;
  rawExcerpt?: string;
  data?: unknown;
  error?: string;
  hint?: string;
};

/**
 * Normalize a raw tool execution result into a structured ToolResult.
 * The model receives this JSON instead of raw command output text.
 */
export function formatToolResult(tool: string, action: string, raw: string): ToolResult {
  // MCP results: strip the "MCP toolname: " prefix for cleaner processing
  let cleanRaw = raw;
  if (tool === "mcp") {
    cleanRaw = raw.replace(/^MCP \w+:\s*/, "");
  }

  const lower = cleanRaw.toLowerCase();

  // ── Detect status ──
  let status: ToolResultStatus = "success";
  let error: string | undefined;
  let hint: string | undefined;

  // Exit code 1 with no useful output
  if (lower.includes("exit code 1") || lower.includes("exit code: 1")) {
    const meaningfulLines = raw.split("\n").filter(l => l.trim().length > 10 && !l.includes("Exit code")).length;
    if (meaningfulLines <= 1) {
      status = "error";
    }
  }

  // Timeout
  if (lower.includes("timed out") || lower.includes("connection timed out") || lower.includes("timeout")) {
    status = "timeout";
    hint = "The target may be down, rate-limiting, or behind a firewall. Do NOT retry the same request. Pivot to a different port or service.";
  }

  if (lower.includes("exit code 127") || lower.includes("command not found")) {
    status = "error";
    error = extractError(cleanRaw);
    hint = lower.includes("nuclei")
      ? "Nuclei is not on PATH. Use the configured full nuclei binary path from the system prompt, or pivot to curl/exploit_sender for bounded validation."
      : "The command is not on PATH. Verify the configured tool path before retrying, or pivot to an available tool.";
  }

  if (lower.includes("could not run nuclei") || lower.includes("no templates provided")) {
    status = "error";
    error = extractError(cleanRaw);
    hint = "Nuclei did not load templates for that invocation. Retry without -t and use the configured binary with -tags or -id, or pivot to the exploit runner when CVE evidence is already strong.";
  }

  // Blocked
  if (lower.includes("blocked") || lower.includes("denied") || lower.includes("not authorized")) {
    status = "blocked";
  }

  // Empty output
  const cleanLines = cleanRaw.split("\n").filter(l => l.trim().length > 0);
  if (cleanLines.length <= 2 && !lower.includes("uid=") && !lower.includes("result")) {
    if (status === "success") status = "empty";
  }

  // ── Known syntax errors → error + corrective hint ──
  if (lower.includes("error") || lower.includes("usage") || lower.includes("flag provided but not defined")) {
    status = "error";
    error = extractError(cleanRaw);

    // httpx
    if (lower.includes("httpx") && (lower.includes("no such option") || lower.includes("-u"))) {
      hint = "This httpx is not usable for ProjectDiscovery-style probing, or the flags are wrong. PATH may resolve to Python httpx. Use curl.exe/security_probe unless ProjectDiscovery httpx is explicitly available.";
    }
    // naabu
    if (lower.includes("naabu") && lower.includes("flag provided but not defined")) {
      hint = "naabu argument error. Use: naabu -host IP -silent (basic scan) or naabu -host IP -p 80,443 (specific ports).";
    }
    // nmap data files
    if (lower.includes("nmap") && (lower.includes("unable to find") || lower.includes("resorting"))) {
      hint = "nmap data files missing. Try: nmap -sV -p PORTS IP (without --script flags).";
    }
    // PowerShell alias
    if (lower.includes("invoke-webrequest") || lower.includes("缺少参数")) {
      hint = "PowerShell aliased 'curl' to Invoke-WebRequest. Always use 'curl.exe' (with .exe) in shell commands.";
    }
    // || in PowerShell
    if (lower.includes("标记") && lower.includes("不是此版本中的有效语句")) {
      hint = "PowerShell does not support '||'. Use separate commands or ';' for chaining.";
    }
    // Generic
    if (!hint) {
      hint = "Command failed. Check tool syntax before retrying. If unsure about flags, try a different tool.";
    }
  }

  // ── Build summary ──
  const summary = buildSummary(tool, raw, cleanRaw, status, cleanLines);

  return { tool, action, status, exitCode: status === "error" ? 1 : 0, summary, rawExcerpt: buildRawExcerpt(cleanRaw), error, hint };
}

function extractError(raw: string): string {
  const lines = raw.split("\n");
  for (const line of lines) {
    const t = line.trim().toLowerCase();
    if (t.includes("error") || t.includes("no such") || t.includes("flag provided") || t.includes("cannot")) {
      return line.trim().slice(0, 200);
    }
  }
  return lines.find(l => l.trim().length > 0)?.trim().slice(0, 200) ?? "Unknown error";
}

function buildSummary(tool: string, _raw: string, cleanRaw: string, status: ToolResultStatus, lines: string[]): string {
  // MCP: pass through nearly full — browser snapshots are the model's eyes
  if (tool === "mcp") {
    return cleanRaw.slice(0, 30_000).trim();
  }

  if (status === "error") {
    // Keep only the error lines, not the full raw output
    const errLines = lines.filter(l =>
      l.toLowerCase().includes("error") ||
      l.toLowerCase().includes("usage") ||
      l.toLowerCase().includes("flag") ||
      l.toLowerCase().includes("no such") ||
      l.toLowerCase().includes("not found")
    );
    if (errLines.length > 0) return errLines.slice(0, 5).join("\n");
    return lines.slice(0, 5).join("\n");
  }

  // Success: extract key signals
  const signals: string[] = [];

  // HTTP response
  for (const line of lines) {
    if (line.includes("HTTP/") || line.includes("Server:") || line.includes("Title:") ||
        line.includes("status:") || line.includes("PORT") || line.includes("open")) {
      signals.push(line.trim());
    }
  }
  if (signals.length > 0) return signals.slice(0, 10).join("\n");

  // Exploit result
  if (cleanRaw.includes("uid=") || cleanRaw.includes("Result:")) {
    const idx = cleanRaw.indexOf("Result:");
    if (idx >= 0) return cleanRaw.slice(idx, idx + 300).trim();
    return cleanRaw.slice(0, 500).trim();
  }

  // Default: first meaningful lines
  return lines.slice(0, 8).map(l => l.trim()).filter(Boolean).join("\n").slice(0, 8_000);
}

/**
 * Render a ToolResult as a compact JSON string for model context.
 * Model sees: {"tool":"shell","status":"error","summary":"...","hint":"Use curl.exe..."}
 */
export function renderToolResult(result: ToolResult): string {
  const obj: Record<string, unknown> = {
    tool: result.tool,
    action: result.action,
    status: result.status,
  };
  if (result.exitCode !== undefined && result.exitCode !== 0) obj.exitCode = result.exitCode;
  obj.summary = result.summary;
  if (result.rawExcerpt) obj.rawExcerpt = result.rawExcerpt;
  if (result.error) obj.error = result.error;
  if (result.hint) obj.hint = result.hint;
  if (result.data) obj.data = result.data;

  return JSON.stringify(obj, null, 0);
}

function buildRawExcerpt(raw: string): string | undefined {
  const normalized = raw.trim();
  if (!normalized) {
    return undefined;
  }
  if (normalized.length <= 20_000) {
    return normalized;
  }
  const head = normalized.slice(0, 12_000);
  const tail = normalized.slice(-6_000);
  return `${head}\n\n[... raw output truncated: ${normalized.length - head.length - tail.length} chars omitted ...]\n\n${tail}`;
}

/**
 * Human-readable one-liner for the terminal log (separate from model context).
 */
export function describeToolResult(result: ToolResult): string {
  const icon = result.status === "success" ? "✅" : result.status === "error" ? "❌" : result.status === "timeout" ? "⏱" : "⚠️";
  return `${icon} ${result.tool}: ${result.action} [${result.status}]${result.hint ? " — " + result.hint : ""}`;
}
