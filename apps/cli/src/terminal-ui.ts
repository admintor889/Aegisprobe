import type { ConversationTurnEvent } from "@aegisprobe/core";
import type { TurnEvent } from "@aegisprobe/shared";
import type { PersistentChatTerminal } from "./chat-terminal.js";

const useColor = Boolean(process.stdout.isTTY && !process.env.NO_COLOR);
const terminalWidth = () => Math.max(72, Math.min(process.stdout.columns || 96, 120));

const ansi = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  magenta: "\x1b[35m",
  yellow: "\x1b[33m",
  gray: "\x1b[90m",
  blue: "\x1b[34m"
};

function style(value: string, code: keyof typeof ansi): string {
  return useColor ? `${ansi[code]}${value}${ansi.reset}` : value;
}

function bold(value: string): string { return style(value, "bold"); }
function faint(value: string): string { return style(value, "dim"); }
function label(value: string): string { return style(value, "cyan"); }
function ok(value: string): string { return style(value, "green"); }
function danger(value: string): string { return style(value, "red"); }
function warn(value: string): string { return style(value, "yellow"); }
function brand(value: string): string { return style(value, "green"); }
function blue(value: string): string { return style(value, "blue"); }

/**
 * Convert common Markdown formatting to plain terminal text.
 * This is a fallback — the system prompt tells the model to output
 * plain text, but some providers ignore that instruction.
 * Codex avoids this problem entirely by training the model to output
 * terminal-safe text when mode=terminal; we can't retrain, so we strip.
 */
function stripMarkdownForTerminal(text: string): string {
  return text
    // Headers: # Title → Title (bold)
    .replace(/^#{1,6}\s+(.+)$/gm, (_, h) => bold(h))
    // Bold: **text** → text (bold)
    .replace(/\*\*(.+?)\*\*/g, (_, b) => bold(b))
    // Italic: *text* → text
    .replace(/(?<!\*)\*([^*\n]+?)\*(?!\*)/g, "$1")
    // Inline code: `text` → text
    .replace(/`([^`\n]+?)`/g, "$1")
    // Links: [text](url) → text (url)
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1 ($2)")
    // Bullet list markers: - or * at line start → —
    .replace(/^[*-]\s+(?!\s)/gm, "\u2014 ")
    // Triple-backtick code fences (open/close) → empty
    .replace(/^```[\w]*\s*$/gm, "")
    // Blockquote: > text → │ text
    .replace(/^>\s?(.+)$/gm, "\u2502 $1")
    // Horizontal rules: --- or *** → empty line
    .replace(/^[-*_]{3,}\s*$/gm, "");
}

type CardTone = "info" | "success" | "warning" | "danger" | "tool" | "agent";

type ToolRecord = {
  id: string;
  name: string;
  arguments: string;
  result?: string;
  error?: boolean;
  startedAt?: number;
  endedAt?: number;
};

type ToolEnvelopeView = {
  status?: string;
  durationMs?: number;
  exitCode?: number | null;
  stdout?: string;
  stderr?: string;
  artifacts?: string[];
  truncated?: { stdout?: boolean; stderr?: boolean };
};

export type ToolViewMode = "compact" | "full";

export function aegisPrompt(): string {
  return `\n${brand("aegis")}${faint(" / agent")}> `;
}

export function printChatBanner(input: {
  sessionId?: string;
  target?: string;
  mode?: "chat" | "pentest" | "resume";
} = {}): void {
  const mode = input.mode ?? "chat";
  const title = `${brand("AegisProbe")}${faint(" agent console")}`;
  const meta = [
    label(mode),
    input.sessionId ? faint(`session ${input.sessionId}`) : undefined,
    input.target ? faint(input.target) : undefined
  ].filter(Boolean).join("  ");
  console.log();
  printBox({
    title,
    tone: "agent",
    lines: [
      meta,
      `${faint("persistent composer")}  ${faint("queued follow-ups")}  ${faint("compact tool transcript")}`,
      `${label("/help")} ${faint("commands")}  ${label("/exit")} ${faint("quit")}  ${label("Esc")} ${faint("interrupt")}`
    ].filter(Boolean)
  });
}

export class ToolTranscriptStore {
  private readonly records = new Map<string, ToolRecord>();
  private readonly order: string[] = [];
  private mode: ToolViewMode = "compact";

  setMode(mode: ToolViewMode): void {
    this.mode = mode;
  }

  getMode(): ToolViewMode {
    return this.mode;
  }

  rememberCall(id: string, name: string, args: string): ToolRecord {
    const existing = this.records.get(id);
    if (existing) {
      existing.name = name;
      existing.arguments = args;
      return existing;
    }
    const record = { id, name, arguments: args };
    this.records.set(id, record);
    this.order.push(id);
    return record;
  }

  start(id: string, name: string): ToolRecord {
    const record = this.records.get(id) ?? this.rememberCall(id, name, "");
    record.startedAt = Date.now();
    return record;
  }

  complete(id: string, result: string, error?: boolean): ToolRecord {
    const record = this.records.get(id) ?? this.rememberCall(id, "tool", "");
    record.result = result;
    record.error = error;
    record.endedAt = Date.now();
    return record;
  }

  render(identifier = "last"): string {
    const id = identifier === "last" ? this.order.at(-1) : identifier;
    const record = id ? this.records.get(id) : undefined;
    if (!record) return `Tool call not found: ${identifier}`;
    const envelope = parseToolEnvelope(record.result);
    const lines = [
      `${record.name}  ${record.id}`,
      "",
      "Arguments",
      prettyJson(record.arguments) || "(none)"
    ];
    if (record.result !== undefined) {
      lines.push(
        "",
        `Result  ${envelope?.status ?? (record.error ? "error" : "complete")}`,
        prettyJson(record.result)
      );
    }
    return lines.join("\n");
  }
}

export class CodexLikeTurnRenderer {
  private textOpen = false;
  private pendingText = "";
  private readonly toolArgs = new Map<string, { name: string; args: string }>();

  constructor(
    private readonly terminal?: PersistentChatTerminal,
    private readonly tools = new ToolTranscriptStore()
  ) {}

  handle(event: ConversationTurnEvent): void {
    switch (event.kind) {
      case "text_start":
        this.startAssistantText();
        this.updateStatus("thinking…");
        break;
      case "text_delta":
        this.writeAssistantDelta(event.content);
        this.updateStatus("thinking…");
        break;
      case "text_end":
        this.endAssistantText();
        break;
      case "tool_call_start":
        this.endAssistantText();
        this.toolArgs.set(event.id, { name: event.name, args: "" });
        this.updateStatus(`calling ${event.name}…`);
        break;
      case "tool_call_delta": {
        const existing = this.toolArgs.get(event.id) ?? { name: "tool", args: "" };
        existing.args += event.arguments;
        this.toolArgs.set(event.id, existing);
        break;
      }
      case "tool_call_end":
        this.endAssistantText();
        this.toolArgs.set(event.id, { name: event.name, args: event.arguments });
        this.tools.rememberCall(event.id, event.name, event.arguments);
        break;
      case "tool_execution_start": {
        this.endAssistantText();
        const record = this.tools.start(event.id, event.name);
        this.writeLines(formatToolStart(record));
        this.updateStatus(`running ${event.name}…`);
        break;
      }
      case "tool_execution_end": {
        this.endAssistantText();
        const record = this.tools.complete(event.id, event.result, event.error);
        this.writeLines(formatToolCompletion(record, this.tools.getMode()));
        this.updateStatus("");
        break;
      }
      case "turn_complete":
        this.endAssistantText();
        this.updateStatus("");
        break;
      case "turn_aborted":
        this.endAssistantText();
        this.writeLine(warn("Turn interrupted."));
        this.updateStatus("");
        break;
      case "turn_error":
        this.endAssistantText();
        this.writeLine(`${danger("Error:")} ${event.error}`);
        this.updateStatus("");
        break;
    }
  }

  finish(): void {
    this.endAssistantText();
  }

  private startAssistantText(): void {
    if (this.textOpen) return;
    this.textOpen = true;
    this.pendingText = "";
    this.writeLine("");
    this.writeLine(`${brand("\u25cf")} ${bold("AegisProbe")}`);
  }

  private writeAssistantDelta(content: string): void {
    if (!this.textOpen) this.startAssistantText();
    if (!this.terminal) {
      process.stdout.write(content);
      return;
    }
    this.pendingText += content;
    const newline = this.pendingText.lastIndexOf("\n");
    if (newline >= 0) {
      const complete = this.pendingText.slice(0, newline + 1);
      this.pendingText = this.pendingText.slice(newline + 1);
      this.terminal.writeLine(stripMarkdownForTerminal(complete));
    }
    this.terminal.setLiveText(stripMarkdownForTerminal(this.pendingText));
  }

  private endAssistantText(): void {
    if (!this.textOpen) return;
    if (this.terminal) {
      this.terminal.setLiveText(stripMarkdownForTerminal(this.pendingText));
      this.terminal.commitLiveText();
    } else {
      process.stdout.write("\n");
    }
    this.pendingText = "";
    this.textOpen = false;
  }

  private writeLine(value: string): void {
    if (this.terminal) this.terminal.writeLine(value);
    else console.log(value);
  }

  private writeLines(lines: string[]): void {
    if (lines.length > 0) this.writeLine(lines.join("\n"));
  }

  private updateStatus(text: string): void {
    this.terminal?.setStatus(text);
  }
}

const printableEvents = new Set<TurnEvent["kind"]>([
  "turn_started",
  "context_built",
  "skill_context_built",
  "security_workflow_built",
  "decision_repair_requested",
  "decision_repair_completed",
  "agent_message",
  "plan_created",
  "tool_approval_requested",
  "tool_approval_resolved",
  "tool_started",
  "tool_completed",
  "tool_blocked",
  "file_change_approval_requested",
  "file_change_approval_resolved",
  "file_change_started",
  "file_change_completed",
  "file_change_blocked",
  "subagent_started",
  "subagent_launched",
  "subagent_progress",
  "subagent_tool_started",
  "subagent_tool_completed",
  "subagent_tool_blocked",
  "subagent_completed",
  "subagent_failed",
  "user_input_requested",
  "turn_completed",
  "turn_failed"
]);

export function printAegisEvent(event: TurnEvent): void {
  if (!printableEvents.has(event.kind)) return;
  if (event.kind === "agent_message") {
    printBox({
      title: `${brand("\u25cf")} ${bold("AegisProbe")}`,
      tone: "agent",
      lines: event.message.split(/\r?\n/)
    });
    return;
  }
  const { title, tone } = eventTitle(event.kind);
  printBox({
    title,
    tone,
    lines: [faint(event.message), ...eventDetails(event.payload)]
  });
}

export function formatToolStart(record: Pick<ToolRecord, "name" | "arguments">): string[] {
  const args = safeJson(record.arguments);
  if (record.name === "execute_shell") {
    const command = objectString(args, "command") || record.arguments || "(empty command)";
    return formatCommandLines(command);
  }
  const summary = compactToolArguments(args, record.arguments);
  return [
    `${faint("\u2022")} ${bold("Calling")} ${label(record.name)}${summary ? ` ${faint(summary)}` : ""}`
  ];
}

export function formatToolCompletion(record: ToolRecord, mode: ToolViewMode): string[] {
  const envelope = parseToolEnvelope(record.result);
  const failed = record.error || envelope?.status === "error" || envelope?.status === "blocked";
  const marker = failed ? danger("\u2514") : faint("\u2514");
  const duration = formatDuration(envelope?.durationMs ?? elapsedMs(record));
  const exit = envelope?.exitCode !== undefined ? `exit ${String(envelope.exitCode)}` : envelope?.status ?? "complete";
  const output = [envelope?.stdout, envelope?.stderr].filter(Boolean).join("\n");
  const lineCount = output ? output.replace(/\r/g, "").split("\n").length : 0;
  const size = output ? formatBytes(Buffer.byteLength(output, "utf8")) : "";
  const details = [exit, duration, lineCount ? `${lineCount} lines` : "", size].filter(Boolean).join(" \u00b7 ");
  const lines = [`  ${marker} ${failed ? danger(details) : faint(details)}`];

  if (failed || mode === "full") {
    const preview = summarizeOutput(output || record.result || "", mode === "full" ? 12 : 4);
    lines.push(...preview.map((line) => `    ${faint("\u2502")} ${line}`));
  }
  if (envelope?.artifacts?.length) {
    lines.push(`    ${faint("\u2514")} ${faint(envelope.artifacts.join(", "))}`);
  }
  return lines;
}

function formatCommandLines(command: string): string[] {
  const logicalLines = command.replace(/\r/g, "").split("\n");
  const first = logicalLines.shift() ?? "";
  return [
    `${faint("\u2022")} ${bold("Running")} ${highlightCommand(first)}`,
    ...logicalLines.map((line) => `  ${faint("\u2502")} ${highlightCommand(line)}`)
  ];
}

function highlightCommand(command: string): string {
  if (!useColor) return command;
  return command
    .split(/(\s+|[|;])/)
    .map((part) => {
      if (/^[|;]$/.test(part)) return faint(part);
      if (/^--?[\w-]+$/.test(part)) return blue(part);
      if (/^\$[\w:?.-]+$/.test(part)) return style(part, "magenta");
      if (/^(['"]).*\1$/.test(part)) return style(part, "green");
      return part;
    })
    .join("");
}

function compactToolArguments(parsed: unknown, raw: string): string {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return shorten(raw, 140);
  const entries = Object.entries(parsed as Record<string, unknown>).slice(0, 3);
  return entries.map(([key, value]) => `${key}=${shorten(renderValue(value), 54)}`).join(" ");
}

function parseToolEnvelope(value?: string): ToolEnvelopeView | undefined {
  const parsed = safeJson(value ?? "");
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return undefined;
  const data = parsed as Record<string, unknown>;
  if (data.version !== 1 || typeof data.tool !== "string") return undefined;
  return {
    status: typeof data.status === "string" ? data.status : undefined,
    durationMs: typeof data.durationMs === "number" ? data.durationMs : undefined,
    exitCode: typeof data.exitCode === "number" || data.exitCode === null ? data.exitCode : undefined,
    stdout: typeof data.stdout === "string" ? data.stdout : undefined,
    stderr: typeof data.stderr === "string" ? data.stderr : undefined,
    artifacts: Array.isArray(data.artifacts) ? data.artifacts.filter((item): item is string => typeof item === "string") : undefined,
    truncated: data.truncated && typeof data.truncated === "object"
      ? data.truncated as ToolEnvelopeView["truncated"]
      : undefined
  };
}

function prettyJson(value: string): string {
  const parsed = safeJson(value);
  return parsed === undefined ? value : JSON.stringify(parsed, null, 2);
}

function objectString(value: unknown, key: string): string | undefined {
  if (!value || typeof value !== "object" || Array.isArray(value)) return undefined;
  const item = (value as Record<string, unknown>)[key];
  return typeof item === "string" ? item : undefined;
}

function renderValue(value: unknown): string {
  return typeof value === "string" ? value : JSON.stringify(value);
}

function elapsedMs(record: ToolRecord): number | undefined {
  if (record.startedAt === undefined || record.endedAt === undefined) return undefined;
  return Math.max(0, record.endedAt - record.startedAt);
}

function formatDuration(value?: number): string {
  if (value === undefined) return "";
  if (value < 1_000) return `${value}ms`;
  return `${(value / 1_000).toFixed(value < 10_000 ? 1 : 0)}s`;
}

function formatBytes(value: number): string {
  if (value < 1_024) return `${value}B`;
  if (value < 1_048_576) return `${(value / 1_024).toFixed(1)}KB`;
  return `${(value / 1_048_576).toFixed(1)}MB`;
}

function eventTitle(kind: TurnEvent["kind"]): { title: string; tone: CardTone } {
  const pretty = kind.replaceAll("_", " ");
  if (kind.includes("failed") || kind.includes("blocked")) return { title: `${danger("x")} ${danger(pretty)}`, tone: "danger" };
  if (kind.includes("completed") || kind.includes("resolved")) return { title: `${ok("ok")} ${ok(pretty)}`, tone: "success" };
  if (kind.includes("approval") || kind.includes("user_input")) return { title: `${warn("?")} ${warn(pretty)}`, tone: "warning" };
  if (kind.includes("tool") || kind.includes("subagent")) return { title: `${label(">")} ${label(pretty)}`, tone: "tool" };
  return { title: `${brand("\u25cf")} ${brand(pretty)}`, tone: "agent" };
}

function eventDetails(payload: unknown): string[] {
  if (!payload || typeof payload !== "object") return [];
  const data = payload as Record<string, unknown>;
  const details: string[] = [];
  for (const key of ["phase", "toolId", "probe", "risk", "approved", "remembered", "exitCode", "status", "findingCount", "outputArtifact", "manifest"]) {
    if (data[key] !== undefined) details.push(`${label(key)} ${String(data[key])}`);
  }
  if (typeof data.command === "string") details.push(`${label("command")} ${shorten(data.command, 220)}`);
  if (typeof data.reason === "string") details.push(`${label("reason")} ${shorten(data.reason, 180)}`);
  if (typeof data.summary === "string") details.push(`${label("summary")} ${shorten(data.summary.split(/\r?\n/).slice(0, 4).join(" | "), 280)}`);
  if (typeof data.stepCount === "number") details.push(`${label("steps")} ${data.stepCount}`);
  return details;
}

function printBox(input: { title: string; lines: string[]; tone?: CardTone }): void {
  const width = terminalWidth();
  const inner = width - 4;
  const border = borderFor(input.tone ?? "info");
  const top = `${border.topLeft}${border.horizontal.repeat(width - 2)}${border.topRight}`;
  const bottom = `${border.bottomLeft}${border.horizontal.repeat(width - 2)}${border.bottomRight}`;
  console.log(top);
  console.log(`${border.vertical} ${padVisible(input.title, inner)} ${border.vertical}`);
  if (input.lines.length > 0) console.log(`${border.leftT}${border.horizontal.repeat(width - 2)}${border.rightT}`);
  for (const rawLine of input.lines) {
    for (const line of wrapAnsi(rawLine || "", inner)) {
      console.log(`${border.vertical} ${padVisible(line, inner)} ${border.vertical}`);
    }
  }
  console.log(bottom);
}

function borderFor(tone: CardTone) {
  const color = tone === "danger"
    ? danger
    : tone === "warning"
      ? warn
      : tone === "success"
        ? ok
        : tone === "tool"
          ? label
          : tone === "agent"
            ? brand
            : blue;
  return {
    horizontal: color("\u2500"),
    vertical: color("\u2502"),
    topLeft: color("\u256d"),
    topRight: color("\u256e"),
    bottomLeft: color("\u2570"),
    bottomRight: color("\u256f"),
    leftT: color("\u251c"),
    rightT: color("\u2524")
  };
}

function summarizeOutput(value: string, maxLines: number): string[] {
  const compact = value.replace(/\r/g, "").split("\n");
  const lines = compact.slice(0, maxLines).map((line) => line.length > 0 ? line : faint("(blank)"));
  if (compact.length > maxLines) lines.push(faint(`... ${compact.length - maxLines} more lines`));
  return lines.length > 0 ? lines : [faint("(no output)")];
}

function wrapAnsi(value: string, width: number): string[] {
  const plain = stripAnsi(value);
  if (visibleLength(value) <= width) return [value];
  if (plain.length === value.length) {
    const chunks: string[] = [];
    for (let index = 0; index < value.length; index += width) chunks.push(value.slice(index, index + width));
    return chunks;
  }
  return [shorten(value, width)];
}

function padVisible(value: string, width: number): string {
  const length = visibleLength(value);
  return length >= width ? shorten(value, width) : `${value}${" ".repeat(width - length)}`;
}

function visibleLength(value: string): number {
  return stripAnsi(value).length;
}

function stripAnsi(value: string): string {
  return value.replace(/\x1b\[[0-9;]*m/g, "");
}

function safeJson(value: string): unknown {
  try {
    return JSON.parse(value || "{}");
  } catch {
    return undefined;
  }
}

function shorten(value: string, maxLength: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  return visibleLength(compact) <= maxLength
    ? compact
    : `${compact.slice(0, Math.max(0, maxLength - 3))}...`;
}
