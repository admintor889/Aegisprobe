import type { ConversationTurnEvent } from "@aegisprobe/core";
import type { TurnEvent } from "@aegisprobe/shared";

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

type CardTone = "info" | "success" | "warning" | "danger" | "tool" | "agent";

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
  const meta = [label(mode), input.sessionId ? faint(`session ${input.sessionId}`) : undefined, input.target ? faint(input.target) : undefined]
    .filter(Boolean)
    .join("  ");
  console.log();
  printBox({
    title,
    tone: "agent",
    lines: [
      meta,
      `${faint("cwd-aware chat")}  ${faint("tool cards")}  ${faint("streaming output")}  ${faint("approval gates")}`,
      `${label("/help")} ${faint("commands")}  ${label("/exit")} ${faint("quit")}  ${label("Esc")} ${faint("interrupt")}`
    ].filter(Boolean)
  });
}

export class CodexLikeTurnRenderer {
  private textOpen = false;
  private textStarted = false;
  private toolArgs = new Map<string, { name: string; args: string }>();
  private currentTool?: { id: string; name: string; startedAt: number };

  handle(event: ConversationTurnEvent): void {
    switch (event.kind) {
      case "text_start":
        this.startAssistantText();
        break;
      case "text_delta":
        this.writeAssistantDelta(event.content);
        break;
      case "text_end":
        this.endAssistantText();
        break;
      case "tool_call_start":
        this.endAssistantText();
        this.toolArgs.set(event.id, { name: event.name, args: "" });
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
        this.printToolRequest(event.id, event.name, event.arguments);
        break;
      case "tool_execution_start":
        this.endAssistantText();
        this.currentTool = { id: event.id, name: event.name, startedAt: Date.now() };
        printInlineStatus(`${label("running")} ${event.name}`);
        break;
      case "tool_execution_end":
        this.endAssistantText();
        this.printToolResult(event);
        this.currentTool = undefined;
        break;
      case "turn_complete":
        this.endAssistantText();
        printInlineStatus(`${ok("done")} ${faint(event.stopReason)}`);
        break;
      case "turn_aborted":
        this.endAssistantText();
        printBox({ title: danger("interrupted"), tone: "warning", lines: ["Turn was interrupted by the user."] });
        break;
      case "turn_error":
        this.endAssistantText();
        printBox({ title: danger("error"), tone: "danger", lines: [event.error] });
        break;
    }
  }

  finish(): void {
    this.endAssistantText();
  }

  private startAssistantText(): void {
    if (this.textOpen) return;
    this.textOpen = true;
    this.textStarted = true;
    process.stdout.write(`\n${brand("▌")} ${bold("AegisProbe")}\n`);
  }

  private writeAssistantDelta(content: string): void {
    if (!this.textOpen) this.startAssistantText();
    process.stdout.write(content);
  }

  private endAssistantText(): void {
    if (!this.textOpen) return;
    process.stdout.write("\n");
    this.textOpen = false;
  }

  private printToolRequest(id: string, name: string, args: string): void {
    const parsed = formatToolArgs(args);
    printBox({
      title: `${label("tool")} ${bold(name)}`,
      tone: "tool",
      lines: parsed.length > 0 ? parsed : [faint(`id ${id}`)]
    });
  }

  private printToolResult(event: Extract<ConversationTurnEvent, { kind: "tool_execution_end" }>): void {
    const elapsed = this.currentTool ? ` ${Date.now() - this.currentTool.startedAt}ms` : "";
    const title = event.error
      ? `${danger("failed")} ${bold(event.id)}${faint(elapsed)}`
      : `${ok("completed")} ${bold(event.id)}${faint(elapsed)}`;
    printBox({
      title,
      tone: event.error ? "danger" : "success",
      lines: summarizeOutput(event.result, 8)
    });
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
    printBox({ title: `${brand("▌")} ${bold("AegisProbe")}`, tone: "agent", lines: event.message.split(/\r?\n/) });
    return;
  }
  const { title, tone } = eventTitle(event.kind);
  const details = eventDetails(event.payload);
  printBox({
    title,
    tone,
    lines: [faint(event.message), ...details]
  });
}

function eventTitle(kind: TurnEvent["kind"]): { title: string; tone: CardTone } {
  const pretty = kind.replaceAll("_", " ");
  if (kind.includes("failed") || kind.includes("blocked")) return { title: `${danger("x")} ${danger(pretty)}`, tone: "danger" };
  if (kind.includes("completed") || kind.includes("resolved")) return { title: `${ok("✓")} ${ok(pretty)}`, tone: "success" };
  if (kind.includes("approval") || kind.includes("user_input")) return { title: `${warn("?")} ${warn(pretty)}`, tone: "warning" };
  if (kind.includes("tool") || kind.includes("subagent")) return { title: `${label(">")} ${label(pretty)}`, tone: "tool" };
  return { title: `${brand("▌")} ${brand(pretty)}`, tone: "agent" };
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
  const color = tone === "danger" ? danger : tone === "warning" ? warn : tone === "success" ? ok : tone === "tool" ? label : tone === "agent" ? brand : blue;
  return {
    horizontal: color("─"),
    vertical: color("│"),
    topLeft: color("╭"),
    topRight: color("╮"),
    bottomLeft: color("╰"),
    bottomRight: color("╯"),
    leftT: color("├"),
    rightT: color("┤")
  };
}

function printInlineStatus(text: string): void {
  console.log(`${faint("  ↳")} ${text}`);
}

function formatToolArgs(raw: string): string[] {
  const parsed = safeJson(raw);
  if (!parsed || typeof parsed !== "object") return raw.trim() ? summarizeOutput(raw, 6) : [];
  const lines: string[] = [];
  for (const [key, value] of Object.entries(parsed as Record<string, unknown>)) {
    const rendered = typeof value === "string" ? value : JSON.stringify(value);
    lines.push(`${label(key)} ${shorten(rendered ?? "", 260)}`);
  }
  return lines;
}

function summarizeOutput(value: string, maxLines: number): string[] {
  const compact = value.replace(/\r/g, "").split("\n");
  const lines = compact.slice(0, maxLines).map((line) => line.length > 0 ? line : faint("(blank)"));
  if (compact.length > maxLines) lines.push(faint(`… ${compact.length - maxLines} more lines`));
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
  try { return JSON.parse(value || "{}"); } catch { return undefined; }
}

function shorten(value: string, maxLength: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  return visibleLength(compact) <= maxLength ? compact : `${compact.slice(0, Math.max(0, maxLength - 3))}...`;
}
