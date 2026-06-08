import type { TurnEvent } from "@aegisprobe/shared";

const useColor = Boolean(process.stdout.isTTY && !process.env.NO_COLOR);

const ansi = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  red: "\x1b[31m",
  magenta: "\x1b[35m"
};

function style(value: string, code: keyof typeof ansi): string {
  return useColor ? `${ansi[code]}${value}${ansi.reset}` : value;
}

function faint(value: string): string {
  return style(value, "dim");
}

function label(value: string): string {
  return style(value, "cyan");
}

function ok(value: string): string {
  return style(value, "green");
}

function danger(value: string): string {
  return style(value, "red");
}

function brand(value: string): string {
  return style(value, "magenta");
}

export function aegisPrompt(): string {
  return `\n${label("aegis")}${faint(" probe")}> `;
}

export function printChatBanner(input: {
  sessionId?: string;
  target?: string;
  mode?: "chat" | "pentest" | "resume";
} = {}): void {
  const mode = input.mode ?? "chat";
  const parts = [
    `${brand("AegisProbe")}`,
    faint(mode),
    input.sessionId ? faint(`session ${input.sessionId}`) : undefined,
    input.target ? faint(input.target) : undefined
  ].filter(Boolean);
  console.log(parts.join("  "));
  console.log(faint("type /help for commands, /exit to quit, Escape to interrupt a running response"));
}

const printableEvents = new Set<TurnEvent["kind"]>([
  "turn_started",
  "context_built",
  "skill_context_built",
  "security_workflow_built",
  "decision_repair_requested",
  "decision_repair_completed",
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
  if (!printableEvents.has(event.kind)) {
    return;
  }
  const { marker, title } = eventTitle(event.kind);
  const details = eventDetails(event.payload);
  console.log(`\n${marker} ${title} ${faint(event.message)}`);
  for (const detail of details) {
    console.log(`  ${faint("-")} ${detail}`);
  }
}

function eventTitle(kind: TurnEvent["kind"]): { marker: string; title: string } {
  if (kind.includes("failed") || kind.includes("blocked")) {
    return { marker: danger("x"), title: danger(kind) };
  }
  if (kind.includes("completed") || kind.includes("resolved")) {
    return { marker: ok("✓"), title: ok(kind) };
  }
  if (kind.includes("approval") || kind.includes("user_input")) {
    return { marker: label("?"), title: label(kind) };
  }
  if (kind.includes("tool") || kind.includes("subagent")) {
    return { marker: label(">"), title: label(kind) };
  }
  return { marker: brand("*"), title: brand(kind) };
}

function eventDetails(payload: unknown): string[] {
  if (!payload || typeof payload !== "object") {
    return [];
  }
  const data = payload as Record<string, unknown>;
  const details: string[] = [];
  for (const key of ["phase", "toolId", "probe", "risk", "approved", "remembered", "exitCode", "status", "findingCount", "outputArtifact", "manifest"]) {
    if (data[key] !== undefined) {
      details.push(`${label(key)}=${String(data[key])}`);
    }
  }
  if (typeof data.command === "string") {
    details.push(`${label("command")}=${shorten(data.command, 220)}`);
  }
  if (typeof data.reason === "string") {
    details.push(`${label("reason")}=${shorten(data.reason, 180)}`);
  }
  if (typeof data.summary === "string") {
    details.push(`${label("summary")}=${shorten(data.summary.split(/\r?\n/).slice(0, 4).join(" | "), 280)}`);
  }
  if (typeof data.stepCount === "number") {
    details.push(`${label("steps")}=${data.stepCount}`);
  }
  return details;
}

function shorten(value: string, maxLength: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  return compact.length <= maxLength ? compact : `${compact.slice(0, maxLength - 3)}...`;
}
