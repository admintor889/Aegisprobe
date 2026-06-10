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

// ── Stateful Markdown → Terminal renderer ──
// Processes lines one at a time, tracking code-fence state so
// fenced code blocks get a dim background + indentation instead
// of being stripped. This mirrors how Codex renders code blocks
// in the terminal: colored background, indented content, optional
// language tag.

const CODE_BG = "\x1b[48;5;236m\x1b[38;5;250m";
const CODE_BORDER = "\x1b[48;5;238m\x1b[38;5;245m";
const RESET = "\x1b[0m";

function takeDisplayPrefix(value: string, width: number): string {
  let used = 0;
  let output = "";
  for (const character of value) {
    const characterWidth = terminalCharacterWidth(character);
    if (used + characterWidth > width) break;
    output += character;
    used += characterWidth;
  }
  return output;
}

function displayWidth(value: string): number {
  let width = 0;
  for (const character of value) width += terminalCharacterWidth(character);
  return width;
}

function terminalCharacterWidth(character: string): number {
  const codePoint = character.codePointAt(0) ?? 0;
  if (codePoint === 0 || codePoint < 32 || (codePoint >= 0x7f && codePoint < 0xa0)) return 0;
  if (
    (codePoint >= 0x300 && codePoint <= 0x36f)
    || (codePoint >= 0x1ab0 && codePoint <= 0x1aff)
    || (codePoint >= 0x1dc0 && codePoint <= 0x1dff)
    || (codePoint >= 0xfe20 && codePoint <= 0xfe2f)
  ) {
    return 0;
  }
  if (
    codePoint >= 0x1100
    && (
      codePoint <= 0x115f
      || codePoint === 0x2329
      || codePoint === 0x232a
      || (codePoint >= 0x2e80 && codePoint <= 0xa4cf && codePoint !== 0x303f)
      || (codePoint >= 0xac00 && codePoint <= 0xd7a3)
      || (codePoint >= 0xf900 && codePoint <= 0xfaff)
      || (codePoint >= 0xfe10 && codePoint <= 0xfe19)
      || (codePoint >= 0xfe30 && codePoint <= 0xfe6f)
      || (codePoint >= 0xff00 && codePoint <= 0xff60)
      || (codePoint >= 0xffe0 && codePoint <= 0xffe6)
      || (codePoint >= 0x1f300 && codePoint <= 0x1faff)
      || (codePoint >= 0x20000 && codePoint <= 0x3fffd)
    )
  ) {
    return 2;
  }
  return 1;
}

class MarkdownTerminalRenderer {
  private inCodeBlock = false;
  private codeLanguage = "";
  private codeLines: string[] = [];
  private readonly width: number;

  constructor(width: number) {
    this.width = width;
  }

  /** Reset state (call when output resets, e.g. new turn). */
  reset(): void {
    this.flushCodeBlock();
  }

  /**
   * Process one line of markdown text. Returns zero or more rendered
   * terminal lines. Code blocks are buffered and emitted as styled
   * blocks when the fence closes.
   */
  processLine(line: string): string[] {
    if (this.inCodeBlock) {
      if (/^```\s*$/.test(line.trim())) {
        return this.flushCodeBlock();
      }
      this.codeLines.push(line);
      return [];
    }

    const fenceMatch = line.match(/^```(\w+)?\s*$/);
    if (fenceMatch) {
      this.inCodeBlock = true;
      this.codeLanguage = fenceMatch[1] ?? "";
      this.codeLines = [];
      return [];
    }

    return [renderMarkdownLine(line)];
  }

  /** Flush any open code block at end of output. */
  flushCodeBlock(): string[] {
    if (!this.inCodeBlock) return [];
    this.inCodeBlock = false;
    const result = this.renderCodeBlock(this.codeLanguage, this.codeLines);
    this.codeLanguage = "";
    this.codeLines = [];
    return result;
  }

  private renderCodeBlock(language: string, lines: string[]): string[] {
    if (lines.length === 0) return [];
    const innerWidth = Math.max(20, this.width - 4);
    const highlighter = pickHighlighter(language);
    const output: string[] = [];
    // top border with language tag
    const langTag = language ? ` ${language} ` : "";
    const topLeft = `${CODE_BORDER} ${label(langTag)}${"─".repeat(Math.max(0, innerWidth - langTag.length - 2))}${RESET}`;
    output.push(topLeft);
    // code lines with background + syntax highlighting
    for (const codeLine of lines) {
      const highlighted = highlighter(codeLine);
      const clipped = takeDisplayPrefix(highlighted, innerWidth);
      const raw = codeLine; // for accurate width calc
      const rawClipped = takeDisplayPrefix(raw, innerWidth);
      const padding = Math.max(0, innerWidth - displayWidth(rawClipped) - 1);
      output.push(`${CODE_BG} ${clipped}${" ".repeat(padding)}${RESET}`);
    }
    // bottom border
    const bottom = `${CODE_BORDER}${"─".repeat(innerWidth + 1)}${RESET}`;
    output.push(bottom);
    return output;
  }
}

// ── Syntax highlighting ──

type Token = { text: string; color: (s: string) => string };
type Highlighter = (line: string) => string;

// Token colors
const KEYWORD  = (s: string) => style(s, "blue");
const STRING   = (s: string) => style(s, "green");
const COMMENT  = (s: string) => style(s, "gray");
const NUMBER   = (s: string) => style(s, "yellow");
const OPERATOR = (s: string) => style(s, "cyan");
const BUILTIN  = (s: string) => style(s, "magenta");
const TYPE     = (s: string) => style(s, "cyan");

/** Match a token at the start of a string. Returns [matched, text] or null. */
type TokenMatcher = (src: string) => [string, (s: string) => string] | null;

function tokenize(line: string, matchers: TokenMatcher[]): string {
  let result = "";
  let remaining = line;
  while (remaining.length > 0) {
    let matched = false;
    for (const m of matchers) {
      const hit = m(remaining);
      if (hit) {
        const [raw, color] = hit;
        result += color(raw);
        remaining = remaining.slice(raw.length);
        matched = true;
        break;
      }
    }
    if (!matched) {
      result += remaining[0]!;
      remaining = remaining.slice(1);
    }
  }
  return result;
}

// ── Per-language matcher sets ──

const shellMatchers: TokenMatcher[] = [
  // single-quoted string
  (s) => { const m = s.match(/^'[^']*'/); return m ? [m[0], STRING] : null; },
  // double-quoted string
  (s) => { const m = s.match(/^"[^"]*"/); return m ? [m[0], STRING] : null; },
  // comment
  (s) => { const m = s.match(/^#.*/); return m ? [m[0], COMMENT] : null; },
  // keyword
  (s) => { const m = s.match(/^(if|then|else|elif|fi|for|while|do|done|case|esac|in|function|return|local|export|unset|set|source|shift|break|continue|exit|trap|exec|eval)(?=\b|[^a-zA-Z0-9_])/); return m ? [m[0], KEYWORD] : null; },
  // flag/option
  (s) => { const m = s.match(/^--?[a-zA-Z][a-zA-Z0-9-]*/); return m ? [m[0], BUILTIN] : null; },
  // variable
  (s) => { const m = s.match(/^\$[a-zA-Z_][a-zA-Z0-9_]*|\$\{[^}]+\}/); return m ? [m[0], TYPE] : null; },
  // number
  (s) => { const m = s.match(/^\b\d+(?:\.\d+)?\b/); return m ? [m[0], NUMBER] : null; },
  // operator/pipe
  (s) => { const m = s.match(/^[|&<>;]{1,2}/); return m ? [m[0], OPERATOR] : null; },
];

const pythonMatchers: TokenMatcher[] = [
  // string (single-quoted)
  (s) => { const m = s.match(/^'''[^]*?'''|^"""[^]*?"""|^'[^']*'|^"[^"]*"/); return m ? [m[0], STRING] : null; },
  // comment
  (s) => { const m = s.match(/^#.*/); return m ? [m[0], COMMENT] : null; },
  // decorator
  (s) => { const m = s.match(/^@[a-zA-Z_][a-zA-Z0-9_.]*/); return m ? [m[0], BUILTIN] : null; },
  // keyword
  (s) => { const m = s.match(/^(def|class|return|if|elif|else|for|while|import|from|as|try|except|finally|with|yield|raise|assert|pass|break|continue|and|or|not|is|in|lambda|global|nonlocal|async|await)(?=\b|[^a-zA-Z0-9_])/); return m ? [m[0], KEYWORD] : null; },
  // builtin
  (s) => { const m = s.match(/^(True|False|None|self|cls|print|len|range|int|str|float|list|dict|set|tuple|type|open|enumerate|zip|map|filter|sorted|reversed|super|isinstance|hasattr|getattr|setattr|delattr|property|staticmethod|classmethod)(?=\b|[^a-zA-Z0-9_])/); return m ? [m[0], BUILTIN] : null; },
  // number
  (s) => { const m = s.match(/^\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/); return m ? [m[0], NUMBER] : null; },
  // function call
  (s) => { const m = s.match(/^[a-zA-Z_][a-zA-Z0-9_]*(?=\s*\()/); return m ? [m[0], TYPE] : null; },
];

const jsMatchers: TokenMatcher[] = [
  // template literal
  (s) => { const m = s.match(/^`[^`]*`/); return m ? [m[0], STRING] : null; },
  // string
  (s) => { const m = s.match(/^'[^']*'|^"[^"]*"/); return m ? [m[0], STRING] : null; },
  // JSX / XML
  (s) => { const m = s.match(/^<\/?[A-Za-z][A-Za-z0-9.-]*[^>]*\/?>/); return m ? [m[0], BUILTIN] : null; },
  // line comment
  (s) => { const m = s.match(/^\/\/.*/); return m ? [m[0], COMMENT] : null; },
  // keyword
  (s) => { const m = s.match(/^(function|const|let|var|return|if|else|for|while|do|switch|case|break|continue|try|catch|finally|throw|new|this|class|extends|import|export|from|default|async|await|yield|typeof|instanceof|in|of|delete|void|with|debugger)(?=\b|[^a-zA-Z0-9_$])/); return m ? [m[0], KEYWORD] : null; },
  // literal
  (s) => { const m = s.match(/^(true|false|null|undefined|NaN|Infinity)(?=\b|[^a-zA-Z0-9_$])/); return m ? [m[0], BUILTIN] : null; },
  // arrow
  (s) => { const m = s.match(/^=>/); return m ? [m[0], OPERATOR] : null; },
  // number
  (s) => { const m = s.match(/^\b\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/); return m ? [m[0], NUMBER] : null; },
  // property access / method call
  (s) => { const m = s.match(/^(?:console|Math|JSON|Object|Array|String|Number|Boolean|Promise|Error|Map|Set|Date|RegExp|parseInt|parseFloat|isNaN|isFinite|encodeURIComponent|decodeURIComponent)(?=\b|[^a-zA-Z0-9_$])/); return m ? [m[0], BUILTIN] : null; },
  // identifier.fn(
  (s) => { const m = s.match(/^[a-zA-Z_$][a-zA-Z0-9_$]*(?=\s*\()/); return m ? [m[0], TYPE] : null; },
];

const xmlMatchers: TokenMatcher[] = [
  // tag
  (s) => { const m = s.match(/^<\/?[A-Za-z][A-Za-z0-9:_.-]*(?:\s+[A-Za-z][A-Za-z0-9:_.-]*(?:\s*=\s*(?:"[^"]*"|'[^']*'))?\s*)*\/?>/); return m ? [m[0], BUILTIN] : null; },
  // attribute value
  (s) => { const m = s.match(/^"[^"]*"/); return m ? [m[0], STRING] : null; },
  // comment
  (s) => { const m = s.match(/^<!--[^]*?-->/); return m ? [m[0], COMMENT] : null; },
  // text content
  (s) => { const m = s.match(/^[^<]+/); return m ? [m[0], faint] : null; },
];

const jsonMatchers: TokenMatcher[] = [
  // string
  (s) => { const m = s.match(/^"(?:[^"\\]|\\.)*"/); return m ? [m[0], STRING] : null; },
  // number
  (s) => { const m = s.match(/^-?\d+(?:\.\d+)?(?:[eE][+-]?\d+)?\b/); return m ? [m[0], NUMBER] : null; },
  // keyword
  (s) => { const m = s.match(/^(true|false|null)(?=\b|[^a-zA-Z0-9_])/); return m ? [m[0], KEYWORD] : null; },
];

const sqlMatchers: TokenMatcher[] = [
  // string
  (s) => { const m = s.match(/^'[^']*'/); return m ? [m[0], STRING] : null; },
  // comment
  (s) => { const m = s.match(/^--.*/); return m ? [m[0], COMMENT] : null; },
  // keyword
  (s) => { const m = s.match(/^(SELECT|FROM|WHERE|AND|OR|NOT|IN|LIKE|BETWEEN|IS|NULL|INSERT|INTO|VALUES|UPDATE|SET|DELETE|CREATE|TABLE|DROP|ALTER|ADD|INDEX|PRIMARY|KEY|FOREIGN|REFERENCES|JOIN|LEFT|RIGHT|INNER|OUTER|ON|AS|ORDER|BY|GROUP|HAVING|LIMIT|OFFSET|UNION|ALL|DISTINCT|COUNT|SUM|AVG|MIN|MAX|CASE|WHEN|THEN|ELSE|END|EXISTS|CAST|COALESCE)(?=\b|[^a-zA-Z0-9_])/i); return m ? [m[0], KEYWORD] : null; },
  // number
  (s) => { const m = s.match(/^\b\d+(?:\.\d+)?\b/); return m ? [m[0], NUMBER] : null; },
];

const yamlMatchers: TokenMatcher[] = [
  // comment
  (s) => { const m = s.match(/^#.*/); return m ? [m[0], COMMENT] : null; },
  // key:
  (s) => { const m = s.match(/^[a-zA-Z_][a-zA-Z0-9_]*(?=\s*:)/); return m ? [m[0], KEYWORD] : null; },
  // string value
  (s) => { const m = s.match(/^"[^"]*"|^'[^']*'/); return m ? [m[0], STRING] : null; },
  // number
  (s) => { const m = s.match(/^\b\d+(?:\.\d+)?\b/); return m ? [m[0], NUMBER] : null; },
  // boolean / null
  (s) => { const m = s.match(/^(true|false|null|yes|no|on|off)(?=\b|[^a-zA-Z0-9_])/i); return m ? [m[0], BUILTIN] : null; },
];

const defaultMatchers: TokenMatcher[] = [
  (s) => { const m = s.match(/^'[^']*'|^"[^"]*"/); return m ? [m[0], STRING] : null; },
  (s) => { const m = s.match(/^(#|\/\/)\s?.*/); return m ? [m[0], COMMENT] : null; },
  (s) => { const m = s.match(/^\b\d+(?:\.\d+)?\b/); return m ? [m[0], NUMBER] : null; },
];

function pickHighlighter(language: string): Highlighter {
  const lang = language.toLowerCase();
  let matchers: TokenMatcher[];

  switch (lang) {
    case "sh": case "bash": case "shell": case "zsh": case "powershell": case "pwsh": case "ps1":
      matchers = shellMatchers; break;
    case "py": case "python": case "python3":
      matchers = pythonMatchers; break;
    case "js": case "javascript": case "ts": case "typescript": case "mjs": case "cjs":
      matchers = jsMatchers; break;
    case "xml": case "html": case "htm": case "svg":
      matchers = xmlMatchers; break;
    case "json": case "jsonc":
      matchers = jsonMatchers; break;
    case "sql": case "mysql": case "psql": case "sqlite":
      matchers = sqlMatchers; break;
    case "yaml": case "yml":
      matchers = yamlMatchers; break;
    default:
      matchers = defaultMatchers;
  }

  return (line: string) => tokenize(line, matchers);
}

/**
 * Render a single non-code-fence markdown line to terminal text.
 */
function renderMarkdownLine(line: string): string {
  return line
    // Headers: # Title → Title (bold)
    .replace(/^(#{1,6})\s+(.+)$/, (_, _hashes, h) => bold(h))
    // Bold: **text** → text (bold)
    .replace(/\*\*(.+?)\*\*/g, (_, b) => bold(b))
    // Italic: *text* → text
    .replace(/(?<!\*)\*([^*\n]+?)\*(?!\*)/g, "$1")
    // Inline code: `text` → dim text
    .replace(/`([^`\n]+?)`/g, (_, c) => faint(c))
    // Links: [text](url) → text
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, "$1")
    // Bullet list markers: - or * at line start → —
    .replace(/^[*-]\s+(?!\s)/gm, "\u2014 ")
    // Blockquote: > text → │ text
    .replace(/^>\s?(.+)$/, "\u2502 $1")
    // Horizontal rules: --- or *** → empty line
    .replace(/^[-*_]{3,}\s*$/, "");
}

// Legacy alias for compatibility
function stripMarkdownForTerminal(text: string): string {
  return renderMarkdownLine(text);
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
  private readonly md: MarkdownTerminalRenderer;

  constructor(
    private readonly terminal?: PersistentChatTerminal,
    private readonly tools = new ToolTranscriptStore()
  ) {
    this.md = new MarkdownTerminalRenderer(terminalWidth());
  }

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
    this.md.reset();
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
    // Split on newlines and feed complete lines through the markdown renderer.
    // The renderer is stateful — it buffers code-fence blocks and emits them
    // as styled terminal blocks when the fence closes.
    while (true) {
      const nl = this.pendingText.indexOf("\n");
      if (nl < 0) break;
      const completeLine = this.pendingText.slice(0, nl);
      this.pendingText = this.pendingText.slice(nl + 1);
      for (const rendered of this.md.processLine(completeLine)) {
        this.terminal.writeLine(rendered);
      }
    }
    // Partial line still in progress — show as live text only.
    // Do NOT feed it through processLine as a complete line; that would
    // flush every token-delta as its own output line.
    this.terminal.setLiveText(renderMarkdownLine(this.pendingText));
  }

  private endAssistantText(): void {
    if (!this.textOpen) return;
    // Flush any remaining buffered code block.
    for (const rendered of this.md.processLine(this.pendingText)) {
      if (this.terminal) this.terminal.writeLine(rendered);
    }
    for (const rendered of this.md.flushCodeBlock()) {
      if (this.terminal) this.terminal.writeLine(rendered);
    }
    this.pendingText = "";
    if (this.terminal) {
      this.terminal.setLiveText("");
      this.terminal.commitLiveText();
    } else {
      process.stdout.write("\n");
    }
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
