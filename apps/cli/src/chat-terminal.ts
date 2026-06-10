import { emitKeypressEvents } from "node:readline";
import { stdin as defaultInput, stdout as defaultOutput } from "node:process";

type Keypress = {
  name?: string;
  sequence?: string;
  ctrl?: boolean;
  meta?: boolean;
  shift?: boolean;
};

type PendingRead = {
  prompt: string;
  resolve: (value: string) => void;
};

type SavedComposer = {
  draft: string;
  cursor: number;
  prompt: string;
};

export type PersistentChatTerminalOptions = {
  input?: NodeJS.ReadStream;
  output?: NodeJS.WriteStream;
  fallbackReadLine?: (prompt: string) => Promise<string>;
};

const PANE_HEIGHT = 3;
const ANSI_RESET = "\x1b[0m";
const ANSI_HIDE_CURSOR = "\x1b[?25l";
const ANSI_SHOW_CURSOR = "\x1b[?25h";
const ANSI_CLEAR_LINE = "\x1b[2K";

export class PersistentChatTerminal {
  private readonly input: NodeJS.ReadStream;
  private readonly output: NodeJS.WriteStream;
  private readonly fallbackReadLine?: (prompt: string) => Promise<string>;
  private readonly tty: boolean;
  private readonly useColor: boolean;
  private readonly queuedMessages: string[] = [];
  private readonly history: string[] = [];
  private readonly keypressHandler: (value: string, key: Keypress) => void;
  private readonly resizeHandler: () => void;
  private pendingRead?: PendingRead;
  private modalRead?: PendingRead;
  private savedComposer?: SavedComposer;
  private busyController?: AbortController;
  private draft = "";
  private cursor = 0;
  private prompt = "aegis";
  private liveText = "";
  private historyIndex = -1;
  private viewportRows = 0;
  private started = false;
  private closed = false;
  private statusText = "";

  constructor(options: PersistentChatTerminalOptions = {}) {
    this.input = options.input ?? defaultInput;
    this.output = options.output ?? defaultOutput;
    this.fallbackReadLine = options.fallbackReadLine;
    this.tty = Boolean(this.input.isTTY && this.output.isTTY);
    this.useColor = Boolean(this.tty && !process.env.NO_COLOR);
    this.keypressHandler = (value, key) => this.handleKeypress(value, key);
    this.resizeHandler = () => this.setupViewport();
  }

  get isInteractive(): boolean {
    return this.tty;
  }

  get queuedCount(): number {
    return this.queuedMessages.length;
  }

  start(): void {
    if (!this.tty || this.started || this.closed) return;
    emitKeypressEvents(this.input);
    this.input.setRawMode?.(true);
    this.input.resume();
    this.input.on("keypress", this.keypressHandler);
    this.output.on("resize", this.resizeHandler);
    this.output.write(ANSI_HIDE_CURSOR);
    this.started = true;
    this.setupViewport();
  }

  close(): void {
    if (this.closed) return;
    this.closed = true;
    if (this.tty) {
      this.clearLiveLine();
      this.clearPane();
      this.output.write(`${ANSI_RESET}\x1b[r${cursorTo(this.rows, 1)}${ANSI_SHOW_CURSOR}`);
      this.input.off("keypress", this.keypressHandler);
      this.output.off("resize", this.resizeHandler);
      this.input.setRawMode?.(false);
    }
    this.pendingRead?.resolve("");
    this.modalRead?.resolve("");
    this.pendingRead = undefined;
    this.modalRead = undefined;
  }

  async readLine(prompt = "aegis"): Promise<string> {
    if (this.queuedMessages.length > 0) {
      return this.queuedMessages.shift() ?? "";
    }
    if (!this.tty) {
      return this.fallbackReadLine ? this.fallbackReadLine(`${prompt}> `) : "";
    }
    this.start();
    this.prompt = prompt;
    this.busyController = undefined;
    return new Promise<string>((resolve) => {
      this.pendingRead = { prompt, resolve };
      this.redraw();
    });
  }

  async requestLine(message: string, prompt = "answer"): Promise<string> {
    if (!this.tty) {
      return this.fallbackReadLine ? this.fallbackReadLine(message) : "";
    }
    this.start();
    this.writeLine(message.trimEnd());
    this.savedComposer = {
      draft: this.draft,
      cursor: this.cursor,
      prompt: this.prompt
    };
    this.draft = "";
    this.cursor = 0;
    this.prompt = prompt;
    return new Promise<string>((resolve) => {
      this.modalRead = { prompt, resolve };
      this.redraw();
    });
  }

  setBusy(controller?: AbortController): void {
    this.busyController = controller;
    if (!controller) this.statusText = "";
    if (this.tty) {
      this.start();
      this.redraw();
    }
  }

  setStatus(text: string): void {
    this.statusText = text;
    if (this.tty && this.started && !this.closed) {
      this.drawPane();
    }
  }

  writeLine(value = ""): void {
    if (!this.tty) {
      this.output.write(`${value}\n`);
      return;
    }
    this.start();
    this.clearLiveLine();
    const lines = value.replace(/\r/g, "").replace(/\n+$/g, "").split("\n");
    for (const line of lines) {
      this.output.write(`${cursorTo(this.contentBottom, 1)}${ANSI_CLEAR_LINE}${line}\n`);
    }
    this.restoreOutputCursor();
    this.drawPane();
  }

  /** Write a user message block to the scrollback with background fill.
   *  Uses three lines — padding above, the message, padding below —
   *  all with the idle pane background, creating a bubble-wrapped look. */
  writeUserLine(value = ""): void {
    if (!this.tty) {
      this.output.write(`${value}\n`);
      return;
    }
    this.start();
    this.clearLiveLine();
    const background = this.useColor ? "\x1b[48;5;236m\x1b[38;5;255m" : "";
    const reset = this.useColor ? ANSI_RESET : "";
    const fill = `${background}${" ".repeat(this.columns)}${reset}`;
    // top padding
    this.output.write(`${cursorTo(this.contentBottom, 1)}${ANSI_CLEAR_LINE}${fill}\n`);
    // message line
    const padded = `${background}${padRight(value, this.columns)}${reset}`;
    this.output.write(`${cursorTo(this.contentBottom, 1)}${ANSI_CLEAR_LINE}${padded}\n`);
    // bottom padding
    this.output.write(`${cursorTo(this.contentBottom, 1)}${ANSI_CLEAR_LINE}${fill}\n`);
    this.restoreOutputCursor();
    this.drawPane();
  }

  writeBlock(value: string): void {
    if (!value) return;
    this.writeLine(value);
  }

  setLiveText(value: string): void {
    this.liveText = value;
    if (!this.tty) return;
    this.start();
    this.drawLiveLine();
    this.drawPane();
  }

  commitLiveText(): void {
    if (!this.liveText) return;
    const value = this.liveText;
    this.clearLiveLine();
    this.liveText = "";
    this.writeLine(value);
  }

  clearLiveText(): void {
    if (!this.liveText) return;
    if (this.tty) {
      this.clearLiveLine();
    }
    this.liveText = "";
    if (this.tty) this.drawPane();
  }

  private get rows(): number {
    return Math.max(PANE_HEIGHT + 2, this.output.rows || 24);
  }

  private get columns(): number {
    return Math.max(36, this.output.columns || 80);
  }

  private get contentBottom(): number {
    return Math.max(1, this.rows - PANE_HEIGHT);
  }

  private setupViewport(): void {
    if (!this.tty || !this.started || this.closed) return;
    this.output.write(`${ANSI_RESET}\x1b[r`);
    if (this.viewportRows > 0 && this.viewportRows !== this.rows) {
      const previousBottom = Math.max(1, this.viewportRows - PANE_HEIGHT);
      for (let index = 0; index < PANE_HEIGHT; index += 1) {
        const row = previousBottom + index + 1;
        if (row <= this.rows) {
          this.output.write(`${cursorTo(row, 1)}${ANSI_CLEAR_LINE}`);
        }
      }
    }
    this.viewportRows = this.rows;
    this.output.write(`${ANSI_RESET}\x1b[1;${this.contentBottom}r`);
    this.drawLiveLine();
    this.drawPane();
    this.restoreOutputCursor();
  }

  private handleKeypress(value: string, key: Keypress): void {
    if (this.closed) return;
    const name = key.name ?? "";

    if (key.ctrl && name === "c") {
      if (this.busyController && !this.busyController.signal.aborted && !this.modalRead) {
        this.busyController.abort();
        this.writeLine("^C Interrupted");
        return;
      }
      if (!this.draft) {
        this.resolveActiveRead("/exit");
        return;
      }
      this.draft = "";
      this.cursor = 0;
      this.redraw();
      return;
    }

    if (name === "escape") {
      if (this.busyController && !this.busyController.signal.aborted && !this.modalRead) {
        this.busyController.abort();
        this.writeLine("Interrupted");
      } else if (this.draft) {
        this.draft = "";
        this.cursor = 0;
        this.redraw();
      }
      return;
    }

    if (name === "return" || name === "enter" || (name === "tab" && this.busyController && !this.modalRead)) {
      this.submitDraft();
      return;
    }

    if (name === "backspace") {
      if (this.cursor > 0) {
        this.draft = `${this.draft.slice(0, this.cursor - 1)}${this.draft.slice(this.cursor)}`;
        this.cursor -= 1;
        this.redraw();
      }
      return;
    }

    if (name === "delete") {
      if (this.cursor < this.draft.length) {
        this.draft = `${this.draft.slice(0, this.cursor)}${this.draft.slice(this.cursor + 1)}`;
        this.redraw();
      }
      return;
    }

    if (name === "left") {
      this.cursor = Math.max(0, this.cursor - 1);
      this.redraw();
      return;
    }
    if (name === "right") {
      this.cursor = Math.min(this.draft.length, this.cursor + 1);
      this.redraw();
      return;
    }
    if (name === "home") {
      this.cursor = 0;
      this.redraw();
      return;
    }
    if (name === "end") {
      this.cursor = this.draft.length;
      this.redraw();
      return;
    }
    if (name === "up" && !this.modalRead) {
      this.recallHistory(1);
      return;
    }
    if (name === "down" && !this.modalRead) {
      this.recallHistory(-1);
      return;
    }

    if (!key.ctrl && !key.meta && value && value >= " ") {
      this.draft = `${this.draft.slice(0, this.cursor)}${value}${this.draft.slice(this.cursor)}`;
      this.cursor += value.length;
      this.redraw();
    }
  }

  private submitDraft(): void {
    const value = this.draft.trim();
    if (!value) return;
    this.history.push(value);
    this.historyIndex = -1;
    this.draft = "";
    this.cursor = 0;

    if (this.modalRead) {
      const modal = this.modalRead;
      this.modalRead = undefined;
      this.restoreSavedComposer();
      modal.resolve(value);
      this.redraw();
      return;
    }

    if (this.busyController) {
      this.queuedMessages.push(value);
      this.writeLine(`Queued message ${this.queuedMessages.length}: ${shorten(value, 96)}`);
      return;
    }

    this.resolveActiveRead(value);
  }

  private resolveActiveRead(value: string): void {
    const pending = this.pendingRead;
    if (!pending) return;
    this.pendingRead = undefined;
    pending.resolve(value);
    this.redraw();
  }

  private restoreSavedComposer(): void {
    if (!this.savedComposer) return;
    this.draft = this.savedComposer.draft;
    this.cursor = this.savedComposer.cursor;
    this.prompt = this.savedComposer.prompt;
    this.savedComposer = undefined;
  }

  private recallHistory(direction: 1 | -1): void {
    if (this.history.length === 0) return;
    if (direction === 1) {
      this.historyIndex = Math.min(this.history.length - 1, this.historyIndex + 1);
    } else {
      this.historyIndex = Math.max(-1, this.historyIndex - 1);
    }
    this.draft = this.historyIndex < 0
      ? ""
      : this.history[this.history.length - 1 - this.historyIndex] ?? "";
    this.cursor = this.draft.length;
    this.redraw();
  }

  private redraw(): void {
    if (!this.tty || this.closed) return;
    this.drawPane();
    this.restoreOutputCursor();
  }

  private drawPane(): void {
    if (!this.tty || this.closed) return;
    const lines = this.composerLines(this.columns);
    const background = this.modalRead
      ? "\x1b[48;5;58m\x1b[38;5;230m"
      : this.busyController
        ? "\x1b[48;5;24m\x1b[38;5;255m"
        : "\x1b[48;5;236m\x1b[38;5;255m";
    for (let index = 0; index < PANE_HEIGHT; index += 1) {
      const row = this.contentBottom + index + 1;
      const text = lines[index] ?? "";
      const rendered = this.useColor
        ? `${background}${padRight(text, this.columns)}${ANSI_RESET}`
        : padRight(text, this.columns);
      this.output.write(`${cursorTo(row, 1)}${ANSI_CLEAR_LINE}${rendered}`);
    }
  }

  private clearPane(): void {
    if (!this.tty) return;
    for (let index = 0; index < PANE_HEIGHT; index += 1) {
      this.output.write(`${cursorTo(this.contentBottom + index + 1, 1)}${ANSI_RESET}${ANSI_CLEAR_LINE}`);
    }
  }

  private drawLiveLine(): void {
    if (!this.tty) return;
    this.output.write(`${cursorTo(this.contentBottom, 1)}${ANSI_CLEAR_LINE}`);
    if (this.liveText) {
      const currentLine = this.liveText.replace(/\r/g, "").split("\n").at(-1) ?? "";
      this.output.write(tailToWidth(currentLine, this.columns));
    }
    this.restoreOutputCursor();
  }

  private clearLiveLine(): void {
    if (!this.tty || !this.liveText) return;
    this.output.write(`${cursorTo(this.contentBottom, 1)}${ANSI_CLEAR_LINE}`);
  }

  private restoreOutputCursor(): void {
    if (!this.tty) return;
    this.output.write(cursorTo(this.contentBottom, 1));
  }

  private composerLines(width: number): string[] {
    const prefix = this.modalRead ? `${this.prompt}> ` : "> ";
    const cursorMarker = "|";
    const before = this.draft.slice(0, this.cursor);
    const after = this.draft.slice(this.cursor);
    const available = Math.max(4, width - prefix.length - cursorMarker.length - 4);
    const visibleDraft = tailToWidth(`${before}${cursorMarker}${after}`, available);
    const state = this.statusText
      ? this.statusText
      : this.modalRead
        ? " enter submit approval"
        : this.busyController
          ? ` enter/tab queue  esc interrupt${this.queuedMessages.length ? `  ${this.queuedMessages.length} queued` : ""}`
          : `${this.queuedMessages.length ? ` ${this.queuedMessages.length} queued  ` : " "}enter send  esc clear`;
    return [
      "",
      ` ${prefix}${visibleDraft}`,
      shorten(state, width - 1)
    ];
  }
}

function cursorTo(row: number, column: number): string {
  return `\x1b[${row};${column}H`;
}

function tailToWidth(value: string, width: number): string {
  if (displayWidth(value) <= width) return value;
  const characters = Array.from(value);
  const output: string[] = [];
  let used = 1;
  for (let index = characters.length - 1; index >= 0; index -= 1) {
    const character = characters[index]!;
    const characterWidth = terminalCharacterWidth(character);
    if (used + characterWidth > width) break;
    output.unshift(character);
    used += characterWidth;
  }
  return `<${output.join("")}`;
}

function padRight(value: string, width: number): string {
  const clipped = takeDisplayPrefix(value, width);
  return `${clipped}${" ".repeat(Math.max(0, width - displayWidth(clipped)))}`;
}

function shorten(value: string, width: number): string {
  const compact = value.replace(/\s+/g, " ").trim();
  return displayWidth(compact) <= width
    ? compact
    : `${takeDisplayPrefix(compact, Math.max(0, width - 3))}...`;
}

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
