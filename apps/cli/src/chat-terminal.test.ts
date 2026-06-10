import { PassThrough } from "node:stream";
import { describe, expect, it, vi } from "vitest";
import { PersistentChatTerminal } from "./chat-terminal.js";

describe("PersistentChatTerminal", () => {
  it("accepts input while busy and returns it as the next queued message", async () => {
    const input = new PassThrough() as PassThrough & {
      isTTY: boolean;
      setRawMode: ReturnType<typeof vi.fn>;
    };
    input.isTTY = true;
    input.setRawMode = vi.fn();

    const output = new PassThrough() as PassThrough & {
      isTTY: boolean;
      columns: number;
      rows: number;
    };
    output.isTTY = true;
    output.columns = 80;
    output.rows = 24;
    let rendered = "";
    output.on("data", (chunk) => {
      rendered += chunk.toString();
    });

    const terminal = new PersistentChatTerminal({
      input: input as unknown as NodeJS.ReadStream,
      output: output as unknown as NodeJS.WriteStream
    });
    terminal.start();
    expect(rendered).toContain("\u001b[1;21r");
    expect(rendered).toContain("\u001b[48;5;236m");
    expect(rendered).not.toContain("+---");

    const first = terminal.readLine("task");
    input.emit("keypress", "h", { name: "h" });
    input.emit("keypress", "i", { name: "i" });
    input.emit("keypress", "\r", { name: "return" });
    await expect(first).resolves.toBe("hi");

    const activeTurn = new AbortController();
    terminal.setBusy(activeTurn);
    expect(rendered).toContain("\u001b[48;5;24m");
    for (const character of "follow up") {
      input.emit("keypress", character, { name: character === " " ? "space" : character });
    }
    input.emit("keypress", "\r", { name: "return" });
    expect(terminal.queuedCount).toBe(1);
    expect(rendered).toContain("enter/tab queue");
    expect(rendered).toContain("1 queued");

    input.emit("keypress", "\u001b", { name: "escape" });
    expect(activeTurn.signal.aborted).toBe(true);

    terminal.setBusy(undefined);
    await expect(terminal.readLine("aegis")).resolves.toBe("follow up");
    expect(terminal.queuedCount).toBe(0);

    output.rows = 30;
    output.emit("resize");
    expect(rendered).toContain("\u001b[1;27r");
    terminal.close();
    expect(rendered).toContain("\u001b[r");
  });
});
