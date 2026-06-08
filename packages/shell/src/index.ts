import { spawn, spawnSync } from "node:child_process";
import { summarizeOutput } from "@aegisprobe/shared";
import iconv from "iconv-lite";

export type ShellResult = {
  exitCode: number | null;
  stdout: string;
  stderr: string;
  summary: string;
};

let _forcedShell: "auto" | "powershell" | "wsl" = "auto";

export function setShellMode(mode: "auto" | "powershell" | "wsl"): void {
  _forcedShell = mode;
}

export function isWindowsShell(): boolean {
  return process.platform === "win32" && !process.env.WSL_DISTRO_NAME && _forcedShell !== "wsl";
}

export function shellCommand(): { binary: string; args: string[]; syntax: string } {
  // Explicit override via env var (like Claude Code's CLAUDE_CODE_SHELL)
  const envShell = process.env.AEGISPROBE_SHELL;
  if (envShell === "powershell" || envShell === "pwsh") {
    return { binary: "powershell.exe", args: ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"], syntax: "PowerShell" };
  }
  if (envShell === "bash" || envShell === "wsl") {
    return { binary: "/bin/bash", args: ["-c"], syntax: "bash" };
  }
  // Forced WSL mode: run commands inside WSL from Windows
  if (_forcedShell === "wsl" && process.platform === "win32" && !process.env.WSL_DISTRO_NAME) {
    return { binary: "wsl", args: ["-e", "bash", "-c"], syntax: "bash" };
  }
  // On Windows native (not inside WSL), use PowerShell
  if (process.platform === "win32" && !process.env.WSL_DISTRO_NAME) {
    return { binary: "powershell.exe", args: ["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"], syntax: "PowerShell" };
  }
  // Linux/macOS — use bash
  return { binary: "/bin/bash", args: ["-c"], syntax: "bash" };
}

export async function runShell(command: string, cwd = process.cwd(), timeoutMs = 600_000): Promise<ShellResult> {
  const shell = shellCommand();
  return new Promise((resolve) => {
    let settled = false;
    let timedOut = false;
    const child = spawn(shell.binary, [...shell.args, command], {
      cwd,
      windowsHide: process.platform === "win32",
      stdio: ["ignore", "pipe", "pipe"]
    });
    const timer = setTimeout(() => {
      timedOut = true;
      killProcessTree(child.pid);
    }, timeoutMs);

    const stdoutChunks: Buffer[] = [];
    const stderrChunks: Buffer[] = [];
    child.stdout.on("data", (chunk: Buffer) => {
      stdoutChunks.push(chunk);
    });
    child.stderr.on("data", (chunk: Buffer) => {
      stderrChunks.push(chunk);
    });
    child.on("close", (exitCode) => {
      if (settled) {
        return;
      }
      settled = true;
      clearTimeout(timer);
      const stdout = decodeProcessOutput(Buffer.concat(stdoutChunks));
      const stderr = [
        decodeProcessOutput(Buffer.concat(stderrChunks)),
        timedOut ? `Command timed out after ${timeoutMs}ms.` : ""
      ].filter(Boolean).join("\n");
      resolve({
        exitCode: timedOut ? null : exitCode,
        stdout,
        stderr,
        summary: summarizeOutput([stdout, stderr].filter(Boolean).join("\n"))
      });
    });
  });
}

export async function runPowerShell(command: string, cwd = process.cwd(), timeoutMs = 120_000): Promise<ShellResult> {
  return runShell(command, cwd, timeoutMs);
}

function killProcessTree(pid: number | undefined): void {
  if (!pid) {
    return;
  }
  if (process.platform === "win32") {
    spawnSync("taskkill.exe", ["/PID", String(pid), "/T", "/F"], {
      windowsHide: true,
      stdio: "ignore"
    });
    return;
  }
  try {
    process.kill(pid, "SIGTERM");
  } catch {
    // The process may already have exited.
  }
}

function decodeProcessOutput(buffer: Buffer): string {
  const utf8 = buffer.toString("utf8");
  const replacementCount = (utf8.match(/\uFFFD/g) ?? []).length;
  if (replacementCount > 0 || (utf8.includes("?") && /[\x80-\xFF]/.test(buffer.toString("binary")))) {
    return iconv.decode(buffer, "gb18030");
  }
  return utf8;
}

// ── Reverse Shell Manager ──

export type ShellSession = {
  id: string;
  port: number;
  status: "listening" | "connected" | "closed";
  startedAt: string;
  output: string;
  process?: ReturnType<typeof spawn>;
};

const shellSessions = new Map<string, ShellSession>();

export function getShellSessions(): ShellSession[] {
  return [...shellSessions.values()];
}

export function getShellSession(id: string): ShellSession | undefined {
  return shellSessions.get(id);
}

export function startShellListener(port: number, timeoutMs = 600_000): ShellSession {
  const id = `shell_${port}_${Date.now()}`;
  const session: ShellSession = {
    id,
    port,
    status: "listening",
    startedAt: new Date().toISOString(),
    output: ""
  };

  const child = spawn("nc", ["-lvnp", String(port)], {
    stdio: ["pipe", "pipe", "pipe"],
    windowsHide: true
  });

  session.process = child;
  shellSessions.set(id, session);

  child.stdout.on("data", (chunk: Buffer) => {
    session.output += decodeProcessOutput(chunk);
  });

  child.stderr.on("data", (chunk: Buffer) => {
    const text = decodeProcessOutput(chunk);
    session.output += text;
    if (text.includes("Connection") || text.includes("connect")) {
      session.status = "connected";
    }
  });

  const timer = setTimeout(() => {
    if (session.status !== "connected") {
      session.status = "closed";
      session.output += "\n[Listener timed out after timeoutMs ms]";
      killShellSession(id);
    }
  }, timeoutMs);

  child.on("close", () => {
    clearTimeout(timer);
    if (session.status === "listening") session.status = "closed";
    shellSessions.delete(id);
  });

  return session;
}

export function sendShellCommand(sessionId: string, command: string): string {
  const session = shellSessions.get(sessionId);
  if (!session || !session.process || session.status !== "connected") {
    return `Session ${sessionId} is not connected.`;
  }
  session.process.stdin?.write(command + "\n");
  return `Command sent to ${sessionId}: ${command}`;
}

export function killShellSession(sessionId: string): void {
  const session = shellSessions.get(sessionId);
  if (session?.process) {
    session.process.kill("SIGTERM");
    session.status = "closed";
  }
  shellSessions.delete(sessionId);
}

export function killAllShellSessions(): void {
  for (const [id] of shellSessions) {
    killShellSession(id);
  }
}
