import { describe, expect, it } from "vitest";
import { evaluateCommand } from "./index.js";

describe("evaluateCommand", () => {
  it("requires approval for harmless commands", () => {
    const decision = evaluateCommand("pwd");
    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(true);
  });

  it("blocks destructive commands", () => {
    const decision = evaluateCommand("rm -rf /");
    expect(decision.allowed).toBe(false);
    expect(decision.risk).toBe("blocked");
  });

  it("allows PowerShell Format-* display cmdlets with approval", () => {
    const decision = evaluateCommand("Format-Hex -Path 'README.md'");
    expect(decision.allowed).toBe(true);
    expect(decision.requiresApproval).toBe(true);
  });

  it("blocks disk formatting commands", () => {
    const decision = evaluateCommand("format C:");
    expect(decision.allowed).toBe(false);
    expect(decision.risk).toBe("blocked");
  });

  it("blocks sensitive file reads", () => {
    const decision = evaluateCommand("Get-Content .env");
    expect(decision.allowed).toBe(false);
    expect(decision.risk).toBe("blocked");
  });

  it("blocks reads outside the workspace", () => {
    const decision = evaluateCommand("Get-Content -Path 'C:\\Windows\\System32\\drivers\\etc\\hosts'");
    expect(decision.allowed).toBe(false);
    expect(decision.risk).toBe("blocked");
  });

  it("allows workspace file writes via Set-Content but still blocks pipes and redirects", () => {
    // Set-Content to workspace paths is now allowed (with approval) for tool output persistence
    expect(evaluateCommand("Set-Content README.md 'changed'").allowed).toBe(true);
    expect(evaluateCommand("Set-Content README.md 'changed'").risk).toBe("low");
    // Pipe-based file writes are still blocked
    expect(evaluateCommand("'changed' | Out-File README.md").allowed).toBe(false);
    // Shell redirects are still blocked
    expect(evaluateCommand("echo changed > README.md").allowed).toBe(false);
  });

  it("allows New-Item -ItemType Directory for safe directory creation", () => {
    expect(evaluateCommand("New-Item -ItemType Directory -Path data").allowed).toBe(true);
    expect(evaluateCommand("New-Item -ItemType Directory -Force -Path .\\data").allowed).toBe(true);
    // New-Item without -ItemType Directory is still blocked
    expect(evaluateCommand("New-Item -ItemType File -Path test.txt").allowed).toBe(false);
  });

  it("blocks Set-Content writing outside the workspace", () => {
    expect(evaluateCommand("Set-Content -Path 'C:\\Windows\\test.txt' 'bad'").allowed).toBe(false);
    expect(evaluateCommand("Set-Content -Path '..\\outside.txt' 'bad'").allowed).toBe(false);
  });

  it("marks scanners as high risk", () => {
    const decision = evaluateCommand("nmap example.com");
    expect(decision.allowed).toBe(true);
    expect(decision.risk).toBe("high");
  });

  it("allows grep-style HTML marker extraction without treating it as redirection", () => {
    const decision = evaluateCommand('curl.exe -s http://127.0.0.1:3000 | findstr /i "<title>"');
    expect(decision.allowed).toBe(true);
    expect(decision.risk).toBe("low");
  });
});
