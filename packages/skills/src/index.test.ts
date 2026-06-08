import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { FileSkillRegistry } from "./index.js";

describe("FileSkillRegistry", () => {
  let workspace: string;

  beforeEach(() => {
    workspace = mkdtempSync(join(tmpdir(), "aegisprobe-skills-"));
  });

  afterEach(() => {
    rmSync(workspace, { recursive: true, force: true });
  });

  it("loads YAML skills and renders matched prompt context", async () => {
    mkdirSync(join(workspace, "web"), { recursive: true });
    writeFileSync(join(workspace, "web", "xss.yaml"), [
      "id: web.xss-check",
      "name: XSS Check",
      "category: web",
      "risk_level: medium",
      "default_permission: approval",
      "requires_approval: true",
      "inputs:",
      "  - url",
      "tools:",
      "  - browser",
      "workflow:",
      "  - collect_parameters",
      "  - safe_reflection_check",
      "outputs:",
      "  - reflected_parameters"
    ].join("\n"), "utf8");

    const registry = new FileSkillRegistry({ roots: [workspace] });
    const matches = await registry.search("check xss reflection on url", { includeHighRisk: true });
    const prompt = await registry.renderPrompt("xss reflected parameters", { includeHighRisk: true });

    expect(matches[0]?.id).toBe("web.xss-check");
    expect(prompt).toContain("Skill: web.xss-check");
    expect(prompt).toContain("safe_reflection_check");
  });

  it("loads Codex-style SKILL.md frontmatter", async () => {
    mkdirSync(join(workspace, "frontend-audit"), { recursive: true });
    writeFileSync(join(workspace, "frontend-audit", "SKILL.md"), [
      "---",
      "name: frontend-audit",
      "description: Analyze frontend JavaScript for exposed routes and hardcoded secrets",
      "allowed-tools: Read Grep Agent",
      "---",
      "",
      "# Frontend Audit",
      "",
      "- enumerate JavaScript bundles",
      "- extract API routes",
      "- inspect source maps",
      "- identify client storage",
      "- review auth guards",
      "- map role-gated views",
      "- collect API clients",
      "- verify route candidates",
      "- avoid whole-bundle dumps",
      "- ninth body-only guidance"
    ].join("\n"), "utf8");

    const registry = new FileSkillRegistry({ roots: [workspace] });
    const skill = await registry.get("frontend-audit");
    const matches = await registry.search("hardcoded secrets in javascript routes");
    const prompt = await registry.renderPrompt("hardcoded secrets in javascript routes");

    expect(skill?.source).toBe("markdown");
    expect(skill?.tools).toEqual(["Read", "Grep", "Agent"]);
    expect(matches[0]?.id).toBe("frontend-audit");
    expect(prompt).toContain("Guidance:");
    expect(prompt).toContain("ninth body-only guidance");
  });
});
