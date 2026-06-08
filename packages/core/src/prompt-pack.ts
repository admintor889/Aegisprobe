import { existsSync, readFileSync } from "node:fs";
import { dirname, join as joinPath, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";

export type PentestSystemPromptPackInput = {
  skillContext: string;
  hasMcpManager: boolean;
  controlledTools: string;
};

export type PentestUserPromptPackInput = {
  target: string;
  active: string;
  profile: string;
  iteration: string;
  latestObservations: string;
  sessionContext: string;
};

const DEFAULT_PACK_NAME = "pentest-expert";

const SYSTEM_SECTIONS = [
  "system.md",
  "methodology-reference.md",
  "payload-capabilities.md",
  "tool-use.md",
  "output-contract.md"
];

export function renderPentestSystemPromptFromPack(input: PentestSystemPromptPackInput): string {
  const variables: Record<string, string> = {
    SKILL_CONTEXT: input.skillContext || "No extra skill context matched this target yet.",
    MCP_CONTEXT: input.hasMcpManager ? "MCP browser tools are available for JS-rendered pages when the capability snapshot exposes them." : "",
    CONTROLLED_TOOLS: input.controlledTools
  };
  const sections = SYSTEM_SECTIONS
    .map((file) => readPromptPackFile(file, variables))
    .filter((section) => section.trim().length > 0);
  if (sections.length > 0) {
    return sections.join("\n\n");
  }
  throw new Error("Pentest prompt pack is missing all system sections. Check configs/prompt-packs/pentest-expert or AEGISPROBE_PROMPT_PACK.");
}

export function renderPentestUserPromptFromPack(input: PentestUserPromptPackInput): string {
  const rendered = readPromptPackFile("user.md", {
    TARGET: input.target,
    ACTIVE: input.active,
    PROFILE: input.profile,
    ITERATION: input.iteration,
    LATEST_OBSERVATIONS: input.latestObservations,
    SESSION_CONTEXT: input.sessionContext
  });
  if (rendered.trim().length > 0) {
    return rendered;
  }
  throw new Error("Pentest prompt pack is missing user.md. Check configs/prompt-packs/pentest-expert or AEGISPROBE_PROMPT_PACK.");
}

export function renderPromptPackTemplate(fileName: string, variables: Record<string, string> = {}): string {
  const rendered = readPromptPackFile(fileName, variables);
  if (rendered.trim().length === 0) {
    throw new Error(`Prompt pack file is missing or empty: ${fileName}. Check configs/prompt-packs/pentest-expert or AEGISPROBE_PROMPT_PACK.`);
  }
  return rendered;
}

function readPromptPackFile(fileName: string, variables: Record<string, string>): string {
  const packDir = resolvePromptPackDir();
  if (!packDir) {
    return "";
  }
  const filePath = joinPath(packDir, fileName);
  if (!existsSync(filePath)) {
    return "";
  }
  return renderTemplate(readFileSync(filePath, "utf8"), variables).trim();
}

function resolvePromptPackDir(): string | undefined {
  const configured = process.env.AEGISPROBE_PROMPT_PACK;
  if (configured) {
    const resolved = resolvePath(configured);
    if (existsSync(resolved)) {
      return resolved;
    }
  }

  const root = findProjectRoot(process.cwd());
  if (root) {
    const dir = joinPath(root, "configs", "prompt-packs", DEFAULT_PACK_NAME);
    if (existsSync(dir)) {
      return dir;
    }
  }

  const moduleRoot = findProjectRoot(dirname(fileURLToPath(import.meta.url)));
  if (moduleRoot) {
    const dir = joinPath(moduleRoot, "configs", "prompt-packs", DEFAULT_PACK_NAME);
    if (existsSync(dir)) {
      return dir;
    }
  }

  return undefined;
}

function findProjectRoot(start: string): string | undefined {
  let current = resolvePath(start);
  for (;;) {
    if (existsSync(joinPath(current, "pnpm-workspace.yaml")) && existsSync(joinPath(current, "configs"))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) {
      return undefined;
    }
    current = parent;
  }
}

function renderTemplate(template: string, variables: Record<string, string>): string {
  return template.replace(/\{\{([A-Z0-9_]+)\}\}/g, (_match, key: string) => variables[key] ?? "");
}
