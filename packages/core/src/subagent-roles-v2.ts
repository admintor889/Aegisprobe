import type { SubAgentRole } from "@aegisprobe/shared";
import type { SubAgentToolDecision } from "@aegisprobe/tools";
import { renderPromptPackTemplate } from "./prompt-pack.js";

export type SubAgentRoleDefV2 = {
  label: string;
  description: string;
  maxIterations: number;
  tools: Array<SubAgentToolDecision["actions"][number]["type"]>;
  promptFile: string;
};

export const subAgentRolesV2: Record<string, SubAgentRoleDefV2> = {
  recon: {
    label: "Reconnaissance",
    description: "Evidence-led information gathering across services, browser-visible surfaces, JavaScript/API assets, and technology signals.",
    maxIterations: 12,
    tools: ["read_file", "list_files", "shell", "security_probe", "mcp"],
    promptFile: "subagents/v2/recon.md"
  },
  analyze: {
    label: "Vulnerability Analysis",
    description: "Evidence-backed CVE, OWASP, authorization, session, configuration, and business-logic hypothesis work.",
    maxIterations: 10,
    tools: ["read_file", "list_files", "shell", "security_probe", "mcp"],
    promptFile: "subagents/v2/analyze.md"
  },
  exploit: {
    label: "Exploitation",
    description: "Controlled validation of approved hypotheses with bounded payloads and clear evidence.",
    maxIterations: 15,
    tools: ["read_file", "list_files", "shell", "security_probe", "mcp"],
    promptFile: "subagents/v2/exploit.md"
  },
  investigate: {
    label: "Investigation",
    description: "General-purpose exploration, file inspection, and focused fact finding.",
    maxIterations: 15,
    tools: ["read_file", "list_files", "apply_patch", "shell"],
    promptFile: "subagents/v2/investigate.md"
  }
};

export const legacyToV2Role: Record<SubAgentRole, string> = {
  recon: "recon",
  fingerprint: "recon",
  frontend: "recon",
  cve: "analyze",
  web_vuln: "analyze",
  reviewer: "analyze",
  exploit: "exploit",
  default: "investigate",
  explorer: "investigate",
  worker: "investigate"
};

export function resolveV2Role(legacyRole: SubAgentRole): SubAgentRoleDefV2 {
  const v2Key = legacyToV2Role[legacyRole] ?? "investigate";
  return subAgentRolesV2[v2Key];
}

export function v2RoleKeys(): string[] {
  return Object.keys(subAgentRolesV2);
}

export function renderV2Prompt(roleKey: string, graphYaml: string, task: string): string {
  const def = subAgentRolesV2[roleKey];
  if (!def) {
    throw new Error(`Unknown v2 role: ${roleKey}`);
  }
  return renderPromptPackTemplate(def.promptFile, {
    GRAPH_YAML: graphYaml,
    TASK: task,
    MAX_ITERATIONS: String(def.maxIterations)
  });
}
