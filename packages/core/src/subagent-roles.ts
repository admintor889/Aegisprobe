import type { SubAgentRole } from "@aegisprobe/shared";
import type { SubAgentToolDecision } from "@aegisprobe/tools";

export type SubAgentRoleDefinition = {
  label: string;
  description: string;
  maxIterations: number;
  foregroundTools: Array<SubAgentToolDecision["actions"][number]["type"]>;
  backgroundTools: Array<SubAgentToolDecision["actions"][number]["type"]>;
  promptFile: string;
};

export const subAgentRoleDefinitions: Record<SubAgentRole, SubAgentRoleDefinition> = {
  default: {
    label: "General-purpose subagent",
    description: "General delegated analysis with read-only workspace access.",
    maxIterations: 20,
    foregroundTools: ["read_file", "list_files"],
    backgroundTools: ["read_file", "list_files"],
    promptFile: "subagents/legacy/default.md"
  },
  explorer: {
    label: "Explorer",
    description: "Find relevant files, facts, and code paths without changing the workspace.",
    maxIterations: 20,
    foregroundTools: ["read_file", "list_files"],
    backgroundTools: ["read_file", "list_files"],
    promptFile: "subagents/legacy/explorer.md"
  },
  reviewer: {
    label: "Reviewer",
    description: "Review known context for bugs, risks, and missing tests without changing files.",
    maxIterations: 20,
    foregroundTools: ["read_file", "list_files"],
    backgroundTools: ["read_file", "list_files"],
    promptFile: "subagents/legacy/reviewer.md"
  },
  worker: {
    label: "Worker",
    description: "Implement a bounded change through the same approved file-edit protocol as the parent.",
    maxIterations: 25,
    foregroundTools: ["read_file", "list_files", "apply_patch"],
    backgroundTools: ["read_file", "list_files"],
    promptFile: "subagents/legacy/worker.md"
  },
  recon: {
    label: "Reconnaissance",
    description: "Evidence-led service discovery, technology fingerprinting, DNS enumeration, HTTP crawling, and JS/API surface mapping.",
    maxIterations: 10,
    foregroundTools: ["read_file", "list_files", "shell", "security_probe"],
    backgroundTools: ["read_file", "list_files"],
    promptFile: "subagents/legacy/recon.md"
  },
  frontend: {
    label: "Frontend Security Analyst",
    description: "Discover browser-visible entry points, login forms, client-side routes, JavaScript assets, source maps, and API calls.",
    maxIterations: 8,
    foregroundTools: ["read_file", "list_files", "shell", "mcp"],
    backgroundTools: ["read_file", "list_files"],
    promptFile: "subagents/legacy/frontend.md"
  },
  fingerprint: {
    label: "Fingerprint",
    description: "Clarify product and version evidence when recon has not already produced enough certainty.",
    maxIterations: 4,
    foregroundTools: ["read_file", "list_files", "shell", "security_probe"],
    backgroundTools: ["read_file", "list_files"],
    promptFile: "subagents/legacy/fingerprint.md"
  },
  cve: {
    label: "CVE Matcher",
    description: "Map confirmed product and version evidence to likely CVEs and validation paths.",
    maxIterations: 5,
    foregroundTools: ["read_file", "list_files", "shell"],
    backgroundTools: ["read_file", "list_files"],
    promptFile: "subagents/legacy/cve.md"
  },
  exploit: {
    label: "Exploitation",
    description: "Validate approved hypotheses through bounded, evidence-backed exploitation attempts.",
    maxIterations: 20,
    foregroundTools: ["read_file", "list_files", "shell", "security_probe", "mcp"],
    backgroundTools: ["read_file", "list_files"],
    promptFile: "subagents/legacy/exploit.md"
  },
  web_vuln: {
    label: "Web Vulnerability Analyst",
    description: "Analyze web and API behavior for OWASP, auth/session, input-validation, and business-logic risk.",
    maxIterations: 15,
    foregroundTools: ["read_file", "list_files", "shell", "security_probe", "mcp"],
    backgroundTools: ["read_file", "list_files"],
    promptFile: "subagents/legacy/web-vuln.md"
  }
};
