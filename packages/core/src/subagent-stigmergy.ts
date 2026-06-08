// ── Stigmergy SubAgent Orchestrator ──
// Replaces the digest-based direct communication model with graph-board coordination.
//
// Design (from Cairn's architecture):
//   1. SubAgents read the shared PenetrationGraph (facts + hypotheses + hints)
//   2. SubAgents write Evidence back to the graph (never modify others' evidence)
//   3. The orchestrator only schedules — it doesn't inject data between agents
//   4. Each agent gets: graph YAML snapshot + task description
//   5. After execution: agent output is parsed and written as Evidence nodes
//
// This eliminates:
//   - _digest.md injection (fragile, lossy)
//   - enrichSubAgentTask (manual context threading)
//   - Fixed pipeline ordering (agents can run in any order)

import { nowIso, newId, type SubAgentRecord, type SubAgentRole } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import type { PenetrationGraph, EvidenceKind, EvidenceConfidence, OverrideKind } from "@aegisprobe/security";
import { createGraphSnapshot, getOpenHypotheses, getUnclaimedHypothesis, getRecentEvidence } from "@aegisprobe/security";
import { resolveV2Role, renderV2Prompt, type SubAgentRoleDefV2 } from "./subagent-roles-v2.js";
import { SubAgentRuntime, type SubAgentEmitter } from "./subagent-runtime.js";

// ── Types ──

export type StigmergySpawnOptions = {
  /** V2 role key (recon, analyze, exploit, investigate) */
  roleKey?: string;
  /** Legacy role (auto-mapped to v2) */
  legacyRole?: SubAgentRole;
  /** The hypothesis ID this agent is investigating (null = general recon/analyze) */
  hypothesisId?: string | null;
  /** Priority */
  priority?: "critical" | "high" | "medium" | "low";
  /** Run in background */
  background?: boolean;
};

export type StigmergyDependencies = {
  store: AuditStore;
  runtime: SubAgentRuntime;
  /** Get the current graph for a session */
  getGraph: (sessionId: string) => PenetrationGraph | undefined;
  /** Update graph with new evidence */
  addEvidence: (sessionId: string, params: {
    kind: EvidenceKind;
    description: string;
    source: { kind: string; role?: string; task?: string; toolId?: string; command?: string };
    confidence?: EvidenceConfidence;
    derivedFrom?: string[];
    tags?: string[];
  }) => string;
  /** Propose new hypotheses */
  proposeHypothesis: (sessionId: string, params: {
    basedOn: string[];
    description: string;
    category: any;
    priority?: string;
    assignedRole?: string | null;
  }) => string;
  /** Add human override */
  addOverride?: (sessionId: string, content: string, kind: string, relatesTo?: string) => string;
};

// ── Stigmergy Spawn ──

export async function spawnStigmergyAgent(
  deps: StigmergyDependencies,
  sessionId: string,
  task: string,
  options: StigmergySpawnOptions = {}
): Promise<SubAgentRecord> {
  const graph = deps.getGraph(sessionId);
  const snapshot = graph ? createGraphSnapshot(graph) : null;
  const graphYaml = snapshot?.yaml ?? "# No graph data yet\n";

  // Resolve role
  let roleKey: string;
  let roleDef: SubAgentRoleDefV2;
  if (options.roleKey) {
    roleKey = options.roleKey;
    roleDef = require("./subagent-roles-v2.js").subAgentRolesV2[roleKey];
  } else if (options.legacyRole) {
    roleDef = resolveV2Role(options.legacyRole);
    roleKey = require("./subagent-roles-v2.js").legacyToV2Role[options.legacyRole];
  } else {
    // Auto-detect role from task content
    roleKey = inferRoleFromTask(task, graph);
    roleDef = require("./subagent-roles-v2.js").subAgentRolesV2[roleKey];
  }

  // Build graph-aware prompt
  const systemPrompt = renderV2Prompt(roleKey, graphYaml, task);

  // Create subagent record
  const legacyRole = options.legacyRole ?? mapV2ToLegacyRole(roleKey);
  const description = `${roleDef.label}: ${task.slice(0, 80)}`;
  const record = deps.store.createSubAgent(sessionId, legacyRole, task, description, {
    status: "running",
    priority: options.priority ?? "high",
    runMode: options.background ? "background" : "foreground",
    maxRetries: 1,
    contextPaths: [],
  });

  // The actual execution uses the SubAgentRuntime but with graph-aware prompt
  // For now, we store the graph context alongside the record
  const outputPath = deps.runtime.initializeOutput(record).outputPath;
  if (outputPath) {
    const fs = require("node:fs");
    const path = require("node:path");
    const dir = path.dirname(outputPath);
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(outputPath, `# ${roleDef.label}\n\n## Graph Context\n\`\`\`yaml\n${graphYaml}\n\`\`\`\n\n## Task\n${task}\n\n## Status\nrunning\n`, "utf8");
  }

  // For now, store the task as a "queued" subagent — actual spawn is handled by the
  // existing subagent dispatch machinery in MainAgent.
  // This avoids circular dependency between stigmergy and orchestration modules.
  deps.store.createSubAgent(sessionId, legacyRole, task, description, {
    status: "queued",
    priority: options.priority ?? "high",
    runMode: options.background ? "background" : "foreground",
    maxRetries: 1,
    contextPaths: [],
  });

  // Return the queued record
  const allAgents = deps.store.listSubAgents(sessionId);
  const queued = allAgents.find((a) => a.task === task && a.status === "queued");
  return queued ?? record;
}

// ── Graph-Driven Dispatch ──
// Reads the graph and decides which agents to spawn next.
// Replaces enqueueBaselinePentestSubAgents (fixed pipeline).

export type DispatchDecision = {
  /** Agents to spawn now */
  spawn: Array<{
    roleKey: string;
    legacyRole: SubAgentRole;
    task: string;
    hypothesisId?: string;
    priority: "critical" | "high" | "medium" | "low";
  }>;
  /** Reason for this dispatch */
  reason: string;
};

export function planGraphDispatch(graph: PenetrationGraph): DispatchDecision {
  const snapshot = createGraphSnapshot(graph);
  const openHyps = getOpenHypotheses(graph);
  const recentEvidence = getRecentEvidence(graph, 20);
  const decisions: DispatchDecision["spawn"] = [];

  // Rule 1: If we have claimed but uninvestigated hypotheses, dispatch them
  const unclaimed = getUnclaimedHypothesis(graph);
  if (unclaimed) {
    const roleKey = hypothesisToRole(unclaimed.category as string);
    decisions.push({
      roleKey,
      legacyRole: mapV2ToLegacyRole(roleKey),
      task: `Investigate hypothesis ${unclaimed.id}: ${unclaimed.description}. Based on evidence [${unclaimed.basedOn.join(", ")}].`,
      hypothesisId: unclaimed.id,
      priority: unclaimed.priority,
    });
  }

  // Rule 2: If no evidence beyond origin/goal → need recon
  const nonSystemEvidence = recentEvidence.filter((e) => e.kind !== "origin" && e.kind !== "goal");
  if (nonSystemEvidence.length === 0 && decisions.length === 0) {
    decisions.push({
      roleKey: "recon",
      legacyRole: "recon",
      task: `Initial reconnaissance of ${graph.target.kind}:${graph.target.value}. Discover open ports, running services, technology stack, subdomains, and HTTP endpoints.`,
      priority: "critical",
    });
  }

  // Rule 3: If we have technology evidence but no CVE analysis → need analyze
  const hasTech = nonSystemEvidence.some((e) => e.kind === "technology");
  const hasCveAnalysis = openHyps.some((h) => h.category === "cve_analysis");
  if (hasTech && !hasCveAnalysis && decisions.length === 0) {
    decisions.push({
      roleKey: "analyze",
      legacyRole: "cve",
      task: `Analyze discovered technologies for known vulnerabilities. Match versions against CVE database and nuclei templates. Propose exploitation hypotheses for confirmed matches.`,
      priority: "high",
    });
  }

  // Rule 4: If we have CVE hypotheses that need validation → need exploit
  const cveHyps = openHyps.filter((h) => h.category === "cve_analysis" || h.category === "vulnerability_scan");
  if (cveHyps.length > 0 && !decisions.some((d) => d.roleKey === "exploit")) {
    const topHyp = cveHyps.sort((a, b) => {
      const pa = { critical: 0, high: 1, medium: 2, low: 3 }[a.priority] ?? 9;
      const pb = { critical: 0, high: 1, medium: 2, low: 3 }[b.priority] ?? 9;
      return pa - pb;
    })[0];
    decisions.push({
      roleKey: "exploit",
      legacyRole: "exploit",
      task: `Validate hypothesis ${topHyp.id}: ${topHyp.description}. Attempt controlled exploitation and collect evidence.`,
      hypothesisId: topHyp.id,
      priority: topHyp.priority,
    });
  }

  return {
    spawn: decisions,
    reason: decisions.length > 0
      ? `Dispatching ${decisions.length} agents: ${decisions.map((d) => d.roleKey).join(", ")}`
      : "No dispatch needed — graph is stable or all hypotheses are claimed",
  };
}

// ── Helpers ──

function hypothesisToRole(category: string): string {
  switch (category) {
    case "recon": return "recon";
    case "fingerprint": return "recon";
    case "cve_analysis": return "analyze";
    case "vulnerability_scan": return "analyze";
    case "exploitation": return "exploit";
    case "post_exploitation": return "exploit";
    case "business_logic": return "analyze";
    case "configuration_review": return "analyze";
    case "credential_testing": return "exploit";
    default: return "investigate";
  }
}

function mapV2ToLegacyRole(v2Key: string): SubAgentRole {
  const map: Record<string, SubAgentRole> = {
    recon: "recon",
    analyze: "cve",       // closest legacy role
    exploit: "exploit",
    investigate: "default",
  };
  return map[v2Key] ?? "default";
}

function inferRoleFromTask(task: string, graph?: PenetrationGraph | null): string {
  const t = task.toLowerCase();
  if (/scan|port|discover|nmap|httpx|subdomain|dns|crawl|fingerprint|wappalyzer/.test(t)) return "recon";
  if (/cve|vulnerab|analyze|match|owasp|misconfig|business.logic|idor/.test(t)) return "analyze";
  if (/exploit|payload|shell|bypass|inject|rce|privilege.escalat/.test(t)) return "exploit";
  return "investigate";
}

// ── Graph Context Builder for LLM Decision Prompt ──

export function buildStigmergyDecisionContext(
  graph: PenetrationGraph | undefined,
  previousActions: string[] = []
): string {
  if (!graph) return "No attack graph initialized yet. Start with reconnaissance.";

  const snapshot = createGraphSnapshot(graph);
  const openHyps = getOpenHypotheses(graph);

  const lines = [
    "## Attack Graph State (Stigmergy Board)",
    "",
    `Target: ${graph.target.kind}:${graph.target.value}`,
    `Status: ${graph.status} | Version: ${graph.version}`,
    "",
    `Evidence: ${snapshot.summary.evidenceCount} nodes`,
    `Open Hypotheses: ${snapshot.summary.openHypotheses}`,
    `Claimed: ${snapshot.summary.claimedHypotheses}`,
    `Concluded: ${snapshot.summary.concludedHypotheses}`,
    `Failed: ${snapshot.summary.failedHypotheses}`,
    `Overrides: ${snapshot.summary.overrideCount}`,
    "",
  ];

  // Key evidence (latest 5)
  const keyEvidence = snapshot.recentEvidence.slice(0, 5);
  if (keyEvidence.length > 0) {
    lines.push("### Key Evidence");
    for (const ev of keyEvidence) {
      lines.push(`- \`${ev.id}\` [${ev.kind}] ${ev.description.slice(0, 150)}`);
    }
    lines.push("");
  }

  // Active hypotheses
  if (openHyps.length > 0) {
    lines.push("### Active Hypotheses (need investigation)");
    for (const hy of openHyps.slice(0, 5)) {
      lines.push(`- \`${hy.id}\` [${hy.priority}] ${hy.category}: ${hy.description.slice(0, 150)}`);
    }
    lines.push("");
  }

  // Recent overrides
  if (snapshot.recentOverrides.length > 0) {
    lines.push("### Human Overrides");
    for (const ov of snapshot.recentOverrides) {
      lines.push(`- [${ov.kind}] ${ov.content.slice(0, 150)}`);
    }
    lines.push("");
  }

  if (previousActions.length > 0) {
    lines.push("### Previous Actions This Turn");
    for (const action of previousActions.slice(-5)) {
      lines.push(`- ${action}`);
    }
    lines.push("");
  }

  return lines.join("\n");
}
