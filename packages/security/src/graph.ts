// ── Penetration Testing Graph Engine ──
// Core graph operations: create, query, mutate, snapshot.
// The graph is the single source of truth for a pentest session.
//
// Design principles (from Cairn):
//   1. Evidence is immutable once written — you can add new Evidence but never modify old
//   2. Hypotheses flow from Evidence → Hypothesis → new Evidence
//   3. Overrides are external injections that modify interpretation
//   4. The graph is append-only with versioning

import { newId, nowIso } from "@aegisprobe/shared";
import type {
  EvidenceNode,
  EvidenceKind,
  EvidenceConfidence,
  EvidenceSource,
  EvidencePayload,
  HypothesisNode,
  HypothesisCategory,
  HypothesisPriority,
  HypothesisStatus,
  OverrideNode,
  OverrideKind,
  PenetrationGraph,
  GraphStatus,
  GraphEvent,
  GraphSnapshot,
  GraphCheckpoint,
} from "./graph-types.js";

// ── Factory ──

export function createPenetrationGraph(params: {
  sessionId: string;
  target: PenetrationGraph["target"];
  goal?: string;
}): PenetrationGraph {
  const originNode: EvidenceNode = {
    id: "origin",
    kind: "origin",
    description: `Target: ${params.target.kind}:${params.target.value}`,
    source: { kind: "system" },
    confidence: "confirmed",
    createdAt: nowIso(),
    sessionId: params.sessionId,
    derivedFrom: [],
    tags: ["origin", params.target.kind, params.target.value],
  };

  const goalNode: EvidenceNode = {
    id: "goal",
    kind: "goal",
    description: params.goal ?? `Complete security assessment of ${params.target.value}. Produce actionable findings with evidence.`,
    source: { kind: "system" },
    confidence: "confirmed",
    createdAt: nowIso(),
    sessionId: params.sessionId,
    derivedFrom: [],
    tags: ["goal"],
  };

  return {
    sessionId: params.sessionId,
    target: params.target,
    status: "active",
    goal: goalNode.description,
    evidence: [originNode, goalNode],
    hypotheses: [],
    overrides: [],
    version: 1,
    createdAt: nowIso(),
    updatedAt: nowIso(),
  };
}

// ── Evidence Operations ──

export function addEvidence(
  graph: PenetrationGraph,
  params: {
    kind: EvidenceKind;
    description: string;
    source: EvidenceSource;
    confidence?: EvidenceConfidence;
    derivedFrom?: string[];
    payload?: EvidencePayload;
    tags?: string[];
  }
): { graph: PenetrationGraph; event: GraphEvent } {
  const node: EvidenceNode = {
    id: newId("ev"),
    kind: params.kind,
    description: params.description,
    source: params.source,
    confidence: params.confidence ?? "medium",
    createdAt: nowIso(),
    sessionId: graph.sessionId,
    derivedFrom: params.derivedFrom ?? [],
    payload: params.payload,
    tags: params.tags ?? [],
  };

  const updated: PenetrationGraph = {
    ...graph,
    evidence: [...graph.evidence, node],
    version: graph.version + 1,
    updatedAt: nowIso(),
  };

  return {
    graph: updated,
    event: { kind: "evidence_added", node },
  };
}

export function getEvidence(graph: PenetrationGraph, id: string): EvidenceNode | undefined {
  return graph.evidence.find((e) => e.id === id);
}

export function getEvidenceByKind(graph: PenetrationGraph, kind: EvidenceKind): EvidenceNode[] {
  return graph.evidence.filter((e) => e.kind === kind);
}

export function getRecentEvidence(graph: PenetrationGraph, count = 10): EvidenceNode[] {
  return [...graph.evidence]
    .filter((e) => e.id !== "origin" && e.id !== "goal")
    .sort((a, b) => b.createdAt.localeCompare(a.createdAt))
    .slice(0, count);
}

// ── Hypothesis Operations ──

export function proposeHypothesis(
  graph: PenetrationGraph,
  params: {
    basedOn: string[];
    description: string;
    category: HypothesisCategory;
    priority?: HypothesisPriority;
    assignedRole?: string | null;
  }
): { graph: PenetrationGraph; event: GraphEvent } {
  // Validate that all basedOn IDs exist in the graph
  for (const id of params.basedOn) {
    if (id !== "origin" && !graph.evidence.some((e) => e.id === id)) {
      throw new Error(`Cannot base hypothesis on unknown evidence: ${id}`);
    }
  }

  const node: HypothesisNode = {
    id: newId("hy"),
    basedOn: params.basedOn,
    concludedTo: null,
    description: params.description,
    category: params.category,
    priority: params.priority ?? "medium",
    status: "open",
    assignedRole: params.assignedRole ?? null,
    claimedBy: null,
    claimedAt: null,
    createdAt: nowIso(),
    concludedAt: null,
    sessionId: graph.sessionId,
  };

  const updated: PenetrationGraph = {
    ...graph,
    hypotheses: [...graph.hypotheses, node],
    version: graph.version + 1,
    updatedAt: nowIso(),
  };

  return {
    graph: updated,
    event: { kind: "hypothesis_proposed", node },
  };
}

export function claimHypothesis(
  graph: PenetrationGraph,
  hypothesisId: string,
  claimedBy: string
): { graph: PenetrationGraph; event: GraphEvent } {
  const idx = graph.hypotheses.findIndex((h) => h.id === hypothesisId);
  if (idx === -1) throw new Error(`Unknown hypothesis: ${hypothesisId}`);

  const existing = graph.hypotheses[idx];
  if (existing.status !== "open") {
    throw new Error(`Cannot claim hypothesis with status: ${existing.status}`);
  }

  const updated_hypotheses = [...graph.hypotheses];
  updated_hypotheses[idx] = {
    ...existing,
    status: "claimed",
    claimedBy,
    claimedAt: nowIso(),
  };

  const updated: PenetrationGraph = {
    ...graph,
    hypotheses: updated_hypotheses,
    version: graph.version + 1,
    updatedAt: nowIso(),
  };

  return {
    graph: updated,
    event: { kind: "hypothesis_claimed", hypothesisId, claimedBy },
  };
}

export function concludeHypothesis(
  graph: PenetrationGraph,
  hypothesisId: string,
  evidenceId: string
): { graph: PenetrationGraph; event: GraphEvent } {
  const idx = graph.hypotheses.findIndex((h) => h.id === hypothesisId);
  if (idx === -1) throw new Error(`Unknown hypothesis: ${hypothesisId}`);
  if (!graph.evidence.some((e) => e.id === evidenceId)) {
    throw new Error(`Unknown evidence: ${evidenceId}`);
  }

  const existing = graph.hypotheses[idx];
  const updated_hypotheses = [...graph.hypotheses];
  updated_hypotheses[idx] = {
    ...existing,
    status: "concluded",
    concludedTo: evidenceId,
    concludedAt: nowIso(),
  };

  const updated: PenetrationGraph = {
    ...graph,
    hypotheses: updated_hypotheses,
    version: graph.version + 1,
    updatedAt: nowIso(),
  };

  return {
    graph: updated,
    event: { kind: "hypothesis_concluded", hypothesisId, evidenceId },
  };
}

export function failHypothesis(
  graph: PenetrationGraph,
  hypothesisId: string,
  reason: string
): { graph: PenetrationGraph; event: GraphEvent } {
  const idx = graph.hypotheses.findIndex((h) => h.id === hypothesisId);
  if (idx === -1) throw new Error(`Unknown hypothesis: ${hypothesisId}`);

  const existing = graph.hypotheses[idx];
  const updated_hypotheses = [...graph.hypotheses];
  updated_hypotheses[idx] = {
    ...existing,
    status: "failed",
    description: `${existing.description} [FAILED: ${reason}]`,
    concludedAt: nowIso(),
  };

  const updated: PenetrationGraph = {
    ...graph,
    hypotheses: updated_hypotheses,
    version: graph.version + 1,
    updatedAt: nowIso(),
  };

  return {
    graph: updated,
    event: { kind: "hypothesis_failed", hypothesisId, reason },
  };
}

export function blockHypothesis(
  graph: PenetrationGraph,
  hypothesisId: string,
  reason: string
): { graph: PenetrationGraph; event: GraphEvent } {
  const idx = graph.hypotheses.findIndex((h) => h.id === hypothesisId);
  if (idx === -1) throw new Error(`Unknown hypothesis: ${hypothesisId}`);

  const existing = graph.hypotheses[idx];
  const updated_hypotheses = [...graph.hypotheses];
  updated_hypotheses[idx] = {
    ...existing,
    status: "blocked",
    description: `${existing.description} [BLOCKED: ${reason}]`,
  };

  const updated: PenetrationGraph = {
    ...graph,
    hypotheses: updated_hypotheses,
    version: graph.version + 1,
    updatedAt: nowIso(),
  };

  return {
    graph: updated,
    event: { kind: "hypothesis_blocked", hypothesisId, reason },
  };
}

export function getHypothesis(graph: PenetrationGraph, id: string): HypothesisNode | undefined {
  return graph.hypotheses.find((h) => h.id === id);
}

export function getOpenHypotheses(graph: PenetrationGraph): HypothesisNode[] {
  return graph.hypotheses.filter((h) => h.status === "open");
}

export function getClaimedHypotheses(graph: PenetrationGraph): HypothesisNode[] {
  return graph.hypotheses.filter((h) => h.status === "claimed");
}

export function getUnclaimedHypothesis(graph: PenetrationGraph): HypothesisNode | undefined {
  // Return highest-priority unclaimed hypothesis
  const priorityRank: Record<HypothesisPriority, number> = {
    critical: 0, high: 1, medium: 2, low: 3,
  };
  return graph.hypotheses
    .filter((h) => h.status === "open")
    .sort((a, b) => (priorityRank[a.priority] ?? 9) - (priorityRank[b.priority] ?? 9))[0];
}

// ── Override Operations ──

export function addOverride(
  graph: PenetrationGraph,
  params: {
    content: string;
    creator?: string;
    kind: OverrideKind;
    relatesTo?: string;
  }
): { graph: PenetrationGraph; event: GraphEvent } {
  const node: OverrideNode = {
    id: newId("ov"),
    content: params.content,
    creator: params.creator ?? "operator",
    createdAt: nowIso(),
    sessionId: graph.sessionId,
    relatesTo: params.relatesTo,
    kind: params.kind,
  };

  const updated: PenetrationGraph = {
    ...graph,
    overrides: [...graph.overrides, node],
    version: graph.version + 1,
    updatedAt: nowIso(),
  };

  return {
    graph: updated,
    event: { kind: "override_added", node },
  };
}

// ── Graph State ──

export function completeGraph(
  graph: PenetrationGraph,
  reason: string
): { graph: PenetrationGraph; event: GraphEvent } {
  const updated: PenetrationGraph = {
    ...graph,
    status: "completed",
    version: graph.version + 1,
    updatedAt: nowIso(),
  };

  return {
    graph: updated,
    event: { kind: "graph_completed", reason },
  };
}

export function isGraphCompleted(graph: PenetrationGraph): boolean {
  return graph.status === "completed";
}

// ── Checkpoint (≈ Cairn's ReasonCheckpoint) ──

export function createGraphCheckpoint(graph: PenetrationGraph): GraphCheckpoint {
  return {
    evidenceCount: graph.evidence.length,
    overrideCount: graph.overrides.length,
    openHypothesisCount: graph.hypotheses.filter((h) => h.status === "open").length,
  };
}

export function hasGraphChanged(checkpoint: GraphCheckpoint, graph: PenetrationGraph): boolean {
  const openCount = graph.hypotheses.filter((h) => h.status === "open").length;
  return (
    graph.evidence.length > checkpoint.evidenceCount ||
    graph.overrides.length > checkpoint.overrideCount ||
    (checkpoint.openHypothesisCount > 0 && openCount === 0) // All open intents concluded
  );
}

export function describeChange(checkpoint: GraphCheckpoint, graph: PenetrationGraph): string | null {
  const changes: string[] = [];
  if (graph.evidence.length > checkpoint.evidenceCount) {
    changes.push(`new evidence: ${graph.evidence.length - checkpoint.evidenceCount}`);
  }
  if (graph.overrides.length > checkpoint.overrideCount) {
    changes.push(`new overrides: ${graph.overrides.length - checkpoint.overrideCount}`);
  }
  const openCount = graph.hypotheses.filter((h) => h.status === "open").length;
  if (checkpoint.openHypothesisCount > 0 && openCount === 0) {
    changes.push("all open hypotheses concluded");
  }
  return changes.length > 0 ? changes.join(", ") : null;
}

// ── Snapshot (for LLM context injection) ──

export function createGraphSnapshot(
  graph: PenetrationGraph,
  options: { maxRecentEvidence?: number; maxHypotheses?: number } = {}
): GraphSnapshot {
  const maxRecent = options.maxRecentEvidence ?? 15;
  const maxHypotheses = options.maxHypotheses ?? 20;

  const openHypotheses = graph.hypotheses
    .filter((h) => h.status === "open" || h.status === "claimed")
    .sort((a, b) => {
      const pa = { critical: 0, high: 1, medium: 2, low: 3 }[a.priority] ?? 9;
      const pb = { critical: 0, high: 1, medium: 2, low: 3 }[b.priority] ?? 9;
      return pa - pb;
    })
    .slice(0, maxHypotheses);

  // Build YAML representation for LLM context
  const yaml = buildGraphYaml(graph);

  return {
    sessionId: graph.sessionId,
    version: graph.version,
    summary: {
      evidenceCount: graph.evidence.length,
      openHypotheses: graph.hypotheses.filter((h) => h.status === "open").length,
      claimedHypotheses: graph.hypotheses.filter((h) => h.status === "claimed").length,
      concludedHypotheses: graph.hypotheses.filter((h) => h.status === "concluded").length,
      failedHypotheses: graph.hypotheses.filter((h) => h.status === "failed").length,
      overrideCount: graph.overrides.length,
    },
    recentEvidence: getRecentEvidence(graph, maxRecent),
    openHypotheses,
    recentOverrides: [...graph.overrides].sort((a, b) => b.createdAt.localeCompare(a.createdAt)).slice(0, 5),
    yaml,
  };
}

// ── YAML Graph Serialization (for LLM prompt injection) ──
// Format mirrors Cairn's graph YAML export for Reason/Explore tasks.

function buildGraphYaml(graph: PenetrationGraph): string {
  const lines: string[] = [
    `session: ${graph.sessionId}`,
    `target: ${graph.target.kind}:${graph.target.value}`,
    `goal: "${graph.goal}"`,
    `status: ${graph.status}`,
    `version: ${graph.version}`,
    "",
    "facts:",
  ];

  // Evidence nodes as "facts" (Cairn terminology)
  for (const ev of graph.evidence) {
    const tags = ev.tags.length > 0 ? `  # ${ev.tags.join(", ")}` : "";
    const confidence = ev.confidence !== "medium" ? ` [${ev.confidence}]` : "";
    lines.push(`  ${ev.id}:`);
    lines.push(`    kind: ${ev.kind}${confidence}`);
    lines.push(`    description: "${escapeYaml(ev.description)}"`);
    lines.push(`    source: ${ev.source.kind}${tags}`);
    if (ev.derivedFrom.length > 0) {
      lines.push(`    derived_from: [${ev.derivedFrom.join(", ")}]`);
    }
  }

  lines.push("");
  lines.push("intents:");

  // Hypotheses as "intents" (Cairn terminology)
  for (const hy of graph.hypotheses) {
    const statusMarker =
      hy.status === "open" ? " [OPEN]" :
      hy.status === "claimed" ? ` [CLAIMED by ${hy.claimedBy}]` :
      hy.status === "concluded" ? ` [CONCLUDED → ${hy.concludedTo}]` :
      hy.status === "failed" ? " [FAILED]" :
      " [BLOCKED]";
    lines.push(`  ${hy.id}:`);
    lines.push(`    based_on: [${hy.basedOn.join(", ")}]`);
    lines.push(`    description: "${escapeYaml(hy.description)}"${statusMarker}`);
    lines.push(`    category: ${hy.category}`);
    lines.push(`    priority: ${hy.priority}`);
    if (hy.assignedRole) lines.push(`    assigned_role: ${hy.assignedRole}`);
  }

  if (graph.overrides.length > 0) {
    lines.push("");
    lines.push("hints:");
    for (const ov of graph.overrides) {
      lines.push(`  ${ov.id}:`);
      lines.push(`    kind: ${ov.kind}`);
      lines.push(`    content: "${escapeYaml(ov.content)}"`);
      lines.push(`    creator: ${ov.creator}`);
      if (ov.relatesTo) lines.push(`    relates_to: ${ov.relatesTo}`);
    }
  }

  return lines.join("\n");
}

function escapeYaml(s: string): string {
  return s.replace(/\\/g, "\\\\").replace(/"/g, '\\"').replace(/\n/g, "\\n");
}

// ── Graph Query Helpers ──

/** Build a prompt snippet summarizing the current graph state for LLM context. */
export function buildGraphContextPrompt(snapshot: GraphSnapshot, maxChars = 4000): string {
  const lines = [
    "## Attack Graph State",
    "",
    `Evidence: ${snapshot.summary.evidenceCount} nodes`,
    `Open Hypotheses: ${snapshot.summary.openHypotheses}`,
    `Claimed: ${snapshot.summary.claimedHypotheses}`,
    `Concluded: ${snapshot.summary.concludedHypotheses}`,
    `Failed: ${snapshot.summary.failedHypotheses}`,
    `Overrides: ${snapshot.summary.overrideCount}`,
    "",
  ];

  if (snapshot.recentEvidence.length > 0) {
    lines.push("### Recent Evidence");
    for (const ev of snapshot.recentEvidence.slice(0, 10)) {
      const src = ev.source.kind === "tool" ? `[${ev.source.toolId}]` : `[${ev.source.kind}]`;
      lines.push(`- \`${ev.id}\` ${src} ${ev.kind}: ${ev.description.slice(0, 200)}`);
    }
    lines.push("");
  }

  if (snapshot.openHypotheses.length > 0) {
    lines.push("### Active Hypotheses");
    for (const hy of snapshot.openHypotheses.slice(0, 10)) {
      lines.push(`- \`${hy.id}\` [${hy.priority}] ${hy.category}: ${hy.description.slice(0, 200)}`);
    }
    lines.push("");
  }

  if (snapshot.recentOverrides.length > 0) {
    lines.push("### Recent Overrides (Human Input)");
    for (const ov of snapshot.recentOverrides) {
      lines.push(`- [${ov.kind}] ${ov.content.slice(0, 200)}`);
    }
    lines.push("");
  }

  const result = lines.join("\n");
  return result.length > maxChars ? result.slice(0, maxChars) + "\n... (truncated)" : result;
}

/** Collect all unique technology names from evidence nodes. */
export function extractTechnologiesFromGraph(graph: PenetrationGraph): string[] {
  return [
    ...new Set(
      graph.evidence
        .filter((e) => e.kind === "technology")
        .map((e) => e.description.split(" ")[0]?.toLowerCase())
        .filter(Boolean)
    ),
  ];
}

/** Build a target description for BM25 feedback search. */
export function buildGraphSearchQuery(graph: PenetrationGraph): string {
  const parts: string[] = [graph.target.value];
  for (const ev of graph.evidence) {
    if (ev.kind === "technology") parts.push(ev.description);
    if (ev.kind === "vulnerability") parts.push(ev.description);
    if (ev.kind === "cve_match") parts.push(ev.description);
  }
  return parts.join(" ");
}
