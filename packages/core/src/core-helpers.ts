import type { SubAgentRecord, TaskTreeNode } from "@aegisprobe/shared";

export function sanitizePathSegment(value: string): string {
  return value.replace(/[^a-z0-9_.-]+/gi, "_").slice(0, 80) || "item";
}

export function validationPriorityRank(priority: "critical" | "high" | "medium" | "low"): number {
  return { critical: 0, high: 1, medium: 2, low: 3 }[priority];
}

export function renderTaskTreeContext(nodes: TaskTreeNode[]): string {
  if (nodes.length === 0) {
    return "";
  }

  const lines = ["Task Tree (active context - maintained outside LLM memory):"];
  for (const node of nodes) {
    const icon = node.status === "running" ? "[running]"
      : node.status === "completed" ? "[done]"
      : node.status === "blocked" ? "[blocked]"
      : node.status === "failed" ? "[failed]"
      : "[todo]";
    lines.push(`  ${icon} [${node.phase}] ${node.title} (${node.status})`);
    if (node.summary) lines.push(`    ${node.summary.slice(0, 5_000)}`);
    if (node.evidenceIds.length > 0) lines.push(`    Evidence: ${node.evidenceIds.length} items`);
    if (node.findingIds.length > 0) lines.push(`    Findings: ${node.findingIds.length} items`);
  }
  return lines.join("\n");
}

export function buildSubAgentDigest(agents: SubAgentRecord[]): string {
  const completed = agents.filter((agent) => agent.status === "completed" && agent.resultSummary);
  if (completed.length === 0) {
    return "";
  }

  const lines = ["## Subagent Discovery Digest", ""];
  for (const agent of completed.slice(-12)) {
    const summary = agent.resultSummary ?? "";
    const header = `### ${agent.role} (${agent.id.slice(-8)})`;
    const desc = agent.description ? ` - ${agent.description}` : "";
    lines.push(`${header}${desc}`);
    lines.push("");
    lines.push(summary.slice(0, 30000));
    lines.push("");
  }
  return lines.join("\n");
}

export function detectSubAgentContradictions(agents: SubAgentRecord[]): string[] {
  const contradictions: string[] = [];
  const summaries = agents.map((agent) => `${agent.role}:${agent.resultSummary ?? ""}`.toLowerCase());
  const hasConfirmed = summaries.some((summary) => /\b(validated|confirmed|true positive)\b/i.test(summary));
  const hasRuledOut = summaries.some((summary) => /\b(false positive|ruled out|not vulnerable)\b/i.test(summary));
  if (hasConfirmed && hasRuledOut) {
    contradictions.push("subagents disagree on whether at least one issue is validated or ruled out");
  }
  const hasNeedsAuth = summaries.some((summary) => /auth|login|credential/.test(summary));
  const hasNoAuthNeeded = summaries.some((summary) => /no auth required|anonymous|unauthenticated/.test(summary));
  if (hasNeedsAuth && hasNoAuthNeeded) {
    contradictions.push("subagents disagree on authentication requirements");
  }
  const riskyClaims = agents
    .filter((agent) => /critical|rce|admin|secret/i.test(agent.resultSummary ?? "") && !/evidence|artifact|output/i.test(agent.resultSummary ?? ""))
    .map((agent) => `${agent.id}:${agent.role}`);
  if (riskyClaims.length > 0) {
    contradictions.push(`high-impact claims without obvious evidence references: ${riskyClaims.join(", ")}`);
  }
  return contradictions;
}
