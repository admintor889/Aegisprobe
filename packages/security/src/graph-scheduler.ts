// ── Graph Scheduler ──
// Drives the graph evolution loop, adapted from Cairn's DispatcherLoop
// (cairn/src/cairn/dispatcher/scheduler/loop.py).
//
// Core cycle:
//   1. Check graph for changes (new evidence, new overrides, open→0 hypotheses)
//   2. If changed → trigger "Analysis" to re-evaluate graph state
//   3. If open hypotheses exist → dispatch highest-priority "Investigation"
//   4. Analysis can declare graph complete
//
// This is the "brain" of the pentest agent — it decides what to do next
// based on the current graph state, not a predefined pipeline.

import type {
  PenetrationGraph,
  GraphCheckpoint,
  GraphSnapshot,
  HypothesisNode,
  HypothesisCategory,
  HypothesisPriority,
  ReasonResult,
} from "./graph-types.js";
import {
  createGraphCheckpoint,
  hasGraphChanged,
  describeChange,
  createGraphSnapshot,
  getUnclaimedHypothesis,
  getOpenHypotheses,
  concludeHypothesis,
  failHypothesis,
  completeGraph,
} from "./graph.js";

// ── Scheduler State ──

export type SchedulerState = {
  graph: PenetrationGraph;
  checkpoint: GraphCheckpoint;
  /** Pending analysis trigger reason (null if no analysis needed) */
  pendingAnalysisTrigger: string | null;
  /** Current investigation in progress */
  activeInvestigation: {
    hypothesisId: string;
    claimedBy: string;
  } | null;
};

// ── Scheduler Operations ──

export function createSchedulerState(graph: PenetrationGraph): SchedulerState {
  return {
    graph,
    checkpoint: createGraphCheckpoint(graph),
    pendingAnalysisTrigger: "initial", // Always start with analysis
    activeInvestigation: null,
  };
}

/** Check if the graph needs re-analysis and update state accordingly. */
export function tickScheduler(state: SchedulerState): SchedulerState {
  const trigger = describeChange(state.checkpoint, state.graph);

  if (trigger) {
    return {
      ...state,
      checkpoint: createGraphCheckpoint(state.graph),
      pendingAnalysisTrigger: trigger,
    };
  }

  // No graph change, but check if we need analysis for other reasons
  if (state.pendingAnalysisTrigger) {
    return state; // Already pending
  }

  // If no open hypotheses and no pending analysis, we might need one
  const openCount = getOpenHypotheses(state.graph).length;
  if (openCount === 0 && state.activeInvestigation === null) {
    return {
      ...state,
      pendingAnalysisTrigger: "all_hypotheses_resolved",
    };
  }

  return state;
}

/** Consume the pending analysis trigger. Returns the snapshot for LLM. */
export function consumeAnalysisTrigger(state: SchedulerState): {
  snapshot: GraphSnapshot;
  trigger: string;
} | null {
  if (!state.pendingAnalysisTrigger) return null;

  const trigger = state.pendingAnalysisTrigger;
  const snapshot = createGraphSnapshot(state.graph);

  return { snapshot, trigger };
}

/** Mark analysis as completed with results. */
export function applyAnalysisResult(
  state: SchedulerState,
  result: ReasonResult
): SchedulerState {
  let graph = state.graph;
  let pendingAnalysisTrigger: string | null = null;

  if (result.kind === "complete") {
    const completed = completeGraph(graph, result.description);
    graph = completed.graph;
    pendingAnalysisTrigger = null; // No more analysis
  } else if (result.kind === "intents") {
    // Import proposeHypothesis dynamically would require graph mutations here
    // For now, new intents from analysis are handled by the caller
    pendingAnalysisTrigger = null; // Analysis consumed
  }

  return {
    ...state,
    graph,
    pendingAnalysisTrigger,
    checkpoint: createGraphCheckpoint(graph),
  };
}

/** Claim the next hypothesis for investigation. */
export function dispatchInvestigation(
  state: SchedulerState,
  claimedBy: string
): { hypothesis: HypothesisNode } | null {
  if (state.activeInvestigation) return null; // Already investigating

  const hypothesis = getUnclaimedHypothesis(state.graph);
  if (!hypothesis) return null;

  return { hypothesis };
}

// ── Analysis Prompt Builder ──
// Builds the LLM prompt for the Analysis (Reason) task.
// Mirrors Cairn's reason.md prompt structure but adapted for penetration testing.

export function buildAnalysisPrompt(snapshot: GraphSnapshot): string {
  const evidenceIds = snapshot.recentEvidence
    .map((e) => e.id)
    .filter((id) => id !== "goal");

  const openHypothesisLines = snapshot.openHypotheses.length > 0
    ? snapshot.openHypotheses.map((h) => `- ${h.id}: ${h.description} [${h.priority}] [${h.category}]`).join("\n")
    : "(none)";

  return `# Task
You are a penetration testing analysis agent. You will receive a YAML snapshot of the current attack graph. The graph contains:
- **facts** (evidence nodes): confirmed objective findings from tools and subagents
- **intents** (hypothesis nodes): proposed investigation directions, some open, some concluded
- **hints** (overrides): human-injected constraints or priorities

You need to interpret the graph and decide:
1. Whether the current evidence already satisfies the assessment goal
2. If not, what new hypotheses should be proposed

# Output Requirements
Return only one raw JSON object. Do not output anything else.

If the assessment is complete (enough evidence to produce a report with actionable findings), return:
\`\`\`json
{"kind":"complete","from":["ev_001","ev_003"],"description":"Sufficient evidence collected: X technologies, Y vulnerabilities confirmed, Z CVEs matched."}
\`\`\`

If new hypotheses should be proposed, return:
\`\`\`json
{"kind":"intents","intents":[{"from":["ev_001"],"description":"Check if nginx 1.14.2 is vulnerable to CVE-2019-xxxx","category":"cve_analysis","priority":"high","assignedRole":"cve"},{"from":["ev_002"],"description":"Probe /api endpoints for IDOR vulnerabilities","category":"business_logic","priority":"medium","assignedRole":"web_vuln"}]}
\`\`\`

If no new hypotheses are needed and the assessment is not yet complete, return:
\`\`\`json
{"kind":"noop"}
\`\`\`

# Rules
- First determine whether the goal is satisfied. If so, \`from\` must reference valid evidence IDs.
- Propose at most 5 high-value, non-overlapping hypotheses. Each should be independent and parallelizable.
- Each hypothesis must be based on existing evidence (referenced by ID in \`from\`).
- Use the category field: recon, fingerprint, cve_analysis, vulnerability_scan, exploitation, post_exploitation, business_logic, configuration_review, credential_testing, reporting.
- Use the priority field: critical (actively exploited, KEV), high (CVSS≥7 or auth bypass), medium (misconfigurations), low (informational).
- The assignedRole field should be: recon, fingerprint, cve, web_vuln, exploit, frontend, or null for any.

# Graph
\`\`\`yaml
${snapshot.yaml}
\`\`\`

# Valid Evidence IDs
${evidenceIds.join(", ") || "(only origin and goal exist)"}

# Open Hypotheses
${openHypothesisLines}
`;
}

// ── Investigation Prompt Builder ──
// Builds the LLM prompt for the Investigation (Explore) task.
// Mirrors Cairn's explore.md prompt structure.

export function buildInvestigationPrompt(
  snapshot: GraphSnapshot,
  hypothesis: HypothesisNode
): string {
  return `# Task
You are a penetration testing investigation agent. You will receive a YAML snapshot of the attack graph and a specific hypothesis to investigate.

Your only job: explore this hypothesis and produce new evidence.

# Output Requirements
Return only one raw JSON object:
\`\`\`json
{"kind":"evidence","description":"confirmed finding: nginx 1.14.2 on port 443 is vulnerable to CVE-2019-xxxx (CVSS 7.5). Verified via nuclei template http/cves/2019/CVE-2019-xxxx.yaml. Response confirmed path traversal."}
\`\`\`

If the hypothesis cannot be confirmed:
\`\`\`json
{"kind":"failed","reason":"No evidence found for this hypothesis after thorough investigation."}
\`\`\`

# Rules
- Focus ONLY on the assigned hypothesis. Do not explore other directions.
- Produce concrete, tool-backed evidence whenever possible.
- If you use a tool, include the command and key output in the description.
- If the hypothesis is blocked (e.g., needs active probing but scope forbids it), report as failed with the blocking reason.

# Graph
\`\`\`yaml
${snapshot.yaml}
\`\`\`

# Assigned Hypothesis
ID: ${hypothesis.id}
Category: ${hypothesis.category}
Priority: ${hypothesis.priority}
Based on evidence: [${hypothesis.basedOn.join(", ")}]
Description: ${hypothesis.description}
`;
}
