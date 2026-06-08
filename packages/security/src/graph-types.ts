// ── Penetration Testing Graph Model ──
// Inspired by Cairn's Blackboard Architecture (Facts/Intents/Hints),
// adapted for real-world penetration testing where:
//   - Evidence replaces Facts (tool outputs, fingerprints, validated findings)
//   - Hypothesis replaces Intents (proposed investigation directions)
//   - Override replaces Hints (human-injected constraints or priorities)
//
// Reference: Cairn server/models.py — Fact/Intent/Hint graph primitives
// Reference: Cairn scheduler/loop.py — Reason → Explore → Reason cycle
// Reference: STIX 2.1 — SDO/SRO relationship modeling for cyber threat intelligence

// ── Core Graph Primitives ──

/** A confirmed, objective finding written to the graph. Immutable once created. */
export type EvidenceNode = {
  id: string;                    // e.g. "ev_001"
  kind: EvidenceKind;
  description: string;           // human-readable summary
  source: EvidenceSource;        // how this evidence was obtained
  confidence: EvidenceConfidence;
  createdAt: string;             // ISO-8601
  sessionId: string;
  /** Evidence IDs this node was derived from (empty for root/origin nodes) */
  derivedFrom: string[];
  /** Raw data payload — tool output, HTTP response, etc. */
  payload?: EvidencePayload;
  /** Tags for BM25 retrieval */
  tags: string[];
};

export type EvidenceKind =
  | "origin"                     // Target specification
  | "goal"                       // Assessment objective
  | "asset"                      // Discovered asset (subdomain, IP, service, URL)
  | "technology"                 // Fingerprinted technology (nginx/1.14.2)
  | "port"                       // Open port with service info
  | "vulnerability"              // Validated vulnerability finding
  | "cve_match"                  // CVE matched to technology version
  | "misconfiguration"           // Security misconfiguration
  | "credential"                 // Discovered credential or secret
  | "business_logic"             // Business logic flaw evidence
  | "tool_output"                // Raw tool output (for traceability)
  | "note";                      // Free-form observation

export type EvidenceConfidence = "confirmed" | "high" | "medium" | "low";

export type EvidenceSource =
  | { kind: "tool"; toolId: string; command: string }
  | { kind: "subagent"; role: string; task: string }
  | { kind: "llm"; reasoning: string }
  | { kind: "manual"; operator: string }
  | { kind: "system" };          // Built-in probes

export type EvidencePayload = {
  /** MIME-like type for the payload content */
  contentType: string;            // "application/json", "text/html", "text/plain"
  /** The actual payload data as a string */
  data: string;
  /** Byte length of payload (for truncation tracking) */
  byteLength: number;
  /** Whether the payload was truncated */
  truncated: boolean;
};

// ── Hypothesis (≈ Cairn Intent) ──

/** A proposed direction of investigation, not yet executed. */
export type HypothesisNode = {
  id: string;                    // e.g. "hy_001"
  /** Evidence IDs this hypothesis is based on (the "from" in Cairn's graph) */
  basedOn: string[];
  /** Evidence ID produced when concluded (the "to" in Cairn's graph). null while open. */
  concludedTo: string | null;
  description: string;           // what we want to investigate
  category: HypothesisCategory;
  priority: HypothesisPriority;
  status: HypothesisStatus;
  /** Which subagent role should handle this (null = any) */
  assignedRole: string | null;
  /** Which worker claimed this hypothesis */
  claimedBy: string | null;
  /** When the hypothesis was claimed */
  claimedAt: string | null;
  createdAt: string;
  concludedAt: string | null;
  sessionId: string;
};

export type HypothesisCategory =
  | "recon"                      // Asset/subdomain discovery
  | "fingerprint"                // Technology identification
  | "cve_analysis"               // CVE matching against version evidence
  | "vulnerability_scan"         // Active vulnerability scanning (nuclei, etc.)
  | "exploitation"               // Exploit attempt
  | "post_exploitation"          // Privilege escalation, lateral movement
  | "business_logic"             // Business logic testing
  | "configuration_review"       // Misconfiguration checking
  | "credential_testing"         // Credential validation
  | "reporting";                 // Evidence synthesis for report

export type HypothesisPriority = "critical" | "high" | "medium" | "low";

export type HypothesisStatus =
  | "open"                       // Proposed, not yet claimed
  | "claimed"                    // Claimed by a worker, in progress
  | "concluded"                  // Worker finished, evidence node created
  | "failed"                     // Exploration failed to produce evidence
  | "blocked";                   // Cannot proceed (needs authorization, missing tool, etc.)

// ── Override (≈ Cairn Hint) ──

/** Human-injected judgment that modifies graph interpretation. */
export type OverrideNode = {
  id: string;                    // e.g. "ov_001"
  content: string;               // the hint text
  creator: string;               // who injected it ("operator", "system")
  createdAt: string;
  sessionId: string;
  /** Optional: link to specific evidence or hypothesis this override relates to */
  relatesTo?: string;
  /** Optional: override type for UI rendering */
  kind: OverrideKind;
};

export type OverrideKind =
  | "skip"                       // "Don't investigate this"
  | "focus"                      // "Prioritize this area"
  | "constraint"                 // "Cannot do X because of Y"
  | "knowledge"                  // "I know that Z is true"
  | "correction";                // "Your previous finding was wrong because..."

// ── Graph State ──

/** The complete attack graph for a session. */
export type PenetrationGraph = {
  sessionId: string;
  target: {
    kind: "url" | "hostname" | "ip";
    value: string;
  };
  status: GraphStatus;
  /** The goal description */
  goal: string;
  evidence: EvidenceNode[];
  hypotheses: HypothesisNode[];
  overrides: OverrideNode[];
  /** Graph version counter — incremented on every mutation */
  version: number;
  createdAt: string;
  updatedAt: string;
};

export type GraphStatus = "active" | "paused" | "completed";

// ── Graph Mutation Events ──

export type GraphEvent =
  | { kind: "evidence_added"; node: EvidenceNode }
  | { kind: "hypothesis_proposed"; node: HypothesisNode }
  | { kind: "hypothesis_claimed"; hypothesisId: string; claimedBy: string }
  | { kind: "hypothesis_concluded"; hypothesisId: string; evidenceId: string }
  | { kind: "hypothesis_failed"; hypothesisId: string; reason: string }
  | { kind: "hypothesis_blocked"; hypothesisId: string; reason: string }
  | { kind: "override_added"; node: OverrideNode }
  | { kind: "graph_completed"; reason: string };

// ── Graph Snapshot (for LLM context injection) ──

export type GraphSnapshot = {
  sessionId: string;
  version: number;
  /** Summary counts */
  summary: {
    evidenceCount: number;
    openHypotheses: number;
    claimedHypotheses: number;
    concludedHypotheses: number;
    failedHypotheses: number;
    overrideCount: number;
  };
  /** Key evidence nodes (origin + latest N) */
  recentEvidence: EvidenceNode[];
  /** Active hypotheses */
  openHypotheses: HypothesisNode[];
  /** Recent overrides */
  recentOverrides: OverrideNode[];
  /** Human-readable graph state for prompt injection */
  yaml: string;
};

// ── Reason Result (≈ Cairn reason task output) ──

export type ReasonResult =
  | { kind: "complete"; from: string[]; description: string }
  | { kind: "intents"; intents: Array<{ from: string[]; description: string; category: HypothesisCategory; priority: HypothesisPriority; assignedRole: string | null }> }
  | { kind: "noop" };

// ── Graph Change Trigger (≈ Cairn's ReasonCheckpoint) ──

export type GraphCheckpoint = {
  evidenceCount: number;
  overrideCount: number;
  openHypothesisCount: number;
};
