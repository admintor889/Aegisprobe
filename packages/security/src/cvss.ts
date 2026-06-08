// ── CVSS v3.1 Calculator ──
// Implements the CVSS v3.1 Specification (https://www.first.org/cvss/v3.1/specification-document)
// Parses CVSS vector strings and computes base, temporal, and environmental scores.

export type CvssSeverity = "none" | "low" | "medium" | "high" | "critical";

export type CvssMetrics = {
  // Base
  AV: "N" | "A" | "L" | "P";  // Attack Vector
  AC: "L" | "H";               // Attack Complexity
  PR: "N" | "L" | "H";         // Privileges Required
  UI: "N" | "R";               // User Interaction
  S: "U" | "C";                // Scope
  C: "N" | "L" | "H";          // Confidentiality
  I: "N" | "L" | "H";          // Integrity
  A: "N" | "L" | "H";          // Availability
  // Temporal (optional)
  E?: "X" | "U" | "P" | "F" | "H";  // Exploit Code Maturity
  RL?: "X" | "O" | "T" | "W" | "U"; // Remediation Level
  RC?: "X" | "U" | "R" | "C";       // Report Confidence
};

export type CvssResult = {
  vector: string;
  baseScore: number;
  baseSeverity: CvssSeverity;
  impactScore: number;
  exploitabilityScore: number;
  temporalScore?: number;
  temporalSeverity?: CvssSeverity;
  metrics: CvssMetrics;
};

// ── Metric Weights (CVSS v3.1 Table 15) ──

const weight: Record<string, any> = {
  AV: { N: 0.85, A: 0.62, L: 0.55, P: 0.20 },
  AC: { L: 0.77, H: 0.44 },
  PR: {
    U: { N: 0.85, L: 0.62, H: 0.27 },
    C: { N: 0.85, L: 0.68, H: 0.50 },
  },
  UI: { N: 0.85, R: 0.62 },
  CIA: { N: 0.00, L: 0.22, H: 0.56 },
};

const temporalWeight: Record<string, any> = {
  E:  { X: 1.00, U: 0.91, P: 0.94, F: 0.97, H: 1.00 },
  RL: { X: 1.00, O: 0.95, T: 0.96, W: 0.97, U: 1.00 },
  RC: { X: 1.00, U: 0.92, R: 0.96, C: 1.00 },
};

// ── Temporal Metric Weights (CVSS v3.1 Table 17-19) ──


// ── Parser ──

export function parseCvssVector(vector: string): CvssMetrics {
  const normalized = vector.trim().toUpperCase();
  const prefix = "CVSS:3.1/";
  const body = normalized.startsWith(prefix) ? normalized.slice(prefix.length) : normalized;
  const parts = body.split("/");
  const metrics: Record<string, string> = {};

  for (const part of parts) {
    const [key, value] = part.split(":");
    if (key && value) metrics[key] = value;
  }

  // Validate required metrics
  for (const required of ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]) {
    if (!metrics[required]) {
      throw new Error(`Missing required CVSS metric: ${required}`);
    }
  }

  return {
    AV: metrics["AV"] as CvssMetrics["AV"],
    AC: metrics["AC"] as CvssMetrics["AC"],
    PR: metrics["PR"] as CvssMetrics["PR"],
    UI: metrics["UI"] as CvssMetrics["UI"],
    S: metrics["S"] as CvssMetrics["S"],
    C: metrics["C"] as CvssMetrics["C"],
    I: metrics["I"] as CvssMetrics["I"],
    A: metrics["A"] as CvssMetrics["A"],
    E: (metrics["E"] as CvssMetrics["E"]) || undefined,
    RL: (metrics["RL"] as CvssMetrics["RL"]) || undefined,
    RC: (metrics["RC"] as CvssMetrics["RC"]) || undefined,
  };
}

// ── Calculator ──

export function calculateCvss(vectorOrMetrics: string | CvssMetrics): CvssResult {
  const metrics = typeof vectorOrMetrics === "string"
    ? parseCvssVector(vectorOrMetrics)
    : vectorOrMetrics;

  // Step 1: Calculate Impact Sub-Score (ISS)
  const iss = 1 - (
    (1 - weight.CIA[metrics.C]) *
    (1 - weight.CIA[metrics.I]) *
    (1 - weight.CIA[metrics.A])
  );

  // Step 2: Calculate Impact Score
  let impact: number;
  if (metrics.S === "U") {
    impact = 6.42 * iss;
  } else {
    impact = 7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 15);
  }

  // Step 3: Calculate Exploitability Score
  const prWeight = metrics.S === "U"
    ? weight.PR.U[metrics.PR]
    : weight.PR.C[metrics.PR];

  const exploitability = (
    8.22 *
    weight.AV[metrics.AV] *
    weight.AC[metrics.AC] *
    prWeight *
    weight.UI[metrics.UI]
  );

  // Step 4: Calculate Base Score
  let baseScore: number;
  if (impact <= 0) {
    baseScore = 0;
  } else if (metrics.S === "U") {
    baseScore = roundUp(Math.min(impact + exploitability, 10));
  } else {
    baseScore = roundUp(Math.min(1.08 * (impact + exploitability), 10));
  }

  // Step 5: Calculate Temporal Score (if metrics provided)
  let temporalScore: number | undefined;
  let temporalSeverity: CvssSeverity | undefined;
  if (metrics.E && metrics.RL && metrics.RC) {
    temporalScore = roundUp(
      baseScore *
      temporalWeight.E[metrics.E] *
      temporalWeight.RL[metrics.RL] *
      temporalWeight.RC[metrics.RC]
    );
    temporalSeverity = severityFromScore(temporalScore);
  }

  const baseSeverity = severityFromScore(baseScore);

  return {
    vector: buildVectorString(metrics),
    baseScore,
    baseSeverity,
    impactScore: roundUp(impact),
    exploitabilityScore: roundUp(exploitability),
    temporalScore,
    temporalSeverity,
    metrics,
  };
}

// ── Helper Functions ──

function roundUp(value: number): number {
  const rounded = Math.round(value * 100_000) / 100_000;
  // CVSS specifies rounding up to 1 decimal place
  const intPart = Math.floor(rounded * 10) / 10;
  if (rounded > intPart) {
    return Math.round((intPart + 0.1) * 10) / 10;
  }
  return Math.round(intPart * 10) / 10;
}

export function severityFromScore(score: number): CvssSeverity {
  if (score === 0) return "none";
  if (score < 4.0) return "low";
  if (score < 7.0) return "medium";
  if (score < 9.0) return "high";
  return "critical";
}

export function severityRank(severity: CvssSeverity): number {
  return { none: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity];
}

function buildVectorString(metrics: CvssMetrics): string {
  const parts = [
    `AV:${metrics.AV}`, `AC:${metrics.AC}`, `PR:${metrics.PR}`, `UI:${metrics.UI}`,
    `S:${metrics.S}`, `C:${metrics.C}`, `I:${metrics.I}`, `A:${metrics.A}`,
  ];
  if (metrics.E) parts.push(`E:${metrics.E}`);
  if (metrics.RL) parts.push(`RL:${metrics.RL}`);
  if (metrics.RC) parts.push(`RC:${metrics.RC}`);
  return `CVSS:3.1/${parts.join("/")}`;
}

// ── Quick score from vector string without full result ──

export function cvssScore(vector: string): number {
  return calculateCvss(vector).baseScore;
}

// ── Compare two CVSS scores for prioritization ──

export function compareCvss(a: string | CvssMetrics, b: string | CvssMetrics): number {
  const scoreA = typeof a === "string" ? cvssScore(a) : calculateCvss(a).baseScore;
  const scoreB = typeof b === "string" ? cvssScore(b) : calculateCvss(b).baseScore;
  return scoreA - scoreB;
}
