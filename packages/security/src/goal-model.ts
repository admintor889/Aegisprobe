// ── Goal Satisfaction Model ──
// Defines when a penetration test is "complete enough" to stop.
//
// Design references:
//   PentestGPT (USENIX 2024): PTT (Pentesting Task Tree) — attack-tree-based progress tracking,
//       182 sub-tasks, NIST 800-115 decomposition, sub-task completion rate as metric
//   PTES: 7 phases, scope-driven termination, reporting as formal closure
//   NIST SP 800-115: 4 phases (Planning → Discovery → Attack → Reporting)
//   OWASP WSTG v4.2: 12 categories, checklist-based coverage
//
// Key insight from PentestGPT paper:
//   "iterative process persists either until a conclusive solution is identified
//    or a deadlock is reached"
//
// This translates to AegisProbe as:
//   Assessment is COMPLETE when (all planned tasks done) OR (no more hypotheses to explore)

import { nowIso } from "@aegisprobe/shared";
import type { PenetrationGraph, HypothesisNode } from "./graph-types.js";

// ── Coverage Dimensions (7-axis assessment) ──

export type CoverageDimension =
  | "asset_discovery"       // Subdomains, IPs, ports, services found
  | "fingerprint"           // Technologies identified with versions
  | "cve_analysis"          // CVEs matched and validated
  | "owasp_top10"           // OWASP categories checked
  | "device_exposure"       // Cameras/printers/firewalls/VPN identified + tested
  | "credential_testing"    // Default/weak passwords tested
  | "frontend_analysis";    // JS endpoints/API routes/secrets extracted

export type DimensionScore = {
  dimension: CoverageDimension;
  label: string;
  /** 0-100 raw score */
  score: number;
  /** Max possible score */
  maxScore: number;
  /** Weight in overall assessment (sum = 1.0) */
  weight: number;
  /** Evidence IDs that support this score */
  evidenceIds: string[];
  /** What's missing to reach 100 */
  gaps: string[];
};

// ── Goal Assessment Result ──

export type GoalAssessment = {
  /** Overall score 0-100 */
  overallScore: number;
  /** Per-dimension breakdown */
  dimensions: DimensionScore[];
  /** Is the assessment complete enough to stop? */
  isComplete: boolean;
  /** If not complete, what should be done next */
  recommendedActions: string[];
  /** Human-readable summary */
  summary: string;
  /** When this assessment was computed */
  evaluatedAt: string;
};

// ── Dimension Weights (from PTES + OWASP priorities) ──

const DIMENSION_WEIGHTS: Record<CoverageDimension, number> = {
  asset_discovery:      0.20,  // Foundation — everything else depends on knowing what's there
  fingerprint:          0.15,  // Technology identification enables CVE matching
  cve_analysis:         0.25,  // Primary value — finding exploitable vulnerabilities
  owasp_top10:          0.15,  // Web application security coverage
  device_exposure:      0.10,  // IoT/embedded — often overlooked, high impact
  credential_testing:   0.10,  // Quick wins — default passwords are common
  frontend_analysis:    0.05,  // Supplementary — JS secrets, API discovery
};

// ── Scoring Rules ──

interface ScoringInput {
  graph: PenetrationGraph;
  /** Technology count with versions */
  techWithVersions: number;
  /** Technology count without versions */
  techWithoutVersions: number;
  /** CVE matches found */
  cveMatches: number;
  /** CVE matches validated (confirmed/high confidence) */
  cveValidated: number;
  /** Device profiles matched */
  devicesIdentified: number;
  /** Devices with credential tests attempted */
  devicesTested: number;
  /** OWASP categories with at least one finding */
  owaspCategoriesCovered: number;
  /** Total OWASP categories applicable (depends on target type) */
  owaspCategoriesApplicable: number;
  /** Subdomains discovered */
  subdomainsFound: number;
  /** Open ports found */
  portsFound: number;
  /** JS files analyzed */
  jsFilesAnalyzed: number;
  /** Endpoints extracted from JS */
  jsEndpointsFound: number;
}

export function assessGoalSatisfaction(input: ScoringInput): GoalAssessment {
  const dimensions: DimensionScore[] = [];
  const evidenceNodes = input.graph.evidence;

  // 1. Asset Discovery
  {
    const subdomainScore = Math.min(input.subdomainsFound * 20, 40); // max at 2 subdomains
    const portScore = Math.min(input.portsFound * 5, 40);             // max at 8 ports
    const serviceScore = countEvidenceByKind(evidenceNodes, "asset") >= 5 ? 20 : countEvidenceByKind(evidenceNodes, "asset") * 4;
    const raw = subdomainScore + portScore + serviceScore;
    dimensions.push({
      dimension: "asset_discovery",
      label: "Asset Discovery (subdomains/IPs/ports/services)",
      score: Math.min(raw, 100),
      maxScore: 100,
      weight: DIMENSION_WEIGHTS.asset_discovery,
      evidenceIds: evidenceNodes.filter((e) => e.kind === "asset" || e.kind === "port").map((e) => e.id),
      gaps: raw < 50
        ? ["Run subfinder/amass for subdomain enumeration", "Run nmap for comprehensive port scan", "Run httpx to probe all HTTP services"]
        : raw < 80
          ? ["Check if C-segment discovery is authorized", "Run dnsx on discovered subdomains"]
          : [],
    });
  }

  // 2. Fingerprint
  {
    const versionScore = Math.min(input.techWithVersions * 15, 60);
    const detectScore = Math.min(input.techWithoutVersions * 5, 20);
    const wappalyzerScore = countEvidenceByKind(evidenceNodes, "technology") >= 3 ? 20 : 0;
    const raw = versionScore + detectScore + wappalyzerScore;
    dimensions.push({
      dimension: "fingerprint",
      label: "Technology Fingerprinting",
      score: Math.min(raw, 100),
      maxScore: 100,
      weight: DIMENSION_WEIGHTS.fingerprint,
      evidenceIds: evidenceNodes.filter((e) => e.kind === "technology").map((e) => e.id),
      gaps: raw < 40
        ? ["Run wappalyzer/whatweb on all HTTP services", "Run nuclei -id tech-detect for version detection"]
        : raw < 70
          ? ["Version detection for remaining technologies", "Confirm framework/CMS versions"]
          : [],
    });
  }

  // 3. CVE Analysis
  {
    const matchScore = Math.min(input.cveMatches * 15, 50);
    const validatedScore = Math.min(input.cveValidated * 25, 50);
    const raw = matchScore + validatedScore;
    dimensions.push({
      dimension: "cve_analysis",
      label: "CVE Matching & Validation",
      score: Math.min(raw, 100),
      maxScore: 100,
      weight: DIMENSION_WEIGHTS.cve_analysis,
      evidenceIds: evidenceNodes.filter((e) => e.kind === "cve_match" || e.kind === "vulnerability").map((e) => e.id),
      gaps: raw < 30
        ? ["Match technology versions against CVE database", "Run NVD API lookup for discovered products"]
        : raw < 60
          ? ["Validate high-priority CVE matches with nuclei", "Check KEV catalog for actively exploited CVEs"]
          : raw < 80
            ? ["Validate remaining CVE candidates", "Run EPSS scoring for prioritization"]
            : [],
    });
  }

  // 4. OWASP Top 10
  {
    const applicable = input.owaspCategoriesApplicable > 0 ? input.owaspCategoriesApplicable : 8; // assume 8 applicable if unknown
    const raw = (input.owaspCategoriesCovered / applicable) * 100;
    dimensions.push({
      dimension: "owasp_top10",
      label: "OWASP Top 10 Coverage",
      score: Math.round(raw),
      maxScore: 100,
      weight: DIMENSION_WEIGHTS.owasp_top10,
      evidenceIds: evidenceNodes.filter((e) => e.kind === "misconfiguration" || e.kind === "business_logic").map((e) => e.id),
      gaps: raw < 30
        ? ["Run nuclei -tags misconfig,exposure for configuration issues", "Test for SQL injection, XSS, command injection"]
        : raw < 60
          ? ["Test authentication/session management", "Check authorization controls (IDOR, privilege escalation)"]
          : raw < 80
            ? ["Business logic testing", "SSRF and deserialization checks"]
            : [],
    });
  }

  // 5. Device Exposure
  {
    const raw = input.devicesIdentified === 0 ? 10  // nothing found = not applicable, give baseline
      : Math.min((input.devicesTested / Math.max(input.devicesIdentified, 1)) * 100, 100);
    dimensions.push({
      dimension: "device_exposure",
      label: "Device Exposure (cameras/printers/firewalls/VPN)",
      score: Math.round(raw),
      maxScore: 100,
      weight: DIMENSION_WEIGHTS.device_exposure,
      evidenceIds: evidenceNodes.filter((e) => e.tags?.some((t) => /device|camera|printer|firewall|vpn|iot/i.test(t))).map((e) => e.id),
      gaps: input.devicesIdentified > 0 && input.devicesTested === 0
        ? ["Test default credentials on identified devices", "Check for known device-specific CVEs"]
        : input.devicesIdentified > 0 && input.devicesTested < input.devicesIdentified
          ? [`${input.devicesIdentified - input.devicesTested} devices not yet tested for default credentials`]
          : [],
    });
  }

  // 6. Credential Testing
  {
    const raw = Math.min((input.devicesTested * 20) + (input.portsFound > 0 ? 20 : 0), 100);
    dimensions.push({
      dimension: "credential_testing",
      label: "Credential & Default Password Testing",
      score: raw,
      maxScore: 100,
      weight: DIMENSION_WEIGHTS.credential_testing,
      evidenceIds: evidenceNodes.filter((e) => e.kind === "credential").map((e) => e.id),
      gaps: raw < 40
        ? ["Test default credentials for identified services", "Check SNMP default community strings"]
        : raw < 70
          ? ["Test weak password combinations", "Check for credential reuse"]
          : [],
    });
  }

  // 7. Frontend Analysis
  {
    const endpointScore = Math.min(input.jsEndpointsFound * 10, 50);
    const secretScore = countEvidenceByKind(evidenceNodes, "credential") >= 1 ? 30 : 0;
    const jsScore = Math.min(input.jsFilesAnalyzed * 10, 20);
    const raw = endpointScore + secretScore + jsScore;
    dimensions.push({
      dimension: "frontend_analysis",
      label: "Frontend Analysis (JS endpoints/API/secrets)",
      score: Math.min(raw, 100),
      maxScore: 100,
      weight: DIMENSION_WEIGHTS.frontend_analysis,
      evidenceIds: evidenceNodes.filter((e) => e.tags?.some((t) => /js|frontend|api|endpoint/i.test(t))).map((e) => e.id),
      gaps: raw < 30
        ? ["Run katana to crawl JS files", "Run subjs to extract JavaScript from HTTP responses"]
        : raw < 60
          ? ["Analyze JS files for API endpoints and secrets", "Check for exposed source maps"]
          : [],
    });
  }

  // Compute overall score
  const overallScore = Math.round(
    dimensions.reduce((sum, d) => sum + d.score * d.weight, 0)
  );

  // Determine completeness
  const isComplete = overallScore >= 80;

  // Build recommended actions
  const recommendedActions = dimensions
    .filter((d) => d.gaps.length > 0)
    .flatMap((d) => d.gaps)
    .slice(0, 8);

  // Build summary
  const dimensionLines = dimensions.map((d) =>
    `  ${d.label}: ${d.score}/${d.maxScore} (weight: ${(d.weight * 100).toFixed(0)}%)`
  ).join("\n");

  const summary = [
    `## Goal Satisfaction Assessment`,
    `Overall: ${overallScore}/100 — ${isComplete ? "✅ COMPLETE — sufficient evidence collected" : "⏳ IN PROGRESS — continue investigation"}`,
    ``,
    `### Dimension Scores`,
    dimensionLines,
    ``,
    recommendedActions.length > 0
      ? `### Recommended Next Actions\n${recommendedActions.map((a, i) => `${i + 1}. ${a}`).join("\n")}`
      : "### Recommended Next Actions\nNo immediate actions required.",
  ].join("\n");

  return {
    overallScore,
    dimensions,
    isComplete,
    recommendedActions,
    summary,
    evaluatedAt: nowIso(),
  };
}

// ── Pentesting Task Tree (PTT) ──
// Based on PentestGPT's attack-tree representation.
// Encodes the testing process's ongoing status and steers subsequent actions.

export type PttNode = {
  id: string;
  title: string;
  phase: "recon" | "scanning" | "vulnerability_assessment" | "exploitation" | "post_exploitation" | "reporting";
  status: "pending" | "in_progress" | "completed" | "blocked" | "not_applicable";
  /** Child sub-tasks */
  children: PttNode[];
  /** Evidence IDs linked to this node */
  evidenceIds: string[];
  /** Hypothesis IDs linked to this node */
  hypothesisIds: string[];
  /** NIST 800-115 task category */
  nistCategory?: string;
  /** CWE ID if applicable */
  cweId?: string;
};

export function createDefaultPtt(target: string): PttNode {
  return {
    id: "root",
    title: `Penetration Test: ${target}`,
    phase: "recon",
    status: "in_progress",
    children: [
      // Phase 1: Reconnaissance (PTES Phase 2 + NIST Discovery)
      {
        id: "recon",
        title: "Reconnaissance & Discovery",
        phase: "recon",
        status: "pending",
        children: [
          { id: "recon-whois", title: "WHOIS & DNS enumeration", phase: "recon", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Network Discovery" },
          { id: "recon-subdomain", title: "Subdomain discovery (passive + active)", phase: "recon", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Network Discovery" },
          { id: "recon-portscan", title: "Port scanning (TCP top 1000 + UDP key ports)", phase: "recon", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Network Discovery" },
          { id: "recon-service", title: "Service/version detection", phase: "recon", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Network Discovery" },
        ],
        evidenceIds: [],
        hypothesisIds: [],
        nistCategory: "Discovery",
      },
      // Phase 2: Scanning & Fingerprinting (PTES Phase 3 + NIST Discovery)
      {
        id: "fingerprint",
        title: "Scanning & Fingerprinting",
        phase: "scanning",
        status: "pending",
        children: [
          { id: "fp-http", title: "HTTP service probing (httpx)", phase: "scanning", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Network Discovery" },
          { id: "fp-tech", title: "Technology fingerprinting (Wappalyzer/nuclei tech-detect)", phase: "scanning", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Vulnerability Scanning" },
          { id: "fp-device", title: "Device identification (cameras/printers/firewalls/VPN)", phase: "scanning", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Vulnerability Scanning" },
          { id: "fp-frontend", title: "Frontend crawling (katana/gau/waybackurls)", phase: "scanning", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Vulnerability Scanning" },
          { id: "fp-js", title: "JavaScript analysis (API endpoints/secrets)", phase: "scanning", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Vulnerability Scanning" },
          { id: "fp-directory", title: "Directory brute-force (low-speed)", phase: "scanning", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Vulnerability Scanning" },
        ],
        evidenceIds: [],
        hypothesisIds: [],
        nistCategory: "Discovery",
      },
      // Phase 3: Vulnerability Analysis (PTES Phase 4 + NIST Attack)
      {
        id: "vuln",
        title: "Vulnerability Analysis",
        phase: "vulnerability_assessment",
        status: "pending",
        children: [
          { id: "vuln-cve", title: "CVE matching (fingerprint → CVE database)", phase: "vulnerability_assessment", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Target Vulnerability Validation" },
          { id: "vuln-owasp", title: "OWASP Top 10 coverage check", phase: "vulnerability_assessment", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Target Vulnerability Validation" },
          { id: "vuln-cred", title: "Credential testing (default passwords/weak passwords)", phase: "vulnerability_assessment", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Password Cracking" },
          { id: "vuln-device", title: "Device-specific vulnerability check", phase: "vulnerability_assessment", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Target Vulnerability Validation" },
        ],
        evidenceIds: [],
        hypothesisIds: [],
        nistCategory: "Attack",
      },
      // Phase 4: Exploitation (PTES Phase 5 + NIST Attack)
      {
        id: "exploit",
        title: "Exploitation & Validation",
        phase: "exploitation",
        status: "pending",
        children: [
          { id: "exp-cve", title: "Exploit validated CVEs", phase: "exploitation", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Target Vulnerability Validation" },
          { id: "exp-access", title: "Obtain initial access", phase: "exploitation", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Target Vulnerability Validation" },
        ],
        evidenceIds: [],
        hypothesisIds: [],
        nistCategory: "Attack",
      },
      // Phase 5: Post-Exploitation (PTES Phase 5)
      {
        id: "post",
        title: "Post-Exploitation",
        phase: "post_exploitation",
        status: "pending",
        children: [
          { id: "post-enum", title: "System enumeration (id/hostname/network/interfaces)", phase: "post_exploitation", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Target Vulnerability Validation" },
          { id: "post-privesc", title: "Privilege escalation check", phase: "post_exploitation", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Target Vulnerability Validation" },
          { id: "post-creds", title: "Credential extraction", phase: "post_exploitation", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Password Cracking" },
          { id: "post-lateral", title: "Lateral movement (if applicable)", phase: "post_exploitation", status: "pending", children: [], evidenceIds: [], hypothesisIds: [], nistCategory: "Target Vulnerability Validation" },
        ],
        evidenceIds: [],
        hypothesisIds: [],
        nistCategory: "Attack",
      },
      // Phase 6: Reporting
      {
        id: "report",
        title: "Reporting & Evidence Synthesis",
        phase: "reporting",
        status: "pending",
        children: [
          { id: "rpt-findings", title: "Compile findings with evidence", phase: "reporting", status: "pending", children: [], evidenceIds: [], hypothesisIds: [] },
          { id: "rpt-remediation", title: "Write remediation recommendations", phase: "reporting", status: "pending", children: [], evidenceIds: [], hypothesisIds: [] },
          { id: "rpt-executive", title: "Executive summary", phase: "reporting", status: "pending", children: [], evidenceIds: [], hypothesisIds: [] },
        ],
        evidenceIds: [],
        hypothesisIds: [],
      },
    ],
    evidenceIds: [],
    hypothesisIds: [],
  };
}

// ── PTT → LLM Context ──

export function renderPttContext(node: PttNode, depth = 0): string {
  const indent = "  ".repeat(depth);
  const statusIcon =
    node.status === "completed" ? "✅" :
    node.status === "in_progress" ? "🔄" :
    node.status === "blocked" ? "🚫" :
    node.status === "not_applicable" ? "➖" : "⬜";

  const lines = [`${indent}${statusIcon} ${node.title} [${node.status}]`];

  for (const child of node.children) {
    lines.push(renderPttContext(child, depth + 1));
  }

  return lines.join("\n");
}

/** Update PTT node statuses based on graph evidence. */
export function updatePttFromGraph(node: PttNode, graph: PenetrationGraph): PttNode {
  const evidenceKinds = new Set(graph.evidence.map((e) => e.kind));
  const updated = { ...node, children: node.children.map((c) => updatePttFromGraph(c, graph)) };

  // Leaf node status logic
  if (updated.children.length === 0) {
    // Check if this leaf has evidence
    if (updated.evidenceIds.length > 0) {
      updated.status = "completed";
    } else if (updated.hypothesisIds.some((hid) => {
      const hyp = graph.hypotheses.find((h) => h.id === hid);
      return hyp && (hyp.status === "claimed" || hyp.status === "concluded");
    })) {
      updated.status = "in_progress";
    }
  } else {
    // Parent node: completed if all children completed
    const allDone = updated.children.every((c) => c.status === "completed" || c.status === "not_applicable");
    const anyProgress = updated.children.some((c) => c.status === "in_progress" || c.status === "completed");
    if (allDone) updated.status = "completed";
    else if (anyProgress) updated.status = "in_progress";
  }

  return updated;
}

// ── Quick helpers ──

function countEvidenceByKind(evidence: Array<{ kind: string }>, kind: string): number {
  return evidence.filter((e) => e.kind === kind).length;
}
