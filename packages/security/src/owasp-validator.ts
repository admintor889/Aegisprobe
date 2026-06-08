// ── OWASP Automated Validation Engine ──
// Closes the loop from "observed" to "validated" for OWASP Top 10 categories.
//
// Design:
//   1. Read current OWASP check status from PenetrationGraph
//   2. For each "observed" check → dispatch safe automated test
//   3. Record validation evidence → update check to "validated" or "ruled_out"
//
// Each OWASP category maps to:
//   - nuclei template tags/IDs (safe, non-destructive)
//   - browser-based checks (MCP Playwright)
//   - curl/http checks
//   - evidence interpretation rules
//
// Reference:
//   - OWASP WSTG v4.2: 12 categories, each with testing methodology
//   - nuclei public templates: ~7000 templates, categorized by CWE/OWASP
//   - NIST SP 800-115: validation phase methodology

import type { PenetrationGraph } from "./graph-types.js";
import type { OwaspValidationItem } from "./types.js";

// ── OWASP → Nuclei Template Mapping ──

export type OwaspCheckMapping = {
  owaspId: string;
  category: string;
  /** Safe nuclei templates (non-destructive, no exploitation) */
  nucleiSafeTags: string[];
  /** Specific nuclei template IDs for targeted testing */
  nucleiTemplateIds: string[];
  /** curl commands for basic checks */
  httpChecks: string[];
  /** Browser-based checks (MCP Playwright) */
  browserChecks: string[];
  /** What constitutes validation success */
  successCriteria: string;
  /** Risk level for active testing */
  risk: "safe" | "caution" | "requires_approval";
};

// ── OWASP → Nuclei Template Mapping (REAL tags from nuclei-templates TEMPLATES-STATS.json) ──
// Tag counts from ProjectDiscovery's official template corpus (7000+ templates):
//   xss(1403), sqli(583), ssrf(190), ssti(53), xxe(47), csrf(5), idor(7)
//   misconfig(983), exposure(1443), default-login(336), panel(1523)
//   cve(4221), kev(507), vuln(6621)
//   ssl(44), tls(41), auth-bypass(271), auth(28)
//   file-upload(112), deserialization(73), traversal(66), lfi(850)
//   debug(98), phpinfo(11), env(9), config(321)
//   injection(52), rce(952)
//   logging(10), logs(64)
//   access-control(4), cookie(6), headers(7)
//   oast(355) — out-of-band (safe SSRF detection)

export const OWASP_CHECK_MAPPINGS: OwaspCheckMapping[] = [
  {
    owaspId: "A01",
    category: "Broken Access Control",
    nucleiSafeTags: ["auth-bypass", "idor", "access-control", "unauth", "panel"],
    nucleiTemplateIds: [],
    httpChecks: [
      "curl -sI TARGET/admin -o /dev/null -w '%{http_code}'",
      "curl -sI TARGET/wp-admin -o /dev/null -w '%{http_code}'",
      "curl -sI TARGET/.git/HEAD -o /dev/null -w '%{http_code}'",
    ],
    browserChecks: [
      "Navigate TARGET/admin → check if accessible without auth (200 = vulnerable)",
    ],
    successCriteria: "At least one admin/restricted path confirmed. All common paths checked.",
    risk: "caution",
  },
  {
    owaspId: "A02",
    category: "Cryptographic Failures",
    nucleiSafeTags: ["ssl", "tls", "ssl-issues", "weak-crypto"],
    nucleiTemplateIds: [],
    httpChecks: [
      "curl -sI https://TARGET | grep -i strict-transport-security",
      "nmap --script ssl-enum-ciphers -p 443 TARGET_HOST",
    ],
    browserChecks: [],
    successCriteria: "TLS scan completed. HSTS status and cipher suite strength recorded.",
    risk: "safe",
  },
  {
    owaspId: "A03",
    category: "Injection",
    nucleiSafeTags: ["xss", "sqli", "ssti", "injection", "lfi", "xxe"],
    nucleiTemplateIds: [],
    httpChecks: [
      "curl -s 'TARGET/?q=<script>alert(1)</script>' | grep -i script",
      "curl -s \"TARGET/?id=1'\" | grep -i 'sql\\|error\\|syntax'",
    ],
    browserChecks: [],
    successCriteria: "Injection probes completed. Record any error signatures or vulnerable parameters.",
    risk: "caution",
  },
  {
    owaspId: "A04",
    category: "Insecure Design",
    nucleiSafeTags: [],
    nucleiTemplateIds: [],
    httpChecks: [],
    browserChecks: [
      "Review business workflow: try URL-skipping steps, replay attacks",
    ],
    successCriteria: "Business logic hypotheses recorded. Requires manual review.",
    risk: "safe",
  },
  {
    owaspId: "A05",
    category: "Security Misconfiguration",
    nucleiSafeTags: ["misconfig", "exposure", "debug", "config", "phpinfo", "env"],
    nucleiTemplateIds: [],
    httpChecks: [
      "curl -sI TARGET/.env -o /dev/null -w '%{http_code}'",
      "curl -sI TARGET/phpinfo.php -o /dev/null -w '%{http_code}'",
      "curl -sI TARGET/.git/HEAD -o /dev/null -w '%{http_code}'",
      "curl -s -X OPTIONS TARGET -I 2>/dev/null | grep -i Allow",
    ],
    browserChecks: [],
    successCriteria: "Common misconfig paths checked. Evidence recorded for each finding.",
    risk: "safe",
  },
  {
    owaspId: "A06",
    category: "Vulnerable Components",
    nucleiSafeTags: ["cve", "kev", "vuln", "eol"],
    nucleiTemplateIds: [],
    httpChecks: [
      "Match observed technology versions against local CVE database",
    ],
    browserChecks: [],
    successCriteria: "CVE matching completed. Each technology with version has been queried.",
    risk: "safe",
  },
  {
    owaspId: "A07",
    category: "Auth Failures",
    nucleiSafeTags: ["auth", "default-login", "login", "cookie", "auth-bypass"],
    nucleiTemplateIds: [],
    httpChecks: [
      "curl -sI TARGET/login -o /dev/null -w '%{http_code}'",
      "Check Set-Cookie headers for HttpOnly/Secure/SameSite flags",
    ],
    browserChecks: [
      "Navigate to login form → test default credentials from DeviceProfileDB",
      "After login: check session cookie rotation (session fixation test)",
    ],
    successCriteria: "Auth endpoints identified. Cookie security and default credentials assessed.",
    risk: "caution",
  },
  {
    owaspId: "A08",
    category: "Software Integrity",
    nucleiSafeTags: ["deserialization", "file-upload", "traversal"],
    nucleiTemplateIds: [],
    httpChecks: [
      "curl -sI TARGET/package.json -o /dev/null -w '%{http_code}'",
      "curl -sI TARGET/composer.json -o /dev/null -w '%{http_code}'",
    ],
    browserChecks: [],
    successCriteria: "Dependency manifests checked. Deserialization and file upload risks assessed.",
    risk: "safe",
  },
  {
    owaspId: "A09",
    category: "Logging Failures",
    nucleiSafeTags: ["logging", "logs", "exposed"],
    nucleiTemplateIds: [],
    httpChecks: [
      "curl -sI TARGET/logs/ -o /dev/null -w '%{http_code}'",
      "curl -sI TARGET/error.log -o /dev/null -w '%{http_code}'",
    ],
    browserChecks: [],
    successCriteria: "Log exposure checked. Exposed log files and error pages recorded.",
    risk: "safe",
  },
  {
    owaspId: "A10",
    category: "SSRF",
    nucleiSafeTags: ["ssrf", "oast"],
    nucleiTemplateIds: [],
    httpChecks: [
      "Identify URL/fetch/import/webhook parameters in discovered endpoints",
    ],
    browserChecks: [],
    successCriteria: "SSRF-susceptible parameters identified. Requires controlled canary for active validation.",
    risk: "caution",
  },
];

// ── Validation Plan ──

export type OwaspValidationPlan = {
  category: string;
  owaspId: string;
  currentStatus: string;
  evidenceIds: string[];
  safeCommands: string[];
  browserCommands: string[];
  risk: OwaspCheckMapping["risk"];
  requiresApproval: boolean;
};

export type OwaspValidationResult = {
  owaspId: string;
  status: "validated" | "ruled_out" | "blocked" | "pending";
  evidenceDescription: string;
  commandOutput: string;
  matchedFindings: number;
};

// ── Plan Builder ──

export function buildOwaspValidationPlan(
  graph: PenetrationGraph,
  activeProbingAllowed: boolean,
  targetUrls: string[] = []
): OwaspValidationPlan[] {
  const plans: OwaspValidationPlan[] = [];

  for (const mapping of OWASP_CHECK_MAPPINGS) {
    // Check if this category has any evidence
    const hasEvidence = graph.evidence.some((ev) => {
      const text = `${ev.description} ${ev.tags?.join(" ") ?? ""}`.toLowerCase();
      return mapping.nucleiSafeTags.some((tag) => text.includes(tag.toLowerCase())) ||
             mapping.nucleiTemplateIds.some((id) => text.includes(id.toLowerCase()));
    });

    // Check existing hypothesis status for this category
    const relevantHypotheses = graph.hypotheses.filter((h) =>
      mapping.nucleiSafeTags.some((tag) =>
        `${h.description} ${h.category}`.toLowerCase().includes(tag.toLowerCase())
      )
    );

    const evidenceIds = graph.evidence
      .filter((ev) => hasEvidence &&
        mapping.nucleiSafeTags.some((tag) => ev.tags?.some((t) => t.includes(tag)))
      )
      .map((ev) => ev.id);

    const requiresApproval = mapping.risk === "requires_approval" ||
      (mapping.risk === "caution" && !activeProbingAllowed);

    // Build safe commands
    const safeCommands: string[] = [];
    if (targetUrls.length > 0) {
      const target = targetUrls[0];

      // nuclei commands (always safe to run with -tags)
      if (mapping.nucleiSafeTags.length > 0) {
        safeCommands.push(
          `nuclei -u "${target}" -tags ${mapping.nucleiSafeTags.join(",")} -jsonl -rl 3 -c 3 -bs 3 -timeout 5`
        );
      }

      // Specific template IDs
      if (mapping.nucleiTemplateIds.length > 0 && mapping.nucleiTemplateIds.length <= 8) {
        safeCommands.push(
          `nuclei -u "${target}" -id ${mapping.nucleiTemplateIds.join(",")} -jsonl -rl 3 -c 3 -bs 3 -timeout 5`
        );
      }

      // HTTP checks
      for (const check of mapping.httpChecks) {
        safeCommands.push(check.replace(/TARGET/g, target));
      }
    }

    plans.push({
      category: mapping.category,
      owaspId: mapping.owaspId,
      currentStatus: hasEvidence ? "observed" : "pending",
      evidenceIds,
      safeCommands: requiresApproval ? [] : safeCommands,
      browserCommands: requiresApproval ? [] : mapping.browserChecks,
      risk: mapping.risk,
      requiresApproval,
    });
  }

  return plans;
}

// ── Command Executor (results for each plan item) ──

/**
 * Build a shell command string that runs all safe tests for a validation plan.
 * Returns a single command string that can be passed to runShell().
 */
export function buildOwaspTestCommand(plan: OwaspValidationPlan): string | null {
  // Filter out URL-specific commands if no target
  const commands = plan.safeCommands.filter((cmd) => {
    // Include nuclei commands, exclude descriptive-only checks
    return cmd.startsWith("nuclei") || cmd.startsWith("curl") || cmd.startsWith("nmap");
  });

  if (commands.length === 0) return null;

  // Join with semicolons for Windows compatibility
  return commands.join(" & ");
}

// ── Evidence Parser ──

export function parseOwaspTestOutput(
  output: string,
  mapping: OwaspCheckMapping
): OwaspValidationResult {
  const lower = output.toLowerCase();
  const findingIndicators = [
    "vulnerability", "vuln", "critical", "high", "medium",
    "exposed", "misconfig", "weak", "default", "missing",
    "bypass", "injection", "xss", "sqli",
  ];

  const matchedFindings = findingIndicators.filter((indicator) =>
    lower.includes(indicator)
  ).length;

  const status: OwaspValidationResult["status"] = matchedFindings > 0
    ? "validated"
    : "ruled_out";

  return {
    owaspId: mapping.owaspId,
    status,
    evidenceDescription: matchedFindings > 0
      ? `Automated test found ${matchedFindings} signal(s) for ${mapping.category}`
      : `Automated test completed with no findings for ${mapping.category}`,
    commandOutput: output.slice(0, 500),
    matchedFindings,
  };
}

// ── OWASP Coverage Report ──

export function buildOwaspCoverageReport(results: OwaspValidationResult[]): string {
  const validated = results.filter((r) => r.status === "validated");
  const ruledOut = results.filter((r) => r.status === "ruled_out");
  const blocked = results.filter((r) => r.status === "blocked");
  const pending = results.filter((r) => r.status === "pending");

  const lines = [
    "## OWASP Top 10 Coverage Report",
    "",
    `Validated: ${validated.length} | Ruled Out: ${ruledOut.length} | Blocked: ${blocked.length} | Pending: ${pending.length}`,
    `Coverage: ${Math.round(((validated.length + ruledOut.length) / Math.max(results.length, 1)) * 100)}%`,
    "",
  ];

  if (validated.length > 0) {
    lines.push("### ✅ Validated");
    for (const r of validated) {
      lines.push(`- **${r.owaspId}**: ${r.evidenceDescription}`);
    }
    lines.push("");
  }

  if (ruledOut.length > 0) {
    lines.push("### ➖ Ruled Out (no evidence found)");
    for (const r of ruledOut) {
      lines.push(`- **${r.owaspId}**: ${r.evidenceDescription}`);
    }
    lines.push("");
  }

  if (blocked.length > 0) {
    lines.push("### 🚫 Blocked (requires active probing authorization)");
    for (const r of blocked) {
      lines.push(`- **${r.owaspId}**: Active testing not authorized`);
    }
    lines.push("");
  }

  if (pending.length > 0) {
    lines.push("### ⬜ Pending (no evidence collected yet)");
    for (const r of pending) {
      lines.push(`- **${r.owaspId}**: Awaiting initial recon evidence`);
    }
    lines.push("");
  }

  return lines.join("\n");
}

// ── Validation Prompt Builder for LLM ──

export function buildOwaspValidationPrompt(
  plans: OwaspValidationPlan[],
  results: OwaspValidationResult[]
): string {
  const report = buildOwaspCoverageReport(results);

  return `${report}

## Next Steps
The following categories still need validation:

${plans
    .filter((p) => !results.some((r) => r.owaspId === p.owaspId && r.status !== "pending"))
    .map((p) => `- **${p.owaspId} ${p.category}**: ${p.safeCommands.length > 0 ? p.safeCommands[0].slice(0, 120) : "Manual check required"}`)
    .join("\n")}
`;
}

// ── ZAP-inspired Job Pipeline ──
// OWASP ZAP Automation Framework: ordered jobs (spider → passiveScan → activeScan → report)
// AegisProbe adaptation: nuclei_safe → httpChecks → browserChecks → report
// Exit codes: 0=clean, 1=blocked/error, 2=findings_found

export type OwaspJobStep = {
  order: number;
  name: string;
  description: string;
  commands: string[];
  dependsOn: string[];
  parallel: boolean;
};

export function buildOwaspJobPipeline(plans: OwaspValidationPlan[], targetUrls: string[]): OwaspJobStep[] {
  const steps: OwaspJobStep[] = [];
  const u = targetUrls[0] || 'TARGET';

  const nucleiSafePlans = plans.filter((p) => p.safeCommands.some((c) => c.startsWith('nuclei')));
  if (nucleiSafePlans.length > 0) {
    const allTags = [...new Set(nucleiSafePlans.flatMap((p) => {
      const m = OWASP_CHECK_MAPPINGS.find((x) => x.owaspId === p.owaspId);
      return m ? m.nucleiSafeTags : [];
    }))];
    steps.push({
      order: 1,
      name: 'nuclei-safe-scan',
      description: 'Run nuclei safe templates for tags: ' + allTags.join(','),
      commands: ['nuclei -u "' + u + '" -tags ' + allTags.join(',') + ' -jsonl -rl 3 -c 3 -bs 3 -timeout 5'],
      dependsOn: [],
      parallel: true,
    });
  }

  const httpCmds = plans.flatMap((p) => p.safeCommands.filter((c) => c.startsWith('curl') || c.startsWith('nmap')));
  if (httpCmds.length > 0) {
    steps.push({
      order: 2,
      name: 'http-checks',
      description: 'Run HTTP security header and config checks',
      commands: httpCmds,
      dependsOn: [],
      parallel: true,
    });
  }

  const browserCmds = plans.flatMap((p) => p.browserCommands);
  if (browserCmds.length > 0) {
    steps.push({
      order: 3,
      name: 'browser-checks',
      description: 'Run browser-based OWASP checks (MCP Playwright)',
      commands: browserCmds,
      dependsOn: [],
      parallel: false,
    });
  }

  steps.push({
    order: 4,
    name: 'owasp-report',
    description: 'Generate OWASP Top 10 coverage report',
    commands: [],
    dependsOn: ['nuclei-safe-scan', 'http-checks', 'browser-checks'],
    parallel: false,
  });

  return steps;
}

export function computeOwaspExitCode(results: OwaspValidationResult[]): number {
  const hasFindings = results.some((r) => r.matchedFindings > 0);
  const hasBlocked = results.some((r) => r.status === 'blocked');
  if (hasBlocked) return 1;
  if (hasFindings) return 2;
  return 0;
}
