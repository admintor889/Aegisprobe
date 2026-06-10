import { existsSync } from "node:fs";
import { join as joinPath } from "node:path";
import { newId, nowIso, type FindingSeverity, type SecurityAsset, type SecurityCveMatch, type SecurityEvidence, type SecurityFinding, type SecurityPhase, type SecurityTechnology, type SecurityToolRunStatus, type SecurityToolFailureCategory, type SecurityValidationCheck, type TargetInput } from "@aegisprobe/shared";
import type {
  NormalizedSecurityObservation,
  OwaspValidationItem,
  SecurityKnowledgeIndex,
  SecurityToolOutputClassification,
  NucleiTemplateKnowledge,
} from "./types.js";
import { uniqueStrings } from "./utils.js";
import { loadSecurityKnowledgeIndex, buildBusinessLogicKnowledgeBase } from "./knowledge-base.js";
import { versionMatches, compareVersions, localAdvisories } from "./pipeline-support.js";
function hostnameForTarget(target: { kind: string; normalized: string }): string {
  if (target.kind === "url") {
    try { return new URL(target.normalized).hostname; } catch { return target.normalized; }
  }
  return target.normalized;
}

import { fingerprint, extractScriptSrc, extractMeta, extractCookies } from "./wappalyzer.js";

export function normalizeSecurityToolOutput(
  toolId: string,
  output: string,
  target: TargetInput
): NormalizedSecurityObservation {
  const normalized: NormalizedSecurityObservation = {
    assets: [],
    technologies: [],
    findings: [],
    cveMatches: [],
    notes: []
  };
  const jsonItems = parseJsonObjects(output);
  const plainLines = output.split(/\r?\n/).map((line) => line.trim()).filter(Boolean);

  switch (toolId) {
    case "subfinder":
      normalizeSubfinder(jsonItems, plainLines, normalized);
      break;
    case "amass":
      normalizeAmass(plainLines, normalized);
      break;
    case "dnsx":
      normalizeDnsx(jsonItems, plainLines, normalized);
      break;
    case "httpx":
      normalizeHttpx(jsonItems, plainLines, normalized, target);
      break;
    case "katana":
      normalizeKatana(jsonItems, plainLines, normalized);
      break;
    case "nuclei-tech":
    case "nuclei-snmp":
    case "nuclei-owasp":
      normalizeNuclei(jsonItems, plainLines, normalized, toolId);
      break;
    case "snmpwalk":
      normalizeSnmpWalk(output, plainLines, normalized, target);
      break;
    case "dirsearch":
      normalizeDirsearch(jsonItems, plainLines, normalized);
      break;
    case "ffuf":
      normalizeFfuf(jsonItems, plainLines, normalized);
      break;
    case "naabu":
    case "naabu-cidr":
      normalizeNaabu(jsonItems, plainLines, normalized);
      break;
    case "nmap":
      normalizeNmap(output, jsonItems, plainLines, normalized);
      break;
    default:
      normalized.notes.push(`No dedicated parser for ${toolId}; raw summary was stored as evidence.`);
  }

  normalized.cveMatches.push(...matchLocalCveKnowledge(normalized.technologies));
  return dedupeNormalizedObservation(normalized);
}

export function classifySecurityToolOutput(
  toolId: string,
  output: string,
  normalized: NormalizedSecurityObservation,
  exitCode?: number
): SecurityToolOutputClassification {
  if (output.startsWith("User denied command:")) {
    return { status: "denied", failureCategory: "user_denied", findingCount: 0, summary: "User denied command execution." };
  }
  if (output.startsWith("Blocked command:")) {
    return { status: "blocked", failureCategory: "blocked", findingCount: 0, summary: "Policy blocked command execution." };
  }

  const findingCount = normalized.findings.length + normalized.cveMatches.length;
  const lower = output.toLowerCase();
  const isNuclei = toolId === "nuclei-tech" || toolId === "nuclei-snmp" || toolId === "nuclei-owasp";
  if (isNuclei) {
    if (/no templates provided|no templates found|could not find template|templates are not provided|failed to read template/.test(lower)) {
      return { status: "failed", failureCategory: "template_error", findingCount, summary: "Nuclei failed before validation because templates were missing or invalid." };
    }
    if (/yaml|unmarshal|parse|malformed/.test(lower) && /template|json|output/.test(lower)) {
      return { status: "failed", failureCategory: "parse_error", findingCount, summary: "Nuclei output or template parsing failed." };
    }
    if (/too many requests|rate limit|http 429|\b429\b/.test(lower)) {
      return { status: "failed", failureCategory: "rate_limited", findingCount, summary: "Nuclei run appears rate-limited." };
    }
    if (/unauthorized|forbidden|requires authentication|http 401|http 403|\b401\b|\b403\b/.test(lower)) {
      return { status: findingCount > 0 ? "success" : "failed", failureCategory: "auth_required", findingCount, summary: "Nuclei saw authentication or authorization barriers." };
    }
    if (/no such host|i\/o timeout|context deadline exceeded|connection refused|network is unreachable|tls handshake timeout|temporary failure/.test(lower)) {
      return { status: "failed", failureCategory: "network_error", findingCount, summary: "Nuclei could not reliably reach the target." };
    }
    if (findingCount === 0 && (exitCode === 0 || /no results found|no vulnerabilities found|no templates matched/.test(lower))) {
      return { status: "no_findings", failureCategory: "no_findings", findingCount: 0, summary: "Nuclei completed with no parseable findings." };
    }
  }

  if (/no such host|i\/o timeout|context deadline exceeded|connection refused|network is unreachable|tls handshake timeout|temporary failure|could not resolve|host seems down/i.test(lower)) {
    return { status: "failed", failureCategory: "network_error", findingCount, summary: `${toolId} could not reliably reach the target.` };
  }
  if (/too many requests|rate limit|http 429|\b429\b/.test(lower)) {
    return { status: "failed", failureCategory: "rate_limited", findingCount, summary: `${toolId} appears rate-limited.` };
  }
  if (/unauthorized|forbidden|requires authentication|http 401|http 403|\b401\b|\b403\b/.test(lower) && findingCount === 0) {
    return { status: "failed", failureCategory: "auth_required", findingCount, summary: `${toolId} observed authentication or authorization barriers.` };
  }
  if (/invalid character|json parse|parse error|malformed|unmarshal|xml syntax/.test(lower)) {
    return { status: "failed", failureCategory: "parse_error", findingCount, summary: `${toolId} output parsing failed or returned malformed data.` };
  }

  if (exitCode !== undefined && exitCode !== 0) {
    const category: SecurityToolFailureCategory = /no such host|timeout|connection refused|network/i.test(output)
      ? "network_error"
      : /parse|json|yaml|unmarshal/i.test(output)
        ? "parse_error"
        : "tool_error";
    return { status: "failed", failureCategory: category, findingCount, summary: `Tool exited with code ${exitCode}.` };
  }

  if (findingCount === 0 && normalized.assets.length === 0 && normalized.technologies.length === 0 && normalized.notes.length === 0) {
    return { status: "no_findings", failureCategory: "no_findings", findingCount: 0, summary: `${toolId} completed but produced no normalized observations.` };
  }

  return {
    status: findingCount === 0 && isNuclei ? "no_findings" : "success",
    failureCategory: findingCount === 0 && isNuclei ? "no_findings" : "none",
    findingCount,
    summary: findingCount > 0 ? `Parsed ${findingCount} finding/CVE signal(s).` : "Tool completed without parser findings."
  };
}

export function matchLocalCveKnowledge(
  technologies: Array<Pick<SecurityTechnology, "target" | "name" | "version" | "evidenceSummary">>,
  projectRoot = process.cwd()
): Array<Omit<SecurityCveMatch, "id" | "sessionId" | "workflowId" | "createdAt">> {
  const matches: Array<Omit<SecurityCveMatch, "id" | "sessionId" | "workflowId" | "createdAt">> = [];
  for (const technology of technologies) {
    for (const advisory of localAdvisories) {
      if (!advisory.products.some((product) => normalizeName(product) === normalizeName(technology.name))) {
        continue;
      }
      if (!technology.version) {
        if (advisory.matchWithoutVersion) {
          matches.push({
            target: technology.target,
            technology: technology.name,
            cveId: advisory.cveId,
            title: advisory.title,
            severity: advisory.severity,
            confidence: "low",
            rationale: `Observed ${technology.name} without a confirmed version. Treat as a candidate only until version evidence is collected.`,
            source: "local-cve-advisory",
            relevanceScore: 45
          });
        }
        continue;
      }
      if (versionMatches(technology.version, advisory)) {
        matches.push({
          target: technology.target,
          technology: `${technology.name} ${technology.version}`,
          cveId: advisory.cveId,
          title: advisory.title,
          severity: advisory.severity,
          confidence: advisory.confidence,
          rationale: `Observed ${technology.name} ${technology.version}; local advisory rule matched ${advisory.rangeLabel}. Validate manually before reporting.`,
          source: "local-cve-advisory",
          relevanceScore: 140
        });
      }
    }
  }
  matches.push(...matchNucleiKnowledgeForTechnologies(technologies, projectRoot));
  return dedupeCveMatches(matches);
}

export function matchNucleiKnowledgeForTechnologies(
  technologies: Array<Pick<SecurityTechnology, "target" | "name" | "version" | "evidenceSummary">>,
  projectRoot = process.cwd(),
  maxMatchesPerTechnology = 20
): Array<Omit<SecurityCveMatch, "id" | "sessionId" | "workflowId" | "createdAt">> {
  const index = loadSecurityKnowledgeIndex(projectRoot);
  if (!index) {
    return [];
  }
  const matches: Array<Omit<SecurityCveMatch, "id" | "sessionId" | "workflowId" | "createdAt">> = [];
  for (const technology of technologies) {
    const techName = normalizeName(technology.name);
    if (!techName || techName.length < 3) {
      continue;
    }
    const candidates = index.templates
      .filter((template) => templateMatchesTechnology(template, technology))
      .filter((template) => templateCompatibleWithObservedVersion(template, technology))
      .map((template) => ({
        template,
        relevance: templateTechnologyRelevance(template, technology)
      }))
      .sort((left, right) =>
        right.relevance - left.relevance
        || cveYear(right.template) - cveYear(left.template)
        || severityRank(right.template.severity) - severityRank(left.template.severity)
        || left.template.id.localeCompare(right.template.id)
      )
      .slice(0, maxMatchesPerTechnology);
    for (const { template, relevance } of candidates) {
      const cveId = template.cveIds[0];
      if (!cveId) {
        continue;
      }
      matches.push({
        target: technology.target,
        technology: technology.version ? `${technology.name} ${technology.version}` : technology.name,
        cveId,
        title: template.name,
        severity: template.severity,
        confidence: technology.version && extractVersions(template.name).includes(cleanVersion(technology.version) ?? "")
          ? "medium"
          : "low",
        rationale: `Local nuclei template index matched observed technology "${technology.name}" to template ${template.id} (relevance ${relevance}). The observed version is "${technology.version ?? "unknown"}"; this remains a candidate unless the template or an authoritative advisory confirms the affected range.`,
        source: `nuclei-template-index:${template.path}`,
        relevanceScore: relevance
      });
    }
  }
  return matches;
}

function templateCompatibleWithObservedVersion(
  template: NucleiTemplateKnowledge,
  technology: Pick<SecurityTechnology, "name" | "version" | "evidenceSummary">
): boolean {
  const observed = cleanVersion(technology.version);
  if (!observed) {
    return true;
  }
  const explicitVersions = uniqueStrings([
    ...extractVersions(template.name),
    ...extractVersions(template.path),
    ...template.tags.flatMap(extractVersions)
  ]);
  if (explicitVersions.length === 0) {
    return true;
  }
  if (explicitVersions.includes(observed)) {
    return true;
  }
  const highestTemplateVersion = explicitVersions
    .sort(compareVersions)
    .at(-1);
  if (highestTemplateVersion && compareVersions(observed, highestTemplateVersion) > 0) {
    return false;
  }
  return true;
}

function extractVersions(value: string): string[] {
  return [...value.matchAll(/\b\d+(?:\.\d+){1,3}\b/g)].map((match) => match[0]);
}

function templateMatchesTechnology(
  template: NucleiTemplateKnowledge,
  technology: Pick<SecurityTechnology, "name" | "version" | "evidenceSummary">
): boolean {
  const techName = normalizeName(technology.name);
  const product = normalizeName(template.product ?? "");
  const vendor = normalizeName(template.vendor ?? "");
  const title = normalizeName(template.name);
  const tags = template.tags.map(normalizeName);
  if (product && (product === techName || techName.includes(product) || product.includes(techName))) {
    return true;
  }
  if (vendor && vendor === techName) {
    return true;
  }
  if (tags.includes(techName)) {
    return true;
  }
  if (title.includes(techName) && techName.length >= 5) {
    return true;
  }
  const evidence = normalizeName(technology.evidenceSummary ?? "");
  return evidence.length >= 5 && (title.includes(evidence) || tags.includes(evidence));
}

function templateTechnologyRelevance(
  template: NucleiTemplateKnowledge,
  technology: Pick<SecurityTechnology, "name" | "version" | "evidenceSummary">
): number {
  const techName = normalizeName(technology.name);
  const product = normalizeName(template.product ?? "");
  const vendor = normalizeName(template.vendor ?? "");
  const title = normalizeName(template.name);
  const tags = template.tags.map(normalizeName);
  const technologyTokens = meaningfulTokens(`${technology.name} ${technology.evidenceSummary ?? ""}`);
  const templateTokens = new Set(meaningfulTokens([
    template.name,
    template.product ?? "",
    template.vendor ?? "",
    ...template.tags
  ].join(" ")));

  let score = 0;
  if (product === techName) score += 80;
  else if (product && (techName.includes(product) || product.includes(techName))) score += 65;
  if (vendor && technologyTokens.includes(vendor)) score += 8;
  if (tags.includes(techName)) score += 24;
  if (title.includes(techName) && techName.length >= 5) score += 18;

  const overlap = technologyTokens.filter((token) => templateTokens.has(token)).length;
  score += Math.min(30, overlap * 6);
  if (template.verified) score += 12;
  if (template.references.length > 0) score += 4;
  if (template.tags.some((tag) => /^(?:kev|vkev)$/i.test(tag))) score += 4;

  const observedVersion = cleanVersion(technology.version);
  if (observedVersion && extractVersions(template.name).includes(observedVersion)) {
    score += 30;
  }
  return score;
}

function meaningfulTokens(value: string): string[] {
  return [...new Set(
    value
      .toLowerCase()
      .replace(/[^a-z0-9.+_-]+/g, " ")
      .split(/\s+/)
      .map((token) => token.trim())
      .filter((token) => token.length >= 3 && !/^\d+(?:\.\d+)*$/.test(token))
  )];
}

function cveYear(template: NucleiTemplateKnowledge): number {
  const cve = template.cveIds[0] ?? template.id;
  const year = Number(/\bCVE-(\d{4})-/i.exec(cve)?.[1] ?? 0);
  return Number.isFinite(year) ? year : 0;
}

function severityRank(severity: FindingSeverity): number {
  return ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 })[severity];
}

export function buildOwaspValidationMatrix(target: TargetInput): OwaspValidationItem[] {
  const targetLabel = `${target.kind}:${target.normalized}`;
  return [
    {
      id: "A01",
      title: "Broken Access Control",
      category: "OWASP Top 10 2021 A01",
      passiveSignals: ["admin routes", "ID-like path parameters", "missing authorization assumptions in API routes"],
      safeChecks: [`Review discovered routes for ${targetLabel} and require credentials before any IDOR/access-control validation.`],
      activeRequiresApproval: true
    },
    {
      id: "A02",
      title: "Cryptographic Failures",
      category: "OWASP Top 10 2021 A02",
      passiveSignals: ["missing HSTS", "weak TLS hints", "mixed-content URLs", "sensitive data in client assets"],
      safeChecks: ["Use header/TLS evidence and frontend asset review; do not attempt credential capture."],
      activeRequiresApproval: false
    },
    {
      id: "A03",
      title: "Injection",
      category: "OWASP Top 10 2021 A03",
      passiveSignals: ["query-heavy endpoints", "search/login/filter forms", "error signatures"],
      safeChecks: ["Only run non-destructive payload checks after explicit authorization and rate limits."],
      activeRequiresApproval: true
    },
    {
      id: "A04",
      title: "Insecure Design",
      category: "OWASP Top 10 2021 A04",
      passiveSignals: ["business workflow assumptions", "missing abuse-case controls", "predictable identifiers"],
      safeChecks: ["Document hypotheses from route/API evidence; require user context for business-logic validation."],
      activeRequiresApproval: false
    },
    {
      id: "A05",
      title: "Security Misconfiguration",
      category: "OWASP Top 10 2021 A05",
      passiveSignals: ["debug headers", "server/version disclosure", "directory listing", "exposed source maps"],
      safeChecks: ["Use httpx/katana/nuclei low-impact evidence and report only evidence-backed exposure."],
      activeRequiresApproval: false
    },
    {
      id: "A06",
      title: "Vulnerable and Outdated Components",
      category: "OWASP Top 10 2021 A06",
      passiveSignals: ["technology versions", "framework fingerprints", "known vulnerable JS libraries"],
      safeChecks: ["Match local CVE/advisory rules only when product/version evidence exists."],
      activeRequiresApproval: false
    },
    {
      id: "A07",
      title: "Identification and Authentication Failures",
      category: "OWASP Top 10 2021 A07",
      passiveSignals: ["login endpoints", "session cookies", "password reset routes", "missing cookie flags"],
      safeChecks: ["Review cookie attributes and auth routes; brute force is out of scope unless explicitly authorized."],
      activeRequiresApproval: true
    },
    {
      id: "A08",
      title: "Software and Data Integrity Failures",
      category: "OWASP Top 10 2021 A08",
      passiveSignals: ["unsigned update flows", "CI/CD endpoints", "source map leakage", "dependency manifests"],
      safeChecks: ["Review exposed files and client bundle metadata; avoid tampering tests."],
      activeRequiresApproval: false
    },
    {
      id: "A09",
      title: "Security Logging and Monitoring Failures",
      category: "OWASP Top 10 2021 A09",
      passiveSignals: ["observable error handling", "missing audit assumptions"],
      safeChecks: ["Record only externally visible evidence; ask for internal context before judging logging maturity."],
      activeRequiresApproval: false
    },
    {
      id: "A10",
      title: "Server-Side Request Forgery",
      category: "OWASP Top 10 2021 A10",
      passiveSignals: ["URL fetch parameters", "webhook/import endpoints", "avatar/image proxy routes"],
      safeChecks: ["Do not perform callback-based SSRF validation without explicit active authorization and a controlled canary endpoint."],
      activeRequiresApproval: true
    }
  ];
}

export function buildSecurityValidationChecks(
  sessionId: string,
  workflowId: string,
  target: TargetInput
): SecurityValidationCheck[] {
  const now = nowIso();
  const owaspChecks: SecurityValidationCheck[] = buildOwaspValidationMatrix(target).map((item) => ({
    id: newId("check"),
    sessionId,
    workflowId,
    checkId: item.id,
    title: item.title,
    category: item.category,
    target: target.normalized,
    phase: phaseForOwaspCheck(item.id),
    status: "pending",
    activeRequiresApproval: item.activeRequiresApproval,
    passiveSignals: item.passiveSignals,
    safeChecks: item.safeChecks,
    rationale: "Awaiting evidence collection.",
    createdAt: now,
    updatedAt: now
  }));
  const businessChecks: SecurityValidationCheck[] = buildBusinessLogicKnowledgeBase().map((item) => ({
    id: newId("check"),
    sessionId,
    workflowId,
    checkId: item.id,
    title: item.title,
    category: `Business Logic: ${item.category}`,
    target: target.normalized,
    phase: "safe_validation" as SecurityPhase,
    status: "pending",
    activeRequiresApproval: true,
    passiveSignals: item.passiveSignals,
    safeChecks: item.safeTestIdeas,
    rationale: "Awaiting route/API evidence and user-provided business context.",
    createdAt: now,
    updatedAt: now
  }));
  return [...owaspChecks, ...businessChecks];
}

function phaseForOwaspCheck(checkId: string): SecurityPhase {
  switch (checkId) {
    case "A02":
    case "A05":
      return "fingerprint";
    case "A06":
    case "A08":
      return "vulnerability_analysis";
    case "A01":
    case "A03":
    case "A07":
    case "A10":
      return "safe_validation";
    default:
      return "frontend";
  }
}

export function parseJsonObjects(output: string): unknown[] {
  const items: unknown[] = [];
  for (const line of output.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || (!trimmed.startsWith("{") && !trimmed.startsWith("["))) {
      continue;
    }
    try {
      const parsed = JSON.parse(trimmed) as unknown;
      if (Array.isArray(parsed)) {
        items.push(...parsed);
      } else {
        items.push(parsed);
      }
    } catch {
      // Tool output often mixes banners and partial lines; keep parsing best-effort.
    }
  }
  return items;
}

function normalizeSubfinder(jsonItems: unknown[], plainLines: string[], normalized: NormalizedSecurityObservation): void {
  for (const item of jsonItems) {
    const host = stringField(item, ["host", "input", "domain"]);
    if (host) {
      addAsset(normalized, "subdomain", host, "tool:subfinder", "high", {
        source: stringField(item, ["source"])
      });
    }
  }
  for (const line of plainLines) {
    const host = line.match(/\b([a-z0-9.-]+\.[a-z]{2,})\b/i)?.[1];
    if (host) addAsset(normalized, "subdomain", host.toLowerCase(), "tool:subfinder", "medium");
  }
}

function normalizeAmass(plainLines: string[], normalized: NormalizedSecurityObservation): void {
  for (const line of plainLines) {
    const host = line.match(/\b([a-z0-9.-]+\.[a-z]{2,})\b/i)?.[1];
    if (host) addAsset(normalized, "subdomain", host.toLowerCase(), "tool:amass", "medium");
  }
}

function normalizeDnsx(jsonItems: unknown[], plainLines: string[], normalized: NormalizedSecurityObservation): void {
  for (const item of jsonItems) {
    const host = stringField(item, ["host", "input", "domain", "raw"]);
    if (host) addAsset(normalized, host.includes(".") ? "subdomain" : "domain", host, "tool:dnsx", "high");
    for (const ip of arrayField(item, ["a", "aaaa", "resp", "all"])) {
      if (isIpAddress(ip)) addAsset(normalized, "ip", ip, "tool:dnsx", "high", { host });
    }
    for (const cname of arrayField(item, ["cname"])) {
      addAsset(normalized, "domain", cname, "tool:dnsx", "medium", { host, record: "CNAME" });
    }
  }
  for (const line of plainLines) {
    for (const ip of line.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
      if (isIpAddress(ip[0])) addAsset(normalized, "ip", ip[0], "tool:dnsx", "medium");
    }
  }
}

function normalizeHttpx(jsonItems: unknown[], plainLines: string[], normalized: NormalizedSecurityObservation, target: TargetInput): void {
  if (jsonItems.length === 0) {
    const techPattern = /\[((?:apache\s+)?shiro|nginx|apache|tomcat|thinkphp|struts2?|spring(?:-?boot)?|weblogic|jboss|wildfly|cloudflare|akamai|wordpress|drupal|joomla|dedecms|discuz|metinfo|zentao|ruoyi|jeecg(?:boot)?|seeyon|weaver|yonyou|kingdee|jenkins|confluence|phpmyadmin|react|vue|next\.?js|express|php)(?:\/([\d.]+))?\]/gi;
    for (const line of plainLines) {
      for (const techMatch of line.matchAll(techPattern)) {
        addTechnology(normalized, target.normalized, techMatch[1] ?? techMatch[0], techMatch[2], "fingerprint", "tool:httpx", "medium", techMatch[0]);
      }
    }
  }
  for (const item of jsonItems) {
    const url = stringField(item, ["url", "input", "host"]) ?? target.normalized;
    addAsset(normalized, "url", url, "tool:httpx", "high", {
      statusCode: numberField(item, ["status_code", "status-code"]),
      title: stringField(item, ["title"]),
      server: stringField(item, ["webserver", "server"]),
      cdn: stringField(item, ["cdn_name", "cdn"]),
      contentLength: numberField(item, ["content_length", "content-length", "cl"]),
      responseTime: stringField(item, ["time", "response-time"])
    });
    const host = stringField(item, ["host", "final_url", "url"]);
    if (host && isIpAddress(host)) addAsset(normalized, "ip", host, "tool:httpx", "medium");
    for (const ip of [...arrayField(item, ["a", "aaaa", "ips"]), ...arrayField(item, ["resolvers"])]) {
      if (isIpAddress(ip)) addAsset(normalized, "ip", ip, "tool:httpx", "medium", { url });
    }
    for (const cname of arrayField(item, ["cname", "cnames"])) {
      addAsset(normalized, "domain", cname, "tool:httpx", "medium", { url, record: "CNAME" });
    }
    const server = stringField(item, ["webserver", "server"]);
    if (server) addServerTechnology(normalized, url, server, "tool:httpx");
    const title = stringField(item, ["title"]);
    if (title && /\bpgadmin\b/i.test(title)) {
      const titleVersion = title.match(/\bpgAdmin\s*(?:4)?\s*([\d.]+)?/i)?.[1];
      addTechnology(normalized, url, "pgAdmin", titleVersion, "admin_panel", "tool:httpx", "high", title);
    }
    for (const tech of arrayField(item, ["tech", "technologies"])) {
      addTechnology(normalized, url, tech, undefined, "fingerprint", "tool:httpx", "medium", tech);
    }
    const cdn = stringField(item, ["cdn_name", "cdn"]);
    if (cdn && cdn !== "false") addTechnology(normalized, url, cdn, undefined, "cdn_waf", "tool:httpx", "medium", `cdn:${cdn}`);
    const status = numberField(item, ["status_code", "status-code"]);
    const favicon = stringField(item, ["favicon", "favicon_hash", "favicon-hash", "mmh3"]);
    const jarm = stringField(item, ["jarm"]);
    const tls = objectField(item, "tls");
    if (favicon) addTechnology(normalized, url, "favicon", favicon, "fingerprint", "tool:httpx", "low", `favicon:${favicon}`);
    if (jarm) addTechnology(normalized, url, "JARM TLS fingerprint", jarm, "fingerprint", "tool:httpx", "low", `jarm:${jarm}`);
    if (tls) {
      const issuer = stringField(tls, ["issuer_dn", "issuer", "issuer_cn"]);
      const subject = stringField(tls, ["subject_dn", "subject", "subject_cn"]);
      if (issuer || subject) {
        normalized.notes.push(`httpx TLS certificate for ${url}: issuer=${issuer ?? "unknown"} subject=${subject ?? "unknown"}`);
      }
    }
    for (const extracted of arrayField(item, ["extracts", "paths", "location"])) {
      if (/^https?:\/\//i.test(extracted) || extracted.startsWith("/")) {
        const discovered = extracted.startsWith("/") ? joinUrlOrigin(url, extracted) : extracted;
        addAsset(normalized, "url", discovered, "tool:httpx", "low", { extractedFrom: url });
        addFrontendSignals(normalized, discovered, "tool:httpx");
      }
    }
    if (status === 401 || status === 403) {
      normalized.findings.push({
        title: `Protected or restricted endpoint observed (${status})`,
        severity: "info",
        confidence: "medium",
        target: url,
        description: `httpx observed HTTP ${status}. This is useful for authorization and attack-surface mapping, not a vulnerability by itself.`,
        evidenceSummary: JSON.stringify({ url, status, title: stringField(item, ["title"]) }).slice(0, 500),
        remediation: "Confirm whether this endpoint is expected to be externally visible and enforce authorization consistently."
      });
    }
  }

  // ── Wappalyzer-powered fingerprinting (~3,500 technology profiles) ──
  if (jsonItems.length > 0) {
    for (const item of jsonItems) {
      const url = stringField(item, ["url", "input", "host"]) ?? stringField(item, ["final_url"]);
      if (!url) continue;
      const hdrs = typeof objectField(item, "header") === "object" ? objectField(item, "header") as Record<string, unknown> : {};
      const headerRecord: Record<string, string> = {};
      for (const [k, v] of Object.entries(hdrs)) { if (typeof v === "string") headerRecord[k] = v; }
      const htmlBody = typeof objectField(item, "body") === "string" ? objectField(item, "body") as string : undefined;
      try {
        const result = fingerprint({ url, headers: headerRecord, html: htmlBody, scriptSrc: htmlBody ? extractScriptSrc(htmlBody) : undefined, cookies: extractCookies(headerRecord), meta: htmlBody ? extractMeta(htmlBody) : undefined });
        for (const tech of result.technologies) {
          if (tech.implied) continue;
          addTechnology(normalized, url, tech.name, tech.version, "fingerprint", "wappalyzer", "high", tech.evidence.slice(0, 3).join("; "));
        }
      } catch { /* skip */ }
    }
  }
}


function normalizeKatana(jsonItems: unknown[], plainLines: string[], normalized: NormalizedSecurityObservation): void {
  const urls = new Set<string>();
  for (const item of jsonItems) {
    const url = stringField(item, ["url", "endpoint", "request", "source"]);
    if (url) urls.add(url);
    const body = stringField(item, ["body", "response", "raw", "content", "javascript"]);
    if (body) {
      addJavaScriptExposureSignals(normalized, body, url ?? "katana-output", "tool:katana");
    }
  }
  for (const line of plainLines) {
    for (const match of line.matchAll(/\bhttps?:\/\/[^\s"'<>]+/gi)) {
      urls.add(match[0]);
    }
  }
  for (const url of urls) {
    addAsset(normalized, "url", url, "tool:katana", "high");
    addFrontendSignals(normalized, url, "tool:katana");
  }
  addJavaScriptExposureSignals(normalized, plainLines.join("\n"), "katana-output", "tool:katana");
}

function normalizeNuclei(jsonItems: unknown[], plainLines: string[], normalized: NormalizedSecurityObservation, toolId: string): void {
  for (const item of jsonItems) {
    const info = objectField(item, "info");
    const name = stringField(info, ["name"]) ?? stringField(item, ["template-id", "template_id"]) ?? "Nuclei matched template";
    const severity = severityField(stringField(info, ["severity"]) ?? stringField(item, ["severity"]));
    const matchedAt = stringField(item, ["matched-at", "matched_at", "host", "url"]) ?? "unknown target";
    const templateId = stringField(item, ["template-id", "template_id"]);
    const classification = objectField(info, "classification");
    const cves = extractCveIds([
      ...arrayField(classification, ["cve-id", "cve_id"]),
      ...arrayField(info, ["tags"]),
      templateId ?? "",
      name
    ]);
    normalized.findings.push({
      title: name,
      severity,
      confidence: toolId === "nuclei-owasp" ? "medium" : "low",
      target: matchedAt,
      description: `Nuclei reported ${name}${templateId ? ` via template ${templateId}` : ""}. Validate evidence before final reporting.`,
      evidenceSummary: JSON.stringify(item).slice(0, 600),
      remediation: "Review the matched template evidence, confirm exploitability in scope, and apply the vendor or configuration remediation."
    });
    for (const cve of cves) {
      normalized.cveMatches.push({
        target: matchedAt,
        technology: name,
        cveId: cve.toUpperCase(),
        title: name,
        severity,
        confidence: "medium",
        rationale: `Nuclei template classification referenced ${cve}.`,
        source: `tool:${toolId}`
      });
    }
  }
  if (jsonItems.length === 0 && plainLines.some((line) => /cve-|critical|high|medium|low/i.test(line))) {
    normalized.notes.push("Nuclei output contained vulnerability-like text but no parseable JSONL item.");
  }
}

function normalizeSnmpWalk(output: string, plainLines: string[], normalized: NormalizedSecurityObservation, target: TargetInput): void {
  const host = hostnameForTarget(target);
  addAsset(normalized, "service", `${host}:161`, "tool:snmpwalk", "high", {
    protocol: "udp",
    community: "public"
  });
  addTechnology(normalized, `${host}:161`, "SNMP", undefined, "service", "tool:snmpwalk", "high", "SNMP walk completed with community public.");

  const joined = plainLines.join("\n");
  const sysDescr = extractSnmpValue(joined, /(?:sysDescr|1\.3\.6\.1\.2\.1\.1\.1\.0)[^=]*=\s*(?:STRING:\s*)?(.+)/i);
  const sysName = extractSnmpValue(joined, /(?:sysName|1\.3\.6\.1\.2\.1\.1\.5\.0)[^=]*=\s*(?:STRING:\s*)?(.+)/i);
  const location = extractSnmpValue(joined, /(?:sysLocation|1\.3\.6\.1\.2\.1\.1\.6\.0)[^=]*=\s*(?:STRING:\s*)?(.+)/i);
  const contact = extractSnmpValue(joined, /(?:sysContact|1\.3\.6\.1\.2\.1\.1\.4\.0)[^=]*=\s*(?:STRING:\s*)?(.+)/i);
  if (sysName) {
    addAsset(normalized, "domain", sysName, "tool:snmpwalk", "medium", { source: "sysName" });
  }
  if (sysDescr) {
    normalized.notes.push(`SNMP sysDescr for ${host}: ${redactSecretLike(sysDescr).slice(0, 300)}`);
    addSnmpTechnologySignals(normalized, `${host}:161`, sysDescr);
  }
  if (location || contact) {
    normalized.notes.push(`SNMP host metadata for ${host}: location=${location ?? "unknown"} contact=${contact ?? "unknown"}`.slice(0, 400));
  }

  const credentialLines = plainLines
    .filter((line) => /\b(pass(?:word)?|pwd|secret|token|key|credential|user(?:name)?|login|web\s*password|community)\b/i.test(line))
    .slice(0, 30);
  if (credentialLines.length > 0) {
    normalized.findings.push({
      title: "SNMP exposed credential-like host metadata",
      severity: "high",
      confidence: "medium",
      target: `${host}:161`,
      description: "SNMP output contains credential-like keys or values. In lab and authorized environments this is a high-value pivot signal; validate the exact context before using or reporting credentials.",
      evidenceSummary: credentialLines.map(redactSecretLike).join("\n").slice(0, 700),
      remediation: "Disable public SNMP communities, restrict SNMP to trusted management networks, rotate exposed credentials, and migrate to SNMPv3 with strong authentication."
    });
  }

  normalized.findings.push({
    title: "SNMP public community exposure",
    severity: "high",
    confidence: "high",
    target: `${host}:161`,
    description: "A successful SNMP walk with the default public community indicates exposed management information and can leak process, network, user, or credential metadata.",
    evidenceSummary: /public/i.test(output) ? "snmpwalk output referenced community public" : "snmpwalk adapter completed using community public",
    remediation: "Remove default communities, enforce SNMPv3, and limit UDP/161 access to an authorized management subnet."
  });

  for (const ip of joined.matchAll(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g)) {
    if (isIpAddress(ip[0])) {
      addAsset(normalized, "ip", ip[0], "tool:snmpwalk", "low", { discoveredFrom: host });
    }
  }
  for (const portLine of plainLines.filter((line) => /\b(?:tcp|udp)\b.*\b(?:listen|listening|port)\b/i.test(line)).slice(0, 20)) {
    normalized.notes.push(`SNMP service/process hint for ${host}: ${redactSecretLike(portLine).slice(0, 250)}`);
  }
}

function extractSnmpValue(output: string, pattern: RegExp): string | undefined {
  const value = output.match(pattern)?.[1]?.trim();
  if (!value) {
    return undefined;
  }
  return value.replace(/^"|"$/g, "");
}

function addSnmpTechnologySignals(normalized: NormalizedSecurityObservation, target: string, sysDescr: string): void {
  const patterns: Array<[RegExp, string]> = [
    [/\bnet-?snmp\b/i, "Net-SNMP"],
    [/\blinux\b/i, "Linux"],
    [/\bubuntu\b/i, "Ubuntu Linux"],
    [/\bdebian\b/i, "Debian Linux"],
    [/\bpostgres(?:ql)?\b/i, "PostgreSQL"],
    [/\bpgadmin\b/i, "pgAdmin"]
  ];
  for (const [pattern, name] of patterns) {
    if (pattern.test(sysDescr)) {
      addTechnology(normalized, target, name, undefined, name.includes("Linux") ? "os" : "service", "tool:snmpwalk", "medium", sysDescr.slice(0, 300));
    }
  }
}

function extractCveIds(values: string[]): string[] {
  const cves = new Set<string>();
  for (const value of values) {
    for (const match of value.matchAll(/\bCVE-\d{4}-\d{4,}\b/gi)) {
      cves.add(match[0].toUpperCase());
    }
  }
  return [...cves];
}

function normalizeDirsearch(jsonItems: unknown[], plainLines: string[], normalized: NormalizedSecurityObservation): void {
  // dirsearch --format=json output: array of result objects or object with results array
  const results = jsonItems.length === 1 && Array.isArray(objectField(jsonItems[0], "results"))
    ? objectField(jsonItems[0], "results") as unknown[]
    : jsonItems;

  for (const result of results) {
    const url = stringField(result, ["url"]);
    const status = numberField(result, ["status"]);
    if (!url) continue;
    const contentLength = numberField(result, ["content-length", "content_length", "length"]);
    const redirect = stringField(result, ["redirect", "redirectLocation", "redirectlocation"]);
    addAsset(normalized, "url", url, "tool:dirsearch", "medium", { status, contentLength, redirect });
    if (redirect && /^https?:\/\//i.test(redirect)) {
      addAsset(normalized, "url", redirect, "tool:dirsearch", "low", { redirectFrom: url });
    }
    if (status && (status === 200 || status === 401 || status === 403)) {
      normalized.findings.push({
        title: `dirsearch discovered: ${url} (HTTP ${status})`,
        severity: status === 200 ? "low" : "info",
        confidence: "medium",
        target: url,
        description: `Recursive directory scan found a path returning HTTP ${status}${redirect ? `, redirecting to ${redirect}` : ""}.`,
        evidenceSummary: JSON.stringify({ url, status, contentLength, redirect }).slice(0, 500),
        remediation: "Confirm the path should be public. If not, restrict access or remove the endpoint."
      });
    }
  }
}

function normalizeFfuf(jsonItems: unknown[], plainLines: string[], normalized: NormalizedSecurityObservation): void {
  for (const item of jsonItems) {
    const results = Array.isArray(objectField(item, "results")) ? objectField(item, "results") as unknown[] : [item];
    for (const result of results) {
      const input = objectField(result, "input");
      const fuzz = stringField(input, ["FUZZ", "fuzz"]) ?? stringField(result, ["FUZZ", "word", "words"]);
      const url = stringField(result, ["url", "input"]) ?? fuzz;
      const status = numberField(result, ["status", "status_code"]);
      if (!url) continue;
      const length = numberField(result, ["length", "content_length", "content-length"]);
      const words = numberField(result, ["words"]);
      const lines = numberField(result, ["lines"]);
      const redirectLocation = stringField(result, ["redirectlocation", "redirect_location"]);
      addAsset(normalized, "url", url, "tool:ffuf", "medium", { status, length, words, lines, redirectLocation });
      if (redirectLocation && /^https?:\/\//i.test(redirectLocation)) {
        addAsset(normalized, "url", redirectLocation, "tool:ffuf", "low", { redirectFrom: url });
      }
      if (status === 200 || status === 401 || status === 403) {
        normalized.findings.push({
          title: `Interesting discovered path (${status})`,
          severity: status === 200 ? "low" : "info",
          confidence: "medium",
          target: url,
          description: `ffuf discovered a path returning HTTP ${status}. Treat as exposure evidence, not a vulnerability by itself.`,
          evidenceSummary: JSON.stringify(result).slice(0, 500),
          remediation: "Confirm whether the path is intended to be public and enforce authentication or remove exposure if needed."
        });
      }
    }
  }
  for (const line of plainLines) {
    const url = line.match(/\bhttps?:\/\/[^\s"'<>]+/i)?.[0];
    if (url) addAsset(normalized, "url", url, "tool:ffuf", "low");
    const path = line.match(/^\s*([/.a-z0-9_-]{2,})\s+\[Status:\s*(\d{3}),\s*Size:\s*(\d+)/i);
    if (path) {
      const target = path[1] ?? "";
      addAsset(normalized, "url", target, "tool:ffuf", "low", { status: Number(path[2]), length: Number(path[3]) });
    }
  }
}

function normalizeNaabu(jsonItems: unknown[], plainLines: string[], normalized: NormalizedSecurityObservation): void {
  const services = new Set<string>();
  for (const item of jsonItems) {
    const host = stringField(item, ["host", "ip", "address"]);
    const port = numberField(item, ["port"]);
    if (host && port) services.add(`${host}:${port}`);
  }
  for (const line of plainLines) {
    const match = line.match(/\b((?:\d{1,3}\.){3}\d{1,3}|[a-z0-9.-]+\.[a-z]{2,}):(\d{1,5})\b/i);
    if (match) services.add(`${match[1]}:${match[2]}`);
  }
  for (const service of services) {
    addAsset(normalized, "service", service, "tool:naabu", "high");
    addDeviceExposureSignal(normalized, service);
  }
}

function normalizeNmap(output: string, jsonItems: unknown[], plainLines: string[], normalized: NormalizedSecurityObservation): void {
  for (const item of jsonItems) {
    const host = stringField(item, ["host", "ip", "address"]);
    const port = numberField(item, ["port"]);
    const service = stringField(item, ["service", "name", "product"]);
    if (host && port) {
      const value = `${host}:${port}`;
      addAsset(normalized, "service", value, "tool:nmap", "high", { service });
      addDeviceExposureSignal(normalized, value);
      if (service) {
        addTechnology(normalized, value, service, stringField(item, ["version"]), "service", "tool:nmap", "medium", JSON.stringify(item).slice(0, 300));
      }
    }
  }

  const xmlHostMatches = [...output.matchAll(/<host\b[\s\S]*?<\/host>/gi)];
  for (const hostBlock of xmlHostMatches) {
    const address = hostBlock[0].match(/<address\s+addr="([^"]+)"/i)?.[1];
    if (!address) {
      continue;
    }
    addAsset(normalized, isIpAddress(address) ? "ip" : "domain", address, "tool:nmap", "medium");
    for (const portMatch of hostBlock[0].matchAll(/<port\s+protocol="([^"]+)"\s+portid="(\d+)"[\s\S]*?<state\s+state="([^"]+)"[\s\S]*?(?:<service\s+([^>]+)>|<\/port>)/gi)) {
      if (portMatch[3] !== "open") {
        continue;
      }
      const port = Number(portMatch[2]);
      const serviceAttrs = portMatch[4] ?? "";
      const product = serviceAttrs.match(/\bproduct="([^"]+)"/i)?.[1] ?? serviceAttrs.match(/\bname="([^"]+)"/i)?.[1];
      const version = serviceAttrs.match(/\bversion="([^"]+)"/i)?.[1];
      const value = `${address}:${port}`;
      addAsset(normalized, "service", value, "tool:nmap", "high", { protocol: portMatch[1], product, version });
      addDeviceExposureSignal(normalized, value);
      if (product) {
        addTechnology(normalized, value, product, version, "service", "tool:nmap", "medium", serviceAttrs);
      }
      for (const cpeMatch of portMatch[0].matchAll(/<cpe>([^<]+)<\/cpe>/gi)) {
        addTechnology(normalized, value, cpeMatch[1] ?? "CPE", undefined, "cpe", "tool:nmap", "medium", cpeMatch[0]);
      }
      for (const scriptMatch of portMatch[0].matchAll(/<script\s+id="([^"]+)"\s+output="([^"]*)"/gi)) {
        const scriptId = scriptMatch[1] ?? "nmap-script";
        const scriptOutput = unescapeXml(scriptMatch[2] ?? "");
        normalized.notes.push(`nmap script ${scriptId} on ${value}: ${scriptOutput.slice(0, 300)}`);
        if (/vulnerable|anonymous|default|weak|expired|self-signed/i.test(scriptOutput)) {
          normalized.findings.push({
            title: `Nmap script signal: ${scriptId}`,
            severity: /vulnerable|default|weak/i.test(scriptOutput) ? "medium" : "info",
            confidence: "medium",
            target: value,
            description: "nmap service script output contains a security-relevant signal. Validate the script context before reporting impact.",
            evidenceSummary: scriptOutput.slice(0, 600),
            remediation: "Review the exposed service configuration and restrict or harden it according to vendor guidance."
          });
        }
        // SNMP-specific signal extraction: community strings, system info, credential-like process args
        if (/snmp/i.test(scriptId)) {
          const communityMatch = scriptOutput.match(/(?:Community|community)(?:\s+string)?[:\s]+(\S+)/i);
          if (communityMatch) {
            normalized.findings.push({
              title: "SNMP community string discovered",
              severity: "medium",
              confidence: "medium",
              target: value,
              description: `SNMP script ${scriptId} revealed community string: ${communityMatch[1]}`,
              evidenceSummary: scriptOutput.slice(0, 500),
              remediation: "Restrict SNMP access to trusted management hosts and replace default community strings."
            });
          }
          const sysDescrMatch = scriptOutput.match(/(?:sysDescr|System)[:\s]+(.+?)(?:\n|$)/i);
          if (sysDescrMatch) {
            normalized.notes.push(`SNMP sysDescr: ${sysDescrMatch[1].slice(0, 200)}`);
            addTechnology(normalized, value, sysDescrMatch[1].slice(0, 100), undefined, "snmp-sysdescr", "tool:nmap", "low", scriptOutput.slice(0, 300));
          }
          // Extract credential-like strings from SNMP process arguments (e.g., "web password: xxx")
          const credMatch = scriptOutput.match(/(?:password|passwd|user|username|login|credential)[\s:=]+(\S+)/gi);
          if (credMatch) {
            for (const cred of credMatch) {
              normalized.findings.push({
                title: "SNMP exposed credential-like string",
                severity: "high",
                confidence: "medium",
                target: value,
                description: `SNMP enumeration revealed a credential-like string: ${cred}. This may grant unauthorized access.`,
                evidenceSummary: scriptOutput.slice(0, 600),
                remediation: "Rotate exposed credentials immediately and restrict SNMP read access."
              });
            }
          }
        }
      }
    }
    const osMatch = hostBlock[0].match(/<osmatch\s+name="([^"]+)"\s+accuracy="([^"]+)"/i);
    if (osMatch) {
      addTechnology(normalized, address, osMatch[1] ?? "Operating system", undefined, "os", "tool:nmap", Number(osMatch[2]) >= 90 ? "medium" : "low", osMatch[0]);
    }
  }

  for (const line of plainLines) {
    const serviceLine = line.match(/^(\d+)\/tcp\s+open\s+([^\s]+)(?:\s+(.+))?/i);
    if (serviceLine) {
      const serviceName = serviceLine[2];
      const product = serviceLine[3]?.trim();
      const host = plainLines.find((candidate) => /Nmap scan report for/i.test(candidate))?.match(/for\s+(.+)$/i)?.[1] ?? "unknown-host";
      const value = `${host}:${serviceLine[1]}`;
      addAsset(normalized, "service", value, "tool:nmap", "medium", { serviceName, product });
      addDeviceExposureSignal(normalized, value);
      if (product || serviceName) {
        addTechnology(normalized, value, product ?? serviceName, undefined, "service", "tool:nmap", "low", line);
      }
    }
  }
}

function addFrontendSignals(normalized: NormalizedSecurityObservation, url: string, source: string): void {
  const lower = url.toLowerCase();
  if (lower.endsWith(".js") || lower.includes(".js?")) {
    addAsset(normalized, "url", url, source, "high", { assetType: "javascript" });
  }
  if (lower.endsWith(".map") || lower.includes(".map?")) {
    normalized.findings.push({
      title: "Exposed source map candidate",
      severity: "low",
      confidence: "medium",
      target: url,
      description: "Crawler evidence found a source-map-like asset. Source maps may expose original client-side source, routes, and implementation details.",
      evidenceSummary: url,
      remediation: "Avoid publishing production source maps unless intentionally protected or stripped of sensitive source."
    });
  }
  if (/\/(?:api|graphql|v\d+|admin|manage|console|swagger|openapi|debug)(?:\/|\?|$)/i.test(url)) {
    normalized.findings.push({
      title: "Sensitive route candidate discovered",
      severity: /\/(?:admin|manage|console|debug)(?:\/|\?|$)/i.test(url) ? "low" : "info",
      confidence: "medium",
      target: url,
      description: "Crawler evidence found an API, administrative, debug, or documentation route candidate. This requires authorization-aware validation.",
      evidenceSummary: url,
      remediation: "Confirm intended exposure, enforce authentication/authorization, and remove debug or documentation routes from public production if not required."
    });
  }
  if (/(?:api[_-]?key|access[_-]?token|secret|client[_-]?secret)=/i.test(url)) {
    normalized.findings.push({
      title: "Credential-like parameter in crawled URL",
      severity: "medium",
      confidence: "medium",
      target: url,
      description: "Crawler evidence found a credential-like parameter name in a URL. This is a leakage candidate until the value and context are reviewed.",
      evidenceSummary: redactSecretLike(url),
      remediation: "Do not place credentials in URLs. Move secrets to server-side storage and rotate any exposed token if confirmed."
    });
  }
}

function addJavaScriptExposureSignals(normalized: NormalizedSecurityObservation, content: string, sourceUrl: string, source: string): void {
  if (!content || !/(function|const|let|var|=>|fetch|axios|XMLHttpRequest|api[_-]?key|token|secret)/i.test(content)) {
    return;
  }
  const endpointMatches = [...content.matchAll(/["'`]((?:\/api\/|\/v\d+\/|\/graphql\b|\/admin\/|\/manage\/|https?:\/\/)[^"'`<>{}\s]{3,220})["'`]/gi)]
    .map((match) => match[1])
    .filter(Boolean);
  for (const endpoint of [...new Set(endpointMatches)].slice(0, 50)) {
    const value = endpoint.startsWith("http") ? endpoint : endpoint;
    addAsset(normalized, "url", value, source, "medium", { sourceUrl, assetType: "javascript-endpoint" });
    if (/\/(?:admin|manage|debug|graphql|swagger|openapi|api)(?:\/|\?|$)/i.test(value)) {
      normalized.findings.push({
        title: "JavaScript-exposed API or administrative route candidate",
        severity: /\/(?:admin|manage|debug)(?:\/|\?|$)/i.test(value) ? "low" : "info",
        confidence: "medium",
        target: value,
        description: "Client-side JavaScript references an API, GraphQL, admin, debug, or documentation route. Validate authorization boundaries before reporting impact.",
        evidenceSummary: redactSecretLike(`${sourceUrl} -> ${value}`),
        remediation: "Ensure sensitive routes enforce server-side authorization and avoid exposing debug or administrative endpoints unintentionally."
      });
    }
  }

  const secretPatterns: Array<[RegExp, string]> = [
    [/\b(?:api[_-]?key|access[_-]?token|secret|client[_-]?secret|authorization)\b\s*[:=]\s*["'`][^"'`]{8,}["'`]/gi, "Credential-like assignment in JavaScript"],
    [/\bAKIA[0-9A-Z]{16}\b/g, "AWS access key pattern in JavaScript"],
    [/\b(?:eyJ[a-zA-Z0-9_-]{20,}\.[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,})\b/g, "JWT-like token in JavaScript"]
  ];
  for (const [pattern, title] of secretPatterns) {
    for (const match of content.matchAll(pattern)) {
      normalized.findings.push({
        title,
        severity: "medium",
        confidence: "medium",
        target: sourceUrl,
        description: "Client-side content contains a credential-like token or key pattern. This is a candidate until the value, environment, and revocation state are confirmed.",
        evidenceSummary: redactSecretLike(match[0]),
        remediation: "Move secrets server-side, rotate confirmed exposed credentials, and review build-time environment variable exposure."
      });
    }
  }
}

function addDeviceExposureSignal(normalized: NormalizedSecurityObservation, service: string): void {
  const port = Number(service.split(":").pop());
  const profile = serviceProfileForPort(port);
  if (!profile) {
    return;
  }
  addTechnology(normalized, service, profile.name, undefined, profile.category, "service-port-profile", "low", `Port ${port} commonly maps to ${profile.name}.`);
  if (!profile.exposureSignal) {
    return;
  }
  normalized.findings.push({
    title: `Exposed ${profile.name} service candidate`,
    severity: "info",
    confidence: "medium",
    target: service,
    description: `Port ${port} commonly maps to ${profile.name}. Treat this as generic service exposure evidence and validate ownership, reachability, and authentication before any follow-up.`,
    evidenceSummary: service,
    remediation: profile.remediation
  });
}

type ServicePortProfile = {
  port: number;
  name: string;
  category: string;
  defaultProbe: boolean;
  httpCandidate?: boolean;
  scheme?: "http" | "https";
  exposureSignal?: boolean;
  remediation: string;
};

export function servicePortProfiles(): ServicePortProfile[] {
  return [
    { port: 22, name: "SSH", category: "remote_access", defaultProbe: true, exposureSignal: true, remediation: "Restrict SSH to trusted administration networks and enforce key-based authentication with strong auditing." },
    { port: 25, name: "SMTP", category: "mail", defaultProbe: true, exposureSignal: true, remediation: "Confirm mail relay exposure is intentional and enforce anti-relay, TLS, and authentication controls." },
    { port: 53, name: "DNS", category: "infrastructure", defaultProbe: true, exposureSignal: true, remediation: "Confirm DNS exposure is intentional and restrict zone transfers to authorized secondaries." },
    { port: 80, name: "HTTP", category: "web", defaultProbe: true, httpCandidate: true, scheme: "http", remediation: "Inventory the HTTP service and enforce expected web security controls." },
    { port: 110, name: "POP3", category: "mail", defaultProbe: true, exposureSignal: true, remediation: "Restrict legacy mail protocols or enforce TLS and strong authentication." },
    { port: 143, name: "IMAP", category: "mail", defaultProbe: true, exposureSignal: true, remediation: "Restrict IMAP exposure or enforce TLS and strong authentication." },
    { port: 161, name: "SNMP", category: "management", defaultProbe: true, exposureSignal: true, remediation: "Restrict SNMP to trusted management networks, change default community strings, and upgrade to SNMPv3 with authentication and encryption." },
    { port: 443, name: "HTTPS", category: "web", defaultProbe: true, httpCandidate: true, scheme: "https", remediation: "Inventory the HTTPS service and enforce expected TLS and web security controls." },
    { port: 554, name: "RTSP camera/media", category: "device", defaultProbe: true, exposureSignal: true, remediation: "Restrict camera/media services to trusted networks and change default credentials." },
    { port: 631, name: "IPP printer", category: "device", defaultProbe: false, exposureSignal: true, remediation: "Restrict printer services to trusted networks and disable unauthenticated administration." },
    { port: 3000, name: "Development HTTP", category: "web", defaultProbe: true, httpCandidate: true, scheme: "http", remediation: "Inventory development web services and verify exposure is intentional." },
    { port: 3306, name: "MySQL/MariaDB", category: "database", defaultProbe: true, exposureSignal: true, remediation: "Restrict database ports to trusted application networks and enforce strong authentication." },
    { port: 3389, name: "RDP", category: "remote_access", defaultProbe: true, exposureSignal: true, remediation: "Restrict RDP to trusted networks and enforce Network Level Authentication." },
    { port: 5000, name: "Development/Admin HTTP", category: "admin_panel", defaultProbe: true, httpCandidate: true, scheme: "http", exposureSignal: true, remediation: "Do not expose development or administrative HTTP services without network restrictions and authentication." },
    { port: 5050, name: "Admin HTTP", category: "admin_panel", defaultProbe: true, httpCandidate: true, scheme: "http", exposureSignal: true, remediation: "Verify the administrative service is intended to be reachable and enforce authentication, patching, and network restrictions." },
    { port: 5432, name: "PostgreSQL", category: "database", defaultProbe: true, exposureSignal: true, remediation: "Restrict database ports to trusted application networks and enforce strong authentication." },
    { port: 5900, name: "VNC", category: "remote_access", defaultProbe: true, exposureSignal: true, remediation: "Restrict VNC to trusted networks and enforce strong authentication." },
    { port: 5985, name: "WinRM HTTP", category: "remote_access", defaultProbe: true, exposureSignal: true, remediation: "Restrict WinRM to trusted management networks and enforce HTTPS with strong authentication." },
    { port: 5986, name: "WinRM HTTPS", category: "remote_access", defaultProbe: true, exposureSignal: true, remediation: "Restrict WinRM to trusted management networks." },
    { port: 6379, name: "Redis", category: "database", defaultProbe: true, exposureSignal: true, remediation: "Restrict Redis to trusted networks and require authentication." },
    { port: 8000, name: "Alternate HTTP", category: "web", defaultProbe: true, httpCandidate: true, scheme: "http", remediation: "Inventory alternate web services and verify they are intentionally exposed." },
    { port: 8080, name: "Alternate HTTP", category: "web", defaultProbe: true, httpCandidate: true, scheme: "http", remediation: "Inventory alternate web services and verify they are intentionally exposed." },
    { port: 8081, name: "Alternate HTTP", category: "web", defaultProbe: true, httpCandidate: true, scheme: "http", remediation: "Inventory alternate web services and verify they are intentionally exposed." },
    { port: 8443, name: "Management HTTPS", category: "admin_panel", defaultProbe: true, httpCandidate: true, scheme: "https", exposureSignal: true, remediation: "Restrict management HTTPS services to trusted networks and enforce strong authentication." },
    { port: 9000, name: "Admin HTTP", category: "admin_panel", defaultProbe: true, httpCandidate: true, scheme: "http", exposureSignal: true, remediation: "Inventory administrative HTTP services and verify exposure is intentional." },
    { port: 9090, name: "Management HTTP", category: "admin_panel", defaultProbe: true, httpCandidate: true, scheme: "http", exposureSignal: true, remediation: "Restrict management web consoles to trusted networks." },
    { port: 9100, name: "JetDirect printer", category: "device", defaultProbe: true, exposureSignal: true, remediation: "Restrict raw printer services to trusted networks and disable unauthenticated printing if not required." },
    { port: 9200, name: "Elasticsearch HTTP", category: "database", defaultProbe: true, httpCandidate: true, scheme: "http", exposureSignal: true, remediation: "Restrict Elasticsearch to trusted networks and require authentication." },
    { port: 9443, name: "Management HTTPS", category: "admin_panel", defaultProbe: true, httpCandidate: true, scheme: "https", exposureSignal: true, remediation: "Restrict management HTTPS services to trusted networks and enforce strong authentication." },
    { port: 10000, name: "Webmin/Admin HTTP", category: "admin_panel", defaultProbe: true, httpCandidate: true, scheme: "http", exposureSignal: true, remediation: "Restrict Webmin/admin panels to trusted networks and enforce patching plus MFA where available." },
    { port: 27017, name: "MongoDB", category: "database", defaultProbe: true, exposureSignal: true, remediation: "Restrict MongoDB to trusted application networks and require authentication." }
  ];
}

export function serviceProfileForPort(port: number): ServicePortProfile | undefined {
  return servicePortProfiles().find((profile) => profile.port === port);
}

function joinUrlOrigin(baseUrl: string, path: string): string {
  try {
    return new URL(path, baseUrl).toString();
  } catch {
    return path;
  }
}

function unescapeXml(value: string): string {
  return value
    .replace(/&quot;/g, "\"")
    .replace(/&apos;/g, "'")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&amp;/g, "&");
}

export function addServerTechnology(normalized: NormalizedSecurityObservation, target: string, server: string, source: string): void {
  const match = server.match(/^([^/\s]+)(?:\/([\w.-]+))?/);
  if (!match) {
    return;
  }
  addTechnology(normalized, target, canonicalTechnologyName(match[1]), match[2], "web_server", source, "medium", server);
}

export function addAsset(
  normalized: NormalizedSecurityObservation,
  kind: SecurityAsset["kind"],
  value: string,
  source: string,
  confidence: SecurityAsset["confidence"],
  metadata?: unknown
): void {
  normalized.assets.push({
    kind,
    value,
    source,
    confidence,
    metadata: metadata === undefined ? undefined : JSON.stringify(metadata)
  });
}

export function addTechnology(
  normalized: NormalizedSecurityObservation,
  target: string,
  name: string,
  version: string | undefined,
  category: string,
  source: string,
  confidence: SecurityTechnology["confidence"],
  evidenceSummary: string
): void {
  const detectedVersion = cleanVersion(version) ?? cleanVersion(name);
  const productName = detectedVersion ? name.replace(detectedVersion, "").replace(/[/:_-]\s*$/, "").trim() : name;
  normalized.technologies.push({
    target,
    name: canonicalTechnologyName(productName || name),
    version: detectedVersion,
    category,
    source,
    confidence,
    evidenceSummary
  });
}

export function dedupeNormalizedObservation(input: NormalizedSecurityObservation): NormalizedSecurityObservation {
  return {
    assets: uniqueBy(input.assets, (item) => `${item.kind}:${item.value}`),
    technologies: uniqueBy(input.technologies, (item) => `${item.target}:${normalizeName(item.name)}:${item.version ?? ""}`),
    findings: uniqueBy(input.findings, (item) => `${item.title}:${item.target}`),
    cveMatches: dedupeCveMatches(input.cveMatches),
    notes: [...new Set(input.notes)]
  };
}

export function dedupeCveMatches<T extends Omit<SecurityCveMatch, "id" | "sessionId" | "workflowId" | "createdAt">>(matches: T[]): T[] {
  const byKey = new Map<string, T>();
  for (const match of matches) {
    const key = [
      normalizeTargetForDedupe(match.target),
      normalizeName(stripVersion(match.technology)),
      (match.cveId ?? match.title).toUpperCase()
    ].join("|");
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, match);
      continue;
    }
    byKey.set(key, mergeCveMatch(existing, match));
  }
  return [...byKey.values()].sort((left, right) =>
    (right.relevanceScore ?? 0) - (left.relevanceScore ?? 0) ||
    severityRank(right.severity) - severityRank(left.severity) ||
    confidenceRank(right.confidence) - confidenceRank(left.confidence) ||
    (left.cveId ?? left.title).localeCompare(right.cveId ?? right.title)
  );
}

function mergeCveMatch<T extends Omit<SecurityCveMatch, "id" | "sessionId" | "workflowId" | "createdAt">>(left: T, right: T): T {
  const severity = severityRank(right.severity) > severityRank(left.severity) ? right.severity : left.severity;
  const confidence = confidenceRank(right.confidence) > confidenceRank(left.confidence) ? right.confidence : left.confidence;
  const sources = [...new Set([left.source, right.source].flatMap((source) => source.split(/\s*\+\s*/)).filter(Boolean))];
  const rationale = [...new Set([left.rationale, right.rationale].filter(Boolean))].join(" ");
  return {
    ...left,
    title: severityRank(right.severity) > severityRank(left.severity) ? right.title : left.title,
    severity,
    confidence,
    source: sources.join(" + "),
    relevanceScore: Math.max(left.relevanceScore ?? 0, right.relevanceScore ?? 0),
    rationale
  };
}

function confidenceRank(confidence: "low" | "medium" | "high"): number {
  return ({ low: 0, medium: 1, high: 2 })[confidence];
}

function stripVersion(value: string): string {
  return value.replace(/\s+\d+(?:\.\d+){0,3}(?:[-+][\w.]+)?$/u, "").trim();
}

function normalizeTargetForDedupe(value: string): string {
  return value.trim().toLowerCase().replace(/\/+$/u, "");
}

function uniqueBy<T>(items: T[], keyOf: (item: T) => string): T[] {
  const seen = new Set<string>();
  const output: T[] = [];
  for (const item of items) {
    const key = keyOf(item).toLowerCase();
    if (seen.has(key)) continue;
    seen.add(key);
    output.push(item);
  }
  return output;
}

export function stringField(input: unknown, keys: string[]): string | undefined {
  if (!input || typeof input !== "object") return undefined;
  const record = input as Record<string, unknown>;
  for (const key of keys) {
    const value = record[key];
    if (typeof value === "string" && value.trim()) return value.trim();
    if (typeof value === "number") return String(value);
  }
  return undefined;
}

export function numberField(input: unknown, keys: string[]): number | undefined {
  const value = stringField(input, keys);
  if (!value) return undefined;
  const numeric = Number(value);
  return Number.isFinite(numeric) ? numeric : undefined;
}

export function arrayField(input: unknown, keys: string[]): string[] {
  if (!input || typeof input !== "object") return [];
  const record = input as Record<string, unknown>;
  const values: string[] = [];
  for (const key of keys) {
    const value = record[key];
    if (Array.isArray(value)) {
      values.push(...value.filter((item): item is string => typeof item === "string"));
    } else if (typeof value === "string" && value.trim()) {
      values.push(value.trim());
    }
  }
  return values;
}

export function objectField(input: unknown, key: string): unknown {
  if (!input || typeof input !== "object") return undefined;
  return (input as Record<string, unknown>)[key];
}

export function severityField(value: string | undefined): FindingSeverity {
  switch (value?.toLowerCase()) {
    case "critical":
    case "high":
    case "medium":
    case "low":
    case "info":
      return value.toLowerCase() as FindingSeverity;
    default:
      return "info";
  }
}

function isIpAddress(value: string): boolean {
  const parts = value.split(".");
  return parts.length === 4 && parts.every((part) => {
    const n = Number(part);
    return /^\d+$/.test(part) && n >= 0 && n <= 255;
  });
}

function canonicalTechnologyName(name: string): string {
  const normalized = normalizeName(name);
  const aliases: Record<string, string> = {
    apache: "Apache HTTP Server",
    httpd: "Apache HTTP Server",
    apacheshiro: "Apache Shiro",
    shiro: "Apache Shiro",
    thinkphp: "ThinkPHP",
    dedecms: "DedeCMS",
    discuz: "Discuz!",
    metinfo: "MetInfo",
    zentao: "ZenTao",
    seeyon: "Seeyon OA",
    fanweioa: "Weaver OA",
    weaveroa: "Weaver OA",
    yonyou: "Yonyou",
    ruoyi: "RuoYi",
    jeecgboot: "JeecgBoot",
    jeecg: "JeecgBoot",
    weblogic: "Oracle WebLogic Server",
    struts: "Apache Struts",
    struts2: "Apache Struts",
    spring: "Spring Framework",
    springboot: "Spring Boot",
    tomcat: "Apache Tomcat",
    jboss: "JBoss/WildFly",
    wildfly: "JBoss/WildFly",
    confluence: "Atlassian Confluence",
    jenkins: "Jenkins",
    drupal: "Drupal",
    joomla: "Joomla",
    magento: "Magento",
    phpcms: "PHPCMS",
    empirecms: "EmpireCMS",
    phpmyadmin: "phpMyAdmin",
    pgadmin: "pgAdmin",
    postgresql: "PostgreSQL",
    postgres: "PostgreSQL",
    lighttpd: "lighttpd",
    werkzeug: "Werkzeug",
    flask: "Flask",
    python: "Python",
    nginx: "nginx",
    jquery: "jQuery",
    wordpress: "WordPress",
    php: "PHP",
    cloudflare: "Cloudflare",
    akamai: "Akamai",
    react: "React",
    vue: "Vue.js",
    nextjs: "Next.js",
    next: "Next.js",
    express: "Express"
  };
  return aliases[normalized] ?? name.trim();
}

function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

function cleanVersion(version: string | undefined): string | undefined {
  const match = version?.match(/\d+(?:\.\d+){0,3}/);
  return match?.[0];
}

function redactSecretLike(value: string): string {
  return value.replace(/((?:api[_-]?key|access[_-]?token|secret|client[_-]?secret)=)[^&\s]+/gi, "$1[redacted]");
}
