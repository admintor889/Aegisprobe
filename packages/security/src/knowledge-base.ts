import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join as joinPath, relative as relativePath } from "node:path";
import { spawnSync } from "node:child_process";
import { newId, nowIso, type FindingSeverity } from "@aegisprobe/shared";
import type {
  BusinessLogicKnowledgeItem,
  FrameworkKnowledgeProfile,
  FrameworkKnowledgeIndex,
  NucleiTemplateKnowledge,
  SecurityKnowledgeIndex,
  SecurityKnowledgeSearchResult,
  SecurityKnowledgeSyncResult,
  FrameworkKnowledgeSeed,
} from "./types.js";
import { curatedFrameworkSeeds } from "./pipeline-support.js";
import { uniqueBy, normalizeName, uniqueStrings, severityRank } from "./utils.js";
export { uniqueStrings, severityRank };

function severityField(value: string | undefined): any {
  const s = (value ?? "").toLowerCase();
  if (s === "critical") return "critical";
  if (s === "high") return "high";
  if (s === "medium") return "medium";
  if (s === "low") return "low";
  return "info";
}



export function securityKnowledgeRoot(projectRoot = process.cwd()): string {
  return joinPath(projectRoot, "data", "security-knowledge");
}

export function nucleiTemplatesRoot(projectRoot = process.cwd()): string {
  return joinPath(projectRoot, "tools", "templates", "nuclei-templates");
}

export function wappalyzerRoot(projectRoot = process.cwd()): string {
  return joinPath(projectRoot, "third_party", "security-tools", "wappalyzer");
}

export function wappalyzerTechnologiesRoot(projectRoot = process.cwd()): string {
  return joinPath(wappalyzerRoot(projectRoot), "src", "technologies");
}

export function securityKnowledgeIndexPath(projectRoot = process.cwd()): string {
  return joinPath(securityKnowledgeRoot(projectRoot), "nuclei-cve-index.json");
}

export function frameworkKnowledgeIndexPath(projectRoot = process.cwd()): string {
  return joinPath(securityKnowledgeRoot(projectRoot), "framework-knowledge.json");
}

export function businessLogicKnowledgePath(projectRoot = process.cwd()): string {
  return joinPath(securityKnowledgeRoot(projectRoot), "business-logic-knowledge.json");
}

export function syncSecurityKnowledge(projectRoot = process.cwd()): SecurityKnowledgeSyncResult {
  const sourcePath = nucleiTemplatesRoot(projectRoot);
  if (!existsSync(sourcePath)) {
    throw new Error(`nuclei templates are missing: ${sourcePath}. Run tools/sync-security-knowledge.ps1 first.`);
  }

  const index = buildNucleiKnowledgeIndex(sourcePath);
  const indexPath = securityKnowledgeIndexPath(projectRoot);
  const logicPath = businessLogicKnowledgePath(projectRoot);
  const frameworkPath = frameworkKnowledgeIndexPath(projectRoot);
  const frameworkIndex = buildFrameworkKnowledgeIndex({
    nucleiIndex: index,
    nucleiSourcePath: sourcePath,
    wappalyzerSourcePath: wappalyzerTechnologiesRoot(projectRoot),
    categoriesPath: joinPath(wappalyzerRoot(projectRoot), "src", "categories.json")
  });
  mkdirSync(dirname(indexPath), { recursive: true });
  writeFileSync(indexPath, `${JSON.stringify(index, null, 2)}\n`, "utf8");
  writeFileSync(frameworkPath, `${JSON.stringify(frameworkIndex, null, 2)}\n`, "utf8");
  writeFileSync(logicPath, `${JSON.stringify(buildBusinessLogicKnowledgeBase(), null, 2)}\n`, "utf8");
  return {
    indexPath,
    businessLogicPath: logicPath,
    frameworkKnowledgePath: frameworkPath,
    templateCount: index.templateCount,
    cveTemplateCount: index.cveTemplateCount,
    cveCount: index.cveCount,
    frameworkProfileCount: frameworkIndex.profileCount
  };
}

export function loadSecurityKnowledgeIndex(projectRoot = process.cwd()): SecurityKnowledgeIndex | undefined {
  const path = securityKnowledgeIndexPath(projectRoot);
  if (!existsSync(path)) {
    return undefined;
  }
  return JSON.parse(readFileSync(path, "utf8")) as SecurityKnowledgeIndex;
}

export function loadFrameworkKnowledgeIndex(projectRoot = process.cwd()): FrameworkKnowledgeIndex | undefined {
  const path = frameworkKnowledgeIndexPath(projectRoot);
  if (!existsSync(path)) {
    return undefined;
  }
  return JSON.parse(readFileSync(path, "utf8")) as FrameworkKnowledgeIndex;
}

export function loadBusinessLogicKnowledge(projectRoot = process.cwd()): BusinessLogicKnowledgeItem[] {
  const path = businessLogicKnowledgePath(projectRoot);
  if (existsSync(path)) {
    return JSON.parse(readFileSync(path, "utf8")) as BusinessLogicKnowledgeItem[];
  }
  return buildBusinessLogicKnowledgeBase();
}

export function searchSecurityKnowledge(query: string, projectRoot = process.cwd(), limit = 20): SecurityKnowledgeSearchResult[] {
  const normalizedQuery = query.trim().toLowerCase();
  if (!normalizedQuery) {
    return [];
  }
  const results: SecurityKnowledgeSearchResult[] = [];
  const index = loadSecurityKnowledgeIndex(projectRoot);
  if (index) {
    for (const cve of index.cves) {
      const haystack = [cve.cveId, ...cve.products, ...cve.templates].join(" ").toLowerCase();
      if (haystack.includes(normalizedQuery)) {
        results.push({
          kind: "cve",
          id: cve.cveId,
          title: `${cve.cveId} (${cve.templateCount} nuclei templates)`,
          severity: highestSeverity(cve.severities),
          source: index.source,
          summary: `products=${cve.products.slice(0, 5).join(", ") || "unknown"} templates=${cve.templates.slice(0, 3).join(", ")}`
        });
      }
    }
    for (const template of index.templates) {
      const haystack = [
        template.id,
        template.name,
        template.product,
        template.vendor,
        template.path,
        ...template.cveIds,
        ...template.cweIds,
        ...template.tags
      ].filter(Boolean).join(" ").toLowerCase();
      if (haystack.includes(normalizedQuery)) {
        results.push({
          kind: "template",
          id: template.id,
          title: template.name,
          severity: template.severity,
          source: template.path,
          summary: `cves=${template.cveIds.join(", ") || "none"} tags=${template.tags.slice(0, 8).join(", ")}`
        });
      }
    }
  }
  for (const item of loadBusinessLogicKnowledge(projectRoot)) {
    const haystack = [
      item.id,
      item.title,
      item.category,
      ...item.owaspRefs,
      ...item.apiRefs,
      ...item.passiveSignals,
      ...item.safeTestIdeas
    ].join(" ").toLowerCase();
    if (haystack.includes(normalizedQuery)) {
      results.push({
        kind: "business_logic",
        id: item.id,
        title: item.title,
        severity: item.risk,
        source: item.category,
        summary: item.safeTestIdeas.slice(0, 2).join(" ")
      });
    }
  }
  const frameworkIndex = loadFrameworkKnowledgeIndex(projectRoot);
  if (frameworkIndex) {
    for (const profile of frameworkIndex.profiles) {
      const haystack = [
        profile.id,
        profile.name,
        profile.ecosystem,
        ...profile.aliases,
        ...profile.categories,
        ...profile.riskFocus,
        ...profile.fingerprintSignals,
        ...profile.topCves,
        ...profile.topTemplates,
        ...profile.topTags
      ].join(" ").toLowerCase();
      if (haystack.includes(normalizedQuery)) {
        results.push({
          kind: "framework",
          id: profile.id,
          title: profile.name,
          severity: profile.riskFocus.some((item) => /rce|auth-bypass|deserialization/i.test(item)) ? "high" : "info",
          source: profile.sources.join(", "),
          summary: `ecosystem=${profile.ecosystem} templates=${profile.templateCount} cves=${profile.cveCount} cnvd=${profile.cnvdCount} risks=${profile.riskFocus.slice(0, 8).join(", ")}`
        });
      }
    }
  }
  return uniqueBy(results, (item) => `${item.kind}:${item.id}:${item.source}`).slice(0, limit);
}

export function buildNucleiKnowledgeIndex(sourcePath: string): SecurityKnowledgeIndex {
  const templates = listTemplateFiles(sourcePath)
    .map((file) => parseNucleiTemplateKnowledge(sourcePath, file))
    .filter((template): template is NucleiTemplateKnowledge => template !== undefined);
  const cveTemplates = templates.filter((template) => template.cveIds.length > 0 || template.tags.some((tag) => /^cve\d{4}$/i.test(tag)));
  const byCve = new Map<string, NucleiTemplateKnowledge[]>();
  for (const template of cveTemplates) {
    for (const cveId of template.cveIds) {
      const existing = byCve.get(cveId) ?? [];
      existing.push(template);
      byCve.set(cveId, existing);
    }
  }
  const cves = [...byCve.entries()]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([cveId, matches]) => ({
      cveId,
      templateCount: matches.length,
      severities: [...new Set(matches.map((item) => item.severity))],
      products: [...new Set(matches.flatMap((item) => [item.vendor, item.product].filter(Boolean) as string[]))].slice(0, 20),
      templates: matches.map((item) => item.id).slice(0, 50)
    }));

  return {
    schemaVersion: 1,
    generatedAt: nowIso(),
    source: "projectdiscovery/nuclei-templates",
    sourcePath,
    templateCount: templates.length,
    cveTemplateCount: cveTemplates.length,
    cveCount: cves.length,
    templates,
    cves
  };
}

type WappalyzerTechnologyProfile = {
  name: string;
  categories: string[];
  cpe?: string;
  website?: string;
  description?: string;
  signals: string[];
};

type FrameworkSourceOptions = {
  nucleiIndex?: SecurityKnowledgeIndex;
  nucleiSourcePath?: string;
  wappalyzerSourcePath?: string;
  categoriesPath?: string;
};

export function buildFrameworkKnowledgeIndex(options: FrameworkSourceOptions = {}): FrameworkKnowledgeIndex {
  const categoryNames = loadWappalyzerCategoryNames(options.categoriesPath);
  const wappalyzerProfiles = options.wappalyzerSourcePath && existsSync(options.wappalyzerSourcePath)
    ? loadWappalyzerTechnologyProfiles(options.wappalyzerSourcePath, categoryNames)
    : [];
  const wappalyzerByName = new Map(wappalyzerProfiles.map((profile) => [normalizeName(profile.name), profile]));
  const nucleiTemplates = options.nucleiIndex?.templates ?? [];
  const profiles = curatedFrameworkSeeds.map((seed) => {
    const aliases = uniqueStrings([seed.name, ...seed.aliases]);
    const matchingWappalyzer = aliases
      .map((alias) => wappalyzerByName.get(normalizeName(alias)))
      .find((profile): profile is WappalyzerTechnologyProfile => profile !== undefined);
    const matchingTemplates = nucleiTemplates.filter((template) => frameworkSeedMatchesTemplate(seed, template));
    const cves = uniqueStrings(matchingTemplates.flatMap((template) => template.cveIds)).sort();
    const tags = uniqueStrings(matchingTemplates.flatMap((template) => template.tags)).sort();
    const risks = uniqueStrings([
      ...seed.riskFocus,
      ...tags.map(riskFromTag).filter((item): item is string => Boolean(item))
    ]);
    const sources = uniqueStrings([
      matchingWappalyzer ? "wappalyzer-technologies" : undefined,
      matchingTemplates.length > 0 ? "projectdiscovery/nuclei-templates" : undefined,
      "curated-framework-intel"
    ].filter(Boolean) as string[]);

    return {
      id: `fw-${normalizeName(seed.name)}`,
      name: seed.name,
      aliases,
      categories: uniqueStrings([...(matchingWappalyzer?.categories ?? []), ...seed.categories]),
      ecosystem: seed.ecosystem,
      riskFocus: risks.slice(0, 20),
      fingerprintSignals: uniqueStrings([...(matchingWappalyzer?.signals ?? []), ...seed.fingerprintSignals]).slice(0, 30),
      cpe: matchingWappalyzer?.cpe ?? seed.cpe,
      website: matchingWappalyzer?.website ?? seed.website,
      sources,
      templateCount: matchingTemplates.length,
      cveCount: cves.length,
      cnvdCount: matchingTemplates.filter((template) => /^CNVD-|^CNV-D|^CNVD/i.test(template.id) || template.tags.some((tag) => tag.startsWith("cnvd"))).length,
      topCves: cves.slice(-20).reverse(),
      topTemplates: matchingTemplates
        .sort((left, right) => severityRank(right.severity) - severityRank(left.severity))
        .map((template) => template.id)
        .slice(0, 25),
      topTags: tags.slice(0, 30),
      verifiedTemplateCount: matchingTemplates.filter((template) => template.verified).length
    } satisfies FrameworkKnowledgeProfile;
  }).sort((left, right) => right.templateCount - left.templateCount || left.name.localeCompare(right.name));

  return {
    schemaVersion: 1,
    generatedAt: nowIso(),
    sources: {
      wappalyzer: options.wappalyzerSourcePath,
      nuclei: options.nucleiSourcePath ?? options.nucleiIndex?.sourcePath,
      curated: "packages/security/src/index.ts#curatedFrameworkSeeds"
    },
    wappalyzerTechnologyCount: wappalyzerProfiles.length,
    profileCount: profiles.length,
    profiles
  };
}

export function loadWappalyzerCategoryNames(path: string | undefined): Map<number, string> {
  const categories = new Map<number, string>();
  if (!path || !existsSync(path)) {
    return categories;
  }
  const parsed = JSON.parse(readFileSync(path, "utf8")) as Record<string, { name?: string }>;
  for (const [id, category] of Object.entries(parsed)) {
    if (category.name) {
      categories.set(Number(id), category.name);
    }
  }
  return categories;
}

export function loadWappalyzerTechnologyProfiles(root: string, categories: Map<number, string>): WappalyzerTechnologyProfile[] {
  const files = readdirSync(root)
    .filter((item) => item.endsWith(".json"))
    .map((item) => joinPath(root, item));
  const profiles: WappalyzerTechnologyProfile[] = [];
  for (const file of files) {
    const parsed = JSON.parse(readFileSync(file, "utf8")) as Record<string, Record<string, unknown>>;
    for (const [name, data] of Object.entries(parsed)) {
      const categoryIds = Array.isArray(data.cats) ? data.cats.filter((item): item is number => typeof item === "number") : [];
      profiles.push({
        name,
        categories: categoryIds.map((id) => categories.get(id) ?? String(id)),
        cpe: typeof data.cpe === "string" ? data.cpe : undefined,
        website: typeof data.website === "string" ? data.website : undefined,
        description: typeof data.description === "string" ? data.description : undefined,
        signals: extractWappalyzerSignals(data)
      });
    }
  }
  return profiles;
}

export function extractWappalyzerSignals(data: Record<string, unknown>): string[] {
  const signals: string[] = [];
  for (const key of ["cookies", "headers", "html", "js", "meta", "scriptSrc", "url", "dom", "robots"]) {
    const value = data[key];
    if (typeof value === "string") {
      signals.push(`${key}:${value.slice(0, 80)}`);
    } else if (Array.isArray(value)) {
      signals.push(...value.slice(0, 5).map((item) => `${key}:${String(item).slice(0, 80)}`));
    } else if (value && typeof value === "object") {
      signals.push(...Object.keys(value as Record<string, unknown>).slice(0, 8).map((item) => `${key}:${item}`));
    }
  }
  return uniqueStrings(signals);
}

export function frameworkSeedMatchesTemplate(seed: FrameworkKnowledgeSeed, template: NucleiTemplateKnowledge): boolean {
  const aliases = seed.aliases.map(normalizeName).concat(normalizeName(seed.name));
  const haystack = [
    template.id,
    template.name,
    template.product,
    template.vendor,
    template.path,
    ...template.tags,
    ...template.references
  ].filter(Boolean).join(" ").toLowerCase();
  const normalizedHaystack = normalizeName(haystack);
  return aliases.some((alias) => alias.length >= 4 && normalizedHaystack.includes(alias));
}

export function riskFromTag(tag: string): string | undefined {
  const normalized = tag.toLowerCase();
  const mapping: Record<string, string> = {
    rce: "rce",
    sqli: "sqli",
    sql: "sqli",
    xss: "xss",
    lfi: "lfi",
    rfi: "rfi",
    ssrf: "ssrf",
    deserialization: "deserialization",
    auth: "auth",
    "auth-bypass": "auth-bypass",
    upload: "upload",
    fileupload: "upload",
    disclosure: "information-disclosure",
    exposure: "exposure",
    traversal: "path-traversal",
    defaultlogin: "default-login",
    default: "default-login",
    takeover: "takeover",
    misconfig: "misconfiguration"
  };
  return mapping[normalized];
}

export function listTemplateFiles(root: string): string[] {
  const files: string[] = [];
  const visit = (directory: string) => {
    for (const item of readdirSync(directory)) {
      if (item === ".git" || item === ".github" || item === "helpers") {
        continue;
      }
      const path = joinPath(directory, item);
      const stat = statSync(path);
      if (stat.isDirectory()) {
        visit(path);
        continue;
      }
      if (/\.(ya?ml)$/i.test(item)) {
        files.push(path);
      }
    }
  };
  visit(root);
  return files;
}

export function parseNucleiTemplateKnowledge(root: string, file: string): NucleiTemplateKnowledge | undefined {
  const content = readFileSync(file, "utf8");
  const id = scalarAt(content, "id");
  const name = scalarAt(content, "name") ?? id;
  if (!id || !name) {
    return undefined;
  }
  const tags = csvScalarAt(content, "tags");
  const cveIds = [...new Set(content.match(/\bCVE-\d{4}-\d{4,}\b/gi)?.map((item) => item.toUpperCase()) ?? [])];
  const cweIds = [...new Set(content.match(/\bCWE-\d+\b/gi)?.map((item) => item.toUpperCase()) ?? [])];
  const references = listBlockAt(content, "reference").filter((item) => /^https?:\/\//i.test(item)).slice(0, 20);
  return {
    id,
    name,
    severity: severityField(scalarAt(content, "severity")),
    path: relativePath(root, file).replace(/\\/g, "/"),
    cveIds,
    cweIds,
    tags,
    references,
    vendor: scalarAt(content, "vendor"),
    product: scalarAt(content, "product"),
    verified: booleanScalarAt(content, "verified"),
    maxRequest: numericScalarAt(content, "max-request") ?? numericScalarAt(content, "max_request")
  };
}

export function scalarAt(content: string, key: string): string | undefined {
  const escaped = key.replace(/[-/\\^$*+?.()|[\]{}]/g, "\\$&");
  const match = content.match(new RegExp(`(?:^|\\n)\\s*${escaped}:\\s*([^\\n#]+)`, "i"));
  return match ? cleanYamlScalar(match[1]) : undefined;
}

export function csvScalarAt(content: string, key: string): string[] {
  const value = scalarAt(content, key);
  if (!value) {
    return [];
  }
  const arrayMatch = value.match(/^\[(.*)\]$/);
  const body = arrayMatch ? arrayMatch[1] : value;
  return body.split(",").map((item) => cleanYamlScalar(item)).filter(Boolean);
}

export function listBlockAt(content: string, key: string): string[] {
  const lines = content.split(/\r?\n/);
  const output: string[] = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (!new RegExp(`^\\s*${key}:\\s*$`, "i").test(lines[index] ?? "")) {
      continue;
    }
    const indent = (lines[index]?.match(/^(\s*)/)?.[1].length ?? 0);
    for (let cursor = index + 1; cursor < lines.length; cursor += 1) {
      const line = lines[cursor] ?? "";
      const currentIndent = line.match(/^(\s*)/)?.[1].length ?? 0;
      if (line.trim() && currentIndent <= indent) {
        break;
      }
      const item = line.trim().replace(/^-\s*/, "");
      if (item) {
        output.push(cleanYamlScalar(item));
      }
    }
    break;
  }
  return output;
}

export function cleanYamlScalar(value: string): string {
  return value.trim().replace(/^["']|["']$/g, "").replace(/\s+#.*$/, "").trim();
}

export function booleanScalarAt(content: string, key: string): boolean | undefined {
  const value = scalarAt(content, key)?.toLowerCase();
  if (value === "true") return true;
  if (value === "false") return false;
  return undefined;
}

export function numericScalarAt(content: string, key: string): number | undefined {
  const value = scalarAt(content, key);
  if (!value) return undefined;
  const parsed = Number.parseInt(value, 10);
  return Number.isFinite(parsed) ? parsed : undefined;
}

export function highestSeverity(severities: FindingSeverity[]): FindingSeverity {
  const rank: Record<FindingSeverity, number> = { info: 0, low: 1, medium: 2, high: 3, critical: 4 };
  return severities.reduce((highest, severity) => rank[severity] > rank[highest] ? severity : highest, "info");
}

export function buildBusinessLogicKnowledgeBase(): BusinessLogicKnowledgeItem[] {
  return [
    {
      id: "BL-001",
      title: "Object ownership and IDOR/BOLA validation",
      category: "access-control",
      risk: "high",
      owaspRefs: ["OWASP WSTG 4.5 Authorization Testing", "OWASP Top 10 A01"],
      apiRefs: ["API1:2023 Broken Object Level Authorization"],
      passiveSignals: ["numeric or UUID object IDs", "routes containing /order/, /user/, /invoice/, /ticket/", "GraphQL nodes with id fields"],
      dataNeeded: ["two authorized accounts with different owned objects", "object ID corpus", "read/write endpoint inventory"],
      safeTestIdeas: ["Map object identifiers from crawled URLs and API schemas.", "Ask the user for two test accounts before any cross-account request."],
      activeTestIdeas: ["Replay read/write requests by swapping only object IDs between same-role accounts under rate limit."],
      evidenceToCollect: ["original owner request", "swapped ID request", "status code/body delta", "resource owner proof"],
      falsePositiveGuards: ["Confirm the accessed object belongs to another principal.", "Exclude intentionally public resources."]
    },
    {
      id: "BL-002",
      title: "Function-level authorization and hidden admin routes",
      category: "access-control",
      risk: "high",
      owaspRefs: ["OWASP WSTG 4.5 Authorization Testing", "OWASP Top 10 A01"],
      apiRefs: ["API5:2023 Broken Function Level Authorization"],
      passiveSignals: ["admin/manage/debug route candidates", "role names in JS bundles", "disabled UI buttons with callable endpoints"],
      dataNeeded: ["low-privilege account", "admin route inventory", "expected role matrix"],
      safeTestIdeas: ["Extract hidden routes and classify them by verb and role sensitivity.", "Generate a role/endpoint matrix for user review."],
      activeTestIdeas: ["Send low-privilege requests to sensitive functions only after scope approval."],
      evidenceToCollect: ["endpoint", "role used", "business operation exposed", "server response"],
      falsePositiveGuards: ["Differentiate unauthenticated redirects from successful privileged action.", "Confirm no benign read-only documentation endpoint."]
    },
    {
      id: "BL-003",
      title: "Mass assignment and object property authorization",
      category: "data-integrity",
      risk: "high",
      owaspRefs: ["OWASP WSTG 4.5 Authorization Testing", "OWASP Top 10 A01"],
      apiRefs: ["API3:2023 Broken Object Property Level Authorization"],
      passiveSignals: ["JSON PUT/PATCH/POST bodies", "client-side role/status/isAdmin fields", "OpenAPI schemas with writable sensitive properties"],
      dataNeeded: ["safe test object", "schema or captured request body", "allowed field list"],
      safeTestIdeas: ["Identify sensitive fields that appear client-controllable.", "Compare client schemas with server-side authorization expectations."],
      activeTestIdeas: ["Attempt harmless unauthorized field change on a dedicated test object."],
      evidenceToCollect: ["field sent", "before/after object state", "server response", "authorization expectation"],
      falsePositiveGuards: ["Use non-production test data.", "Confirm the changed field is security or business sensitive."]
    },
    {
      id: "BL-004",
      title: "Workflow step bypass and state transition abuse",
      category: "workflow",
      risk: "high",
      owaspRefs: ["OWASP WSTG 4.10 Business Logic Testing", "OWASP Top 10 A04"],
      apiRefs: ["API6:2023 Unrestricted Access to Sensitive Business Flows"],
      passiveSignals: ["multi-step checkout/KYC/2FA/password reset flows", "state/status parameters", "wizard-style APIs"],
      dataNeeded: ["flow diagram", "valid test account", "safe transaction sandbox"],
      safeTestIdeas: ["Model state machine from routes and request names.", "Identify terminal operations callable without prior steps."],
      activeTestIdeas: ["Call later workflow steps without prerequisite state using sandbox data only."],
      evidenceToCollect: ["expected sequence", "bypassed sequence", "resulting state", "server-side audit/state proof"],
      falsePositiveGuards: ["Confirm the bypass changes persistent state.", "Do not use real payment/order flows."]
    },
    {
      id: "BL-005",
      title: "Price, quantity, coupon, credit, and refund tampering",
      category: "financial-logic",
      risk: "critical",
      owaspRefs: ["OWASP WSTG 4.10 Business Logic Testing", "OWASP Top 10 A04"],
      apiRefs: ["API6:2023 Unrestricted Access to Sensitive Business Flows"],
      passiveSignals: ["price/amount/discount/coupon/refund/credit parameters", "cart/order/payment APIs", "client-side calculated totals"],
      dataNeeded: ["sandbox account", "non-chargeable test item", "business rule for pricing/refund"],
      safeTestIdeas: ["Identify which monetary values are client submitted versus server computed.", "Flag flows where discount criteria can change after application."],
      activeTestIdeas: ["Attempt non-charging manipulation on sandbox/test payment rails only."],
      evidenceToCollect: ["submitted monetary fields", "server-accepted total", "business rule violated", "no real charge proof"],
      falsePositiveGuards: ["Never execute against real money.", "Confirm server committed the manipulated value."]
    },
    {
      id: "BL-006",
      title: "Race conditions and replay/double-submit abuse",
      category: "concurrency",
      risk: "high",
      owaspRefs: ["OWASP WSTG 4.10 Business Logic Testing", "OWASP Top 10 A04"],
      apiRefs: ["API6:2023 Unrestricted Access to Sensitive Business Flows", "API4:2023 Unrestricted Resource Consumption"],
      passiveSignals: ["redeem/transfer/withdraw/coupon/submit endpoints", "single-use token flows", "idempotency key absence"],
      dataNeeded: ["safe single-use action", "authorization for concurrent testing", "rate limit"],
      safeTestIdeas: ["Detect high-value single-use endpoints and whether idempotency keys are present.", "Prepare a concurrency test plan for explicit approval."],
      activeTestIdeas: ["Send a tiny bounded burst against a sandbox single-use action."],
      evidenceToCollect: ["number of concurrent attempts", "accepted duplicates", "final balance/state", "rate and timing"],
      falsePositiveGuards: ["Use bounded requests only.", "Confirm duplicate state change, not duplicate response rendering."]
    },
    {
      id: "BL-007",
      title: "Authentication recovery, 2FA, invite, and email-change logic",
      category: "identity-workflow",
      risk: "high",
      owaspRefs: ["OWASP WSTG 4.4 Authentication Testing", "OWASP Top 10 A07"],
      apiRefs: ["API2:2023 Broken Authentication"],
      passiveSignals: ["password reset", "2fa", "otp", "invite", "email change", "account recovery routes"],
      dataNeeded: ["test accounts", "mailbox access", "expected auth sequence"],
      safeTestIdeas: ["Map recovery and second-factor routes without brute force.", "Identify tokens passed through URLs or client storage."],
      activeTestIdeas: ["Check whether final recovery steps enforce prior token/session state using test accounts."],
      evidenceToCollect: ["token lifecycle", "session before/after", "bypassed step", "account affected"],
      falsePositiveGuards: ["No brute force.", "No real user accounts."]
    },
    {
      id: "BL-008",
      title: "Tenant isolation and organization boundary checks",
      category: "multi-tenant-access",
      risk: "critical",
      owaspRefs: ["OWASP WSTG 4.5 Authorization Testing", "OWASP Top 10 A01"],
      apiRefs: ["API1:2023 Broken Object Level Authorization", "API5:2023 Broken Function Level Authorization"],
      passiveSignals: ["orgId/tenantId/workspaceId/projectId parameters", "organization switchers", "team management APIs"],
      dataNeeded: ["two test tenants", "same-role accounts in each tenant", "tenant-owned object IDs"],
      safeTestIdeas: ["Build a tenant-aware endpoint map and mark every tenant-scoped identifier.", "Ask for explicit two-tenant test setup."],
      activeTestIdeas: ["Swap tenant identifiers while keeping authenticated principal constant."],
      evidenceToCollect: ["source tenant", "target tenant", "request delta", "cross-tenant result"],
      falsePositiveGuards: ["Confirm tenant separation expectation.", "Exclude shared/global resources."]
    },
    {
      id: "BL-009",
      title: "Business flow abuse and automation controls",
      category: "abuse-prevention",
      risk: "medium",
      owaspRefs: ["OWASP WSTG 4.10 Business Logic Testing", "OWASP Top 10 A04"],
      apiRefs: ["API6:2023 Unrestricted Access to Sensitive Business Flows", "API4:2023 Unrestricted Resource Consumption"],
      passiveSignals: ["vote/comment/post/search/invite/export/report endpoints", "missing captcha/rate-limit headers", "expensive operations"],
      dataNeeded: ["allowed request rate", "business impact definition", "test account"],
      safeTestIdeas: ["Identify sensitive high-volume flows and expected abuse controls.", "Avoid stress testing unless explicitly authorized."],
      activeTestIdeas: ["Run small bounded repeated requests to confirm presence of throttling only with approval."],
      evidenceToCollect: ["request count", "server limits observed", "business impact", "rate headers"],
      falsePositiveGuards: ["Do not label missing captcha alone as a vulnerability.", "Tie impact to concrete business harm."]
    },
    {
      id: "BL-010",
      title: "File/object lifecycle and ownership after upload/share/delete",
      category: "object-lifecycle",
      risk: "high",
      owaspRefs: ["OWASP WSTG 4.5 Authorization Testing", "OWASP Top 10 A01"],
      apiRefs: ["API1:2023 Broken Object Level Authorization", "API3:2023 Broken Object Property Level Authorization"],
      passiveSignals: ["upload/download/share/delete/export endpoints", "signed URL generation", "attachment IDs"],
      dataNeeded: ["benign test files", "two accounts", "retention/share rules"],
      safeTestIdeas: ["Map file lifecycle endpoints and generated object URLs.", "Check whether sensitive file IDs are predictable."],
      activeTestIdeas: ["Verify cross-account access to uploaded benign files after explicit approval."],
      evidenceToCollect: ["file owner", "download/share URL", "authorization context", "object state after delete/revoke"],
      falsePositiveGuards: ["Use harmless files.", "Confirm URL was not intentionally public."]
    }
  ];
}

