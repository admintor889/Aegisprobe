// ── CPE 2.3 Matcher ──
// Replaces substring-based technology matching with proper CPE (Common Platform Enumeration)
// semantic matching, following NIST IR 7695 / CPE 2.3 Specification.
//
// CPE 2.3 format:
//   cpe:2.3:<part>:<vendor>:<product>:<version>:<update>:<edition>:<lang>:<sw_edition>:<target_sw>:<target_hw>:<other>
//
// References:
//   - NIST IR 7695: https://nvlpubs.nist.gov/nistpubs/Legacy/IR/nistir7695.pdf
//   - OWASP DependencyCheck CPEAnalyzer: Lucene-indexed, evidence-weighted confidence
//   - DependencyCheck key features: major version appending, stop word removal, evidence validation
//
// Key improvements over substring matching:
//   1. CPE URI parsing with 11-field structure
//   2. Vendor/product normalization + fuzzy matching
//   3. Version range comparison (via semver module)
//   4. Wildcard handling (* and -)
//   5. Evidence-weighted confidence scoring (DependencyCheck-style)
//   6. Major version appending to product names
//   7. Stop word removal from vendor/product names
//   8. Evidence validation: verify matched CPE terms appear in technology evidence text

import { parseSemverLenient, compareSemver, matchesCpeVersion, type Semver, parseVersionRange } from "./semver.js";

// ── Types ──

export type CpePart = "a" | "o" | "h";  // application | operating system | hardware

export type CpeUri = {
  cpeVersion: "2.3";
  part: CpePart;
  vendor: string;
  product: string;
  version: string;
  update: string;
  edition: string;
  language: string;
  swEdition: string;
  targetSw: string;
  targetHw: string;
  other: string;
  /** Original CPE string */
  raw: string;
};

export type CpeMatchResult = {
  /** Observed technology */
  technology: string;
  /** Observed version */
  version: string | null;
  /** Matched CPE URI (null if match was purely name-based with no CPE URI) */
  cpe: CpeUri | null;
  /** Match confidence */
  confidence: "exact" | "high" | "medium" | "low";
  /** What matched (vendor+product+version / vendor+product / product / fuzzy) */
  matchType: "full" | "vendor_product" | "product_only" | "fuzzy";
  /** Version match detail */
  versionMatch: "exact" | "range" | "wildcard" | "none" | "mismatch";
};

// ── Parser ──

const CPE23_RE = /^cpe:2\.3:([aoh*\-]):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*):([^:]*)$/;

export function parseCpe23(raw: string): CpeUri | null {
  const match = raw.trim().toLowerCase().match(CPE23_RE);
  if (!match) return null;

  return {
    cpeVersion: "2.3",
    part: match[1] as CpePart,
    vendor: unescapeCpe(match[2]),
    product: unescapeCpe(match[3]),
    version: unescapeCpe(match[4]),
    update: unescapeCpe(match[5]),
    edition: unescapeCpe(match[6]),
    language: unescapeCpe(match[7]),
    swEdition: unescapeCpe(match[8]),
    targetSw: unescapeCpe(match[9]),
    targetHw: unescapeCpe(match[10]),
    other: unescapeCpe(match[11]),
    raw: raw.trim(),
  };
}

function unescapeCpe(value: string): string {
  return value
    .replace(/\\:/g, ":")
    .replace(/\\\\/g, "\\")
    .replace(/_/g, " ")  // underscore → space in CPE
    .replace(/%([0-9a-f]{2})/gi, (_, hex) => String.fromCharCode(Number.parseInt(hex, 16)));
}

// ── Normalization ──

const CPE_NORMALIZE_MAP: Record<string, string> = {
  "http server": "http_server",
  "httpd": "http_server",
  "apache http server": "http_server",
  "apache httpd": "http_server",
  "apache2": "http_server",
  "microsoft iis": "iis",
  "internet information services": "iis",
  "nginx": "nginx",
  "nginx plus": "nginx",
  "tomcat": "tomcat",
  "apache tomcat": "tomcat",
  "jetty": "jetty",
  "eclipse jetty": "jetty",
  "node.js": "node_js",
  "nodejs": "node_js",
  "node": "node_js",
  "php": "php",
  "php-fpm": "php",
  "mysql": "mysql",
  "mariadb": "mariadb",
  "postgresql": "postgresql",
  "postgres": "postgresql",
  "redis": "redis",
  "mongodb": "mongodb",
  "mongo db": "mongodb",
  "wordpress": "wordpress",
  "wp": "wordpress",
  "drupal": "drupal",
  "joomla": "joomla",
  "joomla!": "joomla",
  "confluence": "confluence",
  "atlassian confluence": "confluence",
  "jenkins": "jenkins",
  "jenkins ci": "jenkins",
  "gitlab": "gitlab",
  "github": "github",
  "spring": "spring_framework",
  "spring framework": "spring_framework",
  "spring boot": "spring_boot",
  "springboot": "spring_boot",
  "django": "django",
  "flask": "flask",
  "laravel": "laravel",
  "ruby on rails": "rails",
  "rails": "rails",
  "react": "react",
  "react.js": "react",
  "angular": "angular",
  "angular.js": "angular",
  "vue": "vue_js",
  "vue.js": "vue_js",
  "jquery": "jquery",
};

export function normalizeCpeName(name: string): string {
  const lower = name.toLowerCase().trim()
    .replace(/[^a-z0-9_.\-/ ]/g, "")
    .replace(/\s+/g, " ")
    .trim();

  // Check normalization map
  for (const [key, value] of Object.entries(CPE_NORMALIZE_MAP)) {
    if (lower === key || lower.includes(key)) return value;
  }

  // Default: replace spaces with underscores
  return lower.replace(/\s+/g, "_");
}

// ── Fuzzy Matching ──

/** Levenshtein distance for typo-tolerant matching */
function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  const dp: number[][] = Array.from({ length: m + 1 }, () => Array(n + 1).fill(0));

  for (let i = 0; i <= m; i++) dp[i][0] = i;
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] = a[i - 1] === b[j - 1]
        ? dp[i - 1][j - 1]
        : 1 + Math.min(dp[i - 1][j], dp[i][j - 1], dp[i - 1][j - 1]);
    }
  }

  return dp[m][n];
}

function isFuzzyMatch(a: string, b: string, maxDistance = 2): boolean {
  if (a === b) return true;
  if (a.length < 4 || b.length < 4) return a === b;
  const distance = levenshtein(a, b);
  return distance <= maxDistance && distance / Math.max(a.length, b.length) <= 0.3;
}

// ── Stop Words (DependencyCheck-style) ──
// These common words in technology names shouldn't affect CPE matching.

const STOP_WORDS = new Set([
  "the", "a", "an", "and", "or", "for", "of", "in", "on", "to", "by", "with",
  "is", "are", "was", "were", "be", "been", "being",
  "http", "https", "server", "service", "application", "system", "framework",
  "version", "release", "edition", "standard", "enterprise", "community",
  "running", "using", "used", "based", "open", "source", "free",
]);

function removeStopWords(text: string): string {
  return text.split(/[\s_-]+/).filter((w) => !STOP_WORDS.has(w.toLowerCase())).join(" ");
}

// ── Evidence-Weighted CPE Matcher (DependencyCheck-style) ──

/**
 * Enhanced CPE matching with evidence-weighted confidence.
 *
 * @param cpeUris - CPE URI strings to match against
 * @param technology - Observed technology (name + version)
 * @param evidenceText - Optional evidence text from httpx/nuclei/wappalyzer output.
 *   Used to validate matches and boost confidence when evidence text contains
 *   the matched vendor/product names (DependencyCheck-style verification).
 */
function extractMajorVersion(version: string | null | undefined): string | null {
  if (!version) return null;
  const semver = parseSemverLenient(version);
  return semver ? String(semver.major) : null;
}

// ── Evidence Validation (DependencyCheck: collectionContainsString) ──

/** Verify that matched CPE vendor/product terms appear in the evidence text. */
function evidenceContainsTerm(evidenceText: string, cpeTerm: string): boolean {
  if (!evidenceText || !cpeTerm) return false;
  const term = cpeTerm.toLowerCase().replace(/[_]/g, ' ');
  const words = term.split(/[s_-]+/).filter(w => w.length >= 3 && !STOP_WORDS.has(w));
  if (words.length === 0) return false;
  // All significant words must appear in evidence text
  return words.every(w => evidenceText.includes(w));
}

export function matchCpeAgainstTechnology(
  cpeUris: string[],
  technology: { name: string; version?: string | null; evidenceSummary?: string | null }
): CpeMatchResult | null {
  const techName = normalizeCpeName(technology.name);
  const evidenceText = (technology.evidenceSummary ?? "").toLowerCase();
  const techNameClean = removeStopWords(technology.name.toLowerCase());

  // Extract major version for appending (DependencyCheck: "addMajorVersionToTerms")
  const majorVersion = extractMajorVersion(technology.version);
  let best: CpeMatchResult | null = null;


  for (const rawCpe of cpeUris) {
    const cpe = parseCpe23(rawCpe);
    if (!cpe) continue;

    const cpeVendor = normalizeCpeName(cpe.vendor);
    const cpeProduct = normalizeCpeName(cpe.product);

    // Level 1: Exact vendor + product match + version match → "exact"
    if (cpeVendor && cpeProduct && techName.includes(cpeProduct) && cpeProduct.includes(techName.split("_").slice(-1)[0] || "")) {
      const versionMatch = matchCpeVersion(cpe.version, technology.version);
      if (versionMatch === "exact") {
        return {
          technology: technology.name,
          version: technology.version ?? null,
          cpe,
          confidence: "exact",
          matchType: "full",
          versionMatch: "exact",
        };
      }
      if (versionMatch === "range" || versionMatch === "wildcard") {
        const candidate: CpeMatchResult = {
          technology: technology.name,
          version: technology.version ?? null,
          cpe,
          confidence: "high",
          matchType: "full",
          versionMatch,
        };
        if (!best || confidenceRank(candidate.confidence) > confidenceRank(best.confidence)) {
          best = candidate;
        }
      }
    }

    // Level 2: Product match (ignoring vendor)
    if (cpeProduct && (techName === cpeProduct || techName.includes(cpeProduct) || cpeProduct.includes(techName))) {
      const versionMatch = matchCpeVersion(cpe.version, technology.version);
      if (versionMatch !== "mismatch") {
        const candidate: CpeMatchResult = {
          technology: technology.name,
          version: technology.version ?? null,
          cpe,
          confidence: versionMatch === "exact" ? "high" : "medium",
          matchType: "product_only",
          versionMatch,
        };
        if (!best || confidenceRank(candidate.confidence) > confidenceRank(best.confidence)) {
          best = candidate;
        }
      }
    }

    // Level 3: Vendor match
    if (cpeVendor && (techName === cpeVendor || techName.includes(cpeVendor))) {
      const candidate: CpeMatchResult = {
        technology: technology.name,
        version: technology.version ?? null,
        cpe,
        confidence: "medium",
        matchType: "vendor_product",
        versionMatch: "none",
      };
      if (!best || confidenceRank(candidate.confidence) > confidenceRank(best.confidence)) {
        best = candidate;
      }
    }


    // Level 3.5: Major version appending (DependencyCheck: addMajorVersionToTerms)
    // Try matching product with major version appended, e.g. 'http_serverv2' for 'Apache HTTP Server 2.x'
    if (!best && majorVersion && cpeProduct) {
      const versionedProduct = cpeProduct + 'v' + majorVersion;
      const versionedProductAlt = cpeProduct + majorVersion;
      if (techNameClean.includes(cpeProduct) || techNameClean.includes(versionedProduct) || techNameClean.includes(versionedProductAlt)) {
        best = {
          technology: technology.name,
          version: technology.version ?? null,
          cpe,
          confidence: 'medium',
          matchType: 'product_only',
          versionMatch: 'range',
        };
      }
    }

        // Level 4: Fuzzy match
    if (!best && (isFuzzyMatch(techName, cpeProduct) || isFuzzyMatch(techName, cpeVendor))) {
      best = {
        technology: technology.name,
        version: technology.version ?? null,
        cpe,
        confidence: "low",
        matchType: "fuzzy",
        versionMatch: "none",
      };
    }
  }

  
  // Evidence-weighted confidence boost (DependencyCheck-style):
  // If evidence text contains matched CPE vendor/product terms, upgrade confidence.
  if (best && evidenceText && best.cpe) {
    const vendorMatch = evidenceContainsTerm(evidenceText, best.cpe.vendor);
    const productMatch = evidenceContainsTerm(evidenceText, best.cpe.product);
    if (vendorMatch && productMatch && best.confidence === 'medium') {
      best = { ...best, confidence: 'high' };
    } else if (vendorMatch && productMatch && best.confidence === 'high') {
      best = { ...best, confidence: 'exact' };
    } else if (!vendorMatch && !productMatch && best.confidence !== 'exact') {
      // Downgrade if evidence doesn't support the match
      best = { ...best, confidence: best.confidence === 'high' ? 'medium' : 'low' };
    }
  }

  return best;
}

// ── Version Matching ──

function matchCpeVersion(
  cpeVersion: string,
  observedVersion: string | null | undefined
): CpeMatchResult["versionMatch"] {
  if (!observedVersion) return "none";

  // Wildcard
  if (cpeVersion === "*" || cpeVersion === "-") return "wildcard";

  // Exact match
  const cpeClean = cpeVersion.replace(/^[vV]/, "");
  const obsClean = observedVersion.replace(/^[vV]/, "");

  if (cpeClean === obsClean) return "exact";

  // Try semver comparison
  const cpeSemver = parseSemverLenient(cpeVersion);
  const obsSemver = parseSemverLenient(observedVersion);

  if (cpeSemver && obsSemver) {
    const cmp = compareSemver(obsSemver, cpeSemver);
    if (cmp === 0) return "exact";

    // If CPE version has no patch (e.g., "2.4"), treat as range "2.4.*"
    if (!cpeVersion.includes(".") || cpeVersion.split(".").length === 2) {
      // e.g., CPE says "2.4", observed is "2.4.49" → range match
      if (cpeSemver.major === obsSemver.major && cpeSemver.minor === obsSemver.minor) {
        return "range";
      }
    }

    return "mismatch";
  }

  // Substring fallback
  if (cpeClean.includes(obsClean) || obsClean.includes(cpeClean)) {
    return "range";
  }

  return "mismatch";
}

// ── Confidence Ranking ──

function confidenceRank(c: CpeMatchResult["confidence"]): number {
  return { exact: 4, high: 3, medium: 2, low: 1 }[c];
}

// ── Batch Matcher ──

export function batchMatchCpe(
  cpeUris: string[],
  technologies: Array<{ name: string; version?: string | null }>
): CpeMatchResult[] {
  const results: CpeMatchResult[] = [];

  for (const tech of technologies) {
    const match = matchCpeAgainstTechnology(cpeUris, tech);
    if (match) results.push(match);
  }

  // Sort by confidence
  return results.sort((a, b) => confidenceRank(b.confidence) - confidenceRank(a.confidence));
}

// ── Upgrade: Replace substring matching in normalizer ──

export function templateMatchesTechnologyCpe(
  template: { product?: string; vendor?: string; name: string; tags: string[]; path: string },
  technology: { name: string; version?: string | null }
): CpeMatchResult | null {
  // Build synthetic CPE strings from template metadata
  const cpeUris: string[] = [];

  if (template.vendor && template.product) {
    cpeUris.push(`cpe:2.3:a:${escapeCpe(template.vendor)}:${escapeCpe(template.product)}:*:*:*:*:*:*:*:*`);
  }
  if (template.product) {
    cpeUris.push(`cpe:2.3:a:*:${escapeCpe(template.product)}:*:*:*:*:*:*:*:*`);
  }

  // If no CPE-able metadata, fall back to name-based matching
  if (cpeUris.length === 0) {
    // Try to extract product name from template path
    const pathParts = template.path.split("/");
    const candidate = pathParts[pathParts.length - 2] || pathParts[0] || "";
    if (candidate && candidate.length >= 3) {
      cpeUris.push(`cpe:2.3:a:*:${escapeCpe(candidate)}:*:*:*:*:*:*:*:*`);
    }
  }

  return matchCpeAgainstTechnology(cpeUris, technology);
}

function escapeCpe(value: string): string {
  return value.toLowerCase().replace(/[^a-z0-9_.\-]/g, "_").replace(/\s+/g, "_");
}

// ── CPE Match → CVE Confidence Upgrader ──

/**
 * Upgrades CVE match confidence based on CPE match quality.
 * Replaces the old "technology.version && template.name.includes(technology.version)" heuristic.
 */
export function cpeMatchConfidence(match: CpeMatchResult): "confirmed" | "high" | "medium" | "low" {
  if (match.confidence === "exact") return "confirmed";
  if (match.confidence === "high") return match.versionMatch === "exact" ? "high" : "medium";
  if (match.confidence === "medium") return "medium";
  return "low";
}

// ── Utility ──

export function formatCpeMatch(match: CpeMatchResult): string {
  const versionInfo = match.version ? ` v${match.version}` : "";
  const cpeStr = match.cpe ? match.cpe.raw : "no-cpe";
  return `${match.technology}${versionInfo} ← ${cpeStr} [${match.confidence}/${match.matchType}/${match.versionMatch}]`;
}
