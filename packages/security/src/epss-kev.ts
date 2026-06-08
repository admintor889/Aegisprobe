// ── EPSS + KEV Integration ──
// EPSS (Exploit Prediction Scoring System): FIRST.org API — probability that a CVE will be exploited in the next 30 days.
// KEV (Known Exploited Vulnerabilities): CISA catalog of CVEs known to be actively exploited in the wild.
//
// Combined with CVSS, this produces a three-dimensional prioritization:
//   CVSS base score (impact) × EPSS probability (threat) × KEV flag (urgency)

import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { join as joinPath } from "node:path";

// ── Types ──

export type EpssResult = {
  cve: string;
  epss: number;          // 0.0 – 1.0, probability of exploitation in next 30 days
  percentile: number;    // 0.0 – 1.0, relative to all scored CVEs
  date: string;          // date the score was published
};

export type KevEntry = {
  cveId: string;
  vendorProject: string;
  product: string;
  vulnerabilityName: string;
  dateAdded: string;
  shortDescription: string;
  requiredAction: string;
  dueDate: string;
  knownRansomwareCampaignUse: string;  // "Known" or "Unknown"
  notes: string;
};

export type KevCatalog = {
  lastUpdated: string;
  entries: Map<string, KevEntry>;  // cveId → entry
};

export type CvePriorityContext = {
  cvssScore?: number;
  cvssSeverity?: string;
  epssScore?: number;
  epssPercentile?: number;
  inKevCatalog: boolean;
  kevEntry?: KevEntry;
  priorityScore: number;  // 0-100 composite: CVSS × EPSS × KEV-boost
};

// ── Configuration ──

export type EpssKevConfig = {
  epssBaseUrl?: string;          // default: https://api.first.org/data/v1/epss
  kevFeedUrl?: string;           // default: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  kevCachePath?: string;         // default: data/security-knowledge/kev-catalog.json
  kevCacheTtlMs?: number;        // default: 24 hours
  fetchTimeoutMs?: number;
};

// ── EPSS API Client ──

export async function fetchEpssScore(
  cveId: string,
  config: EpssKevConfig = {}
): Promise<EpssResult | null> {
  const normalized = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(normalized)) return null;

  const baseUrl = config.epssBaseUrl || "https://api.first.org/data/v1/epss";
  const url = `${baseUrl}?cve=${encodeURIComponent(normalized)}`;
  const timeout = config.fetchTimeoutMs ?? 10_000;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(url, {
      signal: controller.signal,
      headers: { "User-Agent": "AegisProbe-EPSS/1.0" }
    });
    clearTimeout(timer);

    if (!response.ok) {
      if (response.status === 404) return null;
      return null;
    }

    const data = await response.json() as {
      data?: Array<{
        cve: string;
        epss: string;
        percentile: string;
        date: string;
      }>;
    };

    const item = data.data?.[0];
    if (!item) return null;

    return {
      cve: item.cve,
      epss: Number.parseFloat(item.epss) || 0,
      percentile: Number.parseFloat(item.percentile) || 0,
      date: item.date,
    };
  } catch {
    return null;
  }
}

// ── Batch EPSS ──

export async function fetchEpssScores(
  cveIds: string[],
  config: EpssKevConfig = {}
): Promise<Map<string, EpssResult>> {
  if (cveIds.length === 0) return new Map();

  const normalized = [...new Set(cveIds.map((id) => id.trim().toUpperCase()).filter((id) => /^CVE-\d{4}-\d{4,}$/.test(id)))];

  // EPSS API supports batch via POST, but for simplicity we query one at a time with concurrency
  const concurrency = 3;
  const results = new Map<string, EpssResult>();

  for (let i = 0; i < normalized.length; i += concurrency) {
    const batch = normalized.slice(i, i + concurrency);
    const promises = batch.map(async (id) => {
      const result = await fetchEpssScore(id, config);
      if (result) results.set(id, result);
    });
    await Promise.allSettled(promises);
  }

  return results;
}

// ── KEV Catalog ──

export function defaultKevCachePath(projectRoot = process.cwd()): string {
  return joinPath(projectRoot, "data", "security-knowledge", "kev-catalog.json");
}

export async function fetchKevCatalog(config: EpssKevConfig = {}): Promise<KevCatalog | null> {
  const feedUrl = config.kevFeedUrl
    || "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
  const timeout = config.fetchTimeoutMs ?? 30_000;

  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    const response = await fetch(feedUrl, {
      signal: controller.signal,
      headers: { "User-Agent": "AegisProbe-KEV/1.0" }
    });
    clearTimeout(timer);

    if (!response.ok) return null;

    const data = await response.json() as {
      title?: string;
      catalogVersion?: string;
      dateReleased?: string;
      count?: number;
      vulnerabilities?: Array<{
        cveID: string;
        vendorProject: string;
        product: string;
        vulnerabilityName: string;
        dateAdded: string;
        shortDescription: string;
        requiredAction: string;
        dueDate: string;
        knownRansomwareCampaignUse: string;
        notes: string;
      }>;
    };

    const vulnerabilities = data.vulnerabilities ?? [];
    const entries = new Map<string, KevEntry>();

    for (const vuln of vulnerabilities) {
      const cveId = (vuln.cveID ?? "").trim().toUpperCase();
      if (!cveId) continue;
      entries.set(cveId, {
        cveId,
        vendorProject: vuln.vendorProject ?? "",
        product: vuln.product ?? "",
        vulnerabilityName: vuln.vulnerabilityName ?? "",
        dateAdded: vuln.dateAdded ?? "",
        shortDescription: vuln.shortDescription ?? "",
        requiredAction: vuln.requiredAction ?? "",
        dueDate: vuln.dueDate ?? "",
        knownRansomwareCampaignUse: vuln.knownRansomwareCampaignUse ?? "Unknown",
        notes: vuln.notes ?? "",
      });
    }

    return {
      lastUpdated: data.dateReleased ?? new Date().toISOString(),
      entries,
    };
  } catch {
    return null;
  }
}

// ── KEV Cache ──

export function loadKevCatalogCache(projectRoot = process.cwd()): KevCatalog | null {
  const cachePath = defaultKevCachePath(projectRoot);
  if (!existsSync(cachePath)) return null;

  try {
    const raw = readFileSync(cachePath, "utf8");
    const parsed = JSON.parse(raw) as {
      lastUpdated: string;
      entries: Array<{
        cveId: string;
        vendorProject: string;
        product: string;
        vulnerabilityName: string;
        dateAdded: string;
        shortDescription: string;
        requiredAction: string;
        dueDate: string;
        knownRansomwareCampaignUse: string;
        notes: string;
      }>;
    };

    const entries = new Map<string, KevEntry>();
    for (const entry of parsed.entries ?? []) {
      const cveId = (entry.cveId ?? "").trim().toUpperCase();
      if (!cveId) continue;
      entries.set(cveId, entry as KevEntry);
    }

    return { lastUpdated: parsed.lastUpdated ?? "unknown", entries };
  } catch {
    return null;
  }
}

export function saveKevCatalogCache(catalog: KevCatalog, projectRoot = process.cwd()): void {
  const cachePath = defaultKevCachePath(projectRoot);
  const dir = joinPath(cachePath, "..");
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
  }

  const serialized = {
    lastUpdated: catalog.lastUpdated,
    entries: [...catalog.entries.values()],
  };

  writeFileSync(cachePath, JSON.stringify(serialized, null, 2), "utf8");
}

export function isKevCacheExpired(catalog: KevCatalog | null, ttlMs = 24 * 60 * 60 * 1000): boolean {
  if (!catalog) return true;
  const updated = Date.parse(catalog.lastUpdated);
  if (Number.isNaN(updated)) return true;
  return Date.now() - updated > ttlMs;
}

export async function getKevCatalog(config: EpssKevConfig = {}): Promise<KevCatalog> {
  const ttl = config.kevCacheTtlMs ?? 24 * 60 * 60 * 1000;

  // Try cache first
  const cached = loadKevCatalogCache();
  if (cached && !isKevCacheExpired(cached, ttl)) {
    return cached;
  }

  // Fetch fresh
  const fresh = await fetchKevCatalog(config);
  if (fresh) {
    saveKevCatalogCache(fresh);
    return fresh;
  }

  // Fallback to expired cache
  return cached ?? { lastUpdated: "unknown", entries: new Map() };
}

// ── CVE Lookup ──

export function isInKevCatalog(cveId: string, catalog: KevCatalog): boolean {
  return catalog.entries.has(cveId.trim().toUpperCase());
}

export function getKevEntry(cveId: string, catalog: KevCatalog): KevEntry | undefined {
  return catalog.entries.get(cveId.trim().toUpperCase());
}

// ── Composite Priority Score ──
// Combine CVSS base score, EPSS probability, and KEV flag into a single 0-100 priority score.
//
// Formula:
//   base = CVSS score normalized to 0-100 (CVSS * 10)
//   threat modifier = EPSS percentile * 100 (if available, otherwise 50)
//   urgency modifier = 1.5 if in KEV catalog, otherwise 1.0
//
//   priority = min(base * urgency_modifier + threat_modifier * 0.3, 100)
//
// This ensures:
//   - Critical CVEs (9+) with high EPSS and KEV → ~90-100
//   - Medium CVEs (5-6) with no EPSS/KEV data → ~50-60
//   - Low CVEs (<4) → low priority regardless of EPSS

export function computeCvePriorityScore(
  cvssScore?: number,
  epssPercentile?: number,
  inKev: boolean = false
): number {
  const base = (cvssScore ?? 5.0) * 10; // 0-100
  const threat = (epssPercentile ?? 0.5) * 100 * 0.3; // 0-30
  const urgency = inKev ? 1.5 : 1.0;

  const raw = base * urgency + threat;
  return Math.round(Math.min(raw, 100));
}

export function buildCvePriorityContext(
  cveId: string,
  cvssScore?: number,
  cvssSeverity?: string,
  epssResult?: EpssResult | null,
  kevCatalog?: KevCatalog
): CvePriorityContext {
  const inKev = kevCatalog ? isInKevCatalog(cveId, kevCatalog) : false;
  const kevEntry = kevCatalog ? getKevEntry(cveId, kevCatalog) : undefined;

  return {
    cvssScore,
    cvssSeverity,
    epssScore: epssResult?.epss,
    epssPercentile: epssResult?.percentile,
    inKevCatalog: inKev,
    kevEntry,
    priorityScore: computeCvePriorityScore(cvssScore, epssResult?.percentile, inKev),
  };
}

// ── Priority Tier Label ──

export function priorityTier(score: number): "immediate" | "high" | "medium" | "low" {
  if (score >= 85) return "immediate";
  if (score >= 65) return "high";
  if (score >= 35) return "medium";
  return "low";
}

export function formatPriorityContext(ctx: CvePriorityContext): string {
  const lines = [
    `CVE Priority: ${ctx.priorityScore}/100 (${priorityTier(ctx.priorityScore)})`,
    ctx.cvssScore !== undefined ? `  CVSS: ${ctx.cvssScore} (${ctx.cvssSeverity ?? "unknown"})` : undefined,
    ctx.epssScore !== undefined ? `  EPSS: ${(ctx.epssScore * 100).toFixed(2)}% (percentile: ${((ctx.epssPercentile ?? 0) * 100).toFixed(1)}%)` : undefined,
    ctx.inKevCatalog ? `  ⚠️ CISA KEV: actively exploited in the wild` : undefined,
    ctx.kevEntry ? `  KEV: ${ctx.kevEntry.vulnerabilityName} | added ${ctx.kevEntry.dateAdded} | due ${ctx.kevEntry.dueDate}` : undefined,
    ctx.kevEntry?.knownRansomwareCampaignUse === "Known" ? `  🚨 Known ransomware campaign use` : undefined,
  ];
  return lines.filter(Boolean).join("\n");
}
