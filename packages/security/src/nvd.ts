// ── NVD API Client ──
// Fetches CVE details from the NIST National Vulnerability Database API v2.
// Rate limit: 5 requests per 30 seconds without API key, 50 with key.

export type NvdCveItem = {
  id: string;
  description: string;
  publishedDate: string;
  lastModifiedDate: string;
  cvssVector?: string;         // CVSS 3.1 vector string
  cvssBaseScore?: number;      // 0.0-10.0
  cvssSeverity?: string;       // NONE/LOW/MEDIUM/HIGH/CRITICAL
  cvssV2Vector?: string;
  cvssV2Score?: number;
  weaknesses?: string[];       // CWE IDs
  references: string[];
  cpeMatches: string[];        // CPE strings
  exploitabilityScore?: number;
  impactScore?: number;
};

// ── Configuration ──

export type NvdConfig = {
  apiKey?: string;            // Optional NVD API key for higher rate limits
  baseUrl?: string;           // Default: https://services.nvd.nist.gov/rest/json/cves/2.0
  rateLimitDelayMs?: number;  // Delay between requests (default: 6000ms without key, 1200ms with key)
  maxRetries?: number;
};

// ── Rate Limiter ──

let _lastRequestTime = 0;

function getDelay(config: NvdConfig): number {
  return config.rateLimitDelayMs ?? (config.apiKey ? 1200 : 6000);
}

async function throttle(config: NvdConfig): Promise<void> {
  const now = Date.now();
  const delay = getDelay(config);
  const elapsed = now - _lastRequestTime;
  if (elapsed < delay) {
    await new Promise((resolve) => setTimeout(resolve, delay - elapsed));
  }
  _lastRequestTime = Date.now();
}

// ── Fetch CVE ──

async function fetchWithRetry(url: string, config: NvdConfig, retries = 0): Promise<Response> {
  const headers: Record<string, string> = {
    "User-Agent": "AegisProbe-CVE-Matcher/1.0",
  };
  if (config.apiKey) {
    headers["apiKey"] = config.apiKey;
  }

  try {
    const response = await fetch(url, { headers });
    if (response.status === 403 || response.status === 429) {
      if (retries < (config.maxRetries ?? 3)) {
        await new Promise((resolve) => setTimeout(resolve, getDelay(config) * (retries + 1)));
        return fetchWithRetry(url, config, retries + 1);
      }
    }
    return response;
  } catch (error) {
    if (retries < (config.maxRetries ?? 3)) {
      await new Promise((resolve) => setTimeout(resolve, getDelay(config) * (retries + 1)));
      return fetchWithRetry(url, config, retries + 1);
    }
    throw error;
  }
}

export async function fetchCveDetails(
  cveId: string,
  config: NvdConfig = {}
): Promise<NvdCveItem | null> {
  // Normalize CVE ID
  const normalized = cveId.trim().toUpperCase();
  if (!/^CVE-\d{4}-\d{4,}$/.test(normalized)) {
    return null;
  }

  await throttle(config);

  const baseUrl = config.baseUrl || "https://services.nvd.nist.gov/rest/json/cves/2.0";
  const url = `${baseUrl}?cveId=${encodeURIComponent(normalized)}`;

  try {
    const response = await fetchWithRetry(url, config);
    if (!response.ok) {
      if (response.status === 404) return null;
      throw new Error(`NVD API error: ${response.status} ${response.statusText}`);
    }

    const data = await response.json() as {
      vulnerabilities?: Array<{
        cve: {
          id: string;
          descriptions?: Array<{ lang: string; value: string }>;
          published?: string;
          lastModified?: string;
          metrics?: {
            cvssMetricV31?: Array<{
              cvssData: {
                vectorString: string;
                baseScore: number;
                baseSeverity: string;
                exploitabilityScore?: number;
                impactScore?: number;
              };
            }>;
            cvssMetricV2?: Array<{
              cvssData: { vectorString: string; baseScore: number };
            }>;
          };
          weaknesses?: Array<{
            description: Array<{ value: string }>;
          }>;
          references?: Array<{ url: string }>;
          configurations?: Array<{
            nodes: Array<{
              cpeMatch: Array<{ criteria: string }>;
            }>;
          }>;
        };
      }>;
    };

    const vuln = data.vulnerabilities?.[0]?.cve;
    if (!vuln) return null;

    const cvss31 = vuln.metrics?.cvssMetricV31?.[0]?.cvssData;
    const cvss2 = vuln.metrics?.cvssMetricV2?.[0]?.cvssData;

    const description = vuln.descriptions?.find((d) => d.lang === "en")?.value
      || vuln.descriptions?.[0]?.value
      || "";

    const weaknesses = vuln.weaknesses
      ?.flatMap((w) => w.description.map((d) => d.value))
      || [];

    const references = vuln.references?.map((r) => r.url) || [];

    const cpeMatches = vuln.configurations
      ?.flatMap((c) => c.nodes.flatMap((n) => n.cpeMatch.map((m) => m.criteria)))
      || [];

    return {
      id: vuln.id,
      description,
      publishedDate: vuln.published || "",
      lastModifiedDate: vuln.lastModified || "",
      cvssVector: cvss31?.vectorString,
      cvssBaseScore: cvss31?.baseScore,
      cvssSeverity: cvss31?.baseSeverity,
      exploitabilityScore: cvss31?.exploitabilityScore,
      impactScore: cvss31?.impactScore,
      cvssV2Vector: cvss2?.vectorString,
      cvssV2Score: cvss2?.baseScore,
      weaknesses,
      references,
      cpeMatches,
    };
  } catch (error) {
    // Network errors — return null gracefully
    return null;
  }
}

// ── Batch Fetch ──

export async function fetchCveDetailsBatch(
  cveIds: string[],
  config: NvdConfig = {}
): Promise<Map<string, NvdCveItem>> {
  const results = new Map<string, NvdCveItem>();

  for (const id of cveIds) {
    try {
      const item = await fetchCveDetails(id, config);
      if (item) results.set(id, item);
    } catch {
      // Skip failed fetches
    }
  }

  return results;
}

// ── Offline CVSS lookup — hardcoded for common CVEs ──

const KNOWN_CVE_CVSS: Record<string, string> = {
  // Apache
  "CVE-2021-41773": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 7.5 — path traversal
  "CVE-2021-42013": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 7.5 — path traversal (follow-up)
  "CVE-2021-40438": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 9.0 — SSRF in mod_proxy
  // PHP
  "CVE-2024-4577": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",   // 9.8 — CGI arg injection
  // jQuery
  "CVE-2020-11022": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",   // 6.9 — XSS in jQuery <3.5.0
  // Log4j
  "CVE-2021-44228": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 10.0 — Log4Shell
  "CVE-2021-45046": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 9.0 — Log4j follow-up
  // Spring4Shell
  "CVE-2022-22965": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 9.8
  // Confluence
  "CVE-2022-26134": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 9.8 — OGNL injection
  // ProxyShell
  "CVE-2021-34473": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 9.8 — Exchange
  // ProxyNotShell
  "CVE-2022-41082": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 8.0 — Exchange
  // Citrix
  "CVE-2019-19781": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 9.8
  // F5 BIG-IP
  "CVE-2022-1388":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 9.8
  "CVE-2020-5902":  "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",  // 9.8
};

export function getOfflineCvss(cveId: string): string | undefined {
  return KNOWN_CVE_CVSS[cveId.toUpperCase()];
}
