// ── Wappalyzer-based Technology Fingerprinting Engine ──
// Loads the full Wappalyzer technology database (~3,500+ profiles) and performs
// real-time HTTP response fingerprinting.
//
// Pattern types checked (in order of reliability):
//   headers → meta → cookies → html → scriptSrc → js → dom → url → implies

import { existsSync, readdirSync, readFileSync, statSync } from "node:fs";
import { join as joinPath } from "node:path";

// ── Types ──

export type WappalyzerTechnology = {
  name: string;
  categories: string[];
  priority?: number;
  // Regex patterns (pre-compiled for speed)
  headers?: Map<string, RegExp>;
  html?: RegExp[];
  meta?: Map<string, RegExp>;
  cookies?: Map<string, RegExp>;
  scriptSrc?: RegExp[];
  js?: Map<string, RegExp>;
  dom?: string[];
  url?: RegExp[];
  implies?: string[];
  requires?: string[];
  // Metadata
  website?: string;
  cpe?: string;
  icon?: string;
};

export type DetectedTechnology = {
  name: string;
  version?: string;
  categories: string[];
  confidence: number;        // 0-100
  evidence: string[];         // what patterns matched
  implied: boolean;           // detected via "implies" rather than direct match
};

export type FingerprintInput = {
  url: string;
  statusCode?: number;
  headers: Record<string, string>;
  html?: string;
  scriptSrc?: string[];       // extracted <script src="..."> URLs
  cookies?: Record<string, string>;
  meta?: Record<string, string>;  // meta name → content
};

export type FingerprintResult = {
  url: string;
  technologies: DetectedTechnology[];
  matchCount: number;
};

// ── Global cache (lazy-loaded, survives multiple calls) ──

let _cachedTechnologies: WappalyzerTechnology[] | undefined;
let _cachedCategoryNames: Map<number, string> | undefined;
let _cacheLoadedAt = 0;

const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

// ── Loading ──

export function loadWappalyzerTechnologies(
  projectRoot = process.cwd(),
  forceReload = false
): WappalyzerTechnology[] {
  const now = Date.now();
  if (!forceReload && _cachedTechnologies && (now - _cacheLoadedAt) < CACHE_TTL_MS) {
    return _cachedTechnologies;
  }

  const techDir = joinPath(projectRoot, "third_party", "security-tools", "wappalyzer", "src", "technologies");
  if (!existsSync(techDir)) {
    return [];
  }

  const categoryNames = loadCategoryNames(projectRoot);

  const files = readdirSync(techDir)
    .filter((f) => f.endsWith(".json"))
    .map((f) => joinPath(techDir, f));

  const technologies: WappalyzerTechnology[] = [];

  for (const file of files) {
    try {
      const parsed = JSON.parse(readFileSync(file, "utf8")) as Record<string, Record<string, unknown>>;
      for (const [name, data] of Object.entries(parsed)) {
        const tech = parseTechnologyEntry(name, data, categoryNames);
        if (tech) {
          technologies.push(tech);
        }
      }
    } catch {
      // Skip unparseable files
    }
  }

  // Sort by priority (higher = more specific match, checked first)
  technologies.sort((a, b) => (b.priority ?? 0) - (a.priority ?? 0));

  _cachedTechnologies = technologies;
  _cachedCategoryNames = categoryNames;
  _cacheLoadedAt = now;

  return technologies;
}

function loadCategoryNames(projectRoot: string): Map<number, string> {
  if (_cachedCategoryNames) return _cachedCategoryNames;

  const categoriesPath = joinPath(
    projectRoot, "third_party", "security-tools", "wappalyzer", "src", "categories.json"
  );

  const map = new Map<number, string>();
  if (!existsSync(categoriesPath)) return map;

  try {
    const parsed = JSON.parse(readFileSync(categoriesPath, "utf8")) as Record<string, { name?: string }>;
    for (const [id, cat] of Object.entries(parsed)) {
      if (cat.name) {
        map.set(Number(id), cat.name);
      }
    }
  } catch {
    // Ignore
  }

  return map;
}

function parseTechnologyEntry(
  name: string,
  data: Record<string, unknown>,
  categories: Map<number, string>
): WappalyzerTechnology | undefined {
  if (!name || typeof name !== "string") return undefined;

  const catIds = Array.isArray(data.cats)
    ? data.cats.filter((c): c is number => typeof c === "number")
    : [];

  const tech: WappalyzerTechnology = {
    name,
    categories: catIds.map((id) => categories.get(id) ?? `cat-${id}`),
    priority: typeof data.priority === "number" ? data.priority : undefined,
    website: typeof data.website === "string" ? data.website : undefined,
    cpe: typeof data.cpe === "string" ? data.cpe : undefined,
    icon: typeof data.icon === "string" ? data.icon : undefined,
  };

  // Parse headers patterns: { "Header-Name": "regex\\;version:\\1" }
  if (data.headers && typeof data.headers === "object") {
    const map = new Map<string, RegExp>();
    for (const [key, value] of Object.entries(data.headers as Record<string, unknown>)) {
      if (typeof value !== "string") continue;
      const { regex } = parseWappalyzerPattern(value);
      if (regex) map.set(key.toLowerCase(), regex);
    }
    if (map.size > 0) tech.headers = map;
  }

  // Parse html patterns — can be string or string[]
  if (data.html) {
    const patterns = Array.isArray(data.html) ? data.html : [data.html];
    const regexes: RegExp[] = [];
    for (const p of patterns) {
      if (typeof p !== "string") continue;
      const { regex } = parseWappalyzerPattern(p);
      if (regex) regexes.push(regex);
    }
    if (regexes.length > 0) tech.html = regexes;
  }

  // Parse meta patterns: { "name": "content-regex" }
  if (data.meta && typeof data.meta === "object") {
    const map = new Map<string, RegExp>();
    for (const [key, value] of Object.entries(data.meta as Record<string, unknown>)) {
      if (typeof value !== "string") continue;
      const { regex } = parseWappalyzerPattern(value);
      if (regex) map.set(key.toLowerCase(), regex);
    }
    if (map.size > 0) tech.meta = map;
  }

  // Parse cookies: { "cookie-name": "regex" }
  if (data.cookies && typeof data.cookies === "object") {
    const map = new Map<string, RegExp>();
    for (const [key, value] of Object.entries(data.cookies as Record<string, unknown>)) {
      // cookie name is the key, value is an optional regex on cookie value
      const pattern = typeof value === "string" && value.length > 0 ? value : ".+";
      const { regex } = parseWappalyzerPattern(pattern);
      if (regex) map.set(key.toLowerCase(), regex);
    }
    if (map.size > 0) tech.cookies = map;
  }

  // Parse scriptSrc patterns
  if (data.scriptSrc) {
    const patterns = Array.isArray(data.scriptSrc) ? data.scriptSrc : [data.scriptSrc];
    const regexes: RegExp[] = [];
    for (const p of patterns) {
      if (typeof p !== "string") continue;
      const { regex } = parseWappalyzerPattern(p);
      if (regex) regexes.push(regex);
    }
    if (regexes.length > 0) tech.scriptSrc = regexes;
  }

  // Parse JS patterns: { "variableName": "version-regex" }
  if (data.js && typeof data.js === "object") {
    const map = new Map<string, RegExp>();
    for (const [key, value] of Object.entries(data.js as Record<string, unknown>)) {
      const pattern = typeof value === "string" && value.length > 0 ? value : ".+";
      const { regex } = parseWappalyzerPattern(pattern);
      if (regex) map.set(key, regex);
    }
    if (map.size > 0) tech.js = map;
  }

  // Parse dom selectors
  if (data.dom) {
    const selectors = Array.isArray(data.dom) ? data.dom : [data.dom];
    tech.dom = selectors.filter((s): s is string => typeof s === "string");
    if (tech.dom.length === 0) delete tech.dom;
  }

  // Parse url patterns
  if (data.url) {
    const patterns = Array.isArray(data.url) ? data.url : [data.url];
    const regexes: RegExp[] = [];
    for (const p of patterns) {
      if (typeof p !== "string") continue;
      const { regex } = parseWappalyzerPattern(p);
      if (regex) regexes.push(regex);
    }
    if (regexes.length > 0) tech.url = regexes;
  }

  // Parse implies / requires
  if (Array.isArray(data.implies)) {
    tech.implies = data.implies.filter((item): item is string => typeof item === "string");
  } else if (typeof data.implies === "string") {
    tech.implies = [data.implies];
  }
  if (Array.isArray(data.requires)) {
    tech.requires = data.requires.filter((item): item is string => typeof item === "string");
  } else if (typeof data.requires === "string") {
    tech.requires = [data.requires];
  }

  return tech;
}

/**
 * Parse a Wappalyzer pattern string like:
 *   "nginx(?:/([\\d.]+))?\\;version:\\1"
 * into { regex: RegExp, versionGroup: number|null }
 */
function parseWappalyzerPattern(pattern: string): { regex: RegExp | null; versionGroup: number | null } {
  const versionMatch = pattern.match(/\\;version:(\\?\d+)\s*$/);
  let cleaned = pattern;
  let versionGroup: number | null = null;

  if (versionMatch) {
    cleaned = pattern.slice(0, versionMatch.index!).trim();
    const groupNum = Number.parseInt(versionMatch[1]!.replace(/\\/g, ""), 10);
    if (!Number.isNaN(groupNum)) versionGroup = groupNum;
  }

  try {
    // Wappalyzer uses JavaScript regex syntax directly, but sometimes includes flags
    const flagMatch = cleaned.match(/^\/(.+)\/([gimsuy]*)$/);
    if (flagMatch) {
      return { regex: new RegExp(flagMatch[1]!, flagMatch[2] || ""), versionGroup };
    }
    return { regex: new RegExp(cleaned, "i"), versionGroup };
  } catch {
    return { regex: null, versionGroup: null };
  }
}

// ── Fingerprinting ──

export function fingerprint(
  input: FingerprintInput,
  projectRoot = process.cwd()
): FingerprintResult {
  const technologies = loadWappalyzerTechnologies(projectRoot);
  const detected: DetectedTechnology[] = [];
  const detectedNames = new Set<string>();

  for (const tech of technologies) {
    const result = matchTechnology(tech, input);
    if (result) {
      detected.push(result);
      detectedNames.add(tech.name.toLowerCase());
    }
  }

  // Resolve "implies" dependencies
  for (const d of [...detected]) {
    const tech = technologies.find((t) => t.name.toLowerCase() === d.name.toLowerCase());
    if (!tech?.implies) continue;

    for (const impliedName of tech.implies) {
      if (detectedNames.has(impliedName.toLowerCase())) continue;

      const impliedTech = technologies.find((t) => t.name.toLowerCase() === impliedName.toLowerCase());
      if (impliedTech) {
        detected.push({
          name: impliedTech.name,
          categories: impliedTech.categories,
          confidence: Math.max(10, d.confidence - 20),
          evidence: [`implied by ${tech.name}`],
          implied: true,
        });
        detectedNames.add(impliedName.toLowerCase());
      }
    }
  }

  return {
    url: input.url,
    technologies: detected,
    matchCount: detected.length,
  };
}

function matchTechnology(
  tech: WappalyzerTechnology,
  input: FingerprintInput
): DetectedTechnology | null {
  const evidence: string[] = [];
  let version: string | undefined;
  let totalWeight = 0;
  let matchWeight = 0;

  // Headers — highest confidence (weight: 4)
  if (tech.headers) {
    totalWeight += 4;
    for (const [headerName, regex] of tech.headers) {
      const headerKey = Object.keys(input.headers).find(
        (k) => k.toLowerCase() === headerName
      );
      if (!headerKey) continue;
      const value = input.headers[headerKey]!;
      const match = regex.exec(value);
      if (match) {
        matchWeight += 4;
        evidence.push(`header:${headerName}=${value.slice(0, 80)}`);
        if (match[1] && !version) version = match[1];
        break;
      }
    }
  }

  // Meta tags (weight: 3)
  if (tech.meta && input.meta) {
    totalWeight += 3;
    for (const [metaName, regex] of tech.meta) {
      const metaValue = input.meta[metaName];
      if (!metaValue) continue;
      const match = regex.exec(metaValue);
      if (match) {
        matchWeight += 3;
        evidence.push(`meta:${metaName}=${metaValue.slice(0, 80)}`);
        if (match[1] && !version) version = match[1];
        break;
      }
    }
  }

  // Cookies (weight: 3)
  if (tech.cookies && input.cookies) {
    totalWeight += 3;
    for (const [cookieName, regex] of tech.cookies) {
      const cookieKey = Object.keys(input.cookies).find(
        (k) => k.toLowerCase() === cookieName
      );
      if (!cookieKey) continue;
      const value = input.cookies[cookieKey]!;
      if (regex.test(value)) {
        matchWeight += 3;
        evidence.push(`cookie:${cookieKey}`);
        break;
      }
    }
  }

  // HTML body (weight: 2)
  if (tech.html && input.html) {
    totalWeight += 2;
    for (const regex of tech.html) {
      const match = regex.exec(input.html);
      if (match) {
        matchWeight += 2;
        evidence.push(`html:${match[0].slice(0, 60)}`);
        if (match[1] && !version) version = match[1];
        break;
      }
    }
  }

  // Script sources (weight: 2)
  if (tech.scriptSrc && input.scriptSrc) {
    totalWeight += 2;
    for (const regex of tech.scriptSrc) {
      for (const src of input.scriptSrc) {
        const match = regex.exec(src);
        if (match) {
          matchWeight += 2;
          evidence.push(`scriptSrc:${src.slice(0, 80)}`);
          if (match[1] && !version) version = match[1];
          break;
        }
      }
    }
  }

  // URL patterns (weight: 1)
  if (tech.url) {
    totalWeight += 1;
    for (const regex of tech.url) {
      if (regex.test(input.url)) {
        matchWeight += 1;
        evidence.push(`url:${input.url}`);
        break;
      }
    }
  }

  if (matchWeight === 0) return null;

  const confidence = Math.min(100, Math.round((matchWeight / Math.max(totalWeight, 1)) * 100));

  return {
    name: tech.name,
    version,
    categories: tech.categories,
    confidence,
    evidence,
    implied: false,
  };
}

// ── Utility: extract script src URLs from HTML ──

export function extractScriptSrc(html: string): string[] {
  const regex = /<script[^>]+src=["']([^"']+)["']/gi;
  const srcs: string[] = [];
  let match: RegExpExecArray | null;
  while ((match = regex.exec(html)) !== null) {
    srcs.push(match[1]!);
  }
  return srcs;
}

// ── Utility: extract meta tags from HTML ──

export function extractMeta(html: string): Record<string, string> {
  const meta: Record<string, string> = {};
  const regex = /<meta\s+[^>]*(?:name|property|http-equiv)=["']([^"']+)["'][^>]*content=["']([^"']*)["'][^>]*\/?>/gi;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(html)) !== null) {
    meta[match[1]!.toLowerCase()] = match[2]!;
  }
  return meta;
}

// ── Utility: parse Set-Cookie headers into { name: value } ──

export function extractCookies(headers: Record<string, string>): Record<string, string> {
  const cookies: Record<string, string> = {};
  const setCookie = Object.entries(headers).find(
    ([k]) => k.toLowerCase() === "set-cookie"
  );
  if (!setCookie) return cookies;

  const values = Array.isArray(setCookie[1]) ? setCookie[1] : [setCookie[1]];
  for (const val of values) {
    const match = (val as string).match(/^([^=;]+)=?([^;]*)/);
    if (match) {
      cookies[match[1]!.toLowerCase()] = match[2] ?? "";
    }
  }
  return cookies;
}
