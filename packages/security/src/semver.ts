// ── Semantic Version Matcher ──
// Proper semver parsing + range matching.
// Supports: exact, range (>=, <, <=, >), ~> (pessimistic), ^ (compatible)

export type Semver = {
  major: number;
  minor: number;
  patch: number;
  prerelease?: string;
  raw: string;
};

export type VersionRange = {
  minVersion?: Semver;      // inclusive
  minExclusive?: boolean;
  maxVersion?: Semver;      // exclusive
  maxInclusive?: boolean;
  exactVersions?: Semver[];
  raw?: string;
};

// ── Parser ──

const SEMVER_RE = /^(\d+)\.(\d+)\.(\d+)(?:-([\w.]+))?$/;

export function parseSemver(version: string): Semver | null {
  // Strip leading 'v' or 'V'
  const cleaned = version.trim().replace(/^[vV]/, "");
  const match = cleaned.match(SEMVER_RE);
  if (!match) return null;

  return {
    major: Number.parseInt(match[1]!, 10),
    minor: Number.parseInt(match[2]!, 10),
    patch: Number.parseInt(match[3]!, 10),
    prerelease: match[4],
    raw: version.trim(),
  };
}

export function parseSemverLenient(version: string): Semver | null {
  // Try standard semver first
  const standard = parseSemver(version);
  if (standard) return standard;

  // Try to extract numbers from arbitrary version strings
  const nums = version.match(/(\d+)(?:\.(\d+))?(?:\.(\d+))?/);
  if (!nums) return null;

  return {
    major: Number.parseInt(nums[1]!, 10),
    minor: Number.parseInt(nums[2] || "0", 10),
    patch: Number.parseInt(nums[3] || "0", 10),
    raw: version.trim(),
  };
}

// ── Comparison ──

export function compareSemver(a: Semver, b: Semver): number {
  if (a.major !== b.major) return a.major - b.major;
  if (a.minor !== b.minor) return a.minor - b.minor;
  if (a.patch !== b.patch) return a.patch - b.patch;

  // Prerelease versions are lower than release versions
  if (a.prerelease && !b.prerelease) return -1;
  if (!a.prerelease && b.prerelease) return 1;
  if (a.prerelease && b.prerelease) {
    return a.prerelease.localeCompare(b.prerelease);
  }
  return 0;
}

// ── Range Matching ──

export function parseVersionRange(spec: string): VersionRange {
  const trimmed = spec.trim();

  // Exact version list: "1.2.3, 1.2.4"
  if (/^[\d.]+(?:,\s*[\d.]+)*$/.test(trimmed)) {
    const versions = trimmed.split(",").map((v) => parseSemver(v.trim())).filter(Boolean) as Semver[];
    return { exactVersions: versions, raw: trimmed };
  }

  // Range: ">=1.2.3, <2.0.0"
  const parts = trimmed.split(",").map((p) => p.trim());
  const range: VersionRange = { raw: trimmed };

  for (const part of parts) {
    if (part.startsWith(">=")) {
      range.minVersion = parseSemver(part.slice(2)) || undefined;
      range.minExclusive = false;
    } else if (part.startsWith(">")) {
      range.minVersion = parseSemver(part.slice(1)) || undefined;
      range.minExclusive = true;
    } else if (part.startsWith("<=")) {
      range.maxVersion = parseSemver(part.slice(2)) || undefined;
      range.maxInclusive = true;
    } else if (part.startsWith("<")) {
      range.maxVersion = parseSemver(part.slice(1)) || undefined;
      range.maxInclusive = false;
    } else if (part.startsWith("~>")) {
      // Pessimistic: ~>1.2.3 means >=1.2.3, <1.3.0
      const v = parseSemver(part.slice(2));
      if (v) {
        range.minVersion = v;
        range.minExclusive = false;
        range.maxVersion = { major: v.major, minor: v.minor + 1, patch: 0, raw: `${v.major}.${v.minor + 1}.0` };
        range.maxInclusive = false;
      }
    } else if (part.startsWith("~")) {
      // Tilde: ~1.2.3 means >=1.2.3, <1.3.0
      const v = parseSemver(part.slice(1));
      if (v) {
        range.minVersion = v;
        range.minExclusive = false;
        range.maxVersion = { major: v.major, minor: v.minor + 1, patch: 0, raw: `${v.major}.${v.minor + 1}.0` };
        range.maxInclusive = false;
      }
    } else if (part.startsWith("^")) {
      // Caret: ^1.2.3 means >=1.2.3, <2.0.0
      const v = parseSemver(part.slice(1));
      if (v) {
        range.minVersion = v;
        range.minExclusive = false;
        const nextMajor = v.major === 0 ? v.minor + 1 : v.major + 1;
        range.maxVersion = { major: nextMajor, minor: 0, patch: 0, raw: `${nextMajor}.0.0` };
        range.maxInclusive = false;
      }
    } else {
      // Single exact version
      const v = parseSemver(part);
      if (v) {
        if (!range.exactVersions) range.exactVersions = [];
        range.exactVersions.push(v);
      }
    }
  }

  return range;
}

export function versionInRange(version: string | Semver, range: VersionRange): boolean {
  const v = typeof version === "string" ? parseSemverLenient(version) : version;
  if (!v) return false;

  // Exact version match
  if (range.exactVersions) {
    for (const exact of range.exactVersions) {
      if (compareSemver(v, exact) === 0) return true;
    }
    return false;
  }

  // Min version check
  if (range.minVersion) {
    const cmp = compareSemver(v, range.minVersion);
    if (range.minExclusive ? cmp <= 0 : cmp < 0) return false;
  }

  // Max version check
  if (range.maxVersion) {
    const cmp = compareSemver(v, range.maxVersion);
    if (range.maxInclusive ? cmp > 0 : cmp >= 0) return false;
  }

  // If no bounds set and no exact match, return false (empty range = no match)
  if (!range.minVersion && !range.maxVersion && !range.exactVersions) return false;

  return true;
}

// ── Convenience: one-shot version match ──

export function matchesVersionRange(version: string, spec: string): boolean {
  const range = parseVersionRange(spec);
  return versionInRange(version, range);
}

// ── CPE version matching (handles CPE-specific wildcards) ──

export function matchesCpeVersion(observedVersion: string, cpeVersion: string): boolean {
  // CPE uses '*' for any, '-' for NA
  if (cpeVersion === "*" || cpeVersion === "-") return true;

  // CPE can have ranges like "1.2.3" or "1.2.*"
  if (cpeVersion.includes("*")) {
    const pattern = cpeVersion.replace(/\*/g, "\\d+");
    return new RegExp(`^${pattern}$`).test(observedVersion);
  }

  return parseSemverLenient(observedVersion)?.raw === parseSemverLenient(cpeVersion)?.raw;
}
