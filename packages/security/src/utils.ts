// Shared utility functions used across security modules

export function uniqueStrings(items: string[]): string[] {
  return [...new Set(items.map((item) => item.trim()).filter(Boolean))];
}

export function uniqueBy<T>(items: T[], keyOf: (item: T) => string): T[] {
  const seen = new Set<string>();
  return items.filter((item) => {
    const key = keyOf(item);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

export function normalizeName(name: string): string {
  return name.toLowerCase().replace(/[^a-z0-9]/g, "");
}

export function cleanVersion(version: string | undefined): string | undefined {
  return version?.replace(/^[^\d]*(\d+(?:\.\d+)*).*$/, "$1");
}

export function stripVersion(value: string): string {
  return value.replace(/\s+\d+(?:\.\d+){0,3}.*$/, "");
}

export function normalizeTargetForDedupe(value: string): string {
  return value.toLowerCase().replace(/\/+$/u, "").replace(/^https?:\/\//, "").replace(/:\d+$/, "");
}

export function confidenceRank(confidence: "low" | "medium" | "high"): number {
  return ({ low: 0, medium: 1, high: 2 })[confidence];
}

export function severityRank(severity: "info" | "low" | "medium" | "high" | "critical"): number {
  return ({ info: 0, low: 1, medium: 2, high: 3, critical: 4 })[severity];
}

export function isIpAddress(value: string): boolean {
  return /^\d+\.\d+\.\d+\.\d+$/.test(value.trim());
}

export function canonicalTechnologyName(name: string): string {
  return name.toLowerCase().replace(/[\s_-]+/g, " ").trim();
}

export function redactSecretLike(value: string): string {
  return value.replace(/((?:api[_-]?key|access[_-]?token|secret|client[_-]?secret)=)[^&\s]+/gi, "$1[redacted]");
}

export function safeHostname(value: string): string | undefined {
  try {
    const url = new URL(value.startsWith("http") ? value : `http://${value}`);
    return url.hostname.toLowerCase();
  } catch {
    return undefined;
  }
}
