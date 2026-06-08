// ── Self-Learning Feedback ──
// Inspired by Cairn's Blackboard Architecture: successful attack paths are serialized
// as immutable AttackPathRecords and indexed for BM25 retrieval in future sessions.
// This is NOT a black-box replay — every record is a traceable Fact graph node.
//
// Flow:
//   Session validated findings → AttackPathRecord JSON → data/security-knowledge/feedback/
//   Next similar target → BM25 search across all records → injected into context

import { existsSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join as joinPath } from "node:path";
import { nowIso } from "@aegisprobe/shared";

// ── Types ──

export type AttackPathRecord = {
  id: string;
  createdAt: string;
  sourceSessionId: string;
  target: {
    kind: "url" | "hostname" | "ip";
    value: string;
  };
  summary: string;
  technologies: string[];               // detected technologies (name@version)
  validatedFindings: AttackPathFinding[];
  toolsUsed: string[];                  // tools that produced evidence
  cveMatches: AttackPathCveReference[];
  tags: string[];                       // auto-extracted: framework names, CWE, attack types
  priorityScore: number;                // composite priority for retrieval ranking
};

export type AttackPathFinding = {
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  category: string;                     // OWASP category or CWE
  description: string;
  evidence: string;                     // key evidence that validated this finding
  remediation: string;
};

export type AttackPathCveReference = {
  cveId: string;
  cvssScore?: number;
  epssPercentile?: number;
  inKev: boolean;
  matched: boolean;                     // was this CVE validated against the target?
};

export type FeedbackSearchResult = {
  record: AttackPathRecord;
  score: number;                        // BM25 relevance score
  highlights: string[];                 // matched terms
};

// ── Feedback Index (simple BM25 over tags + summary + technology names) ──

export type FeedbackIndex = {
  records: AttackPathRecord[];
  updatedAt: string;
};

// ── Path helpers ──

export function feedbackRoot(projectRoot = process.cwd()): string {
  return joinPath(projectRoot, "data", "security-knowledge", "feedback");
}

export function feedbackIndexPath(projectRoot = process.cwd()): string {
  return joinPath(feedbackRoot(projectRoot), "index.json");
}

// ── Serialization ──

export function saveAttackPathRecord(record: AttackPathRecord, projectRoot = process.cwd()): void {
  const root = feedbackRoot(projectRoot);
  if (!existsSync(root)) {
    mkdirSync(root, { recursive: true });
  }

  // Save individual record
  const recordPath = joinPath(root, `${record.id}.json`);
  writeFileSync(recordPath, JSON.stringify(record, null, 2), "utf8");

  // Update index
  const index = loadFeedbackIndex(projectRoot);
  const existing = index.records.findIndex((r) => r.id === record.id);
  if (existing >= 0) {
    index.records[existing] = record;
  } else {
    index.records.push(record);
  }
  index.updatedAt = nowIso();
  writeFileSync(feedbackIndexPath(projectRoot), JSON.stringify(index, null, 2), "utf8");
}

export function loadFeedbackIndex(projectRoot = process.cwd()): FeedbackIndex {
  const indexPath = feedbackIndexPath(projectRoot);
  if (!existsSync(indexPath)) {
    return { records: [], updatedAt: nowIso() };
  }
  try {
    const raw = readFileSync(indexPath, "utf8");
    return JSON.parse(raw) as FeedbackIndex;
  } catch {
    return { records: [], updatedAt: nowIso() };
  }
}

export function loadAllFeedbackRecords(projectRoot = process.cwd()): AttackPathRecord[] {
  const root = feedbackRoot(projectRoot);
  if (!existsSync(root)) return [];

  const records: AttackPathRecord[] = [];
  const entries = readdirSync(root, { withFileTypes: true });
  for (const entry of entries) {
    if (entry.isFile() && entry.name.endsWith(".json") && entry.name !== "index.json") {
      try {
        const raw = readFileSync(joinPath(root, entry.name), "utf8");
        records.push(JSON.parse(raw) as AttackPathRecord);
      } catch {
        // Skip corrupted files
      }
    }
  }
  return records;
}

// ── Tokenization (security-domain aware, same style as vectorizer.ts) ──

const STOP_WORDS = new Set([
  "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
  "have", "has", "had", "do", "does", "did", "will", "would", "could",
  "should", "may", "might", "can", "shall", "to", "of", "in", "for",
  "on", "with", "at", "by", "from", "as", "into", "through", "during",
  "before", "after", "above", "below", "between", "and", "but", "or",
  "not", "no", "nor", "so", "yet", "both", "either", "neither", "each",
  "every", "all", "any", "few", "more", "most", "other", "some", "such",
  "only", "own", "same", "than", "too", "very", "just", "that", "this",
]);

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9_\-.:/]/g, " ")
    .split(/\s+/)
    .filter((t) => t.length > 1 && !STOP_WORDS.has(t));
}

// ── BM25 search ──

function bm25Score(
  queryTokens: string[],
  docTokens: string[],
  totalDocs: number,
  docFreqs: Map<string, number>,
  avgDocLen: number,
  k1 = 1.5,
  b = 0.75
): number {
  const docLen = docTokens.length;
  let score = 0;

  // Term frequencies in this document
  const tf = new Map<string, number>();
  for (const t of docTokens) {
    tf.set(t, (tf.get(t) ?? 0) + 1);
  }

  for (const token of queryTokens) {
    const f = tf.get(token) ?? 0;
    if (f === 0) continue;
    const df = docFreqs.get(token) ?? 0;
    if (df === 0) continue;

    const idf = Math.log(1 + (totalDocs - df + 0.5) / (df + 0.5));
    const numerator = f * (k1 + 1);
    const denominator = f + k1 * (1 - b + b * (docLen / avgDocLen));
    score += idf * (numerator / denominator);
  }

  return score;
}

function buildDocText(record: AttackPathRecord): string {
  return [
    record.summary,
    record.target.value,
    ...record.technologies,
    ...record.tags,
    ...record.validatedFindings.map((f) => `${f.title} ${f.category} ${f.description}`),
    ...record.cveMatches.filter((c) => c.matched).map((c) => c.cveId),
    ...record.toolsUsed,
  ].join(" ");
}

export function searchFeedback(
  query: string,
  options: {
    projectRoot?: string;
    topK?: number;
    minScore?: number;
  } = {}
): FeedbackSearchResult[] {
  const projectRoot = options.projectRoot ?? process.cwd();
  const topK = options.topK ?? 5;
  const minScore = options.minScore ?? 0.1;

  const records = loadAllFeedbackRecords(projectRoot);
  if (records.length === 0) return [];

  const queryTokens = tokenize(query);
  if (queryTokens.length === 0) return [];

  // Build document texts and tokenize
  const docTexts = records.map(buildDocText);
  const docTokensList = docTexts.map(tokenize);

  // Compute document frequencies
  const docFreqs = new Map<string, number>();
  for (const tokens of docTokensList) {
    const seen = new Set<string>();
    for (const t of tokens) {
      if (!seen.has(t)) {
        docFreqs.set(t, (docFreqs.get(t) ?? 0) + 1);
        seen.add(t);
      }
    }
  }

  const avgDocLen = docTokensList.reduce((sum, t) => sum + t.length, 0) / records.length;

  // Score each document
  const scored = records.map((record, i) => ({
    record,
    score: bm25Score(queryTokens, docTokensList[i], records.length, docFreqs, avgDocLen),
  }));

  // Filter and sort
  return scored
    .filter((s) => s.score >= minScore)
    .sort((a, b) => b.score - a.score)
    .slice(0, topK)
    .map((s) => ({
      record: s.record,
      score: s.score,
      highlights: findHighlightTerms(queryTokens, docTokensList[records.indexOf(s.record)]),
    }));
}

function findHighlightTerms(queryTokens: string[], docTokens: string[]): string[] {
  const docSet = new Set(docTokens);
  return queryTokens.filter((t) => docSet.has(t)).slice(0, 8);
}

// ── Auto-tagging from record content ──

export function extractTagsFromRecord(record: AttackPathRecord): string[] {
  const tags = new Set<string>();

  // From technologies
  for (const tech of record.technologies) {
    const name = tech.split("@")[0].toLowerCase();
    tags.add(name);
  }

  // From findings
  for (const f of record.validatedFindings) {
    tags.add(f.category.toLowerCase());
    tags.add(f.severity);
  }

  // From CVEs
  for (const cve of record.cveMatches) {
    if (cve.matched) tags.add(cve.cveId.toLowerCase());
  }

  // From tools
  for (const tool of record.toolsUsed) {
    tags.add(`tool:${tool.toLowerCase()}`);
  }

  return [...tags];
}

// ── Build record from session data ──

export function buildAttackPathRecord(params: {
  sessionId: string;
  target: AttackPathRecord["target"];
  technologies: Array<{ name: string; version?: string | null }>;
  validatedFindings: AttackPathFinding[];
  toolsUsed: string[];
  cveMatches: AttackPathCveReference[];
  summary?: string;
}): AttackPathRecord {
  const techNames = params.technologies.map((t) =>
    t.version ? `${t.name}@${t.version}` : t.name
  );

  const record: AttackPathRecord = {
    id: `feedback-${params.sessionId}`,
    createdAt: nowIso(),
    sourceSessionId: params.sessionId,
    target: params.target,
    summary: params.summary ?? `Pentest of ${params.target.value}: ${params.validatedFindings.length} validated findings across ${techNames.length} technologies.`,
    technologies: techNames,
    validatedFindings: params.validatedFindings,
    toolsUsed: [...new Set(params.toolsUsed)],
    cveMatches: params.cveMatches,
    tags: [],
    priorityScore: 0,
  };

  // Auto-extract tags
  record.tags = extractTagsFromRecord(record);

  // Compute priority score: weighted by severity distribution and CVE matches
  const severityWeights: Record<string, number> = { critical: 10, high: 7, medium: 4, low: 2, info: 1 };
  const findingScore = record.validatedFindings.reduce((sum, f) => sum + (severityWeights[f.severity] ?? 1), 0);
  const cveScore = record.cveMatches.filter((c) => c.matched).length * 5;
  const techScore = techNames.length * 2;
  record.priorityScore = Math.min(findingScore + cveScore + techScore, 100);

  return record;
}

// ── Context injection helper ──

export function buildFeedbackContext(
  target: string,
  technologies: string[],
  options: { projectRoot?: string; topK?: number; maxChars?: number } = {}
): string {
  const query = [target, ...technologies].join(" ");
  const results = searchFeedback(query, {
    projectRoot: options.projectRoot,
    topK: options.topK ?? 3,
    minScore: 0.05,
  });

  if (results.length === 0) return "";

  const maxChars = options.maxChars ?? 3000;
  const lines = ["## Relevant Past Attack Paths", ""];
  let charCount = 0;

  for (const { record, score } of results) {
    const entry = [
      `### ${record.target.value} (relevance: ${(score * 100).toFixed(0)}%)`,
      `- Session: ${record.sourceSessionId}`,
      `- Date: ${record.createdAt}`,
      `- Technologies: ${record.technologies.join(", ")}`,
      `- Validated findings: ${record.validatedFindings.length}`,
      record.validatedFindings.length > 0
        ? record.validatedFindings
            .slice(0, 5)
            .map((f) => `  - [${f.severity}] ${f.title} — ${f.evidence.slice(0, 120)}`)
            .join("\n")
        : "  - No validated findings",
      record.cveMatches.filter((c) => c.matched).length > 0
        ? `- Matched CVEs: ${record.cveMatches.filter((c) => c.matched).map((c) => c.cveId).join(", ")}`
        : undefined,
      "",
    ].filter(Boolean).join("\n");

    if (charCount + entry.length > maxChars) break;
    lines.push(entry);
    charCount += entry.length;
  }

  return lines.join("\n");
}
