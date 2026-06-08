// ── Mature RAG Vector Store ──
// Implements BM25 + hybrid scoring + security-domain tokenization.
// Inspired by: LangChain, LlamaIndex, ChromaDB, PentestGPT context retrieval.
//
// Key features:
//   - BM25 scoring (k1=1.5, b=0.75) — industry standard text retrieval
//   - Security-domain tokenizer — CVE, IP, port, version, protocol extraction
//   - Document chunking with overlap — handles large evidence/findings
//   - Hybrid score = BM25 × recencyBoost × severityBoost × sourceAuthority
//   - Incremental indexing — add/remove without full rebuild
//   - SQLite persistence (optional) — survive restarts

// ── Types ──

export type SecurityDocKind =
  | "finding"
  | "cve"
  | "technology"
  | "evidence"
  | "asset"
  | "observation"
  | "workflow"
  | "subagent_output";

export type SecurityDocument = {
  id: string;
  kind: SecurityDocKind;
  text: string;
  // Scoring metadata
  severity?: "critical" | "high" | "medium" | "low" | "info";
  confidence?: "high" | "medium" | "low";
  source?: string;           // e.g. "nmap", "httpx", "wappalyzer"
  createdAt?: string;        // ISO timestamp for recency boost
  // Linkage
  targetUrl?: string;
  technologyName?: string;
  cveId?: string;
};

export type ScoredDocument = {
  doc: SecurityDocument;
  bm25Score: number;
  recencyBoost: number;
  severityBoost: number;
  hybridScore: number;
};

export type SearchOptions = {
  topK?: number;             // default 20
  minScore?: number;         // minimum hybrid score threshold
  boostRecentHours?: number; // window for recency boost (default 24)
  boostSeverity?: boolean;   // boost by severity (default true)
};

// ── BM25 Parameters ──

const BM25_K1 = 1.5;   // term frequency saturation
const BM25_B = 0.75;    // length normalization

// ── Security-Domain Tokenizer ──

const STOP_WORDS = new Set([
  "the","a","an","is","are","was","were","be","been","being","have","has","had",
  "do","does","did","will","would","could","should","may","might","can","shall",
  "to","of","in","for","on","with","at","by","from","as","into","through","during",
  "before","after","above","below","between","and","but","or","not","no","if",
  "then","else","when","where","why","how","this","that","these","those","it",
  "its","he","she","they","we","you","i","me","my","your","our","their","his","her",
  "的","是","在","了","和","也","就","都","而","及","与","着","或","一个",
  "没有","我们","你们","他们","它们","自己","这","那","这个","那个",
  "这些","那些","什么","哪","怎么",
]);

// Security-domain specific token patterns
const SECURITY_PATTERNS: Array<[RegExp, (m: string, ...groups: string[]) => string]> = [
  // CVE IDs → normalized
  [/\bCVE-\d{4}-\d{4,}\b/gi, (m: string) => `cve:${m.toUpperCase()}`],
  // CWE IDs
  [/\bCWE-\d+\b/gi, (m: string) => `cwe:${m.toUpperCase()}`],
  // CVSS scores
  [/\bCVSS:3\.[01]\/[A-Z:/.]+/g, (m: string) => `cvss_vector`],
  // IP addresses → normalize
  [/\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b/g, (m: string) => `ip:${m}`],
  // Port numbers with context
  [/\bport\s*(\d{1,5})\b/gi, (_, p: string) => `port:${p}`],
  [/:(\d{2,5})\//g, (_, p: string) => `port:${p}`],
  // Version numbers
  [/\b(\d+\.\d+(?:\.\d+)*(?:-[a-zA-Z0-9.]+)?)\b/g, (m: string) => `version:${m}`],
  // Protocols
  [/\b(https?|ftp|ssh|smtp|snmp|rdp|smb|mysql|postgresql|mongodb|redis)\b/gi, (m: string) => `proto:${m.toLowerCase()}`],
  // Severity labels
  [/\b(critical|high|medium|low|info)\b/gi, (m: string) => `severity:${m.toLowerCase()}`],
  // HTTP methods
  [/\b(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\b/g, (m: string) => `method:${m}`],
  // Status codes
  [/\bstatus[=:]\s*(\d{3})\b/gi, (_, c: string) => `status:${c}`],
  [/\bHTTP\s*(\d{3})\b/gi, (_, c: string) => `status:${c}`],
  // File extensions (security-relevant)
  [/\b\.(php|asp|aspx|jsp|py|rb|pl|cgi|sh|bat|exe|dll|so|conf|config|env|yml|yaml|json|xml|sql|db|bak|old|swp|git|svn)\b/gi, (m: string) => `ext:${m.toLowerCase()}`],
];

function tokenize(text: string): string[] {
  const normalized = text.toLowerCase();
  const tokens: string[] = [];

  // 1. Extract security-domain patterns
  const consumed = new Set<string>();
  for (const [pattern, mapper] of SECURITY_PATTERNS) {
    for (const match of normalized.matchAll(pattern)) {
      const raw = match[0];
      if (!consumed.has(raw)) {
        consumed.add(raw);
        const mapped = mapper(raw, ...match.slice(1));
        tokens.push(mapped);
      }
    }
  }

  // 2. Extract meaningful words (alphabetic, 2+ chars, no stop words)
  for (const match of normalized.matchAll(/\b[a-z][a-z0-9_-]{1,}\b/g)) {
    const word = match[0];
    if (!STOP_WORDS.has(word) && word.length >= 2 && !consumed.has(word)) {
      tokens.push(word);
    }
  }

  // 3. Bigrams for context (adjacent meaningful words)
  const words = normalized.match(/\b[a-z]{2,}\b/g) || [];
  for (let i = 0; i < words.length - 1; i++) {
    const w1 = words[i]!, w2 = words[i + 1]!;
    if (!STOP_WORDS.has(w1) && !STOP_WORDS.has(w2)) {
      tokens.push(`bigram:${w1}_${w2}`);
    }
  }

  // 4. Chinese characters (2+ consecutive)
  for (const match of normalized.matchAll(/[\u4e00-\u9fff]{2,}/g)) {
    tokens.push(`zh:${match[0]}`);
  }

  // Deduplicate while preserving order
  const seen = new Set<string>();
  return tokens.filter((t) => {
    if (seen.has(t)) return false;
    seen.add(t);
    return true;
  });
}

// ── Document Chunking ──

export function chunkDocument(
  text: string,
  maxChunkChars = 2000,
  overlapChars = 200
): string[] {
  if (text.length <= maxChunkChars) return [text];

  const chunks: string[] = [];
  let start = 0;
  while (start < text.length) {
    let end = start + maxChunkChars;
    if (end < text.length) {
      // Try to break at a sentence boundary
      const boundary = text.lastIndexOf(". ", end);
      if (boundary > start + maxChunkChars / 2) {
        end = boundary + 1;
      }
    }
    chunks.push(text.slice(start, Math.min(end, text.length)));
    start = end - overlapChars;
    if (start < 0) start = 0;
    if (start >= text.length) break;
  }
  return chunks;
}

// ── BM25 Index ──

type TermStats = {
  df: number;                          // document frequency
  postings: Map<string, number>;       // docId → term frequency in that doc
};

export class Bm25Index {
  private terms = new Map<string, TermStats>();  // term → stats
  private docs = new Map<string, SecurityDocument>();
  private docLengths = new Map<string, number>();
  private totalDocs = 0;
  private totalTokens = 0;

  // ── Indexing ──

  addDocument(doc: SecurityDocument, tokens?: string[]): void {
    const docTokens = tokens ?? tokenize(doc.text);
    const docLen = docTokens.length;

    // Remove old version of this document
    if (this.docs.has(doc.id)) {
      this.removeDocument(doc.id);
    }

    this.docs.set(doc.id, doc);
    this.docLengths.set(doc.id, docLen);
    this.totalDocs++;
    this.totalTokens += docLen;

    // Count term frequencies for this document
    const localTf = new Map<string, number>();
    for (const t of docTokens) {
      localTf.set(t, (localTf.get(t) || 0) + 1);
    }

    // Update global term stats
    for (const [term, tf] of localTf) {
      let stats = this.terms.get(term);
      if (!stats) {
        stats = { df: 0, postings: new Map() };
        this.terms.set(term, stats);
      }
      stats.df++;
      stats.postings.set(doc.id, tf);
    }
  }

  addDocuments(docs: SecurityDocument[]): void {
    for (const doc of docs) this.addDocument(doc);
  }

  removeDocument(docId: string): void {
    const doc = this.docs.get(docId);
    if (!doc) return;

    this.docs.delete(docId);
    const docLen = this.docLengths.get(docId) || 0;
    this.docLengths.delete(docId);
    this.totalDocs--;
    this.totalTokens -= docLen;

    // Update term stats (decrement df, remove posting)
    for (const [term, stats] of this.terms) {
      if (stats.postings.has(docId)) {
        stats.df--;
        stats.postings.delete(docId);
        if (stats.df <= 0) this.terms.delete(term);
      }
    }
  }

  // ── BM25 Scoring ──

  private avgDocLength(): number {
    return this.totalDocs > 0 ? this.totalTokens / this.totalDocs : 1;
  }

  /** IDF component */
  private idf(term: string): number {
    const stats = this.terms.get(term);
    if (!stats || stats.df === 0) return 0;
    return Math.log((this.totalDocs - stats.df + 0.5) / (stats.df + 0.5) + 1);
  }

  /** Score a single document against query tokens */
  score(queryTokens: string[], docId: string): number {
    const docLen = this.docLengths.get(docId) || 0;
    if (docLen === 0) return 0;
    const avgdl = this.avgDocLength();

    let score = 0;
    for (const qt of queryTokens) {
      const idf = this.idf(qt);
      if (idf === 0) continue;

      const stats = this.terms.get(qt);
      const tf = stats?.postings.get(docId) || 0;
      if (tf === 0) continue;

      // BM25 formula
      const numerator = tf * (BM25_K1 + 1);
      const denominator = tf + BM25_K1 * (1 - BM25_B + BM25_B * (docLen / avgdl));
      score += idf * (numerator / denominator);
    }
    return score;
  }

  // ── Search ──

  search(
    query: string,
    options: SearchOptions = {}
  ): ScoredDocument[] {
    const queryTokens = tokenize(query);
    if (queryTokens.length === 0) return [];

    const topK = options.topK ?? 20;
    const minScore = options.minScore ?? 0;
    const now = Date.now();
    const boostWindow = (options.boostRecentHours ?? 24) * 60 * 60 * 1000;

    const results: ScoredDocument[] = [];

    for (const [docId, doc] of this.docs) {
      const bm25 = this.score(queryTokens, docId);
      if (bm25 < 0.001) continue;

      // ── Recency boost ──
      let recencyBoost = 1.0;
      if (doc.createdAt) {
        const ageMs = now - new Date(doc.createdAt).getTime();
        if (ageMs < boostWindow) {
          recencyBoost = 1.0 + 0.5 * (1 - ageMs / boostWindow); // up to 1.5x
        } else {
          recencyBoost = Math.max(0.5, Math.exp(-ageMs / (boostWindow * 4))); // decay
        }
      }

      // ── Severity boost ──
      let severityBoost = 1.0;
      if (options.boostSeverity !== false && doc.severity) {
        const sevWeights: Record<string, number> = { critical: 2.0, high: 1.5, medium: 1.2, low: 1.0, info: 0.8 };
        severityBoost = sevWeights[doc.severity] ?? 1.0;
      }

      // ── Source authority boost ──
      let sourceBoost = 1.0;
      if (doc.source) {
        const src = doc.source.toLowerCase();
        if (src.includes("nuclei")) sourceBoost = 1.3;
        else if (src.includes("wappalyzer")) sourceBoost = 1.2;
        else if (src.includes("nmap")) sourceBoost = 1.15;
        else if (src.includes("httpx")) sourceBoost = 1.1;
      }

      const hybridScore = bm25 * recencyBoost * severityBoost * sourceBoost;

      if (hybridScore >= minScore) {
        results.push({ doc, bm25Score: bm25, recencyBoost, severityBoost, hybridScore });
      }
    }

    // Sort by hybrid score
    results.sort((a, b) => b.hybridScore - a.hybridScore);
    return results.slice(0, topK);
  }

  /** Multi-vector search: combine results from multiple query variants */
  multiSearch(queries: string[], options: SearchOptions = {}): ScoredDocument[] {
    const allResults = new Map<string, ScoredDocument>();

    for (const query of queries) {
      for (const result of this.search(query, { ...options, topK: options.topK ?? 10 })) {
        const existing = allResults.get(result.doc.id);
        if (existing) {
          existing.hybridScore = Math.max(existing.hybridScore, result.hybridScore);
          existing.bm25Score = Math.max(existing.bm25Score, result.bm25Score);
        } else {
          allResults.set(result.doc.id, result);
        }
      }
    }

    const merged = [...allResults.values()];
    merged.sort((a, b) => b.hybridScore - a.hybridScore);
    return merged.slice(0, options.topK ?? 20);
  }

  // ── Stats ──

  size(): number { return this.docs.size; }
  termCount(): number { return this.terms.size; }
  clear(): void {
    this.terms.clear();
    this.docs.clear();
    this.docLengths.clear();
    this.totalDocs = 0;
    this.totalTokens = 0;
  }
}

// ── Batch Import: Convert ContextBuildInput items to SecurityDocuments ──

export function toSecurityDocuments(input: {
  findings?: Array<{ id: string; title: string; severity?: string; confidence?: string; target?: string; description?: string; evidenceSummary?: string }>;
  cveMatches?: Array<{ cveId?: string; title: string; severity?: string; confidence?: string; technology?: string; rationale?: string }>;
  technologies?: Array<{ target?: string; name: string; version?: string; category?: string; confidence?: string; evidenceSummary?: string; source?: string }>;
  evidence?: Array<{ id: string; kind: string; source: string; summary: string }>;
  assets?: Array<{ id: string; kind: string; value: string; confidence?: string; source?: string }>;
  observations?: Array<{ id: string; source: string; summary: string }>;
}): SecurityDocument[] {
  const docs: SecurityDocument[] = [];

  for (const f of input.findings ?? []) {
    docs.push({
      id: `finding:${f.id}`,
      kind: "finding",
      text: `[${f.severity ?? "info"}/${f.confidence ?? "low"}] ${f.target ?? ""}: ${f.title}. ${f.description ?? ""} ${f.evidenceSummary ?? ""}`,
      severity: (f.severity as SecurityDocument["severity"]) ?? "info",
      confidence: (f.confidence as SecurityDocument["confidence"]) ?? "low",
      targetUrl: f.target,
    });
  }

  for (const c of input.cveMatches ?? []) {
    docs.push({
      id: `cve:${c.cveId ?? c.title}`,
      kind: "cve",
      text: `[${c.severity ?? "info"}/${c.confidence ?? "low"}] ${c.technology ?? ""}: ${c.cveId ?? ""} ${c.title}. ${c.rationale ?? ""}`,
      severity: (c.severity as SecurityDocument["severity"]) ?? "info",
      confidence: (c.confidence as SecurityDocument["confidence"]) ?? "low",
      cveId: c.cveId,
      technologyName: c.technology,
    });
  }

  for (const t of input.technologies ?? []) {
    docs.push({
      id: `tech:${t.target ?? ""}:${t.name}`,
      kind: "technology",
      text: `${t.target ?? ""}: ${t.name} ${t.version ?? ""} (${t.category ?? ""}) ${t.evidenceSummary ?? ""}`,
      confidence: (t.confidence as SecurityDocument["confidence"]) ?? "medium",
      targetUrl: t.target,
      technologyName: t.name,
      source: t.source,
    });
  }

  for (const e of input.evidence ?? []) {
    const text = `[${e.kind}] ${e.source}: ${e.summary}`;
    if (text.length > 20) {
      docs.push({ id: `evidence:${e.id}`, kind: "evidence", text, source: e.source });
    }
  }

  for (const a of input.assets ?? []) {
    docs.push({
      id: `asset:${a.id}`,
      kind: "asset",
      text: `${a.kind} ${a.value} (${a.confidence ?? "medium"}) source:${a.source ?? "unknown"}`,
      confidence: (a.confidence as SecurityDocument["confidence"]) ?? "medium",
      source: a.source,
    });
  }

  for (const o of input.observations ?? []) {
    docs.push({ id: `obs:${o.id}`, kind: "observation", text: `${o.source}: ${o.summary}`, source: o.source });
  }

  return docs;
}
