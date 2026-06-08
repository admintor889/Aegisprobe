import { truncateForContext, type AgentObservation, type AgentPlan, type ContextFile, type FileChangeRecord, type SecurityAsset, type SecurityCveMatch, type SecurityEvidence, type SecurityFinding, type SecurityTechnology, type SecurityValidationCheck, type SecurityWorkflow, type ShellCommandRecord, type SubAgentRecord, type TargetInput } from "@aegisprobe/shared";
import { Bm25Index, toSecurityDocuments, chunkDocument, type SecurityDocument, type ScoredDocument } from "./vectorizer.js";

// ── Types ──

export type ContextRole = "system" | "user" | "assistant";
export type ContextMessage = { role: ContextRole; content: string; createdAt: string };
export type SessionMemory = { sessionId: string; summary: string; pinnedFacts: string[]; openTasks: string[]; updatedAt: string };
export type ContextSection = { title: string; content: string; priority: "pinned" | "high" | "normal" | "low"; tokens: number };

export type ContextSnapshot = {
  sessionId: string;
  prompt: string;
  sections: ContextSection[];
  messages: ContextMessage[];
  stats: {
    approxTokens: number;
    maxTokens: number;
    totalMessages: number;
    includedMessages: number;
    truncatedSections: string[];
    indexedDocuments: number;
    retrievedDocuments: number;
  };
};

export type ContextBuildInput = {
  sessionId: string;
  memory?: SessionMemory;
  messages: ContextMessage[];
  targets?: TargetInput[];
  plans?: AgentPlan[];
  observations?: AgentObservation[];
  commands?: ShellCommandRecord[];
  fileChanges?: FileChangeRecord[];
  subagents?: SubAgentRecord[];
  securityWorkflows?: SecurityWorkflow[];
  findings?: SecurityFinding[];
  evidence?: SecurityEvidence[];
  assets?: SecurityAsset[];
  technologies?: SecurityTechnology[];
  cveMatches?: SecurityCveMatch[];
  securityChecks?: SecurityValidationCheck[];
  currentInput?: string;
  currentTarget?: TargetInput;
  fileContexts?: ContextFile[];
  turnObservations?: string[];
  skillContext?: string;
  securityWorkflowContext?: string;
  taskTreeContext?: string;
  maxTokens?: number;
};

// ── Constants ──

export const DEFAULT_CONTEXT_TOKEN_BUDGET = 48_000;
const RECENT_MESSAGE_TOKEN_BUDGET = 16_000;
const VECTORIZED_STATE_TOKEN_BUDGET = 14_000;
const VECTOR_TOP_K = 25;
const SECTION_TOKEN_BUDGET = 8_000;

export function approxTokenCount(input: string): number {
  return Math.ceil(input.length / 4);
}

export function emptySessionMemory(sessionId: string, updatedAt: string): SessionMemory {
  return { sessionId, summary: "", pinnedFacts: [], openTasks: [], updatedAt };
}

// ── Semantic Context Manager ──

export class CodexLikeContextManager {
  private index = new Bm25Index();
  private sessionDocIds = new Set<string>();
  private lastIndexHash = "";
  private lastIndexedCount = 0;
  // Cache: only rebuild index when data actually changes
  private indexDirty = true;

  /** Mark index as needing rebuild on next build() */
  invalidateIndex(): void {
    this.indexDirty = true;
  }

  /** Index security state items for semantic retrieval — skips if unchanged */
  indexItems(input: ContextBuildInput, force = false): void {
    // Quick hash to detect if data changed
    const hash = `${input.findings?.length ?? 0}:${input.evidence?.length ?? 0}:${input.technologies?.length ?? 0}:${input.cveMatches?.length ?? 0}:${input.observations?.length ?? 0}`;
    if (!force && hash === this.lastIndexHash && !this.indexDirty) return;
    this.lastIndexHash = hash;
    this.indexDirty = false;

    // Clear previous session's docs
    for (const id of this.sessionDocIds) {
      this.index.removeDocument(id);
    }
    this.sessionDocIds.clear();

    const rawDocs = toSecurityDocuments({
      findings: input.findings?.map((f) => ({
        id: f.id,
        title: f.title,
        severity: f.severity,
        confidence: f.confidence,
        target: f.target,
        description: f.description,
        evidenceSummary: f.evidenceSummary,
      })),
      cveMatches: input.cveMatches?.map((c) => ({
        cveId: c.cveId,
        title: c.title,
        severity: c.severity,
        confidence: c.confidence,
        technology: c.technology,
        rationale: c.rationale,
      })),
      technologies: input.technologies?.map((t) => ({
        target: t.target,
        name: t.name,
        version: t.version,
        category: t.category,
        confidence: t.confidence,
        evidenceSummary: t.evidenceSummary,
        source: t.source,
      })),
      evidence: input.evidence?.map((e) => ({
        id: e.id,
        kind: e.kind,
        source: e.source,
        summary: e.summary,
      })),
      assets: input.assets?.map((a) => ({
        id: a.id,
        kind: a.kind,
        value: a.value,
        confidence: a.confidence,
        source: a.source,
      })),
      observations: input.observations?.map((o) => ({
        id: o.id,
        source: o.source,
        summary: o.summary,
      })),
    });

    // Chunk large documents and index
    for (const doc of rawDocs) {
      if (doc.text.trim().length < 15) continue;

      if (doc.text.length > 2000) {
        // Chunk large documents
        const chunks = chunkDocument(doc.text, 2000, 200);
        for (let i = 0; i < chunks.length; i++) {
          const chunkId = `${doc.id}/chunk${i}`;
          this.index.addDocument({ ...doc, id: chunkId, text: chunks[i]! });
          this.sessionDocIds.add(chunkId);
        }
      } else {
        this.index.addDocument(doc);
        this.sessionDocIds.add(doc.id);
      }
    }
  }

  build(input: ContextBuildInput): ContextSnapshot {
    const maxTokens = input.maxTokens ?? DEFAULT_CONTEXT_TOKEN_BUDGET;
    const truncatedSections: string[] = [];
    const sections: ContextSection[] = [];

    const addSection = (
      title: string,
      content: string | undefined,
      priority: ContextSection["priority"],
      maxChars = SECTION_TOKEN_BUDGET * 4
    ) => {
      const clean = content?.trim();
      if (!clean) return;
      const rendered = clean.length > maxChars ? truncateForContext(clean, maxChars) : clean;
      if (rendered !== clean) truncatedSections.push(title);
      sections.push({ title, content: rendered, priority, tokens: approxTokenCount(rendered) });
    };

    // ── Index for semantic retrieval ──
    this.indexItems(input);

    // ── Pinned sections (always included) ──
    const memory = input.memory ?? emptySessionMemory(input.sessionId, new Date().toISOString());
    addSection("Session Memory", renderMemory(memory), "pinned", 6_000);
    addSection("Current Input", renderCurrentInput(input.currentInput, input.currentTarget), "pinned", 4_000);
    addSection("Targets", renderTargets(input.targets ?? []), "high", 3_000);
    addSection("Open Plans", renderPlans(input.plans ?? []), "high", 6_000);

    // ── BM25 Semantic Retrieval ──
    const query = buildSearchQuery(input);
    let retrievedCount = 0;

    if (this.index.size() > 0 && query.length > 0) {
      // Multi-query search: use both the raw input and a distilled query
      const queries = [query];
      if (input.currentTarget) {
        queries.push(`target:${input.currentTarget.normalized}`);
      }

      const results = this.index.multiSearch(queries, {
        topK: VECTOR_TOP_K,
        boostRecentHours: 24,
        boostSeverity: true,
      });

      if (results.length > 0) {
        const lines: string[] = [
          `BM25-ranked relevant items (${results.length} of ${this.index.size()} indexed):`,
        ];
        for (const { doc, hybridScore, bm25Score, recencyBoost, severityBoost } of results) {
          const relevance = hybridScore > 5 ? "HIGH" : hybridScore > 2 ? "MED" : "LOW";
          const boosts = [];
          if (recencyBoost > 1.1) boosts.push(`recency:${recencyBoost.toFixed(1)}x`);
          if (severityBoost > 1.1) boosts.push(`severity:${severityBoost.toFixed(1)}x`);
          const boostStr = boosts.length > 0 ? ` (${boosts.join(", ")})` : "";
          lines.push(`[${relevance}${boostStr}] ${doc.text.slice(0, 500)}`);
        }
        addSection("Relevant Security State", lines.join("\n"), "high", VECTORIZED_STATE_TOKEN_BUDGET * 4);
        retrievedCount = results.length;
      }
    }

    // ── Summary of all indexed state ──
    addSection("Security State Summary", renderSecurityStateSummary(input), "normal", 2_000);

    // ── Recent / operational context ──
    addSection("Recent Tool Observations", renderObservations(input.observations ?? [], input.turnObservations ?? []), "normal", 4_000);
    addSection("File Context", renderFileContexts(input.fileContexts ?? []), "high", 16_000);
    addSection("File Changes", renderFileChanges(input.fileChanges ?? []), "normal", 6_000);
    addSection("Shell Commands", renderCommands(input.commands ?? []), "normal", 4_000);
    addSection("Subagents", renderSubagents(input.subagents ?? []), "normal", 6_000);
    addSection("Task Tree", input.taskTreeContext, "high", 4_000);
    addSection("Relevant Skills", input.skillContext, "low", 8_000);
    addSection("Security Workflow Context", input.securityWorkflowContext, "low", 20_000);

    // ── Conversation ──
    const recentMessages = selectRecentMessages(input.messages, RECENT_MESSAGE_TOKEN_BUDGET);
    const olderCount = Math.max(0, input.messages.length - recentMessages.length);
    addSection("Conversation History", renderConversation(recentMessages, olderCount), "pinned", RECENT_MESSAGE_TOKEN_BUDGET * 4);

    // ── Pack ──
    const packed = packSections(sections, maxTokens);
    const prompt = packed
      .map((s) => `<${slug(s.title)}>\n${s.content}\n</${slug(s.title)}>`)
      .join("\n\n");

    return {
      sessionId: input.sessionId,
      prompt,
      sections: packed,
      messages: recentMessages,
      stats: {
        approxTokens: packed.reduce((sum, s) => sum + s.tokens, 0),
        maxTokens,
        totalMessages: input.messages.length,
        includedMessages: recentMessages.length,
        truncatedSections,
        indexedDocuments: this.index.size(),
        retrievedDocuments: retrievedCount,
      },
    };
  }

  clearIndex(): void {
    this.index.clear();
    this.sessionDocIds.clear();
  }
}

// ── Search Query Builder ──

function buildSearchQuery(input: ContextBuildInput): string {
  const parts: string[] = [];
  if (input.currentInput) parts.push(input.currentInput);
  if (input.currentTarget) parts.push(input.currentTarget.normalized);
  if (input.turnObservations?.length) parts.push(input.turnObservations.slice(-3).join(" "));
  return parts.join(" ").slice(0, 2000);
}

// ── Rendering ──

export function renderContextSnapshot(snapshot: ContextSnapshot): string {
  return [
    `Session: ${snapshot.sessionId}`,
    `Tokens: ${snapshot.stats.approxTokens}/${snapshot.stats.maxTokens}`,
    `Messages: ${snapshot.stats.includedMessages}/${snapshot.stats.totalMessages}`,
    `Indexed: ${snapshot.stats.indexedDocuments} | Retrieved: ${snapshot.stats.retrievedDocuments}`,
    snapshot.stats.truncatedSections.length ? `Truncated: ${snapshot.stats.truncatedSections.join(", ")}` : "",
    "", "Sections:",
    ...snapshot.sections.map((s) => `- ${s.title} | ${s.priority} | ${s.tokens} tokens`),
    "", snapshot.prompt,
  ].join("\n");
}

export function updateSessionMemory(input: {
  sessionId: string; previous?: SessionMemory; messages: ContextMessage[];
  observations?: AgentObservation[]; plans?: AgentPlan[]; fileChanges?: FileChangeRecord[];
  commands?: ShellCommandRecord[]; subagents?: SubAgentRecord[];
  maxFacts?: number; maxTasks?: number;
}): SessionMemory {
  const now = new Date().toISOString();
  const prev = input.previous ?? emptySessionMemory(input.sessionId, now);
  const facts = new Set(prev.pinnedFacts);
  const tasks = new Set(prev.openTasks);

  for (const m of input.messages.slice(-12)) {
    if (m.role === "user") {
      for (const f of extractDurableFacts(m.content)) facts.add(f);
      for (const t of extractTaskHints(m.content)) tasks.add(t);
    }
  }
  for (const p of input.plans?.slice(-5) ?? []) tasks.add(p.summary);
  for (const c of input.fileChanges?.slice(-8) ?? []) {
    if (c.status === "applied") facts.add(`Applied: ${c.operation} ${c.path}`);
  }
  for (const c of input.commands?.slice(-8) ?? []) {
    if (c.status === "success") facts.add(`Command: ${c.command}`);
  }
  for (const o of input.observations?.slice(-10) ?? []) {
    facts.add(`[${o.source}] ${truncateForContext(o.summary, 280)}`);
  }
  for (const a of input.subagents?.slice(-8) ?? []) {
    if (a.resultSummary) facts.add(`[${a.role}] ${truncateForContext(a.resultSummary, 280)}`);
  }
  return {
    sessionId: input.sessionId,
    summary: compactLines([prev.summary, summarizeRecentConversation(input.messages.slice(-10))], 3_000),
    pinnedFacts: [...facts].slice(-(input.maxFacts ?? 40)),
    openTasks: [...tasks].slice(-(input.maxTasks ?? 30)),
    updatedAt: now,
  };
}

// ── Helpers ──

function packSections(sections: ContextSection[], maxTokens: number): ContextSection[] {
  const order: Record<string, number> = { pinned: 0, high: 1, normal: 2, low: 3 };
  const sorted = [...sections].sort((a, b) => order[a.priority] - order[b.priority]);
  const packed: ContextSection[] = [];
  let used = 0;
  for (const s of sorted) {
    if (used + s.tokens <= maxTokens || s.priority === "pinned") {
      packed.push(s);
      used += s.tokens;
    }
  }
  return packed.sort((a, b) => sections.indexOf(a) - sections.indexOf(b));
}

function selectRecentMessages(msgs: ContextMessage[], budget: number): ContextMessage[] {
  const sel: ContextMessage[] = [];
  let used = 0;
  for (let i = msgs.length - 1; i >= 0; i--) {
    const cost = approxTokenCount(msgs[i]!.content) + 12;
    if (sel.length > 0 && used + cost > budget) break;
    sel.push(msgs[i]!);
    used += cost;
  }
  return sel.reverse();
}

// ── Renderers ──

function renderMemory(m: SessionMemory): string {
  return [
    m.summary ? `Summary:\n${m.summary}` : "No durable summary yet.",
    m.pinnedFacts.length ? `Facts:\n${m.pinnedFacts.map((f) => `- ${f}`).join("\n")}` : "",
    m.openTasks.length ? `Tasks:\n${m.openTasks.map((t) => `- ${t}`).join("\n")}` : "",
    `Updated: ${m.updatedAt}`,
  ].filter(Boolean).join("\n\n");
}

function renderCurrentInput(input?: string, target?: TargetInput): string {
  return [input ? `Input: ${input}` : null, target ? `Target: ${target.kind}:${target.normalized}` : null]
    .filter(Boolean).join("\n");
}

function renderTargets(targets: TargetInput[]): string {
  return targets.slice(-20).map((t) => `- ${t.kind}: ${t.normalized}`).join("\n");
}

function renderPlans(plans: AgentPlan[]): string {
  return plans.slice(-8).map((p) =>
    `Plan ${p.id}\nGoal: ${p.goal}\n${p.steps.map((s, i) => `${i + 1}. ${s}`).join("\n")}`
  ).join("\n\n");
}

function renderObservations(obs: AgentObservation[], turnObs: string[]): string {
  return [
    ...obs.slice(-12).map((o) => `- ${o.createdAt} ${o.source}: ${truncateForContext(o.summary, 800)}`),
    ...turnObs.map((o) => `- current: ${truncateForContext(o, 1000)}`),
  ].join("\n");
}

function renderFileContexts(ctxs: ContextFile[]): string {
  return ctxs.map((c) => `FILE ${c.path}${c.truncated ? " (truncated)" : ""}\n${c.content}`).join("\n\n");
}

function renderFileChanges(changes: FileChangeRecord[]): string {
  return changes.slice(-12).map((c) => `- ${c.createdAt} ${c.status} ${c.operation} ${c.path}: ${c.summary ?? ""}`).join("\n");
}

function renderCommands(cmds: ShellCommandRecord[]): string {
  return cmds.slice(-12).map((c) => `- ${c.createdAt} ${c.status} ${c.command}: ${c.summary ?? ""}`).join("\n");
}

function renderSubagents(agents: SubAgentRecord[]): string {
  return agents.slice(-12).map((a) =>
    `- ${a.id} ${a.role} ${a.status}: ${a.description ?? a.task} | ${a.resultSummary ?? a.progressSummary ?? "pending"}`
  ).join("\n");
}

function renderSecurityStateSummary(input: ContextBuildInput): string {
  return [
    `Assets: ${(input.assets ?? []).length}`,
    `Technologies: ${(input.technologies ?? []).length}`,
    `Findings: ${(input.findings ?? []).length}`,
    `CVEs: ${(input.cveMatches ?? []).length}`,
    `Evidence: ${(input.evidence ?? []).length}`,
    `Checks: ${(input.securityChecks ?? []).length}`,
  ].join(" | ");
}

function renderConversation(msgs: ContextMessage[], older: number): string {
  return [
    older > 0 ? `${older} older messages summarized above.` : null,
    ...msgs.map((m) => `[${m.createdAt}] ${m.role}: ${truncateForContext(m.content, 1600)}`),
  ].filter(Boolean).join("\n");
}

// ── Fact extraction ──

function extractDurableFacts(content: string): string[] {
  const facts: string[] = [];
  for (const p of [/记住|remember\s*[:：]?\s*(.+)/i, /我的|my\s*(?:目标|需求|要求|preference|goal)\s*(?:是|:|：)\s*(.+)/i, /不要|禁止|don't|do not\s+(.+)/i]) {
    const m = content.match(p);
    if (m?.[1]) facts.push(truncateForContext(m[1].trim(), 240));
  }
  return facts;
}

function extractTaskHints(content: string): string[] {
  return /(实现|开发|修复|完善|测试|推进|继续|implement|fix|build|test|continue|add)/i.test(content)
    ? [truncateForContext(content.trim(), 260)] : [];
}

function summarizeRecentConversation(msgs: ContextMessage[]): string {
  return msgs.length ? compactLines(msgs.map((m) => `${m.role}: ${truncateForContext(m.content, 240)}`), 1_800) : "";
}

function compactLines(lines: string[], maxChars: number): string {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const line of lines.join("\n").split(/\r?\n/)) {
    const c = line.trim();
    if (c && !seen.has(c)) { seen.add(c); out.push(c); }
  }
  return truncateForContext(out.slice(-40).join("\n"), maxChars);
}

function slug(title: string): string {
  return title.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_+|_+$/g, "");
}
