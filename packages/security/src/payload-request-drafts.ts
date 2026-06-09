import { nowIso, type SecurityAuthContext } from "@aegisprobe/shared";
import { buildPayloadCandidateSet, type PayloadCandidateInput } from "./payload-candidates.js";
import type { PayloadCandidate, PayloadInsertionHint, PayloadRequestDraft, PayloadRequestDraftSet } from "./types.js";

export type PayloadRequestDraftInput = PayloadCandidateInput & {
  maxDrafts?: number;
};

type DraftContext = {
  targetBase?: string;
  authContexts: SecurityAuthContext[];
  activeAllowed: boolean;
};

export function buildPayloadRequestDraftSet(input: PayloadRequestDraftInput): PayloadRequestDraftSet {
  const candidateSet = buildPayloadCandidateSet(input);
  const context: DraftContext = {
    targetBase: input.target?.kind === "url" ? input.target.normalized : undefined,
    authContexts: input.authContexts ?? [],
    activeAllowed: Boolean(input.activeAllowed)
  };
  const drafts: PayloadRequestDraft[] = [];
  for (const candidate of candidateSet.candidates) {
    addDraftsForCandidate(drafts, candidate, context);
  }
  const maxDrafts = clamp(input.maxDrafts ?? 12, 1, 60);
  const selected = selectDiverseDrafts(drafts.sort((left, right) => draftScore(right) - draftScore(left)), maxDrafts)
    .map((draft, index) => ({ ...draft, id: `pdr-${index + 1}-${draft.candidateId}` }));

  return {
    generatedAt: nowIso(),
    mode: "draft_only",
    focus: input.focus,
    summary: selected.length > 0
      ? `Generated ${selected.length} request draft(s) from payload candidates. No requests were sent.`
      : "No request drafts generated; collect concrete endpoint, method, parameter, body, upload, or auth-context evidence first.",
    candidateSummary: candidateSet.summary,
    evidenceGaps: candidateSet.evidenceGaps,
    drafts: selected,
    guardrails: [
      "Drafts are model workbench material, not an execution plan.",
      "Use, edit, ignore, or defer each draft based on the raw evidence and scope.",
      "Only safe_readonly_fetch/http_get drafts are low-impact read-only candidates; approval_required drafts must not be run without explicit authorization.",
      "Always compare against a baseline and record raw response status/body/hash/error evidence before claiming a vulnerability."
    ]
  };
}

export function renderPayloadRequestDraftSet(set: PayloadRequestDraftSet): string {
  const lines: string[] = [
    `Payload Request Draft Set (${set.generatedAt})`,
    `Mode: ${set.mode}${set.focus ? ` | focus:${set.focus}` : ""}`,
    set.summary,
    `Candidate source: ${set.candidateSummary}`
  ];
  if (set.evidenceGaps.length > 0) {
    lines.push("Evidence gaps:");
    for (const gap of set.evidenceGaps) lines.push(`- ${gap}`);
  }
  if (set.drafts.length === 0) {
    lines.push("No request drafts.");
  } else {
    lines.push("Drafts:");
    for (const draft of set.drafts) {
      const approval = draft.requiresApproval ? "approval-required" : "read-only-or-low-impact";
      lines.push(`- ${draft.id} | ${draft.candidateId} | ${draft.category} | risk:${draft.risk} | ${approval} | tool:${draft.recommendedTool}`);
      lines.push(`  request: ${draft.method} ${draft.url}`);
      if (draft.baselineUrl && draft.baselineUrl !== draft.url) lines.push(`  baseline: ${draft.method} ${draft.baselineUrl}`);
      lines.push(`  insertion: ${formatInsertionHint(draft.insertion)}`);
      lines.push(`  payload: ${draft.payload}`);
      if (draft.authContextNames.length > 0) lines.push(`  auth contexts: ${draft.authContextNames.join(", ")}`);
      if (draft.bodyPreview) lines.push(`  body preview: ${draft.bodyPreview}`);
      if (draft.headerPreview && draft.headerPreview.length > 0) lines.push(`  header preview: ${draft.headerPreview.join("; ")}`);
      lines.push(`  tool hint: ${draft.toolUseHint}`);
      if (draft.approvalReason) lines.push(`  approval reason: ${draft.approvalReason}`);
      lines.push(`  expected observations: ${draft.expectedObservations.join("; ")}`);
      lines.push(`  false-positive guards: ${draft.falsePositiveGuards.join("; ")}`);
      if (draft.notes.length > 0) lines.push(`  notes: ${draft.notes.join("; ")}`);
      if (draft.evidenceRefs.length > 0) lines.push(`  evidence refs: ${draft.evidenceRefs.slice(0, 8).join(", ")}`);
    }
  }
  lines.push("Guardrails:");
  for (const guardrail of set.guardrails) lines.push(`- ${guardrail}`);
  return lines.join("\n");
}

function addDraftsForCandidate(drafts: PayloadRequestDraft[], candidate: PayloadCandidate, context: DraftContext): void {
  const hints = candidate.insertionHints.slice(0, 4);
  if (hints.length === 0 && candidate.category === "authz_object_reference") {
    for (const targetHint of candidate.targetHints.slice(0, 4)) {
      const draft = buildDraft(candidate, {
        endpoint: targetHint,
        method: "GET",
        location: "path",
        name: "route",
        riskSignals: ["read-only-authz-target"],
        evidenceRefs: []
      }, context.authContexts.length >= 2 ? "read-only role/tenant comparison baseline" : "anonymous route baseline", context);
      if (draft) drafts.push(draft);
    }
    return;
  }
  const payloads = candidate.payloads.slice(0, candidate.category === "authz_object_reference" ? 2 : 3);
  for (const hint of hints) {
    if (!canDraftForInsertion(candidate, hint)) continue;
    for (const payload of payloads) {
      const draft = buildDraft(candidate, hint, payload, context);
      if (draft) drafts.push(draft);
    }
  }
}

function buildDraft(
  candidate: PayloadCandidate,
  insertion: PayloadInsertionHint,
  payload: string,
  context: DraftContext
): PayloadRequestDraft | undefined {
  const method = normalizeMethod(insertion.method, insertion.location);
  const baselineUrl = absolutizeUrl(insertion.endpoint, context.targetBase);
  if (!baselineUrl) return undefined;
  const request = buildRequestPreview(baselineUrl, method, insertion, payload, candidate);
  if (!request) return undefined;
  const requiresApproval = needsApproval(candidate, method, insertion, context.activeAllowed);
  const authContextNames = authContextNamesFor(candidate, context.authContexts, method);
  const recommendedTool = recommendedToolFor(requiresApproval, method, authContextNames.length);
  const toolUseHint = buildToolUseHint(recommendedTool, request.url, method, authContextNames);
  return {
    id: `pdr-${candidate.id}`,
    candidateId: candidate.id,
    category: candidate.category,
    title: candidate.title,
    risk: candidate.risk,
    requiresApproval,
    recommendedTool,
    method,
    url: request.url,
    baselineUrl: request.baselineUrl,
    insertion,
    payload,
    authContextNames,
    bodyPreview: request.bodyPreview,
    headerPreview: request.headerPreview,
    toolUseHint,
    approvalReason: requiresApproval ? approvalReason(candidate, method, insertion) : undefined,
    expectedObservations: candidate.expectedObservations,
    falsePositiveGuards: candidate.falsePositiveGuards,
    evidenceRefs: [...new Set(candidate.evidenceRefs.concat(insertion.evidenceRefs))],
    notes: candidate.notes
  };
}

function canDraftForInsertion(candidate: PayloadCandidate, insertion: PayloadInsertionHint): boolean {
  if (insertion.location === "auth_context") return candidate.category === "authz_object_reference";
  if (insertion.location === "upload") return candidate.category === "file_upload";
  if (insertion.location === "header") return candidate.category === "parser_header_injection";
  if (insertion.location === "body") return ["mass_assignment", "command_injection", "ssti", "sql_injection", "xxe", "xss_reflection"].includes(candidate.category);
  if (insertion.location === "path") return ["authz_object_reference", "path_traversal", "ssti", "sql_injection", "xss_reflection"].includes(candidate.category);
  if (insertion.location === "query") return true;
  return false;
}

function buildRequestPreview(
  baselineUrl: string,
  method: string,
  insertion: PayloadInsertionHint,
  payload: string,
  candidate: PayloadCandidate
): { url: string; baselineUrl?: string; bodyPreview?: string; headerPreview?: string[] } | undefined {
  if (insertion.location === "query" && insertion.name) {
    const url = new URL(baselineUrl);
    url.searchParams.set(insertion.name, payload);
    return { url: url.toString(), baselineUrl };
  }
  if (insertion.location === "path") {
    if (candidate.category === "path_traversal" || candidate.category === "ssti" || candidate.category === "sql_injection" || candidate.category === "xss_reflection") {
      return { url: replaceLastPathSegment(baselineUrl, payload), baselineUrl };
    }
    return { url: baselineUrl, baselineUrl };
  }
  if (insertion.location === "body" && insertion.name) {
    return {
      url: baselineUrl,
      baselineUrl,
      bodyPreview: buildBodyPreview(insertion.name, payload)
    };
  }
  if (insertion.location === "upload") {
    return {
      url: baselineUrl,
      baselineUrl,
      bodyPreview: payload,
      headerPreview: ["Content-Type: multipart/form-data or observed upload content type"]
    };
  }
  if (insertion.location === "auth_context") {
    return { url: baselineUrl, baselineUrl };
  }
  if (insertion.location === "header" && insertion.name) {
    return {
      url: baselineUrl,
      baselineUrl,
      headerPreview: [`${insertion.name}: ${payload}`]
    };
  }
  return undefined;
}

function needsApproval(candidate: PayloadCandidate, method: string, insertion: PayloadInsertionHint, activeAllowed: boolean): boolean {
  const stateChanging = !["GET", "HEAD"].includes(method);
  if (stateChanging || insertion.location === "body" || insertion.location === "upload") return true;
  if (insertion.location === "header") return true;
  if (candidate.risk === "high") return true;
  if (candidate.requiresApproval && !activeAllowed) return true;
  return false;
}

function recommendedToolFor(requiresApproval: boolean, method: string, authContextCount: number): PayloadRequestDraft["recommendedTool"] {
  if (requiresApproval) return "approval_required";
  if (authContextCount > 0 && ["GET", "HEAD"].includes(method)) return "safe_readonly_fetch";
  if (["GET", "HEAD"].includes(method)) return "http_get";
  return "manual_review";
}

function buildToolUseHint(
  recommendedTool: PayloadRequestDraft["recommendedTool"],
  url: string,
  method: string,
  authContextNames: string[]
): string {
  if (recommendedTool === "safe_readonly_fetch") {
    return `tool_use safe_readonly_fetch url=${url} authContextName=${authContextNames[0]} method=${method}`;
  }
  if (recommendedTool === "http_get") {
    return `tool_use http_get url=${url}`;
  }
  if (recommendedTool === "approval_required") {
    return "review scope and request explicit approval before any execution";
  }
  return "manual request construction required from raw evidence";
}

function approvalReason(candidate: PayloadCandidate, method: string, insertion: PayloadInsertionHint): string {
  if (!["GET", "HEAD"].includes(method)) return `${method} is state-changing or replay-style validation.`;
  if (insertion.location === "body" || insertion.location === "upload") return `${insertion.location} validation can mutate state or process attacker-controlled content.`;
  if (candidate.risk === "high") return `${candidate.category} is high-risk validation.`;
  return `${candidate.category} candidate requires active-validation approval.`;
}

function authContextNamesFor(candidate: PayloadCandidate, authContexts: SecurityAuthContext[], method: string): string[] {
  if (!["GET", "HEAD"].includes(method)) return [];
  const limit = candidate.category === "authz_object_reference" ? 2 : 1;
  return authContexts.slice(0, limit).map((context) => context.name);
}

function normalizeMethod(method: string | undefined, location: PayloadInsertionHint["location"]): string {
  const value = (method ?? "").toUpperCase();
  if (["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"].includes(value)) return value;
  if (location === "body" || location === "upload") return "POST";
  return "GET";
}

function absolutizeUrl(value: string, base?: string): string | undefined {
  try {
    return new URL(value, base ?? "https://placeholder.invalid").toString();
  } catch {
    return undefined;
  }
}

function replaceLastPathSegment(urlValue: string, payload: string): string {
  const url = new URL(urlValue);
  const parts = url.pathname.split("/");
  const index = Math.max(1, parts.length - 1);
  parts[index] = payload;
  url.pathname = parts.join("/");
  return url.toString();
}

function buildBodyPreview(name: string, payload: string): string {
  const parsedPayload = parseJsonPayload(payload);
  if (parsedPayload && typeof parsedPayload === "object" && !Array.isArray(parsedPayload)) {
    return JSON.stringify(parsedPayload);
  }
  return JSON.stringify({ [name]: parsedPayload ?? payload });
}

function parseJsonPayload(payload: string): unknown | undefined {
  const trimmed = payload.trim();
  if (!trimmed.startsWith("{") && !trimmed.startsWith("[")) return undefined;
  try {
    return JSON.parse(trimmed);
  } catch {
    return undefined;
  }
}

function formatInsertionHint(hint: PayloadInsertionHint): string {
  const method = hint.method ? `${hint.method} ` : "";
  const name = hint.name ? `.${hint.name}` : "";
  const risk = hint.riskSignals.length > 0 ? ` risk=${hint.riskSignals.slice(0, 3).join(",")}` : "";
  return `${method}${hint.endpoint} ${hint.location}${name}${risk}`;
}

function draftScore(draft: PayloadRequestDraft): number {
  let score = 0;
  if (draft.recommendedTool === "safe_readonly_fetch") score += 30;
  if (draft.recommendedTool === "http_get") score += 20;
  if (!draft.requiresApproval) score += 15;
  if (draft.category === "authz_object_reference") score += 10;
  if (draft.category === "sql_injection" && /sqli|sql|\/login|\/search|[?&](?:id|q|search|user)=/i.test(`${draft.url} ${draft.insertion.endpoint}`)) score += 14;
  if (draft.category === "sql_injection" && /\b(?:id|user|username|email|password|q|search|filter|sort|order)\b/i.test(draft.insertion.name ?? "")) score += 8;
  if (draft.insertion.location === "query" || draft.insertion.location === "path") score += 8;
  if (draft.bodyPreview) score += 4;
  if (draft.risk === "low") score += 6;
  if (draft.risk === "medium") score += 3;
  if (/csrf|xsrf|token|nonce|submit|^login$/i.test(draft.insertion.name ?? "")) score -= 8;
  return score;
}

function selectDiverseDrafts(drafts: PayloadRequestDraft[], maxDrafts: number): PayloadRequestDraft[] {
  const selected: PayloadRequestDraft[] = [];
  const seenInsertion = new Set<string>();
  for (const draft of drafts) {
    const key = draftDiversityKey(draft);
    if (seenInsertion.has(key)) continue;
    selected.push(draft);
    seenInsertion.add(key);
    if (selected.length >= maxDrafts) return selected;
  }
  return selected;
}

function draftDiversityKey(draft: PayloadRequestDraft): string {
  return [
    draft.category,
    draft.method,
    draft.insertion.endpoint,
    draft.insertion.location,
    draft.insertion.name ?? ""
  ].join("\u0000");
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
