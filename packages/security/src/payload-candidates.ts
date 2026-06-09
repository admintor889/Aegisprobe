import { nowIso, type SecurityAsset, type SecurityAuthContext, type SecurityCveMatch, type SecurityEvidence, type SecurityTechnology, type TargetInput } from "@aegisprobe/shared";
import type { PayloadCandidate, PayloadCandidateSet, PayloadInsertionHint } from "./types.js";

export type PayloadCandidateInput = {
  target?: TargetInput;
  assets?: SecurityAsset[];
  evidence?: SecurityEvidence[];
  technologies?: SecurityTechnology[];
  cveMatches?: SecurityCveMatch[];
  authContexts?: SecurityAuthContext[];
  focus?: string;
  maxCandidates?: number;
  activeAllowed?: boolean;
  marker?: string;
};

type CandidateContext = {
  corpus: string;
  endpoints: string[];
  insertionHints: PayloadInsertionHint[];
  evidenceRefs: string[];
  marker: string;
  focus?: string;
  activeAllowed: boolean;
};

export function buildPayloadCandidateSet(input: PayloadCandidateInput): PayloadCandidateSet {
  const context = buildCandidateContext(input);
  const candidates: PayloadCandidate[] = [];

  addCandidate(candidates, context, reflectionCandidate(context));
  addCandidate(candidates, context, sqlInjectionCandidate(context));
  addCandidate(candidates, context, sstiCandidate(context));
  addCandidate(candidates, context, commandInjectionCandidate(context));
  addCandidate(candidates, context, pathTraversalCandidate(context));
  addCandidate(candidates, context, ssrfCandidate(context));
  addCandidate(candidates, context, xxeCandidate(context));
  addCandidate(candidates, context, authzCandidate(context, input.authContexts ?? []));
  addCandidate(candidates, context, massAssignmentCandidate(context));
  addCandidate(candidates, context, parserHeaderInjectionCandidate(context));
  addCandidate(candidates, context, fileUploadCandidate(context));

  const max = clamp(input.maxCandidates ?? 12, 1, 40);
  const selected = candidates
    .sort((a, b) => candidateScore(b, context) - candidateScore(a, context))
    .slice(0, max);

  const evidenceGaps = buildEvidenceGaps(context, selected);
  return {
    generatedAt: nowIso(),
    mode: "advisory",
    focus: input.focus,
    summary: selected.length > 0
      ? `Generated ${selected.length} advisory payload candidate(s) from current evidence. No requests were sent.`
      : "No payload candidates generated; collect endpoint, parameter, parser, auth, or technology evidence first.",
    candidates: selected,
    evidenceGaps,
    guardrails: [
      "These are candidate inputs, not an execution plan.",
      "The model decides whether to use, modify, ignore, or defer each candidate.",
      "Do not execute state-changing, destructive, credential, shell, or data-extraction actions without explicit scope and approval.",
      "Prefer marker, boolean, error, timing, and read-only comparison observations before escalating impact."
    ]
  };
}

export function renderPayloadCandidateSet(set: PayloadCandidateSet): string {
  const lines: string[] = [
    `Payload Candidate Set (${set.generatedAt})`,
    `Mode: ${set.mode}${set.focus ? ` | focus:${set.focus}` : ""}`,
    set.summary
  ];
  if (set.evidenceGaps.length > 0) {
    lines.push("Evidence gaps:");
    for (const gap of set.evidenceGaps) lines.push(`- ${gap}`);
  }
  if (set.candidates.length === 0) {
    lines.push("No candidates.");
  } else {
    lines.push("Candidates:");
    for (const candidate of set.candidates) {
      const approval = candidate.requiresApproval ? "approval-required" : "read-only-or-low-impact";
      lines.push(`- ${candidate.id} | ${candidate.category} | risk:${candidate.risk} | ${approval} | ${candidate.title}`);
      if (candidate.targetHints.length > 0) lines.push(`  target hints: ${candidate.targetHints.slice(0, 5).join(", ")}`);
      if (candidate.insertionHints.length > 0) lines.push(`  insertion hints: ${candidate.insertionHints.slice(0, 6).map(formatInsertionHint).join(" ; ")}`);
      if (candidate.payloads.length > 0) lines.push(`  payloads: ${candidate.payloads.slice(0, 6).join(" ; ")}`);
      lines.push(`  prerequisites: ${candidate.prerequisites.join("; ")}`);
      lines.push(`  expected observations: ${candidate.expectedObservations.join("; ")}`);
      lines.push(`  false-positive guards: ${candidate.falsePositiveGuards.join("; ")}`);
      if (candidate.notes.length > 0) lines.push(`  notes: ${candidate.notes.join("; ")}`);
      if (candidate.evidenceRefs.length > 0) lines.push(`  evidence refs: ${candidate.evidenceRefs.slice(0, 6).join(", ")}`);
    }
  }
  lines.push("Guardrails:");
  for (const guardrail of set.guardrails) lines.push(`- ${guardrail}`);
  return lines.join("\n");
}

function buildCandidateContext(input: PayloadCandidateInput): CandidateContext {
  const usefulEvidence = (input.evidence ?? []).filter(isConcretePayloadEvidence);
  const endpointValues = collectEndpoints(input.assets ?? [], usefulEvidence, input.target);
  const insertionHints = collectInsertionHints(input.assets ?? [], usefulEvidence, input.authContexts ?? [], input.target);
  const usefulAssets = (input.assets ?? []).filter((asset) => {
    if (asset.kind !== "url" && !/https?:\/\//i.test(asset.value) && !asset.value.startsWith("/")) return true;
    const metadata = parseMetadata(asset.metadata);
    const endpoint = normalizePayloadEndpoint(asset.value, input.target?.normalized);
    const riskSignals = uniqueStrings([...arrayOfStrings(metadata?.riskSignals), ...routeRiskSignals(endpoint ?? asset.value)]);
    return Boolean(endpoint && isUsefulPayloadEndpoint(endpoint, riskSignals));
  });
  const corpusParts = [
    input.target?.normalized,
    ...endpointValues,
    ...usefulAssets.map((asset) => `${asset.kind} ${asset.value} ${asset.source} ${asset.metadata ?? ""}`),
    ...(input.technologies ?? []).map((technology) => `${technology.name} ${technology.version ?? ""} ${technology.category ?? ""} ${technology.evidenceSummary ?? ""}`),
    ...(input.cveMatches ?? []).map((match) => `${match.cveId ?? ""} ${match.title} ${match.rationale}`),
    ...usefulEvidence.map((item) => `${item.id} ${item.kind} ${item.source} ${item.summary} ${typeof item.data === "string" ? item.data.slice(0, 4000) : JSON.stringify(item.data ?? "").slice(0, 4000)}`),
    ...(input.authContexts ?? []).map((ctx) => `auth ${ctx.name} role:${ctx.role ?? ""} user:${ctx.username ?? ""} base:${ctx.baseUrl ?? ""}`)
  ].filter(Boolean);

  return {
    corpus: corpusParts.join("\n").toLowerCase(),
    endpoints: endpointValues,
    insertionHints,
    evidenceRefs: usefulEvidence.slice(-12).map((item) => item.id),
    marker: safeMarker(input.marker),
    focus: input.focus?.toLowerCase(),
    activeAllowed: Boolean(input.activeAllowed)
  };
}

function isConcretePayloadEvidence(item: SecurityEvidence): boolean {
  if (/^(?:pentest:model_loop|graph:blackboard|decision:|web:control-plane)/i.test(item.source)) return false;
  const source = item.source.toLowerCase();
  if (/shell|command/.test(source)) return false;
  return /^(?:browser:|anonymous_baseline_fetch|safe_readonly_fetch|security_probe:|manual:api-description|api-description|api-inventory)/i.test(item.source)
    || /webapp-recon|api-inventory|auth-surface/.test(source);
}

function collectEndpoints(assets: SecurityAsset[], evidence: SecurityEvidence[], target?: TargetInput): string[] {
  const values = new Set<string>();
  if (target?.kind === "url") values.add(target.normalized);
  for (const asset of assets) {
    if (asset.kind === "url" || /https?:\/\//i.test(asset.value) || asset.value.startsWith("/")) {
      const metadata = parseMetadata(asset.metadata);
      const endpoint = normalizePayloadEndpoint(asset.value, target?.normalized);
      const riskSignals = uniqueStrings([...arrayOfStrings(metadata?.riskSignals), ...routeRiskSignals(endpoint ?? asset.value)]);
      if (endpoint && isUsefulPayloadEndpoint(endpoint, riskSignals)) values.add(endpoint);
    }
  }
  const routePattern = /(https?:\/\/[^\s"'`<>]+|\/(?:api|rest|graphql|admin|auth|login|user|users|orders|files|upload|search)[A-Za-z0-9._~:/?#[\]@!$&()*+,;=%-]*)/gi;
  for (const item of evidence.slice(-40)) {
    const text = `${item.summary}\n${typeof item.data === "string" ? item.data : JSON.stringify(item.data ?? "")}`;
    for (const match of text.matchAll(routePattern)) {
      const value = normalizePayloadEndpoint(match[1] ?? "", target?.normalized);
      if (value && value.length >= 2 && value.length <= 260 && isUsefulPayloadEndpoint(value, routeRiskSignals(value))) values.add(value);
      if (values.size >= 80) break;
    }
  }
  return [...values].slice(0, 80);
}

function collectInsertionHints(
  assets: SecurityAsset[],
  evidence: SecurityEvidence[],
  authContexts: SecurityAuthContext[],
  target?: TargetInput
): PayloadInsertionHint[] {
  const hints: PayloadInsertionHint[] = [];
  for (const asset of assets) {
    if (asset.kind !== "url" && !/https?:\/\//i.test(asset.value) && !asset.value.startsWith("/")) continue;
    const metadata = parseMetadata(asset.metadata);
    const method = stringValue(metadata?.method);
    const endpoint = normalizePayloadEndpoint(asset.value, target?.normalized);
    if (!endpoint) continue;
    const riskSignals = uniqueStrings([...arrayOfStrings(metadata?.riskSignals), ...routeRiskSignals(endpoint)]);
    if (!isUsefulPayloadEndpoint(endpoint, riskSignals)) continue;
    for (const name of namesFromUrlQuery(endpoint).concat(arrayOfStrings(metadata?.queryParams))) {
      hints.push({ endpoint, method, location: "query", name, riskSignals, evidenceRefs: [asset.id] });
    }
    for (const name of arrayOfStrings(metadata?.bodyParamHints)) {
      hints.push({ endpoint, method, location: "body", name, riskSignals, evidenceRefs: [asset.id] });
    }
    for (const name of fieldNamesFromMetadata(metadata)) {
      hints.push({ endpoint, method, location: method && !["GET", "HEAD"].includes(method) ? "body" : "query", name, riskSignals, evidenceRefs: [asset.id] });
    }
    for (const name of pathObjectNames(endpoint, stringValue(metadata?.pathTemplate))) {
      hints.push({ endpoint, method, location: "path", name, riskSignals, evidenceRefs: [asset.id] });
    }
    if (/upload|multipart|attachment|avatar|import/i.test(`${endpoint} ${asset.source} ${JSON.stringify(metadata ?? {})}`)) {
      hints.push({ endpoint, method, location: "upload", name: "file", riskSignals, evidenceRefs: [asset.id] });
    }
    if (/content-?type|multipart|boundary|parser|ognl|expression|struts|file-handling|upload/i.test(`${endpoint} ${asset.source} ${JSON.stringify(metadata ?? {})} ${riskSignals.join(" ")}`)) {
      hints.push({ endpoint, method, location: "header", name: "Content-Type", riskSignals, evidenceRefs: [asset.id] });
    }
  }

  const requestLinePattern = /\b(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+([^\s"'<>]+)/gi;
  for (const item of evidence.slice(-60)) {
    const raw = typeof item.data === "string" ? item.data : JSON.stringify(item.data ?? "");
    for (const match of raw.matchAll(requestLinePattern)) {
      const method = match[1]?.toUpperCase();
      const endpoint = normalizeRequestLineEndpoint(match[2] ?? "", target?.normalized);
      if (!endpoint) continue;
      const riskSignals = routeRiskSignals(endpoint);
      if (!isUsefulPayloadEndpoint(endpoint, riskSignals)) continue;
      for (const name of namesFromUrlQuery(endpoint)) {
        hints.push({ endpoint, method, location: "query", name, riskSignals, evidenceRefs: [item.id] });
      }
      for (const name of pathObjectNames(endpoint)) {
        hints.push({ endpoint, method, location: "path", name, riskSignals, evidenceRefs: [item.id] });
      }
      if (/upload|multipart|attachment|avatar|import/i.test(endpoint)) {
        hints.push({ endpoint, method, location: "upload", name: "file", riskSignals, evidenceRefs: [item.id] });
      }
      if (/content-?type|multipart|boundary|parser|ognl|expression|struts|file-handling|upload/i.test(`${endpoint} ${raw}`)) {
        hints.push({ endpoint, method, location: "header", name: "Content-Type", riskSignals, evidenceRefs: [item.id] });
      }
    }
  }

  for (const context of authContexts) {
    hints.push({
      endpoint: context.baseUrl ?? context.name,
      location: "auth_context",
      name: `${context.name}${context.role ? `:${context.role}` : ""}${context.tenant ? `:${context.tenant}` : ""}`,
      riskSignals: ["registered-auth-context"],
      evidenceRefs: [context.id]
    });
  }

  return dedupeInsertionHints(hints).slice(0, 120);
}

function addCandidate(candidates: PayloadCandidate[], context: CandidateContext, candidate: PayloadCandidate | undefined): void {
  if (!candidate) return;
  if (context.focus && !candidateMatchesFocus(candidate, context.focus)) return;
  candidates.push(candidate);
}

function reflectionCandidate(context: CandidateContext): PayloadCandidate | undefined {
  if (!hasAny(context, ["param", "query", "search", "form", "input", "name=", "q=", "?"])) return undefined;
  return candidate("pc-xss-reflection", "xss_reflection", "Reflection marker probe", "low", context, {
    payloads: [`aegisprobe-${context.marker}`, `\"><aegisprobe-${context.marker}>`],
    prerequisites: ["A reflected parameter, form field, route segment, or client-rendered value is identified."],
    expectedObservations: ["The exact marker appears in the response body, DOM snapshot, or rendered page."],
    falsePositiveGuards: ["Use a unique marker and compare against a baseline request.", "Reflection alone is not script execution."],
    notes: ["Escalate to script execution payloads only after confirming context and output encoding."]
  });
}

function sqlInjectionCandidate(context: CandidateContext): PayloadCandidate | undefined {
  if (!hasAny(context, ["login", "search", "filter", "sort", "id=", "user", "order", "sql", "database", "where", "query"])) return undefined;
  return candidate("pc-sqli", "sql_injection", "SQL injection proof probes", "medium", context, {
    payloads: ["'", "' AND '1'='1", "' AND '1'='2", "\" AND \"1\"=\"1", "1 OR 1=1"],
    prerequisites: ["A parameter or body field plausibly reaches a database query."],
    expectedObservations: ["Different status/body/error/timing behavior between baseline, true predicate, and false predicate."],
    falsePositiveGuards: ["Use paired true/false probes.", "Compare with unchanged baseline.", "Do not treat generic 500 errors as proof without repeatability."],
    notes: ["Data extraction and sqlmap use require explicit active scope and approval."]
  });
}

function sstiCandidate(context: CandidateContext): PayloadCandidate | undefined {
  if (!hasSstiEvidence(context)) return undefined;
  if (!hasConcreteCategorySurface(context, "ssti")) return undefined;
  return candidate("pc-ssti", "ssti", "Server-side template expression probes", "medium", context, {
    payloads: ["{{7*7}}", "${7*7}", "#{7*7}", "<%= 7*7 %>"],
    prerequisites: ["A user-controlled value appears in server-rendered output or template-like error context."],
    expectedObservations: ["The rendered response contains 49 or an engine-specific parse error tied to the expression."],
    falsePositiveGuards: ["Use a baseline marker first.", "Confirm the expression is evaluated server-side, not just echoed client-side."],
    notes: ["RCE escalation is high risk and requires explicit approval."]
  });
}

function commandInjectionCandidate(context: CandidateContext): PayloadCandidate | undefined {
  if (!hasAny(context, ["ping", "nslookup", "host=", "domain=", "cmd=", "command", "convert", "ffmpeg", "imagemagick", "archive", "diagnostic"])) return undefined;
  if (!hasConcreteCategorySurface(context, "command_injection")) return undefined;
  return candidate("pc-command-injection", "command_injection", "Benign command marker probes", "high", context, {
    payloads: [`; echo AEGISPROBE_${context.marker}`, `| echo AEGISPROBE_${context.marker}`, `&& echo AEGISPROBE_${context.marker}`],
    prerequisites: ["A field plausibly reaches an OS command, diagnostic tool, converter, archive handler, or shell wrapper."],
    expectedObservations: ["The marker appears in output, logs, callback, or timing changes consistently with command execution."],
    falsePositiveGuards: ["Prefer output-only marker probes before shell payloads.", "Do not use reverse shells unless explicitly authorized."],
    notes: context.activeAllowed ? ["Active probing is allowed by scope, but this still needs approval if state or command execution risk exists."] : ["Current scope does not allow active exploitation."]
  });
}

function pathTraversalCandidate(context: CandidateContext): PayloadCandidate | undefined {
  if (!hasAny(context, ["file=", "path=", "download", "template=", "page=", "include", "export"])) return undefined;
  if (!hasConcreteCategorySurface(context, "path_traversal")) return undefined;
  return candidate("pc-path-traversal", "path_traversal", "Path traversal read probes", "medium", context, {
    payloads: ["../../../../etc/passwd", "..\\..\\..\\windows\\win.ini", "%2e%2e%2f%2e%2e%2fetc%2fpasswd"],
    prerequisites: ["A path-like parameter, download route, template include, or file retrieval endpoint exists."],
    expectedObservations: ["Response contains OS-specific file markers or a path traversal error distinct from baseline."],
    falsePositiveGuards: ["Compare with a nonexistent filename.", "Confirm content is from the server filesystem, not an application fixture."],
    notes: ["Sensitive file reads may be high impact; follow the engagement scope."]
  });
}

function ssrfCandidate(context: CandidateContext): PayloadCandidate | undefined {
  if (!hasAny(context, ["url=", "uri=", "callback", "webhook", "fetch", "proxy", "redirect", "avatar", "import", "pdf", "screenshot"])) return undefined;
  if (!hasConcreteCategorySurface(context, "ssrf")) return undefined;
  return candidate("pc-ssrf", "ssrf", "SSRF callback probes", "medium", context, {
    payloads: [`https://callback.example/aegisprobe-${context.marker}`, "http://127.0.0.1/", "http://[::1]/"],
    prerequisites: ["A server-side URL fetch, webhook, redirect, import, PDF, screenshot, or proxy feature exists."],
    expectedObservations: ["An authorized callback endpoint receives a request, or response behavior differs for internal vs external URLs."],
    falsePositiveGuards: ["Use an operator-approved callback domain.", "Do not target cloud metadata or internal services without explicit authorization."],
    notes: ["The callback.example value is a placeholder; replace it with an approved controlled endpoint."]
  });
}

function xxeCandidate(context: CandidateContext): PayloadCandidate | undefined {
  if (!hasAny(context, ["xml", "soap", "saml", "svg", "docx", "xlsx", "content-type: application/xml"])) return undefined;
  if (!hasConcreteCategorySurface(context, "xxe")) return undefined;
  return candidate("pc-xxe", "xxe", "XXE external entity callback probe", "high", context, {
    payloads: [`<?xml version="1.0"?><!DOCTYPE x [<!ENTITY e SYSTEM "https://callback.example/xxe-${context.marker}">]><x>&e;</x>`],
    prerequisites: ["An XML parser accepts user-controlled XML, SOAP, SAML, SVG, or office document content."],
    expectedObservations: ["Approved callback endpoint receives a request, or parser error indicates external entity handling."],
    falsePositiveGuards: ["Use a callback marker unique to this request.", "Do not use file:// entity reads unless authorized."],
    notes: ["External callbacks and file reads require explicit scope approval."]
  });
}

function authzCandidate(context: CandidateContext, authContexts: SecurityAuthContext[]): PayloadCandidate | undefined {
  if (!hasAuthorizationBoundaryEvidence(context, authContexts)) return undefined;
  return candidate("pc-authz-object-reference", "authz_object_reference", "Read-only object and role boundary probes", "low", context, {
    payloads: ["same endpoint + peer object id", "same object id + lower-privilege auth context", "same route + different tenant context"],
    prerequisites: ["At least one object identifier, role boundary, tenant boundary, or multiple auth contexts are known."],
    expectedObservations: ["A lower-privilege or cross-tenant context receives data that policy says it should not receive."],
    falsePositiveGuards: ["Compare status, body length/hash, and semantic ownership fields.", "Confirm expected authorization policy before claiming impact."],
    notes: ["Use safe_readonly_fetch for GET/HEAD comparisons when auth contexts are registered."]
  });
}

function massAssignmentCandidate(context: CandidateContext): PayloadCandidate | undefined {
  if (!hasAny(context, ["patch", "put", "profile", "settings", "role", "tenant", "isadmin", "account update", "user update"])) return undefined;
  if (!hasConcreteCategorySurface(context, "mass_assignment")) return undefined;
  return candidate("pc-mass-assignment", "mass_assignment", "Mass-assignment field probes", "high", context, {
    payloads: ['{"role":"admin"}', '{"isAdmin":true}', '{"tenantId":"<other-tenant>"}', '{"permissions":["admin"]}'],
    prerequisites: ["A JSON body update endpoint exists and the engagement allows state-changing validation."],
    expectedObservations: ["The response or later readback shows unauthorized field acceptance or privilege/tenant change."],
    falsePositiveGuards: ["Use a disposable account.", "Record baseline state and restore when required.", "Do not run against production users without explicit approval."],
    notes: ["This is state-changing; request approval before execution."]
  });
}

function parserHeaderInjectionCandidate(context: CandidateContext): PayloadCandidate | undefined {
  if (!hasParserHeaderInjectionEvidence(context)) return undefined;
  if (!hasConcreteCategorySurface(context, "parser_header_injection")) return undefined;
  return candidate("pc-parser-header-injection", "parser_header_injection", "Parser and header expression probes", "high", context, {
    payloads: [
      "Content-Type parser marker expression",
      "content-type variation + benign marker header",
      "multipart boundary/parser error comparison"
    ],
    prerequisites: ["A request parser, multipart upload, content-type dependent route, or framework expression parser is evidenced."],
    expectedObservations: ["A marker header/body value, parser-specific error, or consistent baseline/probe response difference is observed."],
    falsePositiveGuards: ["Compare with a valid baseline content type and a malformed non-expression content type.", "Use non-destructive markers before command execution or file effects."],
    notes: ["Expression-to-command escalation is high risk and requires explicit active authorization."]
  });
}

function fileUploadCandidate(context: CandidateContext): PayloadCandidate | undefined {
  if (!hasAny(context, ["upload", "multipart", "filename", "avatar", "attachment", "import file"])) return undefined;
  if (!hasConcreteCategorySurface(context, "file_upload")) return undefined;
  return candidate("pc-file-upload", "file_upload", "File upload handling probes", "medium", context, {
    payloads: [`probe-${context.marker}.txt with marker AEGISPROBE_${context.marker}`, "image/jpeg content type with non-executable marker body", "filename with double extension marker.txt.jpg"],
    prerequisites: ["A file upload or import endpoint exists."],
    expectedObservations: ["The file is stored, transformed, rejected, or retrievable in a way that clarifies validation behavior."],
    falsePositiveGuards: ["Start with non-executable marker files.", "Do not upload webshells unless explicitly authorized and isolated."],
    notes: ["Executable upload tests are high impact and require explicit approval."]
  });
}

function candidate(
  id: string,
  category: PayloadCandidate["category"],
  title: string,
  risk: PayloadCandidate["risk"],
  context: CandidateContext,
  rest: Omit<PayloadCandidate, "id" | "category" | "title" | "risk" | "targetHints" | "insertionHints" | "evidenceRefs" | "requiresApproval">
): PayloadCandidate {
  return {
    id,
    category,
    title,
    risk,
    targetHints: targetHintsFor(context, category),
    insertionHints: insertionHintsFor(context, category),
    evidenceRefs: context.evidenceRefs,
    requiresApproval: risk !== "low",
    ...rest
  };
}

function targetHintsFor(context: CandidateContext, category: PayloadCandidate["category"]): string[] {
  const keywords: Record<PayloadCandidate["category"], RegExp> = {
    xss_reflection: /[?&](?:q|s|search|name|message|next|redirect)=|\/(?:search|login|profile|comment)/i,
    sql_injection: /[?&](?:id|q|search|user|order|filter|sort)=|\/(?:login|search|api|users|orders)/i,
    ssti: /[?&](?:name|template|view|message)=|\/(?:greet|render|template)/i,
    command_injection: /[?&](?:host|ip|domain|cmd|url)=|\/(?:ping|lookup|convert|diagnostic)/i,
    path_traversal: /[?&](?:file|path|page|template|download)=|\/(?:download|file|static|export)/i,
    ssrf: /[?&](?:url|uri|callback|webhook|redirect|avatar)=|\/(?:fetch|proxy|import|webhook|callback)/i,
    xxe: /\/(?:xml|soap|saml|upload|import)/i,
    authz_object_reference: /\/(?:api\/)?(?:users|orders|tenants|admin|accounts)\/[A-Za-z0-9_-]+/i,
    mass_assignment: /\/(?:api\/)?(?:users|profile|settings|accounts)\/?/i,
    parser_header_injection: /\/(?:upload|import|file|files|doUpload|action)(?:\/|\?|$)|\.action(?:\?|$)/i,
    file_upload: /\/(?:upload|avatar|attachment|import|files)/i
  };
  const regex = keywords[category];
  const matched = context.endpoints.filter((endpoint) => regex.test(endpoint));
  const fallback = category === "authz_object_reference"
    ? context.endpoints.filter((endpoint) => /\/(?:api\/)?(?:users|orders|tenants|admin|accounts)(?:\/|\?|$)/i.test(endpoint))
    : allowEndpointFallback(category)
      ? context.endpoints
      : [];
  return (matched.length > 0 ? matched : fallback).slice(0, 8);
}

function insertionHintsFor(context: CandidateContext, category: PayloadCandidate["category"]): PayloadInsertionHint[] {
  const matched = context.insertionHints.filter((hint) => insertionHintMatchesCategory(hint, category));
  const selected = category === "authz_object_reference"
    ? matched
    : matched.length > 0
      ? matched
      : allowGenericInsertionFallback(category) ? context.insertionHints : [];
  return selected
    .slice()
    .sort((left, right) => insertionHintScore(right, category) - insertionHintScore(left, category))
    .slice(0, 8);
}

function hasConcreteCategorySurface(context: CandidateContext, category: PayloadCandidate["category"]): boolean {
  return targetHintsFor(context, category).length > 0 || insertionHintsFor(context, category).length > 0;
}

function allowEndpointFallback(category: PayloadCandidate["category"]): boolean {
  return category === "xss_reflection" || category === "sql_injection";
}

function allowGenericInsertionFallback(category: PayloadCandidate["category"]): boolean {
  return category === "xss_reflection" || category === "sql_injection" || category === "ssti";
}

function insertionHintMatchesCategory(hint: PayloadInsertionHint, category: PayloadCandidate["category"]): boolean {
  const name = hint.name?.toLowerCase() ?? "";
  const endpoint = hint.endpoint.toLowerCase();
  const combined = `${name} ${endpoint} ${hint.riskSignals.join(" ").toLowerCase()}`;
  if (category === "authz_object_reference") {
    if (hint.location === "auth_context") return true;
    if (hint.location === "path") return /tenant|owner|order|account|admin|object|numeric-id|uuid|\bid\b/.test(combined);
    if (/\b(?:tenant|owner|role|account|admin|object|user_?id|order_?id|tenant_?id|account_?id|owner_?id)\b/.test(name)) return true;
    return hint.location === "query"
      && /\b(?:id|user|order|tenant|account)\b/.test(name)
      && /\/(?:api\/)?(?:users|orders|tenants|admin|accounts)\/[A-Za-z0-9_-]+/i.test(endpoint);
  }
  if (category === "mass_assignment") {
    return hint.location === "body"
      && /\b(?:role|is_?admin|admin|permission|permissions|tenant_?id|tenant|account_?id|account|profile)\b/.test(combined)
      && !/\b(?:username|password|submit|csrf|token)\b/.test(name);
  }
  if (category === "parser_header_injection") {
    if (hint.location === "header" && /content-type|accept|x-|header/.test(name)) return true;
    return /content-?type|multipart|boundary|parser|ognl|expression|struts|action|upload|file-handling|state-changing-method/.test(combined);
  }
  if (category === "file_upload") return hint.location === "upload" || /upload|file|avatar|attachment|import/.test(combined);
  if (category === "path_traversal") return /file|path|page|template|download|include|export/.test(combined);
  if (category === "ssrf") return /url|uri|callback|webhook|redirect|avatar|import|proxy|fetch/.test(combined);
  if (category === "command_injection") return /host|ip|domain|cmd|command|lookup|ping|convert|diagnostic/.test(combined);
  if (category === "xxe") return /xml|soap|saml|svg|docx|xlsx|upload|import/.test(combined) || hint.location === "body";
  if (category === "sql_injection") {
    if (/csrf|xsrf|token|nonce|submit|^login$/i.test(name)) return false;
    return ["query", "body", "path"].includes(hint.location)
      && (/\b(?:id|user|username|email|password|q|search|filter|sort|order)\b/.test(name)
        || /sqli|sql|database|query|\/(?:login|search|users?|orders?)(?:\/|\?|$)/i.test(endpoint));
  }
  if (category === "xss_reflection") {
    if (/csrf|xsrf|token|nonce|submit|^login$/i.test(name)) return false;
    return ["query", "body", "path"].includes(hint.location);
  }
  return hint.location === "query" || hint.location === "body" || hint.location === "path";
}

function insertionHintScore(hint: PayloadInsertionHint, category: PayloadCandidate["category"]): number {
  const name = hint.name?.toLowerCase() ?? "";
  const endpoint = hint.endpoint.toLowerCase();
  const combined = `${name} ${endpoint} ${hint.riskSignals.join(" ").toLowerCase()}`;
  let score = 0;
  if (hint.location === "query" || hint.location === "body") score += 8;
  if (/\/(?:api|rest|graphql|vulnerabilities|admin|users?|orders?|search|login)(?:\/|\?|$)/i.test(endpoint)) score += 4;
  if (/csrf|xsrf|token|nonce|submit|login$|^login$/i.test(name)) score -= 8;

  if (category === "sql_injection") {
    if (/sqli|sql|database|query/.test(combined)) score += 24;
    if (/\b(?:id|user|username|email|password|q|search|filter|sort|order)\b/.test(name)) score += 12;
    if (/\/(?:login|search|users?|orders?)(?:\/|\?|$)/i.test(endpoint)) score += 6;
  }
  if (category === "xss_reflection") {
    if (/\b(?:q|query|search|name|message|comment|title|redirect|next)\b/.test(name)) score += 12;
    if (/\/(?:search|comment|profile|message)(?:\/|\?|$)/i.test(endpoint)) score += 6;
  }
  if (category === "authz_object_reference") {
    if (hint.location === "auth_context") score += 12;
    if (hint.location === "path") score += 8;
    if (/admin|tenant|owner|order|account|user|object|id|uuid/.test(combined)) score += 10;
  }
  if (category === "mass_assignment" && /\b(?:role|isadmin|admin|permission|tenant|account|profile)\b/.test(name)) score += 18;
  if (category === "parser_header_injection") {
    if (hint.location === "header") score += 22;
    if (/content-?type|multipart|boundary|parser|ognl|expression|struts/.test(combined)) score += 18;
    if (/upload|file-handling|\.action|state-changing-method/.test(combined)) score += 8;
  }
  if (category === "path_traversal" && /\b(?:file|path|page|template|download|include|export)\b/.test(name)) score += 18;
  if (category === "ssrf" && /\b(?:url|uri|callback|webhook|redirect|avatar|proxy|fetch)\b/.test(name)) score += 18;
  if (category === "command_injection" && /\b(?:host|ip|domain|cmd|command|lookup|ping)\b/.test(name)) score += 18;
  if (category === "file_upload" && hint.location === "upload") score += 20;
  return score;
}

function candidateMatchesFocus(candidate: PayloadCandidate, focus: string): boolean {
  const aliases = [
    candidate.category,
    candidate.title,
    candidate.notes.join(" "),
    ...(focusAliases[candidate.category] ?? [])
  ].join(" ").toLowerCase();
  return focus.split(/[\s,;]+/).filter(Boolean).some((term) => aliases.includes(term));
}

const focusAliases: Partial<Record<PayloadCandidate["category"], string[]>> = {
  sql_injection: ["sqli", "sql injection"],
  xss_reflection: ["xss", "reflection"],
  authz_object_reference: ["authz", "authorization", "idor", "bola", "bfla", "object reference"],
  mass_assignment: ["mass assignment", "overposting"],
  parser_header_injection: ["parser", "header injection", "content-type", "ognl", "expression injection"],
  command_injection: ["rce", "command injection", "os command"],
  path_traversal: ["lfi", "traversal", "file read"],
  file_upload: ["upload"],
  ssrf: ["server-side request forgery"],
  ssti: ["template injection"],
  xxe: ["xml external entity"]
};

function hasAny(context: CandidateContext, terms: string[]): boolean {
  return terms.some((term) => context.corpus.includes(term.toLowerCase()));
}

function hasSstiEvidence(context: CandidateContext): boolean {
  if (hasAny(context, [
    "template=", "/template", "template engine", "server-side template", "ssti",
    "flask", "jinja", "django", "werkzeug", "gunicorn", "uwsgi",
    "twig", "freemarker", "velocity", "thymeleaf", "erb", "rails",
    "handlebars", "mustache", "nunjucks", "ejs", "pug", "render", "greeting"
  ])) {
    return true;
  }
  const hasServerRenderedHtml = hasAny(context, ["content-type: text/html", "text/html;", "server:"]);
  if (!hasServerRenderedHtml) return false;
  return context.insertionHints.some((hint) => {
    if (hint.location !== "query" && hint.location !== "body" && hint.location !== "path") return false;
    const name = hint.name?.toLowerCase() ?? "";
    const endpoint = hint.endpoint.toLowerCase();
    return /\b(?:name|message|q|query|search|title|text|template|view|page|greet|content)\b/.test(name)
      || /[?&](?:name|message|q|query|search|title|text|template|view|page|greet|content)=/.test(endpoint)
      || /\/(?:greet|render|template|message|search)(?:\/|\?|$)/.test(endpoint);
  });
}

function hasParserHeaderInjectionEvidence(context: CandidateContext): boolean {
  return hasAny(context, [
    "content-type", "multipart", "boundary", "parser", "expression", "ognl",
    "struts", "opensymphony", "xwork", ".action", "file-handling", "upload"
  ]);
}

function hasAuthorizationBoundaryEvidence(context: CandidateContext, authContexts: SecurityAuthContext[]): boolean {
  if (authContexts.length >= 2) return true;
  if (context.insertionHints.some((hint) => insertionHintMatchesCategory(hint, "authz_object_reference"))) return true;
  return context.endpoints.some((endpoint) => /\/(?:api\/)?(?:users|orders|tenants|admin|accounts)(?:\/|\?|$)/i.test(endpoint));
}

function candidateScore(candidate: PayloadCandidate, context: CandidateContext): number {
  let score = candidate.targetHints.length > 0 ? 20 : 0;
  if (candidate.insertionHints.length > 0) score += 10;
  if (candidate.risk === "low") score += 8;
  if (candidate.risk === "medium") score += 5;
  if (!candidate.requiresApproval) score += 4;
  if (context.focus && candidateMatchesFocus(candidate, context.focus)) score += 30;
  if (candidate.category === "authz_object_reference" && hasAny(context, ["tenant", "role", "admin", "order", "user"])) score += 8;
  if (candidate.category === "sql_injection" && hasAny(context, ["login", "search", "id="])) score += 6;
  if (candidate.category === "ssti" && hasAny(context, ["flask", "template", "jinja"])) score += 6;
  return score;
}

function buildEvidenceGaps(context: CandidateContext, candidates: PayloadCandidate[]): string[] {
  const gaps: string[] = [];
  if (context.endpoints.length === 0) gaps.push("No concrete endpoint or URL evidence is available.");
  if (!hasAny(context, ["param", "?", "body", "form", "input", "json"])) gaps.push("No parameter/body/input evidence is available.");
  if (!hasAny(context, ["auth", "cookie", "authorization", "role", "tenant"])) gaps.push("No authentication or authorization context evidence is available.");
  if (candidates.some((candidate) => candidate.requiresApproval) && !context.activeAllowed) gaps.push("Some candidates require active or state-changing validation, but active probing is not currently allowed.");
  return gaps;
}

function safeMarker(marker?: string): string {
  const value = marker ?? Math.random().toString(16).slice(2, 10);
  const cleaned = value.replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 24);
  return cleaned || "probe";
}

function formatInsertionHint(hint: PayloadInsertionHint): string {
  const method = hint.method ? `${hint.method} ` : "";
  const name = hint.name ? `.${hint.name}` : "";
  const risk = hint.riskSignals.length > 0 ? ` risk=${hint.riskSignals.slice(0, 3).join(",")}` : "";
  return `${method}${hint.endpoint} ${hint.location}${name}${risk}`;
}

function namesFromUrlQuery(value: string): string[] {
  try {
    const url = new URL(value, "https://placeholder.invalid");
    return [...url.searchParams.keys()].filter((name) => name.length > 0).slice(0, 12);
  } catch {
    return [];
  }
}

function pathObjectNames(endpoint: string, pathTemplate?: string): string[] {
  const names = new Set<string>();
  if (pathTemplate) {
    for (const match of pathTemplate.matchAll(/\{([A-Za-z0-9_.-]+)\}/g)) {
      if (match[1]) names.add(match[1]);
    }
  }
  let path = endpoint.split("?")[0] ?? endpoint;
  try {
    path = new URL(endpoint).pathname;
  } catch {
    // Keep relative paths as-is.
  }
  if (/[/:][0-9]{2,}(?:\/|$)/.test(path)) names.add("numeric-id");
  if (/[/:][0-9a-f]{8}-[0-9a-f-]{18,}/i.test(path)) names.add("uuid");
  if (/\/(?:users|orders|accounts|tenants|invoices|files|admin)\/[^/?#]+/i.test(path)) names.add("object-reference");
  return [...names].slice(0, 8);
}

function normalizePayloadEndpoint(value: string, base?: string): string | undefined {
  const trimmed = value.trim().replace(/[),.;]+$/g, "");
  if (!/^(?:https?:\/\/|\/)/i.test(trimmed)) return undefined;
  if (/[\s"'<>\\]/.test(trimmed)) return undefined;
  if (looksLikeExpressionOrTextArtifact(decodeURIComponentSafe(trimmed))) return undefined;
  if (trimmed.startsWith("/") && !base) return trimmed;
  try {
    const parsed = new URL(trimmed, base);
    if (base) {
      const baseUrl = new URL(base);
      if (parsed.origin !== baseUrl.origin) return undefined;
    }
    return parsed.toString();
  } catch {
    return base ? undefined : trimmed;
  }
}

function normalizeRequestLineEndpoint(value: string, base?: string): string | undefined {
  const endpoint = normalizePayloadEndpoint(value, base);
  if (!endpoint) return undefined;
  if (looksLikeExpressionOrTextArtifact(endpoint)) return undefined;
  return endpoint;
}

function isUsefulPayloadEndpoint(endpoint: string, riskSignals: string[]): boolean {
  let pathname = endpoint;
  try {
    pathname = new URL(endpoint).pathname;
  } catch {
    // Keep relative paths as-is.
  }
  const decoded = decodeURIComponentSafe(pathname);
  if (looksLikeExpressionOrTextArtifact(decoded)) return false;
  if (hasAccessRiskSignals(riskSignals)) return true;
  if (isStaticLikePath(pathname) || isStaticLikePath(decoded)) return false;
  if (/\/(?:api|rest|graphql|admin|auth|login|signin|session|users?|orders?|accounts?|tenants?|profile|settings|upload|files?|search)(?:\/|\?|$)/i.test(decoded)) return true;
  if (/[?&][A-Za-z][A-Za-z0-9_.-]{0,40}=/.test(endpoint)) return true;
  return !/\.[A-Za-z0-9]{1,8}(?:$|[?#])/i.test(decoded);
}

function hasAccessRiskSignals(riskSignals: string[]): boolean {
  return riskSignals.some((signal) => /api|graphql|admin|auth|business|privileged|tenant|object|workflow|state-changing|upload|file|parameter/i.test(signal));
}

function routeRiskSignals(value: string): string[] {
  const signals: string[] = [];
  if (/\/(?:admin|manage|console|settings|roles?|permissions?)(?:\/|\?|$)/i.test(value)) signals.push("privileged-route");
  if (/\/(?:account|users?|orders?|invoice|tenant|org|workspace|project|tickets?)(?:\/|\?|$)/i.test(value)) signals.push("object-or-tenant-route");
  if (/\/(?:refund|payment|price|coupon|checkout|credit|transfer)(?:\/|\?|$)/i.test(value)) signals.push("financial-workflow-route");
  if (/\/(?:login|signin|reset|password|session|token|oauth|sso|mfa|2fa|otp)(?:\/|\?|$)/i.test(value)) signals.push("auth-workflow-route");
  if (/\/(?:export|download|upload|file|attachment|share|import)(?:\/|\?|$)/i.test(value)) signals.push("data-lifecycle-route");
  if (/\/graphql(?:\/|\?|$)/i.test(value)) signals.push("graphql-endpoint");
  return signals;
}

function looksLikeExpressionOrTextArtifact(value: string): boolean {
  if (/[(){};]/.test(value)) return true;
  if (/(?:^|\/)[+*][A-Za-z_$]/.test(value)) return true;
  if (/\.[A-Za-z_$][\w$]*\(/.test(value)) return true;
  if (/\.\.\.|\[[^\]]*\]|\btruncated\b/i.test(value)) return true;
  if (/(?:^|\/)(?:n|raw)(?:$|[/?#])/i.test(value)) return true;
  return false;
}

function isStaticLikePath(value: string): boolean {
  return /\.(?:m?js|map|css|png|jpe?g|gif|svg|ico|woff2?|ttf|eot)(?:$|[?#/])/i.test(value)
    || /\/(?:public\/static|static|assets|javascripts?|js|css|images?|img|fonts?|vendor|plugins?|datatable|datatables)(?:\/|$)/i.test(value);
}

function decodeURIComponentSafe(value: string): string {
  try {
    return decodeURIComponent(value);
  } catch {
    return value;
  }
}

function dedupeInsertionHints(hints: PayloadInsertionHint[]): PayloadInsertionHint[] {
  const byKey = new Map<string, PayloadInsertionHint>();
  for (const hint of hints) {
    const key = `${hint.method ?? ""}\u0000${hint.endpoint}\u0000${hint.location}\u0000${hint.name ?? ""}`;
    const existing = byKey.get(key);
    if (!existing) {
      byKey.set(key, { ...hint, evidenceRefs: [...new Set(hint.evidenceRefs)], riskSignals: [...new Set(hint.riskSignals)] });
    } else {
      existing.evidenceRefs = [...new Set(existing.evidenceRefs.concat(hint.evidenceRefs))];
      existing.riskSignals = [...new Set(existing.riskSignals.concat(hint.riskSignals))];
    }
  }
  return [...byKey.values()];
}

function parseMetadata(metadata: unknown): Record<string, unknown> | undefined {
  if (typeof metadata === "object" && metadata !== null && !Array.isArray(metadata)) return metadata as Record<string, unknown>;
  if (typeof metadata !== "string" || metadata.trim().length === 0) return undefined;
  try {
    const parsed = JSON.parse(metadata);
    return typeof parsed === "object" && parsed !== null && !Array.isArray(parsed) ? parsed as Record<string, unknown> : undefined;
  } catch {
    return undefined;
  }
}

function arrayOfStrings(value: unknown): string[] {
  return Array.isArray(value) ? value.filter((item): item is string => typeof item === "string" && item.length > 0) : [];
}

function stringValue(value: unknown): string | undefined {
  return typeof value === "string" && value.length > 0 ? value : undefined;
}

function fieldNamesFromMetadata(metadata: Record<string, unknown> | undefined): string[] {
  const fields = metadata?.fields;
  if (!Array.isArray(fields)) return [];
  const names: string[] = [];
  for (const field of fields) {
    if (typeof field === "string") {
      names.push(field);
    } else if (field && typeof field === "object" && typeof (field as { name?: unknown }).name === "string") {
      names.push((field as { name: string }).name);
    }
  }
  return [...new Set(names.filter((name) => name.trim().length > 0))].slice(0, 20);
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim().length > 0))].sort();
}

function clamp(value: number, min: number, max: number): number {
  return Math.min(max, Math.max(min, value));
}
