import { existsSync, statSync } from "node:fs";
import { extractFilePathMentions, extractUrlLikeTargets, hasKnownFileExtension, parseTargetInput, validateReadablePath, type IntentExtraction, type TargetInput } from "@aegisprobe/shared";

export function parseIntentExtraction(
  input: string,
  text: string,
  extractJsonObject: (text: string) => string
): IntentExtraction {
  const parsed = JSON.parse(extractJsonObject(text)) as {
    intent?: unknown;
    targets?: unknown;
    filePaths?: unknown;
    constraints?: unknown;
    needsClarification?: unknown;
    clarificationQuestion?: unknown;
  };
  const parsedTargets = Array.isArray(parsed.targets)
    ? parsed.targets
        .filter((target): target is string => typeof target === "string")
        .map((target) => parseTargetInput(target))
        .filter((target) => target.kind === "url" || target.kind === "domain")
    : [];
  const inferredIntent = typeof parsed.intent === "string" && parsed.intent.trim() ? parsed.intent : inferIntent(input);
  const modelFilePaths = Array.isArray(parsed.filePaths)
    ? parsed.filePaths.filter((path): path is string => typeof path === "string")
    : [];
  const filePaths = sanitizeFilePaths([...modelFilePaths, ...extractFilePathMentions(input)]);
  const fallbackTargets = extractUrlLikeTargets(input);
  const targets = sanitizeTargets(parsedTargets.length > 0 ? parsedTargets : fallbackTargets, filePaths);
  return {
    userText: input,
    intent: normalizeIntent(input, inferredIntent, targets, filePaths),
    targets,
    filePaths,
    constraints: Array.isArray(parsed.constraints)
      ? parsed.constraints.filter((constraint): constraint is string => typeof constraint === "string")
      : [],
    needsClarification: Boolean(parsed.needsClarification),
    clarificationQuestion: typeof parsed.clarificationQuestion === "string" ? parsed.clarificationQuestion : undefined
  };
}

export function fallbackIntent(input: string): IntentExtraction {
  const filePaths = sanitizeFilePaths(extractFilePathMentions(input));
  const explicitTargets = sanitizeTargets(extractUrlLikeTargets(input), filePaths);
  const direct = parseTargetInput(input);
  const targets = explicitTargets.length > 0
    ? explicitTargets
    : (direct.kind === "url" || direct.kind === "domain" ? [direct] : []);
  if (direct.kind === "file") {
    filePaths.push(...sanitizeFilePaths([direct.normalized]).filter((filePath) => !filePaths.includes(filePath)));
  }
  const looksTaskLike = /(\u626b\u63cf|\u63a2\u6d4b|\u6e17\u900f\u6d4b\u8bd5|\u5206\u6790|\u68c0\u67e5|\u6536\u96c6|\u770b\u770b|\u5e2e\u6211|\u8bf7|find|scan|test|analy[sz]e|check|inspect)/i.test(input);
  const intent = inferIntent(input);
  return {
    userText: input,
    intent: normalizeIntent(input, intent, targets, filePaths),
    targets,
    filePaths,
    constraints: extractLocalConstraints(input),
    needsClarification: looksTaskLike && targets.length === 0 && filePaths.length === 0,
    clarificationQuestion: looksTaskLike && targets.length === 0 && filePaths.length === 0
      ? "Please provide the URL, domain, or local file path to work on."
      : undefined
  };
}

export function inferIntent(input: string): string {
  if (/(\u626b\u63cf|\u63a2\u6d4b|\u6e17\u900f\u6d4b\u8bd5|\u5b89\u5168|\u6f0f\u6d1e|scan|pentest|recon)/i.test(input)) {
    return "authorized_security_assessment";
  }
  if (/(\u5206\u6790|\u603b\u7ed3|\u9605\u8bfb|\u770b\u770b|analy[sz]e|summari[sz]e|read)/i.test(input)) {
    return "analysis";
  }
  return "conversation";
}

export function isSecurityAssessmentIntent(intent: string): boolean {
  return /(authorized_)?security_assessment|pentest|penetration|recon|vulnerability|\u5b89\u5168|\u6e17\u900f|\u6f0f\u6d1e/i.test(intent);
}

export function normalizeIntent(input: string, intent: string, targets: TargetInput[], filePaths: string[]): string {
  if (intent === "conversation" && (targets.length > 0 || filePaths.length > 0)) {
    const inferred = inferIntent(input);
    return inferred === "conversation" ? "task" : inferred;
  }
  return intent;
}

export function sanitizeTargets(targets: TargetInput[], filePaths: string[]): TargetInput[] {
  const fileBasenames = new Set(filePaths.map((filePath) => filePath.split(/[\\/]/).at(-1)?.toLowerCase()).filter(Boolean));
  return targets.filter((target) => {
    if (target.kind !== "domain") {
      return true;
    }
    if (hasKnownFileExtension(target.normalized)) {
      return false;
    }
    return !fileBasenames.has(target.normalized.toLowerCase());
  });
}

export function sanitizeFilePaths(filePaths: string[]): string[] {
  const normalized = new Set<string>();
  for (const filePath of filePaths) {
    const decision = validateReadablePath(filePath);
    if (!decision.allowed) {
      continue;
    }
    if (existsSync(decision.absolutePath) && statSync(decision.absolutePath).isFile()) {
      normalized.add(decision.absolutePath);
    }
  }
  return [...normalized];
}

export function extractLocalConstraints(input: string): string[] {
  const constraints: string[] = [];
  if (/(\u4e0d\u8981|\u7981\u6b62|no|avoid).*(\u9ad8\u98ce\u9669|high[- ]?risk|scan|exploit)/i.test(input)) {
    constraints.push("avoid high-risk actions");
  }
  return constraints;
}

export function stepsFromText(text: string): string[] | null {
  const steps = text
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => /^\d+[\.)]\s+/.test(line))
    .map((line) => line.replace(/^\d+[\.)]\s+/, ""));
  return steps.length > 0 ? steps : null;
}
