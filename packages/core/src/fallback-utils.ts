import { MissingProviderKeyError } from "@aegisprobe/provider";
import { newId, nowIso, type AgentDecision, type AgentPlan, type ContextFile, type TargetInput } from "@aegisprobe/shared";

export function summarizeContextsLocally(contexts: ContextFile[], heading: string): string {
  const summaries = contexts.map((ctx) => {
    const lines = ctx.content.split(/\r?\n/);
    const bullets = lines
      .map((line) => line.trim())
      .filter((line) => /^[-*]\s+/.test(line) || /^#{1,3}\s+/.test(line))
      .slice(0, 12)
      .map((line) => `- ${line.replace(/^[-*]\s+/, "")}`);
    const preview = bullets.length > 0
      ? bullets.join("\n")
      : lines.map((line) => line.trim()).filter(Boolean).slice(0, 8).map((line) => `- ${line}`).join("\n");
    return [
      `File: ${ctx.path}`,
      ctx.truncated ? "Note: file content was truncated." : "Note: full file content was read.",
      preview || "- No readable text content found."
    ].join("\n");
  });
  return [heading, ...summaries].join("\n\n");
}

export function buildFallbackDecision(input: {
  userInput: string;
  target: TargetInput;
  contexts: ContextFile[];
  observations: string[];
  error: unknown;
  inferredIntent: string;
  securityWorkflowContext?: string;
}): AgentDecision {
  const securityWorkflowContext = input.securityWorkflowContext ?? "No security workflow available.";
  if (input.observations.length > 0) {
    return {
      message: `Observed tool output and completed the turn. Provider decision fallback is active. Last observation:\n${input.observations.at(-1)}`,
      plan: ["Review the command observation.", "Record the result in SQLite.", "Defer deeper automation to a later version."],
      actions: [],
      final: true
    };
  }

  if (input.contexts.length > 0) {
    return {
      message: summarizeContextsLocally(input.contexts, `Local file analysis for: ${input.userInput}`),
      plan: ["Read referenced local files.", "Summarize visible content.", "Avoid modifying files."],
      actions: [],
      final: true
    };
  }

  if (input.target.kind === "text" && input.inferredIntent === "conversation") {
    return {
      message: "I understand your message as normal conversation. If you want me to execute work, describe the task, URL, domain, or file path.",
      plan: [],
      actions: [],
      final: true
    };
  }

  const reason = input.error instanceof MissingProviderKeyError
    ? `Provider is not configured: ${input.error.message}`
    : `Provider decision failed; using fallback. ${(input.error as Error).message}`;
  const securityAssessment = input.inferredIntent === "authorized_security_assessment" && (input.target.kind === "url" || input.target.kind === "domain");
  const actions = securityAssessment
    ? [
        {
          type: "subagent" as const,
          role: "recon" as const,
          description: "Passive recon plan",
          task: `Plan passive reconnaissance for ${input.target.kind}:${input.target.normalized}. Use this workflow context:\n${securityWorkflowContext}`,
          background: false
        },
        {
          type: "subagent" as const,
          role: "fingerprint" as const,
          description: "Fingerprint plan",
          task: `Identify safe fingerprinting evidence needed for ${input.target.kind}:${input.target.normalized}. Do not run commands; recommend approved probes only.`,
          background: false
        },
        {
          type: "subagent" as const,
          role: "web_vuln" as const,
          description: "OWASP checks",
          task: `Plan non-destructive OWASP Top 10 validation steps for ${input.target.kind}:${input.target.normalized}. Separate hypotheses from evidence.`,
          background: false
        }
      ]
    : input.target.kind === "url"
      ? [{ type: "shell" as const, command: `curl.exe -I --max-time 10 "${input.target.normalized}"`, purpose: "Collect HTTP response headers for the authorized URL." }]
      : input.target.kind === "domain"
        ? [{ type: "shell" as const, command: `nslookup "${input.target.normalized}"`, purpose: "Resolve the authorized domain." }]
        : [];

  return {
    message: `Codex-like fallback decision for: ${input.userInput}\n${reason}`,
    plan: [
      "Confirm current context and authorization.",
      "Request approval before any shell action.",
      "Execute at most one low-impact observation command.",
      "Feed the observation back into the next decision iteration.",
      "Complete the turn with an audited summary."
    ],
    actions,
    final: actions.length === 0
  };
}

export function buildFallbackPlan(sessionId: string, input: string, target: TargetInput): AgentPlan {
  const commands: string[] = [];
  if (target.kind === "url") {
    commands.push(`curl.exe -I --max-time 10 "${target.normalized}"`);
  } else if (target.kind === "domain") {
    commands.push(`nslookup "${target.normalized}"`);
  }

  return {
    id: newId("plan"),
    sessionId,
    goal: input,
    summary: "Fallback plan: build context, confirm authorization, optionally execute safe observation commands, and record all actions in SQLite.",
    steps: [
      "Confirm the target and authorization boundary.",
      "Build local context from file input when provided.",
      "Ask before every shell command.",
      "Record plan, approvals, commands, and observations in SQLite.",
      "Summarize what happened and defer deeper security tooling to later versions."
    ],
    suggestedCommands: commands,
    createdAt: nowIso()
  };
}
