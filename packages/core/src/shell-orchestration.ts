import { evaluateCommand } from "@aegisprobe/policy";
import { newId, nowIso, sanitizeObservationText, truncateForContext, truncateLongLines, type ShellCommandRecord, type TurnEventKind } from "@aegisprobe/shared";
import { runShell } from "@aegisprobe/shell";
import type { AuditStore } from "@aegisprobe/storage";
import { createAgentToolEnvelope, type AgentToolEnvelope } from "./agent-tool-envelope.js";

export type ApprovalDecisionLike = boolean | {
  approved: boolean;
  remember?: boolean;
};

export type NormalizedApproval = {
  approved: boolean;
  remembered: boolean;
};

export type ShellEventEmitter = (kind: TurnEventKind, message: string, payload?: unknown) => void;

export function normalizeApproval(decision: ApprovalDecisionLike): NormalizedApproval {
  if (typeof decision === "boolean") {
    return { approved: decision, remembered: false };
  }
  return { approved: decision.approved, remembered: Boolean(decision.remember) };
}

export async function resolveShellApproval(
  store: AuditStore,
  command: string,
  subject: string,
  detail: string,
  approve: (subject: string, detail: string) => Promise<ApprovalDecisionLike>
): Promise<NormalizedApproval> {
  if (store.hasApprovedShellCommand(command)) {
    return { approved: true, remembered: true };
  }
  const decision = normalizeApproval(await approve(subject, detail));
  if (decision.approved && decision.remembered) {
    store.rememberApprovedShellCommand(command);
  }
  return decision;
}

export async function runApprovedCommand(
  store: AuditStore,
  record: ShellCommandRecord
): Promise<{ exitCode: number; summary: string; output: string }> {
  store.updateCommand({ ...record, status: "approved", updatedAt: nowIso() });
  const result = await runShell(record.command, process.cwd(), shellTimeoutMs(record.command));
  const exitCode = result.exitCode ?? 1;
  const status = exitCode === 0 ? "success" : "failed";
  store.updateCommand({
    ...record,
    status,
    summary: result.summary,
    exitCode,
    updatedAt: nowIso()
  });
  store.addObservation({
    id: newId("obs"),
    sessionId: record.sessionId,
    source: record.command,
    summary: result.summary || "(no output)",
    createdAt: nowIso()
  });
  return {
    exitCode,
    summary: result.summary,
    output: [result.stdout, result.stderr].filter(Boolean).join("\n").trim()
  };
}

function shellTimeoutMs(command: string): number {
  const normalized = command.toLowerCase();
  if (/\b(dirsearch|ffuf|feroxbuster)\b/.test(normalized)) return 60_000;
  if (/\b(katana|nuclei)\b/.test(normalized)) return 90_000;
  if (/\b(nmap|naabu|amass)\b/.test(normalized)) return 120_000;
  return 120_000;
}

export async function executeCommand(
  store: AuditStore,
  approve: (subject: string, detail: string) => Promise<ApprovalDecisionLike>,
  sessionId: string,
  command: string
): Promise<void> {
  const decision = evaluateCommand(command);
  const createdAt = nowIso();
  const record: ShellCommandRecord = {
    id: newId("cmd"),
    sessionId,
    command,
    risk: decision.risk,
    status: decision.allowed ? "pending" : "blocked",
    summary: decision.reason,
    exitCode: null,
    createdAt,
    updatedAt: createdAt
  };
  store.addCommand(record);

  if (!decision.allowed) {
    store.addApproval(sessionId, command, false, decision.reason);
    return;
  }

  const approval = await resolveShellApproval(
    store,
    command,
    `Execute shell command (${decision.risk})`,
    `${command}\n\n${decision.reason}`,
    approve
  );
  store.addApproval(sessionId, command, approval.approved, approval.remembered ? `${decision.reason} Remembered approval.` : decision.reason);
  if (!approval.approved) {
    store.updateCommand({ ...record, status: "denied", updatedAt: nowIso() });
    return;
  }

  await runApprovedCommand(store, record);
}

export async function executeShellAction(
  store: AuditStore,
  approve: (subject: string, detail: string) => Promise<ApprovalDecisionLike>,
  sessionId: string,
  emit: ShellEventEmitter,
  command: string,
  purpose: string
): Promise<string> {
  const decision = evaluateCommand(command);
  const createdAt = nowIso();
  const record: ShellCommandRecord = {
    id: newId("cmd"),
    sessionId,
    command,
    risk: decision.risk,
    status: decision.allowed ? "pending" : "blocked",
    summary: purpose || decision.reason,
    exitCode: null,
    createdAt,
    updatedAt: createdAt
  };
  store.addCommand(record);

  if (!decision.allowed) {
    store.addApproval(sessionId, command, false, decision.reason);
    emit("tool_blocked", `Blocked shell command: ${command}`, { reason: decision.reason, risk: decision.risk });
    return `Blocked command: ${command}. Reason: ${decision.reason}`;
  }

  const alreadyApproved = store.hasApprovedShellCommand(command);
  if (!alreadyApproved) {
    emit("tool_approval_requested", `Approval requested for shell command: ${command}`, {
      command,
      purpose,
      risk: decision.risk,
      reason: decision.reason
    });
  }

  const approval = await resolveShellApproval(
    store,
    command,
    `Execute shell command (${decision.risk})`,
    `${command}\n\nPurpose: ${purpose}\n${decision.reason}`,
    approve
  );
  store.addApproval(sessionId, command, approval.approved, approval.remembered ? `${decision.reason} Remembered approval.` : decision.reason);
  emit("tool_approval_resolved", approval.approved ? "Shell command approved." : "Shell command denied.", {
    command,
    approved: approval.approved,
    remembered: approval.remembered
  });

  if (!approval.approved) {
    store.updateCommand({ ...record, status: "denied", updatedAt: nowIso() });
    return `User denied command: ${command}`;
  }

  emit("tool_started", `Running shell command: ${command}`, { command });
  const result = await runApprovedCommand(store, record);
  emit("tool_completed", `Shell command completed with exit code ${result.exitCode}.`, {
    command,
    exitCode: result.exitCode,
    summary: result.summary
  });
  return [
    `Command: ${command}`,
    `Exit code: ${result.exitCode}`,
    `Output summary:\n${result.summary || "(no output)"}`,
    result.output && result.output !== result.summary ? `Raw output excerpt:\n${truncateForContext(truncateLongLines(sanitizeObservationText(result.output)), 12_000)}` : undefined
  ].filter(Boolean).join("\n");
}

export async function executeShellActionEnvelope(
  store: AuditStore,
  approve: (subject: string, detail: string) => Promise<ApprovalDecisionLike>,
  sessionId: string,
  emit: ShellEventEmitter,
  command: string,
  purpose: string
): Promise<AgentToolEnvelope> {
  const startedAt = nowIso();
  const decision = evaluateCommand(command);
  const record: ShellCommandRecord = {
    id: newId("cmd"),
    sessionId,
    command,
    risk: decision.risk,
    status: decision.allowed ? "pending" : "blocked",
    summary: purpose || decision.reason,
    exitCode: null,
    createdAt: startedAt,
    updatedAt: startedAt
  };
  store.addCommand(record);

  if (!decision.allowed) {
    store.addApproval(sessionId, command, false, decision.reason);
    emit("tool_blocked", `Blocked shell command: ${command}`, {
      reason: decision.reason,
      risk: decision.risk
    });
    return createAgentToolEnvelope({
      tool: "execute_shell",
      status: "blocked",
      startedAt,
      stderr: decision.reason,
      metadata: { command, purpose, risk: decision.risk }
    });
  }

  const alreadyApproved = store.hasApprovedShellCommand(command);
  if (!alreadyApproved) {
    emit("tool_approval_requested", `Approval requested for shell command: ${command}`, {
      command,
      purpose,
      risk: decision.risk,
      reason: decision.reason
    });
  }
  const approval = await resolveShellApproval(
    store,
    command,
    `Execute shell command (${decision.risk})`,
    `${command}\n\nPurpose: ${purpose}\n${decision.reason}`,
    approve
  );
  store.addApproval(
    sessionId,
    command,
    approval.approved,
    approval.remembered ? `${decision.reason} Remembered approval.` : decision.reason
  );
  emit("tool_approval_resolved", approval.approved ? "Shell command approved." : "Shell command denied.", {
    command,
    approved: approval.approved,
    remembered: approval.remembered
  });

  if (!approval.approved) {
    store.updateCommand({ ...record, status: "denied", updatedAt: nowIso() });
    return createAgentToolEnvelope({
      tool: "execute_shell",
      status: "blocked",
      startedAt,
      stderr: "User denied command execution.",
      metadata: { command, purpose, risk: decision.risk }
    });
  }

  emit("tool_started", `Running shell command: ${command}`, { command });
  store.updateCommand({ ...record, status: "approved", updatedAt: nowIso() });
  const result = await runShell(command, process.cwd(), shellTimeoutMs(command));
  const status = result.exitCode === null
    ? "timeout"
    : result.exitCode === 0
      ? "success"
      : "error";
  store.updateCommand({
    ...record,
    status: status === "success" ? "success" : "failed",
    summary: result.summary,
    exitCode: result.exitCode,
    updatedAt: nowIso()
  });
  store.addObservation({
    id: newId("obs"),
    sessionId,
    source: command,
    summary: result.summary || "(no output)",
    createdAt: nowIso()
  });
  emit("tool_completed", `Shell command completed with exit code ${result.exitCode ?? "timeout"}.`, {
    command,
    exitCode: result.exitCode,
    summary: result.summary
  });

  return createAgentToolEnvelope({
    tool: "execute_shell",
    status,
    startedAt,
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
    metadata: {
      command,
      purpose,
      cwd: process.cwd(),
      risk: decision.risk
    }
  });
}
