import { mkdirSync, writeFileSync } from "node:fs";
import { join as joinPath } from "node:path";
import { buildPentestPipeline, buildSecurityToolCommandForInputFile, type NormalizedSecurityObservation, type PentestScope, type PipelinePreflightReport, type SecurityDecisionQueueItem } from "@aegisprobe/security";
import { newId, nowIso, type SecurityFinding, type SecurityToolRun, type SecurityToolRunStatus, type SubAgentRole, type TargetInput } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import { sanitizePathSegment } from "./core-helpers.js";

export function createSecurityToolRun(
  store: AuditStore,
  input: Omit<SecurityToolRun, "id" | "status" | "createdAt" | "updatedAt"> & { status?: SecurityToolRunStatus }
): SecurityToolRun {
  const createdAt = nowIso();
  const run: SecurityToolRun = {
    id: newId("trun"),
    status: input.status ?? "planned",
    createdAt,
    updatedAt: createdAt,
    ...input
  };
  store.addSecurityToolRun(run);
  return run;
}

export function finishSecurityToolRun(
  store: AuditStore,
  run: SecurityToolRun,
  status: SecurityToolRunStatus,
  update: Partial<Pick<SecurityToolRun, "command" | "inputArtifact" | "outputArtifact" | "outputSummary" | "exitCode" | "blockedReason" | "failureCategory" | "findingCount">> = {}
): SecurityToolRun {
  const updated: SecurityToolRun = {
    ...run,
    ...update,
    status,
    updatedAt: nowIso()
  };
  store.updateSecurityToolRun(updated);
  return updated;
}

export function recordPipelinePreflightToolRuns(
  store: AuditStore,
  sessionId: string,
  workflowId: string,
  preflight: PipelinePreflightReport
): void {
  for (const item of preflight.items) {
    if (item.kind !== "tool") {
      continue;
    }
    if (store.listSecurityToolRuns(sessionId, workflowId).some((run) => run.toolId === item.toolId)) {
      continue;
    }
    const status: SecurityToolRunStatus =
      item.status === "blocked" ? "blocked"
        : item.status === "unavailable" ? "missing"
          : item.status === "no_command" ? "skipped"
            : "planned";
    const failureCategory =
      status === "blocked" ? "blocked"
        : status === "missing" ? "missing"
          : undefined;
    createSecurityToolRun(store, {
      sessionId,
      workflowId,
      toolId: item.toolId,
      phase: item.phase,
      origin: "pipeline",
      status,
      command: item.command,
      inputKind: "target",
      inputCount: 1,
      outputSummary: item.detail,
      blockedReason: status === "blocked" || status === "missing" ? item.detail : undefined,
      failureCategory
    });
  }
}

export function describeToolRunStatus(status: SecurityToolRunStatus): string {
  switch (status) {
    case "success":
      return "executed";
    case "denied":
      return "denied by user";
    case "failed":
      return "failed";
    case "blocked":
      return "blocked";
    case "missing":
      return "missing";
    case "skipped":
      return "skipped";
    case "no_findings":
      return "completed with no findings";
    case "planned":
      return "planned";
    default:
      return status;
  }
}

export function extractExitCode(output: string): number | undefined {
  const match = output.match(/^Exit code:\s*(-?\d+)/m);
  if (!match) {
    return undefined;
  }
  const parsed = Number.parseInt(match[1] ?? "", 10);
  return Number.isFinite(parsed) ? parsed : undefined;
}

export function recordNormalizedSecurityObservation(
  store: AuditStore,
  input: {
    sessionId: string;
    workflowId: string;
    observation: NormalizedSecurityObservation;
    enrichFindingForStorage: (finding: SecurityFinding) => SecurityFinding;
    addCveMatchDeduped: (match: {
      id: string;
      sessionId: string;
      workflowId: string;
      createdAt: string;
      target: string;
      technology: string;
      title: string;
      cveId?: string;
      severity: "info" | "low" | "medium" | "high" | "critical";
      confidence: "low" | "medium" | "high";
      rationale: string;
      source: string;
      cvssVector?: string;
      cvssScore?: number;
      references?: string[];
      affectedVersions?: string;
      fixedVersions?: string;
      evidenceSummary?: string;
    }) => void;
  }
): void {
  for (const asset of input.observation.assets) {
    store.addAsset({
      id: newId("asset"),
      sessionId: input.sessionId,
      workflowId: input.workflowId,
      createdAt: nowIso(),
      ...asset
    });
  }
  for (const technology of input.observation.technologies) {
    store.addTechnology({
      id: newId("tech"),
      sessionId: input.sessionId,
      workflowId: input.workflowId,
      createdAt: nowIso(),
      ...technology
    });
  }
  for (const finding of input.observation.findings) {
    store.upsertFinding(input.enrichFindingForStorage({
      id: newId("find"),
      sessionId: input.sessionId,
      workflowId: input.workflowId,
      createdAt: nowIso(),
      updatedAt: nowIso(),
      ...finding
    }));
  }
  for (const match of input.observation.cveMatches) {
    input.addCveMatchDeduped({
      id: newId("cve"),
      sessionId: input.sessionId,
      workflowId: input.workflowId,
      createdAt: nowIso(),
      ...match
    });
  }
  if (input.observation.notes.length > 0) {
    store.addEvidence({
      id: newId("evd"),
      sessionId: input.sessionId,
      workflowId: input.workflowId,
      source: "tool:normalizer",
      kind: "note",
      summary: input.observation.notes.join("\n"),
      data: JSON.stringify(input.observation.notes, null, 2),
      createdAt: nowIso()
    });
  }
}

export function writeAdaptiveInputFile(
  projectRoot: string,
  sessionId: string,
  workflowId: string,
  toolId: string,
  values: string[]
): string {
  const dir = joinPath(projectRoot, "data", "runs", sanitizePathSegment(sessionId), sanitizePathSegment(workflowId));
  mkdirSync(dir, { recursive: true });
  const path = joinPath(dir, `${sanitizePathSegment(toolId)}-${Date.now()}.txt`);
  writeFileSync(path, `${values.join("\n")}\n`, "utf8");
  return path;
}

export function writeToolOutputArtifact(
  projectRoot: string,
  sessionId: string,
  workflowId: string,
  toolId: string | undefined,
  output: string
): string {
  const dir = joinPath(projectRoot, "data", "runs", sanitizePathSegment(sessionId), sanitizePathSegment(workflowId), "artifacts");
  mkdirSync(dir, { recursive: true });
  const path = joinPath(dir, `${sanitizePathSegment(toolId ?? "tool")}-output-${Date.now()}.txt`);
  writeFileSync(path, output, "utf8");
  return path;
}

export function buildDecisionToolCommand(
  projectRoot: string,
  sessionId: string,
  workflowId: string,
  target: TargetInput,
  scope: PentestScope,
  item: SecurityDecisionQueueItem
): { command?: string; inputArtifact?: string } {
  const adapter = buildPentestPipeline(target, scope, projectRoot).adapters.find((candidate) => candidate.id === item.toolId);
  if (!adapter) {
    return {};
  }
  const inputs = decisionItemInputs(item, target);
  if (adapter.buildCommandForInputFile && inputs.length > 0) {
    const inputArtifact = writeAdaptiveInputFile(projectRoot, sessionId, workflowId, item.toolId ?? "tool", inputs);
    return {
      command: buildSecurityToolCommandForInputFile(item.toolId ?? "", inputArtifact, scope, projectRoot),
      inputArtifact
    };
  }
  return {
    command: adapter.buildCommand(target, scope)
  };
}

export function decisionItemInputs(item: SecurityDecisionQueueItem, target: TargetInput): string[] {
  const raw = item.target
    .split(/\s*,\s*/)
    .map((value) => value.trim())
    .filter((value) => value && value !== "unknown");
  const values = raw.length > 0 ? raw : [target.normalized];
  return [...new Set(values.map((value) => value.replace(/[.;]+$/u, "")))];
}

export function inputKindForDecisionTool(toolId: string | undefined): SecurityToolRun["inputKind"] {
  switch (toolId) {
    case "dnsx":
    case "httpx":
    case "subfinder":
    case "amass":
      return "host";
    case "katana":
    case "nuclei-tech":
    case "nuclei-owasp":
    case "dirsearch":
      return "url";
    case "nmap":
      return "service";
    default:
      return "target";
  }
}

export function roleForDecisionItem(item: SecurityDecisionQueueItem): SubAgentRole {
  if (/business|logic|auth|idor|bola|workflow/i.test(`${item.title} ${item.reason}`)) {
    return "web_vuln";
  }
  if (item.phase === "frontend") {
    return "frontend";
  }
  if (item.phase === "recon" || item.phase === "asset_discovery") {
    return "recon";
  }
  if (item.phase === "fingerprint") {
    return "fingerprint";
  }
  if (item.phase === "vulnerability_analysis") {
    return "cve";
  }
  return "default";
}
