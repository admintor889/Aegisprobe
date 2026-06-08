import { mkdirSync, writeFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { nowIso, newId, truncateForContext, type SubAgentRecord, type SubAgentRole, type TargetInput } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import type { SubAgentCoordinationPlan } from "@aegisprobe/security";
import { buildSubAgentDigest, detectSubAgentContradictions } from "./core-helpers.js";
import { subAgentRoleDefinitions } from "./subagent-roles.js";
import { SubAgentRuntime, type SubAgentEmitter } from "./subagent-runtime.js";

export type SubAgentSpawnOptions = {
  background?: boolean;
  description?: string;
  priority?: "critical" | "high" | "medium" | "low";
  queued?: boolean;
  maxRetries?: number;
  parentAgentId?: string;
};

type BaseSubAgentDependencies = {
  store: AuditStore;
  runtime: SubAgentRuntime;
};

type SubAgentQueueDependencies = BaseSubAgentDependencies & {
  buildSubAgentCoordinationPlan: (sessionId: string) => SubAgentCoordinationPlan;
  writeWorkflowEvidenceManifest: (sessionId: string, workflowId: string, target: TargetInput) => string;
  refreshSessionMemory: (sessionId: string) => void;
};

export async function spawnSubAgent(
  deps: BaseSubAgentDependencies,
  sessionId: string,
  role: SubAgentRole,
  task: string,
  contextPaths: string[] = [],
  options: SubAgentSpawnOptions = {}
): Promise<SubAgentRecord> {
  const definition = subAgentRoleDefinitions[role];
  const description = options.description ?? deps.runtime.describeTask(role, task);
  const record = deps.store.createSubAgent(sessionId, role, task, description, {
    status: options.queued ? "queued" : "running",
    priority: options.priority ?? deps.runtime.defaultPriorityForRole(role),
    runMode: options.background ? "background" : "foreground",
    maxRetries: options.maxRetries ?? (options.background ? 2 : 1),
    parentAgentId: options.parentAgentId,
    contextPaths,
    memoryKey: deps.runtime.memoryKey(role, task)
  });
  const withOutput = deps.runtime.initializeOutput(record);
  if (options.queued) {
    deps.runtime.initializeOutput({ ...withOutput, status: "queued" });
    return deps.store.getSubAgent(withOutput.id) ?? withOutput;
  }
  let readyResolve: (() => void) | undefined;
  const ready = new Promise<void>((resolve) => {
    readyResolve = resolve;
  });
  const run = deps.runtime.runRecord(withOutput, definition, task, contextPaths, undefined, Boolean(options.background), readyResolve);
  if (options.background) {
    deps.runtime.trackBackground(withOutput.id, run);
    await Promise.race([
      ready,
      run.then(() => undefined).catch(() => undefined)
    ]);
    return deps.store.getSubAgent(withOutput.id) ?? withOutput;
  }
  await run;
  return deps.store.getSubAgent(withOutput.id) ?? withOutput;
}

export function writeSubAgentDigestFile(store: AuditStore, sessionId: string): string {
  const digest = buildSubAgentDigest(store.listSubAgents(sessionId));
  const digestPath = resolve("data", "subagents", sessionId, "_digest.md");
  mkdirSync(dirname(digestPath), { recursive: true });
  writeFileSync(digestPath, digest || "# Subagent Digest\n\nNo completed subagents yet.\n", "utf8");
  return digestPath;
}

export function enrichSubAgentTask(store: AuditStore, sessionId: string, task: string): { task: string; contextPaths: string[] } {
  const digestPath = writeSubAgentDigestFile(store, sessionId);
  const digest = buildSubAgentDigest(store.listSubAgents(sessionId));
  const enrichedTask = digest
    ? `${task}\n\n---\n## What other subagents have already discovered:\n${digest.slice(0, 30000)}`
    : task;
  return { task: enrichedTask, contextPaths: [digestPath] };
}

export async function executeSubAgentAction(
  deps: BaseSubAgentDependencies,
  sessionId: string,
  emit: SubAgentEmitter,
  role: SubAgentRole,
  description: string | undefined,
  task: string,
  contextPaths: string[],
  background: boolean
): Promise<string> {
  const definition = subAgentRoleDefinitions[role];
  const resolvedDescription = description ?? deps.runtime.describeTask(role, task);
  const enriched = enrichSubAgentTask(deps.store, sessionId, task);
  const enrichedTask = enriched.task;
  const enrichedPaths = [...contextPaths, ...enriched.contextPaths];
  const record = deps.store.createSubAgent(sessionId, role, enrichedTask, resolvedDescription, {
    status: "running",
    priority: deps.runtime.defaultPriorityForRole(role),
    runMode: background ? "background" : "foreground",
    maxRetries: background ? 2 : 1,
    contextPaths: enrichedPaths,
    memoryKey: deps.runtime.memoryKey(role, task)
  });
  const withOutput = deps.runtime.initializeOutput(record);
  emit("subagent_started", `Subagent started: ${withOutput.id}`, {
    id: withOutput.id,
    role,
    description: resolvedDescription,
    tools: background ? definition.backgroundTools : definition.foregroundTools,
    task: enrichedTask,
    background,
    outputPath: withOutput.outputPath
  });
  let readyResolve: (() => void) | undefined;
  const ready = new Promise<void>((resolve) => {
    readyResolve = resolve;
  });
  const run = deps.runtime.runRecord(withOutput, definition, enrichedTask, enrichedPaths, emit, background, readyResolve);
  if (background) {
    deps.runtime.trackBackground(withOutput.id, run);
    await Promise.race([
      ready,
      run.then(() => undefined).catch(() => undefined)
    ]);
    emit("subagent_launched", `Subagent launched in background: ${withOutput.id}`, {
      id: withOutput.id,
      role,
      task: enrichedTask,
      outputPath: withOutput.outputPath
    });
    return `Subagent ${withOutput.id} (${role}) launched in background. Use /agents to check status.`;
  }

  return await run;
}

export async function enqueueSubAgent(
  deps: BaseSubAgentDependencies,
  sessionId: string,
  role: SubAgentRole,
  task: string,
  contextPaths: string[] = [],
  options: Omit<SubAgentSpawnOptions, "queued"> = {}
): Promise<SubAgentRecord> {
  return await spawnSubAgent(deps, sessionId, role, task, contextPaths, {
    ...options,
    queued: true,
    background: options.background ?? true
  });
}

export async function dispatchSubAgentQueue(
  deps: BaseSubAgentDependencies,
  sessionId: string,
  options: { maxJobs?: number; concurrency?: number; recoverStaleAfterMs?: number } = {}
): Promise<string> {
  if (!deps.store.hasSession(sessionId)) {
    throw new Error(`Session not found: ${sessionId}`);
  }
  const staleMs = Math.max(30_000, options.recoverStaleAfterMs ?? 10 * 60_000);
  const staleBefore = new Date(Date.now() - staleMs).toISOString();
  const recovered = deps.store.requeueStaleRunningSubAgents(sessionId, staleBefore);
  const maxJobs = Math.max(1, Math.min(options.maxJobs ?? 4, 12));
  const concurrency = Math.max(1, Math.min(options.concurrency ?? 2, maxJobs));
  const claimed = deps.store.claimQueuedSubAgents(sessionId, maxJobs);
  if (claimed.length === 0) {
    return `Subagent dispatcher found no queued work. recovered=${recovered}`;
  }

  const lines = [`Subagent dispatcher claimed ${claimed.length} job(s). recovered=${recovered} concurrency=${concurrency}`];
  const runOne = async (record: SubAgentRecord): Promise<string> => {
    const definition = subAgentRoleDefinitions[record.role];
    const withOutput = deps.runtime.initializeOutput(record);
    const run = deps.runtime.runRecord(withOutput, definition, record.task, record.contextPaths ?? [], undefined, record.runMode === "background");
    if (record.runMode === "background") {
      deps.runtime.trackBackground(record.id, run);
      return `launched ${record.id} ${record.role} background priority=${record.priority ?? "medium"}`;
    }
    return await run;
  };

  for (let index = 0; index < claimed.length; index += concurrency) {
    const batch = claimed.slice(index, index + concurrency);
    const results = await Promise.all(batch.map((record) => runOne(record)));
    lines.push(...results.map((line) => truncateForContext(line, 500)));
  }
  return lines.join("\n");
}

export async function enqueueRecommendedSubAgents(
  deps: SubAgentQueueDependencies,
  sessionId: string,
  limit = 6
): Promise<string> {
  if (!deps.store.hasSession(sessionId)) {
    throw new Error(`Session not found: ${sessionId}`);
  }
  const plan = deps.buildSubAgentCoordinationPlan(sessionId);
  const existingKeys = new Set(deps.store.listSubAgents(sessionId).map((agent) =>
    `${agent.role}:${agent.description ?? ""}:${agent.task.slice(0, 120)}`
  ));
  const enqueued: SubAgentRecord[] = [];
  for (const item of plan.items.filter((entry) => !entry.blockedReason).slice(0, Math.max(1, limit))) {
    const key = `${item.role}:${item.title}:${item.task.slice(0, 120)}`;
    if (existingKeys.has(key)) {
      continue;
    }
    enqueued.push(await enqueueSubAgent(deps, sessionId, item.role, item.task, [], {
      description: item.title,
      priority: item.priority,
      background: item.runMode === "background",
      maxRetries: item.priority === "critical" || item.priority === "high" ? 2 : 1
    }));
    existingKeys.add(key);
  }
  if (enqueued.length === 0) {
    return "No new subagents were enqueued from the current coordination plan.";
  }
  return [
    `Enqueued ${enqueued.length} recommended subagent(s).`,
    ...enqueued.map((agent) => `- ${agent.id} | ${agent.priority ?? "medium"} | ${agent.role} | ${agent.description ?? agent.task.split(/\r?\n/)[0]}`)
  ].join("\n");
}

export async function enqueueBaselinePentestSubAgents(
  deps: SubAgentQueueDependencies,
  sessionId: string,
  workflowId: string,
  target: TargetInput
): Promise<SubAgentRecord[]> {
  const existingRoles = new Set(deps.store.listSubAgents(sessionId).map((agent) => agent.role));
  const evidenceManifest = deps.writeWorkflowEvidenceManifest(sessionId, workflowId, target);
  const baselinePlan: Array<{
    role: SubAgentRole;
    description: string;
    priority: NonNullable<SubAgentSpawnOptions["priority"]>;
    background: boolean;
    task: string;
  }> = [
    {
      role: "recon",
      description: "Coordinate asset expansion and fallback paths",
      priority: "high",
      background: true,
      task: [
        `Target: ${target.kind}:${target.normalized}`,
        `Read the workflow evidence manifest first: ${evidenceManifest}`,
        "Expand passive asset discovery, reconcile tool availability gaps, and define the next low-risk reconnaissance steps."
      ].join("\n")
    },
    {
      role: "frontend",
      description: "Map frontend/API attack surface",
      priority: "medium",
      background: true,
      task: [
        `Target: ${target.kind}:${target.normalized}`,
        `Use the workflow evidence manifest first: ${evidenceManifest}`,
        "Map routes, forms, JavaScript/API endpoints, source maps, and auth-sensitive frontend entry points from recorded evidence."
      ].join("\n")
    },
    {
      role: "cve",
      description: "Deduplicate and rank CVE/framework candidates",
      priority: "high",
      background: true,
      task: [
        `Target: ${target.kind}:${target.normalized}`,
        `Use the workflow evidence manifest first: ${evidenceManifest}`,
        "Review technology hints, version clues, and blocked tool runs. Rank likely CVE candidates and note the safest validation evidence needed."
      ].join("\n")
    },
    {
      role: "web_vuln",
      description: "Plan authenticated business-logic validation",
      priority: "medium",
      background: false,
      task: [
        `Target: ${target.kind}:${target.normalized}`,
        `Use the workflow evidence manifest first: ${evidenceManifest}`,
        "Prepare a non-destructive OWASP and business-logic validation plan, with auth assumptions, stop conditions, and evidence requirements."
      ].join("\n")
    }
  ];

  const queued: SubAgentRecord[] = [];
  for (const item of baselinePlan) {
    if (existingRoles.has(item.role)) {
      continue;
    }
    queued.push(await enqueueSubAgent(deps, sessionId, item.role, item.task, [evidenceManifest], {
      description: item.description,
      priority: item.priority,
      background: item.background,
      maxRetries: item.priority === "high" || item.priority === "critical" ? 2 : 1
    }));
    existingRoles.add(item.role);
  }
  return queued;
}

export function arbitrateSubAgentResults(
  deps: Pick<SubAgentQueueDependencies, "store" | "refreshSessionMemory">,
  sessionId: string
): string {
  const agents = deps.store.listSubAgents(sessionId);
  const completed = agents.filter((agent) => agent.status === "completed" && agent.resultSummary);
  const failed = agents.filter((agent) => agent.status === "failed");
  const queued = agents.filter((agent) => agent.status === "queued");
  const running = agents.filter((agent) => agent.status === "running");
  if (completed.length === 0 && failed.length === 0) {
    return `Subagent arbitration: no completed or failed subagents yet. queued=${queued.length} running=${running.length}`;
  }

  const roleSummaries = [...new Set(completed.map((agent) => agent.role))]
    .map((role) => {
      const roleAgents = completed.filter((agent) => agent.role === role);
      const highlights = roleAgents
        .map((agent) => agent.resultSummary?.split(/\r?\n/).find((line) => line.trim()))
        .filter((line): line is string => Boolean(line))
        .slice(0, 3);
      return `${role}: ${roleAgents.length} completed; ${highlights.join(" | ")}`;
    });
  const contradictions = detectSubAgentContradictions(completed);
  const summary = [
    `Subagent arbitration: completed=${completed.length} failed=${failed.length} queued=${queued.length} running=${running.length}`,
    ...roleSummaries,
    contradictions.length > 0 ? `Contradictions/risks: ${contradictions.join("; ")}` : "Contradictions/risks: none obvious from summaries.",
    failed.length > 0 ? `Failures requiring retry/review: ${failed.map((agent) => `${agent.id}:${agent.role}`).join(", ")}` : undefined
  ].filter(Boolean).join("\n");

  const workflowId = deps.store.listSecurityWorkflows(sessionId).at(-1)?.id;
  deps.store.addEvidence({
    id: newId("evd"),
    sessionId,
    workflowId,
    source: "subagent:arbitration",
    kind: "note",
    summary: truncateForContext(summary, 1000),
    data: JSON.stringify({
      completed: completed.map((agent) => ({ id: agent.id, role: agent.role, priority: agent.priority, summary: agent.resultSummary })),
      failed: failed.map((agent) => ({ id: agent.id, role: agent.role, retryCount: agent.retryCount, result: agent.resultSummary })),
      contradictions
    }, null, 2),
    createdAt: nowIso()
  });
  deps.store.addObservation({
    id: newId("obs"),
    sessionId,
    source: "subagent:arbitration",
    summary: truncateForContext(summary, 20_000),
    createdAt: nowIso()
  });
  deps.refreshSessionMemory(sessionId);
  return summary;
}
