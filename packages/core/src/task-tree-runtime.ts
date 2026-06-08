import { newId, nowIso, type TaskTreeNode } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import type { PentestPipeline } from "@aegisprobe/security";

export function createPipelineTaskTree(
  store: AuditStore,
  sessionId: string,
  workflowId: string,
  pipeline: PentestPipeline
): TaskTreeNode[] {
  const nodes: TaskTreeNode[] = [];
  const now = nowIso();
  let order = 0;

  for (const step of pipeline.steps) {
    const node: TaskTreeNode = {
      id: newId("task"),
      sessionId,
      workflowId,
      phase: step.phase,
      title: step.title,
      goal: step.description,
      status: "pending",
      toolId: step.toolId,
      evidenceIds: [],
      findingIds: [],
      summary: "",
      sortOrder: order++,
      createdAt: now,
      updatedAt: now
    };
    store.upsertTaskNode(node);
    nodes.push(node);
  }
  return nodes;
}

export function updatePipelineTaskNode(
  store: AuditStore,
  node: TaskTreeNode,
  status: TaskTreeNode["status"],
  summary: string,
  evidenceIds: string[] = [],
  findingIds: string[] = []
): void {
  node.status = status;
  node.summary = summary;
  node.updatedAt = nowIso();
  for (const evidenceId of evidenceIds) node.evidenceIds.push(evidenceId);
  for (const findingId of findingIds) node.findingIds.push(findingId);
  store.upsertTaskNode(node);
}
