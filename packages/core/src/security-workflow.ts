import { buildSecurityWorkflowPlan } from "@aegisprobe/security";
import type { TargetInput } from "@aegisprobe/shared";
import type { AuditStore } from "@aegisprobe/storage";
import type { SkillRegistry } from "@aegisprobe/skills";

export async function buildSecurityWorkflowContext(
  store: AuditStore,
  skillRegistry: SkillRegistry,
  input: {
    sessionId: string;
    intent: string;
    target: TargetInput;
    isSecurityAssessmentIntent: (intent: string) => boolean;
    emit: (kind: string, message: string, payload?: unknown) => void;
  }
): Promise<string> {
  if (!input.isSecurityAssessmentIntent(input.intent) || (input.target.kind !== "url" && input.target.kind !== "domain")) {
    return "No security workflow required for this turn.";
  }
  try {
    const plan = await buildSecurityWorkflowPlan(input.sessionId, input.target, skillRegistry, {
      includeHighRisk: true,
      skillsPerPhase: 3
    });
    store.upsertSecurityWorkflow(plan.workflow);
    store.addSecurityTasks(plan.tasks);
    input.emit("security_workflow_built", "Security workflow built for authorized assessment.", {
      workflowId: plan.workflow.id,
      target: input.target,
      phases: plan.tasks.map((task) => task.phase)
    });
    return plan.prompt;
  } catch (error) {
    return `Security workflow unavailable: ${error instanceof Error ? error.message : String(error)}`;
  }
}
