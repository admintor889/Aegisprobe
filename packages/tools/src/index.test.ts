import { describe, expect, it } from "vitest";
import { parseAgentDecision } from "./index.js";

describe("tool decision parsing", () => {
  it("accepts Claude-style subagent fields", () => {
    const decision = parseAgentDecision(JSON.stringify({
      message: "Delegate.",
      plan: [],
      actions: [
        {
          type: "subagent",
          description: "Inspect storage layer",
          prompt: "Read storage code and summarize risks.",
          subagent_type: "reviewer",
          run_in_background: true
        }
      ],
      final: false
    }));

    expect(decision.actions).toEqual([
      {
        type: "subagent",
        role: "reviewer",
        description: "Inspect storage layer",
        task: "Read storage code and summarize risks.",
        contextPaths: undefined,
        background: true
      }
    ]);
  });

  it("accepts security subagent roles", () => {
    const decision = parseAgentDecision(JSON.stringify({
      message: "Delegate security checks.",
      plan: [],
      actions: [
        { type: "subagent", role: "recon", task: "Plan authorized recon." },
        { type: "subagent", role: "frontend", task: "Inspect frontend routes." },
        { type: "subagent", role: "fingerprint", task: "Infer tech stack." },
        { type: "subagent", role: "cve", task: "Map versions to CVEs." },
        { type: "subagent", role: "web_vuln", task: "Assess OWASP risks." }
      ],
      final: false
    }));

    expect(decision.actions.map((action) => action.type === "subagent" ? action.role : undefined)).toEqual([
      "recon",
      "frontend",
      "fingerprint",
      "cve",
      "web_vuln"
    ]);
  });

  it("accepts built-in security probes", () => {
    const decision = parseAgentDecision(JSON.stringify({
      message: "Probe safely.",
      plan: [],
      actions: [
        {
          type: "security_probe",
          target: "https://example.com",
          probe: "basic_recon",
          purpose: "Collect DNS and HTTP headers."
        }
      ],
      final: false
    }));

    expect(decision.actions).toEqual([
      {
        type: "security_probe",
        target: "https://example.com",
        probe: "basic_recon",
        purpose: "Collect DNS and HTTP headers."
      }
    ]);
  });
});
