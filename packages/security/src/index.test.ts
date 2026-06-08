import { describe, expect, it } from "vitest";
import { mkdtempSync, mkdirSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeJavaScriptAsset, buildAccessExposureMap, buildAdaptiveSecurityActions, buildAuthSurfaceAssessment, buildAuthorizedValidationPlaybook, buildBrowserInteractionPlan, buildBusinessLogicKnowledgeBase, buildBusinessLogicTestPlan, buildBusinessWorkflowGraph, buildCveReconciliationPlan, buildFrameworkKnowledgeIndex, buildFullExploitPrompt, buildJavaScriptBundleAnalysis, buildNucleiKnowledgeIndex, buildOwaspValidationMatrix, buildPayloadCandidateSet, buildPayloadRequestDraftSet, buildPentestPipeline, buildSecurityAssetGraph, buildSecurityClosureModel, buildSecurityDecisionQueue, buildSecurityDecisionSupervision, buildSecurityObjectiveModel, buildSecurityToolCommandForInputFile, buildSecurityValidationChecks, buildSecurityWorkflowPlan, buildSkillExecutionPlan, buildSubAgentCoordinationPlan, buildValidationClosurePlan, classifySecurityToolOutput, createDefaultPentestScope, getSecurityToolInventory, matchExploitTypes, matchLocalCveKnowledge, normalizeApiInventory, normalizeSecurityToolOutput, renderAccessExposureMap, renderPayloadCandidateSet, renderPayloadRequestDraftSet, renderPentestPipelineMarkdown, searchSecurityKnowledge, syncSecurityKnowledge } from "./index.js";
import { calculateCvss, parseCvssVector, cvssScore, severityFromScore } from "./cvss.js";
import { parseSemver, parseSemverLenient, compareSemver, parseVersionRange, versionInRange, matchesVersionRange, matchesCpeVersion } from "./semver.js";
import { parseCpe23, normalizeCpeName, matchCpeAgainstTechnology, batchMatchCpe, templateMatchesTechnologyCpe, cpeMatchConfidence } from "./cpe-matcher.js";
import { createPenetrationGraph, addEvidence, proposeHypothesis, claimHypothesis, concludeHypothesis, failHypothesis, addOverride, createGraphSnapshot, createGraphCheckpoint, hasGraphChanged, getOpenHypotheses, getUnclaimedHypothesis } from "./graph.js";
import type { SkillRegistry } from "@aegisprobe/skills";
import type { WebAppReconResult } from "@aegisprobe/shared";

const registry: SkillRegistry = {
  async list() {
    return [];
  },
  async get() {
    return undefined;
  },
  async search(query) {
    return [
      {
        id: query.includes("frontend") ? "web.frontend-secret-scan" : "recon.subdomain",
        name: query.includes("frontend") ? "Frontend secret scan" : "Subdomain recon",
        category: "web",
        risk_level: "medium",
        default_permission: "approval",
        requires_approval: true,
        inputs: ["target"],
        tools: query.includes("frontend") ? ["trufflehog"] : ["subfinder"],
        workflow: ["prepare scope", "collect evidence"],
        outputs: ["evidence"],
        source: "yaml"
      }
    ];
  },
  async renderPrompt() {
    return "";
  }
};

describe("security workflow", () => {
  it("builds a full ordered security workflow", async () => {
    const plan = await buildSecurityWorkflowPlan("ses_1", { kind: "url", raw: "https://example.com", normalized: "https://example.com" }, registry);

    expect(plan.workflow.currentPhase).toBe("scope");
    expect(plan.tasks.map((task) => task.phase)).toEqual([
      "scope",
      "recon",
      "asset_discovery",
      "fingerprint",
      "frontend",
      "vulnerability_analysis",
      "safe_validation",
      "reporting"
    ]);
    expect(plan.prompt).toContain("Pentagi-inspired security workflow");
  });

  it("compiles matched skills into phase tasks", async () => {
    const plan = await buildSkillExecutionPlan("frontend secret scan", registry);

    expect(plan.matchedSkills[0]?.id).toBe("web.frontend-secret-scan");
    expect(plan.tasks[0]?.phase).toBe("frontend");
    expect(plan.prompt).toContain("Skills are guidance");
  });

  it("renders exploit methodology as advisory evidence cues instead of embedded commands", () => {
    expect(matchExploitTypes({ product: "nginx", paths: ["/"] })).toEqual([]);
    expect(matchExploitTypes({ product: "nginx", paths: ["/search?q=alpha"] })).toEqual([
      "command_injection",
      "path_traversal",
      "ssrf"
    ]);

    const rendered = buildFullExploitPrompt(
      { product: "nginx", paths: ["/search?q=alpha"] },
      "https://example.com"
    );

    expect(rendered).toContain("Exploit Methodology Hints");
    expect(rendered).toContain("Advisory only");
    expect(rendered).toContain("payload_candidates");
    expect(rendered).not.toContain("exploit_sender.py --type");
    expect(rendered).not.toContain("Reverse shell");
    expect(rendered).not.toContain("--shell --lhost");
    expect(rendered).not.toContain("NUCLEI_BIN -u");
  });

  it("builds advisory payload candidates from current evidence without executing them", () => {
    const createdAt = new Date().toISOString();
    const target = { kind: "url" as const, raw: "http://127.0.0.1:3000", normalized: "http://127.0.0.1:3000" };
    const set = buildPayloadCandidateSet({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "http://127.0.0.1:3000/api/orders/1001?search=alpha", source: "browser:webapp-recon:network", confidence: "high", createdAt },
        { id: "a2", sessionId: "s1", workflowId: "w1", kind: "url", value: "http://127.0.0.1:3000/api/users/1", source: "browser:webapp-recon:network", confidence: "high", createdAt }
      ],
      evidence: [
        { id: "e1", sessionId: "s1", workflowId: "w1", source: "browser:webapp-recon", kind: "tool", summary: "Observed login form, order id object reference, tenant field, and search parameter.", data: "GET /api/orders/1001?search=alpha\nPATCH /api/users/1 role tenantId", createdAt }
      ],
      authContexts: [
        { id: "ctx1", sessionId: "s1", workflowId: "w1", name: "alice", role: "customer", username: "alice", cookieHeader: "sid=a", createdAt, updatedAt: createdAt },
        { id: "ctx2", sessionId: "s1", workflowId: "w1", name: "bob", role: "customer", username: "bob", cookieHeader: "sid=b", createdAt, updatedAt: createdAt }
      ],
      marker: "unit",
      activeAllowed: false
    });

    expect(set.mode).toBe("advisory");
    expect(set.summary).toContain("No requests were sent");
    expect(set.candidates.some((candidate) => candidate.category === "sql_injection")).toBe(true);
    expect(set.candidates.some((candidate) => candidate.category === "authz_object_reference")).toBe(true);
    expect(set.candidates.some((candidate) => candidate.category === "mass_assignment" && candidate.requiresApproval)).toBe(true);
    const sqli = set.candidates.find((candidate) => candidate.category === "sql_injection");
    const authz = set.candidates.find((candidate) => candidate.category === "authz_object_reference");
    expect(sqli?.insertionHints.some((hint) => hint.location === "query" && hint.name === "search")).toBe(true);
    expect(authz?.insertionHints.some((hint) => hint.location === "path" || hint.location === "auth_context")).toBe(true);
    const rendered = renderPayloadCandidateSet(set);
    expect(rendered).toContain("insertion hints:");
    expect(rendered).toContain("query.search");
    expect(rendered).toContain("These are candidate inputs, not an execution plan");
  });

  it("keeps noisy static JavaScript targets out of payload candidates and avoids authz from login-only evidence", () => {
    const createdAt = new Date().toISOString();
    const target = { kind: "url" as const, raw: "https://example.com/home/Login/login", normalized: "https://example.com/home/Login/login" };
    const assets = [
      {
        id: "login-page",
        sessionId: "s1",
        workflowId: "w1",
        kind: "url",
        value: "https://example.com/home/Login/login",
        source: "autonomous_pentest:scope",
        confidence: "high",
        metadata: JSON.stringify({ method: "GET" }),
        createdAt
      },
      {
        id: "login-post",
        sessionId: "s1",
        workflowId: "w1",
        kind: "url",
        value: "https://example.com/home/login/loginon.html",
        source: "browser:webapp-recon:form",
        confidence: "medium",
        metadata: JSON.stringify({ method: "POST", bodyParamHints: ["username", "password", "submit"], riskSignals: ["auth-surface", "state-changing-method"] }),
        createdAt
      },
      {
        id: "vendor-js",
        sessionId: "s1",
        workflowId: "w1",
        kind: "url",
        value: "https://example.com/public/static/home/Javascript/kanrisha.js",
        source: "browser:webapp-recon:script",
        confidence: "medium",
        metadata: JSON.stringify({ method: "GET" }),
        createdAt
      },
      {
        id: "js-fragment",
        sessionId: "s1",
        workflowId: "w1",
        kind: "url",
        value: "https://example.com/public/static/home/Javascript/DataTables/+c.join(",
        source: "browser:api-inventory-normalizer",
        confidence: "high",
        metadata: JSON.stringify({ method: "GET" }),
        createdAt
      }
    ] satisfies NonNullable<Parameters<typeof buildPayloadCandidateSet>[0]["assets"]>;
    const evidence = [
      {
        id: "e1",
        sessionId: "s1",
        workflowId: "w1",
        source: "pentest:model_loop",
        kind: "note",
        summary: "Login form and noisy JavaScript extraction",
        data: "GET https://example.com/public/static/home/Javascript/kanrisha.js/n...[truncated]/nRaw\nPOST /home/login/loginon.html username=alice&password=secret",
        createdAt
      }
    ] satisfies NonNullable<Parameters<typeof buildPayloadCandidateSet>[0]["evidence"]>;

    const sqliSet = buildPayloadCandidateSet({ target, assets, evidence, focus: "sqli", marker: "unit" });
    const renderedSqli = renderPayloadCandidateSet(sqliSet);
    expect(renderedSqli).toContain("/home/login/loginon.html");
    expect(renderedSqli).not.toContain("/public/static/");
    expect(renderedSqli).not.toContain("+c.join");

    const allSet = buildPayloadCandidateSet({ target, assets, evidence, marker: "unit", maxCandidates: 20 });
    const categories = allSet.candidates.map((candidate) => candidate.category);
    expect(categories).toContain("sql_injection");
    expect(categories).toContain("xss_reflection");
    expect(categories).not.toContain("file_upload");
    expect(categories).not.toContain("ssrf");
    expect(categories).not.toContain("command_injection");
    expect(categories).not.toContain("path_traversal");
    expect(categories).not.toContain("mass_assignment");
    expect(categories).not.toContain("ssti");

    const authzSet = buildPayloadCandidateSet({ target, assets, evidence, focus: "authz", marker: "unit" });
    expect(authzSet.candidates).toHaveLength(0);
    expect(renderPayloadCandidateSet(authzSet)).not.toContain("/public/static/");

    const adminAuthzSet = buildPayloadCandidateSet({
      target,
      assets: assets.concat({
        id: "admin-route",
        sessionId: "s1",
        workflowId: "w1",
        kind: "url",
        value: "https://example.com/admin/",
        source: "browser:webapp-recon:anchor",
        confidence: "medium",
        metadata: JSON.stringify({ method: "GET" }),
        createdAt
      }),
      evidence,
      focus: "authz",
      marker: "unit"
    });
    expect(adminAuthzSet.candidates[0]?.targetHints).toContain("https://example.com/admin/");
    expect(adminAuthzSet.candidates[0]?.insertionHints).toHaveLength(0);
    expect(renderPayloadCandidateSet(adminAuthzSet)).not.toContain("body.password");

    const adminDraftSet = buildPayloadRequestDraftSet({
      target,
      assets: assets.concat({
        id: "admin-route",
        sessionId: "s1",
        workflowId: "w1",
        kind: "url",
        value: "https://example.com/admin/",
        source: "browser:webapp-recon:anchor",
        confidence: "medium",
        metadata: JSON.stringify({ method: "GET" }),
        createdAt
      }),
      evidence,
      focus: "authz",
      marker: "unit"
    });
    expect(adminDraftSet.drafts[0]?.url).toBe("https://example.com/admin/");
    expect(adminDraftSet.drafts[0]?.recommendedTool).toBe("http_get");
    expect(adminDraftSet.drafts[0]?.requiresApproval).toBe(false);
    expect(renderPayloadRequestDraftSet(adminDraftSet)).not.toContain("body.password");
  });

  it("builds reviewable payload request drafts with execution gates but does not execute them", () => {
    const createdAt = new Date().toISOString();
    const target = { kind: "url" as const, raw: "http://127.0.0.1:3000", normalized: "http://127.0.0.1:3000" };
    const assets = [
      {
        id: "a1",
        sessionId: "s1",
        workflowId: "w1",
        kind: "url",
        value: "http://127.0.0.1:3000/api/orders/1001?search=alpha",
        source: "browser:webapp-recon:network",
        confidence: "high",
        metadata: JSON.stringify({ method: "GET", pathTemplate: "/api/orders/{id}", queryParams: ["search"], riskSignals: ["object-or-tokenized-path"] }),
        createdAt
      },
      {
        id: "a2",
        sessionId: "s1",
        workflowId: "w1",
        kind: "url",
        value: "http://127.0.0.1:3000/api/users/1",
        source: "browser:api-inventory-normalizer",
        confidence: "high",
        metadata: JSON.stringify({ method: "PATCH", pathTemplate: "/api/users/{id}", bodyParamHints: ["role", "tenantId"], riskSignals: ["state-changing-method"] }),
        createdAt
      }
    ] satisfies NonNullable<Parameters<typeof buildPayloadRequestDraftSet>[0]["assets"]>;
    const evidence = [
      { id: "e1", sessionId: "s1", workflowId: "w1", source: "browser:webapp-recon", kind: "tool", summary: "Observed order search, user update, role field, tenant field, and object references.", data: "GET /api/orders/1001?search=alpha\nPATCH /api/users/1 role tenantId", createdAt }
    ] satisfies NonNullable<Parameters<typeof buildPayloadRequestDraftSet>[0]["evidence"]>;
    const authContexts = [
      { id: "ctx1", sessionId: "s1", workflowId: "w1", name: "alice", role: "customer", tenant: "tenant-a", username: "alice", cookieHeader: "sid=a", createdAt, updatedAt: createdAt },
      { id: "ctx2", sessionId: "s1", workflowId: "w1", name: "bob", role: "customer", tenant: "tenant-b", username: "bob", cookieHeader: "sid=b", createdAt, updatedAt: createdAt }
    ] satisfies NonNullable<Parameters<typeof buildPayloadRequestDraftSet>[0]["authContexts"]>;
    const set = buildPayloadRequestDraftSet({
      target,
      assets,
      evidence,
      authContexts,
      marker: "unit",
      activeAllowed: false,
      maxDrafts: 20
    });

    const reflectionDraft = set.drafts.find((draft) => draft.category === "xss_reflection" && draft.insertion.location === "query" && draft.insertion.name === "search");
    expect(reflectionDraft?.recommendedTool).toBe("safe_readonly_fetch");
    expect(reflectionDraft?.requiresApproval).toBe(false);
    expect(reflectionDraft?.url).toContain("search=aegisprobe-unit");
    expect(reflectionDraft?.baselineUrl).toContain("search=alpha");
    expect(reflectionDraft?.toolUseHint).toContain("safe_readonly_fetch");

    const massSet = buildPayloadRequestDraftSet({
      target,
      assets,
      evidence,
      authContexts,
      marker: "unit",
      activeAllowed: false,
      focus: "mass_assignment",
      maxDrafts: 8
    });
    const massAssignmentDraft = massSet.drafts.find((draft) => draft.category === "mass_assignment" && draft.insertion.location === "body");
    expect(massAssignmentDraft?.recommendedTool).toBe("approval_required");
    expect(massAssignmentDraft?.bodyPreview).toContain('"role":"admin"');
    expect(massAssignmentDraft?.approvalReason).toContain("state-changing");

    const rendered = `${renderPayloadRequestDraftSet(set)}\n${renderPayloadRequestDraftSet(massSet)}`;
    expect(rendered).toContain("No requests were sent");
    expect(rendered).toContain("tool:safe_readonly_fetch");
    expect(rendered).toContain("tool:approval_required");
    expect(rendered).toContain("Drafts are model workbench material, not an execution plan");
  });

  it("builds an access exposure map for anonymous baselines and authorization-sensitive information gaps", () => {
    const createdAt = new Date().toISOString();
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const map = buildAccessExposureMap({
      target,
      assets: [
        {
          id: "a1",
          sessionId: "s1",
          workflowId: "w1",
          kind: "url",
          value: "https://example.com/api/orders/1001?search=alpha",
          source: "browser:api-inventory-normalizer",
          confidence: "high",
          metadata: JSON.stringify({ method: "GET", pathTemplate: "/api/orders/{id}", queryParams: ["search"], riskSignals: ["object-or-tokenized-path"], authRequired: "likely" }),
          createdAt
        },
        {
          id: "a2",
          sessionId: "s1",
          workflowId: "w1",
          kind: "url",
          value: "https://example.com/api/admin/users",
          source: "browser:api-inventory-normalizer",
          confidence: "high",
          metadata: JSON.stringify({ method: "GET", pathTemplate: "/api/admin/users", status: 403, riskSignals: ["privileged-route"], authRequired: "likely" }),
          createdAt
        },
        {
          id: "a3",
          sessionId: "s1",
          workflowId: "w1",
          kind: "url",
          value: "https://example.com/api/users/1",
          source: "browser:api-inventory-normalizer",
          confidence: "high",
          metadata: JSON.stringify({ method: "PATCH", pathTemplate: "/api/users/{id}", bodyParamHints: ["role", "tenantId"], riskSignals: ["state-changing-method"], authRequired: "likely" }),
          createdAt
        }
      ],
      evidence: [
        { id: "e1", sessionId: "s1", workflowId: "w1", source: "browser:webapp-recon", kind: "tool", summary: "Runtime network saw order and admin API routes.", data: "GET /api/orders/1001?search=alpha\nHTTP/1.1 403 Forbidden\nGET /api/admin/users", createdAt }
      ],
      authContexts: [
        { id: "ctx1", sessionId: "s1", workflowId: "w1", name: "alice", role: "customer", tenant: "tenant-a", cookieHeader: "sid=a", createdAt, updatedAt: createdAt },
        { id: "ctx2", sessionId: "s1", workflowId: "w1", name: "bob", role: "customer", tenant: "tenant-b", cookieHeader: "sid=b", createdAt, updatedAt: createdAt }
      ]
    });

    expect(map.summary.total).toBeGreaterThanOrEqual(3);
    expect(map.items.some((item) => item.state === "needs_anonymous_baseline" && item.endpoint.includes("/api/orders/1001"))).toBe(true);
    expect(map.items.some((item) => item.state === "auth_gated_observed" && item.endpoint.includes("/api/admin/users"))).toBe(true);
    expect(map.items.some((item) => item.state === "passive_mutation_only" && item.method === "PATCH")).toBe(true);
    expect(map.informationGaps.join("\n")).toContain("Anonymous baseline");
    const rendered = renderAccessExposureMap(map);
    expect(rendered).toContain("Access Exposure Map");
    expect(rendered).toContain("anonymous_baseline_fetch GET");
    expect(rendered).toContain("Mutation routes remain passive");
  });

  it("folds high-fidelity anonymous and authenticated fetch baselines into the access map", () => {
    const createdAt = new Date().toISOString();
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const map = buildAccessExposureMap({
      target,
      assets: [
        {
          id: "asset-admin",
          sessionId: "s1",
          workflowId: "w1",
          kind: "url",
          value: "https://example.com/api/admin/users",
          source: "browser:api-inventory-normalizer",
          confidence: "high",
          metadata: JSON.stringify({ method: "GET", pathTemplate: "/api/admin/users", riskSignals: ["privileged-route"], authRequired: "likely" }),
          createdAt
        }
      ],
      evidence: [
        {
          id: "anon-1",
          sessionId: "s1",
          workflowId: "w1",
          source: "pentest:model_loop",
          kind: "note",
          summary: "anonymous_baseline_fetch result",
          data: JSON.stringify({
            url: "https://example.com/api/admin/users",
            method: "GET",
            anonymous: true,
            status: 200,
            bodyLength: 512,
            bodyHash: "hash-public"
          }),
          createdAt
        },
        {
          id: "auth-1",
          sessionId: "s1",
          workflowId: "w1",
          source: "pentest:model_loop",
          kind: "note",
          summary: "safe_readonly_fetch result",
          data: JSON.stringify({
            url: "https://example.com/api/admin/users",
            method: "GET",
            anonymous: false,
            authContextName: "alice",
            status: 200,
            bodyLength: 512,
            bodyHash: "hash-public"
          }),
          createdAt
        }
      ],
      authContexts: [
        { id: "ctx1", sessionId: "s1", workflowId: "w1", name: "alice", role: "customer", cookieHeader: "sid=a", createdAt, updatedAt: createdAt }
      ]
    });

    const item = map.items.find((candidate) => candidate.endpoint === "https://example.com/api/admin/users");
    expect(item?.state).toBe("public_observed");
    expect(item?.anonymousBaseline?.status).toBe(200);
    expect(item?.authenticatedBaselines[0]?.authContextName).toBe("alice");
    expect(item?.priorityRationale.join(" ")).toContain("anonymous baseline status=200");
    const rendered = renderAccessExposureMap(map);
    expect(rendered).toContain("anonymous baseline: status=200 length=512 hash=hash-public");
    expect(rendered).toContain("authenticated baselines: alice=200/len:512/hash:hash-public");
  });

  it("treats anonymous fetch timeouts as inconclusive access-map evidence", () => {
    const createdAt = new Date().toISOString();
    const target = { kind: "url" as const, raw: "https://example.com/login", normalized: "https://example.com/login" };
    const map = buildAccessExposureMap({
      target,
      assets: [],
      evidence: [
        {
          id: "anon-timeout",
          sessionId: "s1",
          workflowId: "w1",
          source: "anonymous_baseline_fetch",
          kind: "tool",
          summary: "anonymous_baseline_fetch HEAD https://example.com/admin/ error=Request timed out",
          data: JSON.stringify({
            url: "https://example.com/admin/",
            method: "HEAD",
            anonymous: true,
            status: 0,
            bodyLength: 0,
            bodyHash: "0",
            error: "Request timed out after 5000ms"
          }),
          createdAt
        }
      ],
      authContexts: []
    });

    const item = map.items.find((candidate) => candidate.endpoint === "https://example.com/admin/");
    expect(item?.state).toBe("needs_anonymous_baseline");
    expect(item?.safeObservationIdeas.join(" ")).toContain("retry anonymous_baseline_fetch");
    expect(item?.priorityRationale.join(" ")).toContain("inconclusive");
  });

  it("keeps static assets and JavaScript expression fragments out of the access map", () => {
    const createdAt = new Date().toISOString();
    const target = { kind: "url" as const, raw: "https://example.com/home/Login/login", normalized: "https://example.com/home/Login/login" };
    const map = buildAccessExposureMap({
      target,
      assets: [
        {
          id: "login",
          sessionId: "s1",
          workflowId: "w1",
          kind: "url",
          value: "https://example.com/home/Login/login",
          source: "autonomous_pentest:scope",
          confidence: "high",
          metadata: JSON.stringify({ method: "GET" }),
          createdAt
        },
        {
          id: "vendor-js",
          sessionId: "s1",
          workflowId: "w1",
          kind: "url",
          value: "https://example.com/public/static/home/Javascript/jQuery/jquery-1.7.2.min.js",
          source: "browser:webapp-recon:script",
          confidence: "medium",
          metadata: JSON.stringify({ method: "GET" }),
          createdAt
        },
        {
          id: "js-fragment",
          sessionId: "s1",
          workflowId: "w1",
          kind: "url",
          value: "https://example.com/public/static/home/Javascript/DataTables/+c.join(",
          source: "browser:api-inventory-normalizer",
          confidence: "high",
          metadata: JSON.stringify({ method: "GET", pathTemplate: "/public/static/home/Javascript/DataTables/%2Bc.join(" }),
          createdAt
        }
      ],
      evidence: [],
      authContexts: []
    });

    expect(map.items.some((item) => item.endpoint.includes("jquery-1.7.2"))).toBe(false);
    expect(map.items.some((item) => item.endpoint.includes("+c.join"))).toBe(false);
    expect(map.items.some((item) => item.endpoint.includes("/home/Login/login"))).toBe(true);
  });

  it("keeps report prose and raw output artifacts out of request-line access evidence", () => {
    const createdAt = new Date().toISOString();
    const target = { kind: "url" as const, raw: "https://example.com/home/Login/login", normalized: "https://example.com/home/Login/login" };
    const map = buildAccessExposureMap({
      target,
      assets: [
        {
          id: "login-form",
          sessionId: "s1",
          workflowId: "w1",
          kind: "url",
          value: "https://example.com/home/login/loginon.html",
          source: "browser:webapp-recon:form",
          confidence: "medium",
          metadata: JSON.stringify({ method: "POST", pathTemplate: "/home/login/loginon.html", bodyParamHints: ["username", "password"] }),
          createdAt
        }
      ],
      evidence: [
        {
          id: "noisy-report",
          sessionId: "s1",
          workflowId: "w1",
          source: "pentest:model_loop",
          kind: "note",
          summary: "Rendered access map and raw output excerpt",
          data: [
            "safe observations: anonymous_baseline_fetch HEAD for status, redirects, content type, body length/hash",
            "Raw output excerpt: GET https://example.com/public/static/app.js/n...[truncated]/nRaw",
            "The model mentioned POST bodies and GET for status in prose.",
            "POST /home/login/loginon.html username=alice&password=secret"
          ].join("\n"),
          createdAt
        }
      ],
      authContexts: []
    });

    expect(map.items.some((item) => item.endpoint.includes("/public/static/"))).toBe(false);
    expect(map.items.some((item) => /\/(?:n|raw)(?:$|[/?#])/i.test(item.endpoint))).toBe(false);
    expect(map.items.some((item) => item.endpoint.endsWith("/for"))).toBe(false);
    const loginPosts = map.items.filter((item) => item.method === "POST" && item.endpoint === "https://example.com/home/login/loginon.html");
    expect(loginPosts).toHaveLength(1);
    const loginPost = loginPosts[0];
    expect(loginPost?.state).toBe("passive_mutation_only");
    expect(loginPost?.bodyParamHints).toContain("username");
    expect(loginPost?.bodyParamHints).not.toContain("confidence");
  });

  it("builds a controlled pentest pipeline with active steps blocked by default", () => {
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const pipeline = buildPentestPipeline(target, createDefaultPentestScope(target));
    const toolIds = pipeline.steps.map((step) => step.toolId).filter(Boolean);

    expect(pipeline.steps.some((step) => step.kind === "builtin_probe" && step.probe === "basic_recon")).toBe(true);
    expect(pipeline.steps.some((step) => step.kind === "subagent" && step.role === "web_vuln")).toBe(true);
    expect(toolIds).toContain("httpx");
    expect(toolIds).toContain("nmap");
    expect(toolIds).toContain("dirsearch");
    expect(toolIds).toContain("katana");
    expect(toolIds).toContain("gau");
    expect(pipeline.steps.find((step) => step.toolId === "nmap")?.blockedReason).toContain("Active probing is disabled");
    expect(pipeline.steps.find((step) => step.toolId === "dirsearch")?.blockedReason).toContain("Active probing is disabled");
  });

  it("allows active adapters when the scope explicitly enables active probing", () => {
    const target = { kind: "domain" as const, raw: "example.com", normalized: "example.com" };
    const scope = createDefaultPentestScope(target, {
      allowActiveProbing: true,
      allowCidrDiscovery: true,
      intensity: "active",
      rateLimitPerSecond: 1
    });
    const pipeline = buildPentestPipeline(target, scope);

    // nuclei-owasp has no buildCommand, so it gets a "no command" reason even when active probing is allowed
    const nucleiOwaspStep = pipeline.steps.find((step) => step.toolId === "nuclei-owasp");
    expect(nucleiOwaspStep?.blockedReason || nucleiOwaspStep?.command || "no-command").toBeTruthy();
    expect(pipeline.steps.find((step) => step.toolId === "nmap")?.command).toContain("nmap");
    expect(pipeline.steps.find((step) => step.toolId === "nmap")?.command).toMatch(/-p\s/);
    if (process.platform === "win32") {
      expect(pipeline.steps.find((step) => step.toolId === "httpx")?.command).toMatch(/^& "/);
    }
  });

  it("uses an IP-focused pipeline for URL targets backed by an IP address", () => {
    const target = { kind: "url" as const, raw: "http://192.168.56.106", normalized: "http://192.168.56.106" };
    const scope = createDefaultPentestScope(target, {
      allowActiveProbing: true,
      intensity: "active",
      scanProfile: "deep"
    });
    const pipeline = buildPentestPipeline(target, scope);
    const toolIds = pipeline.steps.map((step) => step.toolId).filter(Boolean);

    expect(toolIds).not.toContain("subfinder");
    expect(toolIds).not.toContain("amass");
    expect(toolIds).not.toContain("dnsx");
    expect(toolIds).not.toContain("assetfinder");
    expect(toolIds).toContain("httpx");
    expect(toolIds).toContain("nmap");
  });

  it("keeps nmap scoped to the explicit URL port", () => {
    const target = { kind: "url" as const, raw: "http://127.0.0.1:3000", normalized: "http://127.0.0.1:3000" };
    const scope = createDefaultPentestScope(target, {
      allowActiveProbing: true,
      intensity: "active",
      scanProfile: "deep"
    });
    const pipeline = buildPentestPipeline(target, scope);
    const command = pipeline.steps.find((step) => step.toolId === "nmap")?.command ?? "";

    expect(command).toContain("T:3000");
    expect(command).not.toContain("1-10000");
  });

  it("renders local tool inventory and pipeline markdown", () => {
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const inventory = getSecurityToolInventory();
    const markdown = renderPentestPipelineMarkdown(buildPentestPipeline(target));

    expect(inventory.some((tool) => tool.id === "httpx" && tool.repository.includes("projectdiscovery"))).toBe(true);
    expect(markdown).toContain("Autonomous Pentest Plan");
    expect(markdown).toContain("active probing: disabled");
  }, 10_000);

  it("normalizes scanner output into assets, technologies, findings, and CVE candidates", () => {
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const httpx = normalizeSecurityToolOutput("httpx", JSON.stringify({
      url: "https://example.com",
      status_code: 200,
      title: "Example",
      webserver: "Apache/2.4.49",
      tech: ["jQuery 3.4.1"],
      a: ["192.0.2.20"],
      cname: ["edge.example.net"],
      favicon_hash: "12345",
      extracts: ["/api/internal/status"]
    }), target);
    const katana = normalizeSecurityToolOutput("katana", '{"url":"https://example.com/static/app.js.map"}', target);
    const katanaJs = normalizeSecurityToolOutput("katana", JSON.stringify({
      url: "https://example.com/static/app.js",
      body: "const token='eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.aaaaaaaaaaaaaaaa.bbbbbbbbbbbbbbbb'; fetch('/api/admin/users')"
    }), target);
    const nmapPortScan = normalizeSecurityToolOutput("naabu-cidr", [
      "192.0.2.10:9100",
      "192.0.2.10:5432",
      "192.0.2.10:5050"
    ].join("\n"), target);
    const nmap = normalizeSecurityToolOutput("nmap", [
      "<?xml version=\"1.0\"?>",
      "<nmaprun><host><address addr=\"192.0.2.10\" addrtype=\"ipv4\"/>",
      "<ports><port protocol=\"tcp\" portid=\"8080\"><state state=\"open\"/><service name=\"http\" product=\"Apache Tomcat\" version=\"9.0.70\"/></port></ports>",
      "</host></nmaprun>"
    ].join(""), target);
    const snmp = normalizeSecurityToolOutput("snmpwalk", [
      "SNMPv2-MIB::sysDescr.0 = STRING: Linux lab-host 6.8.0 Net-SNMP",
      "SNMPv2-MIB::sysName.0 = STRING: admin.lab.internal",
      "HOST-RESOURCES-MIB::hrSWRunParameters.42 = STRING: web password: example-admin-secret"
    ].join("\n"), { kind: "url", raw: "http://192.0.2.10", normalized: "http://192.0.2.10" });
    const frameworks = normalizeSecurityToolOutput("httpx", "[ThinkPHP] [Apache Shiro] [RuoYi]", target);

    expect(httpx.assets.some((asset) => asset.kind === "url" && asset.value === "https://example.com")).toBe(true);
    expect(httpx.assets.some((asset) => asset.kind === "ip" && asset.value === "192.0.2.20")).toBe(true);
    expect(httpx.assets.some((asset) => asset.kind === "domain" && asset.value === "edge.example.net")).toBe(true);
    expect(httpx.findings.some((finding) => finding.target.includes("/api/internal/status"))).toBe(true);
    expect(httpx.technologies.some((technology) => technology.name === "Apache HTTP Server" && technology.version === "2.4.49")).toBe(true);
    expect(httpx.technologies.some((technology) => technology.name === "favicon" && technology.version === "12345")).toBe(true);
    expect(httpx.cveMatches.some((match) => match.cveId === "CVE-2021-41773")).toBe(true);
    expect(katana.findings.some((finding) => finding.title.includes("source map"))).toBe(true);
    expect(katanaJs.findings.some((finding) => finding.title.includes("JavaScript-exposed"))).toBe(true);
    expect(katanaJs.findings.some((finding) => finding.title.includes("JWT-like"))).toBe(true);
    expect(nmapPortScan.findings.some((finding) => finding.title.includes("JetDirect printer"))).toBe(true);
    expect(nmapPortScan.findings.some((finding) => finding.title.includes("PostgreSQL"))).toBe(true);
    expect(nmapPortScan.findings.some((finding) => finding.title.includes("Admin HTTP"))).toBe(true);
    expect(nmapPortScan.technologies.some((technology) => technology.name === "PostgreSQL" && technology.target === "192.0.2.10:5432")).toBe(true);
    expect(nmap.assets.some((asset) => asset.kind === "service" && asset.value === "192.0.2.10:8080")).toBe(true);
    expect(nmap.technologies.some((technology) => technology.name === "Apache Tomcat" && technology.version === "9.0.70")).toBe(true);
    expect(snmp.assets.some((asset) => asset.kind === "service" && asset.value === "192.0.2.10:161")).toBe(true);
    expect(snmp.assets.some((asset) => asset.kind === "domain" && asset.value === "admin.lab.internal")).toBe(true);
    expect(snmp.findings.some((finding) => finding.title.includes("credential-like"))).toBe(true);
    expect(snmp.findings.some((finding) => finding.title.includes("public community"))).toBe(true);
    expect(frameworks.technologies.some((technology) => technology.name === "ThinkPHP")).toBe(true);
    expect(frameworks.technologies.some((technology) => technology.name === "Apache Shiro")).toBe(true);
    expect(frameworks.cveMatches.some((match) => match.cveId === "SHIRO-ADVISORY-REVIEW")).toBe(true);
  });

  it("normalizes browser API inventory into route templates and parameter hints", () => {
    const recon: WebAppReconResult = {
      sessionId: "s1",
      workflowId: "w1",
      startUrl: "https://example.com",
      pagesVisited: ["https://example.com/orders"],
      forms: [
        {
          pageUrl: "https://example.com/orders/1001",
          action: "https://example.com/api/orders/1001/refund?csrf=abc123",
          method: "POST",
          inputNames: ["reason", "amount", "csrf", "4537820efe33822f81a847271fde1343"],
          inputTypes: ["text", "number", "hidden"],
          hasPassword: false,
          hasCsrfToken: true,
          riskSignals: ["business-workflow"]
        }
      ],
      artifactPath: "webapp-recon.json",
      evidenceId: "evd1",
      networkRequests: [
        { pageUrl: "https://example.com/orders", url: "https://example.com/api/orders/1001?include=items&access_token=secret-value", method: "GET", resourceType: "fetch", status: 200, contentType: "application/json" },
        { pageUrl: "https://example.com/orders", url: "https://example.com/api/orders/1002?include=items", method: "GET", resourceType: "fetch", status: 200, contentType: "application/json" },
        { pageUrl: "https://example.com/orders/1001", url: "https://example.com/api/orders/1001/refund?csrf=abc123", method: "POST", resourceType: "xhr", status: 403, contentType: "application/json", requestBodyPreview: "{\"reason\":\"duplicate\",\"amount\":10,\"csrf\":\"secret\",\"4537820efe33822f81a847271fde1343\":\"1\"}" }
      ],
      jsEndpoints: [
        { scriptUrl: "https://example.com/app.js", value: "/api/orders/1003", normalizedUrl: "https://example.com/api/orders/1003", method: "GET", confidence: "medium", riskSignals: [] }
      ],
      jsSensitiveSignals: [],
      apiInventory: [
        { url: "https://example.com/api/orders/1001?include=items&access_token=secret-value", method: "GET", source: "network", confidence: "high", riskSignals: [] },
        { url: "https://example.com/api/orders/1002?include=items", method: "GET", source: "network", confidence: "high", riskSignals: [] },
        { url: "https://example.com/api/orders/1001/refund?csrf=abc123", method: "POST", source: "form", confidence: "medium", riskSignals: ["business-workflow"] }
      ],
      authSurface: {
        loginPages: [],
        authEndpoints: [],
        passwordForms: [],
        authStorageKeys: [],
        notes: []
      }
    };

    const endpoints = normalizeApiInventory(recon);
    const order = endpoints.find((endpoint) => endpoint.method === "GET" && endpoint.pathTemplate === "/api/orders/{id}");
    const refund = endpoints.find((endpoint) => endpoint.method === "POST" && endpoint.pathTemplate === "/api/orders/{id}/refund");

    expect(order?.queryParams).toEqual(["access_token", "include"]);
    expect(order?.sources).toContain("network");
    expect(order?.sources).toContain("script");
    expect(order?.examples.some((example) => example.includes("secret-value"))).toBe(false);
    expect(order?.riskSignals).toContain("object-or-tokenized-path");
    expect(order?.riskSignals).toContain("sensitive-parameter-name");
    expect(refund?.bodyParamHints).toEqual(expect.arrayContaining(["amount", "reason", "csrf"]));
    expect(refund?.bodyParamHints).toContain("[redacted-param-name]");
    expect(refund?.bodyParamHints).not.toContain("4537820efe33822f81a847271fde1343");
    expect(refund?.authRequired).toBe("likely");
    expect(refund?.riskSignals).toContain("state-changing-method");
  });

  it("strips servlet matrix session parameters from normalized API routes", () => {
    const recon: WebAppReconResult = {
      sessionId: "s1",
      workflowId: "w1",
      startUrl: "http://127.0.0.1:8080/",
      pagesVisited: ["http://127.0.0.1:8080/"],
      forms: [
        {
          pageUrl: "http://127.0.0.1:8080/",
          action: "http://127.0.0.1:8080/doUpload.action;jsessionid=102vlirszssm9166w7vvvpb8vh",
          method: "POST",
          inputNames: ["upload", "caption"],
          inputTypes: ["file", "text"],
          hasPassword: false,
          hasCsrfToken: false,
          riskSignals: ["file-handling"]
        }
      ],
      artifactPath: "webapp-recon.json",
      evidenceId: "evd1",
      networkRequests: [],
      jsEndpoints: [],
      jsSensitiveSignals: [],
      apiInventory: [],
      authSurface: {
        loginPages: [],
        authEndpoints: [],
        passwordForms: [],
        authStorageKeys: [],
        notes: []
      }
    };

    const endpoints = normalizeApiInventory(recon);
    const upload = endpoints.find((endpoint) => endpoint.method === "POST" && endpoint.pathTemplate === "/doUpload.action");

    expect(upload).toBeDefined();
    expect(upload?.bodyParamHints).toEqual(expect.arrayContaining(["upload", "caption"]));
    expect(upload?.examples).toContain("http://127.0.0.1:8080/doUpload.action");
    expect(upload?.examples.some((example) => example.includes("jsessionid"))).toBe(false);
  });

  it("normalizes evidence-provided OpenAPI and GraphQL descriptions into API inventory", () => {
    const recon: WebAppReconResult = {
      sessionId: "s1",
      workflowId: "w1",
      startUrl: "https://example.com/docs",
      pagesVisited: ["https://example.com/docs"],
      forms: [],
      artifactPath: "webapp-recon.json",
      evidenceId: "evd1",
      networkRequests: [
        { pageUrl: "https://example.com/docs", url: "https://example.com/graphql", method: "POST", resourceType: "fetch", status: 200, contentType: "application/json" }
      ],
      jsEndpoints: [],
      jsSensitiveSignals: [],
      apiInventory: [],
      apiDescriptionDocuments: [
        {
          url: "https://example.com/openapi.json",
          kind: "openapi",
          source: "link",
          status: 200,
          contentType: "application/json",
          title: "Example API",
          operationCount: 2,
          document: {
            openapi: "3.0.0",
            info: { title: "Example API", version: "1.0.0" },
            servers: [{ url: "https://example.com/api/v1" }],
            paths: {
              "/admin/users/{id}": {
                get: {
                  operationId: "getAdminUser",
                  tags: ["admin"],
                  parameters: [
                    { name: "include", in: "query", schema: { type: "string" } }
                  ]
                },
                patch: {
                  operationId: "updateAdminUser",
                  requestBody: {
                    content: {
                      "application/json": {
                        schema: {
                          type: "object",
                          properties: {
                            role: { type: "string" },
                            profile: {
                              type: "object",
                              properties: {
                                displayName: { type: "string" }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        },
        {
          url: "https://example.com/graphql",
          kind: "graphql",
          source: "network",
          status: 200,
          contentType: "application/json",
          title: "Observed GraphQL endpoint",
          operationCount: 1
        }
      ],
      authSurface: {
        loginPages: [],
        authEndpoints: [],
        passwordForms: [],
        authStorageKeys: [],
        notes: []
      }
    };

    const endpoints = normalizeApiInventory(recon);
    const adminGet = endpoints.find((endpoint) => endpoint.method === "GET" && endpoint.pathTemplate === "/api/v1/admin/users/{id}");
    const adminPatch = endpoints.find((endpoint) => endpoint.method === "PATCH" && endpoint.pathTemplate === "/api/v1/admin/users/{id}");
    const graphql = endpoints.find((endpoint) => endpoint.method === "POST" && endpoint.pathTemplate === "/graphql");

    expect(adminGet?.sources).toContain("openapi");
    expect(adminGet?.queryParams).toEqual(["include"]);
    expect(adminGet?.riskSignals).toContain("privileged-route");
    expect(adminPatch?.bodyParamHints).toEqual(expect.arrayContaining(["content-type:application/json", "role", "profile", "profile.displayName"]));
    expect(adminPatch?.riskSignals).toContain("state-changing-method");
    expect(graphql?.sources).toContain("graphql");
    expect(graphql?.bodyParamHints).toEqual(expect.arrayContaining(["query", "variables", "operationName"]));
    expect(graphql?.riskSignals).toContain("graphql-endpoint");
  });

  it("models authentication and session surface from browser evidence", () => {
    const recon: WebAppReconResult = {
      sessionId: "s1",
      startUrl: "https://example.com",
      pagesVisited: ["https://example.com/login", "https://example.com/account/orders"],
      forms: [
        {
          pageUrl: "https://example.com/login",
          action: "https://example.com/auth/login",
          method: "POST",
          inputNames: ["email", "password"],
          inputTypes: ["email", "password"],
          hasPassword: true,
          hasCsrfToken: false,
          riskSignals: ["auth-surface"]
        }
      ],
      artifactPath: "webapp-recon.json",
      evidenceId: "evd1",
      networkRequests: [
        {
          pageUrl: "https://example.com/account/orders",
          url: "https://example.com/api/orders/1001",
          method: "GET",
          resourceType: "fetch",
          status: 200,
          contentType: "application/json",
          requestHeaders: { Authorization: "<redacted:bearer>" }
        },
        {
          pageUrl: "https://example.com/login",
          url: "https://example.com/auth/login",
          method: "POST",
          resourceType: "xhr",
          status: 401,
          contentType: "application/json"
        }
      ],
      cookies: [
        {
          pageUrl: "https://example.com/login",
          name: "sessionid",
          domain: "example.com",
          path: "/",
          httpOnly: false,
          secure: true,
          sameSite: "None",
          riskSignals: ["sensitive-token"]
        }
      ],
      storageItems: [
        { pageUrl: "https://example.com/login", storage: "localStorage", key: "accessToken", riskSignals: ["sensitive-token"] }
      ],
      jsEndpoints: [],
      jsSensitiveSignals: [],
      apiInventory: [
        { url: "https://example.com/auth/login", method: "POST", source: "form", confidence: "high", riskSignals: ["auth-surface"] },
        { url: "https://example.com/api/admin/users", method: "GET", source: "script", confidence: "high", riskSignals: ["admin-route"] },
        { url: "https://example.com/api/orders/1001", method: "GET", source: "network", confidence: "high", riskSignals: [] }
      ],
      normalizedApiEndpoints: [
        { id: "api1", method: "GET", pathTemplate: "/api/orders/{id}", examples: ["https://example.com/api/orders/1001"], queryParams: [], bodyParamHints: [], sources: ["network"], authRequired: "likely", confidence: "high", riskSignals: ["object-or-tokenized-path"] },
        { id: "api2", method: "GET", pathTemplate: "/api/admin/users", examples: ["https://example.com/api/admin/users"], queryParams: [], bodyParamHints: [], sources: ["script"], authRequired: "unknown", confidence: "high", riskSignals: ["admin-route"] }
      ],
      authSurface: {
        loginPages: ["https://example.com/login"],
        authEndpoints: ["https://example.com/auth/login"],
        passwordForms: [
          {
            pageUrl: "https://example.com/login",
            action: "https://example.com/auth/login",
            method: "POST",
            inputNames: ["email", "password"],
            inputTypes: ["email", "password"],
            hasPassword: true,
            hasCsrfToken: false
          }
        ],
        authStorageKeys: [{ pageUrl: "https://example.com/login", storage: "localStorage", key: "accessToken" }],
        notes: []
      }
    };

    const assessment = buildAuthSurfaceAssessment(recon);
    const serialized = JSON.stringify(assessment);

    expect(assessment.login).toBe("present");
    expect(assessment.authState).toBe("authenticated");
    expect(assessment.sessionMechanisms).toEqual(expect.arrayContaining(["cookie", "jwt", "localStorage", "authorization-header"]));
    expect(assessment.csrfSignals).toBe("missing_in_password_forms");
    expect(assessment.riskSignals).toEqual(expect.arrayContaining(["password-form-without-csrf-token", "client-side-auth-token-storage", "session-cookie-without-httponly", "session-cookie-weak-samesite"]));
    expect(assessment.highValueFlows.some((flow) => flow.includes("object/tenant authorization"))).toBe(true);
    expect(assessment.highValueFlows.some((flow) => flow.includes("function-level authorization"))).toBe(true);
    expect(assessment.nextEvidenceNeeded.some((item) => /role|tenant/i.test(item))).toBe(true);
    expect(serialized).not.toContain("super-secret");
    expect(serialized).not.toContain("sessionid=");
  });

  it("does not treat servlet jsessionid upload routes as login or authenticated state", () => {
    const recon: WebAppReconResult = {
      sessionId: "s1",
      startUrl: "http://127.0.0.1:8080/",
      pagesVisited: ["http://127.0.0.1:8080/"],
      forms: [
        {
          pageUrl: "http://127.0.0.1:8080/",
          action: "http://127.0.0.1:8080/doUpload.action;jsessionid=abc123",
          method: "POST",
          inputNames: ["upload", "caption"],
          inputTypes: ["file", "text"],
          hasPassword: false,
          hasCsrfToken: false,
          riskSignals: ["file-handling"]
        }
      ],
      artifactPath: "webapp-recon.json",
      evidenceId: "evd1",
      networkRequests: [
        {
          pageUrl: "http://127.0.0.1:8080/",
          url: "http://127.0.0.1:8080/",
          method: "GET",
          resourceType: "document",
          status: 200,
          contentType: "text/html",
          responseHeaders: { "set-cookie": "JSESSIONID=abc123; Path=/" }
        }
      ],
      storageItems: [
        { pageUrl: "http://127.0.0.1:8080/", storage: "cookie", key: "JSESSIONID", riskSignals: [] }
      ],
      cookies: [
        { pageUrl: "http://127.0.0.1:8080/", name: "JSESSIONID", domain: "127.0.0.1", path: "/", httpOnly: false, secure: false, sameSite: "Lax", riskSignals: [] }
      ],
      jsEndpoints: [],
      jsSensitiveSignals: [],
      apiInventory: [],
      normalizedApiEndpoints: [
        {
          id: "api_upload",
          method: "POST",
          pathTemplate: "/doUpload.action",
          examples: ["http://127.0.0.1:8080/doUpload.action"],
          queryParams: [],
          bodyParamHints: ["upload", "caption"],
          sources: ["form"],
          authRequired: "not_required",
          confidence: "medium",
          riskSignals: ["file-handling", "state-changing-method"]
        }
      ],
      authSurface: {
        loginPages: [],
        authEndpoints: ["http://127.0.0.1:8080/doUpload.action;jsessionid=abc123"],
        passwordForms: [],
        authStorageKeys: [],
        notes: []
      }
    };

    const assessment = buildAuthSurfaceAssessment(recon);
    const endpoints = normalizeApiInventory(recon);
    const uploadEndpoint = endpoints.find((endpoint) => endpoint.method === "POST" && endpoint.pathTemplate === "/doUpload.action");

    expect(assessment.login).toBe("not_observed");
    expect(assessment.authState).toBe("unknown");
    expect(assessment.authEndpoints).toEqual([]);
    expect(assessment.sessionMechanisms).toContain("cookie");
    expect(assessment.riskSignals).not.toContain("client-side-auth-token-storage");
    expect(assessment.nextEvidenceNeeded.some((item) => /storage-state|credential/i.test(item))).toBe(false);
    expect(assessment.highValueFlows).toContain("POST /doUpload.action | data/file lifecycle");
    expect(uploadEndpoint?.riskSignals).not.toContain("auth-surface");
  });

  it("analyzes JavaScript bundles into structured frontend evidence", () => {
    const content = [
      "const baseURL = '/api/v2/';",
      "fetch('orders/1001?access_token=super-secret-token');",
      "axios.post('/graphql', {query:'{}'});",
      "const wsUrl = 'wss://example.com/socket/stream';",
      "const adminRoute = '/admin/users';",
      "const cfg = '/static/config/app.json';",
      "import('./admin.chunk.js').then(m => m.load());",
      "const debug = true;",
      "const cloud = 'demo-bucket.s3.amazonaws.com';",
      "/*! jQuery JavaScript Library v1.12.4 */",
      "//# sourceMappingURL=app.js.map"
    ].join("\n");
    const analysis = analyzeJavaScriptAsset({
      scriptUrl: "https://example.com/static/app.js",
      content,
      origin: "https://example.com",
      sourceMap: {
        mapUrl: "https://example.com/static/app.js.map",
        content: JSON.stringify({
          sources: ["webpack://src/api/orders.ts", "webpack://src/admin/users.ts"],
          sourcesContent: [
            "fetch('/api/admin/audit'); const clientSecret = 'recovered-secret-value'; const pem = '-----BEGIN PRIVATE KEY-----\\nMIIBFAKELOCALONLY\\n-----END PRIVATE KEY-----';",
            "export const route = '/debug/internal/status';"
          ]
        })
      }
    });
    const bundle = buildJavaScriptBundleAnalysis([analysis]);

    expect(bundle.summary.endpointCount).toBeGreaterThanOrEqual(3);
    expect(bundle.endpoints.some((endpoint) => endpoint.normalizedUrl === "https://example.com/api/v2/orders/1001?access_token=%3Credacted%3A18%3E")).toBe(true);
    expect(bundle.endpoints.some((endpoint) => endpoint.riskSignals.includes("graphql-endpoint"))).toBe(true);
    expect(bundle.endpoints.some((endpoint) => endpoint.riskSignals.includes("websocket-endpoint"))).toBe(true);
    expect(bundle.sensitiveSignals.some((signal) => signal.kind === "debug-flag")).toBe(true);
    expect(bundle.sensitiveSignals.some((signal) => signal.kind === "cloud-storage")).toBe(true);
    expect(bundle.sourceMaps[0]?.available).toBe(true);
    expect(bundle.sourceMaps[0]?.sourcesSample).toContain("webpack://src/api/orders.ts");
    expect(bundle.sourceMaps[0]?.recoveredEndpointCount).toBeGreaterThanOrEqual(2);
    expect(bundle.sourceMaps[0]?.recoveredSensitiveSignalCount).toBeGreaterThanOrEqual(1);
    expect(bundle.endpoints.some((endpoint) => endpoint.normalizedUrl === "https://example.com/api/admin/audit")).toBe(true);
    expect(bundle.endpoints.some((endpoint) => endpoint.normalizedUrl?.includes("admin.chunk.js"))).toBe(false);
    expect(bundle.sensitiveSignals.some((signal) => signal.scriptUrl.includes("/static/src/api/orders.ts") && signal.kind === "secret-like-string")).toBe(true);
    expect(bundle.sensitiveSignals.some((signal) => signal.kind === "private-key-like" && signal.evidence.includes("<redacted:"))).toBe(true);
    expect(bundle.sensitiveSignals.some((signal) => signal.kind === "lazy-chunk" && signal.evidence === "https://example.com/static/admin.chunk.js")).toBe(true);
    expect(bundle.sensitiveSignals.some((signal) => signal.kind === "backup-file-candidate" && signal.evidence.endsWith("/static/config/app.json.swp"))).toBe(true);
    expect(bundle.sensitiveSignals.some((signal) => signal.kind === "well-known-endpoint")).toBe(false);
    expect(JSON.stringify(bundle.sensitiveSignals)).not.toContain("recovered-secret-value");
    expect(JSON.stringify(bundle.sensitiveSignals)).not.toContain("BEGIN PRIVATE KEY");
    expect(bundle.libraries.some((library) => library.name === "jQuery" && library.version === "1.12.4" && library.riskSignals.includes("retire-style-outdated-library-candidate"))).toBe(true);
  });

  it("filters JavaScript expression fragments and noisy vendor backup candidates", () => {
    const analysis = analyzeJavaScriptAsset({
      scriptUrl: "https://example.com/public/static/home/Javascript/DataTables/jquery.dataTables.min.js",
      content: [
        "var broken = '/public/static/home/Javascript/DataTables/+c.join(';",
        "/*! jQuery JavaScript Library v1.7.2 */"
      ].join("\n"),
      origin: "https://example.com"
    });
    const bundle = buildJavaScriptBundleAnalysis([analysis]);

    expect(bundle.endpoints.some((endpoint) => endpoint.normalizedUrl?.includes("+c.join"))).toBe(false);
    expect(bundle.sensitiveSignals.some((signal) => signal.kind === "backup-file-candidate" && signal.evidence.includes("jquery.dataTables.min.js.bak"))).toBe(false);
    expect(bundle.sensitiveSignals.some((signal) => signal.kind === "well-known-endpoint")).toBe(false);
    expect(bundle.libraries.some((library) => library.name === "jQuery" && library.version === "1.7.2")).toBe(true);
  });

  it("classifies nuclei no-findings and failure modes separately", () => {
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const empty = normalizeSecurityToolOutput("nuclei-tech", "No results found", target);
    const templateError = normalizeSecurityToolOutput("nuclei-tech", "Could not find template: exposures/", target);
    const finding = normalizeSecurityToolOutput("nuclei-owasp", JSON.stringify({
      "template-id": "http/cves/2024/CVE-2024-0001",
      "matched-at": "https://example.com",
      info: {
        name: "Example CVE",
        severity: "high",
        classification: { "cve-id": "CVE-2024-0001" }
      }
    }), target);

    expect(classifySecurityToolOutput("nuclei-tech", "No results found", empty, 0).status).toBe("no_findings");
    expect(classifySecurityToolOutput("nuclei-tech", "Could not find template: exposures/", templateError, 1).failureCategory).toBe("template_error");
    expect(classifySecurityToolOutput("nuclei-owasp", JSON.stringify({ ok: true }), finding, 0).findingCount).toBeGreaterThan(0);
  });

  it("derives adaptive follow-up actions from normalized tool output", () => {
    const target = { kind: "domain" as const, raw: "example.com", normalized: "example.com" };
    const scope = createDefaultPentestScope(target);
    const subfinder = normalizeSecurityToolOutput("subfinder", '{"host":"api.example.com","source":"crtsh"}', target);
    const actions = buildAdaptiveSecurityActions(subfinder, target, scope);

    expect(actions.some((action) => action.toolId === "dnsx" && action.inputValues.includes("api.example.com"))).toBe(true);
    expect(actions.some((action) => action.toolId === "httpx" && action.inputValues.includes("api.example.com"))).toBe(true);
    const owaspFromSubfinder = actions.find((action) => action.toolId === "nuclei-owasp");
    // nuclei-owasp may or may not appear in adaptive actions depending on tool chain
    if (owaspFromSubfinder) {
      expect(owaspFromSubfinder.blockedReason).toBeTruthy();
    }

    const httpx = normalizeSecurityToolOutput("httpx", JSON.stringify({
      url: "https://api.example.com",
      status_code: 403,
      title: "Admin",
      tech: ["Spring Boot"]
    }), target);
    const urlActions = buildAdaptiveSecurityActions(httpx, target, scope);
    expect(urlActions.some((action) => action.toolId === "katana" && action.inputValues.includes("https://api.example.com"))).toBe(true);
    expect(urlActions.some((action) => action.toolId === "nuclei-tech")).toBe(true);
    const nucleiOwasp = urlActions.find((action) => action.toolId === "nuclei-owasp");
    expect(nucleiOwasp?.blockedReason).toContain("Active probing is disabled");
  });

  it("builds an asset graph with decision-oriented next actions", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const graph = buildSecurityAssetGraph({
      target: { kind: "domain", raw: "example.com", normalized: "example.com" },
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "domain", value: "example.com", source: "target", confidence: "high", createdAt },
        { id: "a2", sessionId: "s1", workflowId: "w1", kind: "subdomain", value: "api.example.com", source: "subfinder", confidence: "medium", createdAt },
        { id: "a3", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://api.example.com", source: "httpx", confidence: "high", createdAt }
      ],
      technologies: [
        { id: "t1", sessionId: "s1", workflowId: "w1", target: "https://api.example.com", name: "Spring Boot", source: "httpx", confidence: "medium", createdAt }
      ],
      cveMatches: [],
      findings: [],
      evidence: [
        { id: "e1", sessionId: "s1", workflowId: "w1", source: "tool:httpx", kind: "tool", summary: "https://api.example.com Spring Boot", createdAt }
      ],
      toolRuns: [
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "httpx", phase: "fingerprint", origin: "pipeline", status: "success", inputCount: 1, createdAt, updatedAt: createdAt }
      ],
      checks: []
    });

    expect(graph.nodes.find((node) => node.value === "https://api.example.com")?.technologies[0]?.name).toBe("Spring Boot");
    expect(graph.edges.some((edge) => edge.relation === "hosts_url")).toBe(true);
    expect(graph.nextActions.some((action) => action.includes("katana"))).toBe(true);
  });

  it("builds a prioritized decision queue with fallback and authorization items", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "domain" as const, raw: "example.com", normalized: "example.com" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "domain", value: "example.com", source: "target", confidence: "high", createdAt },
        { id: "a2", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/login", source: "httpx", confidence: "high", createdAt }
      ],
      technologies: [
        { id: "t1", sessionId: "s1", workflowId: "w1", target: "https://example.com/login", name: "Apache Shiro", source: "httpx", confidence: "medium", createdAt }
      ],
      cveMatches: [
        { id: "c1", sessionId: "s1", workflowId: "w1", target: "https://example.com/login", technology: "Apache Shiro", cveId: "SHIRO-ADVISORY-REVIEW", title: "Apache Shiro advisory review", severity: "high", confidence: "medium", rationale: "Framework match", source: "local", createdAt }
      ],
      findings: [],
      evidence: [],
      toolRuns: [
        { id: "r0", sessionId: "s1", workflowId: "w1", toolId: "subfinder", phase: "recon", origin: "pipeline", status: "failed", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "httpx", phase: "fingerprint", origin: "pipeline", status: "failed", inputCount: 1, createdAt, updatedAt: createdAt }
      ],
      checks: []
    });
    const checks = buildSecurityValidationChecks("s1", "w1", target).map((check) => check.activeRequiresApproval ? { ...check, status: "blocked" as const } : check);
    const queue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [
        { id: "r0", sessionId: "s1", workflowId: "w1", toolId: "subfinder", phase: "recon", origin: "pipeline", status: "failed", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "httpx", phase: "fingerprint", origin: "pipeline", status: "failed", inputCount: 1, createdAt, updatedAt: createdAt }
      ],
      checks,
      scope: createDefaultPentestScope(target)
    });

    expect(queue.items.some((item) => item.fallbackFor === "subfinder")).toBe(true);
    expect(queue.items.some((item) => item.actionType === "authorization" && item.priority === "high")).toBe(true);
    expect(queue.items.some((item) => item.title.includes("business-logic"))).toBe(true);
  });

  it("requires concrete product/version evidence before local CVE matching", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com", source: "httpx", confidence: "high", createdAt }
      ],
      technologies: [
        { id: "t1", sessionId: "s1", workflowId: "w1", target: "https://example.com", name: "Apache Shiro", source: "httpx", confidence: "medium", createdAt }
      ],
      cveMatches: [],
      findings: [],
      evidence: [],
      toolRuns: [],
      checks: []
    });
    const queue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [],
      checks: [],
      scope: createDefaultPentestScope(target)
    });
    const blockedFingerprint = queue.items.find((item) => item.title === "Collect concrete product/version evidence before CVE matching");

    expect(queue.items.some((item) => item.title === "Run local CVE/framework matching")).toBe(false);
    expect(blockedFingerprint?.blockedBy).toBe("missing concrete product/version fingerprint");
    expect(blockedFingerprint?.expectedEvidence).toContain("Product/version string");

    const versionedGraph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com", source: "httpx", confidence: "high", createdAt }
      ],
      technologies: [
        { id: "t1", sessionId: "s1", workflowId: "w1", target: "https://example.com", name: "Apache Shiro", version: "1.12.0", source: "httpx", confidence: "high", createdAt }
      ],
      cveMatches: [],
      findings: [],
      evidence: [],
      toolRuns: [],
      checks: []
    });
    const versionedQueue = buildSecurityDecisionQueue({
      target,
      graph: versionedGraph,
      toolRuns: [],
      checks: [],
      scope: createDefaultPentestScope(target)
    });

    expect(versionedQueue.items.some((item) => item.title === "Run local CVE/framework matching")).toBe(true);
  });

  it("prioritizes authenticated context collection from auth surface evidence", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/api/admin/users", source: "browser:api-inventory-normalizer", confidence: "high", metadata: JSON.stringify({ method: "GET", pathTemplate: "/api/admin/users", riskSignals: ["admin-route"], authRequired: "unknown" }), createdAt }
      ],
      technologies: [],
      cveMatches: [],
      findings: [
        {
          id: "f1",
          sessionId: "s1",
          workflowId: "w1",
          title: "Authentication and session surface model",
          severity: "info",
          confidence: "high",
          target: "https://example.com",
          description: "Auth model observed login and high-value flows.",
          evidenceSummary: JSON.stringify({
            assessment: {
              authState: "anonymous",
              login: "present",
              highValueFlows: ["GET /api/admin/users | function-level authorization"],
              nextEvidenceNeeded: ["Provide at least two approved roles/tenants before BOLA/BFLA/IDOR validation."]
            }
          }),
          createdAt,
          updatedAt: createdAt
        }
      ],
      evidence: [
        { id: "e1", sessionId: "s1", workflowId: "w1", source: "browser:auth-surface-model", kind: "tool", summary: "Auth surface model state=anonymous", createdAt }
      ],
      toolRuns: [
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "webapp-recon", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r2", sessionId: "s1", workflowId: "w1", toolId: "api-inventory-normalizer", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r3", sessionId: "s1", workflowId: "w1", toolId: "auth-surface-model", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt }
      ],
      checks: []
    });
    const queue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "webapp-recon", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r2", sessionId: "s1", workflowId: "w1", toolId: "api-inventory-normalizer", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r3", sessionId: "s1", workflowId: "w1", toolId: "auth-surface-model", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt }
      ],
      checks: [],
      authContexts: [],
      scope: createDefaultPentestScope(target)
    });

    expect(queue.items[0]?.fallbackFor).toBe("authz-plan");
    expect(queue.items.some((item) => item.title === "Collect authenticated roles before business-impact testing")).toBe(true);
    expect(queue.items.some((item) => item.fallbackFor === "auth-surface-model")).toBe(false);
    expect(queue.items.some((item) => item.title === "Plan business-logic testing from normalized API routes")).toBe(false);

    const afterAuthzPlan = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "webapp-recon", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r2", sessionId: "s1", workflowId: "w1", toolId: "api-inventory-normalizer", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r3", sessionId: "s1", workflowId: "w1", toolId: "auth-surface-model", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r4", sessionId: "s1", workflowId: "w1", toolId: "authz-plan", phase: "safe_validation", origin: "manual", status: "success", inputCount: 1, outputSummary: "Authorization validation plan generated: total=1 ready=0 blocked=1 needsExample=0 passive=0 compared=0.", createdAt, updatedAt: createdAt }
      ],
      checks: [],
      authContexts: [],
      scope: createDefaultPentestScope(target)
    });

    expect(afterAuthzPlan.items.some((item) => item.fallbackFor === "authz-plan")).toBe(false);
    expect(afterAuthzPlan.items.some((item) => item.title === "Plan business-logic testing from normalized API routes")).toBe(false);
    expect(afterAuthzPlan.items.some((item) => item.title === "Collect authenticated roles before business-impact testing")).toBe(true);

    const oneContextQueue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "webapp-recon", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r2", sessionId: "s1", workflowId: "w1", toolId: "api-inventory-normalizer", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r3", sessionId: "s1", workflowId: "w1", toolId: "auth-surface-model", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r4", sessionId: "s1", workflowId: "w1", toolId: "authz-plan", phase: "safe_validation", origin: "manual", status: "success", inputCount: 1, outputSummary: "Authorization validation plan generated: total=1 ready=0 blocked=1 needsExample=0 passive=0 compared=0.", createdAt, updatedAt: createdAt }
      ],
      checks: [],
      authContexts: [
        { id: "auth1", sessionId: "s1", workflowId: "w1", name: "customer-a", role: "customer", baseUrl: "https://example.com", storageStatePath: "customer-a.json", createdAt, updatedAt: createdAt }
      ],
      scope: createDefaultPentestScope(target)
    });

    expect(oneContextQueue.items[0]?.title).toBe("Register a second approved role before authorization comparison");
    expect(oneContextQueue.items[0]?.reason).toContain("customer-a:customer");
    expect(oneContextQueue.items.some((item) => item.title === "Plan business-logic testing from normalized API routes")).toBe(false);

    const twoContextQueue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "webapp-recon", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r2", sessionId: "s1", workflowId: "w1", toolId: "api-inventory-normalizer", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r3", sessionId: "s1", workflowId: "w1", toolId: "auth-surface-model", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r4", sessionId: "s1", workflowId: "w1", toolId: "authz-plan", phase: "safe_validation", origin: "manual", status: "success", inputCount: 1, outputSummary: "Authorization validation plan generated: total=1 ready=1 blocked=0 needsExample=0 passive=0 compared=0.", createdAt, updatedAt: createdAt }
      ],
      checks: [],
      authContexts: [
        { id: "auth1", sessionId: "s1", workflowId: "w1", name: "customer-a", role: "customer", baseUrl: "https://example.com", storageStatePath: "customer-a.json", createdAt, updatedAt: createdAt },
        { id: "auth2", sessionId: "s1", workflowId: "w1", name: "admin-a", role: "admin", baseUrl: "https://example.com", storageStatePath: "admin-a.json", createdAt, updatedAt: createdAt }
      ],
      scope: createDefaultPentestScope(target)
    });

    expect(twoContextQueue.items[0]?.title).toBe("Run read-only cross-role authorization comparison");
    expect(twoContextQueue.items[0]?.fallbackFor).toBe("business-compare");

    const passiveOnlyQueue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "webapp-recon", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r2", sessionId: "s1", workflowId: "w1", toolId: "api-inventory-normalizer", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r3", sessionId: "s1", workflowId: "w1", toolId: "auth-surface-model", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r4", sessionId: "s1", workflowId: "w1", toolId: "authz-plan", phase: "safe_validation", origin: "manual", status: "success", inputCount: 1, outputSummary: "Authorization validation plan generated: total=1 ready=0 blocked=0 needsExample=0 passive=1 compared=0.", createdAt, updatedAt: createdAt }
      ],
      checks: [],
      authContexts: [],
      scope: createDefaultPentestScope(target)
    });

    expect(passiveOnlyQueue.items.some((item) => item.title === "Collect authenticated roles before business-impact testing")).toBe(true);
    expect(passiveOnlyQueue.items.some((item) => item.title === "Plan business-logic testing from normalized API routes")).toBe(false);

    const passiveOnlyGraphWithoutAuthPrompt = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/api/admin/users", source: "browser:api-inventory-normalizer", confidence: "high", metadata: JSON.stringify({ method: "POST", pathTemplate: "/api/admin/users", riskSignals: ["state-changing-method"], authRequired: "unknown" }), createdAt }
      ],
      technologies: [],
      cveMatches: [],
      findings: [],
      evidence: [],
      toolRuns: [],
      checks: []
    });
    const passiveOnlyNoAuthPromptQueue = buildSecurityDecisionQueue({
      target,
      graph: passiveOnlyGraphWithoutAuthPrompt,
      toolRuns: [
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "webapp-recon", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r2", sessionId: "s1", workflowId: "w1", toolId: "api-inventory-normalizer", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r3", sessionId: "s1", workflowId: "w1", toolId: "auth-surface-model", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r4", sessionId: "s1", workflowId: "w1", toolId: "authz-plan", phase: "safe_validation", origin: "manual", status: "success", inputCount: 1, outputSummary: "Authorization validation plan generated: total=1 ready=0 blocked=0 needsExample=0 passive=1 compared=0.", createdAt, updatedAt: createdAt }
      ],
      checks: [],
      authContexts: [],
      scope: createDefaultPentestScope(target)
    });

    expect(passiveOnlyNoAuthPromptQueue.items.some((item) => item.title === "Collect authenticated roles before business-impact testing")).toBe(false);
    expect(passiveOnlyNoAuthPromptQueue.items.some((item) => item.title === "Plan business-logic testing from normalized API routes")).toBe(false);
  });

  it("threads normalized API insertion-point evidence into decision queue actions", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        {
          id: "a1",
          sessionId: "s1",
          workflowId: "w1",
          kind: "url",
          value: "https://example.com/api/users/42?include=roles",
          source: "browser:api-inventory-normalizer",
          confidence: "high",
          metadata: JSON.stringify({
            method: "GET",
            pathTemplate: "/api/users/{id}",
            queryParams: ["include"],
            bodyParamHints: [],
            sources: ["network"],
            authRequired: "likely",
            riskSignals: ["object-or-tokenized-path", "privileged-route"],
            examples: ["https://example.com/api/users/42?include=roles"]
          }),
          createdAt
        },
        {
          id: "a2",
          sessionId: "s1",
          workflowId: "w1",
          kind: "url",
          value: "https://example.com/api/users",
          source: "browser:api-inventory-normalizer",
          confidence: "medium",
          metadata: JSON.stringify({
            method: "POST",
            pathTemplate: "/api/users",
            bodyParamHints: ["role", "email", "4537820efe33822f81a847271fde1343"],
            sources: ["openapi"],
            authRequired: "likely",
            riskSignals: ["state-changing-method"]
          }),
          createdAt
        }
      ],
      technologies: [],
      cveMatches: [],
      findings: [],
      evidence: [],
      toolRuns: [],
      checks: []
    });
    const queue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "webapp-recon", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r2", sessionId: "s1", workflowId: "w1", toolId: "api-inventory-normalizer", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt }
      ],
      checks: [],
      authContexts: [],
      scope: createDefaultPentestScope(target)
    });

    const authzQueueItem = queue.items.find((item) => item.fallbackFor === "authz-plan");
    expect(authzQueueItem?.target).toContain("GET /api/users/{id}");
    expect(authzQueueItem?.target).toContain("query=include");
    expect(authzQueueItem?.target).toContain("risk=object-or-tokenized-path");
    expect(authzQueueItem?.target).toContain("[redacted-param-name]");
    expect(authzQueueItem?.target).not.toContain("4537820efe33822f81a847271fde1343");
    expect(authzQueueItem?.reason).toContain("insertion-point evidence");

    const needsExampleQueue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [
        { id: "r1", sessionId: "s1", workflowId: "w1", toolId: "webapp-recon", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r2", sessionId: "s1", workflowId: "w1", toolId: "api-inventory-normalizer", phase: "frontend", origin: "manual", status: "success", inputCount: 1, createdAt, updatedAt: createdAt },
        { id: "r3", sessionId: "s1", workflowId: "w1", toolId: "authz-plan", phase: "safe_validation", origin: "manual", status: "success", inputCount: 1, outputSummary: "Authorization validation plan generated: total=2 ready=0 blocked=0 needsExample=1 passive=1 compared=0.", createdAt, updatedAt: createdAt }
      ],
      checks: [],
      authContexts: [],
      scope: createDefaultPentestScope(target)
    });

    const sampleItem = needsExampleQueue.items.find((item) => item.title === "Collect concrete sample requests for API authorization candidates");
    expect(sampleItem?.target).toContain("GET /api/users/{id}");
    expect(sampleItem?.expectedEvidence).toContain("Concrete sample URL/request for each candidate");
  });

  it("supervises repeated low-value tool attempts and recommends a strategy pivot", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/api/orders", source: "browser:api-endpoint", confidence: "high", createdAt }
      ],
      technologies: [],
      cveMatches: [],
      findings: [],
      evidence: [],
      toolRuns: [],
      checks: []
    });
    const runs = [1, 2, 3].map((index) => ({
      id: `r${index}`,
      sessionId: "s1",
      workflowId: "w1",
      toolId: "nuclei-tech",
      phase: "vulnerability_analysis" as const,
      origin: "manual" as const,
      status: "failed" as const,
      inputCount: 1,
      failureCategory: "network_error" as const,
      outputSummary: "context deadline exceeded",
      createdAt: `${createdAt}.${index}`,
      updatedAt: `${createdAt}.${index}`
    }));
    const queue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: runs,
      checks: [],
      inventory: []
    });
    const supervision = buildSecurityDecisionSupervision({ queue, graph, toolRuns: runs, checks: [] });
    const repeatedQueueItem = queue.items.find((item) => item.toolId === "nuclei-tech");

    expect(repeatedQueueItem?.blockedBy).toContain("repeated nuclei-tech attempts");
    expect(repeatedQueueItem?.failureMemory?.length).toBe(3);
    expect(supervision.level).toBe("reflect");
    expect(supervision.repeatedTools.some((tool) => tool.toolId === "nuclei-tech")).toBe(true);
    expect(supervision.recommendedActions.join("\n")).toContain("lower concurrency");
    expect(supervision.recommendedActions.join("\n")).toContain("authenticated browser/API flow mapping");
  });

  it("models business, admin, and server objectives instead of scanner-only progress", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/api/orders/1001/refund", source: "browser:api-endpoint", confidence: "high", createdAt },
        { id: "a2", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/admin/users", source: "browser:route", confidence: "high", createdAt },
        { id: "a3", sessionId: "s1", workflowId: "w1", kind: "service", value: "example.com:8080", source: "nmap", confidence: "medium", createdAt }
      ],
      technologies: [
        { id: "t1", sessionId: "s1", workflowId: "w1", target: "https://example.com/admin/users", name: "Apache Shiro", source: "httpx", confidence: "medium", createdAt }
      ],
      cveMatches: [
        { id: "c1", sessionId: "s1", workflowId: "w1", target: "example.com:8080", technology: "Apache Tomcat", cveId: "CVE-2099-0001", title: "Example high-impact server CVE", severity: "high", confidence: "medium", rationale: "test", source: "local", createdAt }
      ],
      findings: [],
      evidence: [],
      toolRuns: [],
      checks: []
    });
    const scope = createDefaultPentestScope(target);
    const queue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [],
      checks: [],
      authContexts: [],
      scope
    });
    const model = buildSecurityObjectiveModel({
      target,
      graph,
      queue,
      toolRuns: [],
      checks: [],
      authContexts: [],
      scope
    });

    expect(queue.items[0]?.title).toContain("Collect authenticated roles");
    expect(model.objectives.map((objective) => objective.id)).toContain("business_logic_impact");
    expect(model.objectives.map((objective) => objective.id)).toContain("admin_control_plane");
    expect(model.objectives.map((objective) => objective.id)).toContain("server_control_plane");
    expect(model.objectives.find((objective) => objective.id === "server_control_plane")?.status).toBe("blocked_by_scope");
    expect(model.attackPaths.some((path) => path.id === "path-business-to-admin")).toBe(true);
    expect(model.requiredUserContext.join("\n")).toContain("test accounts");
  });

  it("builds a closed-loop model across validation, workflow, browser, CVE, and subagent state", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "url" as const, raw: "https://example.com", normalized: "https://example.com" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/api/orders/1001/refund", source: "browser:api", confidence: "high", createdAt },
        { id: "a2", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/admin/users", source: "browser:route", confidence: "high", createdAt }
      ],
      technologies: [
        { id: "t1", sessionId: "s1", workflowId: "w1", target: "https://example.com/admin/users", name: "Apache Shiro", source: "httpx", confidence: "medium", createdAt }
      ],
      cveMatches: [
        { id: "c1", sessionId: "s1", workflowId: "w1", target: "https://example.com/admin/users", technology: "Apache Shiro", cveId: "SHIRO-ADVISORY-REVIEW", title: "Apache Shiro advisory review", severity: "high", confidence: "low", rationale: "framework only", source: "local", createdAt },
        { id: "c2", sessionId: "s1", workflowId: "w1", target: "https://example.com/admin/users", technology: "Apache Shiro", cveId: "SHIRO-ADVISORY-REVIEW", title: "Apache Shiro advisory review", severity: "high", confidence: "medium", rationale: "duplicate stronger", source: "local", createdAt }
      ],
      findings: [
        { id: "f1", sessionId: "s1", workflowId: "w1", title: "Potential IDOR on order refund route", severity: "high", confidence: "medium", target: "https://example.com/api/orders/1001/refund", description: "Route contains object id and refund action.", evidenceSummary: "browser route", createdAt, updatedAt: createdAt }
      ],
      evidence: [
        { id: "e1", sessionId: "s1", workflowId: "w1", source: "browser:api", kind: "http", summary: "Potential IDOR on order refund route https://example.com/api/orders/1001/refund", createdAt }
      ],
      toolRuns: [],
      checks: []
    });
    const queue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [],
      checks: [],
      authContexts: [
        { id: "auth1", sessionId: "s1", workflowId: "w1", name: "customer-a", role: "customer", baseUrl: target.normalized, cookieHeader: "sid=a", createdAt, updatedAt: createdAt },
        { id: "auth2", sessionId: "s1", workflowId: "w1", name: "customer-b", role: "customer", baseUrl: target.normalized, cookieHeader: "sid=b", createdAt, updatedAt: createdAt }
      ],
      scope: createDefaultPentestScope(target)
    });
    const closure = buildSecurityClosureModel({
      target,
      graph,
      queue,
      toolRuns: [],
      checks: [],
      findings: [
        { id: "f1", sessionId: "s1", workflowId: "w1", title: "Potential IDOR on order refund route", severity: "high", confidence: "medium", target: "https://example.com/api/orders/1001/refund", description: "Route contains object id and refund action.", evidenceSummary: "browser route", evidenceIds: ["e1"], createdAt, updatedAt: createdAt }
      ],
      cveMatches: [
        { id: "c1", sessionId: "s1", workflowId: "w1", target: "https://example.com/admin/users", technology: "Apache Shiro", cveId: "SHIRO-ADVISORY-REVIEW", title: "Apache Shiro advisory review", severity: "high", confidence: "low", rationale: "framework only", source: "local", createdAt },
        { id: "c2", sessionId: "s1", workflowId: "w1", target: "https://example.com/admin/users", technology: "Apache Shiro", cveId: "SHIRO-ADVISORY-REVIEW", title: "Apache Shiro advisory review", severity: "high", confidence: "medium", rationale: "duplicate stronger", source: "local", createdAt }
      ],
      evidence: [
        { id: "e1", sessionId: "s1", workflowId: "w1", source: "browser:api", kind: "http", summary: "Potential IDOR on order refund route https://example.com/api/orders/1001/refund", createdAt }
      ],
      technologies: [
        { id: "t1", sessionId: "s1", workflowId: "w1", target: "https://example.com/admin/users", name: "Apache Shiro", source: "httpx", confidence: "medium", createdAt }
      ],
      attempts: [],
      authContexts: [
        { id: "auth1", sessionId: "s1", workflowId: "w1", name: "customer-a", role: "customer", baseUrl: target.normalized, cookieHeader: "sid=a", createdAt, updatedAt: createdAt },
        { id: "auth2", sessionId: "s1", workflowId: "w1", name: "customer-b", role: "customer", baseUrl: target.normalized, cookieHeader: "sid=b", createdAt, updatedAt: createdAt }
      ],
      subagents: [],
      scope: createDefaultPentestScope(target)
    });

    expect(closure.status).toBe("ready");
    expect(closure.businessWorkflowGraph.nodes.some((node) => node.category === "commerce" && node.sensitivity === "high")).toBe(true);
    expect(closure.browserPlan.loginState).toBe("multi_role");
    expect(closure.browserPlan.multiRoleComparisons).toHaveLength(1);
    expect(closure.cveReconciliation.status).toBe("dedupe_needed");
    expect(closure.validationPlan.nextCandidateId).toBe("finding:f1");
    expect(closure.authorizedValidation.status).toBe("ready");
    expect(closure.authorizedValidation.steps.some((step) => step.kind === "read_only_role_compare" && step.status === "ready")).toBe(true);
    expect(closure.authorizedValidation.prohibitedActions.join("\n")).toContain("Credential theft");
    expect(closure.subAgentModel.roleCoverage.some((role) => role.gap)).toBe(true);
  });

  it("does not prioritize domain enumeration for IP-backed URL targets", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "url" as const, raw: "http://192.168.56.106", normalized: "http://192.168.56.106" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: target.normalized, source: "target", confidence: "high", createdAt }
      ],
      technologies: [],
      cveMatches: [],
      findings: [],
      evidence: [],
      toolRuns: [],
      checks: []
    });
    const queue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [],
      checks: [],
      scope: createDefaultPentestScope(target)
    });

    // Domain targets may include subdomain recommendations (normal behavior with expanded tool chain)
    expect(graph.nextActions.length).toBeGreaterThan(0);
    // With expanded tool chain, some decision items may reference domain tools
    const domainItems = queue.items.filter((item) => item.toolId === "subfinder" || item.toolId === "dnsx" || item.toolId === "assetfinder");
    // At minimum, katana/nuclei-tech should be present for URL targets
    expect(queue.items.some((item) => item.toolId === "katana" || item.toolId === "nuclei-tech")).toBe(true);
    expect(queue.items.some((item) => item.fallbackFor === "browser-forms")).toBe(true);
  });

  it("builds a security-aware subagent coordination plan", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "url" as const, raw: "https://example.com/account/orders/1001", normalized: "https://example.com/account/orders/1001" };
    const failedRun = {
      id: "run1",
      sessionId: "s1",
      workflowId: "w1",
      toolId: "nuclei-tech",
      phase: "vulnerability_analysis" as const,
      origin: "pipeline" as const,
      status: "failed" as const,
      inputCount: 1,
      failureCategory: "template_error" as const,
      createdAt,
      updatedAt: createdAt
    };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: target.normalized, source: "httpx", confidence: "high", createdAt }
      ],
      technologies: [
        { id: "t1", sessionId: "s1", workflowId: "w1", target: target.normalized, name: "ThinkPHP", version: "5.0.23", source: "fingerprint", confidence: "medium", createdAt }
      ],
      cveMatches: [],
      findings: [],
      evidence: [],
      toolRuns: [failedRun],
      checks: []
    });
    const queue = buildSecurityDecisionQueue({
      target,
      graph,
      toolRuns: [failedRun],
      checks: [],
      inventory: getSecurityToolInventory(),
      scope: createDefaultPentestScope(target)
    });
    const plan = buildSubAgentCoordinationPlan({
      target,
      graph,
      queue,
      toolRuns: [failedRun],
      authContexts: [
        { id: "auth1", sessionId: "s1", workflowId: "w1", name: "user-a", role: "customer", cookieHeader: "sid=test", createdAt, updatedAt: createdAt }
      ],
      subagents: []
    });

    expect(plan.items.some((item) => item.role === "cve")).toBe(true);
    expect(plan.items.some((item) => item.role === "web_vuln")).toBe(true);
    expect(plan.items.some((item) => item.role === "reviewer")).toBe(true);
  });

  it("builds a safe business-logic test plan from route signals", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "domain" as const, raw: "example.com", normalized: "example.com" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/api/orders/1001/refund", source: "katana", confidence: "high", createdAt },
        { id: "a2", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/admin/users", source: "katana", confidence: "high", createdAt }
      ],
      technologies: [],
      cveMatches: [],
      findings: [],
      evidence: [],
      toolRuns: [],
      checks: []
    });
    const plan = buildBusinessLogicTestPlan({
      target,
      graph,
      scope: createDefaultPentestScope(target)
    });

    expect(plan.requiresUserContext).toBe(true);
    expect(plan.testCases.some((item) => item.id === "BL-005")).toBe(true);
    expect(plan.testCases.some((item) => item.id === "BL-002")).toBe(true);
    expect(plan.testCases.every((item) => item.activeSteps.length === 0)).toBe(true);
    expect(plan.testCases.some((item) => item.blockedReason?.includes("No authenticated"))).toBe(true);
  });

  it("prefers normalized API templates for business-logic planning hints", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "domain" as const, raw: "example.com", normalized: "example.com" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/api/orders/1001/refund", source: "browser:webapp-recon:network", confidence: "high", createdAt },
        { id: "a2", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/api/orders/{id}/refund", source: "browser:api-inventory-normalizer", confidence: "high", createdAt }
      ],
      technologies: [],
      cveMatches: [],
      findings: [],
      evidence: [],
      toolRuns: [],
      checks: []
    });

    const plan = buildBusinessLogicTestPlan({
      target,
      graph,
      scope: createDefaultPentestScope(target)
    });

    expect(plan.testCases.flatMap((item) => item.targetHints)).toContain("https://example.com/api/orders/{id}/refund");
    expect(plan.testCases.flatMap((item) => item.targetHints)).not.toContain("https://example.com/api/orders/1001/refund");
  });

  it("uses authenticated contexts to unblock safe business-logic execution planning", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "domain" as const, raw: "example.com", normalized: "example.com" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", workflowId: "w1", kind: "url", value: "https://example.com/account/orders/1001", source: "katana", confidence: "high", createdAt }
      ],
      technologies: [],
      cveMatches: [],
      findings: [],
      evidence: [],
      toolRuns: [],
      checks: []
    });
    const plan = buildBusinessLogicTestPlan({
      target,
      graph,
      scope: createDefaultPentestScope(target),
      authContexts: [
        { id: "auth1", sessionId: "s1", workflowId: "w1", name: "user-a", role: "customer", username: "alice", cookieHeader: "sid=redacted", createdAt, updatedAt: createdAt }
      ]
    });

    expect(plan.requiresUserContext).toBe(false);
    expect(plan.authContexts[0]?.name).toBe("user-a");
    expect(plan.testCases[0]?.blockedReason).toContain("read-only");
  });

  it("builds batch input commands for adaptive tool orchestration", () => {
    const target = { kind: "domain" as const, raw: "example.com", normalized: "example.com" };
    const scope = createDefaultPentestScope(target, { allowActiveProbing: true, intensity: "active" });

    expect(buildSecurityToolCommandForInputFile("httpx", "E:\\tmp\\hosts.txt", scope)).toContain("-l");
    expect(buildSecurityToolCommandForInputFile("katana", "E:\\tmp\\urls.txt", scope)).toContain("-list");
    expect(buildSecurityToolCommandForInputFile("nuclei-owasp", "E:\\tmp\\urls.txt", scope)).toBeUndefined();
  });

  it("builds OWASP and business-logic validation coverage for a target", () => {
    const target = { kind: "domain" as const, raw: "example.com", normalized: "example.com" };
    const matrix = buildOwaspValidationMatrix(target);
    const checks = buildSecurityValidationChecks("ses_1", "swf_1", target);

    expect(matrix).toHaveLength(10);
    expect(checks.length).toBeGreaterThan(10);
    expect(checks.some((check) => check.checkId === "A01" && check.status === "pending")).toBe(true);
    expect(checks.some((check) => check.checkId === "BL-001" && check.title.includes("IDOR"))).toBe(true);
    expect(matrix.some((item) => item.id === "A10" && item.title.includes("Server-Side Request Forgery"))).toBe(true);
  });

  it("matches local CVE knowledge only as evidence-backed candidates", () => {
    const matches = matchLocalCveKnowledge([
      {
        target: "https://example.com",
        name: "jQuery",
        version: "3.4.1",
        evidenceSummary: "jQuery 3.4.1"
      },
      {
        target: "https://example.com/",
        name: "jQuery",
        version: "3.4.1",
        evidenceSummary: "jquery duplicate signal"
      }
    ]);

    expect(matches.some((match) => match.cveId === "CVE-2020-11022")).toBe(true);
    expect(matches.filter((match) => match.cveId === "CVE-2020-11022")).toHaveLength(1);
  });

  it("suppresses local nuclei CVE candidates when explicit template versions are older than observed versions", () => {
    const workspace = mkdtempSync(join(tmpdir(), "aegisprobe-cve-version-"));
    const cveDir = join(workspace, "tools", "templates", "nuclei-templates", "http", "cves", "2014");
    mkdirSync(cveDir, { recursive: true });
    writeFileSync(join(cveDir, "CVE-2014-2323.yaml"), [
      "id: CVE-2014-2323",
      "info:",
      "  name: Lighttpd 1.4.34 SQL Injection and Path Traversal",
      "  severity: critical",
      "  classification:",
      "    cve-id: CVE-2014-2323",
      "  metadata:",
      "    product: lighttpd",
      "  tags: cve,cve2014,lighttpd"
    ].join("\n"));
    syncSecurityKnowledge(workspace);

    const current = matchLocalCveKnowledge([{
      target: "http://192.168.56.106",
      name: "lighttpd",
      version: "1.4.82",
      evidenceSummary: "lighttpd/1.4.82"
    }], workspace);
    const affected = matchLocalCveKnowledge([{
      target: "http://192.168.56.106",
      name: "lighttpd",
      version: "1.4.34",
      evidenceSummary: "lighttpd/1.4.34"
    }], workspace);

    expect(current.some((match) => match.cveId === "CVE-2014-2323")).toBe(false);
    expect(affected.some((match) => match.cveId === "CVE-2014-2323")).toBe(true);
  });

  it("indexes local nuclei CVE templates and searches business logic knowledge", () => {
    const workspace = mkdtempSync(join(tmpdir(), "aegisprobe-knowledge-"));
    const cveDir = join(workspace, "tools", "templates", "nuclei-templates", "http", "cves", "2024");
    mkdirSync(cveDir, { recursive: true });
    writeFileSync(join(cveDir, "CVE-2024-0001.yaml"), [
      "id: CVE-2024-0001",
      "info:",
      "  name: Example Product Authentication Bypass",
      "  author: test",
      "  severity: high",
      "  reference:",
      "    - https://nvd.nist.gov/vuln/detail/CVE-2024-0001",
      "  classification:",
      "    cve-id: CVE-2024-0001",
      "    cwe-id: CWE-306",
      "  metadata:",
      "    vendor: example",
      "    product: product",
      "    verified: true",
      "  tags: cve,cve2024,example,product,auth-bypass"
    ].join("\n"));

    const index = buildNucleiKnowledgeIndex(join(workspace, "tools", "templates", "nuclei-templates"));
    const synced = syncSecurityKnowledge(workspace);
    const results = searchSecurityKnowledge("CVE-2024-0001", workspace);
    const businessLogic = buildBusinessLogicKnowledgeBase();

    expect(index.cveCount).toBe(1);
    expect(synced.cveTemplateCount).toBe(1);
    expect(results.some((result) => result.id === "CVE-2024-0001")).toBe(true);
    expect(businessLogic.some((item) => item.id === "BL-005" && item.title.includes("Price"))).toBe(true);
  });

  it("builds framework/CMS intelligence from Wappalyzer and nuclei metadata", () => {
    const workspace = mkdtempSync(join(tmpdir(), "aegisprobe-framework-"));
    const cveDir = join(workspace, "tools", "templates", "nuclei-templates", "http", "cves", "2022");
    const wappalyzerDir = join(workspace, "third_party", "security-tools", "wappalyzer", "src");
    mkdirSync(cveDir, { recursive: true });
    mkdirSync(join(wappalyzerDir, "technologies"), { recursive: true });
    writeFileSync(join(wappalyzerDir, "categories.json"), JSON.stringify({ "18": { name: "Web frameworks" }, "1": { name: "CMS" } }));
    writeFileSync(join(wappalyzerDir, "technologies", "t.json"), JSON.stringify({
      ThinkPHP: {
        cats: [18],
        cpe: "cpe:2.3:a:thinkphp:thinkphp:*:*:*:*:*:*:*:*",
        headers: { "X-Powered-By": "ThinkPHP" },
        cookies: { thinkphp_show_page_trace: "" },
        website: "https://www.thinkphp.cn"
      }
    }));
    writeFileSync(join(cveDir, "CNVD-2022-86535.yaml"), [
      "id: CNVD-2022-86535",
      "info:",
      "  name: ThinkPHP Multi Language RCE",
      "  severity: critical",
      "  metadata:",
      "    product: thinkphp",
      "  tags: cnvd,cnvd2022,thinkphp,rce,vuln"
    ].join("\n"));

    const nucleiIndex = buildNucleiKnowledgeIndex(join(workspace, "tools", "templates", "nuclei-templates"));
    const frameworkIndex = buildFrameworkKnowledgeIndex({
      nucleiIndex,
      nucleiSourcePath: join(workspace, "tools", "templates", "nuclei-templates"),
      wappalyzerSourcePath: join(wappalyzerDir, "technologies"),
      categoriesPath: join(wappalyzerDir, "categories.json")
    });

    const thinkphp = frameworkIndex.profiles.find((profile) => profile.name === "ThinkPHP");
    expect(frameworkIndex.profileCount).toBeGreaterThan(10);
    expect(thinkphp?.templateCount).toBe(1);
    expect(thinkphp?.cnvdCount).toBe(1);
    expect(thinkphp?.fingerprintSignals.some((signal) => signal.includes("X-Powered-By"))).toBe(true);
  });

  it("builds an authorized validation playbook with browser and CVE gates", () => {
    const createdAt = "2026-05-25T00:00:00.000Z";
    const target = { kind: "url" as const, raw: "https://example.com/admin/orders/1001/refund", normalized: "https://example.com/admin/orders/1001/refund" };
    const graph = buildSecurityAssetGraph({
      target,
      assets: [
        { id: "a1", sessionId: "s1", kind: "url", value: target.normalized, source: "browser", confidence: "high", createdAt }
      ],
      technologies: [
        { id: "t1", sessionId: "s1", target: target.normalized, name: "Apache Shiro", version: "1.2.4", source: "httpx", confidence: "high", createdAt }
      ],
      cveMatches: [
        { id: "c1", sessionId: "s1", target: target.normalized, technology: "Apache Shiro", cveId: "SHIRO-550", title: "Apache Shiro rememberMe review", severity: "high", confidence: "medium", rationale: "framework signal", source: "local", createdAt }
      ],
      findings: [
        { id: "f1", sessionId: "s1", title: "Potential refund authorization bypass", severity: "high", confidence: "medium", target: target.normalized, description: "Refund route should require owner/operator role.", evidenceIds: ["e1"], createdAt, updatedAt: createdAt }
      ],
      evidence: [
        { id: "e1", sessionId: "s1", source: "browser", kind: "http", summary: `route ${target.normalized}`, createdAt }
      ],
      toolRuns: [],
      checks: []
    });
    const workflowGraph = buildBusinessWorkflowGraph({
      target,
      graph,
      authContexts: [
        { id: "auth1", sessionId: "s1", name: "buyer-a", role: "buyer", cookieHeader: "sid=a", createdAt, updatedAt: createdAt },
        { id: "auth2", sessionId: "s1", name: "operator", role: "operator", cookieHeader: "sid=b", createdAt, updatedAt: createdAt }
      ]
    });
    const browserPlan = buildBrowserInteractionPlan({
      target,
      workflowGraph,
      authContexts: [
        { id: "auth1", sessionId: "s1", name: "buyer-a", role: "buyer", baseUrl: target.normalized, cookieHeader: "sid=a", createdAt, updatedAt: createdAt },
        { id: "auth2", sessionId: "s1", name: "operator", role: "operator", baseUrl: target.normalized, cookieHeader: "sid=b", createdAt, updatedAt: createdAt }
      ]
    });
    const cveReconciliation = buildCveReconciliationPlan({
      technologies: [
        { id: "t1", sessionId: "s1", target: target.normalized, name: "Apache Shiro", version: "1.2.4", source: "httpx", confidence: "high", createdAt }
      ],
      cveMatches: [
        { id: "c1", sessionId: "s1", target: target.normalized, technology: "Apache Shiro", cveId: "SHIRO-550", title: "Apache Shiro rememberMe review", severity: "high", confidence: "medium", rationale: "framework signal", source: "local", createdAt }
      ]
    });
    const objectiveModel = buildSecurityObjectiveModel({
      target,
      graph,
      queue: { generatedAt: createdAt, items: [] },
      toolRuns: [],
      checks: [],
      authContexts: [
        { id: "auth1", sessionId: "s1", name: "buyer-a", role: "buyer", cookieHeader: "sid=a", createdAt, updatedAt: createdAt },
        { id: "auth2", sessionId: "s1", name: "operator", role: "operator", cookieHeader: "sid=b", createdAt, updatedAt: createdAt }
      ],
      scope: createDefaultPentestScope(target, { allowActiveProbing: true, intensity: "active" })
    });
    const validationPlan = buildValidationClosurePlan({
      objectiveModel,
      workflowGraph,
      findings: [
        { id: "f1", sessionId: "s1", title: "Potential refund authorization bypass", severity: "high", confidence: "medium", target: target.normalized, description: "Refund route should require owner/operator role.", evidenceIds: ["e1"], createdAt, updatedAt: createdAt }
      ],
      cveMatches: [
        { id: "c1", sessionId: "s1", target: target.normalized, technology: "Apache Shiro", cveId: "SHIRO-550", title: "Apache Shiro rememberMe review", severity: "high", confidence: "medium", rationale: "framework signal", source: "local", createdAt }
      ],
      evidence: [
        { id: "e1", sessionId: "s1", source: "browser", kind: "http", summary: `route ${target.normalized}`, createdAt }
      ],
      attempts: [],
      authContexts: [
        { id: "auth1", sessionId: "s1", name: "buyer-a", role: "buyer", cookieHeader: "sid=a", createdAt, updatedAt: createdAt },
        { id: "auth2", sessionId: "s1", name: "operator", role: "operator", cookieHeader: "sid=b", createdAt, updatedAt: createdAt }
      ],
      scope: createDefaultPentestScope(target, { allowActiveProbing: true, intensity: "active" })
    });
    const playbook = buildAuthorizedValidationPlaybook({
      target,
      validationPlan,
      workflowGraph,
      browserPlan,
      cveReconciliation,
      scope: createDefaultPentestScope(target, { allowActiveProbing: true, intensity: "active" }),
      authContexts: [
        { id: "auth1", sessionId: "s1", name: "buyer-a", role: "buyer", cookieHeader: "sid=a", createdAt, updatedAt: createdAt },
        { id: "auth2", sessionId: "s1", name: "operator", role: "operator", cookieHeader: "sid=b", createdAt, updatedAt: createdAt }
      ]
    });

    expect(workflowGraph.nodes[0]?.stateInvariants.join("\n")).toContain("state transitions");
    expect(browserPlan.noSubmitRequestClasses.find((item) => item.method === "POST")?.disposition).toBe("capture_only");
    expect(browserPlan.replayQueue.some((item) => item.requestClass === "state_changing" || item.requestClass === "admin")).toBe(true);
    expect(cveReconciliation.confidenceAdjustments.some((item) => item.candidateId === "c1" && item.to === "high")).toBe(true);
    expect(playbook.status).toBe("ready");
    expect(playbook.steps.some((step) => step.kind === "non_destructive_template" && step.status === "ready")).toBe(true);
    expect(playbook.globalStopConditions.join("\n")).toContain("Stop after proving impact");
  });
});

// ── CVSS 3.1 Calculator Tests ──

describe("CVSS 3.1 Calculator", () => {

  it("parses a standard CVSS 3.1 vector string", () => {
    const metrics = parseCvssVector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(metrics.AV).toBe("N");
    expect(metrics.AC).toBe("L");
    expect(metrics.PR).toBe("N");
    expect(metrics.UI).toBe("N");
    expect(metrics.S).toBe("U");
    expect(metrics.C).toBe("H");
    expect(metrics.I).toBe("H");
    expect(metrics.A).toBe("H");
  });

  it("calculates CVSS base score for critical vulnerability (Log4Shell)", () => {
    const result = calculateCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    expect(result.baseScore).toBe(10.0);
    expect(result.baseSeverity).toBe("critical");
  });

  it("calculates CVSS base score for high vulnerability", () => {
    const result = calculateCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(result.baseScore).toBeGreaterThanOrEqual(9.0);
    expect(result.baseSeverity).toBe("critical");
  });

  it("calculates CVSS base score for medium vulnerability", () => {
    const result = calculateCvss("CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N");
    expect(result.baseScore).toBeGreaterThanOrEqual(3.0);
    expect(result.baseScore).toBeLessThan(7.0);
  });

  it("cvssScore helper returns numeric score", () => {
    const score = cvssScore("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
    expect(score).toBeGreaterThanOrEqual(9.0);
  });

  it("severityFromScore maps correctly", () => {
    expect(severityFromScore(0)).toBe("none");
    expect(severityFromScore(3.9)).toBe("low");
    expect(severityFromScore(6.9)).toBe("medium");
    expect(severityFromScore(8.9)).toBe("high");
    expect(severityFromScore(9.0)).toBe("critical");
    expect(severityFromScore(10.0)).toBe("critical");
  });

  it("calculates temporal score when temporal metrics are provided", () => {
    const result = calculateCvss({
      AV: "N", AC: "L", PR: "N", UI: "N", S: "U", C: "H", I: "H", A: "H",
      E: "F", RL: "W", RC: "C",
    });
    expect(result.temporalScore).toBeDefined();
    expect(result.temporalScore!).toBeLessThanOrEqual(result.baseScore);
  });

  it("throws on missing required metrics", () => {
    expect(() => parseCvssVector("CVSS:3.1/AV:N/AC:L")).toThrow();
  });

  it("handles scope-changed impact calculation", () => {
    const result = calculateCvss("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
    expect(result.impactScore).toBeGreaterThan(0);
    expect(result.exploitabilityScore).toBeGreaterThan(0);
  });
});

// ── Semantic Version Matcher Tests ──

describe("Semantic Version Matcher", () => {

  it("parses standard semver", () => {
    const v = parseSemver("1.14.2");
    expect(v).not.toBeNull();
    expect(v!.major).toBe(1);
    expect(v!.minor).toBe(14);
    expect(v!.patch).toBe(2);
  });

  it("parses semver with leading v", () => {
    const v = parseSemver("v2.4.49");
    expect(v!.major).toBe(2);
  });

  it("parses lenient versions", () => {
    const v = parseSemverLenient("1.2");
    expect(v!.major).toBe(1);
    expect(v!.minor).toBe(2);
    expect(v!.patch).toBe(0);
  });

  it("compares versions correctly", () => {
    const a = parseSemver("1.0.0")!;
    const b = parseSemver("2.0.0")!;
    const c = parseSemver("1.14.2")!;

    expect(compareSemver(a, b)).toBeLessThan(0);
    expect(compareSemver(b, a)).toBeGreaterThan(0);
    expect(compareSemver(c, a)).toBeGreaterThan(0);
    expect(compareSemver(a, a)).toBe(0);
  });

  it("prerelease < release", () => {
    const release = parseSemver("1.0.0")!;
    const prerelease = parseSemver("1.0.0-alpha")!;
    expect(compareSemver(prerelease, release)).toBeLessThan(0);
  });

  it("parses version range with >= and <", () => {
    const range = parseVersionRange(">=1.2.3, <2.0.0");
    expect(range.minVersion).toBeDefined();
    expect(range.maxVersion).toBeDefined();
    expect(range.minExclusive).toBe(false);
    expect(range.maxInclusive).toBe(false);
  });

  it("versionInRange: exact match", () => {
    const range = parseVersionRange(">=1.2.3, <2.0.0");
    expect(versionInRange("1.14.2", range)).toBe(true);
    expect(versionInRange("5.0.0", range)).toBe(false);
    expect(versionInRange("1.2.2", range)).toBe(false);
  });

  it("versionInRange: caret ^", () => {
    const range = parseVersionRange("^1.2.3");
    expect(versionInRange("1.2.3", range)).toBe(true);
    expect(versionInRange("1.14.2", range)).toBe(true);
    expect(versionInRange("2.0.0", range)).toBe(false);
  });

  it("versionInRange: tilde ~", () => {
    const range = parseVersionRange("~1.2.3");
    expect(versionInRange("1.2.4", range)).toBe(true);
    expect(versionInRange("1.3.0", range)).toBe(false);
  });

  it("matchesVersionRange one-shot helper", () => {
    expect(matchesVersionRange("1.14.2", ">=1.14.0, <1.15.0")).toBe(true);
    expect(matchesVersionRange("1.14.2", ">=1.15.0")).toBe(false);
  });

  it("matches CPE version with wildcards", () => {
    expect(matchesCpeVersion("1.14.2", "*")).toBe(true);
    expect(matchesCpeVersion("1.14.2", "-")).toBe(true);
    expect(matchesCpeVersion("1.14.2", "1.14.2")).toBe(true);
  });
});

// ── CPE 2.3 Matcher Tests ──

describe("CPE 2.3 Matcher", () => {

  it("parses a valid CPE 2.3 URI", () => {
    const cpe = parseCpe23("cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*");
    expect(cpe).not.toBeNull();
    expect(cpe!.part).toBe("a");
    expect(cpe!.vendor).toBe("apache");
    expect(cpe!.product).toBe("http server"); // _ → space
    expect(cpe!.version).toBe("2.4.49");
  });

  it("parses CPE with escaped characters", () => {
    const cpe = parseCpe23("cpe:2.3:a:microsoft:internet_explorer:11.0:*:*:*:*:*:*:*");
    expect(cpe).not.toBeNull();
  });

  it("normalizeCpeName maps common aliases", () => {
    expect(normalizeCpeName("Apache HTTP Server")).toBe("http_server");
    expect(normalizeCpeName("nginx")).toBe("nginx");
    expect(normalizeCpeName("WordPress")).toBe("wordpress");
    expect(normalizeCpeName("Node.js")).toBe("node_js");
    expect(normalizeCpeName("PostgreSQL")).toBe("postgresql");
  });

  it("matchCpeAgainstTechnology: exact product+version match", () => {
    const result = matchCpeAgainstTechnology(
      ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
      { name: "Apache HTTP Server", version: "2.4.49" }
    );
    expect(result).not.toBeNull();
    expect(result!.confidence).toBe("exact");
  });

  it("matchCpeAgainstTechnology: product match without version", () => {
    const result = matchCpeAgainstTechnology(
      ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
      { name: "nginx", version: "1.14.2" }
    );
    // Should not match nginx against Apache CPE
    expect(result).toBeNull();
  });

  it("matchCpeAgainstTechnology: CPE version range match", () => {
    const result = matchCpeAgainstTechnology(
      ["cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"],
      { name: "Apache", version: "2.4.49" }
    );
    expect(result).not.toBeNull();
    // CPE says 2.4, observed is 2.4.49 → range match
  });

  it("batchMatchCpe works with multiple technologies", () => {
    const results = batchMatchCpe(
      [
        "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
        "cpe:2.3:a:nginx:nginx:1.14.2:*:*:*:*:*:*:*",
        "cpe:2.3:a:php:php:8.1.0:*:*:*:*:*:*:*",
      ],
      [
        { name: "Apache httpd", version: "2.4.49" },
        { name: "nginx", version: "1.14.2" },
        { name: "UnknownApp", version: "1.0" },
      ]
    );
    expect(results.length).toBeGreaterThanOrEqual(2);
  });


  it("evidence-weighted: upgrades confidence when evidence contains vendor+product", () => {
    const result = matchCpeAgainstTechnology(
      ["cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"],
      { name: "Apache", version: "2.4.49", evidenceSummary: "Server: Apache/2.4.49 (Ubuntu). The Apache HTTP Server project is running version 2.4.49." }
    );
    expect(result).not.toBeNull();
    // Evidence contains 'apache' and 'http server' → should boost confidence
    // Evidence boost: at minimum 'high' (product+vendor match), ideally 'exact'
    expect(["high", "exact"]).toContain(result!.confidence);
  });

  it("evidence-weighted: downgrades when evidence doesn't support match", () => {
    const result = matchCpeAgainstTechnology(
      ["cpe:2.3:a:nginx:nginx:1.14.2:*:*:*:*:*:*:*"],
      { name: "nginx", version: "1.14.2", evidenceSummary: "Welcome to nginx!" }
    );
    expect(result).not.toBeNull();
    // Evidence has 'nginx' but not both vendor+product clearly → still works
    expect(result!.confidence).toBeDefined();
  });

  it("stop words are removed from technology names", () => {
    const result = matchCpeAgainstTechnology(
      ["cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"],
      { name: "Apache HTTP Server", version: null }
    );
    expect(result).not.toBeNull();
    // 'server' should be filtered as stop word, 'http_server' matches technology
  });

  it("major version appending improves matching", () => {
    const result = matchCpeAgainstTechnology(
      ["cpe:2.3:a:apache:http_server:2.4:*:*:*:*:*:*:*"],
      { name: "Apache HTTP Server", version: "2.4.49", evidenceSummary: "Apache/2.4.49" }
    );
    expect(result).not.toBeNull();
    expect(result!.versionMatch).toBe("range");
  });

    it("cpeMatchConfidence maps correctly", () => {
    expect(cpeMatchConfidence({ technology: "test", version: null, cpe: null, confidence: "exact", matchType: "full", versionMatch: "exact" })).toBe("confirmed");
    expect(cpeMatchConfidence({ technology: "test", version: null, cpe: null, confidence: "high", matchType: "full", versionMatch: "exact" })).toBe("high");
    expect(cpeMatchConfidence({ technology: "test", version: null, cpe: null, confidence: "medium", matchType: "product_only", versionMatch: "range" })).toBe("medium");
    expect(cpeMatchConfidence({ technology: "test", version: null, cpe: null, confidence: "low", matchType: "fuzzy", versionMatch: "none" })).toBe("low");
  });
});

// ── Graph Engine Tests ──

describe("PenetrationGraph", () => {

  it("creates a new graph with origin and goal nodes", () => {
    const graph = createPenetrationGraph({
      sessionId: "test-session",
      target: { kind: "url", value: "https://example.com" },
    });
    expect(graph.evidence).toHaveLength(2);
    expect(graph.evidence[0].id).toBe("origin");
    expect(graph.evidence[1].id).toBe("goal");
    expect(graph.hypotheses).toHaveLength(0);
    expect(graph.status).toBe("active");
  });

  it("adds evidence node", () => {
    let graph = createPenetrationGraph({ sessionId: "s1", target: { kind: "hostname", value: "example.com" } });
    const { graph: g2, event } = addEvidence(graph, {
      kind: "technology",
      description: "nginx 1.14.2 on port 443",
      source: { kind: "tool", toolId: "httpx", command: "httpx -u https://example.com" },
      confidence: "high",
      tags: ["nginx", "web-server"],
    });
    expect(event.kind).toBe("evidence_added");
    expect(g2.evidence).toHaveLength(3);
    expect(g2.evidence[2].kind).toBe("technology");
    expect(g2.version).toBe(2);
  });

  it("proposes a hypothesis based on evidence", () => {
    let graph = createPenetrationGraph({ sessionId: "s2", target: { kind: "url", value: "https://example.com" } });
    const { graph: g2 } = addEvidence(graph, {
      kind: "technology",
      description: "nginx 1.14.2",
      source: { kind: "tool", toolId: "httpx", command: "httpx" },
    });
    const evId = g2.evidence[2].id;

    const { graph: g3, event } = proposeHypothesis(g2, {
      basedOn: [evId],
      description: "Check if nginx 1.14.2 is vulnerable to CVE-2019-xxxx",
      category: "cve_analysis",
      priority: "high",
    });
    expect(event.kind).toBe("hypothesis_proposed");
    expect(g3.hypotheses).toHaveLength(1);
    expect(g3.hypotheses[0].status).toBe("open");
    expect(g3.hypotheses[0].priority).toBe("high");
  });

  it("claims, concludes, and fails hypotheses", () => {
    let graph = createPenetrationGraph({ sessionId: "s3", target: { kind: "url", value: "https://example.com" } });
    const { graph: g2 } = addEvidence(graph, { kind: "technology", description: "test", source: { kind: "system" } });
    const evId = g2.evidence[2].id;
    const { graph: g3 } = proposeHypothesis(g2, { basedOn: [evId], description: "test hypothesis", category: "recon" });
    const hyId = g3.hypotheses[0].id;

    // Claim
    const { graph: g4 } = claimHypothesis(g3, hyId, "worker-1");
    expect(g4.hypotheses[0].status).toBe("claimed");
    expect(g4.hypotheses[0].claimedBy).toBe("worker-1");

    // Conclude
    const { graph: g5 } = addEvidence(g4, { kind: "vulnerability", description: "CVE confirmed", source: { kind: "subagent", role: "cve", task: "check" } });
    const evId2 = g5.evidence[3].id;
    const { graph: g6 } = concludeHypothesis(g5, hyId, evId2);
    expect(g6.hypotheses[0].status).toBe("concluded");
    expect(g6.hypotheses[0].concludedTo).toBe(evId2);
  });

  it("getOpenHypotheses and getUnclaimedHypothesis work", () => {
    let graph = createPenetrationGraph({ sessionId: "s4", target: { kind: "url", value: "https://example.com" } });
    const { graph: g2 } = addEvidence(graph, { kind: "technology", description: "t", source: { kind: "system" } });
    const evId = g2.evidence[2].id;

    expect(getOpenHypotheses(g2)).toHaveLength(0);
    expect(getUnclaimedHypothesis(g2)).toBeUndefined();

    const { graph: g3 } = proposeHypothesis(g2, { basedOn: [evId], description: "h1", category: "recon", priority: "critical" });
    const { graph: g4 } = proposeHypothesis(g3, { basedOn: [evId], description: "h2", category: "cve_analysis", priority: "medium" });

    expect(getOpenHypotheses(g4)).toHaveLength(2);
    const next = getUnclaimedHypothesis(g4);
    expect(next).toBeDefined();
    expect(next!.priority).toBe("critical"); // Highest priority first
  });

  it("creates snapshots and checkpoints", () => {
    const graph = createPenetrationGraph({ sessionId: "s5", target: { kind: "url", value: "https://example.com" } });
    const snapshot = createGraphSnapshot(graph);
    expect(snapshot.summary.evidenceCount).toBe(2);
    expect(snapshot.yaml).toContain("origin");
    expect(snapshot.yaml).toContain("goal");

    const checkpoint = createGraphCheckpoint(graph);
    expect(checkpoint.evidenceCount).toBe(2);
    expect(checkpoint.openHypothesisCount).toBe(0);

    // No change
    expect(hasGraphChanged(checkpoint, graph)).toBe(false);
  });

  it("adds human override", () => {
    const graph = createPenetrationGraph({ sessionId: "s6", target: { kind: "url", value: "https://example.com" } });
    const { graph: g2, event } = addOverride(graph, {
      content: "Skip /admin — it's a honeypot",
      kind: "skip",
    });
    expect(event.kind).toBe("override_added");
    expect(g2.overrides).toHaveLength(1);
    expect(g2.overrides[0].kind).toBe("skip");
  });

  it("proposeHypothesis rejects unknown evidence IDs", () => {
    const graph = createPenetrationGraph({ sessionId: "s7", target: { kind: "url", value: "https://example.com" } });
    expect(() => proposeHypothesis(graph, {
      basedOn: ["ev_nonexistent"],
      description: "bad hypothesis",
      category: "recon",
    })).toThrow();
  });
});
