#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const value = argv[index + 1];
    if (!value) throw new Error(`${arg} requires a value`);
    if (arg === "--case") parsed.case = value;
    else if (arg === "--cases") parsed.cases = resolve(value);
    else if (arg === "--target") parsed.target = value;
    else throw new Error(`Unknown argument: ${arg}`);
    index += 1;
  }
  return parsed;
}

function loadProof(filePath, id) {
  const raw = JSON.parse(readFileSync(filePath, "utf8"));
  const selected = raw.cases?.find((item) => item.id === id);
  if (!selected) throw new Error(`Evaluator case not found: ${id}`);
  return selected.safeProof;
}

function targetUrl(target, path = "/") {
  return new URL(path, target).href;
}

async function fetchObservation(url, request = {}) {
  const response = await fetch(url, {
    method: request.method || "GET",
    headers: request.headers || {},
    body: request.body,
    redirect: "manual"
  });
  const body = await response.text();
  return {
    url,
    method: request.method || "GET",
    status: response.status,
    statusText: response.statusText,
    headers: Object.fromEntries(response.headers.entries()),
    body,
    bodyBytes: Buffer.byteLength(body, "utf8")
  };
}

function matchesExpected(observation, expect = {}) {
  const statusPassed = expect.status == null || observation.status === expect.status;
  const expectedHeader = expect.header;
  const actualHeader = expectedHeader
    ? observation.headers[String(expectedHeader.name).toLowerCase()]
    : undefined;
  const headerPassed = !expectedHeader
    || (expectedHeader.value != null && actualHeader === expectedHeader.value)
    || (expectedHeader.matches != null && new RegExp(expectedHeader.matches).test(actualHeader || ""));
  const contains = Array.isArray(expect.bodyContains)
    ? expect.bodyContains
    : expect.bodyContains == null ? [] : [expect.bodyContains];
  const matches = Array.isArray(expect.bodyMatches)
    ? expect.bodyMatches
    : expect.bodyMatches == null ? [] : [expect.bodyMatches];
  return {
    passed: statusPassed
      && headerPassed
      && contains.every((value) => observation.body.includes(value))
      && matches.every((value) => new RegExp(value).test(observation.body)),
    actualHeader
  };
}

async function evaluateCommandOutput(proof, target) {
  if (proof.insecureTls) process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
  const url = new URL(targetUrl(target, proof.path || "/"));
  if (proof.scheme) url.protocol = `${proof.scheme}:`;
  for (const [name, value] of Object.entries(proof.query || {})) {
    url.searchParams.set(name, String(value));
  }
  const observation = await fetchObservation(url.href, proof);
  const result = matchesExpected(observation, proof.expect);
  return {
    status: result.passed ? "validated" : "not_observed",
    level: proof.level || "shell",
    serviceCompromised: result.passed && (proof.level || "shell") === "shell",
    finding: result.passed ? proof.finding : undefined,
    observation: redactObservation(observation),
    expected: proof.expect
  };
}

async function evaluateResponseHeader(proof, target) {
  const observation = await fetchObservation(targetUrl(target, proof.path || "/"), proof);
  const expected = { header: proof.expectHeader };
  const result = matchesExpected(observation, expected);
  return {
    status: result.passed ? "validated" : "not_observed",
    level: proof.level || "vulnerability",
    serviceCompromised: false,
    finding: result.passed ? proof.finding : undefined,
    observation: redactObservation(observation),
    expected
  };
}

async function evaluateStatusComparison(proof, target) {
  const control = await fetchObservation(targetUrl(target, proof.control?.path || "/"), proof.control);
  const candidate = await fetchObservation(targetUrl(target, proof.candidate?.path || "/"), proof.candidate);
  const expected = proof.expect || {};
  const passed = (expected.controlStatus == null || control.status === expected.controlStatus)
    && (expected.candidateStatus == null || candidate.status === expected.candidateStatus)
    && (expected.candidateBodyContains == null || candidate.body.includes(expected.candidateBodyContains));
  return {
    status: passed ? "validated" : "not_observed",
    level: proof.level || "vulnerability",
    serviceCompromised: false,
    finding: passed ? proof.finding : undefined,
    control: redactObservation(control),
    candidate: redactObservation(candidate),
    expected
  };
}

async function evaluateMultiRole(proof, target) {
  const contexts = [];
  for (const context of proof.authContexts || []) {
    const username = context.username || context.name;
    const password = context.password || `${username}123`;
    const login = await fetchObservation(targetUrl(target, "/api/login"), {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ username, password })
    });
    const token = JSON.parse(login.body || "{}").token;
    if (!token) throw new Error(`Failed to authenticate evaluator context ${context.name}: HTTP ${login.status}`);
    contexts.push({ ...context, username, token });
  }
  if (contexts.length < 2) throw new Error("multiRoleAuthz evaluator requires at least two contexts");

  const observations = [];
  for (const context of contexts) {
    const headers = { authorization: `Bearer ${context.token}` };
    observations.push({
      context: { name: context.name, role: context.role, tenant: context.tenant },
      adminUser: redactObservation(await fetchObservation(targetUrl(target, "/api/admin/users/1"), { headers })),
      foreignOrder: redactObservation(await fetchObservation(targetUrl(target, "/api/orders/102"), { headers }))
    });
  }
  const customerAdminAccess = observations.some((item) =>
    item.context.role === "customer" && item.adminUser.status >= 200 && item.adminUser.status < 300
  );
  return {
    status: customerAdminAccess ? "validated" : "not_observed",
    level: "vulnerability",
    serviceCompromised: false,
    finding: customerAdminAccess ? {
      title: "Expected authorization policy violation observed",
      severity: "high",
      confidence: "high"
    } : undefined,
    observations
  };
}

function redactObservation(observation) {
  return {
    url: observation.url,
    method: observation.method,
    status: observation.status,
    statusText: observation.statusText,
    headers: observation.headers,
    bodyBytes: observation.bodyBytes,
    bodyExcerpt: observation.body.slice(0, 4_000)
  };
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.case || !options.cases || !options.target) {
    throw new Error("--case, --cases, and --target are required");
  }
  const proof = loadProof(options.cases, options.case);
  if (!proof) {
    console.log(JSON.stringify({ status: "skipped", reason: "case has no proof configuration" }));
    return;
  }

  let result;
  if (proof.kind === "commandOutput") result = await evaluateCommandOutput(proof, options.target);
  else if (proof.kind === "responseHeader") result = await evaluateResponseHeader(proof, options.target);
  else if (proof.kind === "responseStatusComparison") result = await evaluateStatusComparison(proof, options.target);
  else if (proof.kind === "multiRoleAuthz") result = await evaluateMultiRole(proof, options.target);
  else throw new Error(`Unsupported evaluator proof kind: ${proof.kind}`);

  console.log(JSON.stringify({
    evaluator: "isolated-lab-proof",
    caseId: options.case,
    ...result
  }));
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
