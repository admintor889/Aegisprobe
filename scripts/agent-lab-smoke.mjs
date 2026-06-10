#!/usr/bin/env node
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { spawn } from "node:child_process";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { AuditStore } from "../packages/storage/dist/index.js";
import { MainAgent } from "../packages/core/dist/index.js";
import { loadConfig, OpenAICompatibleProvider } from "../packages/provider/dist/index.js";

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");

function parseArgs(argv) {
  const parsed = {
    case: "vulhub-struts2-s2-045",
    cases: join(repoRoot, "scripts", "agent-lab-smoke-cases.json"),
    maxToolRounds: 24,
    activeProof: false,
    startTarget: false,
    allowFail: false
  };
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (arg === "--case") parsed.case = requireValue(argv, ++index, arg);
    else if (arg === "--cases") parsed.cases = resolve(repoRoot, requireValue(argv, ++index, arg));
    else if (arg === "--target") parsed.target = requireValue(argv, ++index, arg);
    else if (arg === "--db") parsed.db = resolve(repoRoot, requireValue(argv, ++index, arg));
    else if (arg === "--out") parsed.out = resolve(repoRoot, requireValue(argv, ++index, arg));
    else if (arg === "--max-tool-rounds") {
      parsed.maxToolRounds = Number.parseInt(requireValue(argv, ++index, arg), 10);
    } else if (arg === "--decision-iterations") {
      requireValue(argv, ++index, arg);
    } else if (arg === "--max-pages") {
      requireValue(argv, ++index, arg);
    } else if (arg === "--active-proof") parsed.activeProof = true;
    else if (arg === "--start-target") parsed.startTarget = true;
    else if (arg === "--allow-fail") parsed.allowFail = true;
    else if (arg === "--help" || arg === "-h") parsed.help = true;
    else throw new Error(`Unknown argument: ${arg}`);
  }
  return parsed;
}

function requireValue(argv, index, flag) {
  const value = argv[index];
  if (!value || value.startsWith("--")) throw new Error(`${flag} requires a value`);
  return value;
}

function usage() {
  return [
    "Usage: node scripts/agent-lab-smoke.mjs [options]",
    "",
    "Runs the real AgentThread against a local lab. Known proof material is never",
    "loaded into the agent process; optional proof is evaluated by a separate process.",
    "",
    "  --case <id>",
    "  --target <url>",
    "  --db <path>",
    "  --out <path>",
    "  --max-tool-rounds <n>",
    "  --active-proof",
    "  --start-target",
    "  --allow-fail",
    "  -h, --help"
  ].join("\n");
}

function loadPublicCase(filePath, id) {
  const raw = JSON.parse(readFileSync(filePath, "utf8"));
  const selected = raw.cases?.find((item) => item.id === id);
  if (!selected) {
    const available = raw.cases?.map((item) => item.id).join(", ") || "none";
    throw new Error(`Smoke case not found: ${id}. Available: ${available}`);
  }
  const { safeProof: _privateEvaluatorData, expect: _legacyAssertions, ...publicCase } = selected;
  return publicCase;
}

function defaultOutputPaths(caseId) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  const dir = join(repoRoot, "data", "lab-smoke");
  return {
    db: join(dir, `${caseId}-${stamp}.sqlite`),
    out: join(dir, `${caseId}-${stamp}.json`)
  };
}

async function runEvaluator(options, target) {
  if (!options.activeProof) {
    return { status: "skipped", reason: "run with --active-proof to invoke the isolated evaluator" };
  }
  const evaluatorPath = join(repoRoot, "scripts", "lab-proof-evaluator.mjs");
  const args = [
    evaluatorPath,
    "--case", options.case,
    "--cases", options.cases,
    "--target", target
  ];
  return await new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(process.execPath, args, {
      cwd: repoRoot,
      stdio: ["ignore", "pipe", "pipe"],
      windowsHide: true
    });
    const stdout = [];
    const stderr = [];
    child.stdout.on("data", (chunk) => stdout.push(Buffer.from(chunk)));
    child.stderr.on("data", (chunk) => stderr.push(Buffer.from(chunk)));
    child.on("error", rejectPromise);
    child.on("close", (code) => {
      const out = Buffer.concat(stdout).toString("utf8").trim();
      const err = Buffer.concat(stderr).toString("utf8").trim();
      if (code !== 0) {
        rejectPromise(new Error(`Proof evaluator exited ${code}: ${err || out}`));
        return;
      }
      try {
        resolvePromise(JSON.parse(out));
      } catch (error) {
        rejectPromise(new Error(`Proof evaluator returned invalid JSON: ${error.message}\n${out}\n${err}`));
      }
    });
  });
}

async function startTargetIfRequested(options, caseSpec) {
  if (!options.startTarget) return undefined;
  const config = caseSpec.start;
  if (!config) throw new Error(`Case ${caseSpec.id} has no start config.`);
  const readyUrl = config.readyUrl || caseSpec.target?.defaultUrl;
  if (readyUrl && await isHttpReady(readyUrl)) {
    return { alreadyRunning: true, stop: async () => undefined };
  }
  const logs = [];
  const child = spawn(config.command, Array.isArray(config.args) ? config.args : [], {
    cwd: config.cwd ? resolve(repoRoot, config.cwd) : repoRoot,
    env: { ...process.env, ...(config.env || {}) },
    stdio: ["ignore", "pipe", "pipe"],
    windowsHide: true
  });
  child.stdout?.on("data", (chunk) => logs.push(String(chunk)));
  child.stderr?.on("data", (chunk) => logs.push(String(chunk)));
  if (readyUrl) await waitForHttpReady(readyUrl, config.timeoutMs || 20_000, logs);
  return {
    alreadyRunning: false,
    processId: child.pid,
    stop: async () => {
      if (!child.killed) {
        child.kill();
        await new Promise((resolvePromise) => setTimeout(resolvePromise, 500));
      }
    }
  };
}

async function waitForHttpReady(url, timeoutMs, logs) {
  const startedAt = Date.now();
  while (Date.now() - startedAt < timeoutMs) {
    if (await isHttpReady(url)) return;
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 250));
  }
  throw new Error(`Target did not become ready at ${url} within ${timeoutMs}ms.\n${logs.join("").slice(-4000)}`);
}

async function isHttpReady(url) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 1_500);
  try {
    const response = await fetch(url, { method: "GET", redirect: "manual", signal: controller.signal });
    return response.status > 0;
  } catch {
    return false;
  } finally {
    clearTimeout(timer);
  }
}

function summarizeToolMessages(messages) {
  return messages
    .filter((message) => message.role === "tool")
    .map((message) => {
      try {
        const envelope = JSON.parse(message.content);
        return {
          tool: envelope.tool,
          status: envelope.status,
          exitCode: envelope.exitCode,
          durationMs: envelope.durationMs,
          stdoutBytes: envelope.truncated?.stdoutBytes,
          stderrBytes: envelope.truncated?.stderrBytes,
          artifacts: envelope.artifacts
        };
      } catch {
        return { tool: "unparsed", status: "error" };
      }
    });
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (options.help) {
    console.log(usage());
    return;
  }

  const caseSpec = loadPublicCase(options.cases, options.case);
  const target = options.target || caseSpec.target?.defaultUrl;
  if (!target) throw new Error(`Case ${caseSpec.id} has no target URL.`);
  const defaults = defaultOutputPaths(caseSpec.id);
  const dbPath = options.db || defaults.db;
  const outPath = options.out || defaults.out;
  mkdirSync(dirname(dbPath), { recursive: true });
  mkdirSync(dirname(outPath), { recursive: true });

  const targetProcess = await startTargetIfRequested(options, caseSpec);
  const store = new AuditStore(dbPath);
  const startedAt = Date.now();
  try {
    const provider = new OpenAICompatibleProvider(loadConfig().provider);
    const agent = new MainAgent({
      store,
      provider,
      approve: async () => options.activeProof,
      projectRoot: repoRoot
    });
    const sessionId = agent.createSession(`agent-thread-lab: ${caseSpec.id}`);
    const events = [];
    for await (const event of agent.runConversationTurn(sessionId, target, {
      maxToolRounds: Number.isFinite(options.maxToolRounds) ? options.maxToolRounds : 24
    })) {
      events.push(event);
    }

    const evaluator = await runEvaluator(options, target);
    const messages = store.listConversationMessages(sessionId, 2_000);
    const turnError = events.find((event) => event.kind === "turn_error");
    const agentCompleted = events.some((event) => event.kind === "turn_complete") && !turnError;
    const evaluatorPassed = evaluator.status === "validated";
    const report = {
      caseId: caseSpec.id,
      caseName: caseSpec.name,
      target,
      sessionId,
      dbPath,
      reportPath: outPath,
      architecture: {
        entry: "AgentThread",
        userMessage: target,
        proofEvaluatorProcess: "scripts/lab-proof-evaluator.mjs",
        proofDataLoadedByAgent: false
      },
      timings: { totalMs: Date.now() - startedAt },
      agent: {
        completed: agentCompleted,
        error: turnError?.error,
        assistantMessages: messages
          .filter((message) => message.role === "assistant")
          .map((message) => message.content),
        toolCalls: summarizeToolMessages(messages)
      },
      evaluator,
      targetProcess: targetProcess ? {
        started: !targetProcess.alreadyRunning,
        alreadyRunning: Boolean(targetProcess.alreadyRunning),
        processId: targetProcess.processId
      } : undefined
    };
    report.passed = options.activeProof ? agentCompleted && evaluatorPassed : agentCompleted;
    writeFileSync(outPath, `${JSON.stringify(report, null, 2)}\n`, "utf8");
    console.log(JSON.stringify({
      passed: report.passed,
      caseId: report.caseId,
      target: report.target,
      sessionId: report.sessionId,
      reportPath: outPath,
      agent: {
        completed: report.agent.completed,
        toolCalls: report.agent.toolCalls
      },
      evaluator: report.evaluator
    }, null, 2));
    if (!report.passed && !options.allowFail) process.exitCode = 1;
  } finally {
    store.close();
    await targetProcess?.stop?.();
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.stack || error.message : String(error));
  process.exitCode = 1;
});
