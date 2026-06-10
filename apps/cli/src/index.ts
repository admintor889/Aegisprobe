#!/usr/bin/env node
import { existsSync, fstatSync, readFileSync } from "node:fs";
import { dirname, isAbsolute, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { createInterface } from "node:readline/promises";
import { emitKeypressEvents } from "node:readline";
import { stdin as input, stdout as output } from "node:process";
import { fileURLToPath } from "node:url";
import { Command } from "commander";
import iconv from "iconv-lite";
import { MainAgent, type SafeAuthenticatedFetchDetails, type SafeReadOnlyMethod } from "@aegisprobe/core";
import { describeAuthorization } from "@aegisprobe/policy";
import { loadConfig, OpenAICompatibleProvider, resolveDictPaths } from "@aegisprobe/provider";
import { McpManager } from "@aegisprobe/mcp";
import { setShellMode } from "@aegisprobe/shell";
import { extractUrlLikeTargets, parseTargetInput, type IntentExtraction, type SecurityAuthContext, type SecurityValidationAttempt, type SubAgentRecord, type SubAgentRole, type TurnEvent, type TurnResult } from "@aegisprobe/shared";
import { EmptySkillRegistry, FileSkillRegistry } from "@aegisprobe/skills";
import { buildAccessExposureMap, buildPayloadCandidateSet, buildPayloadRequestDraftSet, buildSkillExecutionPlan, checkSecurityToolHealth, getSecurityToolInventory, loadBusinessLogicKnowledge, loadFrameworkKnowledgeIndex, loadSecurityKnowledgeIndex, renderAccessExposureMap, renderPayloadCandidateSet, renderPayloadRequestDraftSet, searchSecurityKnowledge, syncSecurityKnowledge } from "@aegisprobe/security";
import type { AuditStore } from "@aegisprobe/storage";
import { aegisPrompt, printAegisEvent, printChatBanner } from "./terminal-ui.js";

type CliOptions = {
  config?: string;
};

// Only read piped stdin when it is a file/fifo (not a bare process pipe which would block forever)
const pipedAnswers: string[] | null = (() => {
  if (input.isTTY) return null;
  try {
    const st = fstatSync(0);
    // Only read if stdin is a real file (redirected input); skip anonymous pipes
    if (st.isFile()) {
      return decodeStdin(readFileSync(0)).split(/\r?\n/);
    }
  } catch { /* fd 0 not stat-able */ }
  return null;
})();

// Module-level MCP reference for process exit cleanup
let _mcpManagerForCleanup: McpManager | undefined;

process.on("unhandledRejection", (reason) => {
  const message = reason instanceof Error ? reason.message : String(reason);
  console.error(`[unhandledRejection] ${message}`);
  // Don't exit — let the process continue. The error is logged for debugging.
});

process.on("uncaughtException", (error) => {
  console.error(`[uncaughtException] ${error.message}`);
  console.error(error.stack);
  process.exitCode = 1;
});

process.on("exit", () => {
  if (_mcpManagerForCleanup) {
    try { _mcpManagerForCleanup.stopAll(); } catch { /* best effort */ }
  }
});

async function stopMcpManagerForCleanup(): Promise<void> {
  const manager = _mcpManagerForCleanup;
  _mcpManagerForCleanup = undefined;
  if (manager) {
    await manager.stopAll();
  }
}

const emitWarning = process.emitWarning.bind(process);
process.emitWarning = ((warning: string | Error, ...args: Parameters<typeof process.emitWarning> extends [string | Error, ...infer Rest] ? Rest : never[]) => {
  const message = typeof warning === "string" ? warning : warning.message;
  const warningType = typeof args[0] === "string" ? args[0] : undefined;
  const warningName = warning instanceof Error ? warning.name : warningType;
  if (warningName === "ExperimentalWarning" && message.includes("SQLite")) {
    return;
  }
  return emitWarning(warning as Error, ...(args as []));
}) as typeof process.emitWarning;

process.on("warning", (warning) => {
  if (warning.name === "ExperimentalWarning" && warning.message.includes("SQLite")) {
    return;
  }
  console.warn(warning.stack ?? `${warning.name}: ${warning.message}`);
});

function decodeStdin(buffer: Buffer): string {
  const utf8 = buffer.toString("utf8");
  const replacementCount = (utf8.match(/\uFFFD/g) ?? []).length;
  if (replacementCount > 0 || (utf8.includes("?") && /[\x80-\xFF]/.test(buffer.toString("binary")))) {
    return iconv.decode(buffer, "gb18030");
  }
  return utf8;
}

function resolveCliConfigPath(configPath?: string): string {
  if (configPath) {
    return resolve(configPath);
  }
  if (process.env.AEGISPROBE_CONFIG) {
    return resolve(process.env.AEGISPROBE_CONFIG);
  }
  const cwdConfig = resolve("./configs/config.yaml");
  if (existsSync(cwdConfig)) {
    return cwdConfig;
  }

  const cliDir = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    resolve(cliDir, "../../../configs/config.yaml"),
    resolve(cliDir, "../../configs/config.yaml")
  ];
  return candidates.find((candidate) => existsSync(candidate)) ?? cwdConfig;
}

function projectRootFromConfig(configPath?: string): string {
  return resolve(dirname(resolveCliConfigPath(configPath)), "..");
}

async function main(): Promise<void> {
  const program = new Command();
  program
    .name("aegisprobe")
    .description("Codex-like terminal Agent assistant")
    .option("-c, --config <path>", "config yaml path");

  program.command("chat")
    .description("Start an interactive terminal agent session")
    .action(async () => {
      const options = program.opts<CliOptions>();
      await startChat(options);
    });

  program.command("run")
    .description("Create one agent task session for a URL, domain, file path, or prompt")
    .argument("<target-or-file>")
    .action(async (target: string) => {
      const options = program.opts<CliOptions>();
      await runOnce(target, options);
    });

  program.command("sessions")
    .description("List recent saved sessions")
    .option("-n, --limit <number>", "maximum number of sessions to show", "20")
    .action(async (commandOptions: { limit: string }) => {
      const options = program.opts<CliOptions>();
      const limit = Number.parseInt(commandOptions.limit, 10);
      await listSessions(options, Number.isFinite(limit) ? limit : 20);
    });

  program.command("skills")
    .description("List or search loaded skills")
    .argument("[query...]")
    .option("-n, --limit <number>", "maximum number of skills to show", "20")
    .action(async (queryParts: string[], commandOptions: { limit: string }) => {
      const options = program.opts<CliOptions>();
      const limit = Number.parseInt(commandOptions.limit, 10);
      const registry = createSkillRegistry(options.config);
      const query = queryParts.join(" ").trim();
      const skills = query
        ? await registry.search(query, { limit: Number.isFinite(limit) ? limit : 20, includeHighRisk: true })
        : (await registry.list()).slice(0, Number.isFinite(limit) ? limit : 20);
      if (skills.length === 0) {
        console.log("No skills found.");
        return;
      }
      console.log(query ? `Matched Skills: ${query}` : "Loaded Skills");
      for (const skill of skills) {
        console.log(`- ${skill.id} | ${skill.category} | risk:${skill.risk_level} | ${skill.name}`);
        if (skill.description) {
          console.log(`  ${skill.description}`);
        }
      }
    });

  program.command("skill")
    .description("Show one loaded skill")
    .argument("<id-or-name>")
    .action(async (id: string) => {
      const options = program.opts<CliOptions>();
      const registry = createSkillRegistry(options.config);
      const skill = await registry.get(id);
      if (!skill) {
        console.log(`Skill not found: ${id}`);
        return;
      }
      console.log(`${skill.id} | ${skill.name}`);
      console.log(`category: ${skill.category}`);
      console.log(`risk: ${skill.risk_level}`);
      console.log(`approval: ${skill.requires_approval ? "required" : "not required"}`);
      if (skill.path) {
        console.log(`path: ${skill.path}`);
      }
      if (skill.description) {
        console.log(`description: ${skill.description}`);
      }
      if (skill.tools.length > 0) {
        console.log(`tools: ${skill.tools.join(", ")}`);
      }
      if (skill.workflow.length > 0) {
        console.log(`workflow: ${skill.workflow.join(" -> ")}`);
      }
      if (skill.outputs.length > 0) {
        console.log(`outputs: ${skill.outputs.join(", ")}`);
      }
    });

  program.command("skill-plan")
    .description("Compile matched skills into a policy-controlled execution plan")
    .argument("<query...>")
    .option("-n, --limit <number>", "maximum number of skills to use", "8")
    .action(async (queryParts: string[], commandOptions: { limit: string }) => {
      const options = program.opts<CliOptions>();
      const registry = createSkillRegistry(options.config);
      const limit = Number.parseInt(commandOptions.limit, 10);
      const plan = await buildSkillExecutionPlan(queryParts.join(" "), registry, {
        limit: Number.isFinite(limit) ? limit : 8,
        includeHighRisk: true
      });
      console.log(plan.prompt);
    });

  program.command("tools")
    .description("List configured local security tools and adapter availability")
    .option("--check", "run a short local version/help check for each configured binary")
    .action(async (commandOptions: { check?: boolean }) => {
      const options = program.opts<CliOptions>();
      printToolInventory(Boolean(commandOptions.check), projectRootFromConfig(options.config));
    });

  program.command("lab-vbox-list")
    .description("List local VirtualBox VMs and candidate lab IP hints")
    .action(async () => {
      printVirtualBoxLabs();
    });

  program.command("lab-vbox-start")
    .description("Start a local VirtualBox VM for authorized lab testing")
    .argument("<name-or-uuid>")
    .option("--headless", "start without showing a VM window")
    .action(async (nameOrUuid: string, commandOptions: { headless?: boolean }) => {
      const mode = commandOptions.headless ? "headless" : "gui";
      const result = runVBoxManage(["startvm", nameOrUuid, "--type", mode]);
      console.log(result.output || `VBoxManage startvm exited with ${result.exitCode}`);
    });

  program.command("lab-vbox-discover")
    .description("Show VirtualBox VM network and guest-property IP hints")
    .argument("[name-or-uuid]")
    .action(async (nameOrUuid?: string) => {
      printVirtualBoxLabs(nameOrUuid);
    });

  const knowledge = program.command("knowledge")
    .description("Manage local CVE/template, framework/CMS, and business-logic security knowledge");

  knowledge.command("sync")
    .description("Build the local knowledge index from tools/templates/nuclei-templates")
    .action(async () => {
      const options = program.opts<CliOptions>();
      const result = syncSecurityKnowledge(projectRootFromConfig(options.config));
      console.log("Security knowledge synced.");
      console.log(`- index: ${result.indexPath}`);
      console.log(`- business logic: ${result.businessLogicPath}`);
      console.log(`- framework knowledge: ${result.frameworkKnowledgePath}`);
      console.log(`- templates: ${result.templateCount}`);
      console.log(`- CVE templates: ${result.cveTemplateCount}`);
      console.log(`- CVEs: ${result.cveCount}`);
      console.log(`- framework/CMS profiles: ${result.frameworkProfileCount}`);
    });

  knowledge.command("stats")
    .description("Show local security knowledge statistics")
    .action(async () => {
      const options = program.opts<CliOptions>();
      printKnowledgeStats(projectRootFromConfig(options.config));
    });

  knowledge.command("search")
    .description("Search local CVE/template, framework/CMS, and business-logic knowledge")
    .argument("<query...>")
    .option("-n, --limit <number>", "maximum results to show", "20")
    .action(async (queryParts: string[], commandOptions: { limit: string }) => {
      const options = program.opts<CliOptions>();
      const limit = Number.parseInt(commandOptions.limit, 10);
      printKnowledgeSearch(queryParts.join(" "), Number.isFinite(limit) ? limit : 20, projectRootFromConfig(options.config));
    });

  program.command("shell-mode")
    .description("Switch shell execution mode: auto, powershell, or wsl")
    .argument("[mode]", "auto | powershell | wsl (omit to show current)")
    .action(async (mode?: string) => {
      const { readFileSync, writeFileSync } = await import("fs");
      const { resolve: res } = await import("path");
      const configPath = resolveCliConfigPath();
      const raw = readFileSync(configPath, "utf8");
      const current = raw.match(/shell:\s*(\w+)/)?.[1] ?? "auto";

      if (!mode) {
        console.log(`Current shell mode: ${current}`);
        console.log(`  auto       → auto-detect (WSL=bash, Windows=PowerShell)`);
        console.log(`  powershell → force PowerShell even in WSL`);
        console.log(`  wsl        → force WSL bash even from Windows`);
        return;
      }

      if (!["auto", "powershell", "wsl"].includes(mode)) {
        console.log(`Invalid mode: ${mode}. Use: auto | powershell | wsl`);
        return;
      }

      const updated = raw.replace(/shell:\s*\w+/, `shell: ${mode}`);
      writeFileSync(configPath, updated, "utf8");
      setShellMode(mode as "auto" | "powershell" | "wsl");
      console.log(`Shell mode: ${current} → ${mode} (restart required for full effect on new agents)`);
    });

  const fofa = program.command("fofa")
    .description("Search FOFA network space engine for subdomains, services, and certificates");

  fofa.command("subdomain")
    .description("Search FOFA for subdomains of a domain")
    .argument("<domain>")
    .option("-n, --limit <number>", "max results", "200")
    .action(async (domain: string, cmdOpts: { limit: string; csv?: string }) => {
      const options = program.opts<CliOptions>();
      const config = loadConfig(resolveCliConfigPath(options.config));
      const { fofaSearchSubdomains, fofaExportCsv, renderFofaResults } = await import("@aegisprobe/security");
      const result = await fofaSearchSubdomains(domain, config.fofa);
      if (cmdOpts.csv) console.log(`CSV exported: ${fofaExportCsv(result, cmdOpts.csv)}`);
      console.log(renderFofaResults(result, Number.parseInt(cmdOpts.limit, 10)));
    });

  fofa.command("ip")
    .description("Search FOFA for services on an IP")
    .argument("<ip>")
    .option("-n, --limit <number>", "max results", "200")
    .action(async (ip: string, cmdOpts: { limit: string; csv?: string }) => {
      const options = program.opts<CliOptions>();
      const config = loadConfig(resolveCliConfigPath(options.config));
      const { fofaSearchByIp, fofaExportCsv, renderFofaResults } = await import("@aegisprobe/security");
      const result = await fofaSearchByIp(ip, config.fofa);
      if (cmdOpts.csv) console.log(`CSV exported: ${fofaExportCsv(result, cmdOpts.csv)}`);
      console.log(renderFofaResults(result, Number.parseInt(cmdOpts.limit, 10)));
    });

  fofa.command("cert")
    .description("Search FOFA by SSL certificate domain")
    .argument("<domain>")
    .option("-n, --limit <number>", "max results", "200")
    .action(async (domain: string, cmdOpts: { limit: string; csv?: string }) => {
      const options = program.opts<CliOptions>();
      const config = loadConfig(resolveCliConfigPath(options.config));
      const { fofaSearchByCert, fofaExportCsv, renderFofaResults } = await import("@aegisprobe/security");
      const result = await fofaSearchByCert(domain, config.fofa);
      if (cmdOpts.csv) console.log(`CSV exported: ${fofaExportCsv(result, cmdOpts.csv)}`);
      console.log(renderFofaResults(result, Number.parseInt(cmdOpts.limit, 10)));
    });

  fofa.command("search")
    .description("Search FOFA with a raw query (domain=, ip=, cert=, title=, etc.)")
    .argument("<query...>")
    .option("-n, --limit <number>", "max results", "200")
    .action(async (queryParts: string[], cmdOpts: { limit: string; csv?: string }) => {
      const options = program.opts<CliOptions>();
      const config = loadConfig(resolveCliConfigPath(options.config));
      const { fofaSearch, fofaExportCsv, renderFofaResults } = await import("@aegisprobe/security");
      const result = await fofaSearch(queryParts.join(" "), config.fofa, Number.parseInt(cmdOpts.limit, 10));
      if (cmdOpts.csv) console.log(`CSV exported: ${fofaExportCsv(result, cmdOpts.csv)}`);
      console.log(renderFofaResults(result, Number.parseInt(cmdOpts.limit, 10)));
    });

  program.command("exploit")
    .description("CVE exploit knowledge base — search, sync, and payload generation")
    .argument("[query]", "CVE ID, product name, or keyword to search", "")
    .option("--sync", "rebuild the CVE exploit index from local nuclei templates")
    .option("-n, --limit <number>", "max results", "20")
    .action(async (query: string, cmdOpts: { sync?: boolean; limit: string }) => {
      const options = program.opts<CliOptions>();
      const projectRoot = projectRootFromConfig(options.config);
      const { syncCveExploitIndex, searchCveExploitIndex, renderCveExploitStats, renderPayloadLibrary } = await import("@aegisprobe/security");

      if (cmdOpts.sync) {
        const index = syncCveExploitIndex(projectRoot);
        console.log(renderCveExploitStats(index));
        return;
      }

      if (!query) {
        console.log("Usage: aegisprobe exploit <query> [--sync]");
        console.log("  aegisprobe exploit --sync          Rebuild CVE index from nuclei templates");
        console.log("  aegisprobe exploit CVE-2021-41773  Search for specific CVE");
        console.log("  aegisprobe exploit apache           Search by product name");
        console.log("  aegisprobe exploit payloads         Show payload generation library");
        console.log("");
        const indexPath = `${projectRoot}/data/cve-exploit-kb/cve-index.json`;
        const { existsSync } = await import("node:fs");
        if (existsSync(indexPath)) {
          console.log(`CVE index exists. Run with --sync to rebuild, or provide a query to search.`);
        } else {
          console.log(`No CVE index found. Run with --sync first.`);
        }
        return;
      }

      if (query === "payloads" || query === "library") {
        console.log(renderPayloadLibrary());
        return;
      }

      const results = searchCveExploitIndex(query, projectRoot);
      if (results.length === 0) {
        console.log(`No CVE matches found for "${query}". Try --sync first if you haven't built the index.`);
        return;
      }
      const limit = Number.parseInt(cmdOpts.limit, 10);
      console.log(`Found ${results.length} CVE(s) matching "${query}"${results.length > limit ? ` (showing ${limit})` : ""}:`);
      console.log("");
      for (const entry of results.slice(0, limit)) {
        const icon = entry.severity === "critical" ? "🔴" : entry.severity === "high" ? "🟠" : entry.severity === "medium" ? "🟡" : "🔵";
        console.log(`${icon} ${entry.cveId} [${entry.severity}] — ${entry.name}`);
        console.log(`   Product: ${entry.product} | Year: ${entry.year}`);
        console.log(`   Template: ${entry.templatePath}`);
        console.log("");
      }
    });

  const shell = program.command("shell")
    .description("Reverse shell session management");

  shell.command("listen")
    .description("Start a reverse shell listener on a port")
    .argument("<port>")
    .option("--timeout <ms>", "listener timeout in ms", "120000")
    .action(async (port: string, cmdOpts: { timeout: string }) => {
      const { startShellListener } = await import("@aegisprobe/shell");
      const session = startShellListener(Number.parseInt(port, 10), Number.parseInt(cmdOpts.timeout, 10));
      console.log(`Listener started: ${session.id} on port ${session.port}`);
      console.log(`Status: ${session.status}. Waiting for connection...`);
    });

  shell.command("sessions")
    .description("List active reverse shell sessions")
    .action(async () => {
      const { getShellSessions } = await import("@aegisprobe/shell");
      const sessions = getShellSessions();
      if (sessions.length === 0) {
        console.log("No active shell sessions.");
        return;
      }
      for (const s of sessions) {
        console.log(`${s.id} | port:${s.port} | ${s.status} | ${s.startedAt}`);
        if (s.output) console.log(`  output: ${s.output.slice(-200)}`);
      }
    });

  shell.command("exec")
    .description("Execute a command on a connected shell session")
    .argument("<session-id>")
    .argument("<command...>")
    .action(async (sessionId: string, commandParts: string[]) => {
      const { sendShellCommand } = await import("@aegisprobe/shell");
      const result = sendShellCommand(sessionId, commandParts.join(" "));
      console.log(result);
    });

  shell.command("close")
    .description("Close a shell session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const { killShellSession } = await import("@aegisprobe/shell");
      killShellSession(sessionId);
      console.log(`Session ${sessionId} closed.`);
    });

  program.command("dict")
    .description("Show configured dictionary paths for password/user/directory/subdomain brute-force")
    .action(async () => {
      const options = program.opts<CliOptions>();
      const config = loadConfig(resolveCliConfigPath(options.config));
      const projectRoot = projectRootFromConfig(options.config);
      const paths = resolveDictPaths(config, projectRoot);
      console.log("Dictionary Configuration:");
      console.log(`  enabled: ${config.dicts.enabled}`);
      console.log(`  roots:  ${config.dicts.roots.join(", ")}`);
      console.log("");
      console.log(`  password:   ${paths.password ?? "NOT FOUND"}`);
      console.log(`  username:   ${paths.username ?? "NOT FOUND"}`);
      console.log(`  directory:  ${paths.directory ?? "NOT FOUND"}`);
      console.log(`  subdomain:  ${paths.subdomain ?? "NOT FOUND"}`);
      console.log(`  api:        ${paths.api ?? "NOT FOUND"}`);
    });

  program.command("resume")
    .description("Resume an existing saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      await startChat(options, sessionId);
    });

  program.command("agents")
    .description("List subagents for a saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      printSubAgents(agent, sessionId);
    });

  program.command("agent")
    .description("Show one subagent detail")
    .argument("<session-id>")
    .argument("<agent-id>")
    .action(async (sessionId: string, agentId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printSubAgentDetail(agent, sessionId, agentId);
    });

  program.command("wait-agent")
    .description("Wait for a subagent to leave running status")
    .argument("<session-id>")
    .argument("<agent-id>")
    .option("-t, --timeout <ms>", "wait timeout in milliseconds", "60000")
    .action(async (sessionId: string, agentId: string, commandOptions: { timeout: string }) => {
      const options = program.opts<CliOptions>();
      const timeoutMs = Number.parseInt(commandOptions.timeout, 10);
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const record = await agent.waitSubAgent(sessionId, agentId, Number.isFinite(timeoutMs) ? timeoutMs : 60_000);
      if (!record || record.sessionId !== sessionId) {
        throw new Error(`Subagent not found: ${agentId}`);
      }
      printSubAgentRecord(record, true);
    });

  program.command("diff")
    .description("Show audited file changes for a saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printFileChanges(agent, sessionId);
    });

  program.command("context")
    .description("Show the Codex-like context snapshot for a saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      console.log(agent.renderContextSnapshot(sessionId));
    });

  program.command("probe")
    .description("Run a built-in approval-gated DNS/HTTP security probe for a saved session")
    .argument("<session-id>")
    .argument("<target>")
    .argument("[probe]", "basic_recon, dns, or http_headers", "basic_recon")
    .action(async (sessionId: string, target: string, probe: string) => {
      const options = program.opts<CliOptions>();
      const rl = createInterface({ input, output });
      try {
        const agent = await createAgent(options.config, rl, undefined, undefined, { enableMcp: false });
        if (!agent.hasSession(sessionId)) {
          throw new Error(`Session not found: ${sessionId}`);
        }
        const summary = await agent.executeSecurityProbe(sessionId, target, normalizeProbe(probe));
        console.log(summary);
      } finally {
        rl.close();
        await stopMcpManagerForCleanup();
      }
    });

  program.command("pentest")
    .description("Start or resume a persistent security-agent conversation")
    .argument("<target>")
    .option("--active", "allow approval-gated active scanners such as nuclei/dirsearch/nmap")
    .option("--deep", "prefer a more thorough, higher-budget assessment")
    .option("--allow-cidr", "allow C-segment/CIDR discovery steps when active probing is enabled")
    .option("--rate <number>", "maximum tool rate limit per second", "2")
    .option("--browser", "start MCP/Playwright browser tools for this pentest")
    .option("--yes", "skip authorization prompt (for automated/background runs)")
    .option("--resume", "resume an existing pentest session (target is session-id)")
    .option("--webui", "bridge events to the AegisProbe Web UI at http://127.0.0.1:3200")
    .option("--webui-url <url>", "custom Web UI URL for event bridging", "http://127.0.0.1:3200")
    .action(async (target: string, commandOptions: { active?: boolean; deep?: boolean; allowCidr?: boolean; rate: string; browser?: boolean; yes?: boolean; resume?: boolean; webui?: boolean; webuiUrl?: string }) => {
      const options = program.opts<CliOptions>();
      const rl = createInterface({ input, output });
      const webuiUrl = commandOptions.webui ? (commandOptions.webuiUrl ?? "http://127.0.0.1:3200") : null;
      try {
        const autoApprove = { active: false };

        // Compose onEvent: print to console + bridge to Web UI
        const composedOnEvent = (event: TurnEvent) => {
          printRealtimeEvent(event);
          if (webuiUrl) {
            // Fire-and-forget POST to Web UI
            fetch(`${webuiUrl}/api/events`, {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify(event),
            }).catch(() => { /* webui may not be running */ });
          }
        };

        const agent = await createAgent(options.config, rl, composedOnEvent, autoApprove, { enableMcp: Boolean(commandOptions.browser) });

        if (commandOptions.resume) {
          const sessionId = target; // target is actually session-id in resume mode
          if (!agent.hasSession(sessionId)) throw new Error(`Session not found: ${sessionId}`);
          console.log(`Resuming security session ${sessionId}...`);
          if (webuiUrl) console.log(`Bridging events to Web UI at ${webuiUrl}\n`);
          await chatLoop(agent, sessionId, rl, projectRootFromConfig(options.config), autoApprove);
          console.log(`Session saved: ${sessionId}`);
          return;
        }

        const intent = buildDirectTargetIntent(target, "authorized_security_assessment");
        printIntent(intent);
        if (!commandOptions.yes) {
          const authorized = await confirmAuthorization(rl, intent);
          if (!authorized) {
            console.log("Authorization not confirmed. No session created.");
            return;
          }
        }
        const sessionId = agent.createSession(`pentest: ${target}`);
        if (webuiUrl) console.log(`Bridging events to Web UI at ${webuiUrl}\n`);
        autoApprove.active = Boolean(commandOptions.yes);
        const turnResult = await runChatTurn(agent, sessionId, target, rl);
        if (!turnResult.ok) {
          process.exitCode = 1;
        }
        autoApprove.active = false;
        console.log(`Session saved: ${sessionId}`);
      } finally {
        rl.close();
        await stopMcpManagerForCleanup();
      }
    });

  program.command("runs")
    .description("Show structured security tool run ledger for a saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printSecurityToolRuns(agent, sessionId);
    });

  program.command("evidence")
    .description("Show Evidence/Hypothesis attack graph nodes for a saved session")
    .argument("<session-id>")
    .option("--kind <kind>", "filter by evidence kind (asset, technology, vulnerability, etc.)")
    .action(async (sessionId: string, commandOptions: { kind?: string }) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printGraphEvidence(agent, sessionId, commandOptions.kind);
    });

  program.command("hypotheses")
    .description("Show active investigation hypotheses for a saved session")
    .argument("<session-id>")
    .option("--all", "include concluded and failed hypotheses")
    .action(async (sessionId: string, commandOptions: { all?: boolean }) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printGraphHypotheses(agent, sessionId, commandOptions.all);
    });

  program.command("graph-state")
    .description("Show full attack graph state (YAML dump) for a saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      console.log(agent.renderGraphState(sessionId));
    });

  program.command("browser-login")
    .description("Capture a Playwright storage-state auth context after manual login")
    .argument("<session-id>")
    .argument("<url>")
    .requiredOption("--name <name>", "auth context name")
    .option("--role <role>", "role label")
    .option("--user <username>", "username label")
    .option("--wait <seconds>", "seconds to wait for manual login", "60")
    .option("--headless", "run browser headless; useful only when login is already automated by stored state")
    .action(async (sessionId: string, url: string, commandOptions: { name: string; role?: string; user?: string; wait: string; headless?: boolean }) => {
      const options = program.opts<CliOptions>();
      const agent = await createAgent(options.config, undefined, undefined, undefined, { enableMcp: false });
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const context = await agent.captureBrowserAuthContext(sessionId, url, {
        name: commandOptions.name,
        role: commandOptions.role,
        username: commandOptions.user,
        headed: !commandOptions.headless,
        waitMs: parseNumberOption(commandOptions.wait, 60) * 1000
      });
      printSecurityAuthContext(context);
    });

  program.command("browser-forms")
    .description("Run read-only Playwright same-origin form exploration")
    .argument("<session-id>")
    .argument("[auth-or-url]", "auth context name/id or URL")
    .option("--max-pages <number>", "maximum same-origin pages to visit", "8")
    .option("--headed", "show the browser while exploring")
    .action(async (sessionId: string, authOrUrl: string | undefined, commandOptions: { maxPages: string; headed?: boolean }) => {
      const options = program.opts<CliOptions>();
      const agent = await createAgent(options.config, undefined, undefined, undefined, { enableMcp: false });
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const result = await agent.exploreBrowserForms(sessionId, authOrUrl, {
        maxPages: parseNumberOption(commandOptions.maxPages, 8),
        headed: commandOptions.headed
      });
      console.log(`Browser exploration: pages=${result.pagesVisited.length} forms=${result.forms.length}`);
      console.log(`artifact: ${result.artifactPath}`);
      for (const form of result.forms.slice(0, 20)) {
        console.log(`- ${form.method} ${form.action} | page:${form.pageUrl} | inputs:${form.inputNames.join(",")} | csrf:${form.hasCsrfToken ? "yes" : "no"}`);
      }
    });

  program.command("webapp-recon")
    .description("Build a read-only browser/JS/API application map with Playwright")
    .argument("<session-id>")
    .argument("[auth-or-url]", "auth context name/id or URL")
    .option("--max-pages <number>", "maximum same-origin pages to visit", "10")
    .option("--headed", "show the browser while exploring")
    .option("--no-js", "skip JavaScript source analysis")
    .action(async (sessionId: string, authOrUrl: string | undefined, commandOptions: { maxPages: string; headed?: boolean; js?: boolean }) => {
      const options = program.opts<CliOptions>();
      const agent = await createAgent(options.config, undefined, undefined, undefined, { enableMcp: false });
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const result = await agent.reconWebApplication(sessionId, authOrUrl, {
        maxPages: parseNumberOption(commandOptions.maxPages, 10),
        headed: commandOptions.headed,
        analyzeJs: commandOptions.js !== false
      });
      console.log(`WebApp recon: pages=${result.pagesVisited.length} forms=${result.forms.length} api=${result.apiInventory.length} normalizedApi=${result.normalizedApiEndpoints?.length ?? 0} jsEndpoints=${result.jsEndpoints.length} network=${result.networkRequests.length}`);
      console.log(`artifact: ${result.artifactPath}`);
      if (result.harArtifactPath) {
        console.log(`HAR artifact: ${result.harArtifactPath}`);
      }
      if (result.normalizedApiArtifactPath) {
        console.log(`normalized API artifact: ${result.normalizedApiArtifactPath}`);
      }
      if (result.authSurface.loginPages.length > 0 || result.authSurface.authEndpoints.length > 0 || result.authSurface.passwordForms.length > 0) {
        console.log(`auth surface: loginPages=${result.authSurface.loginPages.length} authEndpoints=${result.authSurface.authEndpoints.length} passwordForms=${result.authSurface.passwordForms.length}`);
      }
      if (result.authAssessment) {
        console.log(`auth model: state=${result.authAssessment.authState} login=${result.authAssessment.login} mechanisms=${result.authAssessment.sessionMechanisms.join(",")} csrf=${result.authAssessment.csrfSignals} highValueFlows=${result.authAssessment.highValueFlows.length}`);
        for (const needed of result.authAssessment.nextEvidenceNeeded.slice(0, 5)) {
          console.log(`auth needed: ${needed}`);
        }
      }
      if (result.jsAnalysisSummary) {
        console.log(`js analyzer: scripts=${result.jsAnalysisSummary.scriptCount} endpoints=${result.jsAnalysisSummary.endpointCount} sourceMaps=${result.jsAnalysisSummary.sourceMapCount} libraries=${result.jsAnalysisSummary.libraryCount} sensitiveSignals=${result.jsAnalysisSummary.sensitiveSignalCount}`);
      }
      for (const item of (result.normalizedApiEndpoints ?? []).slice(0, 30)) {
        console.log(`- ${item.method} ${item.pathTemplate} | sources:${item.sources.join(",")} | auth:${item.authRequired} | confidence:${item.confidence}${item.riskSignals.length ? ` | signals:${item.riskSignals.join(",")}` : ""}`);
      }
      if (!result.normalizedApiEndpoints?.length) {
        for (const item of result.apiInventory.slice(0, 30)) {
          console.log(`- ${item.method ?? "GET"} ${item.url} | source:${item.source} | confidence:${item.confidence}${item.riskSignals.length ? ` | signals:${item.riskSignals.join(",")}` : ""}`);
        }
      }
      for (const signal of result.jsSensitiveSignals.slice(0, 10)) {
        console.log(`! ${signal.kind} ${signal.evidence} | script:${signal.scriptUrl}`);
      }
      for (const sourceMap of (result.jsSourceMaps ?? []).slice(0, 10)) {
        console.log(`map ${sourceMap.available ? "available" : "referenced"} ${sourceMap.mapUrl} | sources:${sourceMap.sourceCount ?? 0}`);
      }
      for (const library of (result.jsLibraries ?? []).filter((item) => item.riskSignals.length > 0).slice(0, 10)) {
        console.log(`lib ${library.name}${library.version ? ` ${library.version}` : ""} | confidence:${library.confidence} | signals:${library.riskSignals.join(",")}`);
      }
    });

  program.command("api-description-import")
    .description("Import an explicit OpenAPI JSON document or GraphQL endpoint into normalized API evidence")
    .argument("<session-id>")
    .argument("<file-or-url>", "explicit OpenAPI JSON file/URL or same-origin GraphQL endpoint URL")
    .action(async (sessionId: string, source: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createAgent(options.config, undefined, undefined, undefined, { enableMcp: false });
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const result = await agent.importApiDescriptionDocument(sessionId, source);
      const document = result.apiDescriptionDocuments[0];
      console.log(`API description import: kind=${document.kind} source=${document.source} operations=${document.operationCount ?? "unknown"} normalizedApi=${result.normalizedApiEndpoints.length}`);
      console.log(`artifact: ${result.artifactPath}`);
      for (const item of result.normalizedApiEndpoints.slice(0, 30)) {
        console.log(`- ${item.method} ${item.pathTemplate} | sources:${item.sources.join(",")} | auth:${item.authRequired} | confidence:${item.confidence}${item.riskSignals.length ? ` | signals:${item.riskSignals.join(",")}` : ""}`);
      }
    });

  program.command("business-plan")
    .description("Show a safe business-logic testing plan for a saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printBusinessLogicTestPlan(agent, sessionId);
    });

  program.command("authz-matrix")
    .description("Show endpoint authorization boundary matrix from normalized API and auth evidence")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printAuthorizationBoundaryMatrix(agent, sessionId);
    });

  program.command("authz-plan")
    .description("Show evidence-driven authorization validation candidates from normalized API evidence")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printAuthorizationValidationPlan(agent, sessionId);
    });

  program.command("access-map")
    .description("Show information-gathering map for anonymous exposure, auth gates, and authorization-sensitive routes")
    .argument("<session-id>")
    .option("-n, --limit <number>", "maximum exposure items to render", "30")
    .action(async (sessionId: string, commandOptions: { limit: string }) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const assets = agent.listAssets(sessionId);
      const targetAsset = [...assets].reverse().find((asset) => ["url", "domain", "ip"].includes(asset.kind));
      const target = agent.latestSecurityTarget(sessionId) ?? agent.listTargets(sessionId)[0] ?? (targetAsset ? parseTargetInput(targetAsset.value) : undefined);
      const map = buildAccessExposureMap({
        target,
        assets,
        evidence: agent.listEvidence(sessionId),
        authContexts: agent.listSecurityAuthContexts(sessionId),
        maxItems: parseNumberOption(commandOptions.limit, 30)
      });
      console.log(renderAccessExposureMap(map));
    });

  program.command("expert-snapshot")
    .description("Show a read-only expert workbench snapshot for model-led pentest decisions")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      console.log(agent.renderExpertSnapshot(sessionId));
    });

  program.command("payload-candidates")
    .description("Generate advisory payload/probe candidates from current session evidence without sending requests")
    .argument("<session-id>")
    .option("--focus <kind>", "optional focus such as xss, sqli, ssti, ssrf, authz, mass_assignment, upload, command_injection")
    .option("-n, --limit <number>", "maximum candidates to render", "12")
    .option("--active", "mark active probing as allowed for advisory risk notes")
    .action(async (sessionId: string, commandOptions: { focus?: string; limit: string; active?: boolean }) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const assets = agent.listAssets(sessionId);
      const targetAsset = [...assets].reverse().find((asset) => ["url", "domain", "ip"].includes(asset.kind));
      const target = targetAsset ? parseTargetInput(targetAsset.value) : undefined;
      const set = buildPayloadCandidateSet({
        target,
        assets,
        evidence: agent.listEvidence(sessionId),
        technologies: agent.listTechnologies(sessionId),
        cveMatches: agent.listCveMatches(sessionId),
        authContexts: agent.listSecurityAuthContexts(sessionId),
        focus: commandOptions.focus,
        maxCandidates: parseNumberOption(commandOptions.limit, 12),
        activeAllowed: Boolean(commandOptions.active)
      });
      console.log(renderPayloadCandidateSet(set));
    });

  program.command("payload-drafts")
    .description("Generate reviewable HTTP request drafts from payload candidates without sending requests")
    .argument("<session-id>")
    .option("--focus <kind>", "optional focus such as xss, sqli, ssti, ssrf, authz, mass_assignment, upload, command_injection")
    .option("-n, --limit <number>", "maximum request drafts to render", "12")
    .option("--active", "mark active probing as allowed for draft gating notes")
    .action(async (sessionId: string, commandOptions: { focus?: string; limit: string; active?: boolean }) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const assets = agent.listAssets(sessionId);
      const targetAsset = [...assets].reverse().find((asset) => ["url", "domain", "ip"].includes(asset.kind));
      const target = targetAsset ? parseTargetInput(targetAsset.value) : undefined;
      const set = buildPayloadRequestDraftSet({
        target,
        assets,
        evidence: agent.listEvidence(sessionId),
        technologies: agent.listTechnologies(sessionId),
        cveMatches: agent.listCveMatches(sessionId),
        authContexts: agent.listSecurityAuthContexts(sessionId),
        focus: commandOptions.focus,
        maxCandidates: Math.max(parseNumberOption(commandOptions.limit, 12), 12),
        maxDrafts: parseNumberOption(commandOptions.limit, 12),
        activeAllowed: Boolean(commandOptions.active)
      });
      console.log(renderPayloadRequestDraftSet(set));
    });

  program.command("safe-fetch")
    .description("Make a read-only HTTP GET/HEAD request with a registered auth context's credentials")
    .argument("<session-id>")
    .argument("<url>")
    .argument("<auth-context-name>")
    .option("--method <method>", "HTTP method (GET or HEAD)", "GET")
    .option("--timeout-ms <number>", "request timeout in milliseconds", "5000")
    .action(async (sessionId: string, url: string, authContextName: string, cmdOptions: { method: string; timeoutMs: string }) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const method = (cmdOptions.method || "GET").toUpperCase();
      if (!["GET", "HEAD"].includes(method)) {
        throw new Error(`Only GET/HEAD methods are allowed for safe-fetch, got: ${method}`);
      }
      const authContexts = agent.listSecurityAuthContexts(sessionId);
      const authContext = authContexts.find((ctx) => ctx.name === authContextName || ctx.id === authContextName);
      if (!authContext) {
        throw new Error(`Auth context not found: ${authContextName}. Registered contexts: ${authContexts.map((ctx) => ctx.name).join(", ") || "none"}`);
      }
      const timeoutMs = boundedFetchTimeout(cmdOptions.timeoutMs);
      const { safeAuthenticatedFetchDetails } = await import("@aegisprobe/core");
      const result = await (safeAuthenticatedFetchDetails as (u: string, c: typeof authContext, m: SafeReadOnlyMethod, t?: number) => Promise<SafeAuthenticatedFetchDetails>)(url, authContext, method as SafeReadOnlyMethod, timeoutMs);
      agent.recordReadOnlyFetchEvidence(sessionId, result, authContext.name);
      printSafeFetchDetails(result, authContext.name);
    });

  program.command("anonymous-fetch")
    .description("Make a read-only anonymous HTTP GET/HEAD request for unauthorized-access baseline evidence")
    .argument("<session-id>")
    .argument("<url>")
    .option("--method <method>", "HTTP method (GET or HEAD)", "GET")
    .option("--timeout-ms <number>", "request timeout in milliseconds", "5000")
    .action(async (sessionId: string, url: string, cmdOptions: { method: string; timeoutMs: string }) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const method = (cmdOptions.method || "GET").toUpperCase();
      if (!["GET", "HEAD"].includes(method)) {
        throw new Error(`Only GET/HEAD methods are allowed for anonymous-fetch, got: ${method}`);
      }
      const timeoutMs = boundedFetchTimeout(cmdOptions.timeoutMs);
      const { safeAnonymousFetchDetails } = await import("@aegisprobe/core");
      const result = await (safeAnonymousFetchDetails as (u: string, m: SafeReadOnlyMethod, t?: number) => Promise<SafeAuthenticatedFetchDetails>)(url, method as SafeReadOnlyMethod, timeoutMs);
      agent.recordReadOnlyFetchEvidence(sessionId, result);
      printSafeFetchDetails(result);
    });

  const authContext = program.command("auth-context")
    .description("Manage authenticated browser/session contexts for safe business-logic testing");

  authContext.command("add")
    .description("Register cookies, headers, or Playwright storage-state for a saved session")
    .argument("<session-id>")
    .requiredOption("--name <name>", "auth context name, for example user-a or admin")
    .option("--base-url <url>", "base URL this login state belongs to")
    .option("--role <role>", "role/tenant label for this login state")
    .option("--username <username>", "username label; secrets are not required")
    .option("--cookie <cookie>", "Cookie header value")
    .option("--authorization <header>", "Authorization header value")
    .option("--headers-json <json>", "additional JSON object of request headers")
    .option("--storage-state <path>", "Playwright storageState JSON file path")
    .option("--notes <text>", "operator notes and authorization boundary")
    .action(async (sessionId: string, commandOptions: {
      name: string;
      baseUrl?: string;
      role?: string;
      username?: string;
      cookie?: string;
      authorization?: string;
      headersJson?: string;
      storageState?: string;
      notes?: string;
    }) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const context = agent.addSecurityAuthContext(sessionId, {
        name: commandOptions.name,
        baseUrl: commandOptions.baseUrl,
        role: commandOptions.role,
        username: commandOptions.username,
        cookieHeader: commandOptions.cookie,
        authorizationHeader: commandOptions.authorization,
        headersJson: commandOptions.headersJson,
        storageStatePath: commandOptions.storageState,
        notes: commandOptions.notes
      });
      printSecurityAuthContext(context);
    });

  authContext.command("list")
    .description("List authenticated contexts for a saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printSecurityAuthContexts(agent.listSecurityAuthContexts(sessionId));
    });

  program.command("business-run")
    .description("Execute a read-only authenticated business-logic check for a saved session")
    .argument("<session-id>")
    .argument("[case-id]", "business test case id, or next", "next")
    .option("--auth <name>", "auth context name or id")
    .action(async (sessionId: string, caseId: string, commandOptions: { auth?: string }) => {
      const options = program.opts<CliOptions>();
      const agent = await createAgent(options.config, undefined, undefined, undefined, { enableMcp: false });
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      console.log(await agent.executeBusinessLogicTest(sessionId, caseId, commandOptions.auth));
    });

  program.command("business-compare")
    .description("Execute read-only cross-role business-logic response comparison")
    .argument("<session-id>")
    .argument("[case-id]", "business test case id, or next", "next")
    .requiredOption("--left <name>", "left auth context name or id")
    .requiredOption("--right <name>", "right auth context name or id")
    .action(async (sessionId: string, caseId: string, commandOptions: { left: string; right: string }) => {
      const options = program.opts<CliOptions>();
      const agent = await createAgent(options.config, undefined, undefined, undefined, { enableMcp: false });
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      console.log(await agent.executeBusinessLogicRoleComparison(sessionId, caseId, commandOptions.left, commandOptions.right));
    });

  program.command("validation-plan")
    .description("Show candidate finding/CVE/business-logic validation plan")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      console.log(agent.buildSecurityValidationPlan(sessionId));
    });

  program.command("validate")
    .description("Record the next or selected non-destructive validation attempt")
    .argument("<session-id>")
    .argument("[target-id]", "finding/cve id, kind:id, or next", "next")
    .action(async (sessionId: string, targetId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      console.log(agent.executeSecurityValidationAttempt(sessionId, targetId));
    });

  program.command("validations")
    .description("Show stored validation attempts")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printSecurityValidationAttempts(agent.listSecurityValidationAttempts(sessionId));
    });

  program.command("findings")
    .description("Show security findings and evidence for a saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printFindings(agent, sessionId);
    });

  program.command("checklist")
    .description("Show OWASP/WSTG-style validation check status for a saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      printSecurityChecklist(agent, sessionId);
    });

  program.command("report")
    .description("Render a Markdown security assessment report for a saved session")
    .argument("<session-id>")
    .action(async (sessionId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      console.log(agent.renderSecurityReport(sessionId));
    });

  program.command("spawn-agent")
    .description("Spawn a subagent for a saved session")
    .argument("<session-id>")
    .argument("<role>")
    .argument("<task...>")
    .option("-b, --background", "launch without waiting for completion")
    .action(async (sessionId: string, role: string, taskParts: string[], commandOptions: { background?: boolean }) => {
      const options = program.opts<CliOptions>();
      const agent = await createAgent(options.config);
      if (!agent.hasSession(sessionId)) {
        throw new Error(`Session not found: ${sessionId}`);
      }
      const record = await agent.spawnSubAgent(sessionId, normalizeRole(role), taskParts.join(" "), [], { background: Boolean(commandOptions.background) });
      printSubAgentRecord(record, true);
    });

  program.command("close-agent")
    .description("Close and abort a running subagent when possible")
    .argument("<session-id>")
    .argument("<agent-id>")
    .action(async (sessionId: string, agentId: string) => {
      const options = program.opts<CliOptions>();
      const agent = await createQueryAgent(options.config);
      const closed = agent.closeSubAgent(sessionId, agentId);
      console.log(closed ? `Closed subagent: ${agentId}` : `Subagent not found: ${agentId}`);
    });

  program.command("webui")
    .description("Start the AegisProbe Web UI server (three-panel dashboard)")
    .option("-p, --port <number>", "listen port", "3000")
    .option("-h, --host <string>", "listen host", "127.0.0.1")
    .option("--no-browser", "don't open the browser automatically")
    .action(async (commandOptions: { port: string; host: string; browser?: boolean }) => {
      const { startServer } = await import("@aegisprobe/server");
      const port = Number.parseInt(commandOptions.port, 10);
      const host = commandOptions.host;
      const { app, httpServer } = startServer({ port, host });

      // Open browser
      if (commandOptions.browser !== false) {
        const url = `http://${host}:${port}`;
        const { spawn } = await import("node:child_process");
        const platform = process.platform;
        if (platform === "win32") {
          spawn("cmd", ["/c", "start", url], { detached: true, stdio: "ignore" });
        } else if (platform === "darwin") {
          spawn("open", [url], { detached: true, stdio: "ignore" });
        } else {
          spawn("xdg-open", [url], { detached: true, stdio: "ignore" });
        }
      }

      // Keep alive
      console.log("Press Ctrl+C to stop the server.");
      await new Promise(() => {}); // never resolves — process stays alive
    });

  await program.parseAsync(process.argv);
}

async function askLine(rl: ReturnType<typeof createInterface>, prompt: string): Promise<string> {
  if (pipedAnswers) {
    output.write(prompt);
    return pipedAnswers.shift() ?? "";
  }
  try {
    return await rl.question(prompt);
  } catch (error) {
    if (error instanceof Error && /readline was closed/i.test(error.message)) {
      return "";
    }
    throw error;
  }
}

async function createStore(configPath?: string): Promise<AuditStore> {
  const { AuditStore } = await import("@aegisprobe/storage");
  const resolvedConfigPath = resolveCliConfigPath(configPath);
  const config = loadConfig(resolvedConfigPath);
  const projectRoot = projectRootFromConfig(resolvedConfigPath);
  const sqlitePath = isAbsolute(config.storage.sqlitePath)
    ? config.storage.sqlitePath
    : resolve(projectRoot, config.storage.sqlitePath);
  return new AuditStore(sqlitePath);
}

function createSkillRegistry(configPath?: string): FileSkillRegistry | EmptySkillRegistry {
  const resolvedConfigPath = resolveCliConfigPath(configPath);
  const config = loadConfig(resolvedConfigPath);
  if (!config.skills.enabled) {
    return new EmptySkillRegistry();
  }
  const configDir = dirname(resolvedConfigPath);
  return new FileSkillRegistry({
    roots: config.skills.roots.map((root) => resolve(configDir, root)),
    includeYaml: config.skills.includeYaml,
    includeMarkdown: config.skills.includeMarkdown,
    maxDepth: config.skills.maxDepth,
    maxSkillBytes: config.skills.maxSkillBytes,
    excludeDirs: config.skills.excludeDirs
  });
}

async function createAgent(
  configPath?: string,
  rl?: ReturnType<typeof createInterface>,
  onEvent?: (event: TurnEvent) => void,
  autoApprove?: { active: boolean },
  runtimeOptions: { enableMcp?: boolean } = {}
): Promise<MainAgent> {
  const resolvedConfigPath = resolveCliConfigPath(configPath);
  const config = loadConfig(resolvedConfigPath);
  if (config.agent.shell && config.agent.shell !== "auto") {
    setShellMode(config.agent.shell as "powershell" | "wsl");
  }
  const provider = new OpenAICompatibleProvider(config.provider);
  const store = await createStore(resolvedConfigPath);
  const skillRegistry = createSkillRegistry(resolvedConfigPath);
  const projectRoot = projectRootFromConfig(resolvedConfigPath);
  const dictPaths = resolveDictPaths(config, projectRoot);
  const enableMcp = (runtimeOptions.enableMcp ?? true) && config.mcp.enabled;
  const mcpManager = enableMcp ? new McpManager() : undefined;
  _mcpManagerForCleanup = mcpManager;
  if (mcpManager) {
    for (const server of config.mcp.servers) {
      mcpManager.addServer(server);
    }
    // Fire-and-forget MCP startup — agent proceeds immediately
    mcpManager.startAll().then(async () => {
      await mcpManager.waitAllReady(30_000);
      const names = mcpManager.listClients().map(c => c.serverName).join(', ');
      const count = mcpManager.listClients().reduce((sum,c)=>sum+c.getTools().length,0);
      if (count > 0) console.log(`MCP ready: ${names} (${count} tools)`);
      else console.log(`MCP: ${names} not ready (tools will appear when server starts)`);
    }).catch(() => {});
  }
  return new MainAgent({
    provider,
    store,
    skillRegistry,
    projectRoot,
    dictPaths,
    mcpManager,
    onEvent,
    approve: async (subject, detail) => {
      if (autoApprove?.active) {
        return { approved: true };
      }
      const prompt = `${subject}\n${detail}\nApprove? Type YES once, ALWAYS to remember this exact command, anything else to deny: `;
      const answer = rl ? await askLine(rl, prompt) : "";
      const normalized = answer.trim().toUpperCase();
      return {
        approved: normalized === "YES" || normalized === "ALWAYS",
        remember: normalized === "ALWAYS"
      };
    }
  });
}

async function createQueryAgent(configPath?: string): Promise<MainAgent> {
  return await createAgent(configPath, undefined, undefined, undefined, { enableMcp: false });
}

async function confirmAuthorization(rl: ReturnType<typeof createInterface>, intent: IntentExtraction): Promise<boolean> {
  if (intent.intent === "conversation" && intent.targets.length === 0 && intent.filePaths.length === 0) {
    return true;
  }
  const summary = intent.targets.length > 0
    ? describeAuthorization(intent.targets)
    : intent.filePaths.length > 0
      ? `file:${intent.filePaths.join(", ")}`
      : "no concrete URL/domain/file extracted";
  const answer = await askLine(rl, `Confirm you are authorized to work on this scope (${summary}). Type YES to continue: `);
  return answer.trim().toUpperCase() === "YES";
}

async function runOnce(target: string, options: CliOptions): Promise<void> {
  const rl = createInterface({ input, output });
  try {
    const autoApprove = { active: true }; // auto-approve for non-interactive runs
    const agent = await createAgent(options.config, rl, printRealtimeEvent, autoApprove);

    const sessionId = agent.createSession(`run: ${target.slice(0, 80)}`);
    console.log(`Session: ${sessionId}`);
    console.log("");

    const interrupt = createInterruptController(rl);
    try {
      await withInterrupt(interrupt, async (signal) => {
        let started = false;
        for await (const event of agent.runConversationTurn(sessionId, target, { signal })) {
          switch (event.kind) {
            case "text_start": started = true; output.write("\n"); break;
            case "text_delta": output.write(event.content); break;
            case "text_end": output.write("\n"); break;
            case "tool_execution_start": break;
            case "tool_execution_end":
              if (event.error) {
                output.write(`  ❌ ${event.result.slice(0, 150)}\n`);
              } else {
                const preview = event.result.length > 200 ? event.result.slice(0, 200) + "..." : event.result;
                output.write(`  ✅ ${preview.replace(/\n/g, "\\n")}\n`);
              }
              break;
            case "turn_complete":
              if (!started) output.write("\n(No response)\n");
              break;
            case "turn_aborted": output.write("\n[Interrupted]\n"); break;
            case "turn_error": output.write(`\nError: ${event.error}\n`); break;
          }
        }
      });
    } finally {
      if (interrupt.rawMode && process.stdin.isTTY) {
        try { process.stdin.setRawMode(false); } catch { /* ok */ }
      }
    }
    console.log(`\nSession saved: ${sessionId}`);
  } finally {
    rl.close();
  }
}

async function startChat(options: CliOptions, resumeSessionId?: string): Promise<void> {
  const rl = createInterface({ input, output });
  try {
    const projectRoot = projectRootFromConfig(options.config);
    const autoApprove = { active: false };
    const agent = await createAgent(options.config, rl, printRealtimeEvent, autoApprove);

    if (resumeSessionId) {
      printChatBanner({ mode: "resume", sessionId: resumeSessionId });
      if (!agent.hasSession(resumeSessionId)) {
        throw new Error(`Session not found: ${resumeSessionId}`);
      }
  console.log(`AegisProbe resumed session ${resumeSessionId}. Type /help for commands or continue the conversation directly.`);
      await chatLoop(agent, resumeSessionId, rl, projectRoot, autoApprove);
      console.log(`Session saved: ${resumeSessionId}`);
      return;
    }

  console.log("AegisProbe chat. Type /help for commands, /exit to quit. Just chat naturally — the agent can read files, run shell commands, and perform security probes. Press Escape to interrupt a running response.");
    printChatBanner({ mode: "chat" });
    const first = await askLine(rl, "Describe the task, URL/domain, file path, or just chat: ");
    if (!first.trim() || first.trim() === "/exit") {
      return;
    }

    const intent = await agent.understandUserInput(first);
    printIntent(intent);
    const authorized = await confirmAuthorization(rl, intent);
    if (!authorized) {
      console.log("Authorization not confirmed. No session created.");
      return;
    }

    const sessionId = agent.createSession(`chat: ${first.slice(0, 80)}`);
    await runChatTurn(agent, sessionId, first, rl);
    await chatLoop(agent, sessionId, rl, projectRoot, autoApprove);
    console.log(`Session saved: ${sessionId}`);
  } finally {
    rl.close();
  }
}

// ── Interrupt Controller ──
// Manages Escape/Ctrl+C keypress handling during agent operations.
// Uses raw mode to detect keypresses while readline handles line editing.

type InterruptState = {
  currentController: AbortController | null;
  rawMode: boolean;
};

function createInterruptController(
  rl: ReturnType<typeof createInterface>
): InterruptState {
  const state: InterruptState = { currentController: null, rawMode: false };

  if (!input.isTTY) return state;

  try {
    emitKeypressEvents(process.stdin);
    process.stdin.setRawMode(true);
    state.rawMode = true;
  } catch {
    // Not a TTY
  }

  if (state.rawMode) {
    process.stdin.on("keypress", (_str: string, key: { name: string; ctrl: boolean }) => {
      if (key.name === "escape" && state.currentController && !state.currentController.signal.aborted) {
        state.currentController.abort();
        output.write("\n⏎ [Interrupted]\n");
      }
      if (key.name === "c" && key.ctrl && state.currentController && !state.currentController.signal.aborted) {
        state.currentController.abort();
        output.write("\n^C [Cancelled]\n");
      }
    });
  }

  return state;
}

function withInterrupt(
  interrupt: InterruptState,
  fn: (signal: AbortSignal) => Promise<void>
): Promise<void> {
  const controller = new AbortController();
  interrupt.currentController = controller;
  return fn(controller.signal).finally(() => {
    interrupt.currentController = null;
  });
}

async function runChatTurn(
  agent: MainAgent,
  sessionId: string,
  userInput: string,
  rl: ReturnType<typeof createInterface>
): Promise<{ ok: boolean }> {
  // Set up interrupt for this turn
  const interrupt = createInterruptController(rl);
  let completed = false;
  let failed = false;

  try {
    await withInterrupt(interrupt, async (signal) => {
      let started = false;
      for await (const event of agent.runConversationTurn(sessionId, userInput, { signal })) {
        switch (event.kind) {
          case "text_start":
            started = true;
            output.write("\n");
            break;
          case "text_delta":
            output.write(event.content);
            break;
          case "text_end":
            output.write("\n");
            break;
          case "tool_execution_start":
            output.write(`  Running ${event.name}...`);
            break;
          case "tool_execution_end":
            if (event.error) {
              output.write(` ❌ ${event.result.slice(0, 100)}\n`);
            } else {
              output.write(` ✅ (${event.result.length} chars)\n`);
            }
            break;
          case "turn_complete":
            completed = true;
            if (!started) {
              output.write("\n(No response)\n");
            }
            break;
          case "turn_aborted":
            failed = true;
            output.write("Turn aborted.\n");
            break;
          case "turn_error":
            failed = true;
            output.write(`\nError: ${event.error}\n`);
            break;
        }
      }
    });
  } finally {
    // Restore readline after raw mode
    if (interrupt.rawMode && process.stdin.isTTY) {
      try {
        process.stdin.setRawMode(false);
      } catch {
        // Already restored
      }
    }
  }
  return { ok: completed && !failed };
}

function printChatHelp(): void {
  console.log(`
AegisProbe Chat Commands
========================
  /exit                    Quit the chat session
  /clear                   Clear conversation history
  /help                    Show this help

  Chat & Tools:
  /shell <command>         Execute a shell command directly
  /tools                   List available security tools
  /tools --check           Check tool health

  Pentest:
  /pentest <target>        Send a target to the current agent thread
  /probe <target> [type]   Quick security probe (basic_recon|dns|http_headers)

  Session:
  /findings                Show findings
  /report                  Generate markdown report
  /context                 Show current context snapshot
  /diff                    Show file changes
  /checklist               Show validation checklist

  SubAgents:
  /agents                  List subagents
  /agent <role> <task>     Spawn a subagent
  /agent-bg <role> <task>  Spawn in background

  Just type anything to chat with the agent.
  Press Escape to interrupt a running response.
`);
}

async function chatLoop(agent: MainAgent, sessionId: string, rl: ReturnType<typeof createInterface>, projectRoot = process.cwd(), autoApprove?: { active: boolean }): Promise<void> {
  while (true) {
    const line = await askLine(rl, aegisPrompt());
    const trimmed = line.trim();
    if (!trimmed) {
      if (!input.isTTY) {
        break;
      }
      continue;
    }
    if (trimmed === "/exit") {
      break;
    }
    if (trimmed === "/clear") {
      agent.clearConversation(sessionId);
      console.log("Conversation cleared.");
      continue;
    }
    if (trimmed === "/help") {
      printChatHelp();
      continue;
    }
    if (trimmed.startsWith("/shell ")) {
      await agent.executeCommand(sessionId, trimmed.slice("/shell ".length));
      continue;
    }
    if (trimmed.startsWith("/probe ")) {
      const [target, probe] = trimmed.slice("/probe ".length).trim().split(/\s+/);
      if (!target) {
        console.log("Usage: /probe <target> [basic_recon|dns|http_headers]");
        continue;
      }
      const summary = await agent.executeSecurityProbe(sessionId, target, normalizeProbe(probe));
      console.log(summary);
      continue;
    }
    if (trimmed.startsWith("/pentest ")) {
      const parts = trimmed.slice("/pentest ".length).trim().split(/\s+/).filter(Boolean);
      const target = parts.find((part) => !part.startsWith("--"));
      if (!target) {
        console.log("Usage: /pentest <target>");
        continue;
      }
      await runChatTurn(agent, sessionId, target, rl);
      continue;
    }
    if (trimmed === "/agents") {
      printSubAgents(agent, sessionId);
      continue;
    }
    if (trimmed === "/tools") {
      printToolInventory(false, projectRoot);
      continue;
    }
    if (trimmed === "/tools --check") {
      printToolInventory(true, projectRoot);
      continue;
    }
    if (trimmed === "/runs") {
      printSecurityToolRuns(agent, sessionId);
      continue;
    }
    if (trimmed.startsWith("/browser-forms")) {
      const parts = trimmed.slice("/browser-forms".length).trim().split(/\s+/).filter(Boolean);
      const maxIndex = parts.indexOf("--max-pages");
      const authOrUrl = parts.find((part, index) => !part.startsWith("--") && index !== maxIndex + 1);
      const result = await agent.exploreBrowserForms(sessionId, authOrUrl, {
        maxPages: maxIndex >= 0 ? parseNumberOption(parts[maxIndex + 1], 8) : 8,
        headed: parts.includes("--headed")
      });
      console.log(`Browser exploration: pages=${result.pagesVisited.length} forms=${result.forms.length}`);
      console.log(`artifact: ${result.artifactPath}`);
      continue;
    }
    if (trimmed === "/business-plan") {
      printBusinessLogicTestPlan(agent, sessionId);
      continue;
    }
    if (trimmed === "/authz-plan") {
      printAuthorizationValidationPlan(agent, sessionId);
      continue;
    }
    if (trimmed === "/auth-list") {
      printSecurityAuthContexts(agent.listSecurityAuthContexts(sessionId));
      continue;
    }
    if (trimmed.startsWith("/business-run")) {
      const parts = trimmed.slice("/business-run".length).trim().split(/\s+/).filter(Boolean);
      const authIndex = parts.indexOf("--auth");
      const authName = authIndex >= 0 ? parts[authIndex + 1] : undefined;
      const caseId = parts.find((part, index) => !part.startsWith("--") && index !== authIndex + 1) ?? "next";
      console.log(await agent.executeBusinessLogicTest(sessionId, caseId, authName));
      continue;
    }
    if (trimmed.startsWith("/business-compare")) {
      const parts = trimmed.slice("/business-compare".length).trim().split(/\s+/).filter(Boolean);
      const leftIndex = parts.indexOf("--left");
      const rightIndex = parts.indexOf("--right");
      const left = leftIndex >= 0 ? parts[leftIndex + 1] : undefined;
      const right = rightIndex >= 0 ? parts[rightIndex + 1] : undefined;
      const caseId = parts.find((part, index) =>
        !part.startsWith("--") && index !== leftIndex + 1 && index !== rightIndex + 1
      ) ?? "next";
      if (!left || !right) {
        console.log("Usage: /business-compare [case-id|next] --left <auth> --right <auth>");
        continue;
      }
      console.log(await agent.executeBusinessLogicRoleComparison(sessionId, caseId, left, right));
      continue;
    }
    if (trimmed === "/validation-plan") {
      console.log(agent.buildSecurityValidationPlan(sessionId));
      continue;
    }
    if (trimmed.startsWith("/validate")) {
      const targetId = trimmed.slice("/validate".length).trim() || "next";
      console.log(agent.executeSecurityValidationAttempt(sessionId, targetId));
      continue;
    }
    if (trimmed === "/validations") {
      printSecurityValidationAttempts(agent.listSecurityValidationAttempts(sessionId));
      continue;
    }
    if (trimmed === "/findings") {
      printFindings(agent, sessionId);
      continue;
    }
    if (trimmed === "/checklist") {
      printSecurityChecklist(agent, sessionId);
      continue;
    }
    if (trimmed === "/report") {
      console.log(agent.renderSecurityReport(sessionId));
      continue;
    }
    if (trimmed.startsWith("/agent-info ")) {
      const agentId = trimmed.slice("/agent-info ".length).trim();
      printSubAgentDetail(agent, sessionId, agentId);
      continue;
    }
    if (trimmed.startsWith("/wait-agent ")) {
      const agentId = trimmed.slice("/wait-agent ".length).trim();
      const record = await agent.waitSubAgent(sessionId, agentId);
      if (!record || record.sessionId !== sessionId) {
        console.log(`Subagent not found: ${agentId}`);
      } else {
        printSubAgentRecord(record, true);
      }
      continue;
    }
    if (trimmed === "/diff") {
      printFileChanges(agent, sessionId);
      continue;
    }
    if (trimmed === "/context") {
      console.log(agent.renderContextSnapshot(sessionId));
      continue;
    }
    if (trimmed.startsWith("/close-agent ")) {
      const agentId = trimmed.slice("/close-agent ".length).trim();
      const closed = agent.closeSubAgent(sessionId, agentId);
      console.log(closed ? `Closed subagent: ${agentId}` : `Subagent not found: ${agentId}`);
      continue;
    }
    if (trimmed.startsWith("/agent ") || trimmed.startsWith("/agent-bg ")) {
      const background = trimmed.startsWith("/agent-bg ");
      const rest = trimmed.slice(background ? "/agent-bg ".length : "/agent ".length).trim();
      const [role, ...taskParts] = rest.split(/\s+/);
      const task = taskParts.join(" ").trim();
      if (!task) {
        console.log(background ? "Usage: /agent-bg <default|explorer|worker|reviewer|recon|frontend|fingerprint|cve|web_vuln> <task>" : "Usage: /agent <default|explorer|worker|reviewer|recon|frontend|fingerprint|cve|web_vuln> <task>");
        continue;
      }
      const record = await agent.spawnSubAgent(sessionId, normalizeRole(role), task, [], { background });
      printSubAgentRecord(record, true);
      continue;
    }
    // ── General conversation turn (streaming with interrupt) ──
    await runChatTurn(agent, sessionId, trimmed, rl);
  }
}

async function listSessions(options: CliOptions, limit: number): Promise<void> {
  const store = await createStore(options.config);
  const sessions = store.listSessions(limit);
  if (sessions.length === 0) {
    console.log("No sessions found.");
    return;
  }
  console.log("Recent Sessions");
  for (const session of sessions) {
    console.log(`- ${session.id} | ${session.updatedAt} | ${session.mode} | ${session.title}`);
  }
}

function printIntent(intent: IntentExtraction): void {
  console.log("\nUnderstood Intent");
  console.log(`- intent: ${intent.intent}`);
  if (intent.targets.length > 0) {
    console.log(`- targets: ${intent.targets.map((target) => `${target.kind}:${target.normalized}`).join(", ")}`);
  }
  if (intent.filePaths.length > 0) {
    console.log(`- files: ${intent.filePaths.join(", ")}`);
  }
  if (intent.constraints.length > 0) {
    console.log(`- constraints: ${intent.constraints.join("; ")}`);
  }
}

function buildDirectTargetIntent(inputText: string, intent: string): IntentExtraction {
  return {
    userText: inputText,
    intent,
    targets: [parseTargetInput(inputText)],
    filePaths: [],
    constraints: ["direct CLI target; skipped model intent extraction for deterministic long-running pentest command"],
    needsClarification: false
  };
}

function directPentestTarget(inputText: string) {
  const trimmed = inputText.trim();
  if (!trimmed) {
    return undefined;
  }
  const direct = parseTargetInput(trimmed);
  if (direct.kind === "url" || direct.kind === "domain") {
    return direct;
  }
  const targets = extractUrlLikeTargets(trimmed).filter((target) => target.kind === "url" || target.kind === "domain");
  if (targets.length === 0) {
    return undefined;
  }
  const securityIntent = /渗透|测试|扫描|漏洞|安全|挖|侦察|探测|pentest|scan|audit|recon|vuln|security/i.test(trimmed);
  return securityIntent ? targets[0] : undefined;
}

function normalizeRole(role: string): SubAgentRole {
  return role === "explorer" ||
    role === "worker" ||
    role === "reviewer" ||
    role === "recon" ||
    role === "frontend" ||
    role === "fingerprint" ||
    role === "cve" ||
    role === "web_vuln" ||
    role === "default"
    ? role
    : "default";
}

function normalizeProbe(probe: string | undefined): "basic_recon" | "dns" | "http_headers" {
  return probe === "dns" || probe === "http_headers" || probe === "basic_recon" ? probe : "basic_recon";
}

function parseNumberOption(value: string | undefined, fallback: number): number {
  const parsed = Number.parseInt(value ?? "", 10);
  return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
}

function boundedFetchTimeout(value: string | undefined): number {
  return Math.max(500, Math.min(parseNumberOption(value, 5_000), 60_000));
}

function printSafeFetchDetails(result: SafeAuthenticatedFetchDetails, authContext?: string): void {
  console.log(JSON.stringify({
    url: result.url,
    method: result.method,
    anonymous: result.anonymous,
    authContext: authContext ?? result.authContextName ?? null,
    timeoutMs: result.timeoutMs ?? null,
    status: result.status,
    statusText: result.statusText,
    contentType: result.contentType ?? null,
    location: result.location ?? null,
    responseHeaders: result.responseHeaders,
    bodyLength: result.bodyLength,
    bodyHash: result.bodyHash,
    bodyExcerpt: result.bodyExcerpt ?? null,
    bodyTruncated: result.bodyTruncated,
    htmlSurface: result.htmlSurface ?? null,
    headerSignature: result.headerSignature,
    error: result.error ?? null
  }, null, 2));
}

function printSubAgents(agent: MainAgent, sessionId: string): void {
  const agents = agent.listSubAgents(sessionId);
  if (agents.length === 0) {
    console.log("No subagents found.");
    return;
  }
  console.log("SubAgents");
  for (const subagent of agents) {
    printSubAgentRecord(subagent, false);
  }
}

function printSubAgentDetail(agent: MainAgent, sessionId: string, agentId: string): void {
  const record = agent.getSubAgent(agentId);
  if (!record || record.sessionId !== sessionId) {
    console.log(`Subagent not found: ${agentId}`);
    return;
  }
  printSubAgentRecord(record, true);
}

function printSubAgentRecord(subagent: SubAgentRecord, detailed: boolean): void {
  const prefix = detailed ? "" : "- ";
  console.log(`${prefix}${subagent.id} | ${subagent.status} | ${subagent.priority ?? "medium"} | ${subagent.runMode ?? "foreground"} | ${subagent.role} | retry:${subagent.retryCount ?? 0}/${subagent.maxRetries ?? 0} | ${subagent.task}`);
  if (subagent.description) {
    console.log(`${detailed ? "" : "  "}description: ${subagent.description}`);
  }
  console.log(`${detailed ? "" : "  "}tool uses: ${subagent.toolUseCount}`);
  if (subagent.lastHeartbeatAt) {
    console.log(`${detailed ? "" : "  "}heartbeat: ${subagent.lastHeartbeatAt}`);
  }
  if (subagent.contextPaths && subagent.contextPaths.length > 0) {
    console.log(`${detailed ? "" : "  "}context: ${subagent.contextPaths.join(", ")}`);
  }
  if (subagent.progressSummary && subagent.status === "running") {
    console.log(`${detailed ? "" : "  "}progress: ${subagent.progressSummary.split(/\r?\n/)[0]}`);
  }
  if (subagent.outputPath) {
    console.log(`${detailed ? "" : "  "}output: ${subagent.outputPath}`);
  }
  if (subagent.resultSummary) {
    const summary = detailed ? subagent.resultSummary : subagent.resultSummary.split(/\r?\n/)[0];
    console.log(`${detailed ? "" : "  "}${summary}`);
  }
}

function printFileChanges(agent: MainAgent, sessionId: string): void {
  const changes = agent.listFileChanges(sessionId);
  if (changes.length === 0) {
    console.log("No file changes found.");
    return;
  }
  console.log("File Changes");
  for (const change of changes) {
    console.log(`- ${change.id} | ${change.status} | ${change.operation} | ${change.path}`);
    if (change.summary) {
      console.log(change.summary);
    }
    if (change.diff) {
      console.log(change.diff);
    }
  }
}

function printSecurityWorkflows(agent: MainAgent, sessionId: string): void {
  const workflows = agent.listSecurityWorkflows(sessionId);
  if (workflows.length === 0) {
    console.log("No security workflows found.");
    return;
  }
  console.log("Security Workflows");
  for (const workflow of workflows) {
    console.log(`- ${workflow.id} | ${workflow.status} | ${workflow.currentPhase} | ${workflow.target.kind}:${workflow.target.normalized}`);
    console.log(`  ${workflow.summary}`);
    const tasks = agent.listSecurityTasks(sessionId, workflow.id);
    for (const task of tasks) {
      const role = task.recommendedRole ? ` | role:${task.recommendedRole}` : "";
      const skills = task.suggestedSkills.length > 0 ? ` | skills:${task.suggestedSkills.join(",")}` : "";
      const tools = task.suggestedTools.length > 0 ? ` | tools:${task.suggestedTools.join(",")}` : "";
      console.log(`  - [${task.phase}] ${task.status} | ${task.title}${role}${skills}${tools}`);
    }
  }
}

function printSecurityToolRuns(agent: MainAgent, sessionId: string): void {
  const runs = agent.listSecurityToolRuns(sessionId);
  if (runs.length === 0) {
    console.log("No security tool runs found.");
    return;
  }
  console.log("Security Tool Runs");
  for (const run of runs) {
    const exit = run.exitCode === undefined ? "" : ` | exit:${run.exitCode}`;
    const inputs = run.inputKind ? ` | ${run.inputKind}:${run.inputCount}` : ` | inputs:${run.inputCount}`;
    const artifact = run.inputArtifact ? ` | input:${run.inputArtifact}` : "";
    const outputArtifact = run.outputArtifact ? ` | output:${run.outputArtifact}` : "";
    const classification = run.failureCategory ? ` | class:${run.failureCategory}` : "";
    const findings = run.findingCount === undefined ? "" : ` | findings:${run.findingCount}`;
    console.log(`- ${run.id} | ${run.status} | ${run.origin} | ${run.phase} | ${run.toolId}${exit}${inputs}${classification}${findings}${artifact}${outputArtifact}`);
    if (run.blockedReason) {
      console.log(`  blocked: ${run.blockedReason}`);
    }
    if (run.command) {
      console.log(`  command: ${run.command}`);
    }
    if (run.outputSummary) {
      console.log(`  summary: ${run.outputSummary.split(/\r?\n/)[0] ?? run.outputSummary}`);
    }
  }
}

function printSecurityValidationAttempts(attempts: SecurityValidationAttempt[]): void {
  if (attempts.length === 0) {
    console.log("No validation attempts found.");
    return;
  }
  console.log("Security Validation Attempts");
  for (const attempt of attempts) {
    console.log(`- ${attempt.id} | ${attempt.status}/${attempt.confidence} | ${attempt.targetKind}:${attempt.targetId} | ${attempt.targetTitle}`);
    console.log(`  method: ${attempt.method}`);
    console.log(`  rationale: ${attempt.rationale}`);
    if (attempt.evidenceIds.length > 0) {
      console.log(`  evidence: ${attempt.evidenceIds.join(", ")}`);
    }
  }
}

function printBusinessLogicTestPlan(agent: MainAgent, sessionId: string): void {
  const plan = agent.buildBusinessLogicTestPlan(sessionId);
  const matrix = agent.buildAuthorizationBoundaryMatrix(sessionId);
  console.log(`Business Logic Test Plan (${plan.generatedAt})`);
  console.log(`Target: ${plan.target}`);
  console.log(`Authorization Matrix: total=${matrix.summary.total} ready=${matrix.summary.ready} blocked=${matrix.summary.blocked} needsExample=${matrix.summary.needsExample} compared=${matrix.summary.compared}`);
  if (plan.authContexts.length > 0) {
    console.log("Authenticated Contexts");
    for (const context of plan.authContexts) {
      console.log(`- ${context.name} | role:${context.role ?? "unknown"} | user:${context.username ?? "unknown"} | base:${context.baseUrl ?? "unknown"}`);
    }
  }
  if (plan.requiresUserContext) {
    console.log("Required User Context");
    for (const question of plan.contextQuestions) {
      console.log(`- ${question}`);
    }
  }
  if (plan.testCases.length === 0) {
    console.log("No business-logic test cases generated.");
    return;
  }
  console.log("Test Cases");
  for (const item of plan.testCases) {
    const blocked = item.blockedReason ? ` | blocked:${item.blockedReason}` : "";
    console.log(`- ${item.id} | ${item.risk} | ${item.category}${blocked} | ${item.title}`);
    if (item.targetHints.length > 0) {
      console.log(`  target hints: ${item.targetHints.join(", ")}`);
    }
    if (item.matchedSignals.length > 0) {
      console.log(`  matched signals: ${item.matchedSignals.join("; ")}`);
    }
    console.log(`  prerequisites: ${item.prerequisites.join("; ")}`);
    console.log(`  safe steps: ${item.safeSteps.join("; ")}`);
    if (item.activeSteps.length > 0) {
      console.log(`  active steps: ${item.activeSteps.join("; ")}`);
    }
    console.log(`  evidence: ${item.evidenceToCollect.join("; ")}`);
    console.log(`  false-positive guards: ${item.falsePositiveGuards.join("; ")}`);
  }
}

function printAuthorizationBoundaryMatrix(agent: MainAgent, sessionId: string): void {
  const matrix = agent.buildAuthorizationBoundaryMatrix(sessionId);
  console.log(`Authorization Boundary Matrix (${matrix.generatedAt})`);
  console.log(`Target: ${matrix.target}`);
  console.log(`Auth contexts: ${matrix.authContextCount}`);
  console.log(`Summary: total=${matrix.summary.total} ready=${matrix.summary.ready} blocked=${matrix.summary.blocked} needsExample=${matrix.summary.needsExample} compared=${matrix.summary.compared}`);
  if (matrix.items.length === 0) {
    console.log("No authorization-sensitive normalized API routes recorded yet.");
    return;
  }
  for (const item of matrix.items.slice(0, 40)) {
    const categories = item.categories.length > 0 ? item.categories.join(",") : "uncategorized";
    console.log(`- ${item.status} | ${item.method} ${item.pathTemplate} | auth:${item.authRequired} | categories:${categories}`);
    if (item.examples.length > 0) {
      console.log(`  examples: ${item.examples.slice(0, 3).join(", ")}`);
    }
    if (item.riskSignals.length > 0) {
      console.log(`  signals: ${item.riskSignals.join(", ")}`);
    }
    if (item.comparedByEvidenceIds.length > 0) {
      console.log(`  compared evidence: ${item.comparedByEvidenceIds.join(", ")}`);
    }
    console.log(`  next: ${item.nextAction}`);
  }
}

function printAuthorizationValidationPlan(agent: MainAgent, sessionId: string): void {
  const plan = agent.buildAuthorizationValidationPlan(sessionId);
  console.log(`Authorization Validation Plan (${plan.generatedAt})`);
  console.log(`Target: ${plan.target}`);
  console.log(`Auth contexts: ${plan.authContextCount}`);
  console.log(`Summary: total=${plan.summary.total} ready=${plan.summary.ready} blocked=${plan.summary.blocked} needsExample=${plan.summary.needsExample} passive=${plan.summary.passiveOnly} compared=${plan.summary.compared}`);
  if (plan.nextActions.length > 0) {
    console.log("Next Actions");
    for (const action of plan.nextActions) {
      console.log(`- ${action}`);
    }
  }
  if (plan.candidates.length === 0) {
    console.log("No authorization validation candidates yet. Run webapp-recon/api inventory first.");
    return;
  }
  console.log("Candidates");
  for (const candidate of plan.candidates.slice(0, 40)) {
    const categories = candidate.categories.length > 0 ? candidate.categories.join(",") : "uncategorized";
    const blocked = candidate.blockedReason ? ` | blocked:${candidate.blockedReason}` : "";
    console.log(`- ${candidate.status} | score:${candidate.priorityScore} | ${candidate.method} ${candidate.pathTemplate} | auth:${candidate.authRequired} | categories:${categories}${blocked}`);
    if (candidate.priorityRationale.length > 0) {
      console.log(`  priority: ${candidate.priorityRationale.slice(0, 4).join("; ")}`);
    }
    if (candidate.examples.length > 0) {
      console.log(`  examples: ${candidate.examples.slice(0, 3).join(", ")}`);
    }
    if (candidate.objectReferences.length > 0) {
      console.log(`  object refs: ${candidate.objectReferences.map((ref) => `${ref.location}:${ref.name}`).join(", ")}`);
    }
    if (candidate.riskSignals.length > 0) {
      console.log(`  signals: ${candidate.riskSignals.join(", ")}`);
    }
    console.log(`  safe steps: ${candidate.safeProcedure.join("; ")}`);
    console.log(`  evidence: ${candidate.expectedEvidence.join("; ")}`);
    console.log(`  guards: ${candidate.falsePositiveGuards.join("; ")}`);
  }
  console.log("Guardrails");
  for (const guardrail of plan.guardrails) {
    console.log(`- ${guardrail}`);
  }
}

function printSecurityAuthContext(context: SecurityAuthContext): void {
  console.log(`${context.id} | ${context.name} | role:${context.role ?? "unknown"} | user:${context.username ?? "unknown"}`);
  console.log(`base: ${context.baseUrl ?? "not set"}`);
  console.log(`cookies: ${context.cookieHeader ? "yes" : "no"} | authorization: ${context.authorizationHeader ? "yes" : "no"} | storage-state: ${context.storageStatePath ?? "none"}`);
}

function printSecurityAuthContexts(contexts: SecurityAuthContext[]): void {
  if (contexts.length === 0) {
    console.log("No authenticated contexts registered.");
    return;
  }
  console.log("Authenticated Contexts");
  for (const context of contexts) {
    printSecurityAuthContext(context);
  }
}

function printFindings(agent: MainAgent, sessionId: string): void {
  const findings = agent.listFindings(sessionId);
  const evidence = agent.listEvidence(sessionId);
  const assets = agent.listAssets(sessionId);
  const technologies = agent.listTechnologies(sessionId);
  const cveMatches = agent.listCveMatches(sessionId);
  if (findings.length === 0 && evidence.length === 0 && assets.length === 0 && technologies.length === 0 && cveMatches.length === 0) {
    console.log("No findings or evidence found.");
    return;
  }
  if (assets.length > 0) {
    console.log("Assets");
    for (const asset of assets) {
      console.log(`- ${asset.id} | ${asset.kind} | ${asset.confidence} | ${asset.value} | ${asset.source}`);
    }
  }
  if (technologies.length > 0) {
    console.log("Technologies");
    for (const technology of technologies) {
      const version = technology.version ? ` ${technology.version}` : "";
      const category = technology.category ? ` | ${technology.category}` : "";
      console.log(`- ${technology.id} | ${technology.confidence}${category} | ${technology.name}${version} | ${technology.target}`);
      if (technology.evidenceSummary) {
        console.log(`  evidence: ${technology.evidenceSummary}`);
      }
    }
  }
  if (cveMatches.length > 0) {
    console.log("CVE Matches");
    for (const match of cveMatches) {
      const cve = match.cveId ? ` | ${match.cveId}` : "";
      console.log(`- ${match.id} | ${match.severity} | ${match.confidence}${cve} | ${match.title}`);
      console.log(`  target: ${match.target}`);
      console.log(`  rationale: ${match.rationale}`);
    }
  }
  if (findings.length > 0) {
    console.log("Findings");
    for (const finding of findings) {
      console.log(`- ${finding.id} | ${finding.state ?? "candidate"} | ${finding.severity} | ${finding.confidence} | ${finding.title}`);
      console.log(`  target: ${finding.target}`);
      console.log(`  ${finding.description}`);
      if (finding.evidenceIds && finding.evidenceIds.length > 0) {
        console.log(`  evidence ids: ${finding.evidenceIds.join(", ")}`);
      }
      if (finding.evidenceSummary) {
        console.log(`  evidence: ${finding.evidenceSummary}`);
      }
      if (finding.remediation) {
        console.log(`  remediation: ${finding.remediation}`);
      }
    }
  }
  if (evidence.length > 0) {
    console.log("Evidence");
    for (const item of evidence) {
      console.log(`- ${item.id} | ${item.kind} | ${item.source} | ${item.summary}`);
    }
  }
}

function printSecurityChecklist(agent: MainAgent, sessionId: string): void {
  const checks = agent.listSecurityChecks(sessionId);
  if (checks.length === 0) {
    console.log("No security validation checks found.");
    return;
  }
  console.log("Security Validation Checklist");
  for (const check of checks) {
    const active = check.activeRequiresApproval ? "active-approval" : "passive-safe";
    console.log(`- ${check.checkId} | ${check.status} | ${active} | ${check.title}`);
    console.log(`  category: ${check.category}`);
    console.log(`  phase: ${check.phase} | target: ${check.target}`);
    if (check.evidenceSummary) {
      console.log(`  evidence: ${check.evidenceSummary}`);
    }
    if (check.rationale) {
      console.log(`  rationale: ${check.rationale}`);
    }
    if (check.safeChecks.length > 0) {
      console.log(`  safe checks: ${check.safeChecks.join(" ")}`);
    }
  }
}

function printToolInventory(check = false, projectRoot = process.cwd()): void {
  const inventory = getSecurityToolInventory(projectRoot);
  console.log("Security Tools");
  for (const tool of inventory) {
    const status = tool.available ? "available" : "missing";
    const source = tool.localSourceAvailable ? "source:yes" : "source:no";
    const binary = tool.localBinaryAvailable ? `local:${tool.localBinaryPath}` : tool.pathBinaryAvailable ? "PATH" : "binary:no";
    console.log(`- ${tool.id} | ${status} | ${tool.phase} | ${tool.intensity} | ${source} | ${binary}`);
    console.log(`  repo: ${tool.repository}`);
    console.log(`  install: ${tool.installCommand}`);
    if (tool.notes.length > 0) {
      console.log(`  notes: ${tool.notes.join(" ")}`);
    }
  }
  if (check) {
    console.log("\nHealth Check");
    for (const health of checkSecurityToolHealth(projectRoot)) {
      const status = health.runnable ? `ran exit=${health.exitCode ?? "null"}` : "not runnable";
      console.log(`- ${health.id} | ${status} | ${health.command}`);
      console.log(`  ${health.summary.split(/\r?\n/)[0] ?? ""}`);
    }
  }
}

function printKnowledgeStats(projectRoot = process.cwd()): void {
  const index = loadSecurityKnowledgeIndex(projectRoot);
  const frameworkIndex = loadFrameworkKnowledgeIndex(projectRoot);
  const businessLogic = loadBusinessLogicKnowledge(projectRoot);
  console.log("Security Knowledge");
  if (index) {
    console.log(`- source: ${index.source}`);
    console.log(`- generated: ${index.generatedAt}`);
    console.log(`- source path: ${index.sourcePath}`);
    console.log(`- templates indexed: ${index.templateCount}`);
    console.log(`- CVE templates: ${index.cveTemplateCount}`);
    console.log(`- unique CVEs: ${index.cveCount}`);
  } else {
    console.log("- CVE/template index: missing. Run `aegisprobe knowledge sync` after pulling nuclei templates.");
  }
  if (frameworkIndex) {
    console.log(`- framework/CMS profiles: ${frameworkIndex.profileCount}`);
    console.log(`- Wappalyzer technologies parsed: ${frameworkIndex.wappalyzerTechnologyCount}`);
    const ecosystems = [...new Set(frameworkIndex.profiles.map((item) => item.ecosystem))];
    console.log(`- framework ecosystems: ${ecosystems.join(", ")}`);
    const topProfiles = frameworkIndex.profiles
      .slice(0, 8)
      .map((item) => `${item.name}(${item.templateCount})`)
      .join(", ");
    console.log(`- top framework profiles: ${topProfiles}`);
  } else {
    console.log("- framework/CMS index: missing. Run `aegisprobe knowledge sync` after pulling Wappalyzer and nuclei templates.");
  }
  console.log(`- business-logic playbooks: ${businessLogic.length}`);
  const categories = [...new Set(businessLogic.map((item) => item.category))];
  console.log(`- business-logic categories: ${categories.join(", ")}`);
}

function printKnowledgeSearch(query: string, limit: number, projectRoot = process.cwd()): void {
  const results = searchSecurityKnowledge(query, projectRoot, limit);
  if (results.length === 0) {
    console.log(`No knowledge results for: ${query}`);
    return;
  }
  console.log(`Knowledge results for: ${query}`);
  for (const result of results) {
    console.log(`- ${result.kind} | ${result.severity ?? "n/a"} | ${result.id} | ${result.title}`);
    console.log(`  source: ${result.source}`);
    console.log(`  ${result.summary}`);
  }
}

function vboxManagePath(): string {
  const configured = process.env.VBOXMANAGE;
  if (configured) {
    return configured;
  }
  if (process.platform === "win32") {
    return "C:\\Program Files\\Oracle\\VirtualBox\\VBoxManage.exe";
  }
  return "VBoxManage";
}

function runVBoxManage(args: string[]): { exitCode: number | null; output: string } {
  const result = spawnSync(vboxManagePath(), args, {
    encoding: "utf8",
    windowsHide: true,
    timeout: 30_000
  });
  return {
    exitCode: result.status,
    output: `${result.stdout ?? ""}${result.stderr ?? ""}`.trim() || (result.error ? result.error.message : "")
  };
}

function printVirtualBoxLabs(filter?: string): void {
  const list = runVBoxManage(["list", "vms"]);
  if (list.exitCode !== 0) {
    console.log(`VBoxManage unavailable or failed: ${list.output}`);
    return;
  }
  const vms = list.output
    .split(/\r?\n/)
    .map((line) => line.match(/^"(.+)"\s+\{(.+)\}$/))
    .filter((match): match is RegExpMatchArray => Boolean(match))
    .map((match) => ({ name: match[1], uuid: match[2] }))
    .filter((vm) => !filter || vm.name.toLowerCase().includes(filter.toLowerCase()) || vm.uuid.toLowerCase() === filter.toLowerCase());

  if (vms.length === 0) {
    console.log(filter ? `No VirtualBox VM matched: ${filter}` : "No VirtualBox VMs found.");
    return;
  }

  console.log("VirtualBox Labs");
  for (const vm of vms) {
    const info = runVBoxManage(["showvminfo", vm.uuid, "--machinereadable"]).output;
    const guestProps = runVBoxManage(["guestproperty", "enumerate", vm.uuid]).output;
    const state = matchMachineValue(info, "VMState") ?? "unknown";
    const os = matchMachineValue(info, "ostype") ?? "unknown";
    const nics = info
      .split(/\r?\n/)
      .filter((line) => /^nic\d+=|^hostonlyadapter\d+=|^bridgeadapter\d+=|^natnet\d+=/i.test(line))
      .slice(0, 12);
    const ips = [...new Set([
      ...[...guestProps.matchAll(/Net\/\d+\/V4\/IP[^,]*,\s+value:\s+([0-9.]+)/gi)].map((match) => match[1]),
      ...[...guestProps.matchAll(/\b(192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+)\b/g)].map((match) => match[1])
    ])];
    console.log(`- ${vm.name} | ${state} | ${os} | ${vm.uuid}`);
    if (nics.length > 0) {
      console.log(`  network: ${nics.join("; ")}`);
    }
    console.log(`  candidate ips: ${ips.join(", ") || "none from guest properties; use host-only DHCP/ARP or VM console to identify IP"}`);
  }
}

function matchMachineValue(input: string, key: string): string | undefined {
  const match = input.match(new RegExp(`^${key}="?(.*?)"?$`, "mi"));
  return match?.[1];
}

async function runTaskLoop(
  agent: MainAgent,
  sessionId: string,
  initialInput: string,
  rl: ReturnType<typeof createInterface>
): Promise<void> {
  let nextInput = initialInput;
  // No hard turn limit — the model decides when the task is complete.
  while (true) {
    const result = await agent.runTurn(sessionId, nextInput);
    printTurnResult(result);

    if (result.status === "completed") {
      return;
    }

    if (result.status === "needs_input" && result.requestedInput) {
      const answer = await askLine(
        rl,
        `\nAgent needs information: ${result.requestedInput.question}\nReason: ${result.requestedInput.reason}\nYour answer (/stop to pause): `
      );
      if (!answer.trim() || answer.trim() === "/stop") {
        console.log("Task paused because required information was not provided.");
        return;
      }
      nextInput = `User provided additional information for the same task:\n${answer.trim()}`;
      continue;
    }

    return;
  }
}

function printTurnResult(result: TurnResult): void {
  if (result.events.length > 0) {
    console.log("");
  }
  console.log("Final Message");
  console.log(result.finalMessage || "(no final message)");
}

function printRealtimeEvent(event: TurnEvent): void {
  printAegisEvent(event);
}

function eventDetails(payload: unknown): string[] {
  if (!payload || typeof payload !== "object") {
    return [];
  }
  const data = payload as Record<string, unknown>;
  const details: string[] = [];
  for (const key of ["phase", "toolId", "probe", "risk", "approved", "remembered", "exitCode", "status", "findingCount", "outputArtifact", "manifest"]) {
    if (data[key] !== undefined) {
      details.push(`${key}: ${String(data[key])}`);
    }
  }
  if (typeof data.command === "string") {
    details.push(`command: ${data.command}`);
  }
  if (typeof data.reason === "string") {
    details.push(`reason: ${data.reason}`);
  }
  if (typeof data.summary === "string") {
    details.push(`summary: ${data.summary.split(/\r?\n/).slice(0, 4).join(" | ")}`);
  }
  if (typeof data.stepCount === "number") {
    details.push(`steps: ${data.stepCount}`);
  }
  return details;
}

function printGraphEvidence(agent: MainAgent, sessionId: string, kindFilter?: string): void {
  const graph = agent.getGraph(sessionId);
  if (!graph) {
    console.log(`No attack graph found for session ${sessionId}.`);
    return;
  }
  let evidence = graph.evidence.filter((e) => e.id !== "origin" && e.id !== "goal");
  if (kindFilter) {
    evidence = evidence.filter((e) => e.kind === kindFilter);
  }
  console.log(`Evidence nodes: ${evidence.length} (origin + goal hidden)`);
  console.log("");
  for (const ev of evidence) {
    const src = typeof ev.source === "object" && "toolId" in ev.source ? `[${(ev.source as any).toolId}]` : `[${ev.source.kind}]`;
    console.log(`${ev.id} ${src} ${ev.kind} [${ev.confidence}]: ${ev.description.slice(0, 200)}`);
  }
}

function printGraphHypotheses(agent: MainAgent, sessionId: string, showAll?: boolean): void {
  const graph = agent.getGraph(sessionId);
  if (!graph) {
    console.log(`No attack graph found for session ${sessionId}.`);
    return;
  }
  let hypotheses = graph.hypotheses;
  if (!showAll) {
    hypotheses = hypotheses.filter((h) => h.status === "open" || h.status === "claimed");
  }
  const statusCounts: Record<string, number> = {};
  for (const h of graph.hypotheses) { statusCounts[h.status] = (statusCounts[h.status] ?? 0) + 1; }
  console.log(`Hypotheses: open=${statusCounts["open"] ?? 0} claimed=${statusCounts["claimed"] ?? 0} concluded=${statusCounts["concluded"] ?? 0} failed=${statusCounts["failed"] ?? 0}`);
  console.log("");
  for (const hy of hypotheses) {
    const statusMarker = hy.status === "claimed" ? ` [${hy.claimedBy}]` : ` [${hy.status}]`;
    console.log(`${hy.id} [${hy.priority}] ${hy.category}${statusMarker}: ${hy.description.slice(0, 200)}`);
    console.log(`  based on: [${hy.basedOn.join(", ")}]`);
    if (hy.concludedTo) console.log(`  → concluded to: ${hy.concludedTo}`);
  }
}

main().catch((error) => {
  console.error(error instanceof Error ? error.message : error);
  process.exitCode = 1;
});
