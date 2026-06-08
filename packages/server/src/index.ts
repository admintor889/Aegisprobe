import { createServer } from "node:http";
import { existsSync, realpathSync } from "node:fs";
import { join as joinPath, dirname, resolve as resolvePath, isAbsolute } from "node:path";
import { fileURLToPath } from "node:url";
import express, { type Request, type Response } from "express";
import { WebSocketServer, type WebSocket } from "ws";
import {
  MainAgent,
  buildAuthorizationBoundaryMatrix,
  buildWebPentestControlPlane,
  buildWebPentestOperatingPicture,
  type AuthorizationBoundaryMatrix,
  type AuthorizationBoundaryMatrixItem,
  type WebPentestControlPlane,
  type WebPentestOperatingEndpoint,
  type WebPentestOperatingPicture
} from "@aegisprobe/core";
import { type TurnEvent, newId, nowIso } from "@aegisprobe/shared";
import { OpenAICompatibleProvider, loadConfig } from "@aegisprobe/provider";
import { AuditStore } from "@aegisprobe/storage";

// ── Types ──

type WsClient = {
  ws: WebSocket;
  sessionId?: string;
};

type SessionState = {
  id: string;
  target: string;
  mode: "chat" | "pentest";
  status: "idle" | "running" | "paused" | "completed" | "failed";
  agent: MainAgent | null;
  store: AuditStore | null;
  events: TurnEvent[];
  messages: { role: string; content: string; time: string }[];
  createdAt: string;
};

let lastAgentCreateError: string | null = null;

// ── Config ──

const __filename = realpathSync(fileURLToPath(import.meta.url));
const __dirname = dirname(__filename);
// __dirname = packages/server/dist → ../../../ = project root
const WEBUI_ROOT = joinPath(__dirname, "../../../apps/webui");
const PROJECT_ROOT = joinPath(__dirname, "../../..");

function resolveServerConfigPath(configPath?: string): string {
  if (configPath) return isAbsolute(configPath) ? configPath : resolvePath(PROJECT_ROOT, configPath);
  if (process.env.AEGISPROBE_CONFIG) {
    return isAbsolute(process.env.AEGISPROBE_CONFIG)
      ? process.env.AEGISPROBE_CONFIG
      : resolvePath(PROJECT_ROOT, process.env.AEGISPROBE_CONFIG);
  }
  return joinPath(PROJECT_ROOT, "configs/config.yaml");
}
function readUiMeta(): { model: string; fastModel: string; projectRoot: string } {
  try {
    const config = loadConfig(resolveServerConfigPath());
    return {
      model: config.provider.model,
      fastModel: config.provider.fastModel,
      projectRoot: PROJECT_ROOT,
    };
  } catch {
    return {
      model: "deepseek-v4-pro",
      fastModel: "deepseek-v4-flash",
      projectRoot: PROJECT_ROOT,
    };
  }
}

// ── Session Store (in-memory for now, backed by AuditStore) ──

const sessions = new Map<string, SessionState>();
const wsClients = new Set<WsClient>();

function broadcast(event: TurnEvent): void {
  const data = JSON.stringify(event);
  for (const client of wsClients) {
    if (client.ws.readyState === client.ws.OPEN) {
      client.ws.send(data);
    }
  }
}

function broadcastFlow(flow: AgentFlowState): void {
  const data = JSON.stringify({ type: "flow", ...enrichFlowForClient(flow) });
  for (const client of wsClients) {
    if (client.ws.readyState === client.ws.OPEN) {
      client.ws.send(data);
    }
  }
}

// ── Agent Flow State ──

type FlowPhase = "idle" | "preflight" | "recon" | "fingerprint" | "analysis" | "exploitation" | "reporting" | "done";

type AgentFlowState = {
  sessionId: string;
  phase: FlowPhase;
  currentStep: string;
  steps: FlowStep[];
  subagents: SubAgentFlowItem[];
  findings: FindingFlowItem[];
  authzMatrix?: AuthorizationBoundaryFlowSnapshot;
  webPentestControl?: WebPentestControlFlowSnapshot;
  webPentestOperating?: WebPentestOperatingFlowSnapshot;
};

type AuthorizationBoundaryFlowSnapshot = {
  generatedAt: string;
  target: string;
  authContextCount: number;
  summary: AuthorizationBoundaryMatrix["summary"];
  items: AuthorizationBoundaryFlowItem[];
};

type AuthorizationBoundaryFlowItem = Pick<
  AuthorizationBoundaryMatrixItem,
  "method" | "pathTemplate" | "categories" | "status" | "nextAction" | "authRequired" | "riskSignals" | "comparedByEvidenceIds"
> & {
  exampleCount: number;
};

type WebPentestControlFlowSnapshot = Pick<
  WebPentestControlPlane,
  "generatedAt" | "target" | "stage" | "summary" | "evidenceCounts" | "nextBestActions" | "decisionGuards"
> & {
  gates: Array<Pick<WebPentestControlPlane["gates"][number], "id" | "status" | "priority" | "title" | "nextAction">>;
};

type WebPentestOperatingFlowSnapshot = Pick<
  WebPentestOperatingPicture,
  "generatedAt" | "target" | "stage" | "summary" | "authState" | "evidenceGaps" | "allowedNextActions" | "blockedUntilEvidence" | "decisionFrame"
> & {
  endpointMap: Array<Pick<WebPentestOperatingEndpoint, "method" | "pathTemplate" | "authRequired" | "confidence" | "queryParams" | "bodyParamHints" | "riskSignals" | "sources" | "score" | "nextAction">>;
};

type FlowStep = {
  id: string;
  title: string;
  status: "pending" | "running" | "completed" | "failed" | "skipped";
  tool?: string;
  command?: string;
  summary?: string;
  startTime?: string;
  endTime?: string;
};

type SubAgentFlowItem = {
  id: string;
  role: string;
  task: string;
  status: "queued" | "running" | "completed" | "failed";
};

type FindingFlowItem = {
  id: string;
  title: string;
  severity: string;
  confidence: string;
  description: string;
};

// ── Phase tracking per session ──

const sessionFlows = new Map<string, AgentFlowState>();

function resolveSqlitePath(config: ReturnType<typeof loadConfig>): string {
  return config.storage?.sqlitePath
    ? (isAbsolute(config.storage.sqlitePath) ? config.storage.sqlitePath : resolvePath(PROJECT_ROOT, config.storage.sqlitePath))
    : resolvePath(PROJECT_ROOT, "data/aegisprobe.sqlite");
}

function withAuditStore<T>(sessionId: string, fn: (store: AuditStore) => T): T | undefined {
  const session = sessions.get(sessionId);
  if (session?.store) return fn(session.store);

  let store: AuditStore | null = null;
  try {
    const config = loadConfig(resolveServerConfigPath());
    store = new AuditStore(resolveSqlitePath(config));
    return fn(store);
  } catch {
    return undefined;
  } finally {
    store?.close();
  }
}

function buildAuthorizationBoundarySnapshot(sessionId: string): AuthorizationBoundaryFlowSnapshot | undefined {
  return withAuditStore(sessionId, (store) => {
    const matrix = buildAuthorizationBoundaryMatrix(store, sessionId);
    if (matrix.summary.total === 0 && matrix.authContextCount === 0) return undefined;
    return {
      generatedAt: matrix.generatedAt,
      target: matrix.target,
      authContextCount: matrix.authContextCount,
      summary: matrix.summary,
      items: matrix.items.slice(0, 8).map((item) => ({
        method: item.method,
        pathTemplate: item.pathTemplate,
        categories: item.categories,
        status: item.status,
        nextAction: item.nextAction,
        authRequired: item.authRequired,
        riskSignals: item.riskSignals.slice(0, 4),
        comparedByEvidenceIds: item.comparedByEvidenceIds.slice(0, 4),
        exampleCount: item.examples.length,
      })),
    };
  });
}

function buildWebPentestControlSnapshot(sessionId: string): WebPentestControlFlowSnapshot | undefined {
  return withAuditStore(sessionId, (store) => {
    const control = buildWebPentestControlPlane(store, sessionId);
    return {
      generatedAt: control.generatedAt,
      target: control.target,
      stage: control.stage,
      summary: control.summary,
      evidenceCounts: control.evidenceCounts,
      nextBestActions: control.nextBestActions.slice(0, 5),
      decisionGuards: control.decisionGuards.slice(0, 5),
      gates: control.gates.map((gate) => ({
        id: gate.id,
        status: gate.status,
        priority: gate.priority,
        title: gate.title,
        nextAction: gate.nextAction,
      })),
    };
  });
}

function buildWebPentestOperatingSnapshot(sessionId: string): WebPentestOperatingFlowSnapshot | undefined {
  return withAuditStore(sessionId, (store) => {
    const picture = buildWebPentestOperatingPicture(store, sessionId);
    return {
      generatedAt: picture.generatedAt,
      target: picture.target,
      stage: picture.stage,
      summary: picture.summary,
      authState: picture.authState,
      endpointMap: picture.endpointMap.slice(0, 8).map((endpoint) => ({
        method: endpoint.method,
        pathTemplate: endpoint.pathTemplate,
        authRequired: endpoint.authRequired,
        confidence: endpoint.confidence,
        queryParams: endpoint.queryParams.slice(0, 5),
        bodyParamHints: endpoint.bodyParamHints.slice(0, 5),
        riskSignals: endpoint.riskSignals.slice(0, 5),
        sources: endpoint.sources.slice(0, 5),
        score: endpoint.score,
        nextAction: endpoint.nextAction,
      })),
      evidenceGaps: picture.evidenceGaps.slice(0, 6),
      allowedNextActions: picture.allowedNextActions.slice(0, 5),
      blockedUntilEvidence: picture.blockedUntilEvidence.slice(0, 5),
      decisionFrame: picture.decisionFrame.slice(0, 5),
    };
  });
}

function enrichFlowForClient(flow: AgentFlowState): AgentFlowState {
  const authzMatrix = buildAuthorizationBoundarySnapshot(flow.sessionId);
  const webPentestControl = buildWebPentestControlSnapshot(flow.sessionId);
  const webPentestOperating = buildWebPentestOperatingSnapshot(flow.sessionId);
  return {
    ...flow,
    authzMatrix,
    webPentestControl,
    webPentestOperating,
  };
}

function initFlow(sessionId: string): AgentFlowState {
  const flow: AgentFlowState = {
    sessionId,
    phase: "idle",
    currentStep: "等待启动",
    steps: [],
    subagents: [],
    findings: [],
  };
  sessionFlows.set(sessionId, flow);
  return flow;
}

function extractToolName(event: TurnEvent): string {
  const payload = event.payload as Record<string, unknown> | undefined;
  if (!payload) return "";

  // Security probe
  if (payload.probe && typeof payload.probe === "string") return `probe:${payload.probe}`;

  // Shell command — extract the binary name
  if (payload.command && typeof payload.command === "string") {
    const cmd = payload.command.trim();
    const firstWord = cmd.split(/\s+/)[0] ?? "";
    // Clean up: remove path, keep just the binary name
    const binary = firstWord.replace(/^.*[/\\]/, "").replace(/\.exe$/i, "");
    if (binary) return binary;
  }

  // Try toolId
  if (payload.toolId && typeof payload.toolId === "string") return payload.toolId as string;

  // Parse from message
  const msg = event.message;
  if (msg.includes("baseline probe")) return "baseline_probe";
  if (msg.includes("security probe")) return "security_probe";
  if (msg.includes("shell command")) return "shell";

  return "";
}

function extractPhaseHint(event: TurnEvent): FlowPhase | null {
  const payload = event.payload as Record<string, unknown> | undefined;
  // Phase from payload
  if (payload?.phase && typeof payload.phase === "string") {
    const p = payload.phase as string;
    if (p === "recon" || p === "fingerprint" || p === "frontend") return "recon";
    if (p === "cve" || p === "owasp") return "analysis";
    if (p === "exploit") return "exploitation";
    if (p === "report") return "reporting";
  }
  return null;
}

function updateFlowFromEvent(sessionId: string, event: TurnEvent): AgentFlowState {
  let flow = sessionFlows.get(sessionId);
  if (!flow) flow = initFlow(sessionId);

  switch (event.kind) {
    case "turn_started":
      if (flow.phase === "idle") {
        flow.phase = "preflight";
        flow.currentStep = "预检 — 检查可用工具";
      }
      break;

    case "tool_started": {
      const tool = extractToolName(event);
      const payload = event.payload as Record<string, unknown> | undefined;
      const cmd = (payload?.command as string) ?? "";
      const stepId = newId("step");

      // Detect phase
      const phaseHint = extractPhaseHint(event);
      if (phaseHint) flow.phase = phaseHint;
      else if (tool === "nmap" || tool === "naabu") flow.phase = "recon";
      else if (tool === "subfinder" || tool === "amass" || tool === "dnsx") flow.phase = "recon";
      else if (tool === "httpx" || tool === "katana" || tool === "whatweb" || tool === "curl") flow.phase = "fingerprint";
      else if (tool === "nuclei" || tool === "searchsploit") flow.phase = "analysis";
      else if (tool.includes("exploit") || tool === "msfconsole" || tool === "sqlmap") flow.phase = "exploitation";
      else if (tool.startsWith("probe:") || tool === "baseline_probe" || tool === "security_probe") flow.phase = "recon";

      const title = tool ? `执行 ${tool}` : event.message.slice(0, 60);
      flow.steps.push({
        id: stepId,
        title,
        status: "running",
        tool,
        command: cmd,
        startTime: nowIso(),
      });
      flow.currentStep = tool ? `正在执行: ${tool}` : event.message.slice(0, 60);
      break;
    }

    case "tool_completed": {
      const tool = extractToolName(event);
      const payload = event.payload as Record<string, unknown> | undefined;
      const summary = (payload?.summary as string) ?? event.message;
      // Find the last running step and mark completed (fuzzy match)
      let matched = false;
      for (let i = flow.steps.length - 1; i >= 0; i--) {
        if (flow.steps[i].status === "running") {
          if (flow.steps[i].tool === tool || tool === "" || flow.steps[i].tool === "" || !matched) {
            flow.steps[i].status = matched ? "skipped" : "completed";
            if (!matched) {
              flow.steps[i].summary = summary;
              flow.steps[i].endTime = nowIso();
              if (!flow.steps[i].tool && tool) flow.steps[i].tool = tool;
              if (flow.steps[i].title.startsWith("执行 ")) {
                flow.steps[i].title = tool ? `执行 ${tool}` : event.message.slice(0, 60);
              }
              matched = true;
            }
            if (matched && flow.steps[i].tool === tool) break; // only skip earlier duplicates of same tool
          }
        }
      }
      flow.currentStep = tool ? `完成: ${tool}` : event.message.slice(0, 60);

      // Detect exploitation success from summary
      if (summary.includes("uid=") || summary.includes("RCE achieved") || summary.includes("root")) {
        flow.phase = "exploitation";
        flow.findings.push({
          id: newId("f"),
          title: "RCE 漏洞利用成功",
          severity: "critical",
          confidence: "confirmed",
          description: summary.slice(0, 200),
        });
      }
      break;
    }

    case "tool_blocked": {
      const tool = extractToolName(event);
      let updated = false;
      for (let i = flow.steps.length - 1; i >= 0; i--) {
        if (flow.steps[i].status === "running") {
          flow.steps[i].status = "failed";
          flow.steps[i].summary = event.message;
          flow.steps[i].endTime = nowIso();
          updated = true;
          break;
        }
      }
      if (!updated) {
        flow.steps.push({
          id: newId("step"),
          title: tool ? `执行 ${tool}` : "工具执行受阻",
          status: "failed",
          tool,
          summary: event.message,
          endTime: nowIso(),
        });
      }
      flow.currentStep = tool ? `受阻: ${tool}` : event.message.slice(0, 60);
      break;
    }

    case "subagent_started":
    case "subagent_launched": {
      const payload = event.payload as { role?: string; task?: string } | undefined;
      flow.subagents.push({
        id: newId("sa"),
        role: payload?.role ?? "unknown",
        task: payload?.task ?? event.message,
        status: "running",
      });
      flow.currentStep = `启动子 Agent: ${payload?.role ?? ""}`;
      break;
    }

    case "subagent_completed": {
      const payload = event.payload as { role?: string } | undefined;
      for (let i = flow.subagents.length - 1; i >= 0; i--) {
        if (flow.subagents[i].role === payload?.role && flow.subagents[i].status === "running") {
          flow.subagents[i].status = "completed";
          break;
        }
      }
      break;
    }

    case "subagent_failed": {
      const payload = event.payload as { role?: string } | undefined;
      for (let i = flow.subagents.length - 1; i >= 0; i--) {
        if (flow.subagents[i].role === payload?.role && flow.subagents[i].status === "running") {
          flow.subagents[i].status = "failed";
          break;
        }
      }
      break;
    }

    case "turn_completed":
      flow.phase = "done";
      flow.currentStep = "扫描完成";
      break;

    case "agent_message":
      // If message mentions findings, we could parse them out
      break;
  }

  sessionFlows.set(sessionId, flow);
  return flow;
}

// ── Express App ──

const app = express();
app.use(express.json());

// Serve static frontend
app.use(express.static(WEBUI_ROOT));

// ── Helpers ──

function param(req: Request, name: string): string {
  const v = (req.params as Record<string, string | string[]>)[name];
  return Array.isArray(v) ? v[0] ?? "" : v ?? "";
}

// ── REST API ──

app.get("/api/meta", (_req: Request, res: Response) => {
  const meta = readUiMeta();
  res.json(meta);
});

app.get("/api/workspace", (_req: Request, res: Response) => {
  res.json({
    rootLabel: PROJECT_ROOT.split(/[/\\]/).filter(Boolean).at(-1) ?? "aegisprobe",
    projectRoot: PROJECT_ROOT,
  });
});

// GET /api/sessions — list all sessions
app.get("/api/sessions", (_req: Request, res: Response) => {
  const list: Array<{ id: string; target: string; mode: string; status: string; createdAt: string }> = [];
  for (const [id, s] of sessions) {
    list.push({ id, target: s.target, mode: s.mode, status: s.status, createdAt: s.createdAt });
  }
  res.json({ sessions: list });
});

// POST /api/sessions — create new session
app.post("/api/sessions", (req: Request, res: Response) => {
  const { target, mode } = req.body as { target?: string; mode?: string };
  if (!target) {
    res.status(400).json({ error: "target is required" });
    return;
  }

  const id = newId("ses");
  const session: SessionState = {
    id,
    target,
    mode: mode === "pentest" ? "pentest" : "chat",
    status: "idle",
    agent: null,
    store: null,
    events: [],
    messages: [],
    createdAt: nowIso(),
  };
  sessions.set(id, session);
  initFlow(id);

  res.json({ sessionId: id, target, mode: session.mode, createdAt: session.createdAt });
});

// GET /api/sessions/:id — session detail
app.get("/api/sessions/:id", (req: Request, res: Response) => {
  const id = param(req, "id");
  const session = sessions.get(id);
  if (!session) {
    res.status(404).json({ error: "session not found" });
    return;
  }
  res.json({
    id: session.id,
    target: session.target,
    mode: session.mode,
    status: session.status,
    createdAt: session.createdAt,
  });
});

// GET /api/sessions/:id/messages — conversation history
app.get("/api/sessions/:id/messages", (req: Request, res: Response) => {
  const id = param(req, "id");
  const session = sessions.get(id);
  if (!session) {
    res.status(404).json({ error: "session not found" });
    return;
  }
  res.json({ messages: session.messages });
});

// POST /api/sessions/:id/messages — send message to agent
app.post("/api/sessions/:id/messages", async (req: Request, res: Response) => {
  const id = param(req, "id");
  const session = sessions.get(id);
  if (!session) {
    res.status(404).json({ error: "session not found" });
    return;
  }

  const { content } = req.body as { content?: string };
  if (!content) {
    res.status(400).json({ error: "content is required" });
    return;
  }

  // Record user message
  const userMsg = { role: "user" as const, content, time: nowIso() };
  session.messages.push(userMsg);

  // Lazily create agent if not yet initialized
  if (!session.agent) {
    try {
      const result = createAgent(id, session.target || "general", session.mode);
      if (!result.agent) {
        const errMsg = lastAgentCreateError
          ? `Failed to start agent: ${lastAgentCreateError}`
          : "Failed to start agent. Check server logs.";
        session.messages.push({ role: "assistant", content: errMsg, time: nowIso() });
        res.json({ message: { role: "assistant", content: errMsg, time: nowIso() } });
        return;
      }
      session.agent = result.agent;
    } catch (err) {
      const errMsg = `Agent error: ${err instanceof Error ? err.message : String(err)}`;
      session.messages.push({ role: "assistant", content: errMsg, time: nowIso() });
      res.json({ message: { role: "assistant", content: errMsg, time: nowIso() } });
      return;
    }
  }

  // Respond immediately — agent responses flow via WebSocket events
  res.json({ message: { role: "user", content, time: userMsg.time }, status: "processing" });

  // Process agent turn asynchronously
  const agent = session.agent;
  try {
    const result = await agent.runTurn(id, content);
    if (result.finalMessage) {
      const latestMessage = session.messages.at(-1);
      if (!(latestMessage?.role === "assistant" && latestMessage.content === result.finalMessage)) {
        session.messages.push({ role: "assistant", content: result.finalMessage, time: nowIso() });
        broadcast({ id: newId("ev"), sessionId: id, turnId: result.turnId, kind: "agent_message", message: result.finalMessage, createdAt: nowIso() });
      }
    }
  } catch (err) {
    const errMsg = `Agent error: ${err instanceof Error ? err.message : String(err)}`;
    session.messages.push({ role: "assistant", content: errMsg, time: nowIso() });
    broadcast({ id: newId("ev"), sessionId: id, turnId: "", kind: "turn_failed", message: errMsg, createdAt: nowIso() });
  }
});

// GET /api/sessions/:id/flow — current agent flow state
app.get("/api/sessions/:id/flow", (req: Request, res: Response) => {
  const id = param(req, "id");
  const flow = sessionFlows.get(id);
  if (!flow) {
    res.json(enrichFlowForClient(initFlow(id)));
    return;
  }
  res.json(enrichFlowForClient(flow));
});

// POST /api/events — receive TurnEvents from CLI agent (bridge)
app.post("/api/events", (req: Request, res: Response) => {
  const event = req.body as TurnEvent | undefined;
  if (!event || !event.sessionId || !event.kind) {
    res.status(400).json({ error: "invalid event" });
    return;
  }

  // Forward to all WebSocket clients
  broadcast(event);

  // Update flow state
  const updatedFlow = updateFlowFromEvent(event.sessionId, event);
  broadcastFlow(updatedFlow);

  // Store event in session
  const session = sessions.get(event.sessionId);
  if (session) {
    session.events.push(event);
    if (event.kind === "agent_message") {
      session.messages.push({ role: "assistant", content: event.message, time: event.createdAt });
    } else if (event.kind === "turn_completed") {
      session.status = "completed";
    }
  } else {
    // Auto-create session if it doesn't exist
    sessions.set(event.sessionId, {
      id: event.sessionId,
      target: "",
      mode: "pentest",
      status: "running",
      agent: null,
      store: null,
      events: [event],
      messages: [],
      createdAt: nowIso(),
    });
    initFlow(event.sessionId);
  }

  res.json({ ok: true });
});

// POST /api/sessions/:id/start — start agent for a session (pentest mode)
app.post("/api/sessions/:id/start", async (req: Request, res: Response) => {
  const id = param(req, "id");
  const session = sessions.get(id);
  if (!session) {
    res.status(404).json({ error: "session not found" });
    return;
  }

  // Agent creation is done in-process via createAgent export
  // For now, respond with instructions to use CLI bridge
  res.json({
    ok: true,
    message: "Session ready. Use CLI pentest with --webui to run the agent against this target.",
    sessionId: id,
    target: session.target,
  });
});

// GET /api/sessions/:id/report — generated security report
app.get("/api/sessions/:id/report", (req: Request, res: Response) => {
  const id = param(req, "id");
  const session = sessions.get(id);
  if (!session) {
    res.status(404).json({ error: "session not found" });
    return;
  }
  // For now, return a simple placeholder report
  res.json({
    sessionId: session.id,
    target: session.target,
    generatedAt: nowIso(),
    summary: session.status === "completed" ? "扫描已完成" : "尚未生成报告",
    findings: [],
  });
});

// ── MIME type helper ──

function mimeType(ext: string): string {
  const map: Record<string, string> = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
  };
  return map[ext] ?? "application/octet-stream";
}

// ── Start Server ──

export type ServerOptions = {
  port?: number;
  host?: string;
  openBrowser?: boolean;
};

export function startServer(options: ServerOptions = {}): { app: ReturnType<typeof express>; httpServer: ReturnType<typeof createServer> } {
  const port = options.port ?? 3000;
  const host = options.host ?? "127.0.0.1";

  const httpServer = createServer(app);

  // WebSocket
  const wss = new WebSocketServer({ server: httpServer, path: "/ws" });

  wss.on("connection", (ws: WebSocket) => {
    const client: WsClient = { ws };
    wsClients.add(client);

    ws.on("close", () => {
      wsClients.delete(client);
    });

    ws.on("message", (raw: Buffer) => {
      try {
        const msg = JSON.parse(raw.toString()) as { type?: string; sessionId?: string };
        if (msg.type === "subscribe" && msg.sessionId) {
          client.sessionId = msg.sessionId;
        }
      } catch { /* ignore malformed */ }
    });

    // Send initial connection confirmation
    ws.send(JSON.stringify({ type: "connected", message: "WebSocket connected to AegisProbe" }));
  });

  httpServer.listen(port, host, () => {
    console.log(`\n  AegisProbe Web UI`);
    console.log(`  ─────────────────────────────────`);
    console.log(`  Local:   http://${host}:${port}`);
    console.log(`  WebSocket: ws://${host}:${port}/ws`);
    console.log(`  ─────────────────────────────────\n`);
  });

  return { app, httpServer };
}

// ── Agent Integration Helpers ──

export function createAgent(
  sessionId: string,
  target: string,
  mode: "chat" | "pentest",
  configPath?: string,
): { agent: MainAgent | null; flow: AgentFlowState } {
  const flow = initFlow(sessionId);

  try {
    const resolvedConfigPath = resolveServerConfigPath(configPath);
    const config = loadConfig(resolvedConfigPath);
    const provider = new OpenAICompatibleProvider(config.provider);
    const sqlitePath = resolveSqlitePath(config);
    const store = new AuditStore(sqlitePath);

    const agent = new MainAgent({
      provider,
      store,
      approve: async () => ({ approved: true, remember: false }),
      onEvent: (event: TurnEvent) => {
        // Forward event to WebSocket clients
        broadcast(event);

        // Update flow state
        const updatedFlow = updateFlowFromEvent(sessionId, event);
        broadcastFlow(updatedFlow);

        // Store event
        const session = sessions.get(sessionId);
        if (session) {
          session.events.push(event);
          // Track messages
          if (event.kind === "agent_message") {
            session.messages.push({ role: "assistant", content: event.message, time: event.createdAt });
          }
        }
      },
    });

    // Update session
    const session = sessions.get(sessionId);
    if (session) {
      session.agent = agent;
      session.store = store;
      session.status = "running";
    }

    flow.currentStep = "Agent 已启动";
    broadcastFlow(flow);

    return { agent, flow };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    lastAgentCreateError = message;
    console.error(`[agent-bridge] Failed to create agent: ${message}`);
    flow.currentStep = `启动失败: ${message}`;
    broadcastFlow(flow);
    return { agent: null, flow };
  }
}
