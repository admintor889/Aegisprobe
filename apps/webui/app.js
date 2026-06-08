const API = {
  async meta() {
    return readJson("/api/meta");
  },
  async workspace() {
    return readJson("/api/workspace");
  },
  async sessions() {
    return readJson("/api/sessions");
  },
  async createSession(target, mode) {
    return readJson("/api/sessions", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ target, mode }),
    });
  },
  async messages(id) {
    return readJson(`/api/sessions/${id}/messages`);
  },
  async sendMessage(id, content) {
    return readJson(`/api/sessions/${id}/messages`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content }),
    });
  },
  async flow(id) {
    return readJson(`/api/sessions/${id}/flow`);
  },
};

const PHASE_LABELS = {
  idle: "idle",
  preflight: "preflight",
  recon: "recon",
  fingerprint: "fingerprint",
  analysis: "analysis",
  exploitation: "exploitation",
  reporting: "reporting",
  done: "done",
};

const state = {
  sessionId: null,
  mode: "chat",
  ws: null,
  flow: null,
  sessions: [],
  seenEventIds: new Set(),
  terminalLines: initialTerminalLines(),
  currentCommand: "等待任务下发",
  currentTarget: "",
  workspace: {
    name: "agent-pentest-assistant",
    path: "",
  },
};

const $ = (selector) => document.querySelector(selector);

const dom = {
  chat: $("#chat-messages"),
  input: $("#chat-input"),
  send: $("#btn-send"),
  modelName: $("#model-name"),
  statusDot: $("#status-indicator"),
  statusText: $("#status-text"),
  statusInline: $("#status-inline"),
  sessionList: $("#session-list"),
  sessionSearch: $("#session-search"),
  sessionCount: $("#session-count"),
  sessionBadge: $("#session-badge"),
  modeBadge: $("#mode-badge"),
  wsStatus: $("#ws-status"),
  chatTitle: $("#chat-title"),
  phaseBadge: $("#phase-badge"),
  phaseName: $("#phase-name"),
  phaseStep: $("#phase-step"),
  webControlPlane: $("#web-control-plane"),
  authzMatrix: $("#authz-matrix"),
  workflowSteps: $("#workflow-steps"),
  findingList: $("#finding-list"),
  terminalOutput: $("#terminal-output"),
  currentCommand: $("#current-command"),
  workspaceName: $("#workspace-name"),
  workspaceShortName: $("#workspace-short-name"),
  workspacePath: $("#workspace-path"),
  workspacePicker: $("#workspace-picker"),
  pickWorkspace: $("#btn-pick-workspace"),
  newSession: $("#btn-new-session"),
  dialog: $("#dialog-new-session"),
  dialogTarget: $("#dialog-target"),
  dialogMode: $("#dialog-mode"),
  dialogCancel: $("#dialog-cancel"),
  dialogConfirm: $("#dialog-confirm"),
};

init();

async function init() {
  bindEvents();
  renderConversationWelcome();
  renderWorkflow();
  renderTerminal();
  await Promise.allSettled([loadMeta(), loadWorkspace(), loadSessions()]);
  connectWs();
}

function bindEvents() {
  dom.send.addEventListener("click", sendMessage);
  dom.input.addEventListener("keydown", onComposerKeyDown);
  dom.input.addEventListener("input", autoResizeComposer);
  dom.sessionSearch.addEventListener("input", () => renderSessions(state.sessions));
  dom.pickWorkspace.addEventListener("click", () => dom.workspacePicker.click());
  dom.workspacePicker.addEventListener("change", onWorkspacePicked);
  dom.newSession.addEventListener("click", openNewSessionDialog);
  dom.dialogCancel.addEventListener("click", () => dom.dialog.close());
  dom.dialogConfirm.addEventListener("click", createNewSession);
}

async function loadMeta() {
  try {
    const meta = await API.meta();
    dom.modelName.textContent = meta.model || "deepseek-v4-pro";
    if (!state.workspace.path) {
      state.workspace.path = meta.projectRoot || "";
      dom.workspacePath.textContent = meta.projectRoot || "未获取到项目根目录";
    }
  } catch {
    dom.modelName.textContent = "deepseek-v4-pro";
  }
}

async function loadWorkspace() {
  try {
    const workspace = await API.workspace();
    state.workspace = {
      name: workspace.rootLabel || "agent-pentest-assistant",
      path: workspace.projectRoot || state.workspace.path,
    };
  } finally {
    renderWorkspace();
  }
}

async function loadSessions() {
  try {
    const data = await API.sessions();
    state.sessions = data.sessions || [];
  } catch {
    state.sessions = [];
  }
  renderSessions(state.sessions);
}

function connectWs() {
  const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
  const ws = new WebSocket(`${protocol}//${window.location.host}/ws`);
  state.ws = ws;

  ws.addEventListener("open", () => {
    dom.wsStatus.textContent = "WS 已连接";
    dom.wsStatus.className = "meta-pill";
    if (state.sessionId) subscribeSession(state.sessionId);
  });

  ws.addEventListener("close", () => {
    dom.wsStatus.textContent = "WS 断开";
    dom.wsStatus.className = "meta-pill meta-pill-muted";
    window.setTimeout(connectWs, 3000);
  });

  ws.addEventListener("error", () => {
    dom.wsStatus.textContent = "WS 错误";
    dom.wsStatus.className = "meta-pill meta-pill-muted";
  });

  ws.addEventListener("message", (event) => {
    let payload;
    try {
      payload = JSON.parse(event.data);
    } catch {
      return;
    }

    if (payload.type === "connected") return;
    if (payload.sessionId && state.sessionId && payload.sessionId !== state.sessionId) return;

    if (payload.type === "flow") {
      state.flow = payload;
      renderWorkflow(payload);
      syncTerminalFromFlow(payload);
      return;
    }

    if (payload.kind) {
      handleTurnEvent(payload);
    }
  });
}

function subscribeSession(sessionId) {
  if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return;
  state.ws.send(JSON.stringify({ type: "subscribe", sessionId }));
}

function onComposerKeyDown(event) {
  if (event.key === "Enter" && !event.shiftKey) {
    event.preventDefault();
    sendMessage();
  }
}

function autoResizeComposer() {
  dom.input.style.height = "auto";
  dom.input.style.height = `${Math.min(dom.input.scrollHeight, 220)}px`;
}

function onWorkspacePicked(event) {
  const files = Array.from(event.target.files || []);
  if (files.length === 0) return;

  const root = files[0].webkitRelativePath.split("/")[0] || "aegisprobe";
  state.workspace = {
    name: root,
    path: "已从浏览器授权目录读取文件结构",
  };
  renderWorkspace();
}

function renderWorkspace() {
  dom.workspaceName.textContent = state.workspace.name || "未选择目录";
  dom.workspaceShortName.textContent = state.workspace.name || "未选择目录";
  dom.workspacePath.textContent = state.workspace.path || "未获取到目录路径";
}

function renderSessions(sessions) {
  const keyword = dom.sessionSearch.value.trim().toLowerCase();
  const filtered = sessions.filter((session) => {
    if (!keyword) return true;
    return `${session.target || ""} ${session.id} ${session.mode}`.toLowerCase().includes(keyword);
  });

  dom.sessionCount.textContent = String(filtered.length);

  if (filtered.length === 0) {
    dom.sessionList.innerHTML = '<div class="empty-state">暂无会话</div>';
    return;
  }

  dom.sessionList.innerHTML = filtered
    .slice()
    .reverse()
    .map((session) => `
      <div class="session-item ${session.id === state.sessionId ? "active" : ""}" data-id="${session.id}" data-mode="${session.mode}">
        <div class="session-title">${escapeHtml(session.target || session.id)}</div>
        <small>${escapeHtml(session.mode)} / ${escapeHtml(session.status)} / ${formatTime(session.createdAt, true)}</small>
      </div>
    `)
    .join("");

  dom.sessionList.querySelectorAll(".session-item").forEach((item) => {
    item.addEventListener("click", () => switchSession(item.dataset.id, item.dataset.mode));
  });
}

async function switchSession(sessionId, mode) {
  if (!sessionId) return;

  state.sessionId = sessionId;
  if (mode) state.mode = mode;
  state.seenEventIds.clear();
  const activeSession = state.sessions.find((item) => item.id === sessionId);
  state.currentTarget = activeSession?.target || state.currentTarget;
  updateSessionMeta();
  subscribeSession(sessionId);
  setStatus("idle", "会话已切换");
  dom.chatTitle.textContent = activeSession?.target || "新对话";

  try {
    const [messageData, flowData] = await Promise.all([API.messages(sessionId), API.flow(sessionId)]);
    dom.chat.innerHTML = "";

    if ((messageData.messages || []).length === 0) {
      renderConversationWelcome();
    } else {
      messageData.messages.forEach((message) => {
        appendMessage({
          role: message.role === "user" ? "user" : "assistant",
          content: message.content,
          time: message.time,
        });
      });
    }

    state.flow = flowData;
    renderWorkflow(flowData);
    syncTerminalFromFlow(flowData);
  } catch (error) {
    appendMessage({
      role: "system",
      content: `切换会话失败: ${toErrorMessage(error)}`,
      time: new Date().toISOString(),
    });
  }

  loadSessions();
}

function openNewSessionDialog() {
  dom.dialog.showModal();
  dom.dialogTarget.focus();
}

async function createNewSession() {
  const target = dom.dialogTarget.value.trim();
  const mode = dom.dialogMode.value;
  if (!target) return;

  try {
    const data = await API.createSession(target, mode);
    dom.dialog.close();
    dom.dialogTarget.value = "";
    state.sessionId = data.sessionId;
    state.mode = data.mode || mode;
    state.flow = null;
    state.seenEventIds.clear();
    state.currentTarget = target;
    state.terminalLines = initialTerminalLines(target);
    state.currentCommand = "等待任务下发";
    updateSessionMeta();
    dom.chatTitle.textContent = target;
    subscribeSession(state.sessionId);
    renderTerminal();
    renderWorkflow();
    dom.chat.innerHTML = "";
    appendMessage({
      role: "assistant",
      content: `已创建新会话，目标为 \`${target}\`。可以直接下达渗透任务。`,
      time: data.createdAt || new Date().toISOString(),
      meta: [`模式 ${state.mode}`],
    });
    loadSessions();
  } catch (error) {
    appendMessage({
      role: "system",
      content: `创建会话失败: ${toErrorMessage(error)}`,
      time: new Date().toISOString(),
    });
  }
}

async function ensureSession(seedText) {
  if (state.sessionId) return;
  const data = await API.createSession(seedText, state.mode);
  state.sessionId = data.sessionId;
  state.mode = data.mode || state.mode;
  state.currentTarget = seedText;
  state.terminalLines = initialTerminalLines(seedText);
  state.currentCommand = "等待任务下发";
  updateSessionMeta();
  dom.chatTitle.textContent = seedText;
  subscribeSession(state.sessionId);
  renderTerminal();
  loadSessions();
}

async function sendMessage() {
  const text = dom.input.value.trim();
  if (!text) return;

  try {
    await ensureSession(text);
  } catch (error) {
    appendMessage({
      role: "system",
      content: `初始化会话失败: ${toErrorMessage(error)}`,
      time: new Date().toISOString(),
    });
    return;
  }

  appendMessage({
    role: "user",
    content: text,
    time: new Date().toISOString(),
    meta: state.workspace.name ? [`工作目录 ${state.workspace.name}`] : [],
  });

  const payload = buildOutboundContent(text);
  dom.input.value = "";
  autoResizeComposer();
  setStatus("running", "agent 正在理解任务");
  appendTerminal(`[user] ${text}`, "info");

  try {
    const data = await API.sendMessage(state.sessionId, payload);
    if (data?.status !== "processing" && data?.message?.role !== "user") {
      appendMessage({
        role: data.message.role === "assistant" ? "assistant" : "system",
        content: data.message.content,
        time: data.message.time,
      });
    } else if ((!state.ws || state.ws.readyState !== WebSocket.OPEN) && data?.message && data.message.role !== "user") {
      appendMessage({
        role: "assistant",
        content: data.message.content,
        time: data.message.time,
      });
    }
  } catch (error) {
    appendMessage({
      role: "system",
      content: `发送失败: ${toErrorMessage(error)}`,
      time: new Date().toISOString(),
    });
    appendTerminal(`[error] ${toErrorMessage(error)}`, "error");
    setStatus("error", "发送失败");
    return;
  }

  setStatus("idle", "已发送");
}

function buildOutboundContent(text) {
  const context = [];
  if (isAbsoluteWorkspacePath(state.workspace.path)) context.push(`工作目录: ${state.workspace.path}`);
  if (context.length === 0) return text;
  return `${text}\n\n[上下文]\n${context.join("\n")}`;
}

function handleTurnEvent(event) {
  if (event.id && state.seenEventIds.has(event.id)) return;
  if (event.id) state.seenEventIds.add(event.id);

  const payload = event.payload || {};

  switch (event.kind) {
    case "agent_message":
      appendMessage({
        role: "assistant",
        content: event.message,
        time: event.createdAt,
      });
      appendTerminal("[agent] 已返回响应", "info");
      setStatus("idle", "响应完成");
      break;
    case "turn_started":
      setStatus("running", "新回合执行中");
      appendTerminal("[turn] start", "info");
      break;
    case "turn_completed":
      setStatus("success", "回合完成");
      appendTerminal("[turn] complete", "info");
      break;
    case "turn_failed":
      setStatus("error", "回合失败");
      appendTerminal(`[turn] failed: ${event.message}`, "error");
      appendMessage({
        role: "system",
        content: `回合失败: ${event.message}`,
        time: event.createdAt,
      });
      break;
    case "tool_started": {
      const command = payload.command || payload.tool || event.message;
      state.currentCommand = command || state.currentCommand;
      renderTerminal();
      appendTerminal(`$ ${command}`, "command");
      appendMessage({
        role: "system",
        content: `启动工具: \`${command}\``,
        time: event.createdAt,
        label: payload.tool || "shell",
      });
      setStatus("running", "工具执行中");
      break;
    }
    case "tool_completed": {
      const summary = payload.summary || event.message || "工具完成";
      appendTerminal(summary, "info");
      appendMessage({
        role: "system",
        content: `工具完成: ${summary}`,
        time: event.createdAt,
        label: payload.tool || "shell",
      });
      setStatus("success", "工具完成");
      break;
    }
    case "tool_blocked":
      appendTerminal(`blocked: ${event.message}`, "warn");
      appendMessage({
        role: "system",
        content: `工具被阻止: ${event.message}`,
        time: event.createdAt,
        label: "shell",
      });
      setStatus("error", "工具被阻止");
      break;
    case "subagent_started":
    case "subagent_launched":
      appendTerminal(`subagent> ${payload.role || "unknown"} | ${payload.task || event.message}`, "info");
      appendMessage({
        role: "system",
        content: payload.task || event.message,
        time: event.createdAt,
        label: payload.role || "reasoning",
      });
      break;
    case "subagent_completed":
      appendTerminal(`subagent done> ${event.message}`, "info");
      break;
    case "subagent_failed":
      appendTerminal(`subagent failed> ${event.message}`, "error");
      break;
    default:
      break;
  }
}

function renderConversationWelcome() {
  dom.chat.innerHTML = `
    <div class="welcome-card centered">
      <div class="welcome-badge">aegisprobe</div>
      <div>
        <h3>输入自然语言任务</h3>
        <p>Agent 会先理解你的目标，再把当前执行步骤实时同步到右侧流程与终端。</p>
      </div>
    </div>
  `;
}

function appendMessage({ role, content, time, meta = [], label = "" }) {
  if (role === "system" && label === "shell") {
    appendToolCard({ content, time, meta, label });
    return;
  }
  const article = document.createElement("article");
  article.className = `message-card ${role}`;
  const roleLabel = role === "user" ? "You" : role === "assistant" ? "aegisprobe" : (label || "system");
  article.innerHTML = `
    <div class="message-avatar">${role === "user" ? "YOU" : role === "assistant" ? "AG" : "SYS"}</div>
    <div class="message-body">
      <div class="message-head">
        <span class="message-role">${escapeHtml(roleLabel)}</span>
        <span class="message-time">${formatTime(time)}</span>
      </div>
      <div class="message-text">${simpleMarkdown(content)}</div>
      ${meta.length ? `<div class="message-meta">${meta.map((item) => `<span class="meta-chip">${escapeHtml(item)}</span>`).join("")}</div>` : ""}
    </div>
  `;
  dom.chat.appendChild(article);
  dom.chat.scrollTop = dom.chat.scrollHeight;
}

function renderWorkflow(flow = state.flow) {
  const phase = flow?.phase || "idle";
  const currentPhase = flow?.currentStep || "等待 agent 接收并理解任务。";

  dom.phaseBadge.textContent = PHASE_LABELS[phase] || "idle";
  dom.phaseName.textContent = phase === "done" ? "执行完成" : phase === "idle" ? "等待启动" : humanizePhase(phase);
  dom.phaseStep.textContent = currentPhase;
  renderWebControlPlane(flow?.webPentestControl, flow?.webPentestOperating);
  renderAuthzMatrix(flow?.authzMatrix);

  const steps = (flow?.steps || []).slice().reverse().slice(0, 6);
  dom.workflowSteps.innerHTML = steps.length === 0
    ? '<div class="empty-state">等待实时步骤...</div>'
    : steps.map((step) => `
      <div class="workflow-step">
        <div class="workflow-step-head">
          <strong>${escapeHtml(step.title || "未命名步骤")}</strong>
          <small>${escapeHtml(step.status || "pending")}</small>
        </div>
        <small>${escapeHtml(step.summary || "等待更多输出")}</small>
        ${step.command ? `<div class="step-command">${escapeHtml(step.command)}</div>` : ""}
      </div>
    `).join("");

  const findings = flow?.findings || [];
  dom.findingList.innerHTML = findings.length === 0
    ? '<div class="empty-state">暂无漏洞发现</div>'
    : findings.slice(0, 4).map((finding) => `
      <div class="finding-card ${sevClass(finding.severity)}">
        <div class="finding-head">
          <strong>${escapeHtml(finding.title)}</strong>
          <span class="sev-tag sev-${sevClass(finding.severity)} ${escapeHtml(finding.severity || "low")}">${escapeHtml(finding.severity || "low")}</span>
        </div>
        <small>${escapeHtml(finding.description || finding.confidence || "等待证据补充")}</small>
      </div>
    `).join("");
}

function renderWebControlPlane(control, operating) {
  if (!dom.webControlPlane) return;
  if (!control && !operating) {
    dom.webControlPlane.innerHTML = `
      <div class="control-head">
        <span>Web Control Plane</span>
        <small>building evidence map</small>
      </div>
    `;
    return;
  }

  const view = operating || control || {};
  const counts = control?.evidenceCounts || {};
  const gates = control?.gates || [];
  const endpoints = operating?.endpointMap || [];
  const actions = operating?.allowedNextActions || control?.nextBestActions || [];
  const blocked = operating?.blockedUntilEvidence || [];
  dom.webControlPlane.innerHTML = `
    <div class="control-head">
      <span>Web Operating Picture</span>
      <small>${escapeHtml(view.stage || "unknown")}</small>
    </div>
    <p class="control-summary">${escapeHtml(view.summary || "")}</p>
    <div class="control-counts">
      ${controlCount("API", counts.normalizedApiEndpoints || 0)}
      ${controlCount("spec", counts.apiDescriptionDocuments || 0)}
      ${controlCount("auth", counts.authContexts || 0)}
      ${controlCount("roles", counts.roleComparisons || 0)}
    </div>
    <div class="endpoint-map">
      ${endpoints.length === 0
        ? '<div class="endpoint-empty">endpoint map pending</div>'
        : endpoints.slice(0, 5).map(renderEndpointMapItem).join("")}
    </div>
    <div class="control-gates">
      ${gates.slice(0, 5).map(renderControlGate).join("")}
    </div>
    <div class="control-actions">
      ${actions.slice(0, 3).map((action) => `<small>${escapeHtml(action)}</small>`).join("")}
    </div>
    <div class="control-blocked">
      ${blocked.slice(0, 3).map((item) => `<small>${escapeHtml(item)}</small>`).join("")}
    </div>
  `;
}

function controlCount(label, value) {
  return `
    <div class="control-count">
      <strong>${escapeHtml(value)}</strong>
      <span>${escapeHtml(label)}</span>
    </div>
  `;
}

function renderControlGate(gate) {
  return `
    <div class="control-gate">
      <span class="control-gate-status ${escapeHtml(gate.status || "missing")}">${escapeHtml(gate.status || "missing")}</span>
      <span>${escapeHtml(gate.title || "")}</span>
    </div>
  `;
}

function renderEndpointMapItem(endpoint) {
  const params = [...(endpoint.queryParams || []), ...(endpoint.bodyParamHints || [])].slice(0, 4);
  const risks = (endpoint.riskSignals || []).slice(0, 3);
  return `
    <div class="endpoint-map-item">
      <div class="endpoint-map-line">
        <strong>${escapeHtml(endpoint.method || "ANY")}</strong>
        <span>${escapeHtml(endpoint.pathTemplate || "/")}</span>
        <small>${escapeHtml(endpoint.score || 0)}</small>
      </div>
      <div class="endpoint-map-meta">
        <span>auth:${escapeHtml(endpoint.authRequired || "unknown")}</span>
        ${params.length ? `<span>params:${escapeHtml(params.join(","))}</span>` : ""}
        ${risks.length ? `<span>risk:${escapeHtml(risks.join(","))}</span>` : ""}
      </div>
    </div>
  `;
}

function renderAuthzMatrix(matrix) {
  if (!dom.authzMatrix) return;
  if (!matrix) {
    dom.authzMatrix.innerHTML = `
      <div class="authz-head">
        <span>API AuthZ Matrix</span>
        <small>waiting for API evidence</small>
      </div>
    `;
    return;
  }

  const summary = matrix.summary || {};
  const items = matrix.items || [];
  dom.authzMatrix.innerHTML = `
    <div class="authz-head">
      <span>API AuthZ Matrix</span>
      <small>${escapeHtml(matrix.authContextCount || 0)} auth contexts</small>
    </div>
    <div class="authz-metrics">
      ${authzMetric("API", summary.total || 0)}
      ${authzMetric("ready", summary.ready || 0)}
      ${authzMetric("blocked", summary.blocked || 0)}
      ${authzMetric("compared", summary.compared || 0)}
    </div>
    <div class="authz-items">
      ${items.length === 0
        ? '<div class="authz-empty">no normalized endpoints yet</div>'
        : items.slice(0, 5).map(renderAuthzItem).join("")}
    </div>
  `;
}

function authzMetric(label, value) {
  return `
    <div class="authz-metric">
      <strong>${escapeHtml(value)}</strong>
      <span>${escapeHtml(label)}</span>
    </div>
  `;
}

function sevClass(s) { const m={critical:'critical',high:'high',medium:'medium',low:'low',info:'info'}; return m[s] || 'info'; }
function sevLabel(s) { const m={critical:'CRIT',high:'HIGH',medium:'MED',low:'LOW',info:'INFO'}; return m[s] || s; }
function renderAuthzItem(item) {
  const categories = (item.categories || []).slice(0, 3).join(" ");
  const signals = (item.riskSignals || []).slice(0, 2).join(" ");
  return `
    <div class="authz-item">
      <div class="authz-route">
        <span class="authz-method">${escapeHtml(item.method || "ANY")}</span>
        <code>${escapeHtml(item.pathTemplate || "")}</code>
        <span class="authz-status ${escapeHtml(item.status || "passive_only")}">${escapeHtml(statusLabel(item.status))}</span>
      </div>
      <small>${escapeHtml(item.nextAction || "evidence collection pending")}</small>
      <div class="authz-tags">
        ${categories ? `<span>${escapeHtml(categories)}</span>` : ""}
        ${signals ? `<span>${escapeHtml(signals)}</span>` : ""}
        ${item.exampleCount ? `<span>${escapeHtml(item.exampleCount)} samples</span>` : ""}
      </div>
    </div>
  `;
}

function statusLabel(status) {
  const labels = {
    ready_for_comparison: "ready",
    blocked_needs_auth_contexts: "blocked",
    needs_concrete_example: "needs example",
    passive_only: "passive",
    compared: "compared",
  };
  return labels[status] || status || "passive";
}

function syncTerminalFromFlow(flow) {
  if (!flow) return;

  const steps = (flow.steps || []).slice(-8);
  if (steps.length === 0) {
    const nextCommand = findCurrentCommand(flow);
    if (nextCommand) {
      state.currentCommand = nextCommand;
      renderTerminal();
    }
    return;
  }

  const lines = initialTerminalLines(state.currentTarget);
  for (const step of steps) {
    if (step.command) {
      lines.push({ tone: "command", text: `$ ${step.command}` });
    }
    if (step.summary) {
      lines.push({ tone: step.status === "failed" ? "error" : "info", text: step.summary });
    } else {
      lines.push({ tone: "info", text: `[${step.status}] ${step.title}` });
    }
  }

  state.currentCommand = findCurrentCommand(flow) || state.currentCommand;
  state.terminalLines = lines.slice(-60);
  renderTerminal();
}

function findCurrentCommand(flow) {
  const steps = flow?.steps || [];
  const running = steps.findLast((step) => step.status === "running" && step.command);
  if (running?.command) return running.command;
  const latest = steps.findLast((step) => step.command);
  return latest?.command || "等待任务下发";
}

function isAbsoluteWorkspacePath(value) {
  return typeof value === "string" && (/^[A-Za-z]:[\\/]/.test(value) || value.startsWith("/"));
}

function renderTerminal() {
  dom.currentCommand.textContent = state.currentCommand;
  dom.terminalOutput.innerHTML = state.terminalLines
    .map((line) => `<span class="terminal-line ${line.tone}">${escapeHtml(line.text)}</span>`)
    .join("\n");
  dom.terminalOutput.scrollTop = dom.terminalOutput.scrollHeight;
}

function appendTerminal(text, tone = "info") {
  state.terminalLines.push({ tone, text });
  if (state.terminalLines.length > 60) state.terminalLines = state.terminalLines.slice(-60);
  renderTerminal();
}

function updateSessionMeta() {
  const btn = document.getElementById('btn-download-report');
  if (btn) {
    btn.style.display = state.sessionId ? 'inline-block' : 'none';
    btn.href = '/api/sessions/' + state.sessionId + '/report?format=download';
  }
  dom.sessionBadge.textContent = state.sessionId ? `${state.sessionId.slice(0, 10)}...` : "未连接";
  dom.modeBadge.textContent = state.mode;
  if (!state.sessionId) dom.chatTitle.textContent = "新对话";
}

function setStatus(status, text, detail) {
  const icon = document.getElementById('agent-status-icon');
  const label = document.getElementById('agent-status-label');
  const detailEl = document.getElementById('agent-status-detail');
  if (icon) {
    icon.className = 'agent-status-icon ' + status;
    if (status === 'thinking') { icon.textContent = '◉'; }
    else if (status === 'calling') { icon.textContent = '◎'; }
    else if (status === 'success') { icon.textContent = '●'; }
    else if (status === 'error') { icon.textContent = '●'; }
    else { icon.textContent = '●'; }
  }
  if (label) {
    const labels = { thinking: '思考中', calling: '执行中', running: '执行中', success: '完成', error: '错误', idle: '就绪' };
    label.textContent = labels[status] || text;
  }
  if (detailEl) { detailEl.textContent = detail || ''; }
  dom.statusDot.className = `status-dot ${status}`;
  dom.statusText.textContent = text;
  dom.statusInline.textContent = text;
}

function initialTerminalLines(target = "") {
  return [
    { tone: "info", text: "aegisprobe terminal ready" },
    { tone: "info", text: target ? `target> ${target}` : "target> waiting for session" },
    { tone: "info", text: "awaiting tool execution..." },
  ];
}

function humanizePhase(phase) {
  const labels = {
    preflight: "预检",
    recon: "信息收集",
    fingerprint: "指纹识别",
    analysis: "漏洞分析",
    exploitation: "利用验证",
    reporting: "报告输出",
  };
  return labels[phase] || phase;
}

function simpleMarkdown(text) {
  let html = escapeHtml(text || "");
  html = html.replace(/```([\s\S]*?)```/g, (_match, code) => `<pre><code>${code.trim()}</code></pre>`);
  html = html.replace(/`([^`]+)`/g, "<code>$1</code>");
  html = html.replace(/\*\*([^*]+)\*\*/g, "<strong>$1</strong>");
  html = html.replace(/\n/g, "<br>");
  return html;
}

function escapeHtml(value) {
  return String(value ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function formatTime(iso, short = false) {
  if (!iso) return "";
  const date = new Date(iso);
  const pad = (number) => String(number).padStart(2, "0");
  const stamp = `${pad(date.getHours())}:${pad(date.getMinutes())}`;
  if (short) return `${date.getMonth() + 1}/${date.getDate()} ${stamp}`;
  return stamp;
}

function toErrorMessage(error) {
  return error instanceof Error ? error.message : String(error);
}

async function readJson(url, options) {
  const response = await fetch(url, options);
  if (!response.ok) {
    const payload = await response.text();
    throw new Error(payload || `${response.status} ${response.statusText}`);
  }
  return response.json();
}
