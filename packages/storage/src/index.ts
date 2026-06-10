import { mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { newId, nowIso, type AgentObservation, type AgentPlan, type FileChangeRecord, type SecurityAsset, type SecurityAuthContext, type SecurityCheckStatus, type SecurityCveMatch, type SecurityEvidence, type SecurityFinding, type SecurityFindingState, type SecurityTechnology, type SecurityToolRun, type SecurityValidationAttempt, type SecurityValidationCheck, type SecurityWorkflow, type SecurityWorkflowTask, type ShellCommandRecord, type SubAgentRecord, type SubAgentRole, type SubAgentRunMode, type SubAgentStatus, type TargetInput, type TaskNodeStatus, type TaskTreeNode, type TurnEvent, type WorkPriority } from "@aegisprobe/shared";

export type StoredSession = {
  id: string;
  title: string;
  mode: string;
  createdAt: string;
  updatedAt: string;
};

export type StoredMessage = {
  role: "user" | "assistant" | "system";
  content: string;
  createdAt: string;
};

export type StoredTarget = TargetInput & {
  createdAt: string;
};

export type SessionMemory = {
  sessionId: string;
  summary: string;
  pinnedFacts: string[];
  openTasks: string[];
  updatedAt: string;
};

export class AuditStore {
  private readonly db: DatabaseSync;

  constructor(sqlitePath: string) {
    const absolute = resolve(sqlitePath);
    mkdirSync(dirname(absolute), { recursive: true });
    this.db = new DatabaseSync(absolute);
    this.db.exec(`
      PRAGMA journal_mode = WAL;
      PRAGMA busy_timeout = 5000;
      PRAGMA foreign_keys = ON;
    `);
    this.migrate();
  }

  close(): void {
    this.db.close();
  }

  migrate(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS sessions (
        id TEXT PRIMARY KEY,
        title TEXT NOT NULL,
        mode TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS messages (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS targets (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        raw TEXT NOT NULL,
        normalized TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS turns (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS turn_events (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        kind TEXT NOT NULL,
        message TEXT NOT NULL,
        payload_json TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS plans (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        goal TEXT NOT NULL,
        summary TEXT NOT NULL,
        steps_json TEXT NOT NULL,
        commands_json TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS approvals (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        subject TEXT NOT NULL,
        approved INTEGER NOT NULL,
        reason TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS commands (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        command TEXT NOT NULL,
        risk TEXT NOT NULL,
        status TEXT NOT NULL,
        summary TEXT,
        exit_code INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS file_changes (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        path TEXT NOT NULL,
        operation TEXT NOT NULL,
        status TEXT NOT NULL,
        summary TEXT,
        diff TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS observations (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        source TEXT NOT NULL,
        summary TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS approved_shell_commands (
        id TEXT PRIMARY KEY,
        command TEXT NOT NULL UNIQUE,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS subagents (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        description TEXT,
        task TEXT NOT NULL,
        status TEXT NOT NULL,
        priority TEXT,
        run_mode TEXT,
        retry_count INTEGER NOT NULL DEFAULT 0,
        max_retries INTEGER NOT NULL DEFAULT 1,
        parent_agent_id TEXT,
        context_paths_json TEXT,
        result_summary TEXT,
        progress_summary TEXT,
        tool_use_count INTEGER NOT NULL DEFAULT 0,
        output_path TEXT,
        last_heartbeat_at TEXT,
        memory_key TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS security_workflows (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        target_json TEXT NOT NULL,
        status TEXT NOT NULL,
        current_phase TEXT NOT NULL,
        summary TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS security_tasks (
        id TEXT PRIMARY KEY,
        workflow_id TEXT NOT NULL,
        session_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        title TEXT NOT NULL,
        description TEXT NOT NULL,
        recommended_role TEXT,
        suggested_skills_json TEXT NOT NULL,
        suggested_tools_json TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS security_tool_runs (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        workflow_id TEXT,
        parent_run_id TEXT,
        tool_id TEXT NOT NULL,
        phase TEXT NOT NULL,
        origin TEXT NOT NULL,
        status TEXT NOT NULL,
        command TEXT,
        input_kind TEXT,
        input_count INTEGER NOT NULL,
        input_artifact TEXT,
        output_artifact TEXT,
        output_summary TEXT,
        exit_code INTEGER,
        blocked_reason TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS findings (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        workflow_id TEXT,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        target TEXT NOT NULL,
        description TEXT NOT NULL,
        evidence_summary TEXT,
        remediation TEXT,
        state TEXT,
        dedupe_key TEXT,
        evidence_ids_json TEXT,
        first_seen_at TEXT,
        last_seen_at TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS evidence (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        workflow_id TEXT,
        finding_id TEXT,
        source TEXT NOT NULL,
        kind TEXT NOT NULL,
        summary TEXT NOT NULL,
        data TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS security_assets (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        workflow_id TEXT,
        kind TEXT NOT NULL,
        value TEXT NOT NULL,
        source TEXT NOT NULL,
        confidence TEXT NOT NULL,
        metadata TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS security_technologies (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        workflow_id TEXT,
        target TEXT NOT NULL,
        name TEXT NOT NULL,
        version TEXT,
        category TEXT,
        source TEXT NOT NULL,
        confidence TEXT NOT NULL,
        evidence_summary TEXT,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS cve_matches (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        workflow_id TEXT,
        target TEXT NOT NULL,
        technology TEXT NOT NULL,
        cve_id TEXT,
        title TEXT NOT NULL,
        severity TEXT NOT NULL,
        confidence TEXT NOT NULL,
        rationale TEXT NOT NULL,
        source TEXT NOT NULL,
        relevance_score INTEGER,
        created_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS security_validation_attempts (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        workflow_id TEXT,
        target_kind TEXT NOT NULL,
        target_id TEXT NOT NULL,
        target_title TEXT NOT NULL,
        method TEXT NOT NULL,
        status TEXT NOT NULL,
        confidence TEXT NOT NULL,
        rationale TEXT NOT NULL,
        evidence_ids_json TEXT NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS security_auth_contexts (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        workflow_id TEXT,
        name TEXT NOT NULL,
        base_url TEXT,
        role TEXT,
        username TEXT,
        tenant TEXT,
        cookie_header TEXT,
        authorization_header TEXT,
        headers_json TEXT,
        storage_state_path TEXT,
        notes TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      -- Migration: add tenant column to existing databases (safe on column-exists)
      CREATE TABLE IF NOT EXISTS security_checks (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        workflow_id TEXT,
        check_id TEXT NOT NULL,
        title TEXT NOT NULL,
        category TEXT NOT NULL,
        target TEXT NOT NULL,
        phase TEXT NOT NULL,
        status TEXT NOT NULL,
        active_requires_approval INTEGER NOT NULL,
        passive_signals_json TEXT NOT NULL,
        safe_checks_json TEXT NOT NULL,
        evidence_summary TEXT,
        rationale TEXT,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS session_memory (
        session_id TEXT PRIMARY KEY,
        summary TEXT NOT NULL,
        pinned_facts_json TEXT NOT NULL,
        open_tasks_json TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS task_tree (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        workflow_id TEXT,
        parent_id TEXT,
        phase TEXT NOT NULL,
        title TEXT NOT NULL,
        goal TEXT NOT NULL,
        status TEXT NOT NULL,
        tool_id TEXT,
        evidence_ids_json TEXT NOT NULL,
        finding_ids_json TEXT NOT NULL,
        summary TEXT NOT NULL,
        sort_order INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS deliverables (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        type TEXT NOT NULL,
        data_json TEXT NOT NULL,
        summary TEXT NOT NULL,
        created_at TEXT NOT NULL
      );
    `);
    // ── Conversation messages (interactive chat) ──
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS conversation_messages (
        id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        role TEXT NOT NULL,
        content TEXT NOT NULL DEFAULT '',
        reasoning_content TEXT,
        tool_call_id TEXT,
        tool_calls_json TEXT,
        created_at TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_conv_msg_session ON conversation_messages(session_id, created_at);
    `);

    this.ensureColumn("subagents", "description", "TEXT");
    this.ensureColumn("conversation_messages", "reasoning_content", "TEXT");
    this.ensureColumn("subagents", "priority", "TEXT");
    this.ensureColumn("subagents", "run_mode", "TEXT");
    this.ensureColumn("subagents", "retry_count", "INTEGER NOT NULL DEFAULT 0");
    this.ensureColumn("subagents", "max_retries", "INTEGER NOT NULL DEFAULT 1");
    this.ensureColumn("subagents", "parent_agent_id", "TEXT");
    this.ensureColumn("subagents", "context_paths_json", "TEXT");
    this.ensureColumn("subagents", "progress_summary", "TEXT");
    this.ensureColumn("subagents", "tool_use_count", "INTEGER NOT NULL DEFAULT 0");
    this.ensureColumn("subagents", "output_path", "TEXT");
    this.ensureColumn("subagents", "last_heartbeat_at", "TEXT");
    this.ensureColumn("subagents", "memory_key", "TEXT");
    this.ensureColumn("security_tool_runs", "output_artifact", "TEXT");
    this.ensureColumn("cve_matches", "relevance_score", "INTEGER");
    this.ensureColumn("security_tool_runs", "failure_category", "TEXT");
    this.ensureColumn("security_tool_runs", "finding_count", "INTEGER");
    this.ensureColumn("findings", "state", "TEXT");
    this.ensureColumn("findings", "dedupe_key", "TEXT");
    this.ensureColumn("findings", "evidence_ids_json", "TEXT");
    this.ensureColumn("findings", "first_seen_at", "TEXT");
    this.ensureColumn("findings", "last_seen_at", "TEXT");
    this.ensureColumn("security_auth_contexts", "tenant", "TEXT");
    this.db.exec("CREATE INDEX IF NOT EXISTS idx_findings_session_dedupe ON findings(session_id, dedupe_key)");
  }

  private ensureColumn(table: string, column: string, definition: string): void {
    const columns = this.db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name: string }>;
    if (!columns.some((row) => row.name === column)) {
      this.db.exec(`ALTER TABLE ${table} ADD COLUMN ${column} ${definition}`);
    }
  }

  createSession(title: string, mode: string): string {
    const id = newId("ses");
    const now = nowIso();
    this.db.prepare("INSERT INTO sessions (id, title, mode, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
      .run(id, title, mode, now, now);
    return id;
  }

  hasSession(sessionId: string): boolean {
    const row = this.db.prepare("SELECT id FROM sessions WHERE id = ?").get(sessionId) as { id: string } | undefined;
    return Boolean(row);
  }

  listSessions(limit = 20): StoredSession[] {
    const rows = this.db.prepare(`
      SELECT id, title, mode, created_at AS createdAt, updated_at AS updatedAt
      FROM sessions
      ORDER BY updated_at DESC
      LIMIT ?
    `).all(limit) as Array<{
      id: string;
      title: string;
      mode: string;
      createdAt: string;
      updatedAt: string;
    }>;
    return rows;
  }

  touchSession(sessionId: string): void {
    this.db.prepare("UPDATE sessions SET updated_at = ? WHERE id = ?").run(nowIso(), sessionId);
  }

  addMessage(sessionId: string, role: "user" | "assistant" | "system", content: string): void {
    this.db.prepare("INSERT INTO messages (id, session_id, role, content, created_at) VALUES (?, ?, ?, ?, ?)")
      .run(newId("msg"), sessionId, role, content, nowIso());
    this.touchSession(sessionId);
  }

  // ── Conversation Messages (interactive chat) ──

  insertConversationMessage(msg: {
    id: string;
    sessionId: string;
    role: string;
    content: string;
    reasoningContent?: string;
    toolCallId?: string;
    toolCalls?: Array<{ id: string; name: string; arguments: string }>;
    createdAt: string;
  }): void {
    this.db.prepare(
      "INSERT INTO conversation_messages (id, session_id, role, content, reasoning_content, tool_call_id, tool_calls_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    ).run(
      msg.id,
      msg.sessionId,
      msg.role,
      msg.content,
      msg.reasoningContent ?? null,
      msg.toolCallId ?? null,
      msg.toolCalls ? JSON.stringify(msg.toolCalls) : null,
      msg.createdAt
    );
    this.touchSession(msg.sessionId);
  }

  listConversationMessages(sessionId: string, limit = 200): Array<{
    id: string;
    sessionId: string;
    role: string;
    content: string;
    reasoningContent?: string;
    toolCallId?: string;
    toolCalls?: Array<{ id: string; name: string; arguments: string }>;
    createdAt: string;
  }> {
    const rows = this.db.prepare(`
      SELECT id, sessionId, role, content, reasoningContent, toolCallId, toolCallsJson, createdAt
      FROM (
        SELECT rowid AS sequence, id, session_id AS sessionId, role, content, tool_call_id AS toolCallId,
               reasoning_content AS reasoningContent, tool_calls_json AS toolCallsJson, created_at AS createdAt
        FROM conversation_messages
        WHERE session_id = ?
        ORDER BY created_at DESC, rowid DESC
        LIMIT ?
      )
      ORDER BY createdAt ASC, sequence ASC
    `).all(sessionId, limit) as Array<{
      id: string;
      sessionId: string;
      role: string;
      content: string;
      reasoningContent?: string;
      toolCallId?: string;
      toolCallsJson?: string;
      createdAt: string;
    }>;
    return rows.map((r) => ({
      ...r,
      toolCalls: r.toolCallsJson ? JSON.parse(r.toolCallsJson) : undefined
    }));
  }

  clearConversationMessages(sessionId: string): void {
    this.db.prepare("DELETE FROM conversation_messages WHERE session_id = ?").run(sessionId);
  }

  replaceConversationMessages(
    sessionId: string,
    messages: Array<{
      id: string;
      role: string;
      content: string;
      reasoningContent?: string;
      toolCallId?: string;
      toolCalls?: Array<{ id: string; name: string; arguments: string }>;
      createdAt: string;
    }>
  ): void {
    const insert = this.db.prepare(
      "INSERT INTO conversation_messages (id, session_id, role, content, reasoning_content, tool_call_id, tool_calls_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    );
    this.db.exec("BEGIN IMMEDIATE");
    try {
      this.db.prepare("DELETE FROM conversation_messages WHERE session_id = ?").run(sessionId);
      for (const message of messages) {
        insert.run(
          message.id,
          sessionId,
          message.role,
          message.content,
          message.reasoningContent ?? null,
          message.toolCallId ?? null,
          message.toolCalls ? JSON.stringify(message.toolCalls) : null,
          message.createdAt
        );
      }
      this.db.exec("COMMIT");
    } catch (error) {
      this.db.exec("ROLLBACK");
      throw error;
    }
    this.touchSession(sessionId);
  }

  getRecentMessages(sessionId: string, limit = 12): StoredMessage[] {
    const rows = this.db.prepare(`
      SELECT role, content, created_at AS createdAt
      FROM messages
      WHERE session_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).all(sessionId, limit) as StoredMessage[];
    return rows.reverse();
  }

  listMessages(sessionId: string, limit = 200): StoredMessage[] {
    const rows = this.db.prepare(`
      SELECT role, content, created_at AS createdAt
      FROM messages
      WHERE session_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).all(sessionId, limit) as StoredMessage[];
    return rows.reverse();
  }

  countMessages(sessionId: string): number {
    const row = this.db.prepare("SELECT COUNT(*) AS count FROM messages WHERE session_id = ?")
      .get(sessionId) as { count: number };
    return row.count;
  }

  addTarget(sessionId: string, target: TargetInput): void {
    this.db.prepare("INSERT INTO targets (id, session_id, kind, raw, normalized, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(newId("tgt"), sessionId, target.kind, target.raw, target.normalized, nowIso());
  }

  listTargets(sessionId: string, limit = 50): StoredTarget[] {
    const rows = this.db.prepare(`
      SELECT kind, raw, normalized, created_at AS createdAt
      FROM targets
      WHERE session_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).all(sessionId, limit) as StoredTarget[];
    return rows.reverse();
  }

  createTurn(sessionId: string): string {
    const id = newId("turn");
    const now = nowIso();
    this.db.prepare("INSERT INTO turns (id, session_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?)")
      .run(id, sessionId, "running", now, now);
    return id;
  }

  updateTurnStatus(turnId: string, status: "completed" | "failed" | "aborted" | "needs_input"): void {
    this.db.prepare("UPDATE turns SET status = ?, updated_at = ? WHERE id = ?")
      .run(status, nowIso(), turnId);
  }

  addTurnEvent(event: TurnEvent): void {
    this.db.prepare("INSERT INTO turn_events (id, session_id, turn_id, kind, message, payload_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(
        event.id,
        event.sessionId,
        event.turnId,
        event.kind,
        event.message,
        event.payload === undefined ? null : JSON.stringify(event.payload),
        event.createdAt
      );
    this.touchSession(event.sessionId);
  }

  addPlan(plan: AgentPlan): void {
    this.db.prepare("INSERT INTO plans (id, session_id, goal, summary, steps_json, commands_json, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)")
      .run(plan.id, plan.sessionId, plan.goal, plan.summary, JSON.stringify(plan.steps), JSON.stringify(plan.suggestedCommands), plan.createdAt);
  }

  listPlans(sessionId: string, limit = 20): AgentPlan[] {
    const rows = this.db.prepare(`
      SELECT id, session_id AS sessionId, goal, summary, steps_json AS stepsJson,
             commands_json AS commandsJson, created_at AS createdAt
      FROM plans
      WHERE session_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).all(sessionId, limit) as Array<Omit<AgentPlan, "steps" | "suggestedCommands"> & {
      stepsJson: string;
      commandsJson: string;
    }>;
    return rows.reverse().map((row) => ({
      id: row.id,
      sessionId: row.sessionId,
      goal: row.goal,
      summary: row.summary,
      steps: JSON.parse(row.stepsJson) as string[],
      suggestedCommands: JSON.parse(row.commandsJson) as string[],
      createdAt: row.createdAt
    }));
  }

  addApproval(sessionId: string, subject: string, approved: boolean, reason?: string): void {
    this.db.prepare("INSERT INTO approvals (id, session_id, subject, approved, reason, created_at) VALUES (?, ?, ?, ?, ?, ?)")
      .run(newId("apr"), sessionId, subject, approved ? 1 : 0, reason ?? null, nowIso());
  }

  addCommand(record: ShellCommandRecord): void {
    this.db.prepare("INSERT INTO commands (id, session_id, command, risk, status, summary, exit_code, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)")
      .run(record.id, record.sessionId, record.command, record.risk, record.status, record.summary ?? null, record.exitCode ?? null, record.createdAt, record.updatedAt);
  }

  updateCommand(record: ShellCommandRecord): void {
    this.db.prepare("UPDATE commands SET status = ?, summary = ?, exit_code = ?, updated_at = ? WHERE id = ?")
      .run(record.status, record.summary ?? null, record.exitCode ?? null, record.updatedAt, record.id);
  }

  listCommands(sessionId: string, limit = 20): ShellCommandRecord[] {
    const rows = this.db.prepare(`
      SELECT id, session_id AS sessionId, command, risk, status, summary,
             exit_code AS exitCode, created_at AS createdAt, updated_at AS updatedAt
      FROM commands
      WHERE session_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).all(sessionId, limit) as ShellCommandRecord[];
    return rows.reverse();
  }

  addFileChange(record: FileChangeRecord): void {
    this.db.prepare(`
      INSERT INTO file_changes (id, session_id, path, operation, status, summary, diff, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      record.id,
      record.sessionId,
      record.path,
      record.operation,
      record.status,
      record.summary ?? null,
      record.diff ?? null,
      record.createdAt,
      record.updatedAt
    );
    this.touchSession(record.sessionId);
  }

  updateFileChange(record: FileChangeRecord): void {
    this.db.prepare(`
      UPDATE file_changes
      SET status = ?, summary = ?, diff = ?, updated_at = ?
      WHERE id = ?
    `).run(record.status, record.summary ?? null, record.diff ?? null, record.updatedAt, record.id);
    this.touchSession(record.sessionId);
  }

  listFileChanges(sessionId: string, limit = 20): FileChangeRecord[] {
    const rows = this.db.prepare(`
      SELECT id, session_id AS sessionId, path, operation, status, summary, diff,
             created_at AS createdAt, updated_at AS updatedAt
      FROM file_changes
      WHERE session_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).all(sessionId, limit) as FileChangeRecord[];
    return rows.reverse();
  }

  addObservation(observation: AgentObservation): void {
    this.db.prepare("INSERT INTO observations (id, session_id, source, summary, created_at) VALUES (?, ?, ?, ?, ?)")
      .run(observation.id, observation.sessionId, observation.source, observation.summary, observation.createdAt);
    this.touchSession(observation.sessionId);
  }

  listObservations(sessionId: string, limit = 30): AgentObservation[] {
    const rows = this.db.prepare(`
      SELECT id, session_id AS sessionId, source, summary, created_at AS createdAt
      FROM observations
      WHERE session_id = ?
      ORDER BY created_at DESC
      LIMIT ?
    `).all(sessionId, limit) as AgentObservation[];
    return rows.reverse();
  }

  getSessionMemory(sessionId: string): SessionMemory | undefined {
    const row = this.db.prepare(`
      SELECT session_id AS sessionId, summary, pinned_facts_json AS pinnedFactsJson,
             open_tasks_json AS openTasksJson, updated_at AS updatedAt
      FROM session_memory
      WHERE session_id = ?
    `).get(sessionId) as {
      sessionId: string;
      summary: string;
      pinnedFactsJson: string;
      openTasksJson: string;
      updatedAt: string;
    } | undefined;
    if (!row) {
      return undefined;
    }
    return {
      sessionId: row.sessionId,
      summary: row.summary,
      pinnedFacts: JSON.parse(row.pinnedFactsJson) as string[],
      openTasks: JSON.parse(row.openTasksJson) as string[],
      updatedAt: row.updatedAt
    };
  }

  upsertSessionMemory(memory: SessionMemory): void {
    this.db.prepare(`
      INSERT INTO session_memory (session_id, summary, pinned_facts_json, open_tasks_json, updated_at)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(session_id) DO UPDATE SET
        summary = excluded.summary,
        pinned_facts_json = excluded.pinned_facts_json,
        open_tasks_json = excluded.open_tasks_json,
        updated_at = excluded.updated_at
    `).run(
      memory.sessionId,
      memory.summary,
      JSON.stringify(memory.pinnedFacts),
      JSON.stringify(memory.openTasks),
      memory.updatedAt
    );
    this.touchSession(memory.sessionId);
  }

  hasApprovedShellCommand(command: string): boolean {
    const row = this.db.prepare("SELECT command FROM approved_shell_commands WHERE command = ?").get(command) as { command: string } | undefined;
    return Boolean(row);
  }

  rememberApprovedShellCommand(command: string): void {
    this.db.prepare("INSERT OR IGNORE INTO approved_shell_commands (id, command, created_at) VALUES (?, ?, ?)")
      .run(newId("allow"), command, nowIso());
  }

  createSubAgent(
    sessionId: string,
    role: SubAgentRole,
    task: string,
    description?: string,
    options: {
      status?: SubAgentStatus;
      priority?: WorkPriority;
      runMode?: SubAgentRunMode;
      retryCount?: number;
      maxRetries?: number;
      parentAgentId?: string;
      contextPaths?: string[];
      memoryKey?: string;
    } = {}
  ): SubAgentRecord {
    const now = nowIso();
    const progressSummary = "Subagent is queued.";
    const status = options.status ?? "running";
    const record: SubAgentRecord = {
      id: newId("agent"),
      sessionId,
      role,
      description,
      task,
      status,
      priority: options.priority ?? "medium",
      runMode: options.runMode ?? "foreground",
      retryCount: options.retryCount ?? 0,
      maxRetries: options.maxRetries ?? 1,
      parentAgentId: options.parentAgentId,
      contextPaths: options.contextPaths ?? [],
      progressSummary,
      toolUseCount: 0,
      lastHeartbeatAt: status === "running" ? now : undefined,
      memoryKey: options.memoryKey,
      createdAt: now,
      updatedAt: now
    };
    this.db.prepare(`
      INSERT INTO subagents (
        id, session_id, role, description, task, status, priority, run_mode,
        retry_count, max_retries, parent_agent_id, context_paths_json,
        result_summary, progress_summary, tool_use_count, output_path,
        last_heartbeat_at, memory_key, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      record.id,
      sessionId,
      role,
      description ?? null,
      task,
      record.status,
      record.priority ?? "medium",
      record.runMode ?? "foreground",
      record.retryCount ?? 0,
      record.maxRetries ?? 1,
      record.parentAgentId ?? null,
      JSON.stringify(record.contextPaths ?? []),
      null,
      progressSummary,
      0,
      null,
      record.lastHeartbeatAt ?? null,
      record.memoryKey ?? null,
      now,
      now
    );
    this.touchSession(sessionId);
    return record;
  }

  claimQueuedSubAgents(sessionId: string, limit = 4): SubAgentRecord[] {
    const queued = this.listSubAgents(sessionId)
      .filter((agent) => agent.status === "queued")
      .sort(compareSubAgentWork)
      .slice(0, Math.max(1, limit));
    const now = nowIso();
    for (const agent of queued) {
      this.db.prepare(`
        UPDATE subagents
        SET status = 'running', progress_summary = ?, last_heartbeat_at = ?, updated_at = ?
        WHERE id = ? AND status = 'queued'
      `).run("Subagent claimed by dispatcher.", now, now, agent.id);
    }
    if (queued.length > 0) {
      this.touchSession(sessionId);
    }
    return queued.map((agent) => ({
      ...agent,
      status: "running",
      progressSummary: "Subagent claimed by dispatcher.",
      lastHeartbeatAt: now,
      updatedAt: now
    }));
  }

  retrySubAgent(agentId: string, reason: string): boolean {
    const existing = this.getSubAgent(agentId);
    if (!existing || (existing.retryCount ?? 0) >= (existing.maxRetries ?? 0)) {
      return false;
    }
    const now = nowIso();
    this.db.prepare(`
      UPDATE subagents
      SET status = 'queued',
          retry_count = retry_count + 1,
          progress_summary = ?,
          result_summary = NULL,
          last_heartbeat_at = NULL,
          updated_at = ?
      WHERE id = ?
    `).run(`Retry queued: ${reason}`, now, agentId);
    this.touchSession(existing.sessionId);
    return true;
  }

  heartbeatSubAgent(agentId: string, progressSummary?: string, toolUseCount?: number): void {
    const existing = this.getSubAgent(agentId);
    if (!existing) {
      return;
    }
    const now = nowIso();
    if (toolUseCount === undefined) {
      this.db.prepare(`
        UPDATE subagents
        SET progress_summary = COALESCE(?, progress_summary), last_heartbeat_at = ?, updated_at = ?
        WHERE id = ?
      `).run(progressSummary ?? null, now, now, agentId);
    } else {
      this.db.prepare(`
        UPDATE subagents
        SET progress_summary = COALESCE(?, progress_summary), tool_use_count = ?, last_heartbeat_at = ?, updated_at = ?
        WHERE id = ?
      `).run(progressSummary ?? null, toolUseCount, now, now, agentId);
    }
    this.touchSession(existing.sessionId);
  }

  requeueStaleRunningSubAgents(sessionId: string, staleBeforeIso: string): number {
    const rows = this.listSubAgents(sessionId).filter((agent) =>
      agent.status === "running" && (!agent.lastHeartbeatAt || agent.lastHeartbeatAt < staleBeforeIso)
    );
    const now = nowIso();
    for (const agent of rows) {
      this.db.prepare(`
        UPDATE subagents
        SET status = 'queued', progress_summary = ?, last_heartbeat_at = NULL, updated_at = ?
        WHERE id = ?
      `).run("Recovered stale running subagent after process restart or heartbeat timeout.", now, agent.id);
    }
    if (rows.length > 0) {
      this.touchSession(sessionId);
    }
    return rows.length;
  }

  setSubAgentOutputPath(agentId: string, outputPath: string): void {
    const existing = this.getSubAgent(agentId);
    this.db.prepare("UPDATE subagents SET output_path = ?, updated_at = ? WHERE id = ?")
      .run(outputPath, nowIso(), agentId);
    if (existing) {
      this.touchSession(existing.sessionId);
    }
  }

  updateSubAgent(agentId: string, status: SubAgentStatus, resultSummary?: string): void {
    const existing = this.getSubAgent(agentId);
    this.db.prepare(`
      UPDATE subagents
      SET status = ?, result_summary = ?, updated_at = ?
      WHERE id = ?
    `).run(status, resultSummary ?? null, nowIso(), agentId);
    if (existing) {
      this.touchSession(existing.sessionId);
    }
  }

  updateSubAgentProgress(agentId: string, progressSummary: string, toolUseCount?: number): void {
    const existing = this.getSubAgent(agentId);
    if (!existing) {
      return;
    }
    const now = nowIso();
    if (toolUseCount === undefined) {
      this.db.prepare(`
        UPDATE subagents
        SET progress_summary = ?, last_heartbeat_at = ?, updated_at = ?
        WHERE id = ?
      `).run(progressSummary, now, now, agentId);
    } else {
      this.db.prepare(`
        UPDATE subagents
        SET progress_summary = ?, tool_use_count = ?, last_heartbeat_at = ?, updated_at = ?
        WHERE id = ?
      `).run(progressSummary, toolUseCount, now, now, agentId);
    }
    this.touchSession(existing.sessionId);
  }

  getSubAgent(agentId: string): SubAgentRecord | undefined {
    const row = this.db.prepare(`
      SELECT id, session_id AS sessionId, role, description, task, status,
             priority, run_mode AS runMode, retry_count AS retryCount,
             max_retries AS maxRetries, parent_agent_id AS parentAgentId,
             context_paths_json AS contextPathsJson,
             result_summary AS resultSummary, progress_summary AS progressSummary,
             tool_use_count AS toolUseCount,
             output_path AS outputPath, last_heartbeat_at AS lastHeartbeatAt,
             memory_key AS memoryKey,
             created_at AS createdAt, updated_at AS updatedAt
      FROM subagents
      WHERE id = ?
    `).get(agentId) as (SubAgentRecord & { contextPathsJson?: string }) | undefined;
    return row ? this.normalizeSubAgent(row) : undefined;
  }

  closeSubAgent(sessionId: string, agentId: string): boolean {
    const result = this.db.prepare(`
      UPDATE subagents
      SET status = 'closed', updated_at = ?
      WHERE id = ? AND session_id = ?
    `).run(nowIso(), agentId, sessionId);
    this.touchSession(sessionId);
    return result.changes > 0;
  }

  listSubAgents(sessionId: string): SubAgentRecord[] {
    const rows = this.db.prepare(`
      SELECT id, session_id AS sessionId, role, description, task, status,
             priority, run_mode AS runMode, retry_count AS retryCount,
             max_retries AS maxRetries, parent_agent_id AS parentAgentId,
             context_paths_json AS contextPathsJson,
             result_summary AS resultSummary, progress_summary AS progressSummary,
             tool_use_count AS toolUseCount,
             output_path AS outputPath, last_heartbeat_at AS lastHeartbeatAt,
             memory_key AS memoryKey,
             created_at AS createdAt, updated_at AS updatedAt
      FROM subagents
      WHERE session_id = ?
      ORDER BY created_at ASC, rowid ASC
    `).all(sessionId) as unknown as Array<SubAgentRecord & { contextPathsJson?: string }>;
    return rows.map((row) => this.normalizeSubAgent(row));
  }

  // ── Deliverables ──

  saveDeliverable(sessionId: string, role: string, type: string, data: Record<string, unknown>, summary: string): void {
    this.db.prepare(`
      INSERT INTO deliverables (id, session_id, role, type, data_json, summary, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(newId("dlv"), sessionId, role, type, JSON.stringify(data), summary, nowIso());
  }

  getDeliverable(sessionId: string, type: string): { role: string; data: Record<string, unknown>; summary: string } | undefined {
    const row = this.db.prepare(`
      SELECT role, data_json, summary FROM deliverables
      WHERE session_id = ? AND type = ?
      ORDER BY created_at DESC LIMIT 1
    `).get(sessionId, type) as { role: string; data_json: string; summary: string } | undefined;
    if (!row) return undefined;
    return { role: row.role, data: JSON.parse(row.data_json), summary: row.summary };
  }

  listDeliverables(sessionId: string): Array<{ role: string; type: string; summary: string }> {
    return this.db.prepare(`
      SELECT role, type, summary FROM deliverables
      WHERE session_id = ?
      ORDER BY created_at DESC
    `).all(sessionId) as Array<{ role: string; type: string; summary: string }>;
  }

  upsertSecurityWorkflow(workflow: SecurityWorkflow): void {
    this.db.prepare(`
      INSERT INTO security_workflows (id, session_id, target_json, status, current_phase, summary, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        target_json = excluded.target_json,
        status = excluded.status,
        current_phase = excluded.current_phase,
        summary = excluded.summary,
        updated_at = excluded.updated_at
    `).run(
      workflow.id,
      workflow.sessionId,
      JSON.stringify(workflow.target),
      workflow.status,
      workflow.currentPhase,
      workflow.summary,
      workflow.createdAt,
      workflow.updatedAt
    );
    this.touchSession(workflow.sessionId);
  }

  addSecurityTasks(tasks: SecurityWorkflowTask[]): void {
    const statement = this.db.prepare(`
      INSERT INTO security_tasks (
        id, workflow_id, session_id, phase, title, description, recommended_role,
        suggested_skills_json, suggested_tools_json, status, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        phase = excluded.phase,
        title = excluded.title,
        description = excluded.description,
        recommended_role = excluded.recommended_role,
        suggested_skills_json = excluded.suggested_skills_json,
        suggested_tools_json = excluded.suggested_tools_json,
        status = excluded.status,
        updated_at = excluded.updated_at
    `);
    for (const task of tasks) {
      statement.run(
        task.id,
        task.workflowId,
        task.sessionId,
        task.phase,
        task.title,
        task.description,
        task.recommendedRole ?? null,
        JSON.stringify(task.suggestedSkills),
        JSON.stringify(task.suggestedTools),
        task.status,
        task.createdAt,
        task.updatedAt
      );
    }
    if (tasks[0]) {
      this.touchSession(tasks[0].sessionId);
    }
  }

  updateSecurityWorkflowStatus(
    workflowId: string,
    status: SecurityWorkflow["status"],
    currentPhase: SecurityWorkflow["currentPhase"],
    summary?: string
  ): void {
    const existing = this.db.prepare("SELECT session_id AS sessionId, summary FROM security_workflows WHERE id = ?")
      .get(workflowId) as { sessionId: string; summary: string } | undefined;
    this.db.prepare(`
      UPDATE security_workflows
      SET status = ?, current_phase = ?, summary = ?, updated_at = ?
      WHERE id = ?
    `).run(status, currentPhase, summary ?? existing?.summary ?? "", nowIso(), workflowId);
    if (existing) {
      this.touchSession(existing.sessionId);
    }
  }

  updateSecurityTaskStatus(taskId: string, status: SecurityWorkflowTask["status"]): void {
    const existing = this.db.prepare("SELECT session_id AS sessionId FROM security_tasks WHERE id = ?")
      .get(taskId) as { sessionId: string } | undefined;
    this.db.prepare("UPDATE security_tasks SET status = ?, updated_at = ? WHERE id = ?")
      .run(status, nowIso(), taskId);
    if (existing) {
      this.touchSession(existing.sessionId);
    }
  }

  listSecurityWorkflows(sessionId: string): SecurityWorkflow[] {
    const rows = this.db.prepare(`
      SELECT id, session_id AS sessionId, target_json AS targetJson, status,
             current_phase AS currentPhase, summary,
             created_at AS createdAt, updated_at AS updatedAt
      FROM security_workflows
      WHERE session_id = ?
      ORDER BY created_at ASC
    `).all(sessionId) as Array<Omit<SecurityWorkflow, "target"> & { targetJson: string }>;
    return rows.map((row) => ({
      id: row.id,
      sessionId: row.sessionId,
      target: JSON.parse(row.targetJson) as TargetInput,
      status: row.status,
      currentPhase: row.currentPhase,
      summary: row.summary,
      createdAt: row.createdAt,
      updatedAt: row.updatedAt
    }));
  }

  listSecurityTasks(sessionId: string, workflowId?: string): SecurityWorkflowTask[] {
    const sql = workflowId
      ? `
        SELECT id, workflow_id AS workflowId, session_id AS sessionId, phase, title, description,
               recommended_role AS recommendedRole, suggested_skills_json AS suggestedSkillsJson,
               suggested_tools_json AS suggestedToolsJson, status, created_at AS createdAt, updated_at AS updatedAt
        FROM security_tasks
        WHERE session_id = ? AND workflow_id = ?
        ORDER BY created_at ASC
      `
      : `
        SELECT id, workflow_id AS workflowId, session_id AS sessionId, phase, title, description,
               recommended_role AS recommendedRole, suggested_skills_json AS suggestedSkillsJson,
               suggested_tools_json AS suggestedToolsJson, status, created_at AS createdAt, updated_at AS updatedAt
        FROM security_tasks
        WHERE session_id = ?
        ORDER BY created_at ASC
      `;
    const rows = (workflowId
      ? this.db.prepare(sql).all(sessionId, workflowId)
      : this.db.prepare(sql).all(sessionId)) as Array<Omit<SecurityWorkflowTask, "suggestedSkills" | "suggestedTools"> & {
        suggestedSkillsJson: string;
        suggestedToolsJson: string;
      }>;
    return rows.map((row) => ({
      ...row,
      recommendedRole: row.recommendedRole ?? undefined,
      suggestedSkills: JSON.parse(row.suggestedSkillsJson) as string[],
      suggestedTools: JSON.parse(row.suggestedToolsJson) as string[]
    }));
  }

  addSecurityToolRun(run: SecurityToolRun): void {
    this.db.prepare(`
      INSERT INTO security_tool_runs (
        id, session_id, workflow_id, parent_run_id, tool_id, phase, origin, status,
        command, input_kind, input_count, input_artifact, output_artifact, output_summary, exit_code,
        blocked_reason, failure_category, finding_count, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      run.id,
      run.sessionId,
      run.workflowId ?? null,
      run.parentRunId ?? null,
      run.toolId,
      run.phase,
      run.origin,
      run.status,
      run.command ?? null,
      run.inputKind ?? null,
      run.inputCount,
      run.inputArtifact ?? null,
      run.outputArtifact ?? null,
      run.outputSummary ?? null,
      run.exitCode ?? null,
      run.blockedReason ?? null,
      run.failureCategory ?? null,
      run.findingCount ?? null,
      run.createdAt,
      run.updatedAt
    );
    this.touchSession(run.sessionId);
  }

  updateSecurityToolRun(run: SecurityToolRun): void {
    this.db.prepare(`
      UPDATE security_tool_runs
      SET status = ?, command = ?, input_kind = ?, input_count = ?, input_artifact = ?,
          output_artifact = ?, output_summary = ?, exit_code = ?, blocked_reason = ?,
          failure_category = ?, finding_count = ?, updated_at = ?
      WHERE id = ?
    `).run(
      run.status,
      run.command ?? null,
      run.inputKind ?? null,
      run.inputCount,
      run.inputArtifact ?? null,
      run.outputArtifact ?? null,
      run.outputSummary ?? null,
      run.exitCode ?? null,
      run.blockedReason ?? null,
      run.failureCategory ?? null,
      run.findingCount ?? null,
      run.updatedAt,
      run.id
    );
    this.touchSession(run.sessionId);
  }

  listSecurityToolRuns(sessionId: string, workflowId?: string): SecurityToolRun[] {
    const sql = workflowId
      ? `
        SELECT id, session_id AS sessionId, workflow_id AS workflowId, parent_run_id AS parentRunId,
               tool_id AS toolId, phase, origin, status, command, input_kind AS inputKind,
               input_count AS inputCount, input_artifact AS inputArtifact, output_artifact AS outputArtifact, output_summary AS outputSummary,
               exit_code AS exitCode, blocked_reason AS blockedReason, failure_category AS failureCategory,
               finding_count AS findingCount, created_at AS createdAt, updated_at AS updatedAt
        FROM security_tool_runs
        WHERE session_id = ? AND workflow_id = ?
        ORDER BY created_at ASC
      `
      : `
        SELECT id, session_id AS sessionId, workflow_id AS workflowId, parent_run_id AS parentRunId,
               tool_id AS toolId, phase, origin, status, command, input_kind AS inputKind,
               input_count AS inputCount, input_artifact AS inputArtifact, output_artifact AS outputArtifact, output_summary AS outputSummary,
               exit_code AS exitCode, blocked_reason AS blockedReason, failure_category AS failureCategory,
               finding_count AS findingCount, created_at AS createdAt, updated_at AS updatedAt
        FROM security_tool_runs
        WHERE session_id = ?
        ORDER BY created_at ASC
      `;
    const rows = (workflowId
      ? this.db.prepare(sql).all(sessionId, workflowId)
      : this.db.prepare(sql).all(sessionId)) as SecurityToolRun[];
    return rows.map((row) => ({
      ...row,
      workflowId: row.workflowId ?? undefined,
      parentRunId: row.parentRunId ?? undefined,
      command: row.command ?? undefined,
      inputKind: row.inputKind ?? undefined,
      inputArtifact: row.inputArtifact ?? undefined,
      outputArtifact: row.outputArtifact ?? undefined,
      outputSummary: row.outputSummary ?? undefined,
      exitCode: row.exitCode ?? undefined,
      blockedReason: row.blockedReason ?? undefined,
      failureCategory: row.failureCategory ?? undefined,
      findingCount: row.findingCount ?? undefined
    }));
  }

  addFinding(finding: SecurityFinding): void {
    this.db.prepare(`
      INSERT INTO findings (
        id, session_id, workflow_id, title, severity, confidence, target, description,
        evidence_summary, remediation, state, dedupe_key, evidence_ids_json, first_seen_at, last_seen_at,
        created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      finding.id,
      finding.sessionId,
      finding.workflowId ?? null,
      finding.title,
      finding.severity,
      finding.confidence,
      finding.target,
      finding.description,
      finding.evidenceSummary ?? null,
      finding.remediation ?? null,
      finding.state ?? "candidate",
      finding.dedupeKey ?? null,
      JSON.stringify(finding.evidenceIds ?? []),
      finding.firstSeenAt ?? finding.createdAt,
      finding.lastSeenAt ?? finding.updatedAt,
      finding.createdAt,
      finding.updatedAt
    );
    this.touchSession(finding.sessionId);
  }

  upsertFinding(finding: SecurityFinding): SecurityFinding {
    if (!finding.dedupeKey) {
      this.addFinding(finding);
      return finding;
    }
    const existing = this.db.prepare(`
      SELECT id, session_id AS sessionId, workflow_id AS workflowId, title, severity, confidence,
             target, description, evidence_summary AS evidenceSummary, remediation,
             state, dedupe_key AS dedupeKey, evidence_ids_json AS evidenceIdsJson,
             first_seen_at AS firstSeenAt, last_seen_at AS lastSeenAt,
             created_at AS createdAt, updated_at AS updatedAt
      FROM findings
      WHERE session_id = ? AND dedupe_key = ?
      ORDER BY created_at ASC
      LIMIT 1
    `).get(finding.sessionId, finding.dedupeKey) as (Omit<SecurityFinding, "evidenceIds"> & { evidenceIdsJson?: string }) | undefined;
    if (!existing) {
      this.addFinding(finding);
      return finding;
    }
    const evidenceIds = uniqueStrings([
      ...parseJsonStringArray(existing.evidenceIdsJson),
      ...(finding.evidenceIds ?? [])
    ]);
    const merged: SecurityFinding = {
      ...existing,
      workflowId: existing.workflowId ?? finding.workflowId,
      severity: rankSeverity(finding.severity) > rankSeverity(existing.severity) ? finding.severity : existing.severity,
      confidence: rankConfidence(finding.confidence) > rankConfidence(existing.confidence) ? finding.confidence : existing.confidence,
      description: mergeText(existing.description, finding.description) ?? existing.description ?? finding.description,
      evidenceSummary: mergeText(existing.evidenceSummary, finding.evidenceSummary),
      remediation: existing.remediation ?? finding.remediation,
      state: strongerFindingState(existing.state, finding.state),
      evidenceIds,
      firstSeenAt: existing.firstSeenAt ?? existing.createdAt,
      lastSeenAt: finding.lastSeenAt ?? finding.updatedAt,
      updatedAt: finding.updatedAt
    };
    this.db.prepare(`
      UPDATE findings
      SET workflow_id = ?, severity = ?, confidence = ?, description = ?, evidence_summary = ?,
          remediation = ?, state = ?, evidence_ids_json = ?, first_seen_at = ?, last_seen_at = ?, updated_at = ?
      WHERE id = ?
    `).run(
      merged.workflowId ?? null,
      merged.severity,
      merged.confidence,
      merged.description,
      merged.evidenceSummary ?? null,
      merged.remediation ?? null,
      merged.state ?? "candidate",
      JSON.stringify(merged.evidenceIds ?? []),
      merged.firstSeenAt ?? merged.createdAt,
      merged.lastSeenAt ?? merged.updatedAt,
      merged.updatedAt,
      merged.id
    );
    this.touchSession(finding.sessionId);
    return merged;
  }

  updateFindingState(findingId: string, state: SecurityFindingState, evidenceIds: string[] = [], rationale?: string): void {
    const existing = this.db.prepare(`
      SELECT id, session_id AS sessionId, evidence_summary AS evidenceSummary, evidence_ids_json AS evidenceIdsJson
      FROM findings
      WHERE id = ?
    `).get(findingId) as { id: string; sessionId: string; evidenceSummary?: string; evidenceIdsJson?: string } | undefined;
    if (!existing) {
      return;
    }
    const mergedEvidenceIds = uniqueStrings([...parseJsonStringArray(existing.evidenceIdsJson), ...evidenceIds]);
    const evidenceSummary = rationale ? mergeText(existing.evidenceSummary, rationale) : existing.evidenceSummary;
    const now = nowIso();
    this.db.prepare(`
      UPDATE findings
      SET state = ?, evidence_ids_json = ?, evidence_summary = ?, last_seen_at = ?, updated_at = ?
      WHERE id = ?
    `).run(state, JSON.stringify(mergedEvidenceIds), evidenceSummary ?? null, now, now, findingId);
    this.touchSession(existing.sessionId);
  }

  listFindings(sessionId: string): SecurityFinding[] {
    const rows = this.db.prepare(`
      SELECT id, session_id AS sessionId, workflow_id AS workflowId, title, severity, confidence,
             target, description, evidence_summary AS evidenceSummary, remediation,
             state, dedupe_key AS dedupeKey, evidence_ids_json AS evidenceIdsJson,
             first_seen_at AS firstSeenAt, last_seen_at AS lastSeenAt,
             created_at AS createdAt, updated_at AS updatedAt
      FROM findings
      WHERE session_id = ?
      ORDER BY created_at ASC
    `).all(sessionId) as Array<Omit<SecurityFinding, "evidenceIds"> & { evidenceIdsJson?: string }>;
    return rows.map((row) => ({
      ...row,
      workflowId: row.workflowId ?? undefined,
      evidenceSummary: row.evidenceSummary ?? undefined,
      remediation: row.remediation ?? undefined,
      state: row.state ?? "candidate",
      dedupeKey: row.dedupeKey ?? undefined,
      evidenceIds: parseJsonStringArray(row.evidenceIdsJson),
      firstSeenAt: row.firstSeenAt ?? row.createdAt,
      lastSeenAt: row.lastSeenAt ?? row.updatedAt
    }));
  }

  addEvidence(evidence: SecurityEvidence): void {
    this.db.prepare(`
      INSERT INTO evidence (id, session_id, workflow_id, finding_id, source, kind, summary, data, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      evidence.id,
      evidence.sessionId,
      evidence.workflowId ?? null,
      evidence.findingId ?? null,
      evidence.source,
      evidence.kind,
      evidence.summary,
      evidence.data ?? null,
      evidence.createdAt
    );
    this.touchSession(evidence.sessionId);
  }

  listEvidence(sessionId: string): SecurityEvidence[] {
    return this.db.prepare(`
      SELECT id, session_id AS sessionId, workflow_id AS workflowId, finding_id AS findingId,
             source, kind, summary, data, created_at AS createdAt
      FROM evidence
      WHERE session_id = ?
      ORDER BY created_at ASC
    `).all(sessionId) as SecurityEvidence[];
  }

  addAsset(asset: SecurityAsset): void {
    this.db.prepare(`
      INSERT INTO security_assets (id, session_id, workflow_id, kind, value, source, confidence, metadata, created_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      asset.id,
      asset.sessionId,
      asset.workflowId ?? null,
      asset.kind,
      asset.value,
      asset.source,
      asset.confidence,
      asset.metadata ?? null,
      asset.createdAt
    );
    this.touchSession(asset.sessionId);
  }

  listAssets(sessionId: string): SecurityAsset[] {
    return this.db.prepare(`
      SELECT id, session_id AS sessionId, workflow_id AS workflowId, kind, value, source,
             confidence, metadata, created_at AS createdAt
      FROM security_assets
      WHERE session_id = ?
      ORDER BY created_at ASC
    `).all(sessionId) as SecurityAsset[];
  }

  addTechnology(technology: SecurityTechnology): void {
    this.db.prepare(`
      INSERT INTO security_technologies (
        id, session_id, workflow_id, target, name, version, category, source,
        confidence, evidence_summary, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      technology.id,
      technology.sessionId,
      technology.workflowId ?? null,
      technology.target,
      technology.name,
      technology.version ?? null,
      technology.category ?? null,
      technology.source,
      technology.confidence,
      technology.evidenceSummary ?? null,
      technology.createdAt
    );
    this.touchSession(technology.sessionId);
  }

  listTechnologies(sessionId: string): SecurityTechnology[] {
    return this.db.prepare(`
      SELECT id, session_id AS sessionId, workflow_id AS workflowId, target, name,
             version, category, source, confidence, evidence_summary AS evidenceSummary,
             created_at AS createdAt
      FROM security_technologies
      WHERE session_id = ?
      ORDER BY created_at ASC
    `).all(sessionId) as SecurityTechnology[];
  }

  addCveMatch(match: SecurityCveMatch): void {
    this.db.prepare(`
      INSERT INTO cve_matches (
        id, session_id, workflow_id, target, technology, cve_id, title, severity,
        confidence, rationale, source, relevance_score, created_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      match.id,
      match.sessionId,
      match.workflowId ?? null,
      match.target,
      match.technology,
      match.cveId ?? null,
      match.title,
      match.severity,
      match.confidence,
      match.rationale,
      match.source,
      match.relevanceScore ?? null,
      match.createdAt
    );
    this.touchSession(match.sessionId);
  }

  updateCveMatch(match: SecurityCveMatch): void {
    this.db.prepare(`
      UPDATE cve_matches
      SET workflow_id = ?, target = ?, technology = ?, cve_id = ?, title = ?, severity = ?,
          confidence = ?, rationale = ?, source = ?, relevance_score = ?
      WHERE id = ?
    `).run(
      match.workflowId ?? null,
      match.target,
      match.technology,
      match.cveId ?? null,
      match.title,
      match.severity,
      match.confidence,
      match.rationale,
      match.source,
      match.relevanceScore ?? null,
      match.id
    );
    this.touchSession(match.sessionId);
  }

  listCveMatches(sessionId: string): SecurityCveMatch[] {
    return this.db.prepare(`
      SELECT id, session_id AS sessionId, workflow_id AS workflowId, target, technology,
             cve_id AS cveId, title, severity, confidence, rationale, source,
             relevance_score AS relevanceScore,
             created_at AS createdAt
      FROM cve_matches
      WHERE session_id = ?
      ORDER BY created_at ASC
    `).all(sessionId) as SecurityCveMatch[];
  }

  addSecurityValidationAttempt(attempt: SecurityValidationAttempt): void {
    this.db.prepare(`
      INSERT INTO security_validation_attempts (
        id, session_id, workflow_id, target_kind, target_id, target_title, method,
        status, confidence, rationale, evidence_ids_json, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      attempt.id,
      attempt.sessionId,
      attempt.workflowId ?? null,
      attempt.targetKind,
      attempt.targetId,
      attempt.targetTitle,
      attempt.method,
      attempt.status,
      attempt.confidence,
      attempt.rationale,
      JSON.stringify(attempt.evidenceIds),
      attempt.createdAt,
      attempt.updatedAt
    );
    this.touchSession(attempt.sessionId);
  }

  listSecurityValidationAttempts(sessionId: string, workflowId?: string): SecurityValidationAttempt[] {
    const sql = workflowId
      ? `
        SELECT id, session_id AS sessionId, workflow_id AS workflowId, target_kind AS targetKind,
               target_id AS targetId, target_title AS targetTitle, method, status,
               confidence, rationale, evidence_ids_json AS evidenceIdsJson,
               created_at AS createdAt, updated_at AS updatedAt
        FROM security_validation_attempts
        WHERE session_id = ? AND workflow_id = ?
        ORDER BY created_at ASC
      `
      : `
        SELECT id, session_id AS sessionId, workflow_id AS workflowId, target_kind AS targetKind,
               target_id AS targetId, target_title AS targetTitle, method, status,
               confidence, rationale, evidence_ids_json AS evidenceIdsJson,
               created_at AS createdAt, updated_at AS updatedAt
        FROM security_validation_attempts
        WHERE session_id = ?
        ORDER BY created_at ASC
      `;
    const rows = (workflowId
      ? this.db.prepare(sql).all(sessionId, workflowId)
      : this.db.prepare(sql).all(sessionId)) as Array<Omit<SecurityValidationAttempt, "evidenceIds"> & { evidenceIdsJson: string }>;
    return rows.map((row) => ({
      ...row,
      workflowId: row.workflowId ?? undefined,
      evidenceIds: JSON.parse(row.evidenceIdsJson) as string[]
    }));
  }

  addSecurityAuthContext(context: SecurityAuthContext): void {
    this.db.prepare(`
      INSERT INTO security_auth_contexts (
        id, session_id, workflow_id, name, base_url, role, username, tenant, cookie_header,
        authorization_header, headers_json, storage_state_path, notes, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      context.id,
      context.sessionId,
      context.workflowId ?? null,
      context.name,
      context.baseUrl ?? null,
      context.role ?? null,
      context.username ?? null,
      context.tenant ?? null,
      context.cookieHeader ?? null,
      context.authorizationHeader ?? null,
      context.headersJson ?? null,
      context.storageStatePath ?? null,
      context.notes ?? null,
      context.createdAt,
      context.updatedAt
    );
    this.touchSession(context.sessionId);
  }

  listSecurityAuthContexts(sessionId: string, workflowId?: string): SecurityAuthContext[] {
    const sql = workflowId
      ? `
        SELECT id, session_id AS sessionId, workflow_id AS workflowId, name, base_url AS baseUrl,
               role, tenant, username, cookie_header AS cookieHeader, authorization_header AS authorizationHeader,
               headers_json AS headersJson, storage_state_path AS storageStatePath, notes,
               created_at AS createdAt, updated_at AS updatedAt
        FROM security_auth_contexts
        WHERE session_id = ? AND (workflow_id = ? OR workflow_id IS NULL)
        ORDER BY created_at ASC
      `
      : `
        SELECT id, session_id AS sessionId, workflow_id AS workflowId, name, base_url AS baseUrl,
               role, tenant, username, cookie_header AS cookieHeader, authorization_header AS authorizationHeader,
               headers_json AS headersJson, storage_state_path AS storageStatePath, notes,
               created_at AS createdAt, updated_at AS updatedAt
        FROM security_auth_contexts
        WHERE session_id = ?
        ORDER BY created_at ASC
      `;
    const rows = (workflowId
      ? this.db.prepare(sql).all(sessionId, workflowId)
      : this.db.prepare(sql).all(sessionId)) as SecurityAuthContext[];
    return rows.map((row) => ({
      ...row,
      workflowId: row.workflowId ?? undefined,
      baseUrl: row.baseUrl ?? undefined,
      role: row.role ?? undefined,
      username: row.username ?? undefined,
      cookieHeader: row.cookieHeader ?? undefined,
      authorizationHeader: row.authorizationHeader ?? undefined,
      headersJson: row.headersJson ?? undefined,
      storageStatePath: row.storageStatePath ?? undefined,
      notes: row.notes ?? undefined
    }));
  }

  addSecurityChecks(checks: SecurityValidationCheck[]): void {
    const statement = this.db.prepare(`
      INSERT INTO security_checks (
        id, session_id, workflow_id, check_id, title, category, target, phase, status,
        active_requires_approval, passive_signals_json, safe_checks_json,
        evidence_summary, rationale, created_at, updated_at
      )
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        title = excluded.title,
        category = excluded.category,
        target = excluded.target,
        phase = excluded.phase,
        status = excluded.status,
        active_requires_approval = excluded.active_requires_approval,
        passive_signals_json = excluded.passive_signals_json,
        safe_checks_json = excluded.safe_checks_json,
        evidence_summary = excluded.evidence_summary,
        rationale = excluded.rationale,
        updated_at = excluded.updated_at
    `);
    for (const check of checks) {
      statement.run(
        check.id,
        check.sessionId,
        check.workflowId ?? null,
        check.checkId,
        check.title,
        check.category,
        check.target,
        check.phase,
        check.status,
        check.activeRequiresApproval ? 1 : 0,
        JSON.stringify(check.passiveSignals),
        JSON.stringify(check.safeChecks),
        check.evidenceSummary ?? null,
        check.rationale ?? null,
        check.createdAt,
        check.updatedAt
      );
    }
    if (checks[0]) {
      this.touchSession(checks[0].sessionId);
    }
  }

  updateSecurityCheckStatus(
    checkId: string,
    status: SecurityCheckStatus,
    evidenceSummary?: string,
    rationale?: string
  ): void {
    const existing = this.db.prepare("SELECT session_id AS sessionId FROM security_checks WHERE id = ?")
      .get(checkId) as { sessionId: string } | undefined;
    this.db.prepare(`
      UPDATE security_checks
      SET status = ?, evidence_summary = ?, rationale = ?, updated_at = ?
      WHERE id = ?
    `).run(status, evidenceSummary ?? null, rationale ?? null, nowIso(), checkId);
    if (existing) {
      this.touchSession(existing.sessionId);
    }
  }

  listSecurityChecks(sessionId: string, workflowId?: string): SecurityValidationCheck[] {
    const sql = workflowId
      ? `
        SELECT id, session_id AS sessionId, workflow_id AS workflowId, check_id AS checkId,
               title, category, target, phase, status,
               active_requires_approval AS activeRequiresApproval,
               passive_signals_json AS passiveSignalsJson,
               safe_checks_json AS safeChecksJson,
               evidence_summary AS evidenceSummary, rationale,
               created_at AS createdAt, updated_at AS updatedAt
        FROM security_checks
        WHERE session_id = ? AND workflow_id = ?
        ORDER BY check_id ASC
      `
      : `
        SELECT id, session_id AS sessionId, workflow_id AS workflowId, check_id AS checkId,
               title, category, target, phase, status,
               active_requires_approval AS activeRequiresApproval,
               passive_signals_json AS passiveSignalsJson,
               safe_checks_json AS safeChecksJson,
               evidence_summary AS evidenceSummary, rationale,
               created_at AS createdAt, updated_at AS updatedAt
        FROM security_checks
        WHERE session_id = ?
        ORDER BY check_id ASC
      `;
    const rows = (workflowId
      ? this.db.prepare(sql).all(sessionId, workflowId)
      : this.db.prepare(sql).all(sessionId)) as Array<Omit<SecurityValidationCheck, "activeRequiresApproval" | "passiveSignals" | "safeChecks"> & {
        activeRequiresApproval: number;
        passiveSignalsJson: string;
        safeChecksJson: string;
      }>;
    return rows.map((row) => ({
      ...row,
      workflowId: row.workflowId ?? undefined,
      activeRequiresApproval: Boolean(row.activeRequiresApproval),
      passiveSignals: JSON.parse(row.passiveSignalsJson) as string[],
      safeChecks: JSON.parse(row.safeChecksJson) as string[],
      evidenceSummary: row.evidenceSummary ?? undefined,
      rationale: row.rationale ?? undefined
    }));
  }

  private normalizeSubAgent(row: SubAgentRecord & { contextPathsJson?: string }): SubAgentRecord {
    return {
      ...row,
      description: row.description ?? undefined,
      priority: row.priority ?? "medium",
      runMode: row.runMode ?? "foreground",
      retryCount: row.retryCount ?? 0,
      maxRetries: row.maxRetries ?? 1,
      parentAgentId: row.parentAgentId ?? undefined,
      contextPaths: parseJsonStringArray(row.contextPathsJson),
      resultSummary: row.resultSummary ?? undefined,
      progressSummary: row.progressSummary ?? undefined,
      toolUseCount: row.toolUseCount ?? 0,
      outputPath: row.outputPath ?? undefined,
      lastHeartbeatAt: row.lastHeartbeatAt ?? undefined,
      memoryKey: row.memoryKey ?? undefined
    };
  }

  // ── Task Tree ──

  upsertTaskNode(node: TaskTreeNode): void {
    this.db.prepare(`
      INSERT INTO task_tree (id, session_id, workflow_id, parent_id, phase, title, goal, status, tool_id, evidence_ids_json, finding_ids_json, summary, sort_order, created_at, updated_at)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      ON CONFLICT(id) DO UPDATE SET
        status = excluded.status,
        evidence_ids_json = excluded.evidence_ids_json,
        finding_ids_json = excluded.finding_ids_json,
        summary = excluded.summary,
        updated_at = excluded.updated_at
    `).run(
      node.id,
      node.sessionId,
      node.workflowId ?? null,
      node.parentId ?? null,
      node.phase,
      node.title,
      node.goal,
      node.status,
      node.toolId ?? null,
      JSON.stringify(node.evidenceIds),
      JSON.stringify(node.findingIds),
      node.summary,
      node.sortOrder,
      node.createdAt,
      node.updatedAt
    );
    this.touchSession(node.sessionId);
  }

  getTaskNodes(sessionId: string, workflowId?: string): TaskTreeNode[] {
    const rows = this.db.prepare(`
      SELECT id, session_id AS sessionId, workflow_id AS workflowId, parent_id AS parentId,
             phase, title, goal, status, tool_id AS toolId,
             evidence_ids_json AS evidenceIdsJson,
             finding_ids_json AS findingIdsJson,
             summary, sort_order AS sortOrder,
             created_at AS createdAt, updated_at AS updatedAt
      FROM task_tree
      WHERE session_id = ? ${workflowId ? "AND workflow_id = ?" : ""}
      ORDER BY sort_order ASC
    `).all(...(workflowId ? [sessionId, workflowId] : [sessionId])) as Array<Omit<TaskTreeNode, "evidenceIds" | "findingIds"> & {
      evidenceIdsJson: string;
      findingIdsJson: string;
    }>;
    return rows.map((row) => ({
      ...row,
      evidenceIds: parseJsonStringArray(row.evidenceIdsJson),
      findingIds: parseJsonStringArray(row.findingIdsJson),
      workflowId: row.workflowId ?? undefined,
      parentId: row.parentId ?? undefined,
      toolId: row.toolId ?? undefined
    }));
  }

  updateTaskNodeStatus(id: string, status: TaskNodeStatus, summary: string): void {
    this.db.prepare(`
      UPDATE task_tree SET status = ?, summary = ?, updated_at = ?
      WHERE id = ?
    `).run(status, summary, nowIso(), id);
  }

  appendTaskNodeEvidence(id: string, evidenceId: string): void {
    const node = this.db.prepare("SELECT evidence_ids_json, session_id FROM task_tree WHERE id = ?")
      .get(id) as { evidence_ids_json: string; session_id: string } | undefined;
    if (!node) return;
    const ids = parseJsonStringArray(node.evidence_ids_json);
    ids.push(evidenceId);
    this.db.prepare("UPDATE task_tree SET evidence_ids_json = ?, updated_at = ? WHERE id = ?")
      .run(JSON.stringify(uniqueStrings(ids)), nowIso(), id);
    this.touchSession(node.session_id);
  }

  appendTaskNodeFinding(id: string, findingId: string): void {
    const node = this.db.prepare("SELECT finding_ids_json, session_id FROM task_tree WHERE id = ?")
      .get(id) as { finding_ids_json: string; session_id: string } | undefined;
    if (!node) return;
    const ids = parseJsonStringArray(node.finding_ids_json);
    ids.push(findingId);
    this.db.prepare("UPDATE task_tree SET finding_ids_json = ?, updated_at = ? WHERE id = ?")
      .run(JSON.stringify(uniqueStrings(ids)), nowIso(), id);
    this.touchSession(node.session_id);
  }

  getActiveTaskContext(sessionId: string): TaskTreeNode[] {
    const nodes = this.getTaskNodes(sessionId);
    if (nodes.length === 0) return [];

    const running = nodes.filter((n) => n.status === "running");
    const pending = nodes.filter((n) => n.status === "pending");
    const active = running.length > 0 ? running : pending.slice(0, 1);
    if (active.length === 0) return [];

    const activeNode = active[0];
    const parent = activeNode.parentId ? nodes.find((n) => n.id === activeNode.parentId) : undefined;
    const children = nodes.filter((n) => n.parentId === activeNode.id).slice(0, 8);
    const siblings = nodes.filter((n) => n.parentId === activeNode.parentId && n.id !== activeNode.id && n.status !== "completed").slice(0, 6);

    return [
      activeNode,
      ...(parent ? [parent] : []),
      ...siblings,
      ...children
    ];
  }
}

function compareSubAgentWork(left: SubAgentRecord, right: SubAgentRecord): number {
  const priorityRank: Record<WorkPriority, number> = {
    critical: 0,
    high: 1,
    medium: 2,
    low: 3
  };
  return (priorityRank[left.priority ?? "medium"] - priorityRank[right.priority ?? "medium"])
    || ((left.retryCount ?? 0) - (right.retryCount ?? 0))
    || left.createdAt.localeCompare(right.createdAt);
}

function parseJsonStringArray(value: string | undefined | null): string[] {
  if (!value) {
    return [];
  }
  try {
    const parsed = JSON.parse(value) as unknown;
    return Array.isArray(parsed) ? parsed.filter((item): item is string => typeof item === "string") : [];
  } catch {
    return [];
  }
}

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter(Boolean))];
}

function mergeText(left: string | undefined, right: string | undefined): string | undefined {
  if (!left) {
    return right;
  }
  if (!right || left.includes(right)) {
    return left;
  }
  if (right.includes(left)) {
    return right;
  }
  return `${left}\n${right}`.slice(0, 4000);
}

function rankSeverity(severity: SecurityFinding["severity"]): number {
  return { info: 0, low: 1, medium: 2, high: 3, critical: 4 }[severity];
}

function rankConfidence(confidence: SecurityFinding["confidence"]): number {
  return { low: 0, medium: 1, high: 2 }[confidence];
}

function strongerFindingState(
  left: SecurityFindingState | undefined,
  right: SecurityFindingState | undefined
): SecurityFindingState {
  const rank: Record<SecurityFindingState, number> = {
    candidate: 0,
    needs_validation: 1,
    false_positive: 2,
    accepted_risk: 3,
    fixed: 4,
    validated: 5
  };
  const safeLeft = left ?? "candidate";
  const safeRight = right ?? "candidate";
  return rank[safeRight] > rank[safeLeft] ? safeRight : safeLeft;
}
