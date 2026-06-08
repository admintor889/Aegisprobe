# AegisProbe 架构文档

## 项目结构

```
agent-pentest-assistant/
├── apps/cli/              # CLI入口 (commander)
│   └── src/index.ts       # 所有命令定义, stdin处理, createAgent
├── packages/
│   ├── core/              # 核心Agent循环 (MainAgent)
│   ├── shared/            # 共享类型 (50+类型定义, 工具函数)
│   ├── security/          # 安全编排 (管线/适配器/FOFA/CVE/载荷)
│   ├── storage/           # SQLite审计存储 (25+表)
│   ├── context/           # 上下文管理器 (CodexLikeContextManager)
│   ├── policy/            # 命令安全策略 (危险命令阻止)
│   ├── provider/          # LLM提供者 (DeepSeek OpenAI-compatible)
│   ├── tools/             # 工具清单/解析 (AgentDecision JSON)
│   ├── skills/            # 技能注册表 (YAML/SKILL.md加载)
│   ├── shell/             # Shell执行 (PowerShell/bash自适应)
│   └── mcp/               # MCP协议客户端 (JSON-RPC stdio)
├── configs/config.yaml    # 主配置
├── tools/bin/             # 外部工具二进制
├── tools/templates/       # nuclei模板
└── data/                  # 运行时数据
    ├── cve-exploit-kb/    # CVE知识库 (4024 CVE索引)
    └── security-knowledge/ # 框架/CMS/业务逻辑知识
```

## 核心数据流

```
用户输入 (URL/域名/IP)
  ↓
CLI: createAgent() → MainAgent
  ↓
executePentestPipeline(sessionId, target, scope)
  ├─ 1. 预检: buildPipelinePreflight() → 展示工具可用性
  ├─ 2. 工作流: buildSecurityWorkflowPlan() → SQLite持久
  ├─ 3. 基线探针: basic_recon (DNS+HTTP头)
  ├─ 4. 模型循环 (无限, LLM控制终止)
  │   ├─ buildContextSnapshot() → 打包上下文
  │   ├─ samplePentestDecision() → 调用V4 Pro
  │   ├─ 解析JSON → AgentDecision {message, plan, actions, final}
  │   ├─ executeDecisionTools() → 执行actions
  │   └─ 观察反馈 → 下一轮
  ├─ 5. 自动分发queued子Agent
  └─ 6. 返回摘要
```

## Agent循环详解

```typescript
// packages/core/src/index.ts — executePentestPipeline()
for (let iter = 0; ; iter += 1) {  // 无限循环
  // 构建上下文快照
  const snapshot = buildContextSnapshot(sessionId, {
    currentInput, currentTarget, turnObservations
  });

  // 调用LLM (V4 Pro)
  const decision = await samplePentestDecision(..., snapshot);

  // decision.final === true → LLM决定终止
  if (decision.final && executableActions.length === 0) break;

  // 执行工具动作
  const results = await executeDecisionTools(decision.actions);
  turnObservations.push(...results);
}
```

## 子Agent系统

### 角色定义 (packages/core/src/index.ts)

```typescript
subAgentRoleDefinitions = {
  recon:       { tools: [shell, security_probe], 迭代:20 }  // PTES Phase 2: 全面扫描
  fingerprint: { tools: [shell, security_probe], 迭代:20 }  // PTES Phase 3: 分类枚举
  cve:         { tools: [shell],                  迭代:25 }  // PTES Phase 4: CVE匹配
  web_vuln:    { tools: [shell, security_probe], 迭代:20 }  // OWASP WSTG
  exploit:     { tools: [shell, security_probe], 迭代:25 }  // PTES Phase 5: 漏洞利用
  frontend:    { tools: [shell],                  迭代:20 }  // 前端爬取
  // read_only角色: explorer, reviewer, default, worker
}
```

> 提示词遵循 **"教方法不教答案"** 原则：只描述方法论和决策树，不硬编码凭据、CVE编号或靶机信息。模型根据实际扫描输出自行判断。

### 子Agent生命周期

```
主循环 LLM决定 → action {type:"subagent", role:"recon", task:"..."}
  ↓
executeSubAgentAction() → 创建SubAgentRecord → SQLite
  ↓
runSubAgentRecord() → 独立LLM循环 (V4 Pro, jsonMode)
  ├─ 构建role-specific system prompt
  ├─ 调用provider.complete() → parseSubAgentToolDecision()
  ├─ 执行工具 (shell/read_file/list_files/security_probe)
  └─ 达到迭代上限或final:true → 返回摘要
  ↓
结果存入SQLite → _digest.md → 主循环观察
```

### 子Agent互通

```
agent A完成 → buildSubAgentDigest() → _digest.md
  ↓
agent B启动 → enrichSubAgentTask() → 注入A的发现
  ↓
主循环 → turnObservations注入累计摘要
```

## 工具系统

### AgentAction类型 (packages/shared)

```typescript
type AgentAction =
  | {type:"shell", command, purpose}
  | {type:"subagent", role, task, background?}
  | {type:"security_probe", target, probe}
  | {type:"read_file", path, purpose}
  | {type:"list_files", path, recursive?}
  | {type:"apply_patch", patch, purpose}
  | {type:"mcp", tool, args, purpose}
  | {type:"ask_user", question, reason}
  | {type:"none", purpose}
```

### 工具分发 (packages/core)

```typescript
toolHandlers = {
  shell: executeShellAction    → runShell() → spawn(bash/powershell)
  subagent: executeSubAgentAction → spawnSubAgent()
  security_probe: executeSecurityProbeAction → DNS/HTTP探测
  read_file: executeReadFileAction
  list_files: executeListFilesAction
  apply_patch: executeApplyPatchAction
  mcp: mcpManager.callTool()
}
```

### 子Agent工具执行 (runSubAgentRecord)

```
LLM返回JSON → parseSubAgentToolDecision()
  → 检查allowedTools.has(action.type) → 阻止未授权工具
  → 分发到对应handler
  → 观察存入observations[]
  → 下一轮迭代
```

## 上下文管理 (packages/context)

### 三层记忆

```
Layer 1: Session Memory (pinned, 6000 chars)
  └─ 摘要 + 关键事实 + 待办 → SQLite持久, 每轮更新

Layer 2: Security State (high, 8000 chars)
  └─ findings + assets + technologies + cve_matches + evidence
  └─ 工具跑出的所有数据

Layer 3: Task Tree (high, 4000 chars)
  └─ 当前活跃节点 + 父节点 + 兄弟节点
  └─ 独立于LLM上下文窗口
```

### 打包策略

```
24000 token总预算 → 按优先级(pinned > high > normal > low)填充
pinned永不丢弃, low可能被截断
```

## MCP协议 (packages/mcp)

### 架构

```
McpManager → 多服务器管理
  ├─ McpClient → 单个MCP服务器
  │   ├─ spawn(npx, [@playwright/mcp@latest])
  │   ├─ JSON-RPC over stdio (Content-Length framing)
  │   ├─ initialize → tools/list → tools/call
  │   └─ 非阻塞启动: fire-and-forget, callTool等待ready
  └─ 工具自动注入提示词
```

### Playwright MCP配置

```yaml
mcp:
  enabled: true
  servers:
    - name: playwright
      command: npx
      args:
        - "@playwright/mcp@latest"
        - "--headless"
        - "--browser=chromium"
```

## 模型分层

```
主循环: V4 Pro (deepseek-v4-pro)
  - 复杂推理, 战略决策, 子Agent编排
  - jsonMode: true, maxTokens: 16000, timeout: 300s

子Agent: V4 Pro (deepseek-v4-pro)
  - 工具调用, JSON输出, MCP浏览器操作
  - jsonMode: true, fast: false, maxTokens: 16000
  - 标识: provider.complete(messages, {jsonMode:true, fast:false})
```

## 审批与安全

```
授权确认 → autoApprove.active = true
  ↓
所有工具自动批准 (approve callback检查autoApprove)
  ↓
policy层阻止危险命令 (rm -rf, format, shutdown等)
  ↓
路径沙箱 (禁止访问工作区外+敏感文件)
```

## CLI命令速查

```bash
# 核心
aegisprobe pentest <target> --active --rate 10 --yes
aegisprobe pentest <session-id> --resume     # 恢复会话

# 信息收集
aegisprobe fofa subdomain <domain>           # FOFA子域名
aegisprobe fofa ip <ip>                      # FOFA IP查询

# CVE
aegisprobe exploit --sync                    # 索引4024 CVE
aegisprobe exploit <cve-id>                  # 搜索CVE

# 字典
aegisprobe dict                              # 查看字典配置

# Shell管理
aegisprobe shell listen <port>               # nc监听
aegisprobe shell sessions                    # 活跃会话
aegisprobe shell exec <id> <cmd>             # 执行命令
```

## 关键文件索引

| 功能 | 文件 |
|------|------|
| CLI入口 | `apps/cli/src/index.ts` |
| Agent循环 | `packages/core/src/index.ts` (MainAgent) |
| 子Agent角色 | `packages/core/src/index.ts` (subAgentRoleDefinitions) |
| 子Agent执行 | `packages/core/src/index.ts` (runSubAgentRecord) |
| pentest决策 | `packages/core/src/index.ts` (samplePentestDecision) |
| resumePentest | `packages/core/src/index.ts` (resumePentestPipeline) |
| 上下文 | `packages/context/src/index.ts` |
| 工具解析 | `packages/tools/src/index.ts` |
| 类型定义 | `packages/shared/src/index.ts` |
| 安全工具 | `packages/security/src/index.ts` |
| FOFA客户端 | `packages/security/src/index.ts` (fofaSearch) |
| 载荷生成 | `packages/security/src/index.ts` (generatePayload) |
| CVE索引 | `packages/security/src/index.ts` (syncCveExploitIndex) |
| SQLite | `packages/storage/src/index.ts` (AuditStore) |
| LLM提供者 | `packages/provider/src/index.ts` |
| Shell执行 | `packages/shell/src/index.ts` |
| Shell管理 | `packages/shell/src/index.ts` (startShellListener) |
| MCP客户端 | `packages/mcp/src/index.ts` |
| 配置 | `configs/config.yaml` |
| 环境变量 | `.env` (DEEPSEEK_API_KEY) |
