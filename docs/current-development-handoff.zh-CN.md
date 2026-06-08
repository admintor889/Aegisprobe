# AegisProbe 当前开发交接文档

生成时间：2026-06-07

工作目录：

```text
E:\My_working_space\aegisprobe\agent-pentest-assistant
```

这份文档给新对话继续开发使用。核心目标不是继续堆 CVE payload，而是把 AegisProbe 从“CVE-first 的脚本型 agent”升级为“先理解 Web 应用、再根据证据选择测试路径的 Web 渗透 agent”。

## 1. 总目标

AegisProbe 下一阶段的产品目标：

- 先做 Web 应用制图，再决定测试路径。
- 证据优先：endpoint、参数、身份态、页面、表单、JS、网络请求、技术栈、版本、响应差异都必须落到 evidence / asset / finding / tool run。
- API-first 但不是 URL-list-first：把浏览器、JS、OpenAPI、GraphQL、运行时网络请求合并成 normalized API inventory。
- 认证和授权优先：有登录面或 API 证据时，优先考虑 session、JWT、IDOR、BOLA、BFLA、tenant isolation、workflow bypass。
- CVE 只能作为后置 targeted validation：必须先有产品/框架/版本/指纹证据，不能上来就跑 payload。
- 主动验证必须受 scope 和 approval 控制。
- secret-like 字符串必须脱敏。
- 不允许硬编码某个靶场、CVE、路径或 payload 到 agent 决策逻辑里。

一句话验收标准：

```text
Agent 每轮先回答“我掌握了哪些 endpoint、参数、身份态、证据、缺口”，然后只选择证据支持的下一步。
```

## 2. 当前项目状态概览

当前项目已经明显不只是脚本小子式 CVE matcher，但还没有达到成熟 Web 渗透人员水平。

已经完成的主干能力：

- WebApp Recon Runtime：Playwright 打开目标，采集页面、表单、链接、iframe、script、runtime network、cookies、storage、JS endpoint、source map hint、auth surface。
- JS Analyzer 基础版：从 JS bundle 中提取 API 路径、baseURL、GraphQL/WebSocket/admin/debug route、secret-like signals、source map、前端库候选。
- API Inventory Normalizer 基础版：把 HTML/JS/network/OpenAPI/GraphQL 来源合并成 normalized API endpoint，保存 method、path template、query/body hints、sources、authRequired、confidence、riskSignals、examples。
- Auth Surface Model 基础版：识别登录页、认证 endpoint、密码表单、auth-related storage/cookie/session/JWT signals。
- Web Operating Picture：每轮决策前生成紧凑 Web/API 作战图，包括 normalized endpoint map、auth state、evidence gaps、allowed next actions、blocked-until-evidence。
- Evidence-driven Decision Queue：队列不是固定流水线，而是从 asset graph、tool runs、findings、auth contexts、scope 动态排序下一步。
- Business Logic / Authorization Planner 基础版：根据 normalized API 和 auth contexts 生成 BOLA/IDOR/BFLA/workflow/tenant 等候选计划。
- 多角色 gating 初步完成：0/1/2 个 auth contexts 时，decision queue 行为不同。
- Read-only cross-role comparison 已接入 decision queue：有两个 approved auth contexts 和 concrete read-only API examples 时，队列可以直接执行只读跨角色响应对比。
- SQLite evidence/assets/findings/tool-runs 已贯穿主流程。
- CLI / MainAgent / Web UI / server 都已能构建。
- Vulhub smoke harness 已覆盖 5 个已知 CVE 靶场，作为回归测试存在，但不能代表业务逻辑能力完成。

最近一次验证结果：

```text
pnpm --filter @aegisprobe/core test       -> 46 passed
pnpm --filter @aegisprobe/security test   -> 75 passed
pnpm --filter @aegisprobe/security build  -> passed
pnpm --filter @aegisprobe/core build      -> passed
pnpm --filter @aegisprobe/cli build       -> passed
pnpm --filter @aegisprobe/server build    -> passed
```

最近一次 Vulhub matrix：

```text
data\lab-smoke-matrix\20260607-001520-959-31532\summary.json
total=5 passed=5 failed=0
```

覆盖：

- vulhub-struts2-s2-045
- vulhub-flask-ssti
- vulhub-spring-cve-2022-22978
- vulhub-apisix-cve-2021-45232
- vulhub-joomla-cve-2023-23752

注意：这些是 proof/regression harness，证明 agent 没有丢掉 CVE 靶场打点能力；它们不能证明 BOLA/BFLA/业务逻辑成熟。

## 3. 重要文件地图

优先阅读：

- `docs/security-agent-flow.md`
- `ROADMAP.md`
- `docs/current-development-handoff.zh-CN.md`

不要优先依赖：

- `docs/modular-development-handoff.zh-CN.md`

原因：该文件在当前终端显示为乱码，可能存在编码损坏。新开发应以本文件和 `docs/security-agent-flow.md` 为准。

核心代码：

| 文件 | 作用 |
|---|---|
| `packages/shared/src/index.ts` | 跨包类型，包含 WebAppReconResult、NormalizedApiEndpoint 等类型 |
| `packages/core/src/security-browser.ts` | Playwright/WebApp recon runtime |
| `packages/security/src/js-analyzer.ts` | JS endpoint、secret-like signal、source map、library analyzer |
| `packages/security/src/api-inventory.ts` | API inventory normalization |
| `packages/security/src/auth-surface.ts` | Auth surface model |
| `packages/core/src/web-pentest-control-plane.ts` | Web Operating Picture / Control Plane |
| `packages/security/src/decision-models.ts` | Evidence-driven decision queue |
| `packages/core/src/security-execution.ts` | Decision queue item execution |
| `packages/core/src/security-business.ts` | Business logic plan、auth context、role comparison |
| `packages/core/src/index.ts` | MainAgent 对外入口和依赖注入 |
| `packages/core/src/decision-prompts.ts` | Pentest decision prompt |
| `apps/cli/src/index.ts` | CLI command entry |
| `packages/server/src/index.ts` | Web UI server API / WebSocket |
| `apps/webui/app.js` | Web UI 前端 |
| `scripts/agent-lab-smoke.mjs` | 本地 lab smoke harness |
| `scripts/agent-lab-smoke-cases.json` | lab proof case 配置 |
| `scripts/run-lab-smoke-matrix.ps1` | Vulhub matrix runner |

## 4. 当前已有能力细节

### 4.1 Browser Recon / WebApp Recon

当前能力：

- Playwright 打开目标 URL。
- 采集 same-origin pages、links、forms、scripts、iframes。
- 监听 runtime network requests。
- 记录 method、URL、status、content-type 等网络信息。
- 采集 localStorage/sessionStorage/cookie signals，遇到 SecurityError 容错。
- 不默认提交表单、不做危险点击。
- 输出 artifact 到 `data/runs/.../browser/webapp-recon-*.json`。
- 写入 SQLite evidence、assets、finding 摘要。

不足：

- 登录后 crawling 还弱，authenticated context 目前主要靠外部注册。
- SPA 深层交互、按钮点击、菜单展开、动态路由发现还不够成熟。
- HAR 级别 headers/body/initiator 还可以更完整。
- iframe / cross-origin 行为只做保守记录，没有做更强的 frame context 分析。

### 4.2 JS Asset Analyzer

当前能力：

- 下载并分析 JS bundle。
- 提取 endpoint candidates、baseURL、GraphQL endpoint、WebSocket URL、admin/debug/internal route。
- 检测 source map hint，并在安全边界内尝试读取 `.map`。
- 提取 secret-like signals，并做脱敏。
- 提取前端库候选，做 Retire.js 风格的 outdated-library candidate signal。

不足：

- AST 解析还不是主路径，当前仍以 regex + lightweight parsing 为主。
- source map 还原只做基础结构，不是完整源码语义分析。
- secret false-positive 分类还需要增强，例如区分 test key、public SDK key、真正高风险 credential。
- 前端库漏洞库仍偏轻，需要和真实 Retire.js advisory/source 或本地 advisory 数据增强。

### 4.3 API Inventory Normalizer

当前能力：

- 合并 HTML/JS 静态提取、浏览器 runtime network、OpenAPI/Swagger、GraphQL introspection hints。
- 输出 normalized endpoint：
  - method
  - pathTemplate
  - examples
  - queryParams
  - bodyParamHints
  - sources
  - authRequired
  - confidence
  - riskSignals
- 做 path template 归一化，例如数字/UUID/token-like segment -> `{id}` / `{token}` 等模板。
- 高熵参数名和 secret-like signals 已做脱敏。
- 归一化 API 会写入 artifact、SQLite asset、evidence、finding 摘要。
- decision queue 和 business logic planner 会优先使用 normalized API，而不是原始 URL 列表。

不足：

- request clustering 还偏规则化，尚未做到成熟代理工具那种相似请求聚类。
- body schema inference 仍浅，复杂 JSON body、GraphQL variables、multipart/form-data 需要增强。
- OpenAPI/Swagger 发现和拉取能力还可以更主动但必须 scope-gated。
- GraphQL introspection 只能在允许范围内进行，默认应保持保守。

### 4.4 Auth Surface Model

当前能力：

- 识别 login/register/password/reset/auth endpoints。
- 识别 password forms。
- 识别 auth-related cookies、storage keys、JWT/session hints。
- 输出 auth state 和 next evidence needed。
- Auth evidence 会进入 Web Operating Picture 和 decision queue。

不足：

- 还没有稳定的“自动登录流程”。
- 还没有完整区分 anonymous / failed-login / authenticated / expired-session。
- MFA、验证码、SSO、OAuth/OIDC 流程只做识别，不做完整流程维护。
- 用户提供账号后，Playwright storageState 生命周期管理仍需要加强。

### 4.5 Evidence-driven Decision Queue

当前能力：

- 决策队列不是固定阶段，而是从当前 evidence graph 动态生成。
- 没有 endpoint/param evidence 时，不允许直接进入 payload/CVE/exploit。
- 有 normalized API 时，优先生成 authz-plan、sample request collection、business logic planning。
- 有产品/版本证据后，才考虑 CVE/framework/template candidate validation。
- 主动工具需要 scope 和 approval。
- 能避免部分重复低价值工具循环。

最近新增的多角色授权 gating：

- 0 个 auth contexts 且存在 auth/authorization surface：队列要求收集 approved roles/users/tenants。
- 1 个 auth context 且 authz-plan blocked：队列要求注册第二个 approved role，不再泛泛做 business logic planning。
- 2 个 auth contexts 且 authz-plan ready：队列优先生成 `Run read-only cross-role authorization comparison`。
- `business-compare` 已接入 `executeSecurityDecisionQueueItem`，可直接从队列执行 read-only role comparison。

不足：

- 重复控制还可以继续增强，尤其是模型多轮反复建议相似 curl/nuclei/dirsearch 的情况。
- 队列“为什么不做某事”的解释可以更细，方便 UI 展示。
- 对 GraphQL、WebSocket、state-changing endpoint 的安全边界还要更精细。

### 4.6 Business Logic / Authorization

当前能力：

- 能从 normalized API 中识别 high-value routes：
  - admin/manage/role/permission
  - object id / UUID / tenant / account / order / invoice
  - refund/payment/price/coupon/credit/transfer
  - reset/password/invite/email/mfa/session/token
  - export/download/upload/file/share/delete
- 能建立 authorization boundary matrix。
- 能生成 authorization validation plan。
- 对 read-only GET/HEAD concrete examples 可执行 cross-role response comparison。
- 能记录 role comparison evidence、validation attempt、candidate finding。

不足：

- 还不能自动判断“两个角色相同响应一定是漏洞”，因为缺少 expected role policy。
- 需要支持用户提供 role policy，例如：
  - customer-a 只能访问自己的 order；
  - customer-b 不能访问 customer-a 的 order；
  - admin 可以访问所有 order；
  - tenant-a 和 tenant-b 必须隔离。
- 还没有足够的本地多角色靶场测试。
- state-changing workflow 测试仍应默认 blocked，需要显式 approval 和安全回滚方案。

## 5. 当前主要不足

按优先级排序：

### P0：缺少多角色业务逻辑测试靶场

现在 Vulhub matrix 能证明 CVE proof 还在，但不能证明成熟 Web pentest 能力。下一步必须补一个本地多角色 Web 测试应用或引入安全训练靶场，验证：

- 登录态 A/B/admin。
- IDOR/BOLA：用户 A 访问用户 B 对象。
- BFLA：普通用户访问 admin API。
- Tenant isolation：tenant A 不能访问 tenant B。
- Workflow bypass：未满足状态前访问后续步骤。
- Mass assignment：普通用户提交 role/isAdmin 等字段。

要求：

- 靶场可以本地启动，最好 Node/Express 或现有 Docker app。
- 只做授权的本地 smoke。
- 不把靶场路径/漏洞逻辑硬编码进 agent 决策。
- smoke assertions 可以针对靶场，但 agent 逻辑不能针对靶场。

### P1：Authenticated Browser Recon 不够成熟

需要让用户能够提供账号/登录步骤/storageState，然后 agent 维护 authenticated context：

- CLI 支持注册 cookieHeader、authorization header、storageState path、username/role/tenant。
- Web UI 支持显示和管理 auth contexts。
- Browser recon 支持 anonymous 和 authenticated 两种 context 分别跑。
- Auth surface model 区分 anonymous、failed-login、authenticated、expired。

### P1：Expected Role Policy 缺失

当前 cross-role response parity 只能变成 candidate/inconclusive。要变成更可信 finding，需要用户或配置提供预期授权策略。

建议增加：

```ts
type ExpectedAuthorizationPolicy = {
  subject: string;
  role?: string;
  tenant?: string;
  canAccess: string[];
  cannotAccess: string[];
  objectOwnership?: Array<{ route: string; ownerParam: string }>;
};
```

策略来源：

- CLI 参数 / JSON 文件。
- Web UI 表单。
- 明确的用户对话输入。
- 从 OpenAPI description / route naming 只能生成 hypothesis，不能直接当 proof。

### P1：Decision Queue 还要继续减少无意义循环

需要继续打磨：

- 同一 tool/input/target 多次失败后降权。
- 同一 endpoint 已经有 authz-plan / sample / comparison 后，不重复生成低价值候选。
- 对 blocked item 给出具体缺口，例如“需要 second role”、“需要 concrete example”、“需要 active approval”。
- 每轮 prompt 中强化“不重复做没有新增证据的动作”。

### P2：GraphQL / WebSocket / OpenAPI 深化

需要增强：

- GraphQL endpoint、operation name、variables、query/mutation 分类。
- WebSocket URL 和 message shape 采样。
- Swagger/OpenAPI URL 发现、拉取、scope validation、path import。
- 对 introspection 保守处理：默认不主动跑，除非 scope/approval 允许。

### P2：Web UI 作战图展示

右侧流程应从固定阶段变成动态节点：

```text
Collected JS assets: 12
Extracted API endpoints: 47
Sensitive hints: 3
Login surface: /login
Auth state: anonymous
Approved auth contexts: customer-a, admin-a
Ready authz candidates: 5
Blocked until evidence: second role / concrete example / active approval
High-value routes: GET /api/admin/users/{id}, GET /api/orders/{id}
```

终端区域显示真实命令/浏览器动作，不显示虚假的固定 pipeline。

### P2：Source Map / Secret Triage

需要把前端敏感信息处理做细：

- source map 中的源码路径和 API 常量应进入 evidence。
- secret-like signals 必须保持脱敏。
- 区分 public key、SDK client id、test token、cloud access key、JWT、private key。
- findings 只能报告“可能泄露”候选，不能把完整 secret 写入 summary。

## 6. 推荐开发路线

### 阶段 A：补多角色本地靶场和 smoke harness

目标：证明 agent 能从“制图 -> auth contexts -> normalized API -> authz plan -> read-only comparison -> candidate finding”走通。

建议新增：

- `labs/targets/local-multirole-app/` 或 `labs/targets/webgoat-like/`
- 本地 Express app 或 Docker compose。
- 用户：
  - `alice` role=`customer` tenant=`tenant-a`
  - `bob` role=`customer` tenant=`tenant-b`
  - `admin` role=`admin`
- 路由：
  - `GET /login`
  - `POST /api/login`
  - `GET /api/me`
  - `GET /api/orders/:id`
  - `GET /api/admin/users/:id`
  - `POST /api/orders/:id/refund`
  - `PATCH /api/users/:id`
- 故意设计若干可控缺陷：
  - read-only IDOR/BOLA endpoint；
  - admin API BFLA；
  - mass assignment 只作为 blocked/approval-gated test，不默认执行。

验收：

- agent 不知道这个靶场名称也能从 recon 得到 API map。
- normalized API 中包含 path template 和 examples。
- auth contexts 注册后，queue 先做 authz-plan，再做 business-compare。
- read-only comparison evidence 写入 SQLite。
- finding 是 candidate/inconclusive，除非提供 expected policy。

### 阶段 B：Authenticated Context 注册和复用

目标：让账号/角色变成一等证据。

开发点：

- CLI 增加 auth context 管理命令，或完善已有接口。
- 支持 storageState path、cookieHeader、authorizationHeader、role、tenant、username、baseUrl。
- Browser recon 支持指定 auth context 运行。
- Web Operating Picture 展示 auth contexts 和 role coverage。
- Decision Queue 对缺少 second role、缺少 tenant pair 给出明确下一步。

验收：

- 0 context：queue 要求注册角色。
- 1 context：queue 要求第二角色。
- 2 contexts：queue 可执行 read-only cross-role comparison。
- failed login / expired cookie 不应被当作 authenticated context。

### 阶段 C：Expected Authorization Policy

目标：把“响应相同候选”升级为“违反预期策略的验证结果”。

开发点：

- 新增 policy 类型和 SQLite 持久化。
- CLI/Web UI 支持导入 policy JSON。
- comparison 时结合 policy 判断 expected deny/allow。
- finding confidence 从 low/inconclusive 升级必须依赖 policy + evidence。

验收：

- 没有 policy：只产生 candidate/inconclusive。
- 有 policy：违反 deny rule 的 read-only access 可产生 validated finding。
- policy 不能从 route name 自动臆断，只能生成建议。

### 阶段 D：UI 作战图和报告

目标：让用户看到 agent 为什么下一步这样做。

开发点：

- Server API 暴露 operating picture / decision queue / authz matrix。
- Web UI 右侧渲染动态节点。
- 报告加入：
  - API inventory summary；
  - auth surface；
  - auth contexts；
  - authz matrix；
  - blocked tests；
  - validated/candidate findings 分离。

验收：

- UI 不显示固定阶段。
- 每个节点能追溯 evidence/tool run。
- 报告不泄露 secret。

## 7. 开发约束

必须遵守：

- 不要回滚用户已有改动。
- 不要硬编码靶场、CVE、固定路径、固定 payload 到 agent 决策逻辑。
- smoke case 可以有靶场特定 assertion，但必须和 agent 决策逻辑隔离。
- 所有结论必须来自 evidence。
- 主动验证必须受 scope 和 approval 控制。
- secret-like 字符串必须脱敏。
- 默认只读；POST/PATCH/DELETE/PUT 类动作必须更严格 gating。
- 不允许把没有 endpoint/param evidence 的 payload test 放到队列前面。
- CVE runner 是后置模块，不是主路线。

## 8. 测试路线

### 8.1 快速单元测试

每次改 core/security 相关逻辑后先跑：

```powershell
pnpm --filter @aegisprobe/security test
pnpm --filter @aegisprobe/core test
```

### 8.2 构建测试

核心包和入口都要过：

```powershell
pnpm --filter @aegisprobe/security build
pnpm --filter @aegisprobe/core build
pnpm --filter @aegisprobe/cli build
pnpm --filter @aegisprobe/server build
```

必要时跑全量：

```powershell
pnpm build
pnpm test
```

### 8.3 本地临时 Web 页面 smoke

用于验证 Browser Recon / JS Analyzer / API Normalizer：

- 本地 HTTP server 提供 HTML、JS、API JSON。
- 页面包含 login form、fetch(`/api/orders/1001?include=items`)、admin route、source map hint。
- 断言：
  - tool run success；
  - artifact 写入；
  - normalized endpoint 写入 asset；
  - high-entropy param/secret 已脱敏；
  - decision queue 不直接跑 CVE。

### 8.4 多角色业务逻辑 smoke

这是下一步最重要测试。

断言：

- anonymous recon 能发现 login/auth surface。
- authenticated recon 能发现更多 API。
- normalized API 有 concrete examples。
- 0/1/2 auth contexts 的 queue 行为符合预期。
- read-only cross-role comparison 使用 concrete example，不使用 `/api/orders/{id}` 模板直接请求。
- comparison evidence 写入 `business-logic:compare:*`。
- 没有 expected policy 时 finding 只能 candidate/inconclusive。
- 有 expected policy 时才能 validated。

### 8.5 Vulhub matrix 回归

用于确认 CVE proof 能力没有退化：

```powershell
pnpm lab:vulhub:matrix
```

或逐个：

```powershell
pnpm lab:vulhub:s2-045
pnpm lab:vulhub:flask-ssti
pnpm lab:vulhub:spring-22978
pnpm lab:vulhub:apisix-45232
```

如果需要 Joomla：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\test-vulhub-batch.ps1 -Root labs\targets\vulhub\joomla\CVE-2023-23752 -BatchSize 1 -MaxTargets 1 -UseSmokeHarness -SmokeActiveProof
```

注意：

- Docker matrix 可能耗时几分钟。
- 不要并发启动占用同一端口的 Vulhub case。
- 这些测试不能替代多角色业务逻辑测试。

## 9. 当前可疑问题和风险

### 9.1 旧中文文档编码损坏

`docs/modular-development-handoff.zh-CN.md` 在当前终端读出乱码。新对话不要基于它继续编辑，除非先确认文件实际编码并修复。

### 9.2 ROADMAP 有历史内容和编码噪声

`ROADMAP.md` 中 v2/v3 历史内容较多，部分中文符号也显示异常。以 `docs/security-agent-flow.md` 和本文件作为当前开发事实。

### 9.3 Web UI 还没有完整呈现 Operating Picture

后端已有 operating picture，UI 仍需更明确展示动态 evidence nodes。

### 9.4 Cross-role comparison 还不是最终漏洞判定

没有 expected role policy 时，响应相同只能说明“需要人工确认的授权候选”。不要把它当作 validated 漏洞。

### 9.5 CVE 靶场通过不代表成熟 Web pentest

Vulhub 5/5 是好信号，但下一步必须用多角色业务逻辑靶场证明 agent 会像渗透人员一样工作。

## 10. 新对话建议第一步

新对话开始后先执行：

```powershell
Get-Content docs\current-development-handoff.zh-CN.md
Get-Content docs\security-agent-flow.md
rg -n "business-compare|authz-plan|NormalizedApiEndpoint|WebAppReconResult|authContext" packages
pnpm --filter @aegisprobe/security test
pnpm --filter @aegisprobe/core test
```

然后优先实现：

```text
P0: 本地多角色 Web 靶场 + smoke harness + expected role policy 雏形。
```

不要先加新 CVE payload。

## 11. 可复制给新对话的提示词

```text
你现在继续开发 E:\My_working_space\aegisprobe\agent-pentest-assistant。

请先阅读：
- docs/current-development-handoff.zh-CN.md
- docs/security-agent-flow.md
- ROADMAP.md

当前目标：把 AegisProbe 从 CVE-first 的脚本型 agent 升级为成熟 Web 渗透人员式的证据驱动 agent。必须先理解 Web 应用，再决定测试路径。不要继续优先堆 CVE payload。

当前已完成：
- webapp-recon 已实现并接入 CLI / MainAgent / decision queue。
- JS analyzer、API inventory normalizer、auth surface model、Web Operating Picture 已有基础版本。
- normalized API 会写入 artifact、SQLite evidence/assets/finding 摘要，并接入 decision queue。
- decision queue 已能基于 normalized API、auth surface、auth contexts、authz-plan 做 evidence-driven 排序。
- 0/1/2 个 auth contexts 的 authorization gating 已初步完成。
- 两个 approved auth contexts + concrete read-only API example 时，队列可执行 business-compare。
- core/security 测试和 core/security/cli/server build 最近一次通过。
- Vulhub 5-case smoke matrix 最近一次 5/5 通过，但这只能证明 CVE proof 回归，不代表业务逻辑能力成熟。

下一步优先级：
1. 不要加新 CVE payload。
2. 先做本地多角色 Web 靶场或多角色 smoke harness，用来验证 IDOR/BOLA/BFLA/tenant isolation/workflow authz。
3. 靶场/smoke assertion 可以有靶场特定数据，但 agent 决策逻辑不允许硬编码靶场、CVE、路径或 payload。
4. 增强 authenticated context 注册/复用：cookieHeader、authorization header、storageState、role、tenant、username。
5. 增加 expected authorization policy 雏形；没有 policy 时 cross-role parity 只能 candidate/inconclusive，有 policy + evidence 时才能 validated。
6. 保持主动验证受 scope 和 approval 控制，默认 read-only。
7. 所有结论必须来自 evidence，secret-like 字符串必须脱敏。

开发时请先读相关代码：
- packages/shared/src/index.ts
- packages/core/src/security-browser.ts
- packages/security/src/js-analyzer.ts
- packages/security/src/api-inventory.ts
- packages/security/src/auth-surface.ts
- packages/core/src/web-pentest-control-plane.ts
- packages/security/src/decision-models.ts
- packages/core/src/security-execution.ts
- packages/core/src/security-business.ts
- packages/core/src/index.ts
- scripts/agent-lab-smoke.mjs
- scripts/agent-lab-smoke-cases.json

验证要求：
- 修改后至少跑 pnpm --filter @aegisprobe/security test
- 修改后至少跑 pnpm --filter @aegisprobe/core test
- 涉及入口/类型时跑 security/core/cli/server build
- 新增多角色能力必须有 smoke 或单元测试证明队列从 recon/API evidence -> authz-plan -> business-compare/blocked reason 的行为正确

不要回滚用户已有改动。工作区可能是 dirty 的，只修改和当前任务相关的文件。
```


