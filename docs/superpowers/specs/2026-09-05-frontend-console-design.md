# 整改运营控制台前端 — 设计文档

日期：2026-09-05
状态：已与需求方逐节确认（定位、技术栈、认证、布局、详情页、后端端点、测试、交付）

## 1. 背景与目标

VulnOps Hub 后端 MVP（FastAPI 模块化单体）已实现 SBOM 摄取与整改工单
（case）生命周期，但无任何前端界面，日常运营（triage、分派、SLA 跟踪、
风险接受、复测关闭）只能靠 curl/Swagger。本设计为后端补一个**整改运营
控制台** Web 前端，让运营闭环可日常使用。

成功标准：

- 运营人员可以在浏览器里完成 case 的完整生命周期操作（列表 → 详情 →
  流转 → 风险接受 → 复测 → 关闭），无需使用 API 工具
- 所有页面使用真实后端数据，无 mock 数据
- 单容器部署形态不变（前端产物由 FastAPI 托管）

## 2. 范围

### 包含

- Vue 3 + Vite + TypeScript + Element Plus + Pinia + Vue Router 的 SPA
- 四个页面：工单看板、工单列表、工单详情、SBOM 提交
- 后端补齐 3 个只读端点（见 §6）
- OpenAPI 客户端代码生成、错误处理、加载/空态
- Vitest 组件/store 测试、Playwright 冒烟链路、CI 前端 job

### 不包含（本期明确不做）

- 登录/OIDC（后端 token 校验未启用；前端不做登录页，部署标注仅限内网/
  反代后使用。OIDC 启用后再补登录与 token 注入）
- SBOM/资产/情报的管理页面（本期只有 SBOM 提交页）
- 工单批量操作、自定义列、导出
- 移动端适配（桌面 1280+ 优先，不刻意做响应式断点）
- 多语言框架（文案中文先行，硬编码即可）

## 3. 关键决策

| 决策 | 选择 | 理由 |
| --- | --- | --- |
| 技术栈 | Vue 3 + TS + Element Plus | 领域参考项目（SecObserve/Dependency-Track/DefectDojo Pro）均为 Vue；Element Plus 高密度表格/表单契合 ops console |
| 认证 | MVP 无登录 | 后端 OIDC 仅配置占位；标注仅限内网 |
| 布局 | 左侧边栏 | 为未来模块（资产/情报）预留导航；Element Plus 经典形态 |
| API 客户端 | openapi-typescript 生成 | 后端接口变更编译期暴露；单一事实源是 openapi/openapi.yaml |
| 部署 | FastAPI StaticFiles 托管 dist | 单容器不变；Dockerfile 多阶段构建 |
| 包管理 | pnpm | 快、磁盘省 |

## 4. 架构

```
repo/
├── src/vulnops/            # 现有后端（补 3 个只读端点）
├── frontend/               # 新增 SPA
│   ├── src/
│   │   ├── api/            # 生成的类型 + fetch 封装（org 注入、错误归一化）
│   │   ├── stores/         # orgStore / casesStore / caseDetailStore
│   │   ├── views/          # Dashboard / CaseList / CaseDetail / SbomSubmit
│   │   ├── components/     # StatusStepper、SlaBadge、PriorityTag、CaseTable、…
│   │   └── router.ts
│   └── package.json
└── (FastAPI StaticFiles 挂载 frontend/dist，SPA fallback)
```

- 开发：`pnpm dev`（Vite :5173，proxy `/api`、`/health` 到 :8000）+ `make dev`
- 生产：`pnpm build` → `frontend/dist` → FastAPI 托管；`/` 与 `/api` 互不干扰
- 后端静态托管代码放 `src/vulnops/api/frontend.py`（仅当 dist 存在时挂载，
  开发模式无 dist 不报错）

## 5. 页面设计

### 5.1 全局框架

左侧固定边栏（LOGO、看板、工单、SBOM 提交；下方灰显未来模块"资产/情报"
作为 roadmap 提示）、顶栏（组织切换器 + 环境徽章 + 版本号）。当前组织存
localStorage（key: `vulnops.org`，默认 `org-demo`）——后端组织是自由路径
参数，无组织列表端点，切换器为输入+记忆。

### 5.2 工单看板 `/`

- 统计卡：open 工单数、SLA 已超时数、P0/P1 未关闭数、平均关闭时长
- 图表（ECharts）：优先级分布环形图、近 30 天 SLA 达成趋势线
- 数据：全部由列表端点聚合（客户端计算），后端本期不做 stats 端点

### 5.3 工单列表 `/cases`

- Element Plus 表格：case_key、标题、状态 Tag、优先级 Tag、owner_team、
  assignee、SLA（剩时/超时徽标）、版本
- 筛选栏：状态、优先级、owner_team、SLA 超时（下拉/开关），映射到 §6.1 查询参数
- 排序（due_at、priority）、分页（page_size 默认 20）
- 行点击进入详情页

### 5.4 工单详情 `/cases/:id`

- 头部：case_key、标题、优先级 Tag、SLA 徽标、版本号（`v{n}`）
- 状态步进条（StatusStepper）：按后端状态机顺序渲染当前进度
- 操作区：按钮**严格来自 `GET allowed-transitions`** 动态渲染；点击流转
  携带 `If-Match: "<version>"`；risk_accepted / not_applicable 打开对应
  表单抽屉（审批人、角色下拉 risk_approver/security_lead/policy_admin、
  补偿措施、evidence、过期时间）
- Tab：暴露面（现有 case.exposures）｜ 风险决策（§6.2）｜ 复测记录（§6.3）
- 右侧栏：本期展示 case 元数据（创建/更新时间、owner_team、assignee、
  policy_version、closure_reason）；审计时间线**本期不做**（后端无对应
  读取端点），布局预留位置，后续加端点即可接入
- 412 处理：弹窗"工单已被他人修改"→ 自动重拉详情并刷新按钮区

### 5.5 SBOM 提交 `/sboms`

- 文本域粘贴 / 文件上传 CycloneDX|SPDX JSON，前端不做格式校验（后端 422
  展示 Problem Details detail）
- 成功展示：sbom_id、content_sha256、幂等结果；携带 `Idempotency-Key`
  （uuid，重试复用）
- 下方展示提交历史（localStorage 本地记录，后端无列表端点）

## 6. 后端补齐端点（纯新增，向后兼容）

全部走现有 CaseService 与组织隔离语义（org 不匹配 → 404，同现有实现）。

### 6.1 `GET /api/v1/organizations/{org_id}/cases`

查询参数：`status`、`priority`、`owner_team`、`assignee`、
`sla_breached`（bool）、`page`（≥1）、`page_size`（1–100，默认 20）、
`sort`（`due_at`/`priority`/`created_at`，前缀 `-` 表示降序，默认
`-created_at`）。

响应（项目首个分页标准形状，后续列表端点沿用）：

```json
{"items": [/* 同现有 GET case 字段 */], "total": 42, "page": 1, "page_size": 20}
```

实现：SQLAlchemy select + where + count + offset/limit；不可信参数 → 422。

### 6.2 `GET /api/v1/organizations/{org_id}/cases/{case_id}/risk-decisions`

→ `{"items": [decision…]}`，按创建时间倒序。

### 6.3 `GET /api/v1/organizations/{org_id}/cases/{case_id}/verifications`

→ `{"items": [verification…]}`，按创建时间倒序。

## 7. 数据接入与状态管理

- **API 层**：`openapi-typescript` 生成类型；`api/client.ts` 轻量 fetch 封装：
  自动注入当前 org 路径、`If-Match`；把 Problem Details
  `{type,title,status,code,detail}` 归一化为 `ApiError`（含 code）
- **Stores（Pinia）**：
  - `orgStore`：当前 org、切换与持久化
  - `casesStore`：列表查询状态（筛选、分页、排序）+ 看板聚合值
  - `caseDetailStore`：当前 case、version、allowed-transitions、
    risk-decisions/verifications 历史、transition()/verify()/decide() 动作
- **错误处理**：ApiError → ElMessage（title+detail）；网络错误自动重试一次；
  412 特殊处理（见 §5.4）；列表空态与骨架屏
- **实时性**：MVP 用轮询（列表页 30s、详情页 15s 可见时轮询；页面不可见暂停），
  不引入 WebSocket

## 8. 测试策略

- **后端**：3 个新端点的 pytest 集成测试（筛选/分页边界、org 隔离 404、
  参数校验 422、排序）
- **前端单元**（Vitest + @vue/test-utils）：stores（筛选状态流、412 冲突
  分支）、StatusStepper（状态→步骤映射）、操作区组件（按 allowed-transitions
  渲染按钮）、Problem Details 错误归一化
- **E2E**（Playwright，CI 可选 job）：一条链路——创建 case → 列表可见 →
  详情流转 new→triage → 验证状态与版本号更新
- **静态检查**：ESLint + vue-tsc；后端 ruff/mypy 现状不变

## 9. 交付与 CI

- Makefile：`frontend-install` / `frontend-dev` / `frontend-build` /
  `frontend-test`；`make dev` 行为不变（纯后端）
- Dockerfile：多阶段 —— node 构建 dist → python 运行镜像 COPY dist；
  docker-compose 无需新服务
- CI（.github/workflows/ci.yml）新增 `frontend` job：
  `pnpm install --frozen-lockfile` → lint → type-check → test → build；
  E2E job 手动触发/可选
- README：Quick start 增加"带前端"运行方式与截图占位

## 10. 里程碑

| 里程碑 | 内容 | 验收 |
| --- | --- | --- |
| M1 | 后端 3 个只读端点 + pytest | 测试绿；curl 可分页/筛选 |
| M2 | 前端骨架 + 工单列表 + 工单详情（流转/风险/复测） | 浏览器完成完整生命周期 |
| M3 | 看板（统计卡+图表）+ SBOM 提交页 | 看板数字与列表一致 |
| M4 | 打磨（空态/骨架屏/412 流）+ Playwright + CI/交付 + README | CI 全绿；单容器可跑 |
