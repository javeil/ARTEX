# 工具执行边界

## 授权范围

PreToolUse 在可配置的拦截工具开关和 allow 规则之前验证目标。任务范围只读取本任务 `source=manual` 的网络范围及其人工关联公司的 company_scope；root_domain/domain 包含自身及点分隔的子域，subdomain 精确匹配，IP/CIDR 包含端口归一化并支持 IPv6。ICP、关键词、继承任务、自动发现及 agent 添加的范围仅用于覆盖度，不能作为网络授权。旧任务应在运行前由用户确认并通过范围 API 添加人工授权；空范围和读取失败均拒绝已知目标。

`add_task_scope` / `add_company_scope` 必须人工审批，不能用 allow 规则或工具开关绕过。agent 添加的 task_scope 不直接授予网络权限，用户须通过任务范围 API 确认。公司范围编辑审批通过后才执行，因此其网络权限变更是人工授权。

无法静态确定全部目标的 Bash、交互 Shell、MCP 调用默认 ask；数据库 setting `scope_unknown_target_action`（GET/PUT `/api/intercept/scope-config` 的 `unknown_target_action`）可选 ask/deny/allow。默认 ask 保留 Python、动态脚本及正常渗透工具的能力，同时要求人工确认不能静态证明的网络副作用；缺少审批存储或审批超时则拒绝。选择 allow 是管理员显式接受不透明调用风险，不能覆盖明确的域外目标或 HTTP 参数错误。

WebFetch 在实际 HTTP transport 上逐请求校验（包含每个重定向），不会对范围拒绝执行直连重试。本地保留 Norma v0.4.3 的 WebFetch 渲染实现，避免改依赖或丢失 Markdown/RECON 输出。Bash 的 curl 自动重定向（-L/--location）及默认跟随跳转的 wget 被拒绝，提示使用 WebFetch 或关闭重定向；配置文件、目标变量、输入文件、未知程序等走不透明调用审批。

这是一道执行前授权闸及 WebFetch 请求闸，不是操作系统网络沙箱。任意代码经人工批准或 unknown=allow 后可以产生静态检查无法穷举的连接；强制限制此类代码的每个数据包仍须部署容器/主机出口防火墙。域名授权信任该域名的 DNS 解析，不通过 DNS 结果给其他 IP/域名自动扩权。SQLi、XSS、密码喷洒、路径遍历、数据导出等能力维持现有策略。

## 核心不可逆破坏防护

六类内置规则有 `protected=true`，数据库方法禁止删除和完整编辑，防止改名或通过编辑接口绕过禁用审计。禁用接口要求原因，以当前单管理员认证身份 `ARTEX administrator` 记录 `intercept_rule_changes`（时间、规则 ID、状态、操作人、原因），状态变更与审计同事务提交。规则列表返回 `core_protection_disabled`，页面突出显示禁用状态。现有未开启规则不会被强制开启，已有同名核心规则迁移为 protected。

Guard 使用 Shell AST 对递归强制删除、系统目录删除、mkfs、dd 写设备、Fork 炸弹、关机重启做不依赖 DB 的检查，先于范围、规则、judge 执行。命中立即结束，不再重复跑 DB 拦截。删除/关闭全部 DB 规则或移除 Bash 的拦截工具配置都不会关闭此层。该层仅处理可识别的命令；任意代码和无法解释的构造仍由范围不透明调用策略及人工审批处理。

## 任务目录清理例外

仅对单条、静态、绝对路径的 `rm -rf` 提供例外，所有操作数必须是真实任务根目录的严格子路径；任务根目录本身也不能删除。任务根来自平台运行上下文 `<data>/tasks/<task_id>`（兼容默认 `/app/data/tasks/<task_id>`），不采信工具参数中的工作目录或变量。拒绝相对路径、任意 `..` 分量、符号链接、通配符、变量、复合脚本、重定向、无法访问/解析的目录。不存在的叶子仍检查现有祖先，不能用符号链接祖先逃逸。Guard 和内置递归删除规则共用这一个例外；其他用户规则仍可拒绝或审批。该检查是执行前快照，运行目录须由平台隔离，不能与不可信并发进程共享写权限。

## 全部调用审计

`tool_call_audit` 每次 PreToolUse 保存一行，包括未命中规则、未启用 judge、被移出拦截工具清单的调用。来源为 core/scope/rule/judge/default_allow，保存任务、工具、至多 2048 字符参数摘要、初始 decision 和 effective_action。ask 在等待人工前持久化，同一行在结束时更新；重启遗留的 pending 表示尚未记录最终决策，不能被误读为允许。取消不丢弃审计，写入有独立 2 秒上限，审计失败阻止执行并明确提示。

采用单次小型同步 INSERT（ask 才需 UPDATE），不使用可能在重启/满队列时静默丢失的异步队列或抽样。内存环只缓存运行时视图。按 task_id/id 索引及 keyset 游标查询，`GET /api/intercept/task/{taskID}/calls?limit=100&before_id=...`，每页最多 500 条，记录在任务删除后保留。保留周期应由部署方按审计要求制定；不在请求路径上全表清理。

SDK 的 ExecuteExtraTool 转发器会先解包再检查实际工具，避免直接 CoreTool.Call 跳过钩子。Monitor 视为 Shell；自定义 command/script 在模板渲染后重新过 Guard，自定义 HTTP 在渲染后过 Guard 且每跳 transport 复验。

## 目标行为控制补强（第二轮）

目标访问将 task_scope/company_scope、全局资产排除、任务 block/allow 规则合并判定。显式排除优先，规则读取失败拒绝访问；URL、协议和端口保留到检查阶段。GET/PUT `/api/tasks/{id}/target-policy` 管理用户确认的策略：targets 可按 host、schemes、ports、path_prefixes、excluded_path_prefixes 收窄既有人工范围。路径前缀按路径分量匹配，不把 /apiary 视作 /api 子路径。此 API 不向 agent 暴露为工具。

独立聊天的主动测试必须绑定授权任务。创建对话支持 task_id，也可通过 PUT `/api/conversations/{id}/authorization` 修改；运行中拒绝换绑。对话页提供授权任务选择器。无授权的对话仍可分析，但不能主动接触目标。绑定的任务暂停、结束或授权时间到期后，目标访问拒绝。

操作策略 mode 支持 standard/read_only/passive；denied_effects 是不可被普通 allow 规则或 judge 覆盖的任务限制。可信人工只读/被动约束会收窄 mode，其他人工 deny 原文与策略版本作为独立 trusted_task_policy 提供给 judge，agent 参数中的同名声明无效。明确改变业务数据的动作拒绝；副作用不明的写操作在标准模式进入 judge/人工审批，在只读模式拒绝。已知读取、查询、登录验证、SQLi/数据导出等正常技术不会因技术名称而被禁用。operations 可由用户为特定服务路径/方法声明 read/probe/authenticate/artifact_create，不能用泛化 read 声明隐藏参数中明确的业务破坏证据。

人工审批绑定本次参数、脚本快照摘要及授权快照版本，并有 5 分钟有效期。快照包含人工 scope、关联公司范围、排除/允许规则、操作策略、人工约束和任务状态；批准后重新读取并核验，变化或任务到期/暂停即拒绝执行。批准记录保存授权版本与调用摘要。审批并不授予下一次调用，也不授予域外访问权限。

每个授权 run 建立独立 HTTP(S) 目标网关，强制检查实际重定向、HTTPS 解密后的路径/方法和业务副作用，既不依赖抓包开关也不在拒绝后透传。Bash 的 curl/wget 固定网关并禁用外部客户端配置；禁止覆盖 proxy、目标映射和 --next。Python/Node 等遵守代理的客户端继承任务网关。浏览器 MCP 使用临时任务配置，将后续页面/脚本请求送入同一检查点。原生 WebFetch/自定义 HTTP 通过同一请求检查方法执行；对不提供实际连接可观测性的原始套接字/远端 Shell 不宣称 HTTP 网关能覆盖，它们仍需要明确目标参数与人工审查。

budget 可设置 requests_per_second、max_concurrent、max_requests、account_attempts/account_window_seconds、consecutive_failures、max_latency_ms、cooldown_seconds。0 表示该项未配置上限；部署者按许可与目标承载能力设置，不假设一个通用安全速率。真实 HTTP 请求在发送前通过 PostgreSQL 事务/服务锁预留额度：同一服务跨任务、worker 和实例共享 RPS、并发与账号窗口，累计请求按任务约束。账号范围/预算开启时，无法从真实请求中唯一确认账号则拒绝，不能凭 agent 自报绕过。

实际请求及完成状态保存在 target_requests，可用 GET `/api/tasks/{id}/target-requests` 游标分页。429 尊重 Retry-After，账号锁定和连续失败/首响应延迟超限对同一服务设置共享冷却；普通 403/WAF 不触发“靶机损坏”熔断。未结束记录保留为 running，重启不会把缺少完成证据的请求静默当作已结束。

暂停流程先发出任务取消并提交暂停，再撤销该任务的新目标访问，取消 HTTP/审批等待和相关 SDK run，等待请求完成记录及 Session/MCP 清理。只有在途数量归零才确认目标访问已停止，超时明确返回仍在停止，不能把发出 cancel 当作完成。授权时间窗/任务 deadline 也绑定到实际请求 context，取消已在执行的访问。GET `/api/tasks/{id}/target-control` 显示 blocked/stopping/active/stopped；显式恢复和冷却重置要求人工原因并记 target_control_events，普通 agent 工具不能修改这些状态。

测试资源账本只接受程序观察到的创建证据：用户声明的 artifact_create 路由实际返回 201 + Location 后登记关联请求 ID、精确资源 URL 和 ETag。GET `/api/tasks/{id}/test-resources` 可查询，agent 没有自报归属的写工具。自动清理还要求用户确认该端点支持 If-Match（cleanup_if_match=true）、强 ETag、当前策略仍授予清理，以及任务完全一致；执行时强制 If-Match。资源 URL 被其他对象复用时，条件不匹配会阻止删除。缺少身份条件时不自动清理；不能因为名字含 test 或 agent 声称拥有就降低真实业务对象的保护。已清理资源取消其删除权限，其他用户规则仍可拒绝。
