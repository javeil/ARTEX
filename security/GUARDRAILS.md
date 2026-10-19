# 工具执行边界

## 授权范围

PreToolUse 在可配置的拦截工具开关和 allow 规则之前验证目标。任务范围只读取本任务 `source=manual` 的网络范围及其人工关联公司的 company_scope；root_domain/domain 包含自身及点分隔的子域，subdomain 精确匹配，IP/CIDR 包含端口归一化并支持 IPv6。ICP、关键词、继承任务、自动发现及 agent 添加的范围仅用于覆盖度，不能作为网络授权。旧任务应在运行前由用户确认并通过范围 API 添加人工授权；空范围和读取失败均拒绝已知目标。

`add_task_scope` 只登记 agent 来源的发现与覆盖度，不改变网络授权，通常不需要范围审批；仍经过工具权限、用户规则与持久化审计。工具结果明确 registration_only，不能因模型传入 source=manual 就提升来源。`add_company_scope` 涉及全局企业归属，仍须人工审批。agent 添加的 task_scope 不直接授予网络权限，用户须通过任务范围 API 确认。agent 新增的公司范围记录 source=agent，只参与资产归属；即使工具审批通过也不自动成为网络授权。用户在公司范围 API 再次提交相同条目才能提升为 manual。公司范围列表返回 source。历史公司范围缺少来源，迁移保留 manual 兼容；升级后应人工复核，不宣称能还原旧数据是谁录入的。

无法静态确定全部目标的 Bash、交互 Shell、MCP 调用默认 ask；数据库 setting `scope_unknown_target_action`（GET/PUT `/api/intercept/scope-config` 的 `unknown_target_action`）可选 ask/deny/allow。默认 ask 保留 Python、动态脚本及正常渗透工具的能力，同时要求人工确认不能静态证明的网络副作用；缺少审批存储或审批超时则拒绝。选择 allow 是管理员显式接受不透明调用风险，不能覆盖明确的域外目标或 HTTP 参数错误。

WebFetch 在实际 HTTP transport 上逐请求校验（包含每个重定向），不会对范围拒绝执行直连重试。本地保留 Norma v0.4.3 的 WebFetch 渲染实现，避免改依赖或丢失 Markdown/RECON 输出。未绑定目标网关的 Bash 自动跟随跳转被拒绝；绑定网关后 curl/wget 每一跳在实际请求层复验，并固定可信客户端路径、关闭客户端配置，拒绝代理/目标映射等覆盖参数。

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

操作策略 mode 支持 standard/read_only/passive；denied_effects 是不可被普通 allow 规则或 judge 覆盖的任务限制。可信人工只读/被动约束会收窄 mode，所有人工 deny 原文与策略版本作为独立 trusted_task_policy 提供给 judge，agent 参数中的同名声明无效。任意自然语言限制无法可靠自动编译；因此新增/修改人工 deny 后先拒绝主动访问，必须由用户在面板将其落实为结构化服务边界、接口用途、账号或预算并逐条确认。确认以约束 ID + 文本 SHA-256 绑定，文本改动即失效。此确认是用户对配置落实的声明，系统不能从任意自然语言证明配置完备。明确只读/被动/禁止登录等识别结果仍进一步收窄策略，确认不会取消这些限制。明确改变业务数据的动作拒绝；副作用不明的写操作在标准模式进入 judge/人工审批，在只读模式拒绝。已知读取、查询、登录验证、SQLi/数据导出等正常技术不会因技术名称而被禁用。operations 可由用户为特定服务路径/方法声明 read/probe/authenticate/artifact_create，不能用泛化 read 声明隐藏参数中明确的业务破坏证据。

人工审批绑定本次参数、脚本快照摘要及授权快照版本，并有 5 分钟有效期。快照包含人工 scope、关联公司范围、排除/允许规则、操作策略、人工约束和任务状态；批准后重新读取并核验，变化或任务到期/暂停即拒绝执行。批准记录保存授权版本与调用摘要。审批并不授予下一次调用，也不授予域外访问权限。

每个授权 run 建立独立 HTTP(S) 目标网关，强制检查实际重定向、HTTPS 解密后的路径/方法和业务副作用，既不依赖抓包开关也不在拒绝后透传。Bash 的 curl/wget 固定网关并禁用外部客户端配置；禁止覆盖 proxy、目标映射和 --next。Python/Node 等遵守代理的客户端继承任务网关。浏览器 MCP 使用临时任务配置，将后续页面/脚本请求送入同一检查点。原生 WebFetch/自定义 HTTP 通过同一请求检查方法执行；TargetHTTP 支持任意 HTTP 方法、头和载荷，大响应完整流式写入任务产物并提供 SHA-256，不截断数据库导出。只要启用账号范围/请求预算，就拒绝无法逐请求观测的原始套接字、扫描脚本及远端 Shell；服务/只读等严格策略也不能用不透明调用审批豁免。可识别的 nmap/nc 参数保留 TCP/UDP 端口及 CIDR；未指定的端口不符合端口限定，NSE/外部配置等归为不透明调用。标准、仅主机范围且未设预算的任务仍保留可配置的不透明调用审批；不宣称这是任意代码的逐包强制边界。

budget 可设置 requests_per_second、max_concurrent、max_requests、account_attempts/account_window_seconds、consecutive_failures、max_latency_ms、cooldown_seconds。0 表示该项未配置上限；部署者按许可与目标承载能力设置，不假设一个通用安全速率。真实 HTTP 请求在发送前通过 PostgreSQL 事务/服务锁预留额度：同一 scheme + host + port 服务键跨任务、worker 和实例共享 RPS、并发与账号窗口（同机不同域名不自动合并），累计请求按任务约束。账号范围/预算开启时，实际 Basic/表单/JSON/GET 登录请求无法唯一确认账号、Authorization 头重复、存在重复 JSON 身份键、参数值冲突或超出检查上限时拒绝；账号限制下不透明 Bearer/Digest 凭据也不能靠 body 自报用户名放行；未知写操作需先由用户声明接口用途。不能凭 agent 自报绕过。对自定义登录协议应配置 authenticate + account_field；此处限定可识别登录尝试的账号，不声称能验证任意 Cookie/外部 token 已属于谁，未知身份协议需要适配。

实际请求及完成状态保存在 target_requests，可用 GET `/api/tasks/{id}/target-requests` 游标分页。429 尊重 Retry-After，账号锁定和连续失败/首响应延迟超限对同一服务设置共享冷却；普通 403/WAF 不触发“靶机损坏”熔断。未结束记录保留为 running，重启不会把缺少完成证据的请求静默当作已结束。

暂停流程先发出任务取消并提交暂停，再撤销该任务的新目标访问，取消 HTTP/审批等待和相关 SDK run，等待请求完成记录及 Session/MCP 清理。只有在途数量归零才确认目标访问已停止，超时明确返回仍在停止，不能把发出 cancel 当作完成。授权时间窗/任务 deadline 也绑定到实际请求 context，取消已在执行的访问。GET `/api/tasks/{id}/target-control` 显示 blocked/stopping/active/stopped；显式恢复和冷却重置要求人工原因并记 target_control_events，普通 agent 工具不能修改这些状态。

测试资源账本只接受程序观察到的创建证据：用户声明的 artifact_create 路由实际返回 201 + Location 后登记关联请求 ID、精确资源 URL 和 ETag。GET `/api/tasks/{id}/test-resources` 可查询，agent 没有自报归属的写工具。自动清理还要求用户确认该端点支持 If-Match（cleanup_if_match=true）、强 ETag、当前策略仍授予清理，以及任务完全一致；执行时强制 If-Match。资源 URL 被其他对象复用时，条件不匹配会阻止删除。缺少身份条件时不自动清理；不能因为名字含 test 或 agent 声称拥有就降低真实业务对象的保护。已清理资源取消其删除权限，其他用户规则仍可拒绝。

## 操作入口和迁移

任务总览的“目标行为控制”面板提供模式、时间窗、服务/路径、接口用途、账号集合、预算、人工约束确认、真实请求与测试资源记录、人工恢复/解冷却。刷新失败明确显示状态不可确认，不继续展示“已停止”的旧结论。保存策略、修改人工约束/任务排除/公司范围/全局规则会取消当前实例在途工作；每次新 HTTP 请求仍从数据库读取授权。多实例的预算/冷却共用 PostgreSQL，但停止/在途取消目前限于持有 run 的进程；不要把另一个无共享运行时的实例返回的 active=0 当作全实例已经停手。

新表自动创建，无需清空原有数据。旧任务无 policy 行时采用 standard、无附加服务限制/预算；已有显式 judge 失败策略不覆盖。独立对话原来没有授权绑定的，升级后主动测试需要先在对话页绑定任务。旧 company_scope 保留来源兼容，新增 agent 发现不再授权；旧人工 deny 没有确认摘要时主动测试先停下，需落实配置并确认。新增审计表无自动清空，target_requests 中重启遗留 running 记录不自动释放并发名额，应结合目标实际状态人工核对。

参考 `security/TARGET_POLICY_EXAMPLE.json`。其中数值仅演示格式，必须按本次测试许可和目标容量调整。policy.targets 只能收窄已经人工授权的 task_scope，不能单独赋予网络权限。未知业务效果不是“目标防御”，返回的 ARTEX 目标管控消息说明拒绝原因。

Playwright 配置使用官方支持的 browser.launchOptions.proxy / browser.contextOptions.proxy，清除更高优先级的代理环境覆盖，拒绝无法应用任务代理的外接 CDP/extension 浏览器；参考 [官方配置结构](https://playwright.dev/mcp/configuration/options)。浏览器能否加载被测页面所依赖的第三方域名取决于这些域名是否明确获授权，不自动把 CDN、回调/OAST 域或跳转域加入范围。

业务效果检查依靠可识别的方法、路径、参数与用户声明的接口用途；它不是目标业务语义的形式证明。存在改变状态的 GET、自定义认证、异步任务等接口时，用户必须配置明确排除/用途，不能仅因 mode=read_only 就假定目标绝无状态变化。平台停止也不能撤回目标端已经接收的异步作业。


## 第二轮审计修复与可验证边界（2026-10-19）

MainAgent、Planner、目标拆解和 Worker 的 session 工厂统一挂 Guard；已有自定义钩子保留，避免双重审批。`WithRunInfo` 原本已经传播 task ID，修复重点是缺失的钩子，不把它描述成所有入口都丢失任务 ID。任务 ID 参数与上下文不一致时拒绝执行。带任务的审批（包括本地 Read/Write）都绑定授权版本；任务状态有递增 epoch，policy 版本也参与绑定，暂停恢复或策略改回旧值仍会使审批失效。

HTTP 命令只有完整静态、可检查的 argv 才能被认作可观测调用；拒绝代理/配置覆盖、curl 多 transfer 边界和动态参数。错误由平台明确说明。常见数据/载荷参数本身允许，`-x` 开头的 POST 数据不会被当成代理参数。未支持的 CLI 选项请使用 TargetHTTP；包装命令、任意解释器和第三方网络工具不是逐请求可观测适配。它们在有服务/路径/时间/模式/预算等严格限制时拒绝，在标准任务里仍受 unknown=ask/deny/显式 allow 的选择影响。人工批准一个任意程序是接受不透明副作用，不能证明其隐藏的 socket 绝不越界；本次不把容器或宿主机配置描述为已经提供了该证明。

shell_send 的 text、paste、hex 共同参与核心命令与显式目标检查，终端编辑/历史状态仍不透明。严格任务拒绝交互输入，不能用审批豁免预算。Monitor 引用文件参与审批内容哈希；同时补充 SDK Monitor 未使用 tc.Env 时的代理环境注入。脚本快照约束审批到执行前的内容，不能代替不可变文件系统或防御已获主机任意写权限的人并发篡改依赖。

enrich 的旧无上下文 API 不再联网，新 ForTask API 需要宿主机任务上下文，并在入队时持有可取消活动租约。HTTP 走同一 TargetRoundTrip，停止等待活动清理；DNS 记录逻辑 lookup 审计。在账号/请求预算下无法准确计数 resolver 的每次重试数据包，因此自动 DNS 任务拒绝，要求选择适配工具。当前 insert_assets 没有实际调用这套旧 Engine，不重新启用资产发现后的隐式探测。

存在路径限制时同时核对原始、解码、点段和反斜杠归一化解释；任一解释超出授权或落入排除即拒绝。没有路径限制时不新增全局编码/路径遍历禁令。直连 HTTP 在拨号时解析一次，校验用户明确设置的 IP/CIDR 排除后连接数值地址，保留 Host/SNI；每次请求使用独立 transport，减少跨授权复用，但会增加 DNS/TLS 和连接开销。使用不透明代理且存在域名的 IP 排除时无法固定代理实际解析地址，拒绝，要求直连 TargetHTTP 或明确 IP 目标；不偷偷降级。未额外禁止所有内网/元数据地址，因为这些可能就是获授权的渗透目标，仍须用户正确设置范围和排除。

实际 Host 虚拟主机和 URL 连接目标都要授权，可以继续测试已授权的虚拟主机。请求体检查上限仍为 1 MiB，响应导出不受此检查上限约束；multipart 字段保留重复值，账号冲突拒绝。Cookie/不透明 Authorization 无法映射到唯一账号时，有账号集合或账号预算的任务拒绝该请求；未虚构任意会话 Cookie 到真实账号的可靠映射。nmap 重复端口按所有出现项保守检查，nc -u 使用 UDP 身份；这是解析器回归，不宣称证明了 nmap 实际接受重复 -p 并发送报文。

归档加入 task_target_policies、task_intercept_rules，恢复后 `restore_review_required=true`，即使旧包缺失策略也先拒绝主动访问。恢复界面提示核对；用户在 PUT target-policy 保存确认时原子清除标记并记审计。现有恢复接口不是任意跨库导入功能，修复的是包本身不再丢失授权条件或立即重新授予主动访问权。

判定器配置以一次选定键查询读取，数据库失败与成功读取到 enabled=false 分开：前者 ask/超时 deny。配置多键以一个事务提交。模型实际调用失败仍尊重已有显式 fail_action；升级不强制覆盖 allow。审批等待每 250ms 只查询状态/有效动作，跨实例 decide 不再依赖本进程通知；pending 数量越大，轮询读取量越大。跨实例即时停止和严格线性化撤销仍不由此保证；运行时取消由持有工作进程的实例负责，发送前复验减少竞态，但不能撤回目标已接收的请求或异步作业。

Playwright 适配只接受主机 PATH 解析的可信启动器及直接官方包参数，不再靠任意参数包含包名认定。拒绝脚本启动器、文件/npm 别名、外接 CDP/extension、自定义浏览器执行文件和覆盖代理的启动参数。清除 Node hook 与相关代理环境覆盖。其前提仍是主机安装与批准的 MCP 包可信；配置回归不能等同于已实机验证每种 Chromium/WebRTC/扩展出站路径。平台 create/update MCP 或自定义工具定义固定要求人工审批，不能依赖工具开关或 allow 规则跳过。

### 崩溃遗留请求核对

不按时间自动把 running 视为已结束，因为目标端可能仍在处理。管理员先暂停任务、停止持有 run 的实例并等待清理，人工核实远端作业停止（多实例需核实所有工作实例），再调用 `POST /api/tasks/{id}/target-control/reconcile`：

```json
{"request_ids":[123],"confirmed_remote_stopped":true,"reason":"已核实进程与目标端作业停止；记录故障工单/证据"}
```

接口仅处理本任务明确选定的 1..100 条 running 记录，要求本实例停止状态、任务暂停和原因；事务将其标为 reconciled 并逐条写 target_control_events。结果未知不伪装成成功，累计请求/账号尝试计数保留，不解除目标冷却、不恢复任务。它是可信管理员的核对操作，不授予 agent 自动清扫权限，也不能把另一台实例 active=0 当作所有远端已停止的证明。


## 减少无效审批（任务日志反馈修复）

发现登记、人工授权与实际联网分别处理。人工在任务范围 API 确认已经存在的 auto/agent 条目时，现在按完整键只提升该条为 manual，并在同一数据库语句写 authorize_scope 审计；不再被 ON CONFLICT 静默忽略。agent/auto 重复登记不能覆盖人工授权，确认单 IP 不会提升旁边的 CIDR。已有人工作用的重复确认保持幂等。任务总览区分发现/人工来源，并给本任务的精确主机提供确认按钮；广泛网段或整根域仍需用户在表单明确输入，不自动授权。

模型侧 add_task_scope 的旧说明错误地把发现登记描述为扩大授权，现已纠正并返回 registration_only/network_authorization_changed=false。升级只替换之前的代码默认说明，保留自定义说明、工具开关及角色绑定。登记发现不再产生一个无法真正授权的范围审批；访问已知域外目标、不可逆命令、严格策略不可观测执行仍按原有门槛拒绝。

traffic_search/get/blob 的 host、URL 仅为已有记录的查询条件，不是新网络目标。这三个内置工具跳过网络范围门，保留原工具权限、用户规则和审计；不会给 WebFetch、TargetHTTP 或外部 MCP 同名后缀免检。只读本地 sed 仅静态 p/数字行范围，不允许 -i/-f、e/w 或动态程序借用例外，选项放在文件名之后也检查。echo/printf 与已验证只读 sed 中的 URL/IP 可作为数据；混入网络调用或未知程序/管道执行时仍将这些字面量纳入目标检查。显式路径的同名自制二进制不能冒充主机本地工具。

对不透明调用，补充提取常见 Python literal create_connection/connect 与 /dev/tcp、/dev/udp 目的地；明确的域外地址先拒绝，不能靠先人工批准整个未知脚本豁免。没有推断变量值或执行脚本来找目标，无法证明的程序仍受原有 ask/严格策略 deny，不使用全局 unknown=allow 来减少提醒。

对于已绑定目标网关的 HTTP 命令，已知无法执行的动态/代理覆盖参数在请求审批前先校验，直接给出原因，避免用户批准后又被同一硬闸拒绝；不放宽 CLI 参数或网关要求。
