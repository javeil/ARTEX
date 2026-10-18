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

