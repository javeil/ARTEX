package agent

// Kept verbatim so startup can replace only the prior code default, preserving
// an administrator's edited tool description and visibility settings.
const LegacyTaskScopeDescription = "把测试范围加入【本任务】——这是本任务的授权边界，也是资产测试覆盖度的分母。\n" +
	"kind 支持：company(整个公司名下资产) / root_domain(整个根域，含所有子域) / subdomain(单个精确子域) / ip / cidr / icp / keyword。\n" +
	"说明：worker 逐个碰到的主机会被系统【自动】加进范围(精确子域)；本工具用于【主动扩大】——把整个根域/整个公司纳入，或补充指定某子域/IP。\n" +
	"value：company 传公司名或 id(公司须已存在)；root_domain/subdomain 传域名；ip/cidr 传 IP 或网段；icp/keyword 传备案号或企业关键词。\n" +
	"务必给 reason 说明依据(可审计)。多条用 entries 数组。"

const TaskScopeDiscoveryDescription = "登记【本任务的发现范围与覆盖度】，始终记录为 agent 来源，不授予网络测试权限。\n" +
	"kind 支持 company/root_domain/subdomain/ip/cidr/icp/keyword；value 为对应公司名或 id、域名、IP、网段、备案或关键词。填写 reason 说明发现依据，多条使用 entries 数组。\n" +
	"平台提示缺少人工授权时，请用户在任务总览确认准确目标；重复登记、换 HTTP 工具或扩大到邻近 IP/整段 CIDR 都不能解除拦截。只能操作已人工授权的目标。"
