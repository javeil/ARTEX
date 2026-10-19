"use client";

import * as React from "react";

import { toast } from "sonner";

import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { api } from "@/lib/api";
import type { TargetControlState, TargetPolicy, TargetRequestRecord, TargetTestResource } from "@/lib/types";

let rowSequence = 0;
const newRowKey = () => `target-row-${++rowSequence}`;

const split = (s: string) =>
  s
    .split(/[\n,]/)
    .map((s) => s.trim())
    .filter(Boolean);
const budgetLabels: [keyof TargetPolicy["budget"], string][] = [
  ["requests_per_second", "每秒目标请求上限"],
  ["max_concurrent", "目标并发请求上限"],
  ["max_requests", "本任务累计请求上限"],
  ["account_attempts", "每账号尝试上限"],
  ["account_window_seconds", "账号计数窗口（秒）"],
  ["consecutive_failures", "连续失败熔断次数"],
  ["max_latency_ms", "首响应延迟上限（毫秒）"],
  ["cooldown_seconds", "熔断冷却（秒）"],
];
function Field({ label, children }: { label: string; children: React.ReactElement<{ id?: string }> }) {
  const id = React.useId();
  return (
    <div className="flex min-w-0 flex-col gap-1 text-xs">
      <label htmlFor={id} className="text-muted-foreground">
        {label}
      </label>
      {React.cloneElement(children, { id })}
    </div>
  );
}
export function TargetControlPanel({ taskId }: { taskId: string }) {
  const [targetKeys, setTargetKeys] = React.useState<string[]>([]);
  const [operationKeys, setOperationKeys] = React.useState<string[]>([]);
  const [taskPaused, setTaskPaused] = React.useState(false);
  const [monitorError, setMonitorError] = React.useState("");
  const [effectiveMode, setEffectiveMode] = React.useState("");
  const [policy, setPolicy] = React.useState<TargetPolicy | null>(null);
  const [constraints, setConstraints] = React.useState<{ id: number; text: string; digest: string }[]>([]);
  const [version, setVersion] = React.useState("");
  const [state, setState] = React.useState<TargetControlState | null>(null);
  const [requests, setRequests] = React.useState<TargetRequestRecord[]>([]);
  const [resources, setResources] = React.useState<TargetTestResource[]>([]);
  const [saving, setSaving] = React.useState(false);
  const [error, setError] = React.useState("");
  const [reason, setReason] = React.useState("");
  const [cooldownTarget, setCooldownTarget] = React.useState("");
  React.useEffect(() => {
    let live = true;
    setPolicy(null);
    setError("");
    api
      .targetPolicy(taskId)
      .then((r) => {
        if (live) {
          setPolicy(r.policy);
          setTargetKeys((r.policy.targets ?? []).map(() => newRowKey()));
          setOperationKeys((r.policy.operations ?? []).map(() => newRowKey()));
          setEffectiveMode(r.effective_policy?.mode ?? r.policy.mode);
          setVersion(r.authorization_version);
          setConstraints(r.unconfirmed_constraints ?? []);
        }
      })
      .catch((e) => {
        if (live) setError((e as Error).message);
      });
    const refresh = async () => {
      const result = await Promise.allSettled([
        api.targetControl(taskId),
        api.targetRequests(taskId),
        api.targetResources(taskId),
      ]);
      if (!live) return;
      if (result[0].status === "fulfilled") {
        setState(result[0].value.target_io);
        setTaskPaused(result[0].value.task_paused);
      } else setState(null);
      setMonitorError(
        result.some((r) => r.status === "rejected") ? "目标执行状态或记录刷新失败，请勿据旧状态判断已停止" : "",
      );
      if (result[1].status === "fulfilled") setRequests(result[1].value.requests);
      if (result[2].status === "fulfilled") setResources(result[2].value.resources);
    };
    void refresh();
    const timer = setInterval(refresh, 5000);
    return () => {
      live = false;
      clearInterval(timer);
    };
  }, [taskId]);
  const update = (patch: Partial<TargetPolicy>) => setPolicy((p) => (p ? { ...p, ...patch } : p));
  async function save() {
    if (!policy || saving) return;
    setSaving(true);
    try {
      for (const n of Object.values(policy.budget))
        if (n !== undefined && (!Number.isSafeInteger(n) || n < 0)) throw new Error("预算必须是非负整数");
      const r = await api.saveTargetPolicy(taskId, policy);
      setPolicy(r.policy);
      setEffectiveMode(r.effective_policy?.mode ?? r.policy.mode);
      setVersion(r.authorization_version);
      setConstraints(r.unconfirmed_constraints ?? []);
      toast.success("目标策略已保存，旧审批失效，在途访问已取消");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setSaving(false);
    }
  }
  async function control(action: "resume" | "cooldown") {
    if (!reason.trim()) {
      toast.error("请填写操作原因");
      return;
    }
    try {
      if (action === "resume") await api.resumeTargetAccess(taskId, reason);
      else await api.resetTargetCooldown(taskId, cooldownTarget, reason);
      const r = await api.targetControl(taskId);
      setState(r.target_io);
      toast.success("操作已记录审计");
    } catch (e) {
      toast.error((e as Error).message);
    }
  }
  let status = "读取状态中";
  if (monitorError) status = "执行状态不可确认";
  else if (state?.stopping) status = "正在停止访问，尚未确认结束";
  else if (state?.stopped) status = "已停止访问目标";
  else if (taskPaused) status = "任务已暂停，新目标访问已禁止";
  else if (state?.blocked) status = "新访问已禁止";
  else if (state) status = "按任务授权和预算执行";
  return (
    <Card>
      <CardHeader>
        <CardTitle>目标行为控制</CardTitle>
        <CardDescription>
          限定测试范围、业务副作用、请求强度和停手条件。SQLi、XSS、密码喷洒、路径遍历及数据导出能力保留。
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="rounded-md border p-3 text-sm">
          {status}
          {state && <span className="ml-2 text-xs text-muted-foreground">未结束执行/请求：{state.active}</span>}
        </div>
        {monitorError && <p className="text-destructive text-sm">{monitorError}</p>}
        {error && <p className="text-sm text-destructive">{error}</p>}
        {policy?.restore_review_required && <p className="text-destructive text-sm">此任务由归档恢复，主动访问已阻止。请核对授权范围、排除规则与预算，再保存用户确认的策略。</p>}
        {policy && (
          <details>
            <summary className="cursor-pointer text-sm font-medium">编辑本任务授权策略</summary>
            <div className="mt-3 space-y-4">
              {constraints.length > 0 && (
                <div className="space-y-2 rounded-md border border-destructive/40 p-3 text-xs">
                  <p>人工禁止条件尚未确认落实，主动测试已阻止。核对下方服务边界、操作用途和预算后逐条确认。</p>
                  {constraints.map((c) => (
                    <label key={c.id} className="flex items-start gap-2">
                      <input
                        type="checkbox"
                        checked={policy.constraint_acknowledgements?.[String(c.id)] === c.digest}
                        onChange={(e) => {
                          const ack = { ...policy.constraint_acknowledgements };
                          if (e.target.checked) ack[String(c.id)] = c.digest;
                          else delete ack[String(c.id)];
                          update({ constraint_acknowledgements: ack });
                        }}
                      />
                      已在可执行配置中落实：{c.text}
                    </label>
                  ))}
                </div>
              )}
              <p className="text-muted-foreground text-xs">
                当前生效模式：{effectiveMode || "standard"}。人工只读、被动、禁止登录等明确约束会进一步收窄以下配置。
              </p>
              <Field label="允许的测试方式">
                <select
                  className="rounded-md border bg-background p-2"
                  value={policy.mode}
                  onChange={(e) => update({ mode: e.target.value as TargetPolicy["mode"] })}
                >
                  <option value="standard">正常授权测试：明确业务破坏拒绝，未知写效果审批</option>
                  <option value="read_only">只读验证：不允许无法确认效果的写操作</option>
                  <option value="passive">被动分析：不主动访问目标</option>
                </select>
              </Field>
              <div className="grid gap-3 sm:grid-cols-2">
                <label className="flex items-center gap-2 text-xs">
                  <input
                    type="checkbox"
                    checked={policy.denied_effects?.includes("authenticate") ?? false}
                    onChange={(e) =>
                      update({
                        denied_effects: e.target.checked
                          ? [...(policy.denied_effects ?? []).filter((v) => v !== "authenticate"), "authenticate"]
                          : policy.denied_effects?.filter((v) => v !== "authenticate"),
                      })
                    }
                  />
                  本任务禁止登录 / 口令尝试
                </label>
                <Field label="授权开始（本地时间，可空）">
                  <Input
                    type="datetime-local"
                    value={policy.starts_at ? localDate(policy.starts_at) : ""}
                    onChange={(e) =>
                      update({ starts_at: e.target.value ? new Date(e.target.value).toISOString() : null })
                    }
                  />
                </Field>
                <Field label="授权结束（到期停止访问，可空）">
                  <Input
                    type="datetime-local"
                    value={policy.expires_at ? localDate(policy.expires_at) : ""}
                    onChange={(e) =>
                      update({ expires_at: e.target.value ? new Date(e.target.value).toISOString() : null })
                    }
                  />
                </Field>
              </div>
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">
                  以下服务限制收窄已有人工测试范围；留空沿用人工主机范围。任务排除规则始终优先。
                </p>
                {(policy.targets ?? []).map((target, i) => (
                  <div key={targetKeys[i]} className="grid gap-2 rounded-md border p-3 sm:grid-cols-2">
                    <Field label="域名 / IP / CIDR">
                      <Input
                        value={target.host}
                        onChange={(e) =>
                          update({
                            targets: policy.targets?.map((t, j) => (j === i ? { ...t, host: e.target.value } : t)),
                          })
                        }
                      />
                    </Field>
                    <Field label="协议，逗号分隔（http / https / tcp / udp）">
                      <Input
                        defaultValue={target.schemes?.join(",") ?? ""}
                        onBlur={(e) =>
                          update({
                            targets: policy.targets?.map((t, j) =>
                              j === i ? { ...t, schemes: split(e.target.value) } : t,
                            ),
                          })
                        }
                      />
                    </Field>
                    <Field label="端口，逗号分隔">
                      <Input
                        defaultValue={target.ports?.join(",") ?? ""}
                        onBlur={(e) =>
                          update({
                            targets: policy.targets?.map((t, j) =>
                              j === i ? { ...t, ports: split(e.target.value).map(Number) } : t,
                            ),
                          })
                        }
                      />
                    </Field>
                    <label className="flex items-center gap-2 text-xs">
                      <input
                        type="checkbox"
                        checked={target.include_subdomains ?? false}
                        onChange={(e) =>
                          update({
                            targets: policy.targets?.map((t, j) =>
                              j === i ? { ...t, include_subdomains: e.target.checked } : t,
                            ),
                          })
                        }
                      />
                      包含子域名
                    </label>
                    <Field label="允许的路径前缀，逗号或换行分隔">
                      <Input
                        defaultValue={target.path_prefixes?.join(",") ?? ""}
                        onBlur={(e) =>
                          update({
                            targets: policy.targets?.map((t, j) =>
                              j === i ? { ...t, path_prefixes: split(e.target.value) } : t,
                            ),
                          })
                        }
                      />
                    </Field>
                    <Field label="禁止的路径前缀">
                      <Input
                        defaultValue={target.excluded_path_prefixes?.join(",") ?? ""}
                        onBlur={(e) =>
                          update({
                            targets: policy.targets?.map((t, j) =>
                              j === i ? { ...t, excluded_path_prefixes: split(e.target.value) } : t,
                            ),
                          })
                        }
                      />
                    </Field>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setTargetKeys((keys) => keys.filter((_, j) => j !== i));
                        update({ targets: policy.targets?.filter((_, j) => j !== i) });
                      }}
                    >
                      移除此服务限制
                    </Button>
                  </div>
                ))}
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setTargetKeys((keys) => [...keys, newRowKey()]);
                    update({ targets: [...(policy.targets ?? []), { host: "", ports: [], schemes: [] }] });
                  }}
                >
                  添加服务限制
                </Button>
              </div>
              <div className="space-y-2">
                <p className="text-xs text-muted-foreground">
                  用户确认的接口用途：只对指定目标、路径、方法生效。明确的业务破坏不会被“探测”声明覆盖。
                </p>
                {(policy.operations ?? []).map((op, i) => (
                  <div key={operationKeys[i]} className="grid gap-2 rounded-md border p-3 sm:grid-cols-2">
                    <Field label="接口主机">
                      <Input
                        value={op.target.host}
                        onChange={(e) =>
                          update({
                            operations: policy.operations?.map((o, j) =>
                              j === i ? { ...o, target: { ...o.target, host: e.target.value } } : o,
                            ),
                          })
                        }
                      />
                    </Field>
                    <Field label="接口路径前缀">
                      <Input
                        defaultValue={op.target.path_prefixes?.join(",") ?? ""}
                        onBlur={(e) =>
                          update({
                            operations: policy.operations?.map((o, j) =>
                              j === i ? { ...o, target: { ...o.target, path_prefixes: split(e.target.value) } } : o,
                            ),
                          })
                        }
                      />
                    </Field>
                    <Field label="HTTP 方法，逗号分隔">
                      <Input
                        defaultValue={op.methods.join(",")}
                        onBlur={(e) =>
                          update({
                            operations: policy.operations?.map((o, j) =>
                              j === i ? { ...o, methods: split(e.target.value).map((m) => m.toUpperCase()) } : o,
                            ),
                          })
                        }
                      />
                    </Field>
                    <Field label="已确认用途">
                      <select
                        className="rounded-md border bg-background p-2"
                        value={op.effect}
                        onChange={(e) =>
                          update({
                            operations: policy.operations?.map((o, j) =>
                              j === i ? { ...o, effect: e.target.value } : o,
                            ),
                          })
                        }
                      >
                        <option value="read">读取 / 查询</option>
                        <option value="probe">漏洞探测 / 利用验证</option>
                        <option value="authenticate">登录尝试</option>
                        <option value="artifact_create">创建本次测试产物</option>
                      </select>
                    </Field>
                    <Field label="登录账号字段（可空，支持点分隔嵌套字段）">
                      <Input
                        value={op.account_field ?? ""}
                        onChange={(e) =>
                          update({
                            operations: policy.operations?.map((o, j) =>
                              j === i ? { ...o, account_field: e.target.value } : o,
                            ),
                          })
                        }
                      />
                    </Field>
                    <label className="flex items-center gap-2 text-xs">
                      <input
                        type="checkbox"
                        checked={op.cleanup_if_match ?? false}
                        onChange={(e) =>
                          update({
                            operations: policy.operations?.map((o, j) =>
                              j === i ? { ...o, cleanup_if_match: e.target.checked } : o,
                            ),
                          })
                        }
                      />
                      已确认创建接口提供强 ETag，且清理接口支持 If-Match
                    </label>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        setOperationKeys((keys) => keys.filter((_, j) => j !== i));
                        update({ operations: policy.operations?.filter((_, j) => j !== i) });
                      }}
                    >
                      移除此接口用途
                    </Button>
                  </div>
                ))}
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => {
                    setOperationKeys((keys) => [...keys, newRowKey()]);
                    update({
                      operations: [
                        ...(policy.operations ?? []),
                        { target: { host: "" }, methods: ["POST"], effect: "probe" },
                      ],
                    });
                  }}
                >
                  添加已确认接口
                </Button>
              </div>
              <Field label="允许尝试的账号（逗号或换行分隔，留空不限定集合）">
                <textarea
                  className="min-h-16 rounded-md border bg-background p-2"
                  defaultValue={policy.accounts?.join("\n") ?? ""}
                  onBlur={(e) => update({ accounts: split(e.target.value) })}
                />
              </Field>
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
                {budgetLabels.map(([key, label]) => (
                  <Field key={key} label={label}>
                    <Input
                      type="number"
                      min={0}
                      step={1}
                      value={policy.budget[key] ?? 0}
                      onChange={(e) => update({ budget: { ...policy.budget, [key]: Number(e.target.value) } })}
                    />
                  </Field>
                ))}
              </div>
              <p className="text-xs text-muted-foreground">
                预算 0
                表示未设置该项上限。目标服务的速率、并发和账号窗口跨任务共享；本任务累计请求单独计数。阈值按测试许可和目标承载能力设置。
              </p>
              <Button onClick={save} disabled={saving}>
                {saving ? "保存中…" : "保存用户确认的策略"}
              </Button>
              <span className="ml-2 text-xs text-muted-foreground">授权版本 {version.slice(0, 12)}</span>
            </div>
          </details>
        )}
        <details>
          <summary className="cursor-pointer text-sm font-medium">目标访问记录与测试产物</summary>
          <div className="mt-2 space-y-1 text-xs">
            {requests.length === 0 ? (
              <p className="text-muted-foreground">尚无实际目标请求记录</p>
            ) : (
              requests.map((r) => (
                <div key={r.id} className="break-all rounded border p-2">
                  #{r.id} {r.method} {r.url} · {r.status_code || r.state} · {r.latency_ms} ms {r.error}
                </div>
              ))
            )}
            {resources.map((r) => (
              <div key={r.id} className="break-all rounded border p-2">
                测试资源 #{r.id} · {r.url} · {r.state} · 创建证据请求 #{r.creation_request_id}
                {r.conditional_cleanup && r.etag ? " · 具备条件清理证据" : " · 不自动清理"}
              </div>
            ))}
          </div>
        </details>
        <details>
          <summary className="cursor-pointer text-sm font-medium">人工恢复 / 解除冷却</summary>
          <div className="mt-2 flex flex-wrap gap-2">
            <Input
              className="sm:w-72"
              placeholder="填写操作原因（必填、将审计）"
              value={reason}
              onChange={(e) => setReason(e.target.value)}
            />
            <Button variant="outline" onClick={() => control("resume")}>
              明确恢复目标访问
            </Button>
            <Input
              className="sm:w-72"
              placeholder="需解除冷却的目标完整 URL"
              value={cooldownTarget}
              onChange={(e) => setCooldownTarget(e.target.value)}
            />
            <Button variant="outline" onClick={() => control("cooldown")}>
              解除此目标冷却
            </Button>
          </div>
        </details>
      </CardContent>
    </Card>
  );
}
function localDate(iso: string) {
  const d = new Date(iso);
  return new Date(d.getTime() - d.getTimezoneOffset() * 60000).toISOString().slice(0, 16);
}
