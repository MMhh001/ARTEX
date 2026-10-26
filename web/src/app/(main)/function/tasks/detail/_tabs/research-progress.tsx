"use client";

import * as React from "react";

import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import type { TaskNode } from "@/lib/types";

const HYPOTHESIS_STAGES = [
  ["suspected", "候选"],
  ["reachable", "入口可达"],
  ["controllable", "输入可控"],
  ["boundary_broken", "边界突破"],
  ["reproduced", "待独立复核"],
  ["independently_reproduced", "独立复现"],
] as const;

const EVIDENCE_TIERS = [
  ["source_analysis", "源码/配置分析"],
  ["test_fixture", "测试夹具"],
  ["target_runtime", "目标运行时"],
] as const;

const GOAL_STATE_LABEL: Record<string, string> = {
  met: "已验收",
  open: "进行中",
  abandoned: "已停止",
};

function payloadOf(node: TaskNode): Record<string, unknown> {
  try {
    const parsed: unknown = JSON.parse(node.payload ?? "{}");
    return parsed && typeof parsed === "object" ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

function stringField(payload: Record<string, unknown>, key: string): string {
  const value = payload[key];
  return typeof value === "string" ? value.trim() : "";
}

function dynamicValidationLabel(value: unknown): string {
  switch (value) {
    case "ready": return "可执行";
    case "blocked": return "受阻";
    case "not_applicable": return "不适用";
    default: return "未知";
  }
}

function preflightStateLabel(value: unknown): string {
  switch (value) {
    case "ready": return "已就绪";
    case "blocked": return "受阻/未就绪";
    default: return "未知";
  }
}

export function ResearchProgress({ goal, nodes }: { goal: string; nodes: TaskNode[] }) {
  // Only report the current task's work; inherited context is reference material,
  // not progress owned by this U-Agent run.
  const localNodes = nodes.filter((node) => !node.inherited);
  const goals = localNodes
    .filter((node) => node.type === "goal")
    .map((node) => ({ node, text: stringField(payloadOf(node), "text") }))
    .filter((item) => item.text)
    .sort((a, b) => Number(a.node.id) - Number(b.node.id));
  const hypotheses = localNodes.filter((node) => node.type === "hypothesis");
  const findings = localNodes.filter((node) => node.type === "finding" && node.state === "confirmed");
  const checkpoints = localNodes.filter((node) => node.type === "checkpoint");
  const checkpoint = checkpoints.length ? payloadOf(checkpoints[checkpoints.length - 1]) : {};
  const preflight = checkpoint.environment_preflight && typeof checkpoint.environment_preflight === "object"
    ? (checkpoint.environment_preflight as Record<string, unknown>)
    : null;
  const nextHop = checkpoint.next_hop && typeof checkpoint.next_hop === "object"
    ? (checkpoint.next_hop as Record<string, unknown>)
    : {};
  const nextStep = typeof nextHop.summary === "string" ? nextHop.summary : "";
  const blockedPaths = Array.isArray(checkpoint.blocked_paths) ? checkpoint.blocked_paths : [];
  const activeHypothesis = [...hypotheses]
    .reverse()
    .find((node) => !["rejected", "independently_reproduced"].includes(node.state));
  const hypothesisNextStep = activeHypothesis ? stringField(payloadOf(activeHypothesis), "next_step") : "";
  const metGoals = goals.filter(({ node }) => node.state === "met").length;

  return (
    <Card className="mb-4">
      <CardHeader className="pb-3">
        <div className="flex flex-wrap items-center justify-between gap-2">
          <CardTitle className="text-base">U-Agent 研究推进</CardTitle>
          <Badge variant="outline">研究路径不替代用户目标</Badge>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        <section className="rounded-lg bg-muted/50 p-3">
          <p className="mb-1 text-xs font-medium text-muted-foreground">你的原始目标</p>
          <p className="whitespace-pre-wrap text-sm">{goal || "未填写目标"}</p>
        </section>

        <div className="grid gap-4 lg:grid-cols-2">
          <section className="min-w-0">
            <div className="mb-2 flex items-center justify-between gap-2">
              <h3 className="text-sm font-medium">目标验收</h3>
              <span className="text-xs tabular-nums text-muted-foreground">
                {metGoals}/{goals.length} 已验收
              </span>
            </div>
            {goals.length ? (
              <ul className="space-y-2">
                {goals.map(({ node, text }) => (
                  <li key={node.id} className="flex items-start gap-2 text-sm">
                    <Badge variant={node.state === "met" ? "secondary" : "outline"} className="mt-0.5 shrink-0">
                      {GOAL_STATE_LABEL[node.state] ?? node.state}
                    </Badge>
                    <span className="min-w-0 break-words">{text}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-muted-foreground">目标验收项尚未生成。</p>
            )}
          </section>

          <section className="min-w-0">
            <div className="mb-2 flex items-center justify-between gap-2">
              <h3 className="text-sm font-medium">漏洞假设证据成熟度</h3>
              <span className="text-xs text-muted-foreground">{hypotheses.length} 条假设</span>
            </div>
            <div className="flex flex-wrap gap-1.5">
              {HYPOTHESIS_STAGES.map(([state, label]) => {
                const count = hypotheses.filter((node) => node.state === state).length;
                return (
                  <Badge key={state} variant={count > 0 ? "secondary" : "outline"}>
                    {label} {count}
                  </Badge>
                );
              })}
              <Badge variant="outline">已排除 {hypotheses.filter((node) => node.state === "rejected").length}</Badge>
              <Badge variant="outline">受阻 {hypotheses.filter((node) => node.state === "blocked").length}</Badge>
              <Badge variant="outline">确认漏洞 {findings.length}</Badge>
            </div>
            <p className="mt-2 text-xs text-muted-foreground">证据类型按当前假设记录统计；测试夹具证明逻辑行为，不代表目标版本已验证。</p>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {EVIDENCE_TIERS.map(([tier, label]) => (
                <Badge key={tier} variant="outline">
                  {label} {hypotheses.filter((node) => stringField(payloadOf(node), "evidence_tier") === tier).length}
                </Badge>
              ))}
              <Badge variant="outline">未标注 {hypotheses.filter((node) => !stringField(payloadOf(node), "evidence_tier")).length}</Badge>
            </div>
          </section>
        </div>

        <section className="rounded-lg border p-3">
          <div className="mb-2 flex flex-wrap items-center justify-between gap-2">
            <h3 className="text-sm font-medium">目标版本与环境预检</h3>
            <Badge variant={preflight ? "secondary" : "outline"}>{preflight ? "已记录" : "尚未记录"}</Badge>
          </div>
          {preflight ? (
            <div className="grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2 xl:grid-cols-3">
              <p><span className="text-muted-foreground">目标版本：</span>{String(preflight.target_version || "unknown")}</p>
              <p><span className="text-muted-foreground">源码修订/制品：</span>{String(preflight.source_revision || "unknown")}</p>
              <p><span className="text-muted-foreground">构建环境：</span>{String(preflight.build_environment || "unknown")}</p>
              <p><span className="text-muted-foreground">依赖：</span>{preflightStateLabel(preflight.dependencies_status)}</p>
              <p><span className="text-muted-foreground">目标启动：</span>{preflightStateLabel(preflight.target_startup)}</p>
              <p><span className="text-muted-foreground">动态验证：</span>{dynamicValidationLabel(preflight.dynamic_validation)}</p>
              {Array.isArray(preflight.blockers) && preflight.blockers.length > 0 && (
                <div className="sm:col-span-2 xl:col-span-3">
                  <span className="text-muted-foreground">阻塞原因：</span>{preflight.blockers.map(String).join("；")}
                </div>
              )}
              {typeof preflight.notes === "string" && preflight.notes && (
                <p className="text-muted-foreground sm:col-span-2 xl:col-span-3">{preflight.notes}</p>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">研究记录还没有说明目标版本、构建依赖和动态验证条件。完成预检前，不能把动态验证视为已具备。</p>
          )}
        </section>

        <div className="grid gap-3 border-t pt-3 text-sm md:grid-cols-2">
          <section>
            <p className="mb-1 text-xs font-medium text-muted-foreground">当前下一步</p>
            <p>{nextStep || hypothesisNextStep || "等待研究规划或新的证据记录。"}</p>
          </section>
          <section>
            <p className="mb-1 text-xs font-medium text-muted-foreground">阻塞路径</p>
            {blockedPaths.length ? (
              <ul className="space-y-1">
                {blockedPaths.slice(0, 3).map((raw, index) => {
                  const item = raw && typeof raw === "object" ? (raw as Record<string, unknown>) : {};
                  const summary = typeof item.summary === "string" ? item.summary : "研究意图受阻";
                  const reason = typeof item.blocked_reason === "string" ? item.blocked_reason : "";
                  return <li key={`${index}-${summary}`}>{summary}{reason ? `：${reason}` : ""}</li>;
                })}
              </ul>
            ) : (
              <p className="text-muted-foreground">当前没有已记录的阻塞路径。</p>
            )}
          </section>
        </div>
      </CardContent>
    </Card>
  );
}
