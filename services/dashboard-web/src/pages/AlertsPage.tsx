import { useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ChevronRight, ShieldAlert, ShieldCheck, Activity, ListChecks } from "lucide-react";
import { useAlerts, useSummary } from "../api/client";
import type { AlertRow } from "../api/types";
import {
  Badge, SeverityBadge, VerdictBadge, StatCard, Spinner, ErrorState, EmptyState, PulseDot, cn, fmtTime, pct,
} from "../components/ui";
import { FilterShell, FilterField, TextFilter, Segmented } from "../components/Filters";

type AF = {
  cls: "all" | "malicious" | "benign";
  sev: "all" | "high" | "medium" | "low";
  verdict: "all" | "pending" | "true_positive" | "false_positive";
  ttp: string;
  endpoint: string;
};

export default function AlertsPage() {
  const [sp, setSp] = useSearchParams();
  const [f, setF] = useState<AF>({ cls: "all", sev: "all", verdict: "all", ttp: sp.get("ttp") ?? "", endpoint: sp.get("endpoint") ?? "" });
  const { data, isLoading, error } = useAlerts(false);
  const { data: s } = useSummary();

  const upd = (k: keyof AF, v: string) => {
    setF({ ...f, [k]: v } as AF);
    if (k === "ttp") { const n = new URLSearchParams(sp); v ? n.set("ttp", v) : n.delete("ttp"); setSp(n, { replace: true }); }
  };
  const clear = () => { setF({ cls: "all", sev: "all", verdict: "all", ttp: "", endpoint: "" }); setSp({}, { replace: true }); };

  const all = data ?? [];
  const match = (a: AlertRow) => {
    if (f.cls === "malicious" && a.pred_label !== 1) return false;
    if (f.cls === "benign" && a.pred_label !== 0) return false;
    if (f.sev !== "all" && (a.severity_label ?? "").toLowerCase() !== f.sev) return false;
    if (f.verdict !== "all" && (a.analyst_decision ?? "pending") !== f.verdict) return false;
    if (f.ttp && !(a.mitre_ttps ?? []).join(" ").toLowerCase().includes(f.ttp.toLowerCase())) return false;
    if (f.endpoint && !`${a.host_id ?? ""} ${a.agent_id ?? ""}`.toLowerCase().includes(f.endpoint.toLowerCase())) return false;
    return true;
  };
  const rows = all.filter(match);
  const hasFilter = f.cls !== "all" || f.sev !== "all" || f.verdict !== "all" || !!f.ttp || !!f.endpoint;

  return (
    <div>
      <PageHeader title="Alert Queue" subtitle="Encrypted-traffic anomaly detection — live XAI pipeline" />
      <div className="space-y-5 p-6">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          <StatCard label="Total flows" value={s?.total_flows ?? "—"} icon={<Activity className="h-4 w-4" />} />
          <StatCard label="Malicious" value={s?.malicious_detected ?? "—"} accent="text-rose-300" icon={<ShieldAlert className="h-4 w-4" />} />
          <StatCard label="Benign" value={s?.benign_detected ?? "—"} accent="text-emerald-300" icon={<ShieldCheck className="h-4 w-4" />} />
          <StatCard label="Pending approvals" value={s?.pending_approvals ?? "—"} accent={s?.pending_approvals ? "text-amber-300" : undefined} icon={<ListChecks className="h-4 w-4" />} />
        </div>

        <FilterShell right={<>
          <span><b className="text-slate-300">{rows.length}</b> / {all.length}</span>
          {hasFilter && <button onClick={clear} className="text-brand hover:underline">clear</button>}
          <PulseDot />
        </>}>
          <FilterField label="Endpoint"><TextFilter value={f.endpoint} onChange={(v) => upd("endpoint", v)} placeholder="host / agent" width="w-36" /></FilterField>
          <FilterField label="MITRE TTP"><TextFilter value={f.ttp} onChange={(v) => upd("ttp", v)} placeholder="T1071" mono width="w-28" /></FilterField>
          <FilterField label="Class"><Segmented value={f.cls} onChange={(v) => upd("cls", v)} options={["all", "malicious", "benign"] as const} /></FilterField>
          <FilterField label="Severity"><Segmented value={f.sev} onChange={(v) => upd("sev", v)} options={["all", "high", "medium", "low"] as const} /></FilterField>
          <FilterField label="Verdict"><Segmented value={f.verdict} onChange={(v) => upd("verdict", v)} options={["all", "pending", "true_positive", "false_positive"] as const} labels={{ true_positive: "TP", false_positive: "FP" }} /></FilterField>
        </FilterShell>

        {isLoading ? <Spinner /> : error ? <ErrorState error={error} /> : all.length === 0 ? (
          <EmptyState>No alerts yet — waiting for pipeline data…</EmptyState>
        ) : rows.length === 0 ? (
          <EmptyState>No alerts match the filter. <button onClick={clear} className="text-brand hover:underline">clear filters</button></EmptyState>
        ) : (
          <div className="panel overflow-hidden p-0">
            <table className="w-full">
              <thead>
                <tr className="border-b border-line text-[0.62rem] uppercase tracking-[0.1em] text-slate-500">
                  <Th>Time</Th><Th>Prediction</Th><Th>Confidence</Th><Th>Severity</Th><Th>MITRE</Th><Th>Endpoint</Th><Th>Verdict</Th><Th />
                </tr>
              </thead>
              <tbody>
                {rows.map((a) => {
                  const mal = a.pred_label === 1;
                  return (
                    <tr key={a.id} className="group border-b border-line/50 transition-colors hover:bg-white/[0.025]">
                      <td className="relative py-3 pl-5 pr-3">
                        <span className={cn("absolute left-0 top-1/2 h-7 w-[3px] -translate-y-1/2 rounded-r", mal ? sevRail(a.severity_label) : "bg-slate-700")} />
                        <span className="font-mono text-[0.72rem] text-slate-400">{fmtTime(a.translated_ts)}</span>
                      </td>
                      <td className="px-3"><Badge tone={mal ? "high" : "benign"}>{mal ? <><ShieldAlert className="h-3 w-3" /> malicious</> : "benign"}</Badge></td>
                      <td className="px-3"><ConfBar p={a.pred_proba} mal={mal} /></td>
                      <td className="px-3">{mal ? <SeverityBadge label={a.severity_label} /> : <span className="text-slate-600">—</span>}</td>
                      <td className="px-3"><span className="font-mono text-[0.72rem] text-brand">{a.mitre_ttps?.join(" ") || "—"}</span></td>
                      <td className="px-3"><span className="font-mono text-[0.68rem] text-slate-400">{a.host_id || (a.agent_id ? `agent ${a.agent_id}` : "—")}</span></td>
                      <td className="px-3"><VerdictBadge decision={a.analyst_decision} /></td>
                      <td className="py-3 pr-5">
                        <Link to={`/alert/${a.id}`} className="inline-flex items-center gap-1 rounded-md border border-line bg-surface2 px-2.5 py-1 text-[0.72rem] text-slate-300 opacity-60 transition group-hover:opacity-100 hover:border-brand/40 hover:text-brand">
                          Detail <ChevronRight className="h-3 w-3" />
                        </Link>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

export function PageHeader({ title, subtitle, right }: { title: string; subtitle?: string; right?: React.ReactNode }) {
  return (
    <header className="sticky top-0 z-10 flex items-center gap-4 border-b border-line bg-bg/80 px-6 py-4 backdrop-blur-md">
      <div>
        <h1 className="text-lg font-bold tracking-tight text-white">{title}</h1>
        {subtitle && <p className="text-[0.72rem] text-slate-500">{subtitle}</p>}
      </div>
      {right && <div className="ml-auto">{right}</div>}
    </header>
  );
}

function ConfBar({ p, mal }: { p: number; mal: boolean }) {
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-surface2">
        <div className={cn("h-full rounded-full", mal ? "bg-rose-400" : "bg-emerald-400")} style={{ width: `${Math.round((p || 0) * 100)}%` }} />
      </div>
      <span className="font-mono text-[0.72rem] text-slate-400">{pct(p)}</span>
    </div>
  );
}

const sevRail = (label?: string | null) => {
  const l = (label || "").toLowerCase();
  return l === "high" ? "bg-rose-500" : l === "medium" ? "bg-amber-500" : "bg-emerald-500";
};
const Th = ({ children }: { children?: React.ReactNode }) => <th className="px-3 py-2.5 text-left font-semibold first:pl-5 last:pr-5">{children}</th>;
