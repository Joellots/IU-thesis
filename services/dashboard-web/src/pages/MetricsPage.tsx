import { Timer, Layers, Gauge as GaugeIcon, ShieldAlert, ShieldCheck } from "lucide-react";
import { useMetrics, useMapping } from "../api/client";
import { Card, StatCard, Donut, Spinner, ErrorState, cn } from "../components/ui";
import { PageHeader } from "./AlertsPage";

export default function MetricsPage() {
  const { data: m, isLoading, error } = useMetrics();
  return (
    <div>
      <PageHeader title="Pipeline Metrics" subtitle="Detection & XAI statistics — thesis evaluation" />
      <div className="mx-auto max-w-5xl space-y-6 p-6">
        {isLoading ? <Spinner /> : error ? <ErrorState error={error} /> : !m ? null : (
          <>
            {/* KPI row */}
            <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
              <StatCard label="Total flows" value={m.total_flows} icon={<Layers className="h-4 w-4" />} />
              <StatCard label="Malicious" value={m.malicious_detected} accent="text-rose-300" icon={<ShieldAlert className="h-4 w-4" />} />
              <StatCard label="Benign" value={m.benign_detected} accent="text-emerald-300" icon={<ShieldCheck className="h-4 w-4" />} />
              <StatCard label="Tier-2 triggers" value={m.tier2_trigger_count} sub={`${(m.tier2_trigger_rate * 100).toFixed(1)}% of flows`} icon={<GaugeIcon className="h-4 w-4" />} />
            </div>

            {/* Detection + classifier quality, side by side with breathing room */}
            <div className="grid gap-6 lg:grid-cols-2">
              <Card title="Detection split">
                <div className="flex items-center justify-center py-3">
                  <Donut a={m.malicious_detected} b={m.benign_detected} size={150} />
                </div>
                <div className="mt-2 border-t border-line pt-3 text-center text-[0.74rem] text-slate-500">
                  malicious rate
                  <span className="ml-2 font-mono text-base text-rose-300">
                    {m.total_flows ? ((m.malicious_detected / m.total_flows) * 100).toFixed(1) : "0"}%
                  </span>
                </div>
              </Card>

              <Card title="Classifier quality (labelled flows)">
                <div className="grid grid-cols-2 gap-2.5">
                  <Cell label="True positive" value={m.confusion_matrix.tp} good />
                  <Cell label="False positive" value={m.confusion_matrix.fp} />
                  <Cell label="False negative" value={m.confusion_matrix.fn} />
                  <Cell label="True negative" value={m.confusion_matrix.tn} good />
                </div>
                <div className="mt-3 flex justify-around border-t border-line pt-3 text-center">
                  <Derived label="Precision" v={ratio(m.confusion_matrix.tp, m.confusion_matrix.tp + m.confusion_matrix.fp)} />
                  <Derived label="Recall" v={ratio(m.confusion_matrix.tp, m.confusion_matrix.tp + m.confusion_matrix.fn)} />
                  <Derived label="F1" v={f1(m.confusion_matrix)} />
                </div>
              </Card>
            </div>

            {/* Latency — clean horizontal tiles */}
            <Card title="Latency">
              <div className="grid gap-3 sm:grid-cols-3">
                <Lat icon={<Timer className="h-4 w-4" />} label="Avg explain (fast tier)" value={m.avg_explain_ms != null ? `${m.avg_explain_ms} ms` : "—"} />
                <Lat icon={<Timer className="h-4 w-4" />} label="Avg pipeline (sent→inferred)" value={m.avg_pipeline_ms != null ? `${m.avg_pipeline_ms} ms` : "—"} />
                <Lat icon={<GaugeIcon className="h-4 w-4" />} label="Tier-2 trigger rate" value={`${(m.tier2_trigger_rate * 100).toFixed(1)}%`} />
              </div>
            </Card>

            <MappingReliability />

            <Card title="Analyst decisions">
              <div className="flex flex-wrap gap-3">
                {Object.entries(m.analyst_decisions).length === 0 && <span className="text-sm text-slate-500">No decisions yet.</span>}
                {Object.entries(m.analyst_decisions).map(([k, v]) => (
                  <div key={k} className="rounded-lg border border-line bg-surface2/60 px-4 py-2.5">
                    <div className="text-[0.62rem] uppercase tracking-wider text-slate-500">{k.replace(/_/g, " ")}</div>
                    <div className="kpi-num text-xl text-white">{v}</div>
                  </div>
                ))}
              </div>
            </Card>
          </>
        )}
      </div>
    </div>
  );
}

function Cell({ label, value, good }: { label: string; value: number; good?: boolean }) {
  return (
    <div className={cn("rounded-lg p-3 text-center", good ? "bg-emerald-500/10 ring-1 ring-inset ring-emerald-500/25" : "bg-rose-500/10 ring-1 ring-inset ring-rose-500/25")}>
      <div className={cn("text-[0.6rem] font-semibold uppercase tracking-wider", good ? "text-emerald-400/80" : "text-rose-400/80")}>{label}</div>
      <div className="kpi-num mt-0.5 text-2xl text-white">{value}</div>
    </div>
  );
}
function Derived({ label, v }: { label: string; v: string }) {
  return (
    <div>
      <div className="text-[0.6rem] uppercase tracking-wider text-slate-500">{label}</div>
      <div className="kpi-num text-base text-brand">{v}</div>
    </div>
  );
}
function Lat({ icon, label, value }: { icon: React.ReactNode; label: string; value: string }) {
  return (
    <div className="flex items-center gap-3 rounded-lg bg-surface2/50 px-3 py-3">
      <span className="text-brand">{icon}</span>
      <div className="min-w-0 flex-1">
        <div className="truncate text-[0.72rem] text-slate-400">{label}</div>
        <div className="kpi-num text-sm text-white">{value}</div>
      </div>
    </div>
  );
}

const ratio = (n: number, d: number) => (d > 0 ? (n / d).toFixed(2) : "—");
function f1(c: { tp: number; fp: number; fn: number }) {
  const p = c.tp + c.fp > 0 ? c.tp / (c.tp + c.fp) : 0;
  const r = c.tp + c.fn > 0 ? c.tp / (c.tp + c.fn) : 0;
  return p + r > 0 ? ((2 * p * r) / (p + r)).toFixed(2) : "—";
}

// The headline result: calibrated feature→TTP mapping reliability.
function MappingReliability() {
  const { data: m } = useMapping();
  if (!m) return null;
  const order = ["mapped", "unmapped_heuristic", "unmapped"];
  const statuses = order.filter((s) => m.by_status[s]).map((s) => ({ key: s, ...m.by_status[s] }));
  const totalStatus = statuses.reduce((n, s) => n + s.n, 0) || 1;
  const maxHist = Math.max(1, ...m.histogram);
  const barFor = (k: string) => (k === "mapped" ? "bg-brand" : k === "unmapped_heuristic" ? "bg-amber-400" : "bg-slate-500");
  return (
    <Card title="Feature→TTP mapping reliability"
      action={m.avg_mapped != null ? <span className="text-[0.7rem] text-slate-500">avg mapped conf <b className="text-brand">{m.avg_mapped}</b></span> : undefined}>
      <div className="grid gap-6 sm:grid-cols-2">
        <div className="space-y-2.5">
          {statuses.length === 0 && <span className="text-sm text-slate-500">No mapped alerts yet.</span>}
          {statuses.map((s) => (
            <div key={s.key}>
              <div className="mb-1 flex justify-between text-[0.72rem]">
                <span className="text-slate-300">{s.key.replace(/_/g, " ")}</span>
                <span className="text-slate-500">{s.n}{s.avg_conf != null ? ` · ${s.avg_conf}` : ""}</span>
              </div>
              <div className="h-2.5 overflow-hidden rounded-full bg-bg/70">
                <div className={cn("h-full rounded-full", barFor(s.key))} style={{ width: `${(s.n / totalStatus) * 100}%` }} />
              </div>
            </div>
          ))}
        </div>
        <div>
          <div className="mb-2 text-[0.62rem] uppercase tracking-wider text-slate-500">mapping-confidence distribution</div>
          <div className="flex h-24 items-end gap-1">
            {m.histogram.map((n, i) => (
              <div key={i} className="flex-1 rounded-t bg-brand/60" style={{ height: `${(n / maxHist) * 100}%`, minHeight: n ? "3px" : "0" }}
                title={`${(i / 10).toFixed(1)}–${((i + 1) / 10).toFixed(1)}: ${n}`} />
            ))}
          </div>
          <div className="mt-1 flex justify-between text-[0.56rem] text-slate-600"><span>0.0</span><span>0.5</span><span>1.0</span></div>
        </div>
      </div>
    </Card>
  );
}
