import { useState } from "react";
import { Link, useParams } from "react-router-dom";
import { ArrowLeft, ExternalLink, Globe, Link2, Fingerprint, Server, Check, ShieldX, Network } from "lucide-react";
import { useAlert, useSubmitFeedback } from "../api/client";
import type { TopKFeature, Observable, SoarAction } from "../api/types";
import {
  Card, Badge, SeverityBadge, VerdictBadge, Gauge, Spinner, ErrorState, cn, pct,
} from "../components/ui";

export default function AlertDetailPage() {
  const { id } = useParams();
  const alertId = Number(id);
  const { data: a, isLoading, error } = useAlert(alertId);

  if (isLoading) return <Spinner />;
  if (error) return <div className="p-6"><ErrorState error={error} /></div>;
  if (!a) return <div className="p-6 text-slate-400">Alert not found.</div>;
  const mal = a.pred_label === 1;

  return (
    <div>
      <header className="sticky top-0 z-10 flex items-center gap-4 border-b border-line bg-bg/80 px-6 py-4 backdrop-blur-md">
        <Link to="/" className="flex items-center gap-1.5 text-sm text-slate-400 hover:text-white"><ArrowLeft className="h-4 w-4" /> Queue</Link>
        <h1 className="text-lg font-bold tracking-tight text-white">Alert <span className="text-slate-500">#{a.id}</span></h1>
        {mal ? <SeverityBadge label={a.severity_label} /> : <Badge tone="benign">benign</Badge>}
        {a.mapping_status && <Badge tone={a.mapping_status === "mapped" ? "brand" : "muted"}>{a.mapping_status}</Badge>}
      </header>

      <div className="mx-auto max-w-5xl space-y-5 p-6">
        {/* Hero: threat gauge + key facts */}
        <Card className="flex flex-col items-center gap-6 sm:flex-row sm:items-stretch">
          <div className="flex flex-col items-center justify-center gap-1 sm:w-44">
            <Gauge value={a.pred_proba} caption={mal ? "threat" : "benign conf"} />
            <div className="text-[0.66rem] uppercase tracking-wider text-slate-500">{a.model} · {a.tier}</div>
          </div>
          <div className="grid flex-1 grid-cols-2 gap-x-6 gap-y-3 sm:grid-cols-3">
            <Field label="Prediction">{mal ? <span className="text-rose-300">Malicious</span> : <span className="text-emerald-300">Benign</span>}</Field>
            <Field label="Feature→TTP mapping" className="col-span-2 sm:col-span-3"><MappingMeter status={a.mapping_status} conf={a.mapping_confidence} /></Field>
            <Field label="Ground truth">{a.true_label === 1 ? "Malicious" : a.true_label === 0 ? "Benign" : "Unknown"}</Field>
            <Field label="Explain time">{a.explain_time_ms != null ? `${a.explain_time_ms.toFixed(1)} ms` : "—"}</Field>
            <Field label="Map version">{a.mapping_version || "—"}</Field>
            <Field label="Verdict"><VerdictBadge decision={a.analyst_decision} /></Field>
            <Field label="Flow ID" className="col-span-2 sm:col-span-3"><code className="font-mono text-[0.72rem] text-amber-300">{a.flow_id}</code></Field>
            {a.host_id && <Field label="Endpoint" className="col-span-2 sm:col-span-3">
              <span className="text-slate-200">{a.host_id}</span> <span className="text-slate-500">· agent {a.agent_id || "?"}{a.host_ip ? ` · ${a.host_ip}` : ""}</span>
            </Field>}
          </div>
        </Card>

        {a.soar_actions && a.soar_actions.length > 0 && (
          <Card title="SOAR Response">
            <div className="space-y-2">{a.soar_actions.map((s) => <SoarRow key={s.id} s={s} />)}</div>
          </Card>
        )}

        {a.mitre_ttps && a.mitre_ttps.length > 0 && (
          <Card title="MITRE ATT&CK">
            <div className="flex flex-wrap gap-2">
              {a.mitre_ttps.map((t, i) => (
                <span key={t} className="inline-flex items-center gap-2 rounded-lg border border-brand/30 bg-brand/10 px-3 py-1.5">
                  <span className="font-mono text-[0.78rem] font-semibold text-brand">{t}</span>
                  {a.mitre_names?.[i] && <span className="text-[0.74rem] text-slate-400">{a.mitre_names[i]}</span>}
                </span>
              ))}
            </div>
          </Card>
        )}

        {a.top_k_json && a.top_k_json.length > 0 && (
          <Card title="XAI Feature Attributions" action={<span className="text-[0.66rem] text-slate-500">red = pushes malicious · green = pushes benign</span>}>
            <AttributionChart features={a.top_k_json} />
          </Card>
        )}

        <div className="grid gap-5 lg:grid-cols-2">
          {a.observables && a.observables.length > 0 && (
            <Card title="Observables">
              <ul className="space-y-2">
                {a.observables.map((o, i) => <li key={i}><ObservableRow o={o} /></li>)}
              </ul>
            </Card>
          )}
          <Card title="Annotation" className={a.observables?.length ? "" : "lg:col-span-2"}>
            <pre className="max-h-56 overflow-auto whitespace-pre-wrap break-words rounded-lg border-l-2 border-rose-500/60 bg-bg/60 p-3 font-mono text-[0.74rem] leading-relaxed text-slate-300">
              {a.annotation || "No annotation."}
            </pre>
          </Card>
        </div>

        <FeedbackForm alertId={alertId} current={a.analyst_decision} note={a.analyst_note}
          explanationUseful={a.explanation_useful} flagForRetraining={a.flag_for_retraining} />
      </div>
    </div>
  );
}

function Field({ label, children, className }: { label: string; children: React.ReactNode; className?: string }) {
  return (
    <div className={className}>
      <div className="text-[0.62rem] uppercase tracking-[0.1em] text-slate-500">{label}</div>
      <div className="mt-0.5 text-[0.86rem]">{children}</div>
    </div>
  );
}

function MappingMeter({ status, conf }: { status: string | null; conf: number | null }) {
  const c = conf ?? 0;
  const tone: "brand" | "medium" | "muted" =
    status === "mapped" ? "brand" : status === "unmapped_heuristic" ? "medium" : "muted";
  const bar = status === "mapped" ? "bg-brand" : status === "unmapped_heuristic" ? "bg-amber-400" : "bg-slate-500";
  return (
    <div className="flex items-center gap-3">
      <Badge tone={tone}>{status || "unmapped"}</Badge>
      <div className="h-2 flex-1 overflow-hidden rounded-full bg-bg/70">
        <div className={cn("h-full rounded-full transition-all duration-500", bar)} style={{ width: `${Math.round(c * 100)}%` }} />
      </div>
      <span className="font-mono text-[0.8rem] text-slate-200">{conf != null ? conf.toFixed(3) : "—"}</span>
    </div>
  );
}

function SoarRow({ s }: { s: SoarAction }) {
  const stTone: "fp" | "tp" | "medium" | "muted" =
    s.status === "executed" ? "fp" : s.status === "rejected" || s.status === "failed" ? "tp" : s.status === "pending" ? "medium" : "muted";
  return (
    <div className="flex flex-wrap items-center gap-2.5 rounded-lg bg-surface2/50 px-3 py-2.5 text-[0.82rem]">
      <Badge tone={s.action_type === "isolate" ? "isolate" : "block"}>
        {s.action_type === "isolate" ? <Network className="h-3 w-3" /> : <ShieldX className="h-3 w-3" />} {s.action_type}
      </Badge>
      {s.target_value && <code className="font-mono text-amber-300">{s.target_value}</code>}
      <Badge tone={stTone}>{s.status}</Badge>
      {s.analyst && <span className="text-[0.72rem] text-slate-500">by {s.analyst}</span>}
      {s.case_url && <a href={s.case_url} target="_blank" rel="noreferrer" className="ml-auto inline-flex items-center gap-1 text-[0.72rem] text-brand hover:underline"><ExternalLink className="h-3 w-3" /> case</a>}
    </div>
  );
}

const OBS_ICON: Record<string, React.ReactNode> = {
  ip: <Globe className="h-3.5 w-3.5" />, domain: <Server className="h-3.5 w-3.5" />,
  url: <Link2 className="h-3.5 w-3.5" />, ja3: <Fingerprint className="h-3.5 w-3.5" />,
};
function ObservableRow({ o }: { o: Observable }) {
  return (
    <div className="flex items-center gap-2.5 rounded-lg bg-surface2/60 px-3 py-2">
      <span className="text-brand">{OBS_ICON[o.type] || <Globe className="h-3.5 w-3.5" />}</span>
      <Badge tone="muted">{o.type}</Badge>
      <code className="truncate font-mono text-[0.76rem] text-amber-300">{o.value}</code>
      {o.role && <span className="ml-auto text-[0.64rem] uppercase tracking-wider text-slate-500">{o.role}</span>}
    </div>
  );
}

function AttributionChart({ features }: { features: TopKFeature[] }) {
  const max = Math.max(...features.map((f) => Math.abs(f.contribution)), 1e-9);
  return (
    <div className="space-y-2.5">
      {features.map((f, i) => {
        const positive = f.direction === "positive" || f.contribution > 0;
        return (
          <div key={i} className="grid grid-cols-[minmax(0,1fr)_104px] items-center gap-4">
            <div>
              <div className="truncate font-mono text-[0.72rem] text-slate-300" title={f.feature}>{f.feature}</div>
              <div className="mt-1 h-2.5 w-full overflow-hidden rounded-full bg-bg/70">
                <div className={cn("h-full rounded-full transition-all duration-500", positive
                  ? "bg-gradient-to-r from-rose-500/70 to-rose-400"
                  : "bg-gradient-to-r from-emerald-500/70 to-emerald-400")}
                  style={{ width: `${(Math.abs(f.contribution) / max) * 100}%` }} />
              </div>
            </div>
            <div className="text-right">
              <span className={cn("font-mono text-[0.76rem] font-semibold", positive ? "text-rose-300" : "text-emerald-300")}>
                {f.contribution >= 0 ? "+" : ""}{f.contribution.toFixed(4)}
              </span>
              <div className="font-mono text-[0.62rem] text-slate-500">val {f.value.toFixed(3)}</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function FeedbackForm({ alertId, current, note, explanationUseful, flagForRetraining }: {
  alertId: number; current?: string | null; note?: string | null;
  explanationUseful?: boolean | null; flagForRetraining?: boolean | null;
}) {
  const [noteVal, setNoteVal] = useState(note || "");
  const [useful, setUseful] = useState(!!explanationUseful);
  const [flag, setFlag] = useState(!!flagForRetraining);
  const fb = useSubmitFeedback(alertId);
  const submit = (decision: "true_positive" | "false_positive") =>
    fb.mutate({ decision, note: noteVal, explanation_useful: useful, flag_for_retraining: flag });

  return (
    <Card title="Analyst Verdict & Feedback — Step 6">
      <textarea value={noteVal} onChange={(e) => setNoteVal(e.target.value)} rows={2} placeholder="Optional note / reason…"
        className="w-full rounded-lg border border-line bg-bg/60 p-2.5 text-sm text-slate-200 outline-none transition focus:border-brand/50 focus:ring-1 focus:ring-brand/30" />
      <div className="mt-3 flex flex-col gap-2.5 text-sm text-slate-300">
        <Check2 checked={useful} onChange={setUseful}>The XAI explanation was useful</Check2>
        <Check2 checked={flag} onChange={setFlag}>Flag this flow for the next retraining set</Check2>
      </div>
      <div className="mt-4 flex flex-wrap items-center gap-3">
        <button onClick={() => submit("true_positive")} disabled={fb.isPending}
          className="rounded-lg border border-rose-500/40 bg-rose-500/15 px-4 py-2 text-sm font-semibold text-rose-200 transition hover:bg-rose-500/25 disabled:opacity-50">True Positive</button>
        <button onClick={() => submit("false_positive")} disabled={fb.isPending}
          className="rounded-lg border border-emerald-500/40 bg-emerald-500/15 px-4 py-2 text-sm font-semibold text-emerald-200 transition hover:bg-emerald-500/25 disabled:opacity-50">False Positive</button>
        <div className="ml-auto flex items-center gap-2 text-[0.76rem] text-slate-500">
          current: <VerdictBadge decision={current} />
          {fb.isSuccess && <span className="flex items-center gap-1 text-emerald-300"><Check className="h-3.5 w-3.5" /> saved</span>}
          {fb.isError && <span className="text-rose-300">save failed</span>}
        </div>
      </div>
    </Card>
  );
}

function Check2({ checked, onChange, children }: { checked: boolean; onChange: (v: boolean) => void; children: React.ReactNode }) {
  return (
    <label className="flex cursor-pointer items-center gap-2.5 select-none">
      <button type="button" onClick={() => onChange(!checked)}
        className={cn("grid h-4 w-4 place-items-center rounded border transition", checked ? "border-brand bg-brand/80" : "border-line bg-surface2")}>
        {checked && <Check className="h-3 w-3 text-white" />}
      </button>
      {children}
    </label>
  );
}
