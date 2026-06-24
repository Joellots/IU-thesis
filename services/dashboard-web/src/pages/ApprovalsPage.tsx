import { useState } from "react";
import { Link } from "react-router-dom";
import { ExternalLink, ShieldX, Network, Clock, ChevronDown, ChevronRight } from "lucide-react";
import { useApprovals, useDecideApproval } from "../api/client";
import type { Approval } from "../api/types";
import { Card, Badge, Spinner, ErrorState, EmptyState, PulseDot, cn } from "../components/ui";
import { FilterShell, FilterField, TextFilter, Segmented } from "../components/Filters";
import { PageHeader } from "./AlertsPage";

type Filters = { endpoint: string; ip: string; action: "all" | "block" | "isolate"; ttp: string };
const EMPTY: Filters = { endpoint: "", ip: "", action: "all", ttp: "" };

export default function ApprovalsPage() {
  const { data, isLoading, error } = useApprovals();
  const [f, setF] = useState<Filters>(EMPTY);
  const [showExpired, setShowExpired] = useState(false);

  const all = data ?? [];
  const matches = (a: Approval) => {
    const ep = `${a.host_id ?? ""} ${a.agent_id ?? ""}`.toLowerCase();
    if (f.endpoint && !ep.includes(f.endpoint.toLowerCase())) return false;
    if (f.ip && !(a.target_value ?? "").toLowerCase().includes(f.ip.toLowerCase())) return false;
    if (f.action !== "all" && a.action_type !== f.action) return false;
    if (f.ttp && !(a.mitre_ttps ?? []).join(" ").toLowerCase().includes(f.ttp.toLowerCase())) return false;
    return true;
  };
  const filtered = all.filter(matches);
  const active = filtered.filter((a) => (a.mins_left ?? 0) >= 0);
  const expired = filtered.filter((a) => (a.mins_left ?? 0) < 0);
  const hasFilter = !!(f.endpoint || f.ip || f.ttp) || f.action !== "all";

  return (
    <div>
      <PageHeader title="SOAR Approvals" subtitle="Gated block / isolate actions awaiting an analyst decision"
        right={<div className="flex items-center gap-2 text-[0.72rem] text-slate-500"><PulseDot tone="rose" /> {active.length} active</div>} />
      <div className="mx-auto max-w-3xl space-y-4 p-6">
        <FilterBar f={f} setF={setF} total={all.length} shown={filtered.length} onClear={() => setF(EMPTY)} hasFilter={hasFilter} />

        {isLoading ? <Spinner /> : error ? <ErrorState error={error} /> : all.length === 0 ? (
          <EmptyState>No pending approvals. Gated <b className="text-slate-300">block</b> / <b className="text-slate-300">isolate</b> actions will appear here.</EmptyState>
        ) : filtered.length === 0 ? (
          <EmptyState>No approvals match the filter. <button onClick={() => setF(EMPTY)} className="text-brand hover:underline">clear filters</button></EmptyState>
        ) : (
          <>
            {active.map((a) => <ApprovalCard key={a.id} a={a} />)}
            {expired.length > 0 && (
              <div className="overflow-hidden rounded-xl border border-line bg-surface/40">
                <button onClick={() => setShowExpired((v) => !v)}
                  className="flex w-full items-center gap-2 px-4 py-2.5 text-[0.78rem] text-slate-400 transition hover:text-slate-200">
                  {showExpired ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
                  Expired
                  <span className="rounded-full bg-slate-600/40 px-2 py-0.5 text-[0.64rem] font-semibold">{expired.length}</span>
                  <span className="ml-auto text-[0.66rem] text-slate-600">past the approval window — can no longer execute</span>
                </button>
                {showExpired && <div className="space-y-3 p-3 pt-0">{expired.map((a) => <ApprovalCard key={a.id} a={a} expired />)}</div>}
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}

// ── Filter bar (AWS-console style) ────────────────────────────────────────────
function FilterBar({ f, setF, total, shown, onClear, hasFilter }: {
  f: Filters; setF: (f: Filters) => void; total: number; shown: number; onClear: () => void; hasFilter: boolean;
}) {
  const upd = (k: keyof Filters, v: string) => setF({ ...f, [k]: v } as Filters);
  return (
    <FilterShell right={<>
      <span><b className="text-slate-300">{shown}</b> / {total}</span>
      {hasFilter && <button onClick={onClear} className="text-brand hover:underline">clear</button>}
    </>}>
      <FilterField label="Endpoint (host / agent)"><TextFilter value={f.endpoint} onChange={(v) => upd("endpoint", v)} placeholder="ip-172-31… / 001" /></FilterField>
      <FilterField label="Target IP"><TextFilter value={f.ip} onChange={(v) => upd("ip", v)} placeholder="185.173.…" mono width="w-36" /></FilterField>
      <FilterField label="MITRE TTP"><TextFilter value={f.ttp} onChange={(v) => upd("ttp", v)} placeholder="T1071" mono width="w-28" /></FilterField>
      <FilterField label="Action"><Segmented value={f.action} onChange={(v) => upd("action", v)} options={["all", "block", "isolate"] as const} /></FilterField>
    </FilterShell>
  );
}

// ── Approval card ─────────────────────────────────────────────────────────────
function ApprovalCard({ a, expired }: { a: Approval; expired?: boolean }) {
  const decide = useDecideApproval();
  const result = decide.data;
  const isolate = a.action_type === "isolate";
  const [mode, setMode] = useState<"idle" | "approve" | "reject">("idle");
  const [confirmText, setConfirmText] = useState("");
  const [note, setNote] = useState("");
  // AWS-style: the analyst must type this exact string to enable the action.
  const token = (isolate ? (a.host_id || a.agent_id) : a.target_value) || a.action_type;

  return (
    <Card className={cn("border-l-2", isolate ? "border-l-fuchsia-500/60" : "border-l-rose-500/60", expired && "opacity-60")}>
      <div className="mb-3 flex flex-wrap items-center gap-2">
        <Badge tone={isolate ? "isolate" : "block"}>
          {isolate ? <Network className="h-3 w-3" /> : <ShieldX className="h-3 w-3" />} {a.action_type.toUpperCase()}
        </Badge>
        {(a.severity_label || a.severity != null) && <Badge tone="high">{a.severity_label || `SEV ${a.severity}`}</Badge>}
        {a.intel_malicious && <Badge tone="intel">intel: malicious</Badge>}
        <span className="text-[0.66rem] uppercase tracking-wider text-amber-400">{a.status}</span>
        {a.mins_left != null && (
          <span className={cn("ml-auto flex items-center gap-1 text-[0.72rem]", a.mins_left < 0 ? "text-slate-500" : a.mins_left <= 5 ? "font-semibold text-rose-300" : "text-slate-500")}>
            <Clock className="h-3 w-3" /> {a.mins_left >= 0 ? `~${a.mins_left} min` : "EXPIRED"}
          </span>
        )}
      </div>

      <div className="grid gap-2 text-[0.82rem] text-slate-300 sm:grid-cols-2">
        <Row label="Endpoint">{a.host_id || "—"} <span className="text-slate-500">· {a.agent_id || "?"}{a.host_ip ? ` · ${a.host_ip}` : ""}</span></Row>
        {!isolate && <Row label="Target IP"><code className="font-mono text-amber-300">{a.target_value || "—"}</code></Row>}
        <Row label="MITRE">{a.mitre_ttps?.join(", ") || "—"}</Row>
        {a.pred_proba != null && <Row label="Model conf.">{(a.pred_proba * 100).toFixed(0)}%</Row>}
      </div>

      <div className="mt-2.5 flex flex-wrap gap-3 text-[0.74rem]">
        {a.case_url && <a href={a.case_url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1 text-brand hover:underline"><ExternalLink className="h-3 w-3" /> TheHive case{a.case_id ? ` ${a.case_id}` : ""}</a>}
        {a.alert_id && <Link to={`/alert/${a.alert_id}`} className="text-brand hover:underline">alert #{a.alert_id}</Link>}
      </div>

      {expired ? (
        <div className="mt-3 text-[0.72rem] text-slate-500">Expired — can no longer be executed.</div>
      ) : result ? (
        <div className={cn("mt-3.5 rounded-lg p-3 text-[0.8rem]",
          result.ok ? "border border-emerald-500/40 bg-emerald-500/10 text-emerald-200"
          : result.kind === "conflict" ? "border border-amber-500/40 bg-amber-500/10 text-amber-200"
          : "border border-rose-500/40 bg-rose-500/10 text-rose-200")}>
          {result.ok ? <>Decision applied — <b>{result.status}</b>{result.ar_result ? <pre className="mt-1.5 whitespace-pre-wrap break-words font-mono text-[0.7rem] text-slate-400">{JSON.stringify(result.ar_result, null, 2)}</pre> : null}</>
            : (result.detail || "Failed.")}
        </div>
      ) : mode === "idle" ? (
        <div className="mt-4 flex gap-3">
          <button onClick={() => { setMode("approve"); setConfirmText(""); }}
            className="rounded-lg bg-emerald-600 px-4 py-2 text-sm font-semibold text-white shadow-glow transition hover:bg-emerald-500">Approve…</button>
          <button onClick={() => { setMode("reject"); setNote(""); }}
            className="rounded-lg border border-line bg-surface2 px-4 py-2 text-sm font-semibold text-slate-300 transition hover:border-rose-500/40 hover:text-rose-300">Reject…</button>
        </div>
      ) : mode === "approve" ? (
        <div className="mt-4 rounded-lg border border-rose-500/30 bg-rose-500/[0.06] p-3">
          <div className="text-[0.78rem] leading-relaxed text-slate-300">
            This runs the <b className="text-rose-300">REAL {a.action_type}</b> on <b>{a.host_id || a.agent_id}</b>.
            To confirm, type <code className="rounded bg-bg px-1.5 py-0.5 font-mono text-amber-300">{token}</code> below.
          </div>
          <div className="mt-2.5 flex gap-2">
            <input autoFocus value={confirmText} onChange={(e) => setConfirmText(e.target.value)} placeholder={token}
              onKeyDown={(e) => { if (e.key === "Enter" && confirmText.trim() === token) decide.mutate({ id: a.id, decision: "approve" }); }}
              className="flex-1 rounded-lg border border-line bg-bg px-2.5 py-1.5 font-mono text-[0.8rem] text-slate-200 outline-none transition focus:border-rose-500/50" />
            <button disabled={confirmText.trim() !== token || decide.isPending} onClick={() => decide.mutate({ id: a.id, decision: "approve" })}
              className="rounded-lg bg-emerald-600 px-4 py-1.5 text-sm font-semibold text-white transition hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-40">Confirm</button>
            <button onClick={() => setMode("idle")} className="rounded-lg border border-line px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
          </div>
        </div>
      ) : (
        <div className="mt-4 rounded-lg border border-line bg-surface2/40 p-3">
          <textarea autoFocus value={note} onChange={(e) => setNote(e.target.value)} rows={2} placeholder="Reason for rejection (optional)…"
            className="w-full rounded-lg border border-line bg-bg p-2 text-[0.82rem] text-slate-200 outline-none transition focus:border-brand/40" />
          <div className="mt-2 flex gap-2">
            <button onClick={() => decide.mutate({ id: a.id, decision: "reject", note })} disabled={decide.isPending}
              className="rounded-lg border border-rose-500/40 bg-rose-500/15 px-4 py-1.5 text-sm font-semibold text-rose-200 transition hover:bg-rose-500/25 disabled:opacity-40">Confirm Reject</button>
            <button onClick={() => setMode("idle")} className="rounded-lg border border-line px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200">Cancel</button>
          </div>
        </div>
      )}
    </Card>
  );
}

function Row({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <div className="flex gap-2">
      <span className="w-[72px] shrink-0 text-[0.62rem] uppercase tracking-[0.08em] text-slate-500">{label}</span>
      <span className="min-w-0 truncate">{children}</span>
    </div>
  );
}
