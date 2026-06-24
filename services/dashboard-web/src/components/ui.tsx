import type { ReactNode } from "react";

export function cn(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(" ");
}

// ── Panels ─────────────────────────────────────────────────────────────────
export function Card({ title, action, children, className }: {
  title?: string; action?: ReactNode; children: ReactNode; className?: string;
}) {
  return (
    <section className={cn("panel p-5 animate-fade-in", className)}>
      {(title || action) && (
        <div className="mb-4 flex items-center justify-between">
          {title && <h2 className="text-[0.7rem] font-semibold uppercase tracking-[0.12em] text-slate-400">{title}</h2>}
          {action}
        </div>
      )}
      {children}
    </section>
  );
}

// ── Badges ───────────────────────────────────────────────────────────────────
type Tone = "high" | "medium" | "low" | "benign" | "muted" | "brand" | "tp" | "fp" | "block" | "isolate" | "intel";
const TONES: Record<Tone, string> = {
  high:    "bg-rose-500/15 text-rose-300 ring-1 ring-inset ring-rose-500/40",
  medium:  "bg-amber-500/15 text-amber-300 ring-1 ring-inset ring-amber-500/40",
  low:     "bg-emerald-500/15 text-emerald-300 ring-1 ring-inset ring-emerald-500/40",
  benign:  "bg-slate-500/10 text-slate-400 ring-1 ring-inset ring-slate-500/30",
  muted:   "bg-slate-500/15 text-slate-300 ring-1 ring-inset ring-slate-600/50",
  brand:   "bg-brand/15 text-brand ring-1 ring-inset ring-brand/40",
  tp:      "bg-rose-500/15 text-rose-300 ring-1 ring-inset ring-rose-500/30",
  fp:      "bg-emerald-500/15 text-emerald-300 ring-1 ring-inset ring-emerald-500/30",
  block:   "bg-rose-500/15 text-rose-300 ring-1 ring-inset ring-rose-500/40",
  isolate: "bg-fuchsia-500/15 text-fuchsia-300 ring-1 ring-inset ring-fuchsia-500/40",
  intel:   "bg-rose-500/20 text-rose-200 ring-1 ring-inset ring-rose-500/40",
};

export function Badge({ children, tone = "muted", className }: { children: ReactNode; tone?: Tone; className?: string }) {
  return <span className={cn("inline-flex items-center gap-1 whitespace-nowrap rounded-md px-2 py-0.5 text-[0.68rem] font-semibold", TONES[tone], className)}>{children}</span>;
}

const SEV_TONE = (label?: string | null): Tone => {
  const l = (label || "").toLowerCase();
  return l === "high" ? "high" : l === "medium" ? "medium" : l === "low" ? "low" : "muted";
};
export function SeverityBadge({ label }: { label?: string | null }) {
  return <Badge tone={SEV_TONE(label)}>{label || "—"}</Badge>;
}

export function VerdictBadge({ decision }: { decision?: string | null }) {
  if (!decision || decision === "pending") return <Badge tone="muted">pending</Badge>;
  if (decision === "true_positive" || decision === "confirmed") return <Badge tone="tp">true positive</Badge>;
  if (decision === "false_positive" || decision === "dismissed") return <Badge tone="fp">false positive</Badge>;
  return <Badge tone="muted">{decision}</Badge>;
}

export function PulseDot({ tone = "brand" }: { tone?: "brand" | "rose" | "emerald" }) {
  const c = tone === "rose" ? "bg-rose-400" : tone === "emerald" ? "bg-emerald-400" : "bg-brand";
  return <span className={cn("inline-block h-2 w-2 rounded-full animate-pulse-dot", c)} />;
}

// ── KPI stat tile ─────────────────────────────────────────────────────────────
export function StatCard({ label, value, accent, icon, sub }: {
  label: string; value: ReactNode; accent?: string; icon?: ReactNode; sub?: ReactNode;
}) {
  return (
    <div className="panel relative overflow-hidden p-4">
      <div className="flex items-start justify-between">
        <div className="text-[0.64rem] font-medium uppercase tracking-[0.1em] text-slate-500">{label}</div>
        {icon && <div className="text-slate-600">{icon}</div>}
      </div>
      <div className={cn("kpi-num mt-2 text-3xl", accent || "text-white")}>{value}</div>
      {sub && <div className="mt-1 text-[0.7rem] text-slate-500">{sub}</div>}
    </div>
  );
}

// ── Radial gauge (0..1) ───────────────────────────────────────────────────────
export function Gauge({ value, size = 132, caption }: { value: number; size?: number; caption?: string }) {
  const v = Math.max(0, Math.min(1, value || 0));
  const stroke = 12;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const color = v >= 0.85 ? "#fb7185" : v >= 0.6 ? "#fbbf24" : "#34d399";
  return (
    <div className="relative inline-flex items-center justify-center" style={{ width: size, height: size }}>
      <svg width={size} height={size} className="-rotate-90">
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#1b2230" strokeWidth={stroke} />
        <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke={color} strokeWidth={stroke}
          strokeLinecap="round" strokeDasharray={`${c * v} ${c}`}
          style={{ transition: "stroke-dasharray 0.6s ease, stroke 0.4s ease", filter: `drop-shadow(0 0 6px ${color}66)` }} />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="kpi-num text-2xl" style={{ color }}>{(v * 100).toFixed(0)}%</span>
        {caption && <span className="text-[0.62rem] uppercase tracking-wider text-slate-500">{caption}</span>}
      </div>
    </div>
  );
}

// ── Donut (malicious vs benign) ───────────────────────────────────────────────
export function Donut({ a, b, size = 120, labelA = "malicious", labelB = "benign" }: {
  a: number; b: number; size?: number; labelA?: string; labelB?: string;
}) {
  const total = a + b || 1;
  const stroke = 14;
  const r = (size - stroke) / 2;
  const c = 2 * Math.PI * r;
  const aLen = (a / total) * c;
  return (
    <div className="flex items-center gap-4">
      <div className="relative" style={{ width: size, height: size }}>
        <svg width={size} height={size} className="-rotate-90">
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#34d399" strokeWidth={stroke} />
          <circle cx={size / 2} cy={size / 2} r={r} fill="none" stroke="#fb7185" strokeWidth={stroke}
            strokeDasharray={`${aLen} ${c}`} style={{ transition: "stroke-dasharray 0.6s ease" }} />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="kpi-num text-xl text-white">{total}</span>
          <span className="text-[0.6rem] uppercase tracking-wider text-slate-500">flows</span>
        </div>
      </div>
      <div className="space-y-1 text-[0.78rem]">
        <div className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm bg-rose-400" /> {labelA} <span className="text-slate-500">· {a}</span></div>
        <div className="flex items-center gap-2"><span className="h-2.5 w-2.5 rounded-sm bg-emerald-400" /> {labelB} <span className="text-slate-500">· {b}</span></div>
      </div>
    </div>
  );
}

// ── States ────────────────────────────────────────────────────────────────────
export function Spinner({ label = "Loading…" }: { label?: string }) {
  return <div className="flex items-center gap-2 p-8 text-sm text-slate-500"><span className="h-4 w-4 animate-spin rounded-full border-2 border-slate-700 border-t-brand" />{label}</div>;
}
export function EmptyState({ children }: { children: ReactNode }) {
  return <div className="rounded-xl border border-dashed border-line bg-surface/40 p-10 text-center text-sm text-slate-500">{children}</div>;
}
export function ErrorState({ error }: { error: unknown }) {
  const msg = error instanceof Error ? error.message : String(error);
  return <div className="rounded-xl border border-rose-500/40 bg-rose-500/10 p-4 text-sm text-rose-300">Failed to load — {msg}</div>;
}

// ── helpers ────────────────────────────────────────────────────────────────────
export function fmtTime(ts: string | null | undefined): string {
  if (!ts) return "—";
  const d = new Date(ts);
  return isNaN(d.getTime()) ? String(ts) : d.toLocaleTimeString();
}
export function pct(x: number | null | undefined): string {
  return x == null ? "—" : `${(x * 100).toFixed(0)}%`;
}
