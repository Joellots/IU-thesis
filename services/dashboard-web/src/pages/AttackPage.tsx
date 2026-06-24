import { Link } from "react-router-dom";
import { Crosshair } from "lucide-react";
import { useAttack } from "../api/client";
import { Card, Spinner, ErrorState, cn } from "../components/ui";
import { PageHeader } from "./AlertsPage";

// The framework's fixed feature→class→TTP mapping (fmm-2.0.0).
const ATTACK = [
  {
    tactic: "Command and Control",
    blurb: "Large, low-variance encrypted payloads + programmatic TCP windows — automated beaconing.",
    techniques: [
      { id: "T1071", name: "Application Layer Protocol", sub: false },
      { id: "T1071.001", name: "Web Protocols", sub: true },
      { id: "T1573", name: "Encrypted Channel", sub: false },
    ],
  },
  {
    tactic: "Exfiltration",
    blurb: "Rapid, regular inter-arrival timing (low IAT) — sustained bulk upload over an encrypted channel.",
    techniques: [
      { id: "T1041", name: "Exfiltration Over C2 Channel", sub: false },
      { id: "T1048.002", name: "Exfil Over Asymmetric Encrypted Non-C2 Protocol", sub: true },
    ],
  },
] as const;

export default function AttackPage() {
  const { data: counts, isLoading, error } = useAttack();
  const values = Object.values(counts ?? {});
  const max = Math.max(1, ...values);
  const total = values.reduce((a, b) => a + b, 0);
  const nTech = ATTACK.reduce((n, t) => n + t.techniques.length, 0);

  return (
    <div>
      <PageHeader title="MITRE ATT&CK Coverage"
        subtitle="Validated feature→class→TTP mapping (fmm-2.0.0) — cells sized by mapped-alert count" />
      <div className="mx-auto max-w-4xl space-y-5 p-6">
        {isLoading ? <Spinner /> : error ? <ErrorState error={error} /> : (
          <>
            <div className="flex flex-wrap items-center gap-3 text-[0.78rem] text-slate-400">
              <Crosshair className="h-4 w-4 text-brand" />
              <span><b className="text-slate-200">{total}</b> mapped alerts across {nTech} techniques · 2 tactics</span>
              <span className="ml-auto flex items-center gap-2 text-[0.7rem] text-slate-500">
                low <span className="h-3 w-20 rounded bg-gradient-to-r from-rose-500/15 to-rose-500/70" /> high
              </span>
            </div>

            <div className="grid gap-5 md:grid-cols-2">
              {ATTACK.map((col) => (
                <Card key={col.tactic} title={col.tactic}>
                  <p className="-mt-2 mb-3 text-[0.72rem] italic text-slate-500">{col.blurb}</p>
                  <div className="space-y-2">
                    {col.techniques.map((t) => {
                      const n = counts?.[t.id] ?? 0;
                      const intensity = n ? 0.12 + 0.55 * (n / max) : 0;
                      return (
                        <Link key={t.id} to={`/?ttp=${t.id}`}
                          className={cn("flex items-center gap-3 rounded-lg border p-3 transition hover:border-brand/50 hover:shadow-glow",
                            t.sub && "ml-5", n ? "border-rose-500/30" : "border-line")}
                          style={n ? { background: `rgba(244,63,94,${intensity})` } : undefined}>
                          <div className="min-w-0 flex-1">
                            <div className="font-mono text-[0.84rem] font-semibold text-white">
                              {t.id}{t.sub && <span className="ml-1.5 text-[0.58rem] font-normal uppercase tracking-wider text-slate-400">sub</span>}
                            </div>
                            <div className="truncate text-[0.74rem] text-slate-300">{t.name}</div>
                          </div>
                          <div className="text-right">
                            <div className="kpi-num text-xl text-white">{n}</div>
                            <div className="text-[0.56rem] uppercase tracking-wider text-slate-400">alerts</div>
                          </div>
                        </Link>
                      );
                    })}
                  </div>
                </Card>
              ))}
            </div>
            <p className="text-center text-[0.72rem] text-slate-500">Click a technique to filter the alert queue by that TTP.</p>
          </>
        )}
      </div>
    </div>
  );
}
