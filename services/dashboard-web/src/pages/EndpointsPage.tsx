import { Link } from "react-router-dom";
import { Server, ShieldAlert, ListChecks } from "lucide-react";
import { useEndpoints } from "../api/client";
import { Card, Badge, Spinner, ErrorState, EmptyState, fmtTime, cn } from "../components/ui";
import { PageHeader } from "./AlertsPage";

export default function EndpointsPage() {
  const { data, isLoading, error } = useEndpoints();
  const rows = data ?? [];
  return (
    <div>
      <PageHeader title="Endpoints" subtitle="Hosts that produced flows (Wazuh agents / sensors) — alert & response activity" />
      <div className="mx-auto max-w-4xl space-y-4 p-6">
        {isLoading ? <Spinner /> : error ? <ErrorState error={error} /> : rows.length === 0 ? (
          <EmptyState>No endpoint-identified flows yet. Run <code className="text-amber-300">detctl sim &lt;agent_id&gt;</code> (replay-as-endpoint) so flows carry an agent identity.</EmptyState>
        ) : (
          <div className="grid gap-3 sm:grid-cols-2">
            {rows.map((e, i) => (
              <Card key={i}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex min-w-0 items-center gap-2.5">
                    <div className="grid h-9 w-9 shrink-0 place-items-center rounded-lg bg-brand/15 text-brand"><Server className="h-4 w-4" /></div>
                    <div className="min-w-0">
                      <div className="truncate font-semibold text-white">{e.host_id || "—"}</div>
                      <div className="truncate text-[0.7rem] text-slate-500">agent {e.agent_id || "?"}{e.host_ip ? ` · ${e.host_ip}` : ""}</div>
                    </div>
                  </div>
                  {e.pending > 0 && <Badge tone="medium"><ListChecks className="h-3 w-3" /> {e.pending} pending</Badge>}
                </div>

                <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                  <Stat label="alerts" value={e.alerts} />
                  <Stat label="malicious" value={e.malicious} tone="text-rose-300" />
                  <Stat label="last seen" value={fmtTime(e.last_seen)} small />
                </div>

                <Link to={`/?endpoint=${encodeURIComponent(e.host_id || e.agent_id || "")}`}
                  className="mt-3 inline-flex items-center gap-1 text-[0.74rem] text-brand hover:underline">
                  <ShieldAlert className="h-3 w-3" /> view alerts
                </Link>
              </Card>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function Stat({ label, value, tone, small }: { label: string; value: React.ReactNode; tone?: string; small?: boolean }) {
  return (
    <div className="rounded-lg bg-surface2/50 py-2">
      <div className={cn(small ? "text-[0.72rem]" : "kpi-num text-lg", tone || "text-white")}>{value}</div>
      <div className="text-[0.56rem] uppercase tracking-wider text-slate-500">{label}</div>
    </div>
  );
}
