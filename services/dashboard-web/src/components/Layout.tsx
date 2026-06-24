import { NavLink, Outlet } from "react-router-dom";
import { ShieldHalf, Radar, ListChecks, BarChart3, Crosshair, Server } from "lucide-react";
import { useSummary } from "../api/client";
import { useLive } from "../api/live";
import { cn, PulseDot } from "./ui";

function NavItem({ to, icon, label, badge }: { to: string; icon: React.ReactNode; label: string; badge?: number }) {
  return (
    <NavLink to={to} end
      className={({ isActive }) =>
        cn("group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-all",
          isActive ? "bg-brand/10 text-white" : "text-slate-400 hover:bg-white/5 hover:text-slate-100")
      }>
      {({ isActive }) => (
        <>
          <span className={cn("absolute left-0 h-5 w-[3px] rounded-r bg-brand transition-opacity", isActive ? "opacity-100" : "opacity-0")} />
          <span className={cn(isActive ? "text-brand" : "text-slate-500 group-hover:text-slate-300")}>{icon}</span>
          <span className="flex-1 font-medium">{label}</span>
          {badge ? <span className="rounded-full bg-rose-500/20 px-2 text-[0.68rem] font-bold text-rose-300 ring-1 ring-inset ring-rose-500/40">{badge}</span> : null}
        </>
      )}
    </NavLink>
  );
}

export default function Layout() {
  const { data: s } = useSummary();
  const connected = useLive();
  return (
    <div className="app-shell flex h-full">
      <aside className="flex w-64 shrink-0 flex-col border-r border-line bg-surface/70 backdrop-blur">
        <div className="flex items-center gap-3 px-5 py-5">
          <div className="grid h-9 w-9 place-items-center rounded-lg bg-brand-grad shadow-glow">
            <ShieldHalf className="h-5 w-5 text-white" />
          </div>
          <div>
            <div className="text-[1.05rem] font-extrabold leading-none tracking-tight text-white">Aegis</div>
            <div className="mt-0.5 text-[0.62rem] uppercase tracking-[0.18em] text-slate-500">Threat Ops</div>
          </div>
        </div>

        <nav className="flex flex-col gap-1 px-3">
          <NavItem to="/" icon={<Radar className="h-[18px] w-[18px]" />} label="Alerts" />
          <NavItem to="/approvals" icon={<ListChecks className="h-[18px] w-[18px]" />} label="Approvals" badge={s?.pending_approvals} />
          <NavItem to="/endpoints" icon={<Server className="h-[18px] w-[18px]" />} label="Endpoints" />
          <NavItem to="/attack" icon={<Crosshair className="h-[18px] w-[18px]" />} label="ATT&CK" />
          <NavItem to="/metrics" icon={<BarChart3 className="h-[18px] w-[18px]" />} label="Metrics" />
        </nav>

        <div className="mt-auto space-y-3 border-t border-line p-4">
          {s && (
            <div className="grid grid-cols-2 gap-2 text-center">
              <div className="rounded-lg bg-surface2 p-2">
                <div className="kpi-num text-lg text-rose-300">{s.malicious_detected}</div>
                <div className="text-[0.58rem] uppercase tracking-wider text-slate-500">malicious</div>
              </div>
              <div className="rounded-lg bg-surface2 p-2">
                <div className="kpi-num text-lg text-white">{s.total_flows}</div>
                <div className="text-[0.58rem] uppercase tracking-wider text-slate-500">flows</div>
              </div>
            </div>
          )}
          <div className="flex items-center gap-2 text-[0.66rem] text-slate-500">
            <PulseDot tone={connected ? "emerald" : "rose"} />
            {connected ? "live · websocket" : "reconnecting…"}
          </div>
        </div>
      </aside>

      <main className="flex-1 overflow-y-auto">
        <Outlet />
      </main>
    </div>
  );
}
