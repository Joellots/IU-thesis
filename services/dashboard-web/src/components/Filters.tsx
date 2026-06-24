import type { ReactNode } from "react";
import { Search } from "lucide-react";
import { cn } from "./ui";

/** The filter-bar panel; pass fields as children and an optional right-side count. */
export function FilterShell({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="panel p-3">
      <div className="flex flex-wrap items-end gap-3">
        {children}
        {right && <div className="ml-auto flex items-center gap-3 text-[0.72rem] text-slate-500">{right}</div>}
      </div>
    </div>
  );
}

export function FilterField({ label, children }: { label: string; children: ReactNode }) {
  return (
    <label className="flex flex-col gap-1">
      <span className="text-[0.58rem] uppercase tracking-[0.1em] text-slate-500">{label}</span>
      {children}
    </label>
  );
}

export function TextFilter({ value, onChange, placeholder, mono, width = "w-44" }: {
  value: string; onChange: (v: string) => void; placeholder?: string; mono?: boolean; width?: string;
}) {
  return (
    <div className="relative">
      <Search className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate-600" />
      <input value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        className={cn("rounded-lg border border-line bg-bg py-1.5 pl-7 pr-2 text-[0.8rem] text-slate-200 outline-none transition focus:border-brand/50", width, mono && "font-mono")} />
    </div>
  );
}

/** Generic segmented control over a string union. `labels` optionally prettifies options. */
export function Segmented<T extends string>({ value, onChange, options, labels }: {
  value: T; onChange: (v: T) => void; options: readonly T[]; labels?: Partial<Record<T, string>>;
}) {
  return (
    <div className="flex rounded-lg border border-line bg-bg p-0.5">
      {options.map((o) => (
        <button key={o} onClick={() => onChange(o)}
          className={cn("rounded-md px-2.5 py-1 text-[0.72rem] capitalize transition", value === o ? "bg-brand/20 text-white" : "text-slate-400 hover:text-slate-200")}>
          {labels?.[o] ?? o}
        </button>
      ))}
    </div>
  );
}
