import {
  useQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import type {
  Summary,
  AlertRow,
  AlertDetail,
  Approval,
  ApprovalResult,
  Metrics,
  AttackCounts,
  Endpoint,
  MappingStats,
  FeedbackPayload,
} from "./types";

// Same-origin: nginx (prod) / Vite proxy (dev) forwards /api to the FastAPI backend.
async function getJSON<T>(path: string): Promise<T> {
  const res = await fetch(`/api${path}`);
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

async function postJSON<T>(path: string, body: unknown): Promise<T> {
  const res = await fetch(`/api${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok && res.status >= 500) throw new Error(`${res.status} ${res.statusText}`);
  return (await res.json()) as T;
}

// ── Queries ──────────────────────────────────────────────────────────────────
export const useSummary = () =>
  useQuery({ queryKey: ["summary"], queryFn: () => getJSON<Summary>("/summary") });

export const useAlerts = (maliciousOnly: boolean) =>
  useQuery({
    queryKey: ["alerts", maliciousOnly],
    queryFn: () =>
      getJSON<AlertRow[]>(`/alerts?malicious_only=${maliciousOnly}&limit=200`),
  });

export const useAlert = (id: number) =>
  useQuery({
    queryKey: ["alert", id],
    queryFn: () => getJSON<AlertDetail>(`/alerts/${id}`),
    refetchInterval: false,
  });

export const useApprovals = () =>
  useQuery({ queryKey: ["approvals"], queryFn: () => getJSON<Approval[]>("/approvals") });

export const useMetrics = () =>
  useQuery({
    queryKey: ["metrics"],
    queryFn: () => getJSON<Metrics>("/metrics"),
    refetchInterval: 6000,
  });

export const useAttack = () =>
  useQuery({
    queryKey: ["attack"],
    queryFn: () => getJSON<AttackCounts>("/attack"),
  });

export const useEndpoints = () =>
  useQuery({ queryKey: ["endpoints"], queryFn: () => getJSON<Endpoint[]>("/endpoints") });

export const useMapping = () =>
  useQuery({ queryKey: ["mapping"], queryFn: () => getJSON<MappingStats>("/mapping") });

// ── Mutations ────────────────────────────────────────────────────────────────
export function useDecideApproval() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (vars: { id: number; decision: "approve" | "reject"; note?: string }) =>
      postJSON<ApprovalResult>(`/approvals/${vars.id}/decide`, {
        decision: vars.decision,
        note: vars.note ?? "",
      }),
    onSettled: () => qc.invalidateQueries({ queryKey: ["approvals"] }),
  });
}

export function useSubmitFeedback(alertId: number) {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: (payload: FeedbackPayload) =>
      postJSON<{ ok: boolean; verdict: string }>(`/alerts/${alertId}/feedback`, payload),
    onSettled: () => {
      qc.invalidateQueries({ queryKey: ["alert", alertId] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
    },
  });
}
