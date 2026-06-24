// Shapes returned by the FastAPI dashboard JSON API (services/dashboard/main.py).

export interface Summary {
  total_flows: number;
  malicious_detected: number;
  benign_detected: number;
  pending_approvals: number;
}

export interface AlertRow {
  id: number;
  flow_id: string;
  translated_ts: string | null;
  pred_label: number;
  pred_proba: number;
  severity: number | null;
  severity_label: string | null;
  mitre_ttps: string[] | null;
  top_k_features: string | null;
  analyst_decision: string | null;
  model: string;
  tier: string;
  true_label: number | null;
  agent_id: string | null;
  host_id: string | null;
}

export type AttackCounts = Record<string, number>;

export interface TopKFeature {
  feature: string;
  value: number;
  contribution: number;
  direction: string; // "positive" | "negative"
}

export interface Observable {
  type: string; // ip | domain | url | ja3
  value: string;
  role?: string; // src | dst
}

export interface AlertDetail extends AlertRow {
  sent_ts: string | null;
  inferred_ts: string | null;
  explain_time_ms: number | null;
  annotation: string | null;
  mitre_names: string[] | null;
  top_k_json: TopKFeature[] | null;
  observables: Observable[] | null;
  mapping_status: string | null;
  mapping_confidence: number | null;
  mapping_version: string | null;
  mapping_reason: string | null;
  agent_id: string | null;
  host_id: string | null;
  host_ip: string | null;
  explanation_useful: boolean | null;
  flag_for_retraining: boolean | null;
  analyst_note: string | null;
  soar_actions?: SoarAction[];
}

export interface SoarAction {
  id: number;
  action_type: string;          // block | isolate
  target_value: string | null;
  status: string;               // pending | executed | rejected | failed | expired
  case_id: string | null;
  case_url: string | null;
  requested_ts: string | null;
  decided_ts: string | null;
  analyst: string | null;
  note: string | null;
}

export interface Endpoint {
  host_id: string | null;
  agent_id: string | null;
  host_ip: string | null;
  alerts: number;
  malicious: number;
  last_seen: string | null;
  pending: number;
}

export interface MappingStats {
  by_status: Record<string, { n: number; avg_conf: number | null }>;
  histogram: number[];
  avg_mapped: number | null;
}

export interface Approval {
  id: number;
  alert_id: number | null;
  flow_id: string | null;
  agent_id: string | null;
  action_type: string; // block | isolate
  target_value: string | null;
  case_id: string | null;
  case_url: string | null;
  severity: number | string | null;
  severity_label?: string | null;
  mitre_ttps: string[] | null;
  intel_malicious: boolean | null;
  status: string;
  requested_ts: string | null;
  expires_ts: string | null;
  decided_ts: string | null;
  analyst: string | null;
  note: string | null;
  ar_result: unknown;
  host_id: string | null;
  host_ip: string | null;
  pred_proba: number | null;
  annotation: string | null;
  mins_left: number | null;
}

export interface ApprovalResult {
  ok: boolean;
  kind?: string; // ok | conflict | config | notfound | unreachable | error
  status?: string; // executed | failed | rejected (when ok)
  ar_result?: unknown;
  detail?: string;
}

export interface Metrics {
  total_flows: number;
  malicious_detected: number;
  benign_detected: number;
  tier2_trigger_count: number;
  tier2_trigger_rate: number;
  avg_explain_ms: number | null;
  avg_pipeline_ms: number | null;
  analyst_decisions: Record<string, number>;
  confusion_matrix: { tp: number; fp: number; tn: number; fn: number };
}

export interface FeedbackPayload {
  decision: "true_positive" | "false_positive";
  note?: string;
  explanation_useful?: boolean;
  flag_for_retraining?: boolean;
}
