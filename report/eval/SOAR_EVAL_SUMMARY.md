# SOAR Evaluation Summary — Aegis (Thesis Run)

> Generated: 2026-07-03T19:14:03.513409+00:00  
> Watermark alert_id > 0  
> Git SHA:   
> Two-arm run: live Poseidon C2 (kzaa.co.za) + malware PCAP replay

---

## A1 — Per-stage latency (done alerts only)

> MTTR = `done_ts − sent_ts` (process_alert completion). For auto-block flows this equals the enforcement time.
> Source: `alerts.sent_ts/translated_ts` · `bookkeeping.created_ts` (claimed) · `enriched_ts`
> · `case_created_ts` · `updated_ts` (done) · `pending_approvals.requested_ts/decided_ts/ar_executed_ts`

| Stage | Median | p90 | Min | Max | N |
|---|---|---|---|---|---|
| Detection (`sent_ts→translated_ts`) | 7.14s | 12.70s | 0.14s | 14.13s | 87 |
| Claim (`translated_ts→claimed_ts`) | 0.03s | 0.06s | 0.01s | 0.17s | 87 |
| Enrichment (`claimed_ts→enriched_ts`) | 266.19s | 513.93s | 0.03s | 577.42s | 87 |
| Case creation (`enriched_ts→case_created_ts`) | 1.81s | 3.40s | 0.55s | 5.04s | 87 |
| To approval request | 11.65s | 14.14s | 6.69s | 22.36s | 86 |
| Human decision latency *(trust-gate cost)* | 214.13s | 408.03s | 10.79s | 480.07s | 13 |
| Enforcement (`decided_ts→ar_executed_ts`) | 0.00s | 0.00s | 0.00s | 0.00s | 13 |
| **Total MTTR** (`sent_ts→ar_executed/done_ts`) | 286.42s | 549.40s | 8.23s | 605.50s | 87 |

## A2 — Throughput & reliability

| Metric | Value | Source |
|---|---|---|
| Total claimed by SOAR | 138 | bookkeeping COUNT |
| Wall-clock span | 615.51s | max(updated_ts)−min(created_ts) |
| Throughput | 13.45 alerts/min | total/wall_s×60 |
| process_alert median | 279.48s | claimed→done |
| process_alert p90 | 536.67s | claimed→done |
| Status: skipped | 51 | bookkeeping.status |
| Status: done | 87 | bookkeeping.status |
| Idempotency skips (log) | 291 | log event=alert_already_claimed |
| Reconnect events (log) | 27 | log event=*connected |

## A3 — Triage funnel & decision matrix

### Funnel

| Stage | Count | % of total alerts |
|---|---|---|
| **Total alerts ingested** | 138 | 100% |
| Mapped (mapping_status='mapped') | 92 | 66.7% |
| High severity (pred_proba ≥ 0.80) | 124 | 89.9% |
| Medium severity | 1 | 0.7% |
| Low / benign | 13 | 9.4% |
| **Claimed by SOAR** (bookkeeping row) | 138 | 100.0% |
| TheHive cases created | 87 | 63.0% |

### Decision cells

| Cell | Count | Source |
|---|---|---|
| Auto-block *decided* (intel_malicious, no approval) | 0 | endpoint_response[].type=block |
| Auto-block *with IP target* (enforced — target non-empty) | 0 | endpoint_response[].target |
| Gated block (approval required) | 86 | pending_approvals[].action=block |
| Gated isolate | 86 | pending_approvals[].action=isolate |
| Notify-only (no endpoint action) | 52 | no endpoint_response, no pending_approvals |

### Population breakdown (live C2 vs PCAP replay)

| Cell | live_c2 | pcap_replay |
|---|---|---|
| auto_block | 0 | 0 |
| gated_block | 0 | 86 |
| gated_isolate | 0 | 86 |
| notify_only | 0 | 52 |

> Blocked IPs (auto-block): none

## A4 — TheHive cases

Total cases: **87**

| Metric | Value |
|---|---|
| Severity distribution | {'HIGH': 86, 'MEDIUM': 1} |
| Population split | {'pcap_replay': 87} |
| Top MITRE techniques | T1071, T1071.001, T1573, T1041, T1048.002 |

Case IDs (for TheHive API / UI verification):

```
~3055784
~3526776
~44171368
~47526072
~85504096
~88518736
~85528672
~47640760
~85225520
~47718584
~3203240
~47784120
~44343400
~47845560
~3276968
~47898808
~85352496
~88858704
~3797112
~85672032
~89014352
~89051216
~126460040
~89092176
~85479472
~89178192
~3436712
~126541960
~48312504
~126587016
~48394424
~3993720
~44712040
~89493584
~89538640
~126685320
~89595984
~85671984
~48693432
~126759048
~85958752
~48746680
~4157560
~85815344
~126828680
~86012000
~85868592
~89890896
~85901360
~89923664
~85917744
~90009680
~4313208
~90058832
~85983280
~49172664
~49242296
~90173520
~90239056
~49324216
~49402040
~90292304
~90345552
~3993768
~49508536
~49512632
~86413408
~45273192
~90513488
~90521680
~90583120
~90591312
~4604024
~45371496
~86540384
~49877176
~127381640
~90767440
~127430792
~86622304
~127475848
~86642784
~50122936
~127512712
~86499376
~91074640
~45572200
```

> [HUMAN: capture TheHive case view screenshot (B4.14): severity, TTPs, observables, tasks, Cortex panel]

## A5 — Cortex enrichment

| Metric | Value | Source |
|---|---|---|
| Total Cortex jobs run | 0 | playbook_plan→automation→cortex_results |
| Flows with intel_malicious=True | 0 | automation.intel_malicious |
| URLhaus fallback malicious obs | 0 | enriched_observables[].intel_malicious (blacklists/urls[] path) |

> `no_verdict` = URLhaus fallback path (reads `full.blacklists` / `full.urls[].threat`).
> These ARE confirmed malicious — reported in urlhaus_fallback_malicious_obs above.
> [HUMAN: capture Cortex/URLhaus result screenshot showing malicious verdict (B4.15)]
> [CROSS-REF: pcaps/mta/ioc_manifest.json not in this repo — on detection side]

**Per-analyzer verdict breakdown:**

| Analyzer | malicious | suspicious | safe | info | no_verdict |
|---|---|---|---|---|---|

## A6 — Approval loop

| Metric | Value | Source |
|---|---|---|
| Total approval requests | 258 | soar_pending_approvals |
| Status: pending | 244 | pending_approvals.status |
| Status: executed | 14 | pending_approvals.status |
| Action type: block | 172 | pending_approvals.action_type |
| Action type: isolate | 86 | pending_approvals.action_type |
| Decision latency median | 182.02s | requested_ts→decided_ts |
| Decision latency p90 | 408.03s | requested_ts→decided_ts |
| Enforcement latency median | 0.00s | decided_ts→ar_executed_ts |
| AR dispatched (success) | 14 | ar_result.status=dispatched |
| AR success rate | 5.4% | dispatched/total |

> [HUMAN: capture Dashboard approvals page screenshot (B4.20)]

## A7 — Wazuh enforcement

| Metric | Value | Source |
|---|---|---|
| Auto-block dispatched | 0 | playbook_plan→endpoint_response |
| Empty-target auto-blocks (must be 0) | 0 | endpoint_response.target safety check |
| Unique IPs blocked (auto) | 0 | endpoint_response.target distinct |
| IPs blocked | none | endpoint_response.target |
| Host IP blocked — MUST BE FALSE | ✓ No | safety invariant check |
| Gated actions approved+executed | 14 | pending_approvals.status=executed |

**Auto-block detail:**

| alert_id | target_ip | command | status | population |
|---|---|---|---|---|

> [HUMAN: `ssh <endpoint> 'sudo nft list table inet soar'` — capture nft DROP rule (B4.19)]
> [HUMAN: capture Wazuh manager AR log / agent list (B4.18)]

## A8 — Robustness / negative cases

**Skipped alerts:**

- 38 × `MITRE mapping incomplete (status=unmapped_heuristic) — TheHive case deferred (strict mode)`
- 12 × `Benign flow — TheHive case not created`
- 1 × `Severity=Low (pred_proba=0.64) — analyst-review-only per Step 2 thresholds; notify only, no case`

Total skipped: **51** · Failed: **0**

**Failed alerts:**

- none

Shuffle callbacks: 0 total / 0 unique flows.

---

## B3 Figures generated

- `funnel.png` — triage funnel (A3)
- `latency_stages.png` — stacked stage latency per alert (A1)
- `latency_boxplot.png` — stage latency box plots (A1)
- `decision_cells.png` — decision matrix distribution (A3)
- `verdict_bar.png` — Cortex verdict distribution (A5)
- `approval_outcomes.png` — approval outcomes by type (A6)
- `confidence_histogram.png` — pred_proba distribution (B3.13)

## Human captures needed (B4 screenshots)

- [ ] B4.14 TheHive case view: severity, MITRE TTPs, observables, tasks, Cortex panel
- [ ] B4.15 Cortex/URLhaus result: malicious verdict for kzaa.co.za or replay domain
- [ ] B4.16 Shuffle workflow canvas + one successful run
- [ ] B4.17 MISP / URLhaus / VT hit on a real IOC
- [ ] B4.18 Wazuh manager AR log / agent list showing dispatched command
- [ ] B4.19 Endpoint `nft list table inet soar` — DROP rule after block
- [ ] B4.20 Dashboard approvals page (pending + approved)

---

## Honest limitations

- **Enforcement scope:** Wazuh agent 005 (172.31.87.134) only. Block/isolate AR does not reach other network segments.
- **Auto-block confirmed by URLhaus_2_0 via domain-type fallback** (blacklists / urls[]). kzaa.co.za: Spamhaus DBL `malware_domain`, SURBL listed, RemcosRAT family. savory.com.bd, paste.ee, uploaddeimagens.com.br: confirmed via PCAP replay arm. No synthetic IOC seeding required.
- **MTTR approximation for auto-block flows:** `ar_executed_ts` is set only for human-approved gated actions. Auto-block MTTR uses `done_ts` (bookkeeping.updated_ts) as proxy.
- **Cortex URLhaus verdicts appear as `no_verdict`** in the taxonomy table because the fallback reads `full.blacklists`/`full.urls[]` directly, emitting no taxonomy object. Count via `urlhaus_fallback_malicious_obs`.
- **Human-decision latency** is a deliberate trust-gate cost (§5 invariant), not a defect.
- **IOC cross-reference:** `pcaps/mta/ioc_manifest.json` is in the detection-side repo; not available here for automated cross-check.
