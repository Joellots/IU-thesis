"""Tests for automated TheHive case actions."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from case_automation import (  # noqa: E402
    annotate_observable_intel,
    derive_intel_verdict,
    normalize_pattern_ids,
    should_run_responders,
    run_pre_case_enrichment,
    _summarize_cortex_job,
)


def test_normalize_pattern_ids_dedupes():
    assert normalize_pattern_ids(["T1071", "T1071.001", "T1071"]) == [
        "T1071",
        "T1071.001",
    ]


def test_should_run_responders_when_auto_enabled(monkeypatch):
    monkeypatch.setenv("AUTO_RUN_RESPONDERS", "true")
    assert should_run_responders({"pred_label": 1, "severity_label": "LOW"}) is True


def test_should_run_responders_legacy_severity_gate(monkeypatch):
    monkeypatch.setenv("AUTO_RUN_RESPONDERS", "false")
    monkeypatch.setenv("RUN_RESPONDERS_ON_ALL", "false")
    monkeypatch.setenv("FORCE_ACTIVE_RESPONSE", "false")
    assert should_run_responders({"pred_label": 1, "severity_label": "LOW"}) is False
    assert should_run_responders({"pred_label": 1, "severity_label": "HIGH"}) is True


def _verdict(analyzer, verdict):
    return {"analyzer_name": analyzer, "observable_value": "x", "observable_type": "ip", "verdict": verdict, "taxonomies": ""}


def test_intel_malicious_requires_a_confirmation_analyzer(monkeypatch):
    monkeypatch.delenv("INTEL_CONFIRMATION_ANALYZERS", raising=False)
    # A non-trusted analyzer flagging "malicious" is not enough on its own.
    malicious, score = derive_intel_verdict([_verdict("Some_Heuristic_1_0", "malicious")])
    assert malicious is False
    assert score == 1.0  # still counts toward the softer intel_score signal


def test_intel_malicious_true_on_single_trusted_positive(monkeypatch):
    monkeypatch.delenv("INTEL_CONFIRMATION_ANALYZERS", raising=False)
    malicious, score = derive_intel_verdict(
        [_verdict("VirusTotal_GetReport_3_1", "malicious"), _verdict("Abuse_Finder_3_0", "safe")]
    )
    assert malicious is True
    assert score == 0.5


def test_intel_score_excludes_pending_and_error(monkeypatch):
    verdicts = [
        _verdict("MISP_2_1", "malicious"),
        _verdict("Abuse_Finder_3_0", "pending"),
        _verdict("DShield_lookup_1_0", "error"),
    ]
    malicious, score = derive_intel_verdict(verdicts)
    assert malicious is True
    assert score == 1.0  # 1 malicious / 1 resolved (pending+error excluded)


def test_intel_confirmation_analyzers_configurable(monkeypatch):
    monkeypatch.setenv("INTEL_CONFIRMATION_ANALYZERS", "Custom_Analyzer_1_0")
    malicious, _ = derive_intel_verdict([_verdict("VirusTotal_GetReport_3_1", "malicious")])
    assert malicious is False  # not in the overridden allowlist
    malicious, _ = derive_intel_verdict([_verdict("Custom_Analyzer_1_0", "malicious")])
    assert malicious is True


def test_no_verdicts_yields_no_intel():
    assert derive_intel_verdict([]) == (False, 0.0)


def test_annotate_observable_intel_flags_only_confirmed_matches(monkeypatch):
    monkeypatch.delenv("INTEL_CONFIRMATION_ANALYZERS", raising=False)
    observables = [
        {"type": "ip", "value": "203.0.113.7", "role": "dst"},
        {"type": "domain", "value": "bad.example", "role": "dst"},
    ]
    verdicts = [
        {"analyzer_name": "VirusTotal_GetReport_3_1", "observable_type": "ip", "observable_value": "203.0.113.7", "verdict": "malicious"},
        {"analyzer_name": "Some_Heuristic_1_0", "observable_type": "domain", "observable_value": "bad.example", "verdict": "malicious"},
    ]
    annotated = annotate_observable_intel(observables, verdicts)
    by_value = {o["value"]: o for o in annotated}
    assert by_value["203.0.113.7"]["intel_malicious"] is True
    assert "intel_malicious" not in by_value["bad.example"]  # non-trusted analyzer doesn't confirm
    # original list is untouched
    assert "intel_malicious" not in observables[0]



def _success_job(report):
    return {"status": "Success", "report": report}


def test_summarize_cortex_job_uses_taxonomy_levels():
    job = _success_job({
        "summary": {
            "taxonomies": [
                {"level": "safe", "namespace": "Example", "predicate": "Score", "value": "clean"},
                {"level": "suspicious", "namespace": "Example", "predicate": "Score", "value": "watch"},
            ]
        }
    })
    assert _summarize_cortex_job(job) == ("suspicious", "Example/Score=clean; Example/Score=watch")


def test_summarize_cortex_job_urlhaus_full_hit_is_malicious():
    job = _success_job({
        "summary": {},
        "full": {
            "query_status": "ok",
            "url_status": "online",
            "threat": "malware_download",
            "payloads": [{"signature": "Mirai"}],
            "data_type": "url",
        },
    })
    assert _summarize_cortex_job(job) == ("malicious", "URLhaus/Search=malware_download")


def test_summarize_cortex_job_urlhaus_no_results_is_info():
    job = _success_job({"summary": {}, "full": {"query_status": "no_results", "data_type": "url"}})
    assert _summarize_cortex_job(job) == ("info", "URLhaus/Search=No results")


def test_summarize_cortex_job_misp_positive_event_is_malicious():
    job = _success_job({
        "summary": {
            "taxonomies": [
                {"level": "suspicious", "namespace": "MISP", "predicate": "Search", "value": "1 event(s)"}
            ]
        },
        "full": {"results": [{"name": "thesis-misp", "result": [{"Event": {"id": "9"}}]}]},
    })
    assert _summarize_cortex_job(job) == ("malicious", "MISP/Search=1 event(s)")


def test_summarize_cortex_job_misp_zero_events_stays_info():
    job = _success_job({
        "summary": {
            "taxonomies": [
                {"level": "info", "namespace": "MISP", "predicate": "Search", "value": "0 events"}
            ]
        },
        "full": {"results": [{"name": "thesis-misp", "result": []}]},
    })
    assert _summarize_cortex_job(job) == ("info", "MISP/Search=0 events")


def test_summarize_cortex_job_circl_known_malicious_fallback():
    job = _success_job({"summary": {}, "full": {"KnownMalicious": True}})
    assert _summarize_cortex_job(job) == ("malicious", "CIRCLHashlookup/KnownMalicious=true")



class _FakeCortex:
    """Fake of the CortexClient enrichment interface. Mirrors the real
    client's composition: `run_analyzer_on_observable` = launch + wait in
    one blocking call (the real one holds the CORTEX_MAX_CONCURRENT
    semaphore across both — see cortex_client.run_analyzer_on_observable).
    `call_order` records the interleaving so tests can assert each job's
    launch/wait completes before the next job starts."""

    def __init__(self):
        self.launch_calls = []
        self.wait_calls = []
        self.call_order = []

    def launch_analyzer_on_observable(self, *, analyzer_name, data, data_type):
        self.launch_calls.append((analyzer_name, data, data_type))
        self.call_order.append(("launch", f"job-{len(self.launch_calls)}"))
        return {
            "analyzer_name": analyzer_name,
            "data_type": data_type,
            "data": data,
            "job_id": f"job-{len(self.launch_calls)}",
        }

    def wait_for_job_report(self, *, analyzer_name, data, data_type, job_id, wait_seconds):
        self.wait_calls.append((analyzer_name, data, data_type, job_id, wait_seconds))
        self.call_order.append(("wait", job_id))
        return {
            "analyzer_name": analyzer_name,
            "data_type": data_type,
            "data": data,
            "job_id": job_id,
            "report": {
                "status": "Success",
                "report": {
                    "summary": {},
                    "full": {
                        "query_status": "ok",
                        "url_status": "online",
                        "threat": "malware_download",
                        "payloads": [{"signature": "Mirai"}],
                    },
                },
            },
        }

    def run_analyzer_on_observable(
        self, *, analyzer_name, data, data_type, parameters=None, force=False, wait_seconds=5
    ):
        launch = self.launch_analyzer_on_observable(
            analyzer_name=analyzer_name, data=data, data_type=data_type
        )
        job_id = launch.get("job_id")
        if not job_id:
            return launch
        return self.wait_for_job_report(
            analyzer_name=analyzer_name,
            data=data,
            data_type=data_type,
            job_id=job_id,
            wait_seconds=wait_seconds,
        )


def test_run_pre_case_enrichment_produces_intel_before_case(monkeypatch):
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "false")
    monkeypatch.setenv("AUTO_RUN_CORTEX", "true")
    monkeypatch.setenv("MAX_CORTEX_RUNS_PER_FLOW", "5")
    monkeypatch.setenv("MAX_OBSERVABLES_PER_FLOW", "5")
    monkeypatch.setenv("CORTEX_PRE_CASE_WAIT_SEC", "7")
    cortex = _FakeCortex()

    summary = run_pre_case_enrichment(
        alert={"pred_label": 1},
        observables=[{"type": "url", "value": "http://bad.example/i"}],
        cortex=cortex,
        analyzers_for_observable_type=lambda data_type: ["URLhaus_2_0"] if data_type == "url" else [],
    )

    assert cortex.launch_calls == [("URLhaus_2_0", "http://bad.example/i", "url")]
    assert len(cortex.wait_calls) == 1
    assert cortex.wait_calls[0][:4] == ("URLhaus_2_0", "http://bad.example/i", "url", "job-1")
    # per-job wait, capped by the (also 7s) total budget; truncated by
    # int(remaining) so it can be 7 or, if a sliver of time has already
    # elapsed, one less.
    assert cortex.wait_calls[0][4] in (6, 7)
    assert summary["intel_malicious"] is True
    assert summary["intel_score"] == 1.0
    assert summary["enriched_observables"][0]["intel_malicious"] is True
    assert summary["verdicts"][0]["verdict"] == "malicious"


def test_run_pre_case_enrichment_completes_each_job_before_launching_next(monkeypatch):
    """Each job's report is retrieved before the next job is launched —
    per-job serialization is what lets the CORTEX_MAX_CONCURRENT semaphore
    (held across the whole launch→report span in
    cortex_client.run_analyzer_on_observable) cap how many jobs run inside
    Cortex at once. A launch-all-then-poll-all structure here would release
    the cap while jobs are merely queued and re-saturate Cortex."""
    monkeypatch.setenv("ORCHESTRATOR_DRY_RUN", "false")
    monkeypatch.setenv("AUTO_RUN_CORTEX", "true")
    monkeypatch.setenv("MAX_CORTEX_RUNS_PER_FLOW", "5")
    monkeypatch.setenv("MAX_OBSERVABLES_PER_FLOW", "5")
    monkeypatch.setenv("CORTEX_PRE_CASE_WAIT_SEC", "5")
    monkeypatch.setenv("CORTEX_PRE_CASE_TOTAL_BUDGET_SEC", "10")
    cortex = _FakeCortex()

    run_pre_case_enrichment(
        alert={"pred_label": 1},
        observables=[
            {"type": "url", "value": "http://bad.example/a"},
            {"type": "url", "value": "http://bad.example/b"},
        ],
        cortex=cortex,
        analyzers_for_observable_type=lambda data_type: ["URLhaus_2_0"] if data_type == "url" else [],
    )

    assert len(cortex.launch_calls) == 2
    assert len(cortex.wait_calls) == 2
    assert cortex.call_order == [
        ("launch", "job-1"),
        ("wait", "job-1"),
        ("launch", "job-2"),
        ("wait", "job-2"),
    ]
