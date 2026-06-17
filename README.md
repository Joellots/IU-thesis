# IU-thesis — XAI-SOAR

**Explainable ML for Malicious Encrypted Traffic Detection and Trust-Aware SOAR Integration.**

> **Cross-system context — read `context/SYSTEM_OVERVIEW.md` first.** The project spans two
> machines in separate repos (this **detection** half and the **SOAR** half); `SYSTEM_OVERVIEW.md`
> describes both halves and the `alerts`-table contract between them. This repo is the detection
> half — NFStream capture → inference → XAI → translator → the shared PostgreSQL `alerts` table.

Key docs: `context/SYSTEM_OVERVIEW.md` (whole project), `context/context.md` (detection-side
detail), `context/SOAR_WORKFLOW_SPEC.md` (SOAR workflow + contract).
