# Data Sources & Attribution

The code in this repository is MIT-licensed (see `LICENSE`). The **bundled dataset** and the
**third-party tools** the framework integrates have their own provenance and terms, documented
here. If you reuse the dataset or the framework, please cite the original sources.

## Bundled dataset — `data/training_dataset.csv`

This file contains **derived per-flow statistical features** (NFStream aggregates: packet/payload
lengths, TCP windows, inter-arrival timing, JA3/JA3S) and per-flow labels — **not** raw packet
captures. The flows were extracted and labelled from publicly available captures:

- **malware-traffic-analysis.net (MTA)** — Brad Duncan. Real Windows-malware traffic captures
  (2022–2025), shared publicly for research/education. The malicious labels derive from MTA's
  **published IOCs** for each capture. https://www.malware-traffic-analysis.net/
- **CTU‑13 / CTU‑Normal (Stratosphere IPS, CTU University, Prague)** — benign background traffic.
  Cite: S. García, M. Grill, J. Stiborek, A. Zunino, *"An empirical comparison of botnet detection
  methods,"* Computers & Security, 2014. https://www.stratosphereips.org/datasets-overview

The labelling is **IOC-completeness-dependent** (a malicious endpoint absent from a capture's
published IOC file is labelled benign) — a documented limitation, not ground-truth-perfect.
Methodology and the full sourcing narrative: `context/DETECTION_FRAMEWORK_CONTEXT.md` (Appendix A).

> To replay your **own** traffic instead, replace `data/training_dataset.csv` with a CSV of the
> same columns (or rebuild with `detctl dataset`). The large raw `data/dataset.csv` is **not**
> distributed.

## Methodological inspiration
- **Composed Encrypted Malicious Traffic Dataset** (Mendeley `ztyk4h3v6s`; method: arXiv 2203.09332)
  — the TLS-encrypted, Zeek-filtered, label-inherited approach this dataset mirrors.

## Key third-party tools (each under its own licence)
- **NFStream** 6.6.0 — flow feature extraction. Cite: Z. Aouini, A. Pekar, *"NFStream: A flexible
  network data analysis framework,"* Computer Networks 204:108719, 2022.
- **Apache Kafka**, **PostgreSQL**, **scikit-learn**, **XGBoost**, **SHAP**, **LIME**,
  **InterpretML (EBM)**, **FastAPI**, **React/Vite/Tailwind**.
- **SOAR half (separate repo):** **Wazuh** (agent + Active-Response), **TheHive**, **Cortex**,
  **MISP**, **Shuffle** — MITRE ATT&CK® technique IDs are © The MITRE Corporation.

## Citing this framework
Joel C. Okore, *"Explainable Machine Learning for Malicious Encrypted Traffic Detection and
Trust-Aware SOAR Integration,"* MSc thesis, Innopolis University, 2026.
