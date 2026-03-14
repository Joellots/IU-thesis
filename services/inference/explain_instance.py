"""
explain_instance.py
-------------------
Self-contained explanation module ported from the research notebook.
Exposes a single public function: explain_instance()

Tier-1 (always-on, fast):
    • XGBoost built-in contributions  — deterministic, O(depth) per tree
    • EBM local explanations          — exact additive shape-function lookup

Tier-2 (on-demand, flagged flows only):
    • LIME  — stochastic local surrogate (2000 perturbations)
    • SHAP  — exact TreeExplainer values (reference / validation)
"""

import time
import numpy as np
import pandas as pd
from typing import Any

# ── Tier-2 trigger logic ──────────────────────────────────────────────────────
def is_flagged(p_malicious: float,
               high_thresh: float = 0.80,
               uncertain_lo: float = 0.45,
               uncertain_hi: float = 0.55) -> bool:
    return p_malicious >= high_thresh or uncertain_lo <= p_malicious <= uncertain_hi


# ── Contribution extractors ───────────────────────────────────────────────────

def make_xgb_contrib_fn(xgb_model):
    """Returns a function that extracts per-feature contributions from XGBoost."""
    booster = xgb_model.get_booster() if hasattr(xgb_model, "get_booster") else xgb_model

    def _fn(x_row: pd.Series) -> np.ndarray:
        import xgboost as xgb
        dm = xgb.DMatrix(x_row.to_frame().T, feature_names=list(x_row.index))
        # pred_contribs returns shape (1, n_features+1) — last col is bias
        contribs = booster.predict(dm, pred_contribs=True)[0, :-1]
        return contribs.astype(float)

    return _fn


def make_ebm_contrib_fn(ebm_model):
    """Returns a function that extracts main-effect contributions from EBM."""
    feat_names = list(ebm_model.feature_names_in_)
    feat_set   = set(feat_names)

    def _fn(x_row: pd.Series) -> np.ndarray:
        x_df      = pd.DataFrame([x_row.values], columns=list(x_row.index))
        local_exp = ebm_model.explain_local(x_df, name="EBM_local")
        data      = local_exp.data(0)

        out          = np.zeros(len(x_row))
        name_to_pos  = {f: i for i, f in enumerate(x_row.index)}

        for name, score in zip(data["names"], data["scores"]):
            # Filter out interaction terms (contain " x ")
            if name in feat_set and name in name_to_pos:
                out[name_to_pos[name]] = float(score)

        return out

    return _fn


def make_lime_contrib_fn(lime_explainer, predict_proba_fn, feature_names):
    """Returns a LIME explanation function."""
    def _fn(x_row: pd.Series) -> np.ndarray:
        exp = lime_explainer.explain_instance(
            x_row.values,
            predict_proba_fn,
            num_features=len(feature_names),
            num_samples=2000,
        )
        contrib_map = dict(exp.as_list())
        out = np.zeros(len(feature_names))
        for i, f in enumerate(feature_names):
            out[i] = contrib_map.get(f, 0.0)
        return out

    return _fn


def make_shap_contrib_fn(shap_explainer):
    """Returns a SHAP TreeExplainer function."""
    def _fn(x_row: pd.Series) -> np.ndarray:
        vals = shap_explainer.shap_values(x_row.to_frame().T)
        if isinstance(vals, list):
            vals = vals[1]          # binary classification — class 1
        return np.array(vals[0], dtype=float)

    return _fn


# ── Core API ──────────────────────────────────────────────────────────────────

def explain_instance(
    x_row:       pd.Series,
    model:       Any,
    model_name:  str,
    contrib_fn,
    tier:        str   = "fast",
    k:           int   = 5,
    instance_id: str   = "",
    true_label:  int   = -1,
) -> dict:
    """
    Produce a standardised explanation record for one flow instance.

    Returns
    -------
    dict with keys:
        flow_id, model, tier, pred_label, pred_proba, explain_time_ms,
        top_k_features (comma-separated str), top_k_json (list of dicts),
        true_label
    """
    t0 = time.perf_counter()

    # Prediction
    x_df       = pd.DataFrame([x_row.values], columns=list(x_row.index))
    pred_label = int(model.predict(x_df)[0])
    pred_proba = float(model.predict_proba(x_df)[0][1])

    # Contributions
    contribs   = contrib_fn(x_row)

    # Safe top-k extraction — guard against shape mismatches
    n          = min(len(contribs), len(x_row))
    feat_names = list(x_row.index[:n])
    top_pos    = np.argsort(np.abs(contribs[:n]))[::-1][:k]

    top_k = [
        {
            "feature":      feat_names[p],
            "value":        float(x_row.iloc[p]),
            "contribution": float(contribs[p]),
            "direction":    "positive" if contribs[p] >= 0 else "negative",
        }
        for p in top_pos
    ]

    explain_ms = (time.perf_counter() - t0) * 1000

    return {
        "flow_id":         instance_id,
        "model":           model_name,
        "tier":            tier,
        "pred_label":      pred_label,
        "pred_proba":      round(pred_proba, 6),
        "explain_time_ms": round(explain_ms, 3),
        "top_k_features":  ",".join(e["feature"] for e in top_k),
        "top_k_json":      top_k,
        "true_label":      true_label,
    }