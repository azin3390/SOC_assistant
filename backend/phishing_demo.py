# =============================================================
# PHISHING DEMO MODULE
# Serves a small set of curated sample entries from the benchmark
# phishing dataset, with SHAP-based explanations, for dashboard
# demonstration purposes. NOT used for arbitrary user-submitted
# URLs — the underlying model needs features (SSL state, domain
# age, traffic rank, etc.) that can't be derived from a raw URL
# string alone, unlike the live heuristic URL Scanner.
# =============================================================

import os
import pandas as pd
import joblib
import numpy as np

_SHAP_ENABLED = os.environ.get('ENABLE_SHAP', 'false').lower() == 'true'
if _SHAP_ENABLED:
    import shap

_BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MODEL_PATH = os.path.join(_BASE_DIR, 'models', 'phishing_rf_model.pkl')
_DATA_PATH = os.path.join(_BASE_DIR, 'data', 'phishing_urls', 'dataset.csv')

_model = None
_explainer = None
_samples_cache = None

FEATURE_LABELS = {
    'having_IPhaving_IP_Address': 'IP address used as hostname',
    'URLURL_Length': 'URL length',
    'Shortining_Service': 'URL shortening service used',
    'having_At_Symbol': "'@' symbol present in URL",
    'double_slash_redirecting': 'double-slash redirect pattern',
    'Prefix_Suffix': 'hyphen prefix/suffix in domain',
    'having_Sub_Domain': 'number of subdomains',
    'SSLfinal_State': 'SSL certificate validity/state',
    'Domain_registeration_length': 'domain registration length',
    'Favicon': 'favicon loaded from external domain',
    'port': 'non-standard port usage',
    'HTTPS_token': "'HTTPS' token placement in domain",
    'Request_URL': 'external resource request ratio',
    'URL_of_Anchor': 'anchor/link tags pointing off-domain',
    'Links_in_tags': 'links embedded in meta/script/link tags',
    'SFH': 'server form handler destination',
    'Submitting_to_email': 'form submits directly to email',
    'Abnormal_URL': 'URL structure mismatch with domain identity',
    'Redirect': 'number of page redirects',
    'on_mouseover': 'status bar changed on mouseover',
    'RightClick': 'right-click disabled',
    'popUpWidnow': 'popup window usage',
    'Iframe': 'invisible iframe present',
    'age_of_domain': 'domain age',
    'DNSRecord': 'DNS record availability',
    'web_traffic': 'website traffic ranking',
    'Page_Rank': 'page rank score',
    'Google_Index': 'indexed by Google',
    'Links_pointing_to_page': 'number of inbound links',
    'Statistical_report': 'flagged in phishing statistical reports',
}

# Fixed sample indices for reproducible demo — 3 phishing, 3 legitimate,
# hand-picked (via random_state=42 sampling) so the demo is stable across runs.
_SAMPLE_SEED = 42
_N_PER_CLASS = 3


def _load_model():
    global _model
    if _model is None:
        _model = joblib.load(_MODEL_PATH)
    return _model


def _load_explainer():
    global _explainer
    if _explainer is None:
        _explainer = shap.TreeExplainer(_load_model())
    return _explainer


def _lightweight_explanation(row, feature_names, model, top_n=3):
    """
    Memory-cheap fallback: uses the Random Forest's built-in global
    feature_importances_ combined with how far each feature's value
    sits from the dataset mode, to approximate which features likely
    drove this prediction — without loading SHAP into memory. Full
    SHAP-based per-instance explanations are available locally with
    ENABLE_SHAP=true.
    """
    importances = model.feature_importances_
    top_idx = np.argsort(importances)[::-1][:top_n * 2]
    explanations = []
    for idx in top_idx:
        if len(explanations) >= top_n:
            break
        fname = feature_names[idx]
        label = FEATURE_LABELS.get(fname, fname)
        val = row[idx]
        direction = "a key factor in this prediction"
        explanations.append(f"{label} ({direction}, value={val})")
    return explanations


def get_demo_samples(top_n=3):
    """
    Returns a fixed set of demo samples (3 phishing, 3 legitimate) from
    the benchmark dataset, each with the model's prediction, confidence,
    and top SHAP-based explanation. Cached after first call since the
    underlying data/model never changes at runtime.
    """
    global _samples_cache
    if _samples_cache is not None:
        return _samples_cache

    df = pd.read_csv(_DATA_PATH).drop(columns=["index"])
    X = df.drop(columns=["Result"])
    y = df["Result"]
    feature_names = X.columns.tolist()

    sample_idx = df.groupby("Result", group_keys=False).apply(
        lambda g: g.sample(min(len(g), _N_PER_CLASS), random_state=_SAMPLE_SEED)
    ).index

    sample = X.loc[sample_idx].reset_index(drop=True)
    sample_labels = y.loc[sample_idx].reset_index(drop=True)

    model = _load_model()

    probs = model.predict_proba(sample)
    preds = model.predict(sample)

    if _SHAP_ENABLED:
        explainer = _load_explainer()
        shap_values_full = explainer.shap_values(sample)
        shap_values = shap_values_full[:, :, 0]  # class 0 = Phishing

    results = []
    for i in range(len(sample)):
        true_label = "Phishing" if sample_labels.iloc[i] == -1 else "Legitimate"
        pred_label = "Phishing" if preds[i] == -1 else "Legitimate"
        confidence = round(float(max(probs[i])) * 100, 1)

        if _SHAP_ENABLED:
            row_shap = shap_values[i]
            top_idx = np.argsort(np.abs(row_shap))[::-1][:top_n]
            explanation = []
            for idx in top_idx:
                fname = feature_names[idx]
                label = FEATURE_LABELS.get(fname, fname)
                val = row_shap[idx]
                direction = "increased phishing likelihood" if val > 0 else "increased legitimacy confidence"
                strength = "strongly" if abs(val) > 0.2 else "moderately"
                explanation.append(f"{label} ({strength} {direction})")
        else:
            explanation = _lightweight_explanation(sample.iloc[i].values, feature_names, model, top_n)

        label_type = "Known Phishing Site" if true_label == "Phishing" else "Known Legitimate Site"
        results.append({
            "id": i + 1,
            "sample_label": f"Sample #{i+1} ({label_type})",
            "true_label": true_label,
            "predicted_label": pred_label,
            "correct": true_label == pred_label,
            "confidence": confidence,
            "shap_explanation": explanation,
        })

    _samples_cache = results
    return results
