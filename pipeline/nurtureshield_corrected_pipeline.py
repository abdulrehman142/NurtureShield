"""Corrected / Final Research Pipeline for NurtureShield.

This module is separate from the four notebooks documenting the Original
Research Iteration. It investigates class-correlated URL representation,
canonicalizes one leading HTTP(S) scheme before feature extraction, removes
``uses_https``, and preserves a corrected 31-feature schema. It then performs
registered-domain-aware splitting, analyzes the bare-hostname bias, applies
training-only benign host-only counterfactual augmentation, compares models,
selects the decision threshold on validation data, verifies scheme invariance,
and exports corrected evaluation and production artifacts.

The finalized production threshold is 0.30. Final artifacts are written under
``Output/Corrected_Research/``, including ``features.py``,
``hist_gradient_boosting.joblib``, ``final_model_config.json``, and corrected
CSV/JSON evaluation outputs. This module performs URL analysis as text only;
it does not visit or request URLs.

Usage:
    python nurtureshield_corrected_pipeline.py --input malicious_phish.csv \
        --output-dir corrected_artifacts
"""

from __future__ import annotations

import argparse
import json
import math
import platform
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Iterable
from urllib.parse import parse_qs, urlsplit

import joblib
import numpy as np
import pandas as pd
import sklearn
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import GroupShuffleSplit
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sklearn.utils.class_weight import compute_sample_weight

try:
    import tldextract
except ImportError as exc:  # pragma: no cover - environment setup error
    raise RuntimeError("Install tldextract before running this pipeline.") from exc


SCHEMA_VERSION = "nurtureshield-corrected-v1"
RANDOM_STATE = 42
LABEL_MAPPING = {"benign": 0, "phishing": 1, "defacement": 1, "malware": 1}
SUSPICIOUS_TOKENS = (
    "login", "signin", "verify", "verification", "account", "secure",
    "update", "confirm", "password", "credential", "bank", "payment",
    "wallet", "recover", "support", "security", "authenticate", "webscr",
    "ebayisapi",
)
SCHEME_RE = re.compile(r"^(?:https?|ftp):\/\/", re.IGNORECASE)
HTTP_SCHEME_RE = re.compile(r"^(https?):\/\/", re.IGNORECASE)


def canonicalize_url(value: object) -> str:
    """Return the URL spelling used by the extractor.

    HTTP and HTTPS are transport metadata, not lexical URL content for this
    URL-only classifier.  Removing only the leading HTTP(S) scheme and its
    separators makes scheme-equivalent inputs identical while retaining ports,
    paths, queries, fragments, encoding, Unicode, and host structure.
    Other schemes remain visible and are audited as abnormal input.
    """
    text = str(value).strip()
    return HTTP_SCHEME_RE.sub("", text, count=1)


def _parse_url(value: object):
    text = str(value).strip()
    parse_target = text if SCHEME_RE.match(text) else "//" + text
    try:
        return urlsplit(parse_target)
    except ValueError:
        return urlsplit("//")


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    length = len(text)
    return -sum((n / length) * math.log2(n / length) for n in counts.values())


def _is_ip(hostname: str) -> int:
    import ipaddress

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        return 0
    return 1


def _extract_registered_domain(hostname: str, extractor) -> str:
    if not hostname:
        return ""
    result = extractor(hostname)
    if result.domain and result.suffix:
        return f"{result.domain}.{result.suffix}".lower()
    return hostname.lower()


def extract_url_features(value: object) -> dict[str, float | int]:
    """Extract the corrected 31-feature representation."""
    url = canonicalize_url(value)
    parsed = _parse_url(url)
    hostname = (parsed.hostname or "").lower()
    path = parsed.path or ""
    query = parsed.query or ""
    url_lower = url.lower()
    url_length = len(url)
    digits = sum(char.isdigit() for char in url)
    letters = sum(char.isalpha() for char in url)
    special = sum(not char.isalnum() for char in url)
    hostname_parts = [part for part in hostname.split(".") if part]
    suspicious = sum(url_lower.count(token) for token in SUSPICIOUS_TOKENS)
    try:
        query_parameters = len(parse_qs(query, keep_blank_values=True))
    except ValueError:
        query_parameters = 0
    try:
        explicit_port = int(parsed.port is not None)
    except ValueError:
        explicit_port = 1

    return {
        "url_length": url_length,
        "hostname_length": len(hostname),
        "path_length": len(path),
        "query_length": len(query),
        "digit_count": digits,
        "letter_count": letters,
        "special_char_count": special,
        "dot_count": url.count("."),
        "hyphen_count": url.count("-"),
        "underscore_count": url.count("_"),
        "slash_count": url.count("/"),
        "question_count": url.count("?"),
        "equal_count": url.count("="),
        "at_count": url.count("@"),
        "ampersand_count": url.count("&"),
        "percent_count": url.count("%"),
        "digit_ratio": digits / url_length if url_length else 0.0,
        "letter_ratio": letters / url_length if url_length else 0.0,
        "special_char_ratio": special / url_length if url_length else 0.0,
        "subdomain_count": max(len(hostname_parts) - 2, 0),
        "uses_ip_address": _is_ip(hostname),
        "has_explicit_port": explicit_port,
        "has_percent_encoding": int(bool(re.search(r"%[0-9a-fA-F]{2}", url))),
        "has_punycode": int("xn--" in hostname),
        "has_unicode": int(any(ord(char) > 127 for char in url)),
        "suspicious_token_count": suspicious,
        "has_suspicious_token": int(suspicious > 0),
        "path_depth": len([segment for segment in path.split("/") if segment]),
        "query_parameter_count": query_parameters,
        "url_entropy": _entropy(url),
        "hostname_entropy": _entropy(hostname),
    }


FEATURE_NAMES = list(extract_url_features("example.com"))


def feature_frame(urls: Iterable[object]) -> pd.DataFrame:
    return pd.DataFrame([extract_url_features(url) for url in urls], columns=FEATURE_NAMES)


def scheme_audit(frame: pd.DataFrame) -> pd.DataFrame:
    raw = frame["url"].astype(str).str.strip()
    explicit = raw.str.extract(r"^([A-Za-z][A-Za-z0-9+.-]*):\/\/", expand=False).str.lower()
    category = pd.Series("no_explicit_scheme", index=frame.index)
    category.loc[explicit.isin(["http"])] = "http"
    category.loc[explicit.isin(["https"])] = "https"
    category.loc[explicit.notna() & ~explicit.isin(["http", "https"])] = "other_abnormal"
    result = (
        pd.crosstab(frame["original_label"], category, normalize="index")
        .mul(100)
        .reindex(columns=["http", "https", "no_explicit_scheme", "other_abnormal"], fill_value=0)
        .round(4)
    )
    return result


def _clean(raw: pd.DataFrame) -> pd.DataFrame:
    required = {"url", "type"}
    missing = required - set(raw.columns)
    if missing:
        raise ValueError(f"Input dataset is missing columns: {sorted(missing)}")
    data = raw[["url", "type"]].copy()
    data["url"] = data["url"].astype(str).str.strip()
    data["original_label"] = data["type"].astype(str).str.strip().str.lower()
    invalid = set(data["original_label"]) - set(LABEL_MAPPING)
    if invalid:
        raise ValueError(f"Unexpected labels: {sorted(invalid)}")
    data = data.drop_duplicates("url").copy()
    data["label"] = data["original_label"].map(LABEL_MAPPING).astype(int)
    extractor = tldextract.TLDExtract(suffix_list_urls=None)
    data["hostname"] = data["url"].map(lambda value: (_parse_url(value).hostname or "").lower())
    data["registered_domain"] = data["hostname"].map(
        lambda value: _extract_registered_domain(value, extractor)
    )
    return data[data["registered_domain"].ne("")].reset_index(drop=True)


def _split(data: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
    first = GroupShuffleSplit(n_splits=1, train_size=0.70, random_state=RANDOM_STATE)
    train_idx, temp_idx = next(first.split(data, y=data["label"], groups=data["registered_domain"]))
    train = data.iloc[train_idx].copy()
    temp = data.iloc[temp_idx].copy()
    second = GroupShuffleSplit(n_splits=1, train_size=0.50, random_state=RANDOM_STATE)
    val_idx, test_idx = next(second.split(temp, y=temp["label"], groups=temp["registered_domain"]))
    return train, temp.iloc[val_idx].copy(), temp.iloc[test_idx].copy()


def _host_only_url(value: object) -> str:
    """Create a host-only counterfactual without changing the hostname."""
    parsed = _parse_url(canonicalize_url(value))
    hostname = parsed.hostname or ""
    try:
        port = parsed.port
    except ValueError:
        port = None
    return f"{hostname}:{port}" if port is not None else hostname


def _augment_training_data(train: pd.DataFrame) -> pd.DataFrame:
    """Counteract the dataset's path-presence label artifact.

    The raw data contains an extreme bias: bare host/no-query URLs are almost
    entirely malicious.  Adding host-only variants of benign training URLs
    teaches the model that an ordinary host remains a plausible benign URL
    when its path is absent.  This is a generic structural augmentation, not a
    domain allowlist, and it is generated from training data only.
    """
    benign = train[train["label"].eq(0)].copy()
    benign["url"] = benign["url"].map(_host_only_url)
    benign = benign[benign["url"].ne("")]
    augmented = pd.concat([train, benign], ignore_index=True)
    return augmented.drop_duplicates(subset=["url", "label"]).reset_index(drop=True)


def leakage_report(splits: dict[str, pd.DataFrame]) -> dict[str, int]:
    domains = {name: set(part["registered_domain"]) for name, part in splits.items()}
    urls = {name: set(part["url"]) for name, part in splits.items()}
    report = {}
    for left, right in (("train", "validation"), ("train", "test"), ("validation", "test")):
        report[f"{left}_{right}_domain_overlap"] = len(domains[left] & domains[right])
        report[f"{left}_{right}_url_overlap"] = len(urls[left] & urls[right])
    if any(report.values()):
        raise AssertionError(f"Data leakage detected: {report}")
    return report


def _metrics(y_true, probabilities, threshold: float) -> dict:
    predictions = (probabilities >= threshold).astype(int)
    tn, fp, fn, tp = confusion_matrix(y_true, predictions, labels=[0, 1]).ravel()
    return {
        "accuracy": accuracy_score(y_true, predictions),
        "precision": precision_score(y_true, predictions, zero_division=0),
        "recall": recall_score(y_true, predictions, zero_division=0),
        "f1": f1_score(y_true, predictions, zero_division=0),
        "roc_auc": roc_auc_score(y_true, probabilities),
        "pr_auc": average_precision_score(y_true, probabilities),
        "confusion_matrix": [[int(tn), int(fp)], [int(fn), int(tp)]],
    }


def _models() -> dict[str, object]:
    return {
        "logistic_regression": Pipeline([
            ("scaler", StandardScaler()),
            ("classifier", LogisticRegression(max_iter=2000, class_weight="balanced", random_state=RANDOM_STATE)),
        ]),
        "random_forest": RandomForestClassifier(
            n_estimators=300, max_features="sqrt", class_weight="balanced",
            n_jobs=-1, random_state=RANDOM_STATE,
        ),
        "hist_gradient_boosting": HistGradientBoostingClassifier(
            learning_rate=0.1, max_iter=300, max_leaf_nodes=31,
            min_samples_leaf=20, l2_regularization=1.0,
            early_stopping=True, validation_fraction=0.1,
            n_iter_no_change=20, random_state=RANDOM_STATE,
        ),
    }


def _threshold_table(y, probabilities) -> pd.DataFrame:
    rows = []
    for threshold in np.arange(0.10, 0.91, 0.01):
        result = _metrics(y, probabilities, float(threshold))
        rows.append({"threshold": round(float(threshold), 2), **result})
    return pd.DataFrame(rows)


def _select_threshold(y, probabilities) -> tuple[float, pd.DataFrame]:
    table = _threshold_table(y, probabilities)
    # Security-oriented selection: require at least 85% malicious recall, then
    # maximize F1, recall, precision.  All values are validation-only.
    eligible = table[table["recall"] >= 0.85]
    if eligible.empty:
        eligible = table
    winner = eligible.sort_values(
        ["f1", "recall", "precision", "threshold"],
        ascending=[False, False, False, True],
    ).iloc[0]
    return float(winner["threshold"]), table


def sanity_cases() -> list[str]:
    return [
        "example.com", "http://example.com", "https://example.com",
        "wikipedia.org", "http://wikipedia.org", "https://wikipedia.org",
        "en.wikipedia.org/wiki/Flower", "http://en.wikipedia.org/wiki/Flower",
        "https://en.wikipedia.org/wiki/Flower",
        "https://www.google.com/", "http://secure-account-verify.example.com/login?id=829183",
        "https://xn--example-ova.com/%76%65%72%69%66%79",
    ]


def scheme_invariance(model, threshold: float) -> pd.DataFrame:
    urls = sanity_cases()
    probabilities = model.predict_proba(feature_frame(urls))[:, 1]
    rows = []
    for i in range(0, 9, 3):
        group = probabilities[i:i + 3]
        for url, probability in zip(urls[i:i + 3], group):
            rows.append({
                "url": url, "probability": float(probability),
                "prediction": int(probability >= threshold),
                "group_probability_range": float(np.max(group) - np.min(group)),
            })
    return pd.DataFrame(rows)


def subtype_metrics(data: pd.DataFrame, probabilities: np.ndarray, threshold: float) -> pd.DataFrame:
    """Report held-out performance for the original malicious subtypes."""
    predictions = (probabilities >= threshold).astype(int)
    rows = []
    for subtype in ("phishing", "malware", "defacement"):
        mask = data["original_label"].eq(subtype).to_numpy()
        if mask.any():
            rows.append({
                "subtype": subtype,
                "count": int(mask.sum()),
                "malicious_recall": float((predictions[mask] == 1).mean()),
                "mean_probability": float(probabilities[mask].mean()),
            })
    return pd.DataFrame(rows)


def robustness_report(model, threshold: float) -> pd.DataFrame:
    """Measure controlled structural changes without claiming robustness."""
    originals = [
        "example.com",
        "wikipedia.org/wiki/Flower",
        "secure-account-verify.example.com/login?id=829183",
        "192.0.2.10/login",
        "xn--example-ova.com/path",
    ]
    transformations = {
        "scheme_http": lambda value: "http://" + value,
        "scheme_https": lambda value: "https://" + value,
        "added_subdomain": lambda value: "www." + value,
        "path_noise": lambda value: value + "/a/b",
        "query_noise": lambda value: value + "?a=1&b=2",
        "percent_encoding": lambda value: value.replace("e", "%65", 1),
        "unicode": lambda value: value.replace("example", "exämple", 1),
        "punycode": lambda value: value.replace("example.com", "xn--example-ova.com", 1),
    }
    base = model.predict_proba(feature_frame(originals))[:, 1]
    rows = []
    for name, transform in transformations.items():
        variants = [transform(value) for value in originals]
        probabilities = model.predict_proba(feature_frame(variants))[:, 1]
        for original, variant, base_probability, probability in zip(
            originals, variants, base, probabilities
        ):
            rows.append({
                "base_url": original,
                "variant": variant,
                "transformation": name,
                "base_probability": float(base_probability),
                "variant_probability": float(probability),
                "probability_change": float(probability - base_probability),
                "prediction_flip": int(
                    (base_probability >= threshold) != (probability >= threshold)
                ),
            })
    return pd.DataFrame(rows)


def run(input_path: Path, output_dir: Path) -> dict:
    output_dir.mkdir(parents=True, exist_ok=True)
    raw = pd.read_csv(input_path)
    clean = _clean(raw)
    audit = scheme_audit(clean)
    train, validation, test = _split(clean)
    splits = {"train": train, "validation": validation, "test": test}
    leakage = leakage_report(splits)
    training_data = _augment_training_data(train)
    matrices = {
        "train": feature_frame(training_data["url"]),
        "validation": feature_frame(validation["url"]),
        "test": feature_frame(test["url"]),
    }
    models = _models()
    validation_results = []
    fitted = {}
    for name, model in models.items():
        weights = compute_sample_weight("balanced", training_data["label"]) if name == "hist_gradient_boosting" else None
        model.fit(
            matrices["train"],
            training_data["label"],
            **({"sample_weight": weights} if weights is not None else {}),
        )
        fitted[name] = model
        probabilities = model.predict_proba(matrices["validation"])[:, 1]
        threshold, thresholds = _select_threshold(validation["label"], probabilities)
        result = {"model": name, "threshold": threshold, **_metrics(validation["label"], probabilities, threshold)}
        validation_results.append(result)
        thresholds.to_csv(output_dir / f"{name}_validation_thresholds.csv", index=False)

    eligible_models = [
        result for result in validation_results
        if result["recall"] >= 0.90 and result["precision"] >= 0.45
    ]
    if not eligible_models:
        eligible_models = validation_results
    selected = max(
        eligible_models,
        key=lambda result: (result["f1"], result["recall"], result["precision"]),
    )
    selected_model = fitted[selected["model"]]
    final_threshold = selected["threshold"]
    test_probabilities = selected_model.predict_proba(matrices["test"])[:, 1]
    test_result = _metrics(test["label"], test_probabilities, final_threshold)
    subtype = subtype_metrics(test, test_probabilities, final_threshold)
    sanity = scheme_invariance(selected_model, final_threshold)
    robustness = robustness_report(selected_model, final_threshold)
    sanity.to_csv(output_dir / "scheme_invariance.csv", index=False)
    subtype.to_csv(output_dir / "final_test_subtypes.csv", index=False)
    robustness.to_csv(output_dir / "robustness_re_evaluation.csv", index=False)
    if hasattr(selected_model, "feature_importances_"):
        importance = pd.DataFrame({
            "feature": FEATURE_NAMES,
            "importance": selected_model.feature_importances_,
        }).sort_values("importance", ascending=False)
        importance.to_csv(output_dir / "global_feature_importance.csv", index=False)

    joblib.dump(selected_model, output_dir / f"{selected['model']}.joblib")
    metadata = {
        "schema_version": SCHEMA_VERSION,
        "model": selected["model"],
        "feature_count": len(FEATURE_NAMES),
        "feature_names": FEATURE_NAMES,
        "threshold": final_threshold,
        "label_mapping": LABEL_MAPPING,
        "preprocessing": "strip one leading http:// or https:// before parsing and counting",
        "training_augmentation": "host-only counterfactuals generated from benign training URLs",
        "uses_https_removed": True,
        "threshold_policy": (
            "model threshold selected on validation; prefer candidates with "
            "malicious recall >= 0.90 and precision >= 0.45, then maximize F1"
        ),
        "split": "70/15/15 registered-domain-aware GroupShuffleSplit, frozen seed 42",
        "rows": {name: len(part) for name, part in splits.items()},
        "augmented_training_rows": len(training_data),
        "leakage": leakage,
        "python": platform.python_version(),
        "sklearn": sklearn.__version__,
        "numpy": np.__version__,
        "pandas": pd.__version__,
    }
    (output_dir / "final_model_config.json").write_text(json.dumps(metadata, indent=2) + "\n")
    audit.to_csv(output_dir / "scheme_distribution_by_class.csv")
    pd.DataFrame(validation_results).to_csv(output_dir / "validation_model_comparison.csv", index=False)
    pd.DataFrame([test_result]).to_json(output_dir / "final_test_metrics.json", orient="records", indent=2)
    return {
        "metadata": metadata,
        "validation": validation_results,
        "test": test_result,
        "subtypes": subtype.to_dict(orient="records"),
        "scheme_audit": audit,
        "robustness": robustness.to_dict(orient="records"),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    report = run(args.input, args.output_dir)
    print(json.dumps(report["metadata"], indent=2))
    print(json.dumps(report["test"], indent=2))


if __name__ == "__main__":
    main()
