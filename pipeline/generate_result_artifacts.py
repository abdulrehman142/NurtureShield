"""
NurtureShield - Final Result Artifact Generator

Generates report-ready figures and tables from the corrected NurtureShield
experimental outputs stored in results/.

This script:
- DOES NOT train the model.
- DOES NOT modify the model.
- DOES NOT modify research results.
- Only converts existing corrected results into report-ready artifacts.

Important:
- Held-out test metrics/confusion matrix in final_test_metrics.json were
  evaluated at threshold 0.24.
- Production threshold 0.30 was selected separately from validation analysis.
"""

from pathlib import Path
import json

import numpy as np
import pandas as pd
import matplotlib.pyplot as plt


# =====================================================================
# CONFIGURATION
# =====================================================================

ROOT = Path(__file__).resolve().parents[1]
RESULTS = ROOT / "results"
OUTPUT = ROOT / "Result_Artifacts"

OUTPUT.mkdir(parents=True, exist_ok=True)

TEST_EVALUATION_THRESHOLD = 0.24
PRODUCTION_THRESHOLD = 0.30

plt.rcParams.update({
    "figure.dpi": 150,
    "savefig.dpi": 300,
    "font.size": 11,
    "axes.titlesize": 14,
    "axes.labelsize": 11,
})


# =====================================================================
# HELPERS
# =====================================================================

def save_figure(fig, filename):
    """Save a figure as both PNG and PDF."""

    fig.tight_layout()

    png_path = OUTPUT / f"{filename}.png"
    pdf_path = OUTPUT / f"{filename}.pdf"

    fig.savefig(png_path, bbox_inches="tight")
    fig.savefig(pdf_path, bbox_inches="tight")

    plt.close(fig)

    print(f"Saved: {png_path.name}")
    print(f"Saved: {pdf_path.name}")


def find_column(df, candidates):
    """Find a dataframe column using case-insensitive candidate names."""

    mapping = {
        str(column).lower().strip(): column
        for column in df.columns
    }

    for candidate in candidates:
        key = candidate.lower().strip()

        if key in mapping:
            return mapping[key]

    return None


def normalize_score_series(series):
    """
    Convert metric values to numeric fractions.

    If values appear to be percentages such as 89.3 instead of 0.893,
    convert them to 0-1 fractions.
    """

    values = pd.to_numeric(series, errors="coerce")
    valid = values.dropna()

    if not valid.empty and valid.max() > 1.0 and valid.max() <= 100:
        values = values / 100.0

    return values


def add_bar_labels(ax, bars, values, percentage=False):
    """Add readable values above bars."""

    for bar, value in zip(bars, values):

        if pd.isna(value):
            continue

        if percentage:
            label = f"{value * 100:.1f}%"
        else:
            label = f"{value:.3f}"

        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + 0.015,
            label,
            ha="center",
            va="bottom",
            fontsize=9
        )


# =====================================================================
# LOAD FINAL TEST METRICS
# =====================================================================

metrics_path = RESULTS / "final_test_metrics.json"
metrics = None

if metrics_path.exists():

    with open(metrics_path, "r", encoding="utf-8") as file:
        metrics_data = json.load(file)

    if isinstance(metrics_data, list):

        if not metrics_data:
            raise ValueError(
                "final_test_metrics.json contains an empty list."
            )

        metrics = metrics_data[0]

    elif isinstance(metrics_data, dict):

        metrics = metrics_data

    else:
        raise ValueError(
            "Unexpected JSON structure in final_test_metrics.json."
        )

    print("\n" + "=" * 72)
    print("FINAL HELD-OUT TEST METRICS")
    print("=" * 72)
    print(json.dumps(metrics, indent=2))

else:
    print(f"WARNING: Missing {metrics_path}")


# =====================================================================
# 1. FINAL HELD-OUT MODEL PERFORMANCE
# =====================================================================

if metrics is not None:

    metric_definitions = [
        ("Accuracy", "accuracy"),
        ("Precision", "precision"),
        ("Recall", "recall"),
        ("F1 Score", "f1"),
        ("ROC-AUC", "roc_auc"),
        ("PR-AUC", "pr_auc"),
    ]

    rows = []

    for display_name, key in metric_definitions:

        if key in metrics and isinstance(metrics[key], (int, float)):
            rows.append({
                "Metric": display_name,
                "Score": float(metrics[key])
            })

    if rows:

        performance = pd.DataFrame(rows)

        performance.to_csv(
            OUTPUT / "01_final_model_performance.csv",
            index=False
        )

        fig, ax = plt.subplots(figsize=(9, 5))

        bars = ax.bar(
            performance["Metric"],
            performance["Score"]
        )

        ax.set_ylim(0, 1)
        ax.set_ylabel("Score")

        ax.set_title(
            "Corrected NurtureShield Held-Out Test Performance\n"
            f"Evaluation Threshold = {TEST_EVALUATION_THRESHOLD:.2f}"
        )

        ax.grid(axis="y", alpha=0.25)

        add_bar_labels(
            ax,
            bars,
            performance["Score"]
        )

        save_figure(
            fig,
            "01_final_model_performance"
        )


# =====================================================================
# 2. HELD-OUT TEST CONFUSION MATRIX
# =====================================================================

if metrics is not None:

    confusion_matrix = metrics.get("confusion_matrix")

    if confusion_matrix is not None:

        cm = np.asarray(confusion_matrix, dtype=int)

        if cm.shape != (2, 2):
            print("WARNING: Confusion matrix is not 2x2.")

        else:

            tn, fp = cm[0]
            fn, tp = cm[1]

            cm_table = pd.DataFrame(
                cm,
                index=[
                    "Actual Legitimate",
                    "Actual Malicious"
                ],
                columns=[
                    "Predicted Legitimate",
                    "Predicted Malicious"
                ]
            )

            cm_table.to_csv(
                OUTPUT / "02_confusion_matrix.csv"
            )

            fig, ax = plt.subplots(figsize=(6.8, 5.8))

            image = ax.imshow(cm)

            ax.set_xticks([0, 1])
            ax.set_yticks([0, 1])

            ax.set_xticklabels([
                "Legitimate",
                "Malicious"
            ])

            ax.set_yticklabels([
                "Legitimate",
                "Malicious"
            ])

            ax.set_xlabel("Predicted Class")
            ax.set_ylabel("Actual Class")

            ax.set_title(
                "Corrected Model — Held-Out Test Confusion Matrix\n"
                f"Evaluation Threshold = {TEST_EVALUATION_THRESHOLD:.2f}"
            )

            labels = [
                ["TN", "FP"],
                ["FN", "TP"]
            ]

            max_value = cm.max()

            for row in range(2):
                for column in range(2):

                    value = cm[row, column]

                    ax.text(
                        column,
                        row,
                        f"{labels[row][column]}\n{value:,}",
                        ha="center",
                        va="center",
                        fontsize=13,
                        fontweight="bold",
                        color=(
                            "white"
                            if value > max_value / 2
                            else "black"
                        )
                    )

            fig.colorbar(
                image,
                ax=ax,
                fraction=0.046,
                pad=0.04
            )

            save_figure(
                fig,
                "02_confusion_matrix"
            )

            print("\nHeld-Out Confusion Matrix:")
            print(f"TN = {tn:,}")
            print(f"FP = {fp:,}")
            print(f"FN = {fn:,}")
            print(f"TP = {tp:,}")


# =====================================================================
# 3. MODEL COMPARISON
# =====================================================================

comparison_path = RESULTS / "validation_model_comparison.csv"

if comparison_path.exists():

    comparison = pd.read_csv(comparison_path)

    print("\n" + "=" * 72)
    print("VALIDATION MODEL COMPARISON")
    print("=" * 72)
    print(comparison.to_string(index=False))

    comparison.to_csv(
        OUTPUT / "03_model_comparison_table.csv",
        index=False
    )

    model_col = find_column(
        comparison,
        ["model", "model_name", "classifier"]
    )

    # Keep this graph readable: focus on the most useful
    # threshold-dependent metrics.
    metric_definitions = [
        ("Accuracy", "accuracy"),
        ("Precision", "precision"),
        ("Recall", "recall"),
        ("F1 Score", "f1"),
    ]

    available_metrics = []

    for display_name, key in metric_definitions:

        column = find_column(comparison, [key])

        if column is not None:
            available_metrics.append(
                (display_name, column)
            )

    if model_col is not None and available_metrics:

        x = np.arange(len(comparison))
        width = 0.8 / len(available_metrics)

        fig, ax = plt.subplots(figsize=(10.5, 5.8))

        for index, (display_name, column) in enumerate(
            available_metrics
        ):

            values = normalize_score_series(
                comparison[column]
            )

            positions = (
                x
                + (
                    index
                    - (len(available_metrics) - 1) / 2
                )
                * width
            )

            ax.bar(
                positions,
                values,
                width,
                label=display_name
            )

        pretty_model_names = (
            comparison[model_col]
            .astype(str)
            .str.replace("_", " ", regex=False)
            .str.title()
        )

        ax.set_xticks(x)
        ax.set_xticklabels(pretty_model_names)

        ax.set_ylim(0, 1)
        ax.set_ylabel("Validation Score")

        ax.set_title(
            "Validation Performance of Candidate Models"
        )

        ax.grid(axis="y", alpha=0.25)
        ax.legend(ncol=4)

        save_figure(
            fig,
            "03_model_comparison"
        )


# =====================================================================
# 4. HGB VALIDATION THRESHOLD ANALYSIS
# =====================================================================

threshold_path = (
    RESULTS /
    "hist_gradient_boosting_validation_thresholds.csv"
)

if threshold_path.exists():

    thresholds = pd.read_csv(threshold_path)

    print("\n" + "=" * 72)
    print("HISTGRADIENTBOOSTING THRESHOLD ANALYSIS")
    print("=" * 72)

    print(thresholds.to_string(index=False))

    thresholds.to_csv(
        OUTPUT / "04_threshold_analysis_table.csv",
        index=False
    )

    threshold_col = find_column(
        thresholds,
        ["threshold", "decision_threshold"]
    )

    precision_col = find_column(
        thresholds,
        ["precision"]
    )

    recall_col = find_column(
        thresholds,
        ["recall"]
    )

    f1_col = find_column(
        thresholds,
        ["f1", "f1_score"]
    )

    if threshold_col is not None:

        x = pd.to_numeric(
            thresholds[threshold_col],
            errors="coerce"
        )

        fig, ax = plt.subplots(figsize=(10, 5.7))

        if precision_col is not None:
            ax.plot(
                x,
                normalize_score_series(
                    thresholds[precision_col]
                ),
                marker="o",
                markersize=3,
                linewidth=1.5,
                label="Precision"
            )

        if recall_col is not None:
            ax.plot(
                x,
                normalize_score_series(
                    thresholds[recall_col]
                ),
                marker="o",
                markersize=3,
                linewidth=1.5,
                label="Recall"
            )

        if f1_col is not None:
            ax.plot(
                x,
                normalize_score_series(
                    thresholds[f1_col]
                ),
                marker="o",
                markersize=3,
                linewidth=1.5,
                label="F1 Score"
            )

        ax.axvline(
            PRODUCTION_THRESHOLD,
            linestyle="--",
            linewidth=1.8,
            label=(
                "Production threshold "
                f"({PRODUCTION_THRESHOLD:.2f})"
            )
        )

        # Highlight the actual production threshold row.
        production_row = thresholds[
            np.isclose(
                pd.to_numeric(
                    thresholds[threshold_col],
                    errors="coerce"
                ),
                PRODUCTION_THRESHOLD
            )
        ]

        if not production_row.empty:

            row = production_row.iloc[0]

            if recall_col is not None:

                recall_value = float(row[recall_col])

                ax.scatter(
                    [PRODUCTION_THRESHOLD],
                    [recall_value],
                    s=65,
                    zorder=5
                )

        ax.set_xlim(
            x.min(),
            x.max()
        )

        ax.set_ylim(0, 1)

        ax.set_xlabel("Decision Threshold")
        ax.set_ylabel("Validation Score")

        ax.set_title(
            "HistGradientBoosting Validation Threshold Analysis"
        )

        ax.grid(alpha=0.25)
        ax.legend()

        save_figure(
            fig,
            "04_threshold_analysis"
        )


# =====================================================================
# 5. MALICIOUS SUBTYPE PERFORMANCE
# =====================================================================

subtypes_path = RESULTS / "final_test_subtypes.csv"

if subtypes_path.exists():

    subtypes = pd.read_csv(subtypes_path)

    print("\n" + "=" * 72)
    print("MALICIOUS SUBTYPE PERFORMANCE")
    print("=" * 72)

    print(subtypes.to_string(index=False))

    subtypes.to_csv(
        OUTPUT /
        "05_malicious_subtype_performance_table.csv",
        index=False
    )

    subtype_col = find_column(
        subtypes,
        ["subtype", "type", "class", "label"]
    )

    recall_col = find_column(
        subtypes,
        [
            "malicious_recall",
            "recall",
            "detection_rate",
            "true_positive_rate"
        ]
    )

    if subtype_col is not None and recall_col is not None:

        values = normalize_score_series(
            subtypes[recall_col]
        )

        labels = (
            subtypes[subtype_col]
            .astype(str)
            .str.replace("_", " ", regex=False)
            .str.title()
        )

        fig, ax = plt.subplots(figsize=(8, 5))

        bars = ax.bar(
            labels,
            values
        )

        ax.set_ylim(0, 1)
        ax.set_ylabel("Recall")

        ax.set_title(
            "Detection Recall by Malicious URL Subtype"
        )

        ax.grid(axis="y", alpha=0.25)

        add_bar_labels(
            ax,
            bars,
            values,
            percentage=True
        )

        save_figure(
            fig,
            "05_malicious_subtype_performance"
        )


# =====================================================================
# 6. ROBUSTNESS SUMMARY
# =====================================================================

robustness_path = RESULTS / "robustness_re_evaluation.csv"

if robustness_path.exists():

    robustness = pd.read_csv(robustness_path)

    print("\n" + "=" * 72)
    print("ROBUSTNESS RE-EVALUATION")
    print("=" * 72)

    print(robustness.to_string(index=False))

    # Preserve raw corrected robustness results.
    robustness.to_csv(
        OUTPUT /
        "06_robustness_re_evaluation_table.csv",
        index=False
    )

    required_columns = {
        "transformation",
        "probability_change",
        "prediction_flip"
    }

    if required_columns.issubset(robustness.columns):

        robustness["absolute_probability_change"] = (
            pd.to_numeric(
                robustness["probability_change"],
                errors="coerce"
            ).abs()
        )

        robustness["prediction_flip"] = pd.to_numeric(
            robustness["prediction_flip"],
            errors="coerce"
        )

        robustness_summary = (
            robustness
            .groupby(
                "transformation",
                as_index=False
            )
            .agg(
                samples=(
                    "transformation",
                    "size"
                ),
                mean_absolute_probability_change=(
                    "absolute_probability_change",
                    "mean"
                ),
                max_absolute_probability_change=(
                    "absolute_probability_change",
                    "max"
                ),
                prediction_flips=(
                    "prediction_flip",
                    "sum"
                )
            )
        )

        robustness_summary["prediction_flip_rate"] = (
            robustness_summary["prediction_flips"]
            / robustness_summary["samples"]
        )

        # More readable report ordering.
        preferred_order = [
            "scheme_http",
            "scheme_https",
            "added_subdomain",
            "path_noise",
            "query_noise",
            "percent_encoding",
            "unicode",
            "punycode",
        ]

        order_map = {
            name: index
            for index, name in enumerate(preferred_order)
        }

        robustness_summary["_order"] = (
            robustness_summary["transformation"]
            .map(order_map)
            .fillna(999)
        )

        robustness_summary = (
            robustness_summary
            .sort_values("_order")
            .drop(columns="_order")
            .reset_index(drop=True)
        )

        robustness_summary.to_csv(
            OUTPUT / "06_robustness_summary.csv",
            index=False
        )

        labels = (
            robustness_summary["transformation"]
            .str.replace("_", " ", regex=False)
            .str.title()
        )

        values = (
            robustness_summary[
                "mean_absolute_probability_change"
            ]
        )

        fig, ax = plt.subplots(figsize=(10.5, 5.7))

        bars = ax.bar(
            labels,
            values
        )

        ax.set_ylabel(
            "Mean Absolute Probability Change"
        )

        ax.set_title(
            "Corrected Model Robustness Under URL Transformations"
        )

        ax.tick_params(
            axis="x",
            rotation=30
        )

        ax.grid(
            axis="y",
            alpha=0.25
        )

        for bar, value in zip(bars, values):

            ax.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + 0.005,
                f"{value:.3f}",
                ha="center",
                va="bottom",
                fontsize=9
            )

        save_figure(
            fig,
            "06_robustness_summary"
        )


# =====================================================================
# 7. SCHEME INVARIANCE
# =====================================================================

scheme_path = RESULTS / "scheme_invariance.csv"

if scheme_path.exists():

    scheme = pd.read_csv(scheme_path)

    print("\n" + "=" * 72)
    print("SCHEME INVARIANCE")
    print("=" * 72)

    print(scheme.to_string(index=False))

    # Keep the raw table because it demonstrates that scheme variants
    # receive identical probabilities.
    scheme.to_csv(
        OUTPUT / "07_scheme_invariance_table.csv",
        index=False
    )

    # Create a concise summary grouped by URL family.
    if (
        "url" in scheme.columns
        and "probability" in scheme.columns
        and "group_probability_range" in scheme.columns
    ):

        scheme_summary = pd.DataFrame({
            "Maximum Probability Range": [
                pd.to_numeric(
                    scheme["group_probability_range"],
                    errors="coerce"
                ).max()
            ],
            "Scheme Invariant": [
                bool(
                    np.isclose(
                        pd.to_numeric(
                            scheme["group_probability_range"],
                            errors="coerce"
                        ).fillna(0).max(),
                        0.0
                    )
                )
            ]
        })

        scheme_summary.to_csv(
            OUTPUT / "07_scheme_invariance_summary.csv",
            index=False
        )


# =====================================================================
# 8. SCHEME DISTRIBUTION BY CLASS
# =====================================================================

scheme_distribution_path = (
    RESULTS /
    "scheme_distribution_by_class.csv"
)

if scheme_distribution_path.exists():

    scheme_distribution = pd.read_csv(
        scheme_distribution_path
    )

    print("\n" + "=" * 72)
    print("SCHEME DISTRIBUTION BY CLASS")
    print("=" * 72)

    print(
        scheme_distribution.to_string(
            index=False
        )
    )

    scheme_distribution.to_csv(
        OUTPUT /
        "08_scheme_distribution_by_class_table.csv",
        index=False
    )


# =====================================================================
# 9. PRODUCTION THRESHOLD SUMMARY
# =====================================================================

if threshold_path.exists():

    thresholds = pd.read_csv(threshold_path)

    threshold_col = find_column(
        thresholds,
        ["threshold", "decision_threshold"]
    )

    if threshold_col is not None:

        threshold_values = pd.to_numeric(
            thresholds[threshold_col],
            errors="coerce"
        )

        production_row = thresholds[
            np.isclose(
                threshold_values,
                PRODUCTION_THRESHOLD
            )
        ]

        if not production_row.empty:

            production_summary = production_row.copy()

            production_summary.insert(
                0,
                "purpose",
                "Production operating threshold selected from validation"
            )

            production_summary.to_csv(
                OUTPUT /
                "09_production_threshold_summary.csv",
                index=False
            )


# =====================================================================
# 10. ARTIFACT INDEX
# =====================================================================

summary_lines = [
    "NurtureShield - Final Result Artifacts",
    "======================================",
    "",
    "Generated from corrected NurtureShield experimental outputs.",
    "",
    "Production configuration:",
    "- Model: HistGradientBoostingClassifier",
    "- Feature count: 31",
    f"- Production threshold: {PRODUCTION_THRESHOLD:.2f}",
    "",
    "Evaluation note:",
    (
        "- The held-out test metrics and confusion matrix stored in "
        f"final_test_metrics.json use threshold "
        f"{TEST_EVALUATION_THRESHOLD:.2f}."
    ),
    (
        "- Threshold 0.30 was selected separately from validation "
        "analysis as the production operating threshold."
    ),
    (
        "- The held-out 0.24 confusion matrix must therefore not be "
        "presented as a 0.30 production confusion matrix."
    ),
    "",
    "Recommended report artifacts:",
    "- 01_final_model_performance.png",
    "- 02_confusion_matrix.png",
    "- 03_model_comparison.png",
    "- 04_threshold_analysis.png",
    "- 05_malicious_subtype_performance.png",
    "- 06_robustness_summary.png",
    "- 07_scheme_invariance_summary.csv",
    "- 09_production_threshold_summary.csv",
    "",
    "Generated files:",
]

for path in sorted(OUTPUT.iterdir()):

    if path.name != "ARTIFACTS.txt":
        summary_lines.append(
            f"- {path.name}"
        )

(OUTPUT / "ARTIFACTS.txt").write_text(
    "\n".join(summary_lines),
    encoding="utf-8"
)


# =====================================================================
# FINISHED
# =====================================================================

print("\n" + "=" * 72)
print("RESULT ARTIFACT GENERATION COMPLETE")
print("=" * 72)

print(f"\nOutput directory:\n{OUTPUT}\n")

print("Generated files:")

for path in sorted(OUTPUT.iterdir()):
    print(f"  - {path.name}")