# NurtureShield

**Machine Learning-Based Malicious URL and Phishing Detection System**

> **Check the link before you trust the click.**

NurtureShield is a machine-learning-based security tool that detects potentially malicious URLs using their lexical and structural characteristics. It analyzes URLs locally as text without automatically visiting or fetching the destination.

## Features

- Detects **phishing, malware, and defacement URLs**
- Uses a **HistGradientBoosting** classifier
- Extracts **31 URL-based security features**
- Performs URL analysis without visiting the destination
- Uses corrected URL canonicalization to reduce representation bias
- Provides probability-based malicious URL detection
- Supports integration with a web application and browser extension

## How It Works

```text
URL
 │
 ▼
URL Canonicalization
 │
 ▼
31-Feature Extraction
 │
 ▼
HistGradientBoosting Model
 │
 ▼
Malicious Probability
 │
 ▼
Decision Threshold (0.30)
 │
 ├── Legitimate
 └── Malicious
```

## Project Structure

```text
NurtureShield/
├── Dataset/
│   └── malicious_phish.csv
├── pipeline/
│   └── nurtureshield_corrected_pipeline.py
├── model/
│   ├── features.py
│   ├── final_model_config.json
│   └── hist_gradient_boosting.joblib
├── results/
│   └── evaluation and robustness results
├── requirements.txt
├── .gitignore
└── README.md
```

## Dataset

The model is trained using the **Malicious URLs Dataset** from Kaggle:

https://www.kaggle.com/datasets/sid321axn/malicious-urls-dataset

The dataset contains four URL categories:

- Benign
- Phishing
- Defacement
- Malware

For binary classification, phishing, defacement, and malware URLs are treated as **malicious**, while benign URLs are treated as **legitimate**.

The dataset is not included in this repository. Download `malicious_phish.csv` from Kaggle and place it inside the `Dataset/` directory.

## Setup

Clone the repository:

```bash
git clone https://github.com/abdulrehman142/NurtureShield.git
cd NurtureShield
```

Create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

## Run the Pipeline

Place the dataset at:

```text
Dataset/malicious_phish.csv
```

Then run:

```bash
python pipeline/nurtureshield_corrected_pipeline.py \
  --input Dataset/malicious_phish.csv \
  --output-dir corrected_artifacts
```

## Model

| Component | Configuration |
|---|---|
| Classifier | HistGradientBoostingClassifier |
| Features | 31 |
| Classification | Binary |
| Legitimate Label | 0 |
| Malicious Label | 1 |
| Decision Threshold | 0.30 |
| Analysis | URL-only |

The final trained model and production feature extractor are available in the `model/` directory.

## Security Note

NurtureShield performs **URL-only analysis**. It does not automatically visit, execute, scrape, or download content from the submitted destination.

A legitimate prediction does not guarantee that a website is safe; the model provides a machine-learning-based risk assessment from URL characteristics.
