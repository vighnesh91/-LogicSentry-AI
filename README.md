# LogicSentry AI

**LogicSentry AI** is a deterministic, offline application security triage engine designed to run entirely inside your local runtime environment. It combines static application security testing (**SAST**) and dynamic application security testing (**DAST**) to isolate critical business logic vulnerabilities, identify hidden privilege flaws, and suppress heuristic false positives without internet dependencies.

---

## 🚀 Key Features

* **Combined SAST & DAST Analysis:** Directly maps source-code routes (Python, JavaScript/TypeScript, PHP, Java/Spring Boot) and uses them to intelligently supplement dynamic black-box testing.
* **Offline-First AI Triage:** Employs an ultra-lightweight, local LLM pipeline (`Qwen2.5-0.5B-Instruct`) to score findings and filter out noisy false positives entirely on your local machine.
* **Business-Logic Fuzzing:** Automatically targets parameters tied to core pricing indexes, quantities, discounts, and authorization layers (`price`, `quantity`, `amount`, `role`, etc.).
* **Advanced Replay & Concurrency Checks:** 
  * **BOLA Validation:** Compares multi-identity context flows (User A vs. User B).
  * **Race Conditions:** Fires synchronized concurrent requests to test transactional integrity.
  * **Sequential Anti-Replay:** Validates step-skipping and idempotency.

---

## 📦 Core Requirements

LogicSentry AI requires **Python 3.11 or newer**. 

Install the required framework wrappers via pip:
```bash
python -m pip install pydantic>=2,<3 aiohttp>=3.9,<4 rich>=13
```

### Optional Configurations
* **Offline AI Triage:** Install `transformers`, `torch`, and `accelerate` to enable local model evaluation. (If weights are missing, the tool safely fails open and retains heuristic leads).
* **Automated URL Tracking:** Install `playwright` to enable headless browser interaction for real-time traffic captures.

---

## 💻 CLI Usage Examples

### 1. Automated URL Capture & Active DAST Scan
Provide a target domain, capture standard same-origin requests, and execute active mutations:
```bash
python LogicSentryAI.py --auto-capture-url "https://test-environment.local" --confirm-active
```

### 2. Static Source & Manual HAR Combination (Grey-Box Scan)
Bundle code structures into a ZIP file and feed an authenticated HTTP traffic file (`.har`) to run precise targeted differential analysis:
```bash
python LogicSentryAI.py \
  --src ./source-code-bundle.zip \
  --har ./traffic-capture.har \
  --target "api.internal.local" \
  --confirm-active \
  --output report.md
```

### 3. Testing for BOLA and Identity Flaws
Pass User A's traffic context along with User B's authentication signatures to scan for authorization bypasses:
```bash
python LogicSentryAI.py \
  --har ./traffic-capture.har \
  --target "api.internal.local" \
  --confirm-active \
  --secondary-header "Authorization: Bearer <User_B_Token>"
```

### 4. Running Concurrency & Transactional Race Tests
Verify balance mutations or duplication constraints by sending multiple synchronized micro-requests:
```bash
python LogicSentryAI.py --har ./traffic-capture.har --target "api.internal.local" --confirm-active --test-race --race-count 15
```

---

## 🛠 Command-Line Parameter Overview

| Flag | Type | Description |
| :--- | :--- | :--- |
| `--src` | `Path` | Target ZIP file holding application source files for static review. |
| `--har` | `Path` | An exported HTTP Archive file providing transaction baselines. |
| `--auto-capture-url` | `URL` | Spawns automated runtime crawl pipelines to dynamically harvest traffic maps. |
| `--target` | `String` | Regex pattern or hostname segment isolating matching HAR requests. |
| `--header` | `Name:Value` | Replaces or pushes designated authentication keys into User A baseline queries. |
| `--test-race` | `Flag` | Triggers simultaneous connection barrages against target workflow endpoints. |
| `--output` | `Path` | Path to save output findings (`.md`, `.json`, `.html`, `.sarif`). |
| `--fail-on` | `Choice` | Breaks builder execution if severities meet target limits (`High`, `Critical`, etc.). |

---

## 🛡 CI/CD Integration (GitHub Actions)

Generate a pre-configured GitHub Actions orchestration blueprint automatically:
```bash
python LogicSentryAI.py --generate-pipeline
```
This automatically updates your local workspace with `.github/workflows/logicsentry-ai-scan.yml`, allowing you to plug automated business-logic validation checks right into your development pipeline.

---

## ⚖ Disclaimer
This utility is intended exclusively for **authorized security testing** on systems you own or have explicit legal permission to audit. The author assumes no liability for misuse, service disruptions, or damage caused by this software.
