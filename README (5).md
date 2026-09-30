
#Network intrusion detection system (IDS) Simulation 


## Overview 

The **Network Intrusion Detection System (IDS) Simulation** is a comprehensive, production-style cybersecurity monitoring application. It ingests simulated network flow records, extracts advanced statistical indicators, evaluates traffic through multi-layered signature rules and statistical anomaly detection models, fuses risk scores, and presents actionable intelligence on a real-time Security Operations Center (SOC) dashboard.
## Problem statement 

Modern enterprises face relentless probing, brute-force attacks, port scanning, and data exfiltration attempts. Security Operations Centers (SOCs) are flooded with high volumes of raw network telemetry and alert fatigue. Security analysts require practical visibility tools capable of parsing network flows, differentiating normal application traffic from suspicious anomalies, correlating related alerts, and facilitating rapid incident triage.
##  Objectives 

1. **Simulate Enterprise Telemetry:** Generate realistic synthetic network traffic records representing normal web browsing, DNS queries, and anomalous behavior.
2. **Multi-Layered Detection:** Implement deterministic signature-based rules alongside statistical Z-score anomaly detection and optional machine learning classification.
3. **Hybrid Risk Scoring:** Fuse multi-engine findings into a single risk score (0–100) with dynamic alert severity ratings.
4. **SOC Triage Workflow:** Build a professional dashboard supporting incident status transitions (`NEW` → `INVESTIGATING` → `RESOLVED` / `FALSE_POSITIVE`), analyst notes, and alert correlation.
## Cybersecurity Relevance 

•This project mirrors how enterprise security teams deploy and interact with network security monitoring (NSM) and NIDS tools like Suricata, Snort, or cloud VPC Flow Log analytics. It demonstrates core competencies required for **SOC Analyst**, **Threat Detection Engineer**, and **Incident Responder** roles.

## IDS concept

*   **IDS vs. IPS:** Passive monitoring and alerting vs. active inline blocking. This project is strictly an **IDS** to preserve analysis visibility.
*   **Signature-Based Detection:** Matching known threat patterns (e.g., high connection rates or high SYN ratios) against established rules.
*   **Anomaly-Based Detection:** Identifying deviations from baseline operational standards using statistical variance.
## Architecture 

Synthetic Traffic Generator
            ↓
    Flow Collection API
            ↓
   Feature Extractor
            ↓
┌───────────────────────┐
│ Rule Engine           │
│ Statistical Anomaly   │
│ Optional ML Model     │
└───────────────────────┘
            ↓
    Hybrid Risk Engine
            ↓
     Alert Engine
            ↓
     SQLite Database
            ↓
   SOC Web Dashboard
            ↓
 Analyst Triage Workflow
## Technology stack

-Core Logic: Python 3.9+
-Backend API: Flask, Flask-CORS, SQLite
-Machine Learning: Scikit-Learn, NumPy, Joblib, Pandas
-Frontend UI: React.js, Vite, Axios, CSS3
## Synthetic dataset

The dataset generator creates 5,500+ structured flow records (data/network_traffic.csv) adhering strictly to reserved IP ranges (192.0.2.0/24, 198.51.100.0/24) representing safe, synthetic normal and suspicious scenarios without any external network touching.
## Traffic simulator 

The traffic simulator (simulator/traffic_simulator.py) continuously emits synthetic network flow JSON records to the backend ingestion endpoint in real time (--mode normal or --mode mixed).
## Feature engineering 

Extracts key security metrics from raw flows:

-bytes_per_second / packets_per_second: Volumetric analysis.
-failure_ratio: Brute-force and scanning indicator.
-syn_ratio: SYN flood detection.
-connection_rate: Rapid connection frequency.

## Signature-based detection 


Evaluates flows against configurable deterministic rules (IDS-001 through IDS-006) checking connection thresholds, SYN ratios, and service port probes.
## Anomaly detection

Calculates statistical Z-scores against baseline traffic means and standard deviations, generating an anomaly score from 0 to 100.
## Machine learning 

An optional supervised Random Forest Classifier trained on engineered flow features, evaluated using Accuracy, Precision, Recall, and Confusion Matrices.
## Risk scoring 

Maps combined scores to operational classifications:

0–20: NORMAL
21–50: SUSPICIOUS
51–100: POTENTIAL INTRUSION (Severity: Low, Medium, High, Critical)
## Alerts generation 

Automatically structures high-risk observations into formal security alerts containing timestamps, source/destination IPs, rules matched, and initial status (NEW).
## Alerts Correlation 

Groups related alerts originating from the same source IP within sliding time windows to reduce alert fatigue.
## SOC dashboard 

A real-time cybersecurity interface displaying metric cards (Total Flows, Normal vs. Suspicious, Open/Critical Alerts, Avg Risk Score) and an active security alert queue.
## Incident Investigation 


Allows SOC Tier 1 analysts to click alerts, view investigation details, update status (NEW → INVESTIGATING → RESOLVED / FALSE_POSITIVE), and log custom analyst triage notes.
## API documentation 

-POST /api/flows: Ingest new network flow.

-GET /api/dashboard/stats: Retrieve SOC summary metrics.

-GET /api/alerts: List active security alerts.

-PUT /api/alerts/{id}/status: Update alert workflow status.

-POST /api/alerts/{id}/notes: Append analyst triage notes.
## Usage

Generate Dataset: python simulator/generate_dataset.py
Train ML Model: python ml/train_model.py
Start Backend: cd backend && python app.py
Start Frontend: cd frontend && npm install && npm run dev
Start Simulator: python simulator/traffic_simulator.py --mode mixed
## Security 

-Uses strictly synthetic flow data.
Does not capture or store packet payloads.
Backend inputs validated against malformed IPs and invalid ports.
## Results 

Successfully demonstrates real-time detection of synthetic multi-port probing, SYN flooding, and brute-force indicators with an intuitive SOC workflow interface.

## False Positives & False Negatives 

-False Positives: Legitimate administrative bursts (e.g., database backups) can trigger anomaly rules. Mitigated by threshold tuning and analyst feedback.

-False Negatives: Slow-and-low scanning techniques may fall below baseline variance thresholds. Mitigated by hybrid ML integration..
## Limitations 

-Simulated flows rather than live promiscuous packet capture (libpcap).

-Static baseline statistical models.
## Future improvement 

-Integrate Suricata EVE-JSON log ingestion.
Add integration connectors for SIEM tools (Elasticsearch/Splunk).

-Deploy containerized multi-container Docker Compose architecture.
## Learning outcomes 

-Mastered network flow telemetry analysis and feature engineering.

-Designed a multi-layered hybrid intrusion detection engine.

-Built an end-to-end SOC incident investigation workflow.
## Disclaimer 

This project is designed exclusively for defensive cybersecurity education.
All suspicious network behavior is represented using synthetic data or authorized isolated lab environments. Do NOT use these techniques against unauthorized networks or systems.



## Author

* **GitHub:** [nandiniveram2009](https://github.com)
* **LinkedIn:** [Nandini Verma](https://linkedin.com)



## Machine learning 

An optional supervised Random Forest Classifier trained on engineered flow features, evaluated using Accuracy, Precision, Recall, and Confusion Matrices.
## Risk scoring 

Maps combined scores to operational classifications:

0–20: NORMAL
21–50: SUSPICIOUS
51–100: POTENTIAL INTRUSION (Severity: Low, Medium, High, Critical)
## API documentation 

-POST /api/flows: Ingest new network flow.

-GET /api/dashboard/stats: Retrieve SOC summary metrics.

-GET /api/alerts: List active security alerts.

-PUT /api/alerts/{id}/status: Update alert workflow status.

-POST /api/alerts/{id}/notes: Append analyst triage notes.