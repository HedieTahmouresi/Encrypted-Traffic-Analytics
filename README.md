<div align="center">

# 🛡️ Split-Edge NIDS: Encrypted Traffic Analysis
**A 2-Tier Machine Learning Intrusion Detection System for TLS 1.2/1.3**

![Python](https://img.shields.io/badge/Python-3776AB?style=for-the-badge&logo=python&logoColor=white)
![Zeek](https://img.shields.io/badge/Zeek-4A4A4A?style=for-the-badge&logo=linux&logoColor=white)
![XGBoost](https://img.shields.io/badge/XGBoost-1793D1?style=for-the-badge&logo=databricks&logoColor=white)
![scikit-learn](https://img.shields.io/badge/scikit--learn-F7931E?style=for-the-badge&logo=scikit-learn&logoColor=white)
![Pandas](https://img.shields.io/badge/Pandas-150458?style=for-the-badge&logo=pandas&logoColor=white)

</div>

## 📌 Project Overview
As network encryption becomes ubiquitous, traditional Deep Packet Inspection (DPI) is increasingly blind to malicious payloads. This project introduces a high-performance Network Intrusion Detection System (NIDS) designed to identify and classify modern cyber threats hidden within encrypted tunnels, strictly **without decrypting the payload**.

By analyzing the metadata "envelope" (unencrypted TLS handshakes) and the physical geometry of the flow (packet sizes, inter-arrival times), this system preserves data privacy while maintaining uncompromising network security. 

---

## 🏗️ Architecture: 2-Tier Split-Edge Design
The system utilizes a distributed inference pipeline, decoupling high-speed flow metrics from computationally heavy metadata extraction to solve the latency bottlenecks of encrypted traffic analysis.

### ⚡ Tier 1: The Edge Filter (High-Speed Bouncer)
* **Role:** Deployed at the network edge to make instant, low-latency binary decisions on every connection.
* **Model:** Logistic Regression.
* **Feature Set:** Universal Flow Metrics (NFStream). Analyzes packet inter-arrival times, flow duration, and forward/backward byte ratios.
* **Action:** Benign traffic flows normally. Anomalies trigger Tier 2 escalation.

### 🧠 Tier 2: The Gateway (Deep Threat Analyzer)
* **Role:** Deployed at a centralized gateway to perform multi-class threat classification on flagged anomalies.
* **Model:** Tree Ensemble (XGBoost).
* **Feature Set:** The Hybrid Set. Combines Tier 1 geometry with heavy TLS metadata extracted from the unencrypted `ClientHello` packet (SNI, cipher suites) via Zeek.

---

## 🧩 Data Engineering & The Hybrid Extractor
Relying on standard benchmark CSVs (like the raw CIC-IDS2017) introduces data integrity flaws, as ~25% of generated flows contain incomplete metrics. To ensure production-grade reliability, this system processes raw `.pcap` files directly using a custom **Hybrid Feature Extractor** (`src/feature_extractor.py`).

1. **NFStream (Statistical Geometry):** Captures the exact sequence of packet lengths and time deltas (`splt_analysis=10`), flushing inactive states dynamically.
2. **Zeek (Event-Driven Logs):** A custom script (`ml_extractor.zeek`) parses connection states, TLS handshakes, and authentication events (e.g., SSH/FTP failures) in real-time, even if the connection is maliciously aborted.
3. **The Merger Engine:** Eliminates Cartesian explosion by strictly aligning NFStream and Zeek vectors using a bidirectional 5-tuple hash and a chronological sliding floor (`pd.merge_asof` with a 2000ms tolerance). 
4. **Time-Based Rolling Windows:** Automated attacks like Brute Force rely on multiple connection requests. The preprocessor computes 60-second rolling aggregates over identical 5-tuple targets to catch multi-connection brute-forcing attempts.
5. **Anti-Leakage Preprocessor:** The `StreamPreprocessor` rigorously drops "cheating" features (IP addresses, MACs, L7 plaintext leaks) before inference, forcing the models to learn true protocol behaviors rather than memorizing dataset artifacts.

---

## 🛑 Threat Detection Capabilities
The inference engine categorizes network behavior into the following states:

* `0` **Benign:** Normal, human-driven web and network traffic.
* `1` **Low & Slow DoS:** Identifies highly regular, mathematical timing gaps (e.g., Slowloris) designed to exhaust server sockets.
* `2` **L7 Web Flood:** Detects anomalous HTTP geometries and skewed forward/backward byte ratios.
* `3` **DDoS (Volume Attacks):** Recognizes severe reductions in packet inter-arrival times (highly dense bursts) and anomalous TCP flag distributions (e.g., Hulk, GoldenEye).
* `4` **Brute Force:** Catches systematic automated SSH/FTP attempts using 60s rolling failure windows combined with machine-like packet timing intervals.
* `5` **Exploit (Heartbleed):** Tracks anomalous payload lengths specified in unencrypted TLS heartbeat requests relative to the actual network packets returned by the server.

---

## 🛠️ Installation & Setup
This project is heavily optimized for native Linux environments (Ubuntu 24.04+). 

### 1. Clone the Repository
```bash
git clone [https://github.com/yourusername/encrypted-traffic-analytics.git](https://github.com/yourusername/encrypted-traffic-analytics.git)
cd encrypted-traffic-analytics

```

### 2. Environment Setup

The provided setup script automatically installs Zeek from the official OpenSUSE repositories and installs all required Python dependencies in one step.

```bash
chmod +x setup.sh run.sh
./setup.sh

```

---

## 🚀 Live Inference Usage

To run the NIDS against a captured PCAP file or a live interface pipeline, simply execute the runner script. This initializes the Hybrid Extractor and feeds the resulting matrices into the trained XGBoost/LR pipelines.

```bash
./run.sh

```

**Expected Terminal Output:**

```text
============================================================
 🛡️ ENCRYPTED TRAFFIC ANALYTICS - LIVE INFERENCE ENGINE 🛡️
============================================================

[*] Starting packet capture and hybrid feature extraction...
[*] Running NFStream on ./data/raw/test.pcap...
[+] NFStream extraction complete.
[*] Running Zeek on ./data/raw/test.pcap...
[+] Zeek extraction complete.
[*] Merging NFStream and Zeek features...
[+] Merge complete. Final dataset shape: (X, Y)

[*] Live Detection Started...
------------------------------------------------------------
[🚨 THREAT DETECTED] Type: Brute Force
    Target Flow: 192.168.1.50 -> 10.0.0.5:22

[🚨 THREAT DETECTED] Type: Low & Slow DoS
    Target Flow: 192.168.1.100 -> 10.0.0.5:443
------------------------------------------------------------
[*] Inference Session Complete.
    Total Flows Processed: 1042
    Benign Passed: 1040 | Anomalies Blocked: 2
============================================================

```

---

## 📚 Academic Foundations

The architecture, feature selection, and ML methodologies of this NIDS were built upon foundational research, notably:

1. *Enhanced Malicious Traffic Detection in Encrypted Communication Using TLS Features and a Multi-class Classifier Ensemble.*
2. *Encrypted Traffic Analytics (ETA): Machine Learning Approaches for Intrusion Detection Without Decryption.*
3. *Network Intrusion Datasets: A Survey on Limitations and Recommendations.*
   
