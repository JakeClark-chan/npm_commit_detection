# Experiment Setup

## 1. Environment
All experiments were conducted on a Linux workstation with the following specifications to ensure consistent performance measurement:
*   **OS**: Linux (Kernel 6.x)
*   **Hardware**: 8 vCPUs, 16GB RAM.
*   **Software Dependencies**:
    *   Python 3.10+
    *   Docker Engine (for Package Hunter sandbox)
    *   Falco (System Call Monitor)
    *   Snyk CLI (v1.1290.0)

## 2. Dataset
To evaluate the system's effectiveness, we curated a diverse dataset comprising both benign and malicious samples.

### 2.1. Malicious Dataset (Positive Class)
We utilized the **Malware-Packages** dataset and real-world samples identified in recent supply chain attacks.
*   **Total Malicious Samples**: 50 repositories/commits.
*   **Attack Types**:
    *   **Reverse Shell**: Payload connecting to external C2.
    *   **Data Exfiltration**: Stealing `/etc/passwd` or ENV variables.
    *   **Logic Bombs**: Malicious behavior triggered only on production environments.
    *   **Typosquatting**: Packages mimicking popular libraries (e.g., `mongoose` vs malicious clones).

### 2.2. Benign Dataset (Negative Class)
We selected top-tier Npm packages to test for false positives.
*   **Repositories**: `express`, `lodash`, `react`, `axios`.
*   **Total Benign Samples**: 100 commits (randomly sampled from history).

## 3. Evaluation Metrics
We measure the performance using standard Information Retrieval metrics.

### 3.1. Confusion Matrix
*   **True Positive (TP)**: Malicious commit correctly identified as MALICIOUS.
*   **False Positive (FP)**: Benign commit incorrectly flagged as MALICIOUS/SUSPICIOUS.
*   **True Negative (TN)**: Benign commit correctly identified as BENIGN.
*   **False Negative (FN)**: Malicious commit missed (labeled as BENIGN).

### 3.2. Derived Metrics
$$
\text{Precision} = \frac{TP}{TP + FP}
$$

$$
\text{Recall} = \frac{TP}{TP + FN}
$$

$$
F1\text{-Score} = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}
$$

### 3.3. Performance Metrics
*   **Latency**: Average time to analyze a single commit (seconds).
*   **Overhead**: CPU/Memory usage during parallel analysis.
