# Verification Phase

## 1. Overview
The **Verification Phase** is the final decision-making engine of the pipeline. It correlates findings from the disparate analysis modules (Static, Dynamic, Snyk) to eliminate false positives and confirm true positives. By reducing the noise inherent in individual tools, it provides a high-confidence verdict.

## 2. Methodology

The verification logic (`llm/verification.py`) employs a **Multi-Stage Correlation Algorithm**:

### 2.1. Normalization
First, outputs from all tools are mapped to a unified `NormalizedFinding` schema:
*   `category`: e.g., `code_injection`, `network_access`.
*   `severity`: CRITICAL, HIGH, MEDIUM, LOW.
*   `evidence`: Code snippet (Static) or System Call/Log (Dynamic).
*   `location`: File path (Static) or Process/IP (Dynamic).

### 2.2. Cross-Analysis Matching
We use an LLM to semantically match findings across domains.
Let $S$ be static findings and $D$ be dynamic findings. A match $M(s, d)$ is established if:
$$
\text{SemanticSimilarity}(s_{desc}, d_{desc}) > \theta \quad \text{AND} \quad \text{ContextMatch}(s_{file}, d_{process})
$$

*Example*:
*   **Static**: Found `child_process.exec("curl " + url)` in `install.js`.
*   **Dynamic**: Detected process `curl` spawning with arguments matching a URL pattern.
*   **Result**: **CONFIRMED MATCH** (High Confidence).

### 2.3. Verdict Generation
The final verdict is determined by the "Confirmation Matrix":

| Static Severity | Dynamic Confirmation | Snyk Confirmation | Verdict |
| :--- | :--- | :--- | :--- |
| HIGH/CRITICAL | Yes | - | **MALICIOUS** |
| HIGH/CRITICAL | - | Yes | **MALICIOUS** |
| MEDIUM | Yes | - | **SUSPICIOUS** (Review) |
| HIGH | No | No | **SUSPICIOUS** (Potential Dead Code) |
| LOW | - | - | **BENIGN** |

### 2.4. LLM Synthesis
Finally, the system uses the LLM to generate a human-readable **Comprehensive Report**.
*   It summarizes the confirmed matches.
*   It explains *why* the commit is considered malicious (e.g., "The install script executes a reverse shell which was confirmed by runtime monitoring connecting to IP 1.2.3.4").

## 3. Output
The module produces a Markdown report (`verification_report_*.md`) and a final status code:
*   `is_malicious`: Boolean flag.
*   `malicious_confidence`: Float (0.0 - 1.0).
