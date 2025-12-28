# Pre-Analysis Phase

## 1. Overview
The **Pre-Analysis Phase** acts as a rapid filtering layer designed to identify "high-risk" commits and reduce the computational load for subsequent, more expensive analysis stages (Static and Dynamic). By analyzing metadata, contributor patterns, and file statistics, it provides a preliminary risk assessment.

## 2. Methodology

The pre-analysis module (`analyzers/pre_analysis.py`) performs three key assessments:

1.  **Metadata Analysis**: Inspects commit messages and timestamps using Git metadata.
2.  **Contributor Trust Scoring**: Evaluates the reputation of the committer.
3.  **Change Analysis**: Quantifies code churn and detects usage of sensitive files.

### 2.1. Contributor Trust Scoring
We implement a heuristic-based trust scoring system to identify potental "insider threats" or compromised accounts, as well as new contributors who might introduce malicious code.

For a contributor $C$, the Trust Score $T_C$ is calculated as:

$$
T_C = \min\left(\frac{N_{commits}}{50}, 1.0\right)
$$

Where:
*   $N_{commits}$: Total number of commits by the contributor in the history of the repository.
*   The score ranges from $0.0$ (Untrusted/New) to $1.0$ (Fully Trusted).
*   **Thresholds**:
    *   $T_C \ge 0.7$: Trusted Contributor.
    *   $T_C < 0.3$: Low-trust/Suspicious Contributor.
    *   New Contributor: Defined as having $< 5$ total commits.

### 2.2. Sensitive File Detection
The system maintains a list of sensitive file patterns (RegEx) that are frequent targets for malware injection (e.g., build scripts, configuration files).

**Detection Algorithm**:
Input: List of changed files $F = \{f_1, f_2, ...\}$
Output: Set of sensitive files $S \subseteq F$

Let $P$ be the set of sensitive patterns (e.g., `package.json`, `install.sh`, `.env`, `.github/workflows/.*`).
A file $f_i$ is flagged if:
$$
\exists p \in P : \text{match}(f_i, p) = \text{True}
$$

**Critical Alerts**:
*   Modifications to `package.json` trigger a dependency check alert.
*   Modifications to build scripts (`install.sh`, `setup.js`) trigger a high-priority alert.

### 2.3. Change Anomaly Detection
We analyze the volume of code changes to detect anomalies such as "Large Commits" which may attempt to hide malicious code within a massive refactor.

**Metric**: Net Change $ \Delta = \sum Additions - \sum Deletions $
**Anomaly Rule**:
$$
\text{IsLargeCommit}(c) = 
\begin{cases} 
\text{True} & \text{if } (Additions + Deletions) > 500 \\
\text{False} & \text{otherwise}
\end{cases}
$$

## 3. Implementation Details
The `PreAnalyzer` class orchestrates these checks.

*   `get_commit_metadata(sha)`: Extracts standard Git fields.
*   `build_contributor_profiles(shas)`: Aggregates historical data to compute $T_C$.
*   `_analyze_changes(shas)`: Computes statistical metrics on code churn.

## 4. Output
The result is a structured JSON and textual report containing:
*   List of new/untrusted contributors.
*   List of modified sensitive files.
*   List of anomalous large commits.
*   **Actionable Signal**: If critical files are modified or the contributor is untrusted, the subsequent Static Analysis phase will elevate the **Risk Score** for the affected files.
