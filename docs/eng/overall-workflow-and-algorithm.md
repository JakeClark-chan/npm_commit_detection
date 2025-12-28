# Overall Workflow and Algorithm

## 1. Overview
The **NPM Commit Detection System** is a comprehensive security analysis pipeline designed to detect malicious code injections in NPM package updates (commits). The system integrates multiple analysis techniques—static analysis (enhanced by LLMs), dynamic analysis (runtime monitoring), and third-party security scanning (Snyk)—into a unified workflow orchestrated to maximize detection accuracy and minimize false positives.

The core philosophy is "Defense in Depth":
1.  **Pre-analysis**: Rapidly filters and prioritizes files based on metadata and heuristics.
2.  **Static Analysis**: Deep code inspection using Large Language Models (LLMs) to understand semantics and obfuscation.
3.  **Dynamic Analysis**: Runtime behavioral monitoring to capture malicious actions (network connections, file system access).
4.  **Verification**: A cross-referencing stage where an LLM correlates findings from all tools to produce a final high-confidence verdict.

## 2. System Architecture

The workflow is orchestrated as a Directed Acyclic Graph (DAG) or a parallel execution pipeline depending on the input context (single commit vs. version range).

### High-Level Algorithm
Input: $R$ (Repository), $C$ (Target Commit or Version Range)
Output: $V$ (Verdict: MALICIOUS/BENIGN), $Report$

1.  **Initialization**:
    *   Validate repository $R$.
    *   Identify target commits $\{c_1, c_2, ..., c_n\}$ from $C$.

2.  **Phase 1: Pre-Analysis (Per Commit)**:
    *   Extract metadata (author, timestamp, message).
    *   Calculate **Contributor Trust Score** ($T_{contributor}$).
    *   Identify changed files and filter by extensions/sensitivity.
    *   *Goal*: Reduce search space for computationally expensive steps.

3.  **Phase 2: Parallel Analysis**:
    The system executes the following modules concurrently using a Thread Pool:
    
    *   **Module A: Static Analysis (LLM-based)**
        *   **Deobfuscation**: If code is obfuscated (detected by heuristics/entropy), apply `DeobfuscatorAgent`.
            *   $Code_{clean} = Deobfuscate(Code_{obfuscated})$
        *   **Risk Scoring**: specific files are prioritized based on extension and content patterns.
        *   **LLM Scan**: $Issues_{static} = LLM_{analyze}(Code_{clean}, Context)$
    
    *   **Module B: Dynamic Analysis (Package Hunter)**
        *   Pack the repository at commit $c_i$ into an NPM tarball.
        *   Execute inside a sandbox (Falco-monitored container).
        *   Capture system calls (network, file, process).
        *   $Issues_{dynamic} = Normalize(Logs_{falco})$
    
    *   **Module C: Snyk SAST**
        *   Run Snyk Code engine on changed files.
        *   $Issues_{snyk} = Snyk(Files_{changed})$

4.  **Phase 3: Verification & Correlation**:
    *   Normalize all findings into a unified schema $F = \{f | f \in Issues_{static} \cup Issues_{dynamic} \cup Issues_{snyk}\}$.
    *   **Cross-Matching**: Use LLM to find semantic correlations between findings from different sources (e.g., Static detection of `eval()` matches Dynamic detection of `execve`).
        *   $Match(f_a, f_b) \iff SemanticSimilarity(f_a, f_b) > Threshold$
    *   **Verdict Generation**:
        *   If $\exists (f_{static}, f_{dynamic})$ such that $Match(f_{static}, f_{dynamic})$ is MALICIOUS $\implies$ **VERDICT = MALICIOUS**.
        *   Else if High Confidence Static/Dynamic independently $\implies$ **Review Required**.

## 3. Core Algorithms

### 3.1. Orchestration Logic
The main execution flow is implemented in `main.py` using a `ThreadPoolExecutor`.

```python
def run_analysis(config):
    # Parallel Execution Strategy
    futures = {}
    with ThreadPoolExecutor() as executor:
        # Submit Static Analysis Task
        futures[executor.submit(run_static_analysis, ...)] = 'static'
        
        # Submit Dynamic Analysis Task (if applicable)
        if config.use_dynamic:
            futures[executor.submit(run_dynamic_analysis, ...)] = 'dynamic'
            
        # Submit Snyk Analysis Task (if applicable)
        if config.use_snyk:
            futures[executor.submit(run_snyk_analysis, ...)] = 'snyk'
            
    # Collect and Verify
    results = gather_results(futures)
    final_report = run_verification(results.static, results.dynamic, results.snyk)
    return final_report
```

### 3.2. Verification & Scoring
The final scoring relies on confirming static suspicions with dynamic evidence. The system avoids a simple weighted sum in favor of a **Confirmation Model**.

Let $S$ be the set of static findings and $D$ be the set of dynamic findings.
We define a matching function $M(s, d)$ via an LLM prompt that evaluates if finding $s \in S$ explains event $d \in D$.

$$
Verdict = 
\begin{cases} 
\text{MALICIOUS} & \text{if } \exists s \in S, d \in D : M(s, d) = \text{True} \land Severity(s) \ge \text{HIGH} \\
\text{SUSPICIOUS} & \text{if } S \neq \emptyset \lor D \neq \emptyset \\
\text{BENIGN} & \text{otherwise}
\end{cases}
$$

This binary confirmation prevents false positives common in static analysis (dead code) and dynamic analysis (benign install scripts).
