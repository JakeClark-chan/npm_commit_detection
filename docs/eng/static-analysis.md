# Static Analysis Phase

## 1. Overview
The **Static Analysis Phase** serves as the core inspection engine of the system. Unlike traditional SAST tools that rely solely on pattern matching (regex), this module leverages the semantic understanding capabilities of Large Language Models (LLMs) to detect complex malicious behaviors, such as logic bombs, obfuscated payloads, and subtle backdoors that regex would miss.

## 2. Methodology

The static analysis pipeline (`llm/static_analysis.py`) follows a structured approach:
1.  **Deobfuscation**: Pre-processing code to reveal hidden intents (detailed in [Deobfuscation Documentation](./deobfuscation.md)).
2.  **File Filtering & Risk Scoring**: Prioritizing files to analyze to optimize Token usage and Performance.
3.  **Pattern Detection**: Fast heuristic scan for suspicious keywords.
4.  **Deep LLM Inspection**: Sending high-risk code diffs to the LLM for semantic analysis.

### 2.1. File Risk Scoring Algorithm
To handle large commits efficiently, we calculate a **Risk Score ($S_{risk}$)** for every changed file. Only files with the highest scores are forwarded to the LLM.

The risk score for a file $f$ is calculated as:

$$
S_{risk}(f) = S_{ext}(f) + S_{content}(f) + S_{sensitive}(f)
$$

Where:
*   **$S_{ext}(f)$ (Extension Score)**:
    *   Build Configs (`.vscode`, `tasks.json`): $10$ points
    *   System Scripts (`.sh`, `.bash`): $8$ points
    *   Core Logic (`.js`, `.ts`): $5$ points
    *   Web/Other (`.html`, `.php`): $3$ points
    *   Default: $1$ point
*   **$S_{content}(f)$ (Content Score)**: Based on regex pattern matches.
    *   $S_{content} = 2 \times N_{matches}$, where $N_{matches}$ is the count of unique suspicious categories found (e.g., `eval`, `network`).
*   **$S_{sensitive}(f)$**: $+5$ points if the file is in the "Sensitive Files" watchlist.

**Selection Strategy**: The system selects the **Top N** (default: 10) files with the highest $S_{risk}$ for LLM analysis.

### 2.2. Suspicious Pattern Detection
We employ a dictionary of Regular Expressions to identifying suspicious capabilities before LLM analysis. Categories include:
*   **Execution**: `eval`, `exec`, `spawn`, `Function(string)`.
*   **Network**: `http.get`, `curl`, `wget`, `fetch`, `axios`.
*   **Obfuscation**: `\x[0-9a-f]`, `base64`, `rot13`, `fromCharCode`.
*   **Environment**: `process.env`, `/etc/shadow`, `whoami`.

### 2.3. LLM Analysis Logic
The filtered code changes are consolidated into a structured prompt context.

**Input Context**:
*   Commit Metadata (Author, Message).
*   Consolidated Diff of Top-Risk Files (cleaned to remove deletion noise).
*   Global Suspicious Pattern findings.

**Model**: OpenAI GPT-4o-mini (optimized for speed/cost) or GPT-4o (for higher accuracy).

**Prompt Structure**:
> "You are a cybersecurity expert specializing in detecting supply chain attacks... Analyze the following code changes for malicious intent. Ignore style changes. Focus on: arbitrary code execution, data exfiltration, and obfuscation. Return findings in JSON."

### 2.4. Import Analysis
In parallel, the system parses Import/Require statements to detect new dependencies.
*   **Goal**: Detect "Typosquatting" or known malicious packages.
*   **Heuristic**: Checks imports against a watchlist of suspicious terms (`crypto`, `child_process`, `net`) and flags them for the verification phase.

## 3. Output
The Static Analysis module produces a JSON object containing:
*   `total_issues`: Count of detected vulnerabilities.
*   `issues`: List of `SecurityIssue` objects, each containing:
    *   `severity`: CRITICAL, HIGH, MEDIUM, LOW.
    *   `category`: Type of attack (e.g., `code_injection`).
    *   `file_path`, `line_number`.
    *   `description`: LLM-generated explanation.
    *   `recommendation`: remediation steps.
