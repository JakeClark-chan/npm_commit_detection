# Real-World Experiment: Stress Testing

## 1. Objective
Beyond synthetic datasets, validating the tool against **real-world malware** found in the wild is crucial. This experiment aimed to stress-test the system against a curated list of active malicious repositories to evaluate its robustness and ability to handle diverse obfuscation techniques used by actual attackers.

## 2. Methodology
We developed a specialized stress-test suite (`stress_test_realworld.py`) that operates on a live list of compromised or malicious repositories (`list-of-realworld-repo.json`).

*   **Scope**: 12 known malicious repositories involving data theft, crypto-mining, and remote access trojans (RATs).
*   **Constraint**: The test was confined to **Static Analysis only** to ensure safety and speed, simulating a pre-commit hook scenario where running dynamic analysis might be too slow.
*   **Concurrency**: Utilized a Thread Pool with 8 workers to process multiple commits simultaneously.

## 3. Findings

### 3.1. Successful Detections
The system successfully identified sophisticated patterns:
*   **Obfuscated Install Scripts**: Detected `install.js` files containing hex-encoded payloads designed to download binaries completely invisible to simple regex.
*   **Hidden Cron Jobs**: Identified attempts to write to `/etc/cron.d` for persistence.
*   **Supply Chain Attacks**: Detected malicious dependency modifications in `package.json`.

### 3.2. LLM Reasoning Capabilities
One of the most significant findings was the LLM's ability to "connect the dots".
> *Example*: In one repo, the code split a malicious URL into three separate string variables and concatenated them only at the point of the `fetch` call. The Static Analysis LLM correctly reconstructed the string and flagged the domain as a C2 server.

## 4. Challenges Identified
*   **Token Limits**: Extremely large minified files occasionally exceeded the LLM's context window. We implemented a "Chunking Strategy" to mitigate this, but it sometimes broke the semantic context.
*   **Ambiguous Scripts**: Some "malicious" behavior (e.g., telemetry reporting) looked identical to legitimate analytics code.

## 5. Summary
The real-world stress test confirmed that the system is production-ready for identifying high-impact threats. It demonstrated that even without dynamic analysis, the enhanced Static Analysis (LLM + Deobfuscation) is highly effective at catching current malware trends.
