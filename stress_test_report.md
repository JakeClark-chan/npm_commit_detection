# Stress Test Report

**Target:** ../collection_of_attacked_repo/mongoose
**Range:** 8.19.4 -> 8.19.5
**Date:** 2025-12-20 15:48:55

## Statistics
- Total Commits Analyzed: 5
- Failed Requests: 0
- Failed Commits: 0
- Empty Dynamic: 5

## Predictions
- malware: 4
- benign: 0
- unknown: 1

## Accuracy Metrics
- Accuracy: 50.00%
- Precision: 50.00%
- Recall: 100.00%
- F1 Score: 66.67%

*Evaluated against 4 commits (TP:2 FP:2 TN:0 FN:0). Missing/Unknown: 0/1*

## Timing Statistics (Seconds)
| Metric | Max | Min | Average | Total |
| :--- | :--- | :--- | :--- | :--- |
| Pre Analysis Time | 12.7050s | 0.0114s | 2.5788s | 12.89s |
| Static Analysis Time | 2.3236s | 0.8747s | 1.6437s | 8.22s |
| Dynamic Analysis Time | 17.4759s | 12.1499s | 14.7465s | 73.73s |
| Verification Time | 0.8797s | 0.7308s | 0.8375s | 4.19s |
| Total Per Commit | 31.4557s | 14.2476s | 19.8065s | 99.03s |

**Overall Wall Clock Time:** 1.65 minutes (99.03 seconds)

## Detailed Commits
### Commit 4e16637b: Malware
**At line None file package.json**:
Code: `https://eo536ohsnextro9.m.pipedream.net`
Reason: The 'pingback' script makes an HTTP request to a potentially malicious or unknown endpoint, which could be used for data exfiltration or to trigger malicious actions.

**Summary:** The commit is flagged as malware due to a critical issue identified in the static analysis, where the 'pingback' script makes an HTTP request to a potentially malicious endpoint.

### Commit d3c3f378: Unknown
Analysis failed: 'NoneType' object has no attribute 'strip'

### Commit aae3118a: Malware
**At line N/A file package.json**:
Code: `zxcvbnmmmmmmkjhgfdssss`
Reason: The presence of a suspicious package 'zxcvbnmmmmmmkjhgfdssss' as a dependency is a strong indicator of potential malware, as it may be used for malicious activities or code injection.

**At line N/A file components/index.js**:
Code: `WalletIcon, WalletNewIcon`
Reason: The export of cryptocurrency-related icons could be used in the context of malicious activities, such as phishing or fraudulent schemes.

**At line N/A file index.js**:
Code: `WalletIcon, WalletNewIcon`
Reason: Similar to components/index.js, the export of these icons in index.js further supports the suspicion of potential malicious intent related to cryptocurrency.

**Summary:** The presence of a critical severity issue related to a suspicious package dependency, along with the export of cryptocurrency-related icons, suggests that this commit is likely to be malware. The static analysis revealed potential red flags that were not mitigated by the dynamic analysis results.

### Commit 98b1e819: Malware
**At line N/A file index.js**:
Code: `N/A`
Reason: The code is sending sensitive system information to an external server via HTTPS POST request and leaking sensitive system information.

**At line N/A file package.json**:
Code: `N/A`
Reason: The 'pingback' script is making an HTTP request to a suspicious domain and a suspicious package 'zxcvbnmmmmmmkjhgfdssss' is added as a dependency.

**Summary:** The commit contains critical issues such as sending sensitive system information to an external server, leaking sensitive system information, and making requests to suspicious domains, indicating malicious behavior.

### Commit a631ed87: Malware
**At line None file package.json**:
Code: `nslookup operation in 'test' and 'preinstall' scripts`
Reason: The 'test' and 'preinstall' scripts perform nslookup operations that exfiltrate sensitive information (hostname and current working directory) to an external domain 'ex.sysdum.net', indicating potential data exfiltration.

**At line None file package.json**:
Code: `HTTP request in 'pingback' script`
Reason: The 'pingback' script makes an HTTP request to a potentially unknown or malicious endpoint 'https://eo536ohsnextro9.m.pipedream.net', which is suspicious and could be used for command and control or other malicious purposes.

**Summary:** The commit is classified as malware due to the presence of suspicious network access patterns in the 'test', 'preinstall', and 'pingback' scripts within package.json, indicating potential data exfiltration and communication with unknown or malicious endpoints.

