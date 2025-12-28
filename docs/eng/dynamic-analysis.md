# Dynamic Analysis Phase

## 1. Overview
Static analysis, while powerful, can be bypassed by sophisticated obfuscation or code that creates logic at runtime. The **Dynamic Analysis Phase** addresses this limitation by executing the code in a controlled sandbox environment and monitoring its real-time behavior.

## 2. Technology Stack
We utilize **Package Hunter**, a Falco-based behavior monitoring tool tailored for Npm packages.
*   **Engine**: `sysdig/package-hunter`.
*   **Monitor**: Sysdig Falco (Kernel-level system call interception).
*   **Trace Targets**: Network connections, File system modifications, Process spawning.

## 3. Workflow

The dynamic analysis module (`tools/dynamic_analysis.py`) executes the following lifecycle:

1.  **Preparation**:
    *   Checkout the repository at the specific commit $C$.
    *   Execute `npm pack` to generate a tarball ($P_{tgz}$), simulating exactly what would be published to the registry.

2.  **Submission**:
    *   Upload $P_{tgz}$ to the local Package Hunter server via API ($P_{tgz} \rightarrow \text{localhost:3000}$).

3.  **Execution & Monitoring**:
    *   Package Hunter installs the package in a Docker container.
    *   It executes distinct lifecycle hooks: `preinstall`, `install`, `postinstall`, and `test`.
    *   Falco drivers intercept syscalls matched against security rules.

4.  **Result Aggregation**:
    *   The system polls the API for the analysis status.
    *   Upon completion, it retrieves a JSON report containing a list of **Events**.

## 4. Detection Capabilities

The system detects "IOCs" (Indicators of Compromise) mapped to Falco rules:

### 4.1. Network Activity
*   **Suspicious Outbound Connections**: Connections to non-standard ports or known C2 (Command & Control) IPs.
*   **DNS Exfiltration**: High volume of DNS requests.

### 4.2. File System
*   **Sensitive Read**: Access to `/etc/shadow`, `~/.ssh/id_rsa`, `.env`.
*   **Persistence**: Writing to `/etc/cron.d`, `~/.bashrc`.

### 4.3. Process Execution
*   **Shell Spawning**: `sh -c`, `bash`, `cmd.exe` triggered by install scripts.
*   **Reverse Shells**: Pipes connected to network sockets.

## 5. Limitation Handling
Dynamic analysis is computationally expensive and requires a running server.
*   **Optimization**: It is only triggered if a specific commit hash is provided (targeted mode) or if Static Analysis flags a commit as "High Risk but Ambiguous" (future work).
*   **Timeout**: Analysis is capped at 300 seconds to prevent denial of service by infinite loops.
