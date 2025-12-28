# GitHub Actions Integration

## 1. Overview
Integrating the **NPM Commit Detection System** into a Continuous Integration (CI) pipeline enables automated security auditing for every code change. This ensures that no malicious commit is deployed to production or published to the NPM registry.

## 2. CI Architecture
The CI workflow operates as a **Gatekeeper**:
1.  **Trigger**: Push to `main` branch or standard Pull Request.
2.  **Environment**: Ubuntu-latest runner (GitHub Actions).
3.  **Action**:
    *   Checkout code.
    *   Install dependencies.
    *   Run `commit_detection` in **Validation Mode**.
4.  **Enforcement**:
    *   If `is_malicious == True` $\rightarrow$ **Fail Build** & Notify Security Team.
    *   If `is_malicious == False` $\rightarrow$ **Pass Build**.

## 3. Workflow Configuration (`.github/workflows/security-scan.yaml`)

```yaml
name: NPM Security Scan

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  security-check:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      pull-requests: write

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python
      uses: actions/setup-python@v4
      with:
        python-version: '3.10'

    - name: Install Dependencies
      run: |
        pip install -r requirements.txt
        npm install -g snyk

    - name: Run Commit Detection
      env:
        OPENAI_API_KEY: ${{ secrets.OPENAI_API_KEY }}
        SNYK_TOKEN: ${{ secrets.SNYK_TOKEN }}
      run: |
        python main.py --repo_path . --scan_latest
        
    - name: Upload Report
      if: always()
      uses: actions/upload-artifact@v3
      with:
        name: security-report
        path: reports/verification_report_*.md
```

## 4. Failure Handling
When a malicious commit is detected, the workflow returns a non-zero exit code (e.g., `exit 1`).
*   **GitHub UI**: The PR is blocked from merging.
*   **Artifacts**: The detailed verification report is uploaded for review.
*   **Notifications**: Can be configured to send alerts to Slack/Discord webhooks.
