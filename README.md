# Commit Detection - NPM Malware Analysis

Comprehensive commit analysis tool combining pre-analysis and static analysis with LangGraph and OpenAI LLM.

## Overview

This tool analyzes git repository commits to detect potential security issues and malicious code, specifically designed for npm packages. It implements a two-phase analysis workflow:

1. **Pre-Analysis Phase**: Analyzes metadata, contributor trust, and code changes
2. **Static Analysis Phase**: Uses OpenAI LLM to detect security vulnerabilities

## Features

### Pre-Analysis
- Repository metadata analysis
- Contributor trust scoring
- Sensitive file detection (package.json, build scripts, etc.)
- Change pattern analysis
- Large commit detection

### Static Analysis (LLM-powered)
The LLM analyzes code to detect:
- **Code Injection**: eval(), Function(), vm.runInNewContext
- **Suspicious Network Access**: Unexpected HTTP requests, data exfiltration
- **Data Leaks**: Exposure of credentials, tokens, sensitive data
- **Unsafe Environment Variables**: process.env access patterns
- **Crypto Activities**: Bitcoin, Ethereum, wallet operations, mining
- **Command Execution**: child_process, exec(), spawn()
- **Obfuscation**: Hex encoding, base64, suspicious patterns

## Installation

```bash
cd commit_detection
uv pip install -e .
```

## Configuration

Create a `.env` file with:

```env
OPENAI_API_KEY=your_openai_api_key
OPENAI_BASE_URL=https://api.openai.com/v1/

# LLM Configuration
LLM_MODEL=gpt-4o-mini
LLM_CONTEXT_WINDOW=128000

# Optional: Enable LangSmith tracing
LANGSMITH_API_KEY=your_langsmith_api_key
LANGSMITH_TRACING_V2=true
LANGSMITH_PROJECT=commit-detection
```

### Configuration Options
- `LLM_MODEL`: OpenAI model to use (default: `gpt-4o-mini`)
- `LLM_CONTEXT_WINDOW`: Maximum context window in tokens (default: `128000`)
  - gpt-4o-mini: 128,000 tokens
  - gpt-4o: 128,000 tokens  
  - gpt-4-turbo: 128,000 tokens
  - gpt-3.5-turbo: 16,385 tokens

The tool automatically handles large commits by:
1. Using `tiktoken` to count tokens accurately
2. Splitting large diffs into chunks based on file boundaries
3. Making multiple LLM requests with context from previous chunks
4. Maintaining analysis consistency across chunks

## Usage

### Basic Usage

```bash
python main.py <repo_path> <version_tag> [previous_tag]
```

### Examples

Analyze specific version:
```bash
python main.py ../mongoose 8.19.1
```

Compare two versions:
```bash
python main.py ../mongoose 8.19.1 8.19.0
```

### Output

The tool generates two files:
1. `analysis_report_<version>_<timestamp>.txt` - Human-readable report
2. `analysis_report_<version>_<timestamp>.json` - Structured JSON data (LLM-friendly)

### Exit Codes
- `0`: No issues found
- `1`: Security issues found (non-critical)
- `2`: Critical security issues found

## Architecture

### LangGraph Workflow

```
┌─────────────────┐
│  Pre-Analysis   │  Analyze metadata, contributors, changes
│     (Node 1)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Static Analysis │  LLM-powered vulnerability detection
│     (Node 2)    │
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ Generate Report │  Create comprehensive report
│     (Node 3)    │
└─────────────────┘
```

### Modules

- **main.py**: Entry point and LangGraph workflow orchestration
- **pre_analysis.py**: Repository analysis, contributor profiling, metadata detection
- **static_analysis.py**: LLM-powered security analysis

## LangSmith Integration

When `LANGSMITH_API_KEY` is configured, the workflow is automatically traced in LangSmith, allowing you to:
- Visualize the workflow execution
- Monitor LLM calls and token usage
- Debug and optimize analysis steps
- Track performance metrics

Visit [LangSmith](https://smith.langchain.com/) to view your traces.

## Example Output

```
================================================================================
NPM COMMIT DETECTION - COMPREHENSIVE ANALYSIS REPORT
================================================================================

Repository: ../mongoose
Version: 8.19.1
Previous Version: 8.19.0
Analysis Date: 2025-11-12T10:30:45

================================================================================
PART 1: PRE-ANALYSIS
================================================================================

Total commits analyzed: 15
Sensitive files modified: 3
New contributors: 1
⚠️  Build/install scripts modified: postinstall.js

================================================================================
PART 2: STATIC ANALYSIS
================================================================================

Total Security Issues Found: 2

Issues by Severity:
  HIGH: 1
  MEDIUM: 1

[1] HIGH - suspicious_network
    Commit: a1b2c3d4
    File: lib/network.js
    Description: Unexpected HTTP request to external domain
    Recommendation: Review and validate the necessity of this network call
```

## Based On

This tool implements concepts from:
- **Anomalicious** paper (arXiv:2103.03846): Pre-analysis methodology
- **LangGraph**: Workflow orchestration
- **LangSmith**: Observability and tracing

## Development

### Run Tests
```bash
pytest test_*.py
```

### Lint
```bash
ruff check .
```

## License

MIT
