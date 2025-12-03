# NPM Commit Detection - Interactive TUI Mode

## Overview

The TUI (Text User Interface) mode provides an interactive, user-friendly way to configure and run commit detection analyses using `fzf` for menu navigation.

## Installation

### Prerequisites

1. **fzf** - Fuzzy finder for terminal
   ```bash
   # Ubuntu/Debian
   sudo apt install fzf
   
   # macOS
   brew install fzf
   
   # Arch Linux
   sudo pacman -S fzf
   ```

2. **Python dependencies**
   ```bash
   pip install -r requirements.txt
   ```

## Usage

### Interactive Mode (TUI)

Simply run `main.py` without any arguments to enter interactive mode:

```bash
cd commit_detection
python main.py
```

### Command-Line Mode

Traditional command-line usage is still supported:

```bash
# Static analysis only
python main.py /path/to/repo v1.2.0 v1.1.0

# Static + Dynamic analysis
python main.py /path/to/repo v1.2.0 v1.1.0 --dynamic abc123def

# Dynamic analysis with specific commit
python main.py /path/to/repo v1.2.0 --dynamic abc123def
```

## TUI Workflow

The interactive mode guides you through 5 phases:

### Phase 1: Repository Selection

Choose how to select a repository:

1. **Select from local folder**
   - Recursively scans current directory for Git repositories
   - Shows: `<Folder> - <Package Name> - <Git Remote URL>`
   - Navigate up directories with `<< GO UP ONE DIRECTORY`
   - Returns to main menu with `<< BACK TO MAIN MENU`

2. **Clone from remote URL**
   - Enter a Git repository URL
   - Automatically clones to `/tmp/npm_commit_detection_<name>_<timestamp>`
   - Useful for analyzing remote packages without manual cloning

3. **Choose from recent history**
   - Shows recently used repositories (up to 20 entries)
   - Displays repository path, name, remote URL, and last accessed date
   - History stored in `~/.npm_commit_detection_history.json`

### Phase 2: Choose End Point (Destination Tag)

- Lists all tags from the repository, sorted by date (newest first)
- Shows format: `<tag> (YYYY-MM-DD)`
- Option to skip static analysis: `<< SKIP STATIC ANALYSIS`
- This tag serves as the end point for commit range analysis

### Phase 3: Choose Start Point

- Lists tags that come before the end tag (chronologically)
- Shows format: `<tag> (YYYY-MM-DD)`
- Can be left empty to analyze from the beginning of the repository
- Skipped automatically if static analysis was skipped in Phase 2

### Phase 4: Choose Commit for Dynamic Analysis

- Lists commits between start and end tags
- Shows format: `<hash> (YYYY-MM-DD) - <commit subject>`
- Sorted by date (newest first)
- Default selection: latest commit in the range
- Option to skip: `<< SKIP DYNAMIC ANALYSIS`

### Phase 5: Confirmation and Execution

Displays a comprehensive summary:

```
==============================================================
CONFIGURATION SUMMARY
==============================================================
Repository: /path/to/repo
Package Name: example-package
Remote URL: https://github.com/user/repo.git

STATIC ANALYSIS:
  End Tag: v1.2.0
  Start Tag: v1.1.0

DYNAMIC ANALYSIS:
  Commit Hash: abc123def

✅ Automatically verify both analyses after completion
==============================================================
```

Options:
- `✅ CONFIRM AND START ANALYSIS` - Proceed with analysis
- `❌ CANCEL` - Return to repository selection

## Features

### Parallel Execution

When both static and dynamic analyses are selected:
- Runs both analyses in parallel using ThreadPoolExecutor
- Significantly reduces total execution time
- Shows progress for each analysis independently

### Automatic Verification

When both analyses complete:
- Automatically runs verification to compare findings
- Uses LLM to normalize and match results
- Generates comprehensive verification report

### Server Availability Handling

For dynamic analysis:
- Checks if Package Hunter server (localhost:3000) is available
- If not available, waits up to 5 minutes for server to start
- Shows waiting status every 30 seconds
- Provides instructions if timeout occurs

### History Management

- Automatically saves used repositories to history
- Stores: repository path, package name, remote URL, timestamp
- Maximum 20 entries (oldest automatically removed)
- Deduplicates entries (recent usage updates timestamp)

### Minimal Output Mode

During execution:
- Shows essential progress messages only
- Hides verbose details unless errors occur
- Clear success/failure indicators with emoji
- Structured output with clear section separators

## Output Files

All reports are saved to the `reports/` directory:

### Static Analysis
- `analysis_report_<tag>_<timestamp>.json` - Structured JSON data
- `analysis_report_<tag>_<timestamp>.txt` - Human-readable report (legacy)

### Dynamic Analysis
- `dynamic_report_<hash>_<timestamp>.json` - Package Hunter results

### Verification
- `verification_report_<timestamp>.json` - Comparison results
- `verification_report_<timestamp>.txt` - Detailed verification report

## Navigation Keys

Within fzf menus:

- `↑/↓` or `Ctrl-K/Ctrl-J` - Navigate items
- `Enter` - Select item
- `Esc` or `Ctrl-C` - Cancel/Go back
- Type to filter items (fuzzy search)
- `Ctrl-P/Ctrl-N` - Previous/Next item
- `Tab` - Toggle selection (multi-select mode)

## Examples

### Example 1: Quick Analysis of Local Repository

```bash
python main.py
# 1. Select "1. Select from local folder"
# 2. Choose your repository from the list
# 3. Select end tag (e.g., "v1.2.0")
# 4. Select start tag (e.g., "v1.1.0")
# 5. Choose a commit for dynamic analysis
# 6. Confirm and start
```

### Example 2: Analyze Remote Repository

```bash
python main.py
# 1. Select "2. Clone from remote URL"
# 2. Enter: https://github.com/Automattic/mongoose.git
# 3. Select tags and commit as needed
# 4. Confirm and start
```

### Example 3: Static Analysis Only

```bash
python main.py
# 1. Select repository
# 2. Select end tag
# 3. Select start tag
# 4. Select "<< SKIP DYNAMIC ANALYSIS>"
# 5. Confirm
```

### Example 4: Use Recent Repository

```bash
python main.py
# 1. Select "3. Choose from recent history"
# 2. Choose from previously used repositories
# 3. Continue with tag/commit selection
```

## Exit Codes

- `0` - Success, no issues found
- `1` - Security issues found (non-critical)
- `2` - Critical security issues found
- `130` - User interrupted (Ctrl-C)

## Troubleshooting

### fzf not found
```
❌ Error: fzf is not installed on your system.
```
**Solution:** Install fzf using your package manager (see Installation section)

### No Git repositories found
```
❌ No Git repositories found in current directory
```
**Solution:** 
- Navigate to a directory containing Git repositories
- Use "Go up one directory" to search parent directories
- Use "Clone from remote URL" option instead

### Package Hunter server not available
```
⏳ Package Hunter server (localhost:3000) is not available
   Waiting for server to start...
```
**Solution:** Start the Package Hunter server in another terminal:
```bash
cd /path/to/package-hunter
FALCO_TOKEN=<your-token> NODE_ENV=development DEBUG=pkgs* node src/server.js
```

### Repository no longer exists (from history)
```
❌ Repository no longer exists: /tmp/npm_commit_detection_repo_123456
```
**Solution:** The temporary repository was deleted. Clone again or select a different repository.

## Advanced Configuration

### Environment Variables

- `OPENAI_API_KEY` - Required for LLM-based analysis
- `LANGSMITH_API_KEY` - Optional, enables LangSmith tracing
- `LANGSMITH_PROJECT` - LangSmith project name
- `FALCO_TOKEN` - Package Hunter authorization token
- `POLL_INTERVAL` - Seconds between status polls (default: 2)
- `ANALYSIS_TIMEOUT` - Maximum analysis time in seconds (default: 300)

### History File Location

History is stored at: `~/.npm_commit_detection_history.json`

To clear history:
```bash
rm ~/.npm_commit_detection_history.json
```

To view history:
```bash
cat ~/.npm_commit_detection_history.json | jq
```

## Tips

1. **Use fuzzy search**: Type part of the repository/tag name to quickly filter
2. **Recent history**: Use history for frequently analyzed repositories
3. **Parallel execution**: Select both analyses to save time
4. **Skip options**: Use skip options when you only need one type of analysis
5. **Navigate efficiently**: Use `<< GO UP ONE DIRECTORY` to explore parent folders
