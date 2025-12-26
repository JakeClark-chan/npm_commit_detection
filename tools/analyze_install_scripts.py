import json
import subprocess
import os

REPO_PATH = "../collection_of_attacked_repo/mongoose"
TRUTH_FILE = "truth_commits.json"
FROM_TAG = "8.19.4"
TO_TAG = "8.19.5"

def analyze_scripts():
    # 1. Load Truth Labels
    with open(TRUTH_FILE, 'r') as f:
        truth_data = json.load(f)
    truth_map = {item['hash']: item['label'] for item in truth_data}
    
    # 2. Get Commits
    cmd = ["git", "-C", REPO_PATH, "log", f"{FROM_TAG}..{TO_TAG}", "--pretty=format:%H"]
    result = subprocess.run(cmd, capture_output=True, text=True, check=True)
    commits = result.stdout.strip().split('\n')
    commits = [c for c in commits if c]
    
    print(f"Analyzing {len(commits)} commits for install scripts...")
    
    has_scripts_count = 0
    malware_with_scripts = 0
    benign_with_scripts = 0
    unknown_with_scripts = 0
    
    details = []
    
    for i, sha in enumerate(commits):
        # 3. Check for preinstall/postinstall additions in package.json
        # We look for lines added ('+') in package.json containing "preinstall" or "postinstall"
        
        # Check if package.json was changed
        diff_cmd = ["git", "-C", REPO_PATH, "show", sha, "--", "package.json"]
        diff_res = subprocess.run(diff_cmd, capture_output=True, text=True) # Don't check=True, might be empty if file not exists/changed
        
        diff_content = diff_res.stdout
        
        has_script = False
        if diff_content:
            for line in diff_content.splitlines():
                if line.startswith('+') and not line.startswith('+++'):
                    lower_line = line.lower()
                    if '"preinstall"' in lower_line or "'preinstall'" in lower_line or \
                       '"postinstall"' in lower_line or "'postinstall'" in lower_line:
                        has_script = True
                        break
        
        if has_script:
            has_scripts_count += 1
            label = truth_map.get(sha, "unknown")
            
            if label == "malware":
                malware_with_scripts += 1
            elif label == "benign":
                benign_with_scripts += 1
            else:
                unknown_with_scripts += 1
                
            details.append(f"- {sha[:8]} ({label}): Found install script")
            
    print("\n## Install Script Analysis")
    print(f"- Total Commits with Install Scripts: {has_scripts_count}")
    print(f"  - Malware: {malware_with_scripts}")
    print(f"  - Benign: {benign_with_scripts}")
    # print(f"  - Unknown: {unknown_with_scripts}")
    
    # print("\n### Details")
    # for d in details:
    #     print(d)

if __name__ == "__main__":
    analyze_scripts()
