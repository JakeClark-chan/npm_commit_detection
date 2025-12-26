
import json
import random
import subprocess
import shutil
import os
from pathlib import Path

# Configuration
REPO_PATH = Path("../collection_of_attacked_repo/mongoose")
MALWARE_SOURCE = Path("../npm_malware_extracted")
BENIGN_SOURCE = Path("../npm_benign_extracted")
TRUTH_FILE = Path("truth_commits.json")
OUTPUT_FILE = Path("truth_subset_commits.json")
BASE_TAG = "8.19.4"
NEW_TAG = "8.19.5"
COUNT_PER_TYPE = 50

def run_command(cmd, cwd=None):
    subprocess.run(cmd, shell=True, check=True, cwd=cwd or REPO_PATH)

def get_git_hash(cwd=None):
    result = subprocess.run("git rev-parse HEAD", shell=True, capture_output=True, text=True, cwd=cwd or REPO_PATH)
    return result.stdout.strip()

def main():
    print(f"Reading {TRUTH_FILE}...")
    with open(TRUTH_FILE, 'r') as f:
        all_commits = json.load(f)

    malware = [c for c in all_commits if c['label'] == 'malware']
    benign = [c for c in all_commits if c['label'] == 'benign']

    print(f"Found {len(malware)} malware and {len(benign)} benign samples.")

    # Select subsets
    selected_malware = random.sample(malware, min(COUNT_PER_TYPE, len(malware)))
    selected_benign = random.sample(benign, min(COUNT_PER_TYPE, len(benign)))
    
    subset = selected_malware + selected_benign
    random.shuffle(subset)
    print(f"Selected {len(subset)} commits for generation.")

    # Prepare Repo
    print(f" preparing repo at {REPO_PATH}...")
    # Checkout base tag and create branch
    run_command(f"git checkout {BASE_TAG}")
    run_command(f"git checkout -b stress-test-{NEW_TAG}")

    new_truth = []

    for i, commit_info in enumerate(subset):
        label = commit_info['label']
        sample_folder = commit_info['sample_folder']
        
        # Determine source directory
        if label == 'malware':
            src_dir = MALWARE_SOURCE / sample_folder
        else:
            src_dir = BENIGN_SOURCE / sample_folder
            
        if not src_dir.exists():
            print(f"Warning: Source {src_dir} does not exist. Skipping.")
            continue

        print(f"[{i+1}/{len(subset)}] applying {label} sample: {sample_folder}")

        # METHOD: Revert to BASE content, then apply new content.
        # This ensures "Diff" is effectively "Remove Old Sample + Add New Sample" 
        # (plus incidental base restore if sample modified base).
        
        # 1. Reset working tree and index to BASE_TAG content, but keep HEAD where it is.
        # We use `git checkout BASE_TAG -- .` 
        # This stages the "revert to base" changes.
        run_command(f"git checkout {BASE_TAG} -- .")

        # 2. Copy new sample files over
        # We use a simple copy. 'cp -r' or python shutil.
        # We must avoid copying .git directories if any exist in source.
        for item in src_dir.iterdir():
            if item.name == '.git':
                continue
            
            dest = REPO_PATH / item.name
            if item.is_dir():
                if dest.exists():
                    shutil.rmtree(dest)
                shutil.copytree(item, dest)
            else:
                shutil.copy2(item, dest)

        # 3. Stage and Commit
        run_command("git add .")
        
        msg = f"Update to {sample_folder} ({label})"
        # Allow empty commits if for some reason content matches base exactly (unlikely but safe)
        run_command(f"git commit --allow-empty -m '{msg}'")

        # 4. Record new hash
        new_hash = get_git_hash()
        new_entry = {
            "hash": new_hash,
            "sample_folder": sample_folder,
            "label": label,
            "original_hash": commit_info.get("hash") # Track origin if needed
        }
        new_truth.append(new_entry)

    # Tag
    run_command(f"git tag {NEW_TAG}")
    print(f"Tagged {NEW_TAG}")

    # Save Truth
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(new_truth, f, indent=2)
    print(f"Saved {len(new_truth)} entries to {OUTPUT_FILE}")

if __name__ == "__main__":
    main()
