import os
import json
import glob
import re
from datetime import datetime

REPORTS_DIR = "../reports"
OUTPUT_FILE = "all_dynamic_report.json"

def get_latest_reports():
    # Pattern: dynamic_report_<commit_hash>_<date>_<time>.json
    # Example: dynamic_report_12991f90_20251203_161237.json
    pattern = re.compile(r"dynamic_report_([a-f0-9]+)_(\d{8})_(\d{6})\.json")
    
    reports = {} # commit_hash -> {path, timestamp}
    
    files = glob.glob(os.path.join(REPORTS_DIR, "dynamic_report_*.json"))
    print(f"Found {len(files)} report files.")
    
    for file_path in files:
        filename = os.path.basename(file_path)
        match = pattern.match(filename)
        if match:
            commit_hash = match.group(1)
            date_str = match.group(2)
            time_str = match.group(3)
            
            try:
                dt = datetime.strptime(f"{date_str}{time_str}", "%Y%m%d%H%M%S")
                timestamp = dt.timestamp()
                
                if commit_hash not in reports or timestamp > reports[commit_hash]['timestamp']:
                    reports[commit_hash] = {
                        'path': file_path,
                        'timestamp': timestamp
                    }
            except ValueError:
                print(f"Skipping malformed timestamp in: {filename}")
                continue
    
    print(f"identified {len(reports)} unique commits with reports.")
    return reports

def create_cache(reports_map):
    cache = {}
    
    for commit, info in reports_map.items():
        try:
            with open(info['path'], 'r') as f:
                data = json.load(f)
                cache[commit] = data
        except Exception as e:
            print(f"Error reading {info['path']}: {e}")
            
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(cache, f, indent=2)
        
    print(f"Successfully cached {len(cache)} reports into {OUTPUT_FILE}")

if __name__ == "__main__":
    if not os.path.exists(REPORTS_DIR):
        print(f"Directory {REPORTS_DIR} not found.")
    else:
        latest_reports = get_latest_reports()
        create_cache(latest_reports)
