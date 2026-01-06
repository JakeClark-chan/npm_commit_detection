#!/usr/bin/env python3
"""
Dynamic Analysis Module for NPM Package Malware Detection
Performs runtime analysis using Package Hunter (Falco-based sandbox)
"""

import os
import sys
import json
import time
import subprocess
import requests
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from urllib.parse import urlparse

from dotenv import load_dotenv

# Load environment variables
load_dotenv()


class DynamicAnalyzer:
    """Performs dynamic analysis of NPM packages using Package Hunter"""
    
    def __init__(
        self,
        package_hunter_url: str = "http://localhost:3000",
        poll_interval: int = 2,
        timeout: int = 300,
        auth_token: Optional[str] = None
    ):
        self.package_hunter_url = package_hunter_url.rstrip('/')
        self.poll_interval = poll_interval
        self.timeout = timeout
        self.auth_token = auth_token or os.getenv("FALCO_TOKEN")
        self.reports_dir = Path(__file__).parent.parent / "reports"
        self.reports_dir.mkdir(exist_ok=True)
    
    def _get_headers(self, content_type: Optional[str] = None) -> Dict[str, str]:
        """Get request headers with optional authorization"""
        headers = {}
        if self.auth_token:
            headers['Authorization'] = f'Bearer {self.auth_token}'
        if content_type:
            headers['Content-Type'] = content_type
        return headers
    
    def _check_server_availability(self) -> bool:
        """Check if Package Hunter server is available"""
        try:
            response = requests.get(
                f"{self.package_hunter_url}/",
                headers=self._get_headers(),
                timeout=5
            )
            # Server is available if it responds with any status code (including error responses)
            # A 200 with error JSON means the server is running and responding
            if response.status_code in [200, 400, 401]:
                # Check if it's a JSON error response indicating the server is alive
                try:
                    data = response.json()
                    # If we get {"status":"error","reason":"..."}, server is available
                    if isinstance(data, dict) and data.get('status') == 'error':
                        return True
                except:
                    pass
                return True
            return False
        except requests.exceptions.RequestException as e:
            print(f"❌ Package Hunter server not available: {e}")
            return False
    
    def _npm_pack(self, repo_path: str, commit_hash: str) -> Optional[str]:
        """
        Checkout commit and create npm package tarball
        Returns the .tgz filename or None on failure
        """
        repo_path = Path(repo_path).resolve()
        
        if not repo_path.exists():
            print(f"❌ Repository not found: {repo_path}")
            return None
        
        print(f"📦 Preparing package at commit {commit_hash[:8]}...")
        
        try:
            # Checkout the specific commit
            subprocess.run(
                ["git", "checkout", commit_hash],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )

            # Run npm pack
            result = subprocess.run(
                ["npm", "pack"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            # Extract .tgz filename from output
            output_lines = result.stdout.strip().split('\n')
            tgz_file = None
            for line in output_lines:
                if line.endswith('.tgz'):
                    tgz_file = line.strip()
                    break
            
            if not tgz_file:
                print(f"❌ Could not find .tgz file in npm pack output")
                return None
            
            tgz_path = repo_path / tgz_file
            if not tgz_path.exists():
                print(f"❌ Package file not found: {tgz_path}")
                return None
            
            print(f"✅ Package created: {tgz_file}")
            return str(tgz_path)
            
        except subprocess.CalledProcessError as e:
            print(f"❌ Failed to create package: {e.stderr}")
            return None
    
    def _upload_package(self, tgz_path: str) -> Optional[str]:
        """
        Upload package to Package Hunter for analysis
        Returns analysis ID or None on failure
        """
        print(f"📤 Uploading package to {self.package_hunter_url}...")
        
        try:
            with open(tgz_path, 'rb') as f:
                response = requests.post(
                    f"{self.package_hunter_url}/monitor/project/npm",
                    data=f.read(),
                    headers=self._get_headers('application/octet-stream'),
                    timeout=30
                )
            
            if response.status_code != 200:
                print(f"❌ Upload failed with status {response.status_code}: {response.text}")
                return None
            
            result = response.json()
            analysis_id = result.get('id')
            
            if not analysis_id:
                print(f"❌ No analysis ID in response: {result}")
                return None
            
            print(f"✅ Package uploaded, analysis ID: {analysis_id}")
            return analysis_id
            
        except requests.exceptions.RequestException as e:
            print(f"❌ Upload request failed: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"❌ Invalid JSON response: {e}")
            return None
    
    def _poll_results(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """
        Poll Package Hunter for analysis results
        Returns analysis results or None on failure/timeout
        """
        print(f"⏳ Polling for results (ID: {analysis_id})...")
        
        start_time = time.time()
        poll_count = 0
        
        while True:
            elapsed = time.time() - start_time
            
            if elapsed > self.timeout:
                print(f"❌ Timeout after {self.timeout}s waiting for analysis")
                return None
            
            try:
                response = requests.get(
                    f"{self.package_hunter_url}/?id={analysis_id}",
                    headers=self._get_headers(),
                    timeout=10
                )
                
                if response.status_code != 200:
                    print(f"❌ Poll failed with status {response.status_code}: {response.text}")
                    return None
                
                result = response.json()
                status = result.get('status')
                
                poll_count += 1
                
                if status == 'finished':
                    print(f"\r✅ Analysis complete after {elapsed:.1f}s ({poll_count} polls)")
                    return result
                elif status == 'pending':
                    print(f"\r   ⏳ Status: pending ({elapsed:.0f}s elapsed)...", end="", flush=True)
                    time.sleep(self.poll_interval)
                elif status == 'error':
                    print(f"\r❌ Analysis failed: {result.get('message', 'Unknown error')}")
                    return None
                else:
                    print(f"\r⚠️  Unknown status: {status}")
                    time.sleep(self.poll_interval)
                    
            except requests.exceptions.RequestException as e:
                print(f"❌ Poll request failed: {e}")
                return None
            except json.JSONDecodeError as e:
                print(f"❌ Invalid JSON response: {e}")
                return None
    
    def _save_report(self, results: Dict[str, Any], commit_hash: str) -> str:
        """Save analysis results to JSON file"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"dynamic_report_{commit_hash[:8]}_{timestamp}.json"
        filepath = self.reports_dir / filename
        
        with open(filepath, 'w') as f:
            json.dump(results, f, indent=2)
        
        print(f"💾 Report saved: {filepath}")
        return str(filepath)
    
    def analyze(self, repo_path: str, commit_hash: str) -> Optional[str]:
        """
        Perform complete dynamic analysis workflow
        
        Args:
            repo_path: Path to git repository
            commit_hash: Git commit hash to analyze
        
        Returns:
            Path to report file or None on failure
        """
        print("\n" + "="*80)
        print("🔬 DYNAMIC ANALYSIS - Package Hunter Runtime Monitoring")
        print("="*80)
        print(f"📂 Repository: {repo_path}")
        print(f"📌 Commit: {commit_hash}")
        print()
        
        # 1. Check server availability
        if not self._check_server_availability():
            print("❌ Package Hunter server is not available at", self.package_hunter_url)
            print("   Please ensure the server is running with:")
            print("   NODE_ENV=development DEBUG=pkgs* node src/server.js")
            return None
        
        print("✅ Package Hunter server is available")
        
        # 2. Create package
        tgz_path = self._npm_pack(repo_path, commit_hash)
        if not tgz_path:
            return None
        
        # 3. Upload package
        analysis_id = self._upload_package(tgz_path)
        if not analysis_id:
            return None
        
        # 4. Poll for results
        results = self._poll_results(analysis_id)
        if not results:
            return None
        
        # 5. Save report
        report_path = self._save_report(results, commit_hash)
        
        # Cleanup package file
        try:
            Path(tgz_path).unlink()
            print(f"🗑️  Cleaned up: {tgz_path}")
        except Exception as e:
            print(f"⚠️  Could not clean up package file: {e}")
        
        print()
        print("="*80)
        print("✅ DYNAMIC ANALYSIS COMPLETE")
        print("="*80)
        
        return report_path


def main():
    """Command-line interface for dynamic analysis"""
    if len(sys.argv) < 3:
        print("Usage: python dynamic_analysis.py <repo_path> <commit_hash>")
        print()
        print("Environment variables:")
        print("  FALCO_TOKEN        - Authorization token for Package Hunter")
        print("  POLL_INTERVAL      - Seconds between status polls (default: 2)")
        print("  ANALYSIS_TIMEOUT   - Maximum analysis time in seconds (default: 300)")
        sys.exit(1)
    
    repo_path = sys.argv[1]
    commit_hash = sys.argv[2]

    # Load .env file
    load_dotenv()
    
    # Get optional parameters from environment
    poll_interval = int(os.getenv("POLL_INTERVAL", "15"))
    timeout = int(os.getenv("ANALYSIS_TIMEOUT", "300"))
    
    analyzer = DynamicAnalyzer(
        poll_interval=poll_interval,
        timeout=timeout
    )
    
    report_path = analyzer.analyze(repo_path, commit_hash)
    
    if report_path:
        sys.exit(0)
    else:
        sys.exit(1)


if __name__ == "__main__":
    main()
