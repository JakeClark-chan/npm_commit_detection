#!/usr/bin/env python3
"""
Dynamic Analysis Module for NPM Package Malware Detection
Performs runtime analysis using Package Hunter (Falco-based sandbox)
"""

import os
import sys
import json
import time
import logging
import subprocess
import requests
from pathlib import Path
from datetime import datetime
from typing import Optional, Dict, Any
from urllib.parse import urlparse

from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)


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
        except requests.exceptions.ConnectionError as e:
            logger.error(f"❌ Package Hunter server not available: {e}")
            return False
    
    def _npm_pack(self, repo_path: str, commit_hash: str) -> Optional[str]:
        """
        Checkout commit and create npm package tarball
        Returns the .tgz filename or None on failure
        """
        repo_path = Path(repo_path).resolve()
        
        if not repo_path.exists():
            logger.error(f"❌ Repository not found: {repo_path}")
            return None
        
        logger.info(f"📦 Preparing package at commit {commit_hash[:8]}...")
        
        try:
            # Checkout the specific commit
            subprocess.run(
                ["git", "checkout", commit_hash],
                cwd=repo_path,
                check=True,
                capture_output=True,
                text=True
            )
            # PROBLEM: Because package is broken, so we don't need to try very hard to fix it
            # # Fix peer dependency issues for Package Hunter
            # # 1. Create .npmrc with legacy-peer-deps=true
            # npmrc_path = repo_path / ".npmrc"
            # with open(npmrc_path, 'w') as f:
            #     f.write("legacy-peer-deps=true\n")
            
            # # 2. Ensure .npmrc is included in package.json 'files' whitelist
            # # And upgrade React to 18 to resolve peer dependency issues
            # pkg_json_path = repo_path / "package.json"
            # if pkg_json_path.exists():
            #     try:
            #         with open(pkg_json_path, 'r') as f:
            #             pkg_data = json.load(f)
                    
            #         changed = False
                    
            #         # Add .npmrc to files
            #         if 'files' in pkg_data and isinstance(pkg_data['files'], list):
            #             if '.npmrc' not in pkg_data['files']:
            #                 pkg_data['files'].append('.npmrc')
            #                 changed = True
            #                 logger.info("✅ Added .npmrc to package.json files list")

            #         # Upgrade React to 18
            #         for dep_type in ['dependencies', 'devDependencies']:
            #             if dep_type in pkg_data:
            #                 if 'react' in pkg_data[dep_type]:
            #                     pkg_data[dep_type]['react'] = '^18.2.0'
            #                     changed = True
            #                     logger.info(f"✅ Updated react in {dep_type} to ^18.2.0")
            #                 if 'react-dom' in pkg_data[dep_type]:
            #                     pkg_data[dep_type]['react-dom'] = '^18.2.0'
            #                     changed = True
            #                     logger.info(f"✅ Updated react-dom in {dep_type} to ^18.2.0")

            #         if changed:
            #             with open(pkg_json_path, 'w') as f:
            #                 json.dump(pkg_data, f, indent=2)
                            
            #     except Exception as e:
            #         logger.warning(f"⚠️ Failed to update package.json: {e}")

            # # 3. Remove package-lock.json if it exists
            # # This avoids strict version locking conflicts
            # lock_file = repo_path / "package-lock.json"
            # if lock_file.exists():
            #     lock_file.unlink()
            
            # Run npm pack
            result = subprocess.run(
                ["npm", "pack", "--ignore-scripts"],
                cwd=repo_path,
                capture_output=True,
                text=True,
                check=True
            )
            
            # Find the .tgz file
            tgz_files = list(repo_path.glob("*.tgz"))
            if not tgz_files:
                logger.error("❌ Could not find .tgz file in npm pack output")
                return None
                
            tgz_path = tgz_files[0]
            if not tgz_path.exists():
                logger.error(f"❌ Package file not found: {tgz_path}")
                return None
                
            logger.info(f"✅ Package created: {tgz_path.name}")
            return tgz_path
            
        except subprocess.CalledProcessError as e:
            logger.error(f"❌ Failed to create package: {e.stderr}")
            return None
        except Exception as e:
            logger.error(f"❌ Error during npm pack: {e}")
            return None
    
    def _upload_package(self, tgz_path: str) -> Optional[str]:
        """
        Upload package to Package Hunter for analysis
        Returns analysis ID or None on failure
        """
        logger.info(f"📤 Uploading package to {self.package_hunter_url}...")
        
        try:
            with open(tgz_path, 'rb') as f:
                files = {'file': (Path(tgz_path).name, f, 'application/gzip')}
                response = requests.post(f"{self.package_hunter_url}/analyze", files=files)
                
            if response.status_code == 200:
                result = response.json()
                analysis_id = result.get('id')
                if not analysis_id:
                    logger.error(f"❌ No analysis ID in response: {result}")
                    return None
                    
                logger.info(f"✅ Package uploaded, analysis ID: {analysis_id}")
                return analysis_id
            else:
                logger.error(f"❌ Upload failed with status {response.status_code}: {response.text}")
                return None
                
        except requests.exceptions.RequestException as e:
            logger.error(f"❌ Upload request failed: {e}")
            return None
        except ValueError as e:
            logger.error(f"❌ Invalid JSON response: {e}")
            return None
    
    def _poll_results(self, analysis_id: str) -> Optional[Dict[str, Any]]:
        """
        Poll Package Hunter for analysis results
        Returns analysis results or None on failure/timeout
        """
        logger.info(f"⏳ Polling for results (ID: {analysis_id})...")
        start_time = time.time()
        poll_count = 0
        
        while time.time() - start_time < self.timeout:
            try:
                response = requests.get(
                    f"{self.package_hunter_url}/result/{analysis_id}",
                    headers=self._get_headers(),
                    timeout=10
                )
                poll_count += 1
                
                if response.status_code == 200:
                    result = response.json()
                    status = result.get('status')
                    
                    if status == 'finished':
                        elapsed = time.time() - start_time
                        logger.info(f"✅ Analysis complete after {elapsed:.1f}s ({poll_count} polls)")
                        return result
                    elif status == 'pending' or status == 'running':
                        elapsed = time.time() - start_time
                        if poll_count % 2 == 0: # Reduce log spam
                            logger.info(f"   ⏳ Status: {status} ({elapsed:.0f}s elapsed)...")
                        time.sleep(self.poll_interval)
                    elif status == 'failed':
                        logger.error(f"❌ Analysis failed: {result.get('message', 'Unknown error')}")
                        return None
                    else:
                        logger.warning(f"⚠️  Unknown status: {status}")
                        time.sleep(self.poll_interval)
                else:
                    logger.error(f"❌ Poll failed with status {response.status_code}: {response.text}")
                    return None
                    
            except requests.exceptions.RequestException as e:
                logger.error(f"❌ Poll request failed: {e}")
                time.sleep(self.poll_interval)
            except json.JSONDecodeError as e:
                logger.error(f"❌ Invalid JSON response: {e}")
                time.sleep(self.poll_interval)
                
        logger.error(f"❌ Timeout after {self.timeout}s waiting for analysis")
        return None
    
    def _save_report(self, results: Dict[str, Any], commit_hash: str) -> str:
        """Save analysis results to JSON file"""
        try:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"dynamic_report_{commit_hash[:8]}_{timestamp}.json"
            filepath = self.reports_dir / filename
            
            with open(filepath, 'w') as f:
                json.dump(results, f, indent=2)
            
            logger.info(f"💾 Report saved: {filepath}")
            return str(filepath)
        except Exception as e:
            logger.error(f"❌ Failed to save report: {e}")
            return None
    
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
            print("   FALCO_TOKEN=<token> NODE_ENV=development DEBUG=pkgs* node src/server.js")
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
