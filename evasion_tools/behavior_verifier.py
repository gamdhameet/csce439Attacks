"""
Behavior Verifier: Use VirusTotal API to verify behavior of malware samples.

This module compares original and modified samples using the VirusTotal API
to demonstrate behavioral consistency and evasion effectiveness.
"""

import os
import time
import json
import hashlib
import requests
from pathlib import Path
from typing import Dict, Any, Tuple
from collections import defaultdict


class BehaviorVerifier:
    """Verify behavior of malware samples using VirusTotal API."""
    
    def __init__(self, api_key: str, output_dir: str = "reports"):
        """
        Initialize behavior verifier.
        
        Args:
            api_key: VirusTotal API key
            output_dir: Directory to save verification reports
        """
        self.api_key = api_key
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        self.vt_url = "https://www.virustotal.com/api/v3"
        self.rate_limit_delay = 15  # 15 seconds between requests (4 per minute)
        self.last_request_time = 0
        self.requests_today = 0
        self.daily_limit = 500
    
    def _enforce_rate_limit(self):
        """Enforce rate limiting (4 requests per minute)."""
        elapsed = time.time() - self.last_request_time
        if elapsed < self.rate_limit_delay:
            time.sleep(self.rate_limit_delay - elapsed)
        self.last_request_time = time.time()
    
    def get_file_hash(self, file_path: str) -> str:
        """Calculate SHA256 hash of a file."""
        sha256 = hashlib.sha256()
        with open(file_path, 'rb') as f:
            for chunk in iter(lambda: f.read(4096), b''):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def get_file_report(self, file_hash: str) -> Dict[str, Any]:
        """
        Get VirusTotal report for a file hash.
        
        Args:
            file_hash: SHA256 hash of file
        
        Returns:
            Dictionary containing report data or empty dict if not found
        """
        if self.requests_today >= self.daily_limit:
            print(f"[!] Daily VirusTotal limit ({self.daily_limit}) reached. Skipping.")
            return {}
        
        self._enforce_rate_limit()
        
        headers = {
            "x-apikey": self.api_key
        }
        
        try:
            response = requests.get(
                f"{self.vt_url}/files/{file_hash}",
                headers=headers,
                timeout=10
            )
            self.requests_today += 1
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 404:
                return {}  # File not found in VirusTotal
            else:
                print(f"[-] VirusTotal API error: {response.status_code}")
                return {}
        
        except requests.exceptions.RequestException as e:
            print(f"[-] Error querying VirusTotal: {e}")
            return {}
    
    def extract_behavioral_indicators(self, vt_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Extract behavioral indicators from VirusTotal report.
        
        Args:
            vt_report: VirusTotal API response
        
        Returns:
            Dictionary with extracted indicators
        """
        if not vt_report or 'data' not in vt_report:
            return {}
        
        data = vt_report.get('data', {})
        attributes = data.get('attributes', {})
        
        indicators = {
            'total_detections': len(attributes.get('last_analysis_results', {})),
            'malicious_detections': sum(1 for r in attributes.get('last_analysis_results', {}).values() 
                                        if r.get('category') == 'malicious'),
            'undetected_by': sum(1 for r in attributes.get('last_analysis_results', {}).values() 
                                if r.get('category') == 'undetected'),
            'type_description': attributes.get('type_description', 'Unknown'),
            'meaningful_name': attributes.get('meaningful_name', 'Unknown'),
            'pe_info': attributes.get('pe_info', {}),
            'magic': attributes.get('magic', 'Unknown'),
            'file_size': attributes.get('size', 0),
        }
        
        return indicators
    
    def compare_samples(self, original_file: str, modified_file: str) -> Dict[str, Any]:
        """
        Compare original and modified samples.
        
        Args:
            original_file: Path to original malware file
            modified_file: Path to modified malware file
        
        Returns:
            Dictionary with comparison results
        """
        original_hash = self.get_file_hash(original_file)
        modified_hash = self.get_file_hash(modified_file)
        
        print(f"[*] Comparing samples...")
        print(f"    Original: {original_hash}")
        print(f"    Modified: {modified_hash}")
        
        # Get reports for both files
        print(f"[*] Querying VirusTotal for original sample...")
        original_report = self.get_file_report(original_hash)
        
        print(f"[*] Querying VirusTotal for modified sample...")
        modified_report = self.get_file_report(modified_hash)
        
        # Extract indicators
        original_indicators = self.extract_behavioral_indicators(original_report)
        modified_indicators = self.extract_behavioral_indicators(modified_report)
        
        return {
            'original_hash': original_hash,
            'modified_hash': modified_hash,
            'original_indicators': original_indicators,
            'modified_indicators': modified_indicators,
            'original_found': bool(original_report),
            'modified_found': bool(modified_report),
            'comparison': self._compare_indicators(original_indicators, modified_indicators)
        }
    
    def _compare_indicators(self, original: Dict[str, Any], modified: Dict[str, Any]) -> Dict[str, Any]:
        """Compare behavioral indicators."""
        return {
            'detection_delta': modified.get('malicious_detections', 0) - original.get('malicious_detections', 0),
            'type_changed': original.get('type_description') != modified.get('type_description'),
            'size_changed': original.get('file_size') != modified.get('file_size'),
        }
    
    def verify_all_techniques(self, techniques_dir: str, original_dir: str, 
                            sample_count: int = 3) -> Dict[str, Any]:
        """
        Verify all evasion techniques using representative samples.
        
        Args:
            techniques_dir: Directory containing subdirectories for each technique
            original_dir: Directory containing original malware samples
            sample_count: Number of samples to verify per technique
        
        Returns:
            Dictionary with verification results
        """
        techniques_path = Path(techniques_dir)
        original_path = Path(original_dir)
        
        results = {}
        technique_dirs = sorted([d for d in techniques_path.iterdir() if d.is_dir()])
        
        for technique_dir in technique_dirs:
            technique_name = technique_dir.name
            print(f"\n[*] Verifying technique: {technique_name}")
            
            # Get sample files for this technique
            modified_files = sorted([f for f in technique_dir.iterdir() if f.is_file()],
                                   key=lambda x: (x.name.isdigit() and int(x.name), x.name))
            
            technique_results = {}
            for i, modified_file in enumerate(modified_files[:sample_count]):
                original_file = original_path / modified_file.name
                
                if not original_file.exists():
                    print(f"[-] Original file not found: {original_file}")
                    continue
                
                print(f"\n[*] Sample {i+1}/{min(sample_count, len(modified_files))}: {modified_file.name}")
                
                comparison = self.compare_samples(str(original_file), str(modified_file))
                technique_results[modified_file.name] = comparison
                
                # Print summary
                if comparison['original_found']:
                    print(f"    Original detections: {comparison['original_indicators'].get('malicious_detections', 'N/A')}")
                else:
                    print(f"    Original: Not found in VirusTotal")
                
                if comparison['modified_found']:
                    print(f"    Modified detections: {comparison['modified_indicators'].get('malicious_detections', 'N/A')}")
                else:
                    print(f"    Modified: Not found in VirusTotal")
                
                print(f"    Detection delta: {comparison['comparison'].get('detection_delta', 'N/A')}")
            
            results[technique_name] = technique_results
        
        return results
    
    def generate_verification_report(self, verification_results: Dict[str, Any], 
                                    output_file: str = None) -> str:
        """
        Generate verification report from results.
        
        Args:
            verification_results: Results from verify_all_techniques
            output_file: Path to output JSON report
        
        Returns:
            Path to report file
        """
        if output_file is None:
            output_file = self.output_dir / "vt_verification_report.json"
        
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        # Add metadata
        report = {
            'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
            'requests_used': self.requests_today,
            'daily_limit': self.daily_limit,
            'results': verification_results
        }
        
        with open(output_file, 'w') as f:
            json.dump(report, f, indent=2)
        
        print(f"\n[+] Verification report saved: {output_file}")
        return str(output_file)


def main():
    """Test behavior verifier."""
    api_key = os.environ.get('VIRUSTOTAL_API_KEY', '')
    if not api_key:
        print("[-] VIRUSTOTAL_API_KEY environment variable not set")
        return
    
    verifier = BehaviorVerifier(api_key)
    results = verifier.verify_all_techniques("modified_samples", "to_be_evaded_ds", sample_count=2)
    verifier.generate_verification_report(results)


if __name__ == "__main__":
    main()

