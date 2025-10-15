#!/usr/bin/env python3
"""
Test ONLY the Advanced Hybrid samples against all team models.
Uses the SAME format and scoring as 2_batch_test_models.py:
- Score = evaded/total for each team
- Output format: technique, team_3, team_4, ..., avg_evaded_per_team, total_samples
"""

import requests
import subprocess
import time
import csv
from pathlib import Path
from datetime import datetime
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys

# Configuration
HYBRID_DIR = Path("/home/gamdhameet/Attack/modified_samples/hybrid_advanced")
RESULTS_DIR = Path("/home/gamdhameet/Attack/results")
BASE_PORT = 8080

# All team models (excluding team_15 as it's broken)
TEAM_MODELS = [f"team_{i}" for i in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17]]

# Assign each model to a different port
MODEL_PORTS = {model: BASE_PORT + idx for idx, model in enumerate(TEAM_MODELS)}

# Global dictionary to store container IDs
model_containers = {}
container_lock = threading.Lock()

def test_sample_against_model(sample_path, model_name, port, timeout=20):
    """Test a sample against a model on specific port."""
    try:
        with open(sample_path, 'rb') as f:
            data = f.read()
        
        api_url = f"http://localhost:{port}/"
        headers = {'Content-Type': 'application/octet-stream'}
        response = requests.post(api_url, data=data, headers=headers, timeout=timeout)
        
        if response.status_code == 200:
            return response.json().get('result')
        else:
            return None
    except Exception as e:
        return None

def test_technique_against_team(samples, model_name, port):
    """Test all samples of a technique against one team model."""
    evaded_count = 0
    total_count = 0
    
    for sample in samples:
        result = test_sample_against_model(sample, model_name, port)
        if result is not None:
            total_count += 1
            if result == 0:  # 0 = evaded (goodware), 1 = detected (malware)
                evaded_count += 1
    
    return {
        'evaded': evaded_count,
        'total': total_count,
        'rate': evaded_count / total_count if total_count > 0 else 0
    }

def start_docker_model(model_name, port, retries=2):
    """Start a Docker model container on specific port."""
    for attempt in range(retries):
        cmd = f"docker run --rm --memory=1g -d -p {port}:8080 {model_name}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            container_id = result.stdout.strip()
            with container_lock:
                model_containers[model_name] = container_id
            print(f"  ✓ {model_name} running on port {port}")
            return True
        else:
            if "port is already allocated" in result.stderr:
                # Try to kill existing container on this port
                find_cmd = f"docker ps -q --filter publish={port}"
                existing = subprocess.run(find_cmd, shell=True, capture_output=True, text=True).stdout.strip()
                if existing:
                    subprocess.run(f"docker stop {existing}", shell=True, capture_output=True, text=True)
                    subprocess.run(f"docker rm {existing}", shell=True, capture_output=True, text=True)
            time.sleep(2)
    
    print(f"  ✗ {model_name} failed to start")
    return False

def stop_all_models():
    """Stop all tracked Docker containers."""
    print("\nStopping all models...")
    with container_lock:
        containers_to_stop = list(model_containers.values())
        model_containers.clear()
    
    for cid in containers_to_stop:
        try:
            subprocess.run(f"docker stop {cid}", shell=True, capture_output=True, text=True, timeout=10)
            subprocess.run(f"docker rm {cid}", shell=True, capture_output=True, text=True, timeout=5)
        except:
            pass
    
    # Cleanup any remaining
    subprocess.run("docker stop $(docker ps -aq) 2>/dev/null", shell=True, capture_output=True, text=True)
    subprocess.run("docker rm $(docker ps -aq) 2>/dev/null", shell=True, capture_output=True, text=True)
    print("All models stopped")

def start_all_models():
    """Start all models in parallel."""
    print("Starting all models in parallel...")
    started_models = []
    
    with ThreadPoolExecutor(max_workers=len(TEAM_MODELS)) as executor:
        futures = {executor.submit(start_docker_model, model, MODEL_PORTS[model]): model for model in TEAM_MODELS}
        for future in as_completed(futures):
            if future.result():
                started_models.append(futures[future])
    
    print(f"\n{len(started_models)}/{len(TEAM_MODELS)} models started successfully")
    print("Waiting 5 seconds for full initialization...")
    time.sleep(5)
    return started_models

def main():
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    csv_file = RESULTS_DIR / f"hybrid_advanced_{timestamp}.csv"
    
    print("=" * 80)
    print(" ADVANCED HYBRID EVASION - BATCH TESTING")
    print("=" * 80)
    
    # Stop any lingering containers
    subprocess.run("docker stop $(docker ps -aq) 2>/dev/null", shell=True, capture_output=True, text=True)
    subprocess.run("docker rm $(docker ps -aq) 2>/dev/null", shell=True, capture_output=True, text=True)
    
    # Get all hybrid samples
    hybrid_samples = sorted(list(HYBRID_DIR.glob("*.exe")), key=lambda x: int(x.stem))
    
    if not hybrid_samples:
        print(f"\nNo hybrid samples found in {HYBRID_DIR}")
        print("Please run 3_create_hybrid_samples.py first!")
        return
    
    print(f"\nFound {len(hybrid_samples)} hybrid samples to test")
    print(f"Testing against {len(TEAM_MODELS)} models")
    print(f"Output: {csv_file}")
    
    # Start all models
    active_models = start_all_models()
    if not active_models:
        print("No models started successfully. Exiting.")
        return
    
    print("\n" + "=" * 80)
    print(" TESTING IN PROGRESS")
    print("=" * 80)
    
    try:
        # Open CSV for writing
        with open(csv_file, 'w', newline='') as f:
            # CSV headers: technique, team_3, team_4, ..., team_17, avg_evaded_per_team, total_samples
            fieldnames = ['technique'] + sorted(active_models) + ['avg_evaded_per_team', 'total_samples']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # Test hybrid_advanced technique
            technique_name = "hybrid_advanced"
            print(f"\nTesting technique: {technique_name} ({len(hybrid_samples)} samples)")
            
            row = {'technique': technique_name, 'total_samples': len(hybrid_samples)}
            
            # Test against all models in parallel
            with ThreadPoolExecutor(max_workers=len(active_models)) as executor:
                futures = {}
                for model in active_models:
                    port = MODEL_PORTS[model]
                    future = executor.submit(test_technique_against_team, hybrid_samples, model, port)
                    futures[future] = model
                
                results = {}
                for future in as_completed(futures):
                    model = futures[future]
                    try:
                        result = future.result(timeout=300)  # 5 min timeout per model
                        results[model] = result
                        evaded = result['evaded']
                        total = result['total']
                        rate = result['rate']
                        print(f"  {model}: {evaded}/{total} evaded ({rate:.1%})")
                    except Exception as e:
                        results[model] = {'evaded': 0, 'total': 0, 'rate': 0}
                        print(f"  {model}: ERROR - {e}")
            
            # Calculate results for this technique
            total_evaded = 0
            total_tested = 0
            
            for model in sorted(active_models):
                if model in results:
                    evaded = results[model]['evaded']
                    total = results[model]['total']
                    row[model] = f"{evaded}/{total}"
                    total_evaded += evaded
                    total_tested += total
                else:
                    row[model] = "ERROR"
            
            # Average evasion per team
            avg_evaded = total_evaded / len(active_models) if active_models else 0
            row['avg_evaded_per_team'] = f"{avg_evaded:.1f}/{len(hybrid_samples)}"
            
            # Write row
            writer.writerow(row)
            f.flush()
            
            print(f"\n  → Average: {avg_evaded:.1f}/{len(hybrid_samples)} evaded per team ({avg_evaded/len(hybrid_samples)*100:.1f}%)")
        
        print("\n" + "=" * 80)
        print(" TESTING COMPLETE")
        print("=" * 80)
        print(f"\nResults saved to: {csv_file}")
        
        # Print summary
        print(f"\n📊 HYBRID ADVANCED RESULTS:")
        print("-" * 80)
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                avg = row['avg_evaded_per_team']
                total = row['total_samples']
                avg_num = float(avg.split('/')[0])
                evasion_rate = (avg_num / int(total) * 100) if int(total) > 0 else 0
                print(f"  Technique: {row['technique']}")
                print(f"  Average evaded per team: {avg}")
                print(f"  Overall evasion rate: {evasion_rate:.1f}%")
                print()
                print(f"  Per-team breakdown:")
                for model in sorted(active_models):
                    if model in row and row[model] != 'ERROR':
                        print(f"    {model}: {row[model]}")
        
        # Compare with previous techniques
        print(f"\n📈 COMPARISON WITH PREVIOUS TECHNIQUES:")
        print(f"  Previous best (dropper): 28.2% evasion")
        if avg_num > 0:
            hybrid_evasion = avg_num / int(total) * 100
            print(f"  Advanced hybrid: {hybrid_evasion:.1f}% evasion")
            
            if hybrid_evasion > 28.2:
                improvement = hybrid_evasion - 28.2
                print(f"  🎉 IMPROVEMENT: +{improvement:.1f}% better evasion!")
            else:
                print(f"  ⚠️  Performance below dropper technique")
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Cleaning up...")
    except Exception as e:
        print(f"\n\nError occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        stop_all_models()
    
    print(f"\n{'='*80}")
    print(f"Full results: {csv_file}")
    print(f"{'='*80}\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Cleaning up...")
        stop_all_models()
    except Exception as e:
        print(f"\n\nError: {e}")
        import traceback
        traceback.print_exc()
        stop_all_models()
