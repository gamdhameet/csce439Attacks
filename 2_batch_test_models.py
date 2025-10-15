#!/usr/bin/env python3
"""
Parallel batch testing with CORRECT scoring:
- Test each technique's 50 samples against each team
- Count how many samples EVADE each team
- Score = evaded_count/50 for each technique-team pair
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
MODIFIED_BASE = Path("/home/gamdhameet/Attack/modified_samples")
RESULTS_DIR = Path("/home/gamdhameet/Attack/results")
BASE_PORT = 8080

# All team models (excluding team_15 as it's broken)
TEAM_MODELS = [f"team_{i}" for i in [1, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 16, 17]]

# Assign each model to a different port
MODEL_PORTS = {model: BASE_PORT + idx for idx, model in enumerate(TEAM_MODELS)}

# Global containers tracking
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

def start_docker_model(model_name, port, retries=2):
    """Start a Docker model container on specific port with retries."""
    for attempt in range(retries):
        # Map external port to internal 8080 (models always use 8080 internally)
        cmd = f"docker run --rm --memory=1g -d -p {port}:8080 {model_name}"
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        
        if result.returncode == 0:
            container_id = result.stdout.strip()
            with container_lock:
                model_containers[model_name] = container_id
            
            # Wait and verify
            time.sleep(4)
            
            # Health check
            try:
                response = requests.get(f"http://localhost:{port}/", timeout=2)
                with container_lock:
                    model_containers[model_name] = container_id
                return container_id
            except:
                if attempt < retries - 1:
                    stop_docker_container(container_id)
                    time.sleep(2)
                    continue
                else:
                    with container_lock:
                        model_containers[model_name] = container_id
                    return container_id
        
        if attempt < retries - 1:
            time.sleep(2)
    
    return None

def stop_docker_container(container_id):
    """Stop a Docker container."""
    if container_id:
        subprocess.run(f"docker stop {container_id} 2>/dev/null", shell=True, capture_output=True)

def start_all_models():
    """Start all models in parallel on different ports."""
    print("Starting all models in parallel...")
    print("=" * 70)
    
    with ThreadPoolExecutor(max_workers=len(TEAM_MODELS)) as executor:
        futures = {}
        for model, port in MODEL_PORTS.items():
            future = executor.submit(start_docker_model, model, port)
            futures[future] = model
        
        started_models = []
        for future in as_completed(futures):
            model = futures[future]
            port = MODEL_PORTS[model]
            container_id = future.result()
            if container_id:
                print(f"  ✓ {model} running on port {port}")
                started_models.append(model)
            else:
                print(f"  ✗ {model} failed to start")
    
    print(f"\n{len(started_models)}/{len(TEAM_MODELS)} models started successfully")
    print("Waiting 5 seconds for full initialization...")
    time.sleep(5)
    print("=" * 70)
    return started_models

def stop_all_models():
    """Stop all running model containers."""
    print("\nStopping all models...")
    with container_lock:
        containers_to_stop = list(model_containers.values())
    
    with ThreadPoolExecutor(max_workers=len(containers_to_stop)) as executor:
        for container_id in containers_to_stop:
            executor.submit(stop_docker_container, container_id)
    
    print("All models stopped")

def test_technique_against_team(technique_samples, model_name, port):
    """Test all samples of a technique against one team model."""
    evaded_count = 0
    total_count = 0
    
    for sample_path in technique_samples:
        result = test_sample_against_model(sample_path, model_name, port)
        if result is not None:
            total_count += 1
            if result == 0:  # 0 means evaded/not detected
                evaded_count += 1
    
    return {
        'evaded': evaded_count,
        'total': total_count,
        'rate': evaded_count / total_count if total_count > 0 else 0
    }

def batch_test_all(active_models):
    """Batch test all techniques against all models - CORRECT SCORING."""
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    
    # Prepare CSV output
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    csv_file = RESULTS_DIR / f"technique_scores_{timestamp}.csv"
    
    # Collect samples by technique
    techniques = {}
    for technique_dir in sorted(MODIFIED_BASE.iterdir()):
        if technique_dir.is_dir():
            technique_name = technique_dir.name
            samples = sorted(technique_dir.glob("*.exe"))
            techniques[technique_name] = samples
            print(f"Technique '{technique_name}': {len(samples)} samples")
    
    print(f"\nTesting {len(techniques)} techniques against {len(active_models)} models")
    print(f"Output: {csv_file}\n")
    
    try:
        # Open CSV for writing
        with open(csv_file, 'w', newline='') as f:
            # CSV headers: technique, team_3, team_4, ..., team_17, avg_evasion
            fieldnames = ['technique'] + active_models + ['avg_evaded_per_team', 'total_samples']
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            
            # Test each technique
            for idx, (technique_name, samples) in enumerate(techniques.items(), 1):
                print(f"[{idx}/{len(techniques)}] Testing technique: {technique_name} ({len(samples)} samples)")
                
                row = {'technique': technique_name, 'total_samples': len(samples)}
                
                # Test against all models in parallel
                with ThreadPoolExecutor(max_workers=len(active_models)) as executor:
                    futures = {}
                    for model in active_models:
                        port = MODEL_PORTS[model]
                        future = executor.submit(test_technique_against_team, samples, model, port)
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
                
                for model in active_models:
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
                row['avg_evaded_per_team'] = f"{avg_evaded:.1f}/{len(samples)}"
                
                # Write row
                writer.writerow(row)
                f.flush()
                
                print(f"  → Average: {avg_evaded:.1f}/{len(samples)} evaded per team ({avg_evaded/len(samples)*100:.1f}%)\n")
        
        print("=" * 70)
        print(f"Testing complete!")
        print(f"Results saved to: {csv_file}")
        
        # Print summary
        print("\nSUMMARY BY TECHNIQUE:")
        print("-" * 70)
        with open(csv_file, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                technique = row['technique']
                avg = row['avg_evaded_per_team']
                print(f"  {technique:15} Avg evaded per team: {avg}")
    
    except KeyboardInterrupt:
        print("\n\nInterrupted by user. Cleaning up...")
    except Exception as e:
        print(f"\n\nError occurred: {e}")
        import traceback
        traceback.print_exc()
    finally:
        stop_all_models()

if __name__ == "__main__":
    # Stop any running containers first
    print("Stopping any existing Docker containers...")
    subprocess.run("docker stop $(docker ps -q) 2>/dev/null", shell=True)
    time.sleep(3)
    
    active_models = start_all_models()
    
    if not active_models:
        print("ERROR: No models started successfully!")
        sys.exit(1)
    
    batch_test_all(active_models)
