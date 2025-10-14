import requests
import os
import sys
import docker
import time
import json
from tqdm import tqdm

MODELS_DIR = "models_v2/models"
SAMPLES_DIR = "to_be_evaded_ds"
RESULTS_FILE = "baseline_results.json"
HOST = "http://localhost:8080"

def get_model_paths():
    return [os.path.join(MODELS_DIR, f) for f in os.listdir(MODELS_DIR) if f.endswith(".tar")]

def get_sample_paths():
    samples = [os.path.join(SAMPLES_DIR, f) for f in os.listdir(SAMPLES_DIR) if not f.endswith(".txt")]
    return sorted(samples, key=lambda x: int(os.path.basename(x)))

def test_sample(sample_path):
    with open(sample_path, "rb") as f:
        data = f.read()
    headers = {"Content-Type": "application/octet-stream"}
    try:
        response = requests.post(HOST, data=data, headers=headers)
        if response.status_code == 200:
            return response.json()
    except requests.exceptions.ConnectionError:
        return None
    return None

def main():
    docker_client = docker.from_env()
    model_paths = get_model_paths()
    sample_paths = get_sample_paths()
    
    all_results = {}

    for model_path in tqdm(model_paths, desc="Models"):
        model_name = os.path.basename(model_path).replace(".tar", "")
        all_results[model_name] = {}

        # Load and run model
        print(f"Loading {model_name}...")
        with open(model_path, 'rb') as model_file:
            docker_client.images.load(model_file.read())
        
        container = docker_client.containers.run(f"{model_name}:latest", detach=True, ports={'8080/tcp': 8080}, mem_limit="1g")
        
        # Wait for the model to be ready
        time.sleep(10) # Simple delay, a better implementation would check the endpoint

        for sample_path in tqdm(sample_paths, desc=f"Samples for {model_name}", leave=False):
            sample_id = os.path.basename(sample_path)
            result = test_sample(sample_path)
            if result:
                all_results[model_name][sample_id] = result
        
        try:
            container.stop()
        except docker.errors.NotFound:
            print(f"Container for {model_name} not found, it might have stopped already.")
        
        container.remove()

        # Give the system a moment to release the port
        time.sleep(2)

        with open(RESULTS_FILE, "w") as f:
            json.dump(all_results, f, indent=4)

    print(f"Baseline testing complete. Results saved to {RESULTS_FILE}")

if __name__ == "__main__":
    main()
