import requests
import os
import sys
import docker
import time
import json
from tqdm import tqdm
import argparse

MODELS_DIR = "models_v2/models"
HOST = "http://localhost:8080"

def get_model_paths():
    return [os.path.join(MODELS_DIR, f) for f in os.listdir(MODELS_DIR) if f.endswith(".tar")]

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
    parser = argparse.ArgumentParser(description="Test a modified sample against all models.")
    parser.add_argument("-s", "--sample", required=True, help="Path to the modified sample to test.")
    args = parser.parse_args()

    if not os.path.exists(args.sample):
        print(f"Error: Sample file '{args.sample}' not found.")
        return

    docker_client = docker.from_env()
    model_paths = get_model_paths()
    
    results = {}

    for model_path in tqdm(model_paths, desc="Testing against models"):
        model_name = os.path.basename(model_path).replace(".tar", "")
        
        container = None
        try:
            print(f"Loading and running {model_name}...")
            with open(model_path, 'rb') as model_file:
                docker_client.images.load(model_file.read())
            
            container = docker_client.containers.run(f"{model_name}:latest", detach=True, ports={'8080/tcp': 8080}, mem_limit="1g")
            
            time.sleep(10) # Wait for model to start
            
            result = test_sample(args.sample)
            if result:
                results[model_name] = result
                print(f"Result for {model_name}: {result}")
            else:
                results[model_name] = {"error": "Failed to get result"}
                print(f"Failed to get result for {model_name}")

        finally:
            if container:
                try:
                    container.stop()
                    container.remove()
                except docker.errors.NotFound:
                    pass
            time.sleep(2) # Release port

    results_file = "modified_sample_results.json"
    with open(results_file, "w") as f:
        json.dump(results, f, indent=4)

    print(f"\nTesting complete. Results saved to {results_file}")

if __name__ == "__main__":
    main()
