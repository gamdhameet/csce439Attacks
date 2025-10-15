#!/usr/bin/env python3
"""
Batch create modified samples using all techniques.
Organizes output by technique into separate folders.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from evasion_tools import append_data, pe_header_modify, dropper, mimicry, dead_code, encoder

MALWARE_DIR = Path("/home/gamdhameet/Attack/to_be_evaded_ds")
MODIFIED_BASE = Path("/home/gamdhameet/Attack/modified_samples")
BENIGN_DIR = Path("/usr/bin")

def get_benign_sample():
    """Get ls as benign sample."""
    return BENIGN_DIR / "ls"

def create_all_modified_samples():
    """Create modified versions of all 50 samples using each technique."""
    
    print("Creating modified samples for all 50 malware samples...")
    print("=" * 70)
    
    for sample_id in range(1, 51):
        sample_path = MALWARE_DIR / str(sample_id)
        
        if not sample_path.exists():
            print(f"Sample {sample_id} not found, skipping...")
            continue
        
        print(f"\nProcessing sample {sample_id}...")
        
        # Technique 1: Append Random
        try:
            output = MODIFIED_BASE / "append_random" / f"{sample_id}.exe"
            append_data.append_random_bytes(str(sample_path), str(output), size_kb=50)
            print(f"  ✓ append_random/{sample_id}.exe")
        except Exception as e:
            print(f"  ✗ append_random failed: {e}")
        
        # Technique 2: PE Header
        try:
            output = MODIFIED_BASE / "pe_header" / f"{sample_id}.exe"
            pe_header_modify.apply_light_modifications(str(sample_path), str(output))
            print(f"  ✓ pe_header/{sample_id}.exe")
        except Exception as e:
            print(f"  ✗ pe_header failed: {e}")
        

        
        # Technique 4: Dropper
        try:
            benign = get_benign_sample()
            output = MODIFIED_BASE / "dropper" / f"{sample_id}.exe"
            dropper.create_simple_dropper(str(sample_path), str(benign), str(output), method='append')
            print(f"  ✓ dropper/{sample_id}.exe")
        except Exception as e:
            print(f"  ✗ dropper failed: {e}")
        
        # Technique 5: Mimicry
        try:
            output = MODIFIED_BASE / "mimicry" / f"{sample_id}.exe"
            result = mimicry.apply_random_benign_mimicry(str(sample_path), str(output))
            if 'error' not in result:
                print(f"  ✓ mimicry/{sample_id}.exe")
            else:
                print(f"  ✗ mimicry failed: {result['error']}")
        except Exception as e:
            print(f"  ✗ mimicry failed: {e}")
        
        # Technique 6: Dead Code
        try:
            output = MODIFIED_BASE / "dead_code" / f"{sample_id}.exe"
            dead_code.insert_junk_data(str(sample_path), str(output), junk_size_kb=20)
            print(f"  ✓ dead_code/{sample_id}.exe")
        except Exception as e:
            print(f"  ✗ dead_code failed: {e}")
        
        # Technique 7: XOR Encoding
        try:
            output = MODIFIED_BASE / "xor_encoding" / f"{sample_id}.exe"
            encoder.xor_encode_partial(str(sample_path), str(output), start_offset=512)
            print(f"  ✓ xor_encoding/{sample_id}.exe")
        except Exception as e:
            print(f"  ✗ xor_encoding failed: {e}")
        

    
    print("\n" + "=" * 70)
    print("Modified sample creation complete!")
    print("\nSummary:")
    for technique_dir in MODIFIED_BASE.iterdir():
        if technique_dir.is_dir() and not technique_dir.name.startswith('temp'):
            count = len(list(technique_dir.glob("*.exe")))
            print(f"  {technique_dir.name}: {count} samples")

if __name__ == "__main__":
    create_all_modified_samples()

