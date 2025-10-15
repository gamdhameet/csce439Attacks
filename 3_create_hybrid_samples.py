#!/usr/bin/env python3
"""
Create 50 modified samples using ONLY the Advanced Hybrid technique.
This combines ALL evasion methods in strategic layers.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from evasion_tools.hybrid_advanced import apply_advanced_hybrid_evasion

MALWARE_DIR = Path("/home/gamdhameet/Attack/to_be_evaded_ds")
OUTPUT_DIR = Path("/home/gamdhameet/Attack/modified_samples/hybrid_advanced")
BENIGN_DIR = Path("/usr/bin")

def create_hybrid_samples():
    """Create 50 advanced hybrid modified samples."""
    
    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    print("=" * 80)
    print(" ADVANCED HYBRID EVASION - SAMPLE GENERATION")
    print("=" * 80)
    print(f"\nThis technique combines ALL 8+ evasion methods in strategic layers:")
    print("  1. Multi-stage XOR encoding (3 rounds)")
    print("  2. Realistic benign code/import injection")
    print("  3. PE header mimicry from real benign executables")
    print("  4. Advanced dropper with chunk interleaving")
    print("  5. Cryptographic random padding")
    print("  6. Final multi-round XOR obfuscation")
    print("  7. PE header timestamp/checksum modifications")
    print("  8. Structural evasion via benign wrapper")
    print("\n" + "=" * 80)
    
    success_count = 0
    fail_count = 0
    
    for sample_id in range(1, 51):
        sample_path = MALWARE_DIR / str(sample_id)
        
        if not sample_path.exists():
            print(f"\n[{sample_id}/50] Sample {sample_id} not found, skipping...")
            fail_count += 1
            continue
        
        output_path = OUTPUT_DIR / f"{sample_id}.exe"
        
        print(f"\n{'='*80}")
        print(f"[{sample_id}/50] Processing sample {sample_id} with Advanced Hybrid technique")
        print(f"{'='*80}")
        
        try:
            result = apply_advanced_hybrid_evasion(
                str(sample_path),
                str(output_path),
                benign_dir=str(BENIGN_DIR)
            )
            
            if 'error' not in result:
                success_count += 1
                print(f"\n✓ SUCCESS: hybrid_advanced/{sample_id}.exe created")
            else:
                fail_count += 1
                print(f"\n✗ FAILED: {result.get('error', 'Unknown error')}")
        
        except Exception as e:
            fail_count += 1
            print(f"\n✗ FAILED with exception: {e}")
            import traceback
            traceback.print_exc()
    
    print("\n" + "=" * 80)
    print(" GENERATION COMPLETE")
    print("=" * 80)
    print(f"\nResults:")
    print(f"  ✓ Successful: {success_count}/50 samples")
    print(f"  ✗ Failed: {fail_count}/50 samples")
    print(f"\nOutput directory: {OUTPUT_DIR}")
    print(f"Total files created: {len(list(OUTPUT_DIR.glob('*.exe')))}")
    print("\nNext step: Run 4_test_hybrid.py to test against all models")

if __name__ == "__main__":
    create_hybrid_samples()

