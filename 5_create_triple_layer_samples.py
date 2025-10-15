#!/usr/bin/env python3
"""
Create 50 modified samples using the Triple-Layer technique.
This strategically combines XOR encoding, dead code, and dropper.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
from evasion_tools.triple_layer import apply_triple_layer_evasion

MALWARE_DIR = Path("/home/gamdhameet/Attack/to_be_evaded_ds")
OUTPUT_DIR = Path("/home/gamdhameet/Attack/modified_samples/triple_layer")
BENIGN_DIR = Path("/usr/bin")

def create_triple_layer_samples():
    """Create 50 triple-layer modified samples."""
    
    # Create output directory
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    
    print("=" * 80)
    print(" TRIPLE-LAYER EVASION - SAMPLE GENERATION")
    print("=" * 80)
    print(f"\nThis technique applies 3 layers in strategic order:")
    print("  Layer 1: XOR Encoding - Obfuscate the payload (targets team_12)")
    print("  Layer 2: Dead Code - Confuse the structure (targets team_4)")
    print("  Layer 3: Dropper - Wrap in benign executable (targets team_5, 6, 11)")
    print("\nThis layered approach ensures:")
    print("  • Even if outer layers are unpacked, payload is still obfuscated")
    print("  • Signature-based detection is thwarted by dead code")
    print("  • Structural analysis is confused by benign wrapper")
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
        print(f"[{sample_id}/50] Processing sample {sample_id}")
        print(f"{'='*80}")
        
        try:
            result = apply_triple_layer_evasion(
                str(sample_path),
                str(output_path),
                benign_dir=str(BENIGN_DIR)
            )
            
            if 'error' not in result:
                success_count += 1
                print(f"\n✓ SUCCESS: triple_layer/{sample_id}.exe created")
                print(f"  Layers: {result['layers_applied']}")
                print(f"  Size increase: {result['size_increase_percent']:.1f}%")
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
    print("\nNext steps:")
    print("  1. Run 2_batch_test_models.py to test against all models")
    print("  2. Compare results with other techniques")
    print("\nExpected targets:")
    print("  • team_12 (XOR specialist) - Layer 1 obfuscation")
    print("  • team_4 (dead code detection) - Layer 2 confusion")
    print("  • team_5, team_6, team_11 (dropper vulnerable) - Layer 3 wrapper")

if __name__ == "__main__":
    create_triple_layer_samples()

