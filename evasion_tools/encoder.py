#!/usr/bin/env python3
"""
Evasion Technique: XOR and Base64 Encoding
Encode parts of the executable to evade signature-based detection.
"""

import base64
import random
from pathlib import Path

def xor_encode_file(input_file, output_file, key=None):
    """
    XOR encode entire file with a key.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        key: XOR key (single byte or bytes), or None for random
    
    Returns:
        dict with encoding info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Generate key if not provided
    if key is None:
        key = random.randint(1, 255)
    
    if isinstance(key, int):
        key = bytes([key])
    
    # XOR encode
    encoded_data = bytearray()
    for i, byte in enumerate(data):
        encoded_data.append(byte ^ key[i % len(key)])
    
    with open(output_path, 'wb') as f:
        f.write(encoded_data)
    
    return {
        'technique': 'xor_encoding',
        'key': key.hex() if isinstance(key, bytes) else hex(key),
        'original_size': len(data),
        'encoded_size': len(encoded_data)
    }

def xor_encode_partial(input_file, output_file, start_offset=512, end_offset=None, key=None):
    """
    XOR encode only a portion of the file (e.g., skip PE header).
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        start_offset: Offset to start encoding (skip header)
        end_offset: Offset to stop encoding (None = end of file)
        key: XOR key
    
    Returns:
        dict with encoding info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    if key is None:
        key = random.randint(1, 255)
    
    if isinstance(key, int):
        key = bytes([key])
    
    if end_offset is None:
        end_offset = len(data)
    
    # XOR encode only the specified portion
    for i in range(start_offset, min(end_offset, len(data))):
        data[i] = data[i] ^ key[i % len(key)]
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return {
        'technique': 'xor_partial_encoding',
        'key': key.hex() if isinstance(key, bytes) else hex(key),
        'start_offset': start_offset,
        'end_offset': end_offset,
        'encoded_bytes': min(end_offset, len(data)) - start_offset,
        'total_size': len(data)
    }

def base64_encode_section(input_file, output_file, section_size=1024):
    """
    Base64 encode a section of the file and append it.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        section_size: Size of section to encode
    
    Returns:
        dict with encoding info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Take a section from the middle
    if len(data) > section_size * 2:
        start = len(data) // 3
        section = data[start:start + section_size]
    else:
        section = data[:section_size]
    
    # Base64 encode the section
    encoded_section = base64.b64encode(section)
    
    # Create marker
    marker = b'BASE64_ENCODED_SECTION:'
    
    # Append encoded section to original file
    output_data = data + marker + encoded_section
    
    with open(output_path, 'wb') as f:
        f.write(output_data)
    
    return {
        'technique': 'base64_section_encoding',
        'section_size': len(section),
        'encoded_size': len(encoded_section),
        'original_total': len(data),
        'new_total': len(output_data)
    }

def multi_xor_encode(input_file, output_file, num_keys=3):
    """
    Apply multiple rounds of XOR with different keys.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        num_keys: Number of XOR rounds
    
    Returns:
        dict with encoding info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    keys = []
    
    # Apply multiple XOR rounds
    for _ in range(num_keys):
        key = random.randint(1, 255)
        keys.append(key)
        
        for i in range(len(data)):
            data[i] = data[i] ^ key
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return {
        'technique': 'multi_xor_encoding',
        'num_rounds': num_keys,
        'keys': [hex(k) for k in keys],
        'size': len(data)
    }

def rotating_xor_encode(input_file, output_file, key_sequence=None):
    """
    XOR encode with rotating key sequence.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        key_sequence: List of keys to rotate through, or None for random
    
    Returns:
        dict with encoding info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = f.read()
    
    # Generate key sequence if not provided
    if key_sequence is None:
        key_sequence = [random.randint(1, 255) for _ in range(16)]
    
    # XOR with rotating keys
    encoded_data = bytearray()
    for i, byte in enumerate(data):
        key = key_sequence[i % len(key_sequence)]
        encoded_data.append(byte ^ key)
    
    with open(output_path, 'wb') as f:
        f.write(encoded_data)
    
    return {
        'technique': 'rotating_xor_encoding',
        'key_sequence': [hex(k) for k in key_sequence],
        'key_length': len(key_sequence),
        'size': len(encoded_data)
    }

def obfuscate_strings(input_file, output_file):
    """
    Find and XOR-encode string-like sections.
    This is a simplified version that encodes any sequence of printable characters.
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    key = random.randint(1, 255)
    encoded_count = 0
    
    # Simple heuristic: encode sequences of printable ASCII
    i = 0
    while i < len(data):
        # Check if we have a printable string (4+ chars)
        if 32 <= data[i] <= 126:
            string_start = i
            while i < len(data) and 32 <= data[i] <= 126:
                i += 1
            
            string_length = i - string_start
            
            # If string is long enough, encode it
            if string_length >= 4:
                for j in range(string_start, i):
                    data[j] = data[j] ^ key
                encoded_count += 1
        else:
            i += 1
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return {
        'technique': 'string_obfuscation',
        'key': hex(key),
        'strings_encoded': encoded_count,
        'size': len(data)
    }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python encoder.py <input_file> <output_file> [technique] [key]")
        print("Techniques: xor, xor_partial, base64, multi_xor, rotating_xor, strings")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    technique = sys.argv[3] if len(sys.argv) > 3 else "xor"
    key = int(sys.argv[4], 16) if len(sys.argv) > 4 else None
    
    if technique == "xor":
        result = xor_encode_file(input_file, output_file, key)
    elif technique == "xor_partial":
        result = xor_encode_partial(input_file, output_file, key=key)
    elif technique == "base64":
        result = base64_encode_section(input_file, output_file)
    elif technique == "multi_xor":
        result = multi_xor_encode(input_file, output_file)
    elif technique == "rotating_xor":
        result = rotating_xor_encode(input_file, output_file)
    elif technique == "strings":
        result = obfuscate_strings(input_file, output_file)
    else:
        print(f"Unknown technique: {technique}")
        sys.exit(1)
    
    print(f"Encoding applied: {output_file}")
    print(f"Technique: {result['technique']}")
    
    if 'key' in result:
        print(f"Key: {result['key']}")
    
    if 'keys' in result:
        print(f"Keys: {', '.join(result['keys'])}")
    
    print(f"Size: {result.get('size', result.get('new_total', 'N/A'))} bytes")

