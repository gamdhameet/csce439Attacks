#!/usr/bin/env python3
"""
Evasion Technique: Append Goodware or Random Data
Appends benign data to the end of malware to change its statistical properties.
"""

import os
import random
import struct
from pathlib import Path

def append_random_bytes(input_file, output_file, size_kb=100):
    """
    Append random bytes to a file.
    
    Args:
        input_file: Path to input malware file
        output_file: Path to output modified file
        size_kb: Size of random data to append in KB
    
    Returns:
        dict with modification info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    # Read original file
    with open(input_path, 'rb') as f:
        original_data = f.read()
    
    original_size = len(original_data)
    
    # Generate random bytes
    random_data = bytes([random.randint(0, 255) for _ in range(size_kb * 1024)])
    
    # Write modified file
    with open(output_path, 'wb') as f:
        f.write(original_data)
        f.write(random_data)
    
    new_size = output_path.stat().st_size
    
    return {
        'technique': 'append_random_bytes',
        'original_size': original_size,
        'appended_size': len(random_data),
        'new_size': new_size,
        'size_increase_percent': ((new_size - original_size) / original_size) * 100
    }

def append_benign_file(input_file, output_file, benign_file):
    """
    Append content from a benign file to malware.
    
    Args:
        input_file: Path to input malware file
        output_file: Path to output modified file
        benign_file: Path to benign file to append
    
    Returns:
        dict with modification info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    benign_path = Path(benign_file)
    
    # Read files
    with open(input_path, 'rb') as f:
        original_data = f.read()
    
    with open(benign_path, 'rb') as f:
        benign_data = f.read()
    
    original_size = len(original_data)
    
    # Write modified file
    with open(output_path, 'wb') as f:
        f.write(original_data)
        f.write(benign_data)
    
    new_size = output_path.stat().st_size
    
    return {
        'technique': 'append_benign_file',
        'original_size': original_size,
        'appended_size': len(benign_data),
        'benign_source': str(benign_file),
        'new_size': new_size,
        'size_increase_percent': ((new_size - original_size) / original_size) * 100
    }

def append_zero_padding(input_file, output_file, size_kb=50):
    """
    Append zero bytes (null padding) to a file.
    
    Args:
        input_file: Path to input malware file
        output_file: Path to output modified file
        size_kb: Size of padding to append in KB
    
    Returns:
        dict with modification info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    # Read original file
    with open(input_path, 'rb') as f:
        original_data = f.read()
    
    original_size = len(original_data)
    
    # Generate zero padding
    padding = b'\x00' * (size_kb * 1024)
    
    # Write modified file
    with open(output_path, 'wb') as f:
        f.write(original_data)
        f.write(padding)
    
    new_size = output_path.stat().st_size
    
    return {
        'technique': 'append_zero_padding',
        'original_size': original_size,
        'appended_size': len(padding),
        'new_size': new_size,
        'size_increase_percent': ((new_size - original_size) / original_size) * 100
    }

def append_text_data(input_file, output_file, text_content=None, size_kb=50):
    """
    Append text data to a file (e.g., fake license, documentation).
    
    Args:
        input_file: Path to input malware file
        output_file: Path to output modified file
        text_content: Custom text to append (or None for default)
        size_kb: Approximate size in KB if using default text
    
    Returns:
        dict with modification info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    # Read original file
    with open(input_path, 'rb') as f:
        original_data = f.read()
    
    original_size = len(original_data)
    
    # Generate text content if not provided
    if text_content is None:
        # Create fake documentation/license text
        text_lines = [
            "MIT License",
            "",
            "Copyright (c) 2024",
            "",
            "Permission is hereby granted, free of charge, to any person obtaining a copy",
            "of this software and associated documentation files (the \"Software\"), to deal",
            "in the Software without restriction, including without limitation the rights",
            "to use, copy, modify, merge, publish, distribute, sublicense, and/or sell",
            "copies of the Software, and to permit persons to whom the Software is",
            "furnished to do so, subject to the following conditions:",
            "",
            "The above copyright notice and this permission notice shall be included in all",
            "copies or substantial portions of the Software.",
            "",
        ]
        
        # Repeat to reach desired size
        target_size = size_kb * 1024
        text_content = ""
        while len(text_content.encode()) < target_size:
            text_content += "\n".join(text_lines) + "\n\n"
        
        text_content = text_content[:target_size]
    
    text_data = text_content.encode('utf-8', errors='ignore')
    
    # Write modified file
    with open(output_path, 'wb') as f:
        f.write(original_data)
        f.write(text_data)
    
    new_size = output_path.stat().st_size
    
    return {
        'technique': 'append_text_data',
        'original_size': original_size,
        'appended_size': len(text_data),
        'new_size': new_size,
        'size_increase_percent': ((new_size - original_size) / original_size) * 100
    }

if __name__ == "__main__":
    # Example usage
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python append_data.py <input_file> <output_file> [technique] [size_kb]")
        print("Techniques: random, benign, zero, text")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    technique = sys.argv[3] if len(sys.argv) > 3 else "random"
    size_kb = int(sys.argv[4]) if len(sys.argv) > 4 else 100
    
    if technique == "random":
        result = append_random_bytes(input_file, output_file, size_kb)
    elif technique == "zero":
        result = append_zero_padding(input_file, output_file, size_kb)
    elif technique == "text":
        result = append_text_data(input_file, output_file, size_kb=size_kb)
    else:
        print(f"Unknown technique: {technique}")
        sys.exit(1)
    
    print(f"Modified file created: {output_file}")
    print(f"Original size: {result['original_size']} bytes")
    print(f"New size: {result['new_size']} bytes")
    print(f"Size increase: {result['size_increase_percent']:.2f}%")

