#!/usr/bin/env python3
"""
Evasion Technique: Dead Code/Imports Insertion
Insert non-executed code, functions, and imports to dilute malicious features.
"""

import struct
import random
from pathlib import Path

# Common benign Windows API imports that can be added
BENIGN_IMPORTS = [
    b'kernel32.dll\x00CreateFileA\x00',
    b'kernel32.dll\x00ReadFile\x00',
    b'kernel32.dll\x00WriteFile\x00',
    b'kernel32.dll\x00CloseHandle\x00',
    b'user32.dll\x00MessageBoxA\x00',
    b'user32.dll\x00GetWindowTextA\x00',
    b'gdi32.dll\x00CreateFontA\x00',
    b'gdi32.dll\x00TextOutA\x00',
    b'advapi32.dll\x00RegOpenKeyA\x00',
    b'advapi32.dll\x00RegQueryValueA\x00',
    b'shell32.dll\x00ShellExecuteA\x00',
    b'ws2_32.dll\x00socket\x00',
    b'ws2_32.dll\x00connect\x00',
]

# x86 NOP instructions and benign code sequences
NOP_SEQUENCES = [
    b'\x90',  # NOP
    b'\x66\x90',  # 2-byte NOP
    b'\x0f\x1f\x00',  # 3-byte NOP
    b'\x0f\x1f\x40\x00',  # 4-byte NOP
]

# Benign x86 code sequences (that do nothing harmful)
BENIGN_CODE_SEQUENCES = [
    # Push and pop (no net effect)
    b'\x50\x58',  # push eax; pop eax
    b'\x51\x59',  # push ecx; pop ecx
    b'\x52\x5a',  # push edx; pop edx
    
    # Move register to itself
    b'\x89\xc0',  # mov eax, eax
    b'\x89\xc9',  # mov ecx, ecx
    b'\x89\xd2',  # mov edx, edx
    
    # XOR register with 0 (sets to 0)
    b'\x31\xc0',  # xor eax, eax
    b'\x31\xc9',  # xor ecx, ecx
    
    # Test register with itself
    b'\x85\xc0',  # test eax, eax
    b'\x85\xc9',  # test ecx, ecx
]

def insert_nop_sled(input_file, output_file, nop_count=100):
    """
    Insert NOP sled (no-operation instructions) into the file.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        nop_count: Number of NOP sequences to insert
    
    Returns:
        dict with modification info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    original_size = len(data)
    
    # Generate NOP sled
    nop_sled = bytearray()
    for _ in range(nop_count):
        nop_sled.extend(random.choice(NOP_SEQUENCES))
    
    # Insert at a random position (but not in header)
    if len(data) > 1024:
        insert_pos = random.randint(1024, len(data) - 100)
        data = data[:insert_pos] + nop_sled + data[insert_pos:]
    else:
        # Just append
        data.extend(nop_sled)
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return {
        'technique': 'nop_sled_insertion',
        'original_size': original_size,
        'nop_count': nop_count,
        'nop_bytes_added': len(nop_sled),
        'new_size': len(data)
    }

def insert_benign_code(input_file, output_file, code_count=50):
    """
    Insert benign code sequences that don't affect execution.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        code_count: Number of code sequences to insert
    
    Returns:
        dict with modification info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    original_size = len(data)
    
    # Generate benign code block
    benign_code = bytearray()
    for _ in range(code_count):
        benign_code.extend(random.choice(BENIGN_CODE_SEQUENCES))
    
    # Append to end
    data.extend(benign_code)
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return {
        'technique': 'benign_code_insertion',
        'original_size': original_size,
        'code_sequences_added': code_count,
        'code_bytes_added': len(benign_code),
        'new_size': len(data)
    }

def insert_fake_imports(input_file, output_file, import_count=10):
    """
    Insert fake import strings (not functional, but adds benign-looking data).
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        import_count: Number of fake imports to add
    
    Returns:
        dict with modification info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    original_size = len(data)
    
    # Select random imports
    fake_imports = bytearray()
    selected_imports = random.sample(BENIGN_IMPORTS, min(import_count, len(BENIGN_IMPORTS)))
    
    for imp in selected_imports:
        fake_imports.extend(imp)
    
    # Append to end
    data.extend(fake_imports)
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return {
        'technique': 'fake_imports_insertion',
        'original_size': original_size,
        'imports_added': len(selected_imports),
        'import_bytes_added': len(fake_imports),
        'new_size': len(data)
    }

def insert_fake_strings(input_file, output_file):
    """
    Insert benign-looking strings to dilute malicious string features.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
    
    Returns:
        dict with modification info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    original_size = len(data)
    
    # Benign strings commonly found in legitimate software
    benign_strings = [
        b"Copyright (C) Microsoft Corporation. All rights reserved.\x00",
        b"Windows is a registered trademark of Microsoft Corporation.\x00",
        b"Usage: program.exe [options] <input>\x00",
        b"Error: File not found\x00",
        b"Success: Operation completed\x00",
        b"Please enter your name: \x00",
        b"Processing... Please wait.\x00",
        b"Version 1.0.0\x00",
        b"Licensed under MIT License\x00",
        b"https://www.example.com\x00",
        b"config.ini\x00",
        b"settings.xml\x00",
        b"readme.txt\x00",
        b"help.chm\x00",
        b"C:\\Program Files\\\x00",
        b"HKEY_LOCAL_MACHINE\x00",
    ]
    
    # Add random selection of strings
    fake_strings = bytearray()
    for _ in range(20):
        fake_strings.extend(random.choice(benign_strings))
    
    # Append to end
    data.extend(fake_strings)
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return {
        'technique': 'fake_strings_insertion',
        'original_size': original_size,
        'string_bytes_added': len(fake_strings),
        'new_size': len(data)
    }

def insert_junk_data(input_file, output_file, junk_size_kb=10):
    """
    Insert mixed junk data (combination of code, strings, imports).
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        junk_size_kb: Approximate size of junk data in KB
    
    Returns:
        dict with modification info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    with open(input_path, 'rb') as f:
        data = bytearray(f.read())
    
    original_size = len(data)
    target_junk_size = junk_size_kb * 1024
    
    junk_data = bytearray()
    
    while len(junk_data) < target_junk_size:
        choice = random.randint(0, 3)
        
        if choice == 0:
            # Add NOP sequence
            junk_data.extend(random.choice(NOP_SEQUENCES))
        elif choice == 1:
            # Add benign code
            junk_data.extend(random.choice(BENIGN_CODE_SEQUENCES))
        elif choice == 2:
            # Add fake import
            junk_data.extend(random.choice(BENIGN_IMPORTS))
        else:
            # Add random padding
            junk_data.extend(bytes([random.randint(0, 255) for _ in range(16)]))
    
    # Append to end
    data.extend(junk_data[:target_junk_size])
    
    with open(output_path, 'wb') as f:
        f.write(data)
    
    return {
        'technique': 'junk_data_insertion',
        'original_size': original_size,
        'junk_bytes_added': len(junk_data[:target_junk_size]),
        'new_size': len(data)
    }

def apply_all_dead_code(input_file, output_file):
    """Apply all dead code insertion techniques."""
    # Chain multiple techniques
    temp_file = str(Path(output_file).with_suffix('.tmp'))
    
    # Start with NOP insertion
    result1 = insert_nop_sled(input_file, temp_file, nop_count=50)
    
    # Add benign code
    temp_file2 = temp_file + '2'
    result2 = insert_benign_code(temp_file, temp_file2, code_count=30)
    
    # Add fake strings
    temp_file3 = temp_file + '3'
    result3 = insert_fake_strings(temp_file2, temp_file3)
    
    # Add fake imports and save to final
    result4 = insert_fake_imports(temp_file3, output_file, import_count=10)
    
    # Cleanup temp files
    Path(temp_file).unlink(missing_ok=True)
    Path(temp_file2).unlink(missing_ok=True)
    Path(temp_file3).unlink(missing_ok=True)
    
    return {
        'technique': 'dead_code_combined',
        'original_size': result1['original_size'],
        'new_size': result4['new_size'],
        'total_added': result4['new_size'] - result1['original_size'],
        'techniques_applied': ['nop_sled', 'benign_code', 'fake_strings', 'fake_imports']
    }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python dead_code.py <input_file> <output_file> [technique]")
        print("Techniques: nop, code, imports, strings, junk, all")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    technique = sys.argv[3] if len(sys.argv) > 3 else "all"
    
    if technique == "nop":
        result = insert_nop_sled(input_file, output_file)
    elif technique == "code":
        result = insert_benign_code(input_file, output_file)
    elif technique == "imports":
        result = insert_fake_imports(input_file, output_file)
    elif technique == "strings":
        result = insert_fake_strings(input_file, output_file)
    elif technique == "junk":
        result = insert_junk_data(input_file, output_file)
    else:  # all
        result = apply_all_dead_code(input_file, output_file)
    
    print(f"Dead code inserted: {output_file}")
    print(f"Technique: {result['technique']}")
    print(f"Original size: {result['original_size']} bytes")
    print(f"New size: {result['new_size']} bytes")
    print(f"Added: {result['new_size'] - result['original_size']} bytes")

