#!/usr/bin/env python3
"""
Evasion Technique: Using Packers
Apply executable packers like UPX to compress and obfuscate the binary.
"""

import subprocess
import shutil
from pathlib import Path

def check_upx_installed():
    """Check if UPX is installed on the system."""
    return shutil.which('upx') is not None

def install_upx_hint():
    """Provide installation hint for UPX."""
    return """
UPX is not installed. To install:
  - Fedora/RHEL: sudo dnf install upx
  - Ubuntu/Debian: sudo apt install upx-ucl
  - Arch: sudo pacman -S upx
  - Or download from: https://upx.github.io/
"""

def apply_upx_packer(input_file, output_file, compression_level=9, options=None):
    """
    Apply UPX packer to executable.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        compression_level: Compression level (1-9, where 9 is best)
        options: Additional UPX options (list)
    
    Returns:
        dict with packing info
    """
    if not check_upx_installed():
        return {
            'technique': 'upx_packer',
            'error': 'UPX not installed',
            'hint': install_upx_hint()
        }
    
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    # Copy input to output first
    shutil.copy2(input_path, output_path)
    
    # Build UPX command
    cmd = ['upx', f'-{compression_level}']
    
    if options:
        cmd.extend(options)
    
    # Add --force-overwrite to avoid prompts
    cmd.extend(['--force-overwrite', str(output_path)])
    
    try:
        # Run UPX
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        
        original_size = input_path.stat().st_size
        new_size = output_path.stat().st_size
        
        return {
            'technique': 'upx_packer',
            'compression_level': compression_level,
            'original_size': original_size,
            'new_size': new_size,
            'compression_ratio': (original_size - new_size) / original_size if original_size > 0 else 0,
            'upx_output': result.stdout,
            'upx_errors': result.stderr if result.returncode != 0 else None,
            'success': result.returncode == 0
        }
    
    except subprocess.TimeoutExpired:
        return {
            'technique': 'upx_packer',
            'error': 'UPX timeout (file too large or complex)'
        }
    except Exception as e:
        return {
            'technique': 'upx_packer',
            'error': str(e)
        }

def apply_upx_with_overlay(input_file, output_file):
    """
    Apply UPX but preserve overlay data (--overlay=copy).
    Some malware has data appended that needs to be preserved.
    """
    return apply_upx_packer(input_file, output_file, compression_level=9, 
                           options=['--overlay=copy'])

def apply_upx_brute(input_file, output_file):
    """
    Apply UPX with brute force compression (slower but better compression).
    """
    return apply_upx_packer(input_file, output_file, compression_level=9,
                           options=['--brute', '--ultra-brute'])

def apply_custom_packer(input_file, output_file, packer_command):
    """
    Apply a custom packer using a shell command.
    
    Args:
        input_file: Path to input file
        output_file: Path to output file
        packer_command: Command template with {input} and {output} placeholders
    
    Returns:
        dict with packing info
    """
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    # Replace placeholders
    cmd = packer_command.format(input=str(input_path), output=str(output_path))
    
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=120)
        
        if output_path.exists():
            original_size = input_path.stat().st_size
            new_size = output_path.stat().st_size
            
            return {
                'technique': 'custom_packer',
                'command': cmd,
                'original_size': original_size,
                'new_size': new_size,
                'output': result.stdout,
                'errors': result.stderr if result.returncode != 0 else None,
                'success': result.returncode == 0
            }
        else:
            return {
                'technique': 'custom_packer',
                'error': 'Output file not created',
                'command': cmd,
                'output': result.stdout,
                'errors': result.stderr
            }
    
    except Exception as e:
        return {
            'technique': 'custom_packer',
            'error': str(e),
            'command': cmd
        }

def unpack_upx(input_file, output_file):
    """
    Unpack a UPX-packed file (for testing/verification).
    """
    if not check_upx_installed():
        return {
            'error': 'UPX not installed'
        }
    
    input_path = Path(input_file)
    output_path = Path(output_file)
    
    # Copy input to output first
    shutil.copy2(input_path, output_path)
    
    try:
        result = subprocess.run(['upx', '-d', str(output_path)], 
                              capture_output=True, text=True, timeout=60)
        
        return {
            'unpacked': result.returncode == 0,
            'output': result.stdout,
            'errors': result.stderr if result.returncode != 0 else None
        }
    
    except Exception as e:
        return {
            'error': str(e)
        }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python packer.py <input_file> <output_file> [mode]")
        print("Modes: normal, overlay, brute")
        print()
        
        if not check_upx_installed():
            print(install_upx_hint())
        
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) > 3 else "normal"
    
    if mode == "overlay":
        result = apply_upx_with_overlay(input_file, output_file)
    elif mode == "brute":
        result = apply_upx_brute(input_file, output_file)
    else:
        result = apply_upx_packer(input_file, output_file)
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        if 'hint' in result:
            print(result['hint'])
        sys.exit(1)
    
    if result.get('success'):
        print(f"Successfully packed: {output_file}")
        print(f"Original size: {result['original_size']} bytes")
        print(f"Packed size: {result['new_size']} bytes")
        print(f"Compression ratio: {result['compression_ratio']:.2%}")
    else:
        print(f"Packing failed")
        if result.get('upx_errors'):
            print(f"Errors: {result['upx_errors']}")

