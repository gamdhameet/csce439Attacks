#!/usr/bin/env python3
"""
Evasion Technique: PE Header Manipulation
Modifies PE header fields that don't affect functionality but change the file signature.
"""

import struct
import random
import time
from pathlib import Path

class PEHeaderModifier:
    """Modify PE (Portable Executable) header fields for evasion."""
    
    def __init__(self, input_file):
        self.input_file = Path(input_file)
        with open(self.input_file, 'rb') as f:
            self.data = bytearray(f.read())
        
        self.modifications = []
        self._parse_pe_header()
    
    def _parse_pe_header(self):
        """Parse basic PE header structure."""
        # Check DOS header signature
        if len(self.data) < 64 or self.data[0:2] != b'MZ':
            raise ValueError("Not a valid PE file (missing MZ signature)")
        
        # Get PE header offset from DOS header
        pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
        
        if pe_offset + 24 > len(self.data):
            raise ValueError("Invalid PE header offset")
        
        # Check PE signature
        if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            raise ValueError("Not a valid PE file (missing PE signature)")
        
        self.pe_offset = pe_offset
        self.coff_header_offset = pe_offset + 4
        
    def modify_timestamp(self, new_timestamp=None):
        """
        Modify the TimeDateStamp in COFF header.
        This field is often ignored by loaders.
        """
        timestamp_offset = self.coff_header_offset + 4
        
        if new_timestamp is None:
            # Use random timestamp from last 10 years
            new_timestamp = int(time.time()) - random.randint(0, 10 * 365 * 24 * 60 * 60)
        
        struct.pack_into('<I', self.data, timestamp_offset, new_timestamp)
        self.modifications.append(f"Modified timestamp to {new_timestamp}")
        return self
    
    def modify_checksum(self):
        """
        Modify the checksum in optional header.
        Windows loader typically doesn't verify this for most executables.
        """
        # Optional header starts after COFF header (24 bytes after PE signature)
        optional_header_offset = self.coff_header_offset + 20
        
        # Checksum is at offset 64 in optional header
        checksum_offset = optional_header_offset + 64
        
        if checksum_offset + 4 <= len(self.data):
            # Set to zero or random value
            new_checksum = random.randint(0, 0xFFFFFFFF)
            struct.pack_into('<I', self.data, checksum_offset, new_checksum)
            self.modifications.append(f"Modified checksum to {new_checksum}")
        
        return self
    
    def add_dos_stub_padding(self, size=64):
        """
        Add padding bytes to DOS stub area.
        This area is between DOS header and PE header.
        """
        # DOS header is 64 bytes, PE header location is at offset 0x3C
        dos_stub_start = 64
        dos_stub_end = self.pe_offset
        
        if dos_stub_end - dos_stub_start < size:
            # Need to move PE header forward
            padding = bytes([random.randint(0, 255) for _ in range(size)])
            
            # Insert padding before PE header
            self.data = self.data[:dos_stub_end] + padding + self.data[dos_stub_end:]
            
            # Update PE header offset in DOS header
            new_pe_offset = dos_stub_end + size
            struct.pack_into('<I', self.data, 0x3C, new_pe_offset)
            self.pe_offset = new_pe_offset
            self.coff_header_offset = self.pe_offset + 4
            
            self.modifications.append(f"Added {size} bytes of DOS stub padding")
        
        return self
    
    def modify_characteristics(self):
        """
        Modify characteristics flags (carefully to not break execution).
        Some flags are cosmetic or rarely checked.
        """
        characteristics_offset = self.coff_header_offset + 18
        
        if characteristics_offset + 2 <= len(self.data):
            current_chars = struct.unpack('<H', self.data[characteristics_offset:characteristics_offset+2])[0]
            
            # Only modify non-critical flags
            # Bit 0 (RELOCS_STRIPPED) can sometimes be toggled
            # Bit 7 (BYTES_REVERSED_HI) is obsolete
            
            # Toggle bit 7 (obsolete flag, shouldn't affect execution)
            new_chars = current_chars ^ 0x0080
            
            struct.pack_into('<H', self.data, characteristics_offset, new_chars)
            self.modifications.append(f"Modified characteristics from {current_chars:#x} to {new_chars:#x}")
        
        return self
    
    def add_section_slack_space(self):
        """
        Add slack space (zeros) at the end of the last section.
        This is common in legitimate executables.
        """
        # This is a simplified version - full implementation would need to parse section headers
        # For now, just append to the end
        slack_size = random.randint(512, 2048)
        self.data.extend(b'\x00' * slack_size)
        self.modifications.append(f"Added {slack_size} bytes of section slack space")
        return self
    
    def modify_minor_version(self):
        """
        Modify minor linker version in optional header.
        Usually cosmetic and not checked.
        """
        optional_header_offset = self.coff_header_offset + 20
        minor_version_offset = optional_header_offset + 3
        
        if minor_version_offset < len(self.data):
            new_version = random.randint(0, 255)
            self.data[minor_version_offset] = new_version
            self.modifications.append(f"Modified minor linker version to {new_version}")
        
        return self
    
    def save(self, output_file):
        """Save modified PE file."""
        output_path = Path(output_file)
        
        with open(output_path, 'wb') as f:
            f.write(self.data)
        
        return {
            'technique': 'pe_header_modification',
            'modifications': self.modifications,
            'original_size': self.input_file.stat().st_size,
            'new_size': len(self.data),
            'output_file': str(output_path)
        }

def apply_all_modifications(input_file, output_file):
    """Apply all safe PE header modifications."""
    try:
        modifier = PEHeaderModifier(input_file)
        
        modifier.modify_timestamp() \
                .modify_checksum() \
                .modify_characteristics() \
                .modify_minor_version() \
                .add_section_slack_space()
        
        result = modifier.save(output_file)
        return result
    
    except Exception as e:
        return {
            'technique': 'pe_header_modification',
            'error': str(e),
            'modifications': []
        }

def apply_light_modifications(input_file, output_file):
    """Apply only timestamp and checksum modifications (safest)."""
    try:
        modifier = PEHeaderModifier(input_file)
        
        modifier.modify_timestamp() \
                .modify_checksum()
        
        result = modifier.save(output_file)
        return result
    
    except Exception as e:
        return {
            'technique': 'pe_header_modification',
            'error': str(e),
            'modifications': []
        }

if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 3:
        print("Usage: python pe_header_modify.py <input_file> <output_file> [light|all]")
        sys.exit(1)
    
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    mode = sys.argv[3] if len(sys.argv) > 3 else "all"
    
    if mode == "light":
        result = apply_light_modifications(input_file, output_file)
    else:
        result = apply_all_modifications(input_file, output_file)
    
    if 'error' in result:
        print(f"Error: {result['error']}")
        sys.exit(1)
    
    print(f"PE header modified successfully: {output_file}")
    print(f"Modifications applied:")
    for mod in result['modifications']:
        print(f"  - {mod}")
    print(f"Original size: {result['original_size']} bytes")
    print(f"New size: {result['new_size']} bytes")

