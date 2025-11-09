"""
PE Header Manipulation Evasion Technique: Modify PE header fields.

This technique exploits the fact that the Windows PE loader does not
validate every section or field. By modifying checksums, timestamps, and
section names, we can evade feature-based detection models.
"""

import os
import time
import random
import struct
from pathlib import Path
from typing import Dict, Any

try:
    import pefile
except ImportError:
    pefile = None


class PEHeaderManipulation:
    """Manipulate PE header fields for evasion."""
    
    def __init__(self, output_dir: str):
        """
        Initialize PE header manipulation.
        
        Args:
            output_dir: Directory to save modified files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        
        if pefile is None:
            print("[-] Warning: pefile not installed. Using fallback binary manipulation.")
    
    def modify_pe_headers_binary(self, input_file: str, output_file: str = None) -> str:
        """
        Modify PE headers using binary manipulation (no pefile dependency).
        
        Modifies:
        - Timestamp (offset 0x3C + 4 bytes for PE offset, then 0x4 for timestamp)
        - Checksums
        - Section names
        
        Args:
            input_file: Path to input PE file
            output_file: Path to output modified file
        
        Returns:
            Path to output file
        """
        with open(input_file, 'rb') as f:
            data = bytearray(f.read())
        
        # Verify MZ header
        if data[:2] != b'MZ':
            print(f"[-] Not a valid PE file: {input_file}")
            return None
        
        # Get PE offset from DOS header (at offset 0x3C)
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        
        # Verify PE signature
        if pe_offset > len(data) - 4 or data[pe_offset:pe_offset+2] != b'PE':
            print(f"[-] Invalid PE signature at offset {pe_offset}")
            return None
        
        # Modify timestamp (at PE offset + 4)
        timestamp_offset = pe_offset + 4
        new_timestamp = struct.pack('<I', int(time.time()) - random.randint(86400, 86400*365))
        data[timestamp_offset:timestamp_offset+4] = new_timestamp
        
        # Modify checksum (at PE offset + 0x58 for 32-bit, 0x68 for 64-bit)
        # First, determine if 32-bit or 64-bit from magic number at PE offset + 0x18
        magic_offset = pe_offset + 0x18
        magic = struct.unpack('<H', data[magic_offset:magic_offset+2])[0]
        
        if magic == 0x10b:  # 32-bit
            checksum_offset = pe_offset + 0x58
        elif magic == 0x20b:  # 64-bit
            checksum_offset = pe_offset + 0x68
        else:
            checksum_offset = pe_offset + 0x58  # Default to 32-bit
        
        # Set random checksum
        new_checksum = struct.pack('<I', random.randint(0, 0xFFFFFFFF))
        data[checksum_offset:checksum_offset+4] = new_checksum
        
        # Modify section names (if accessible)
        # Sections start after PE header (typically at PE offset + 0xF8 for 32-bit)
        section_header_offset = pe_offset + 0xF8
        num_sections_offset = pe_offset + 0x06
        num_sections = struct.unpack('<H', data[num_sections_offset:num_sections_offset+2])[0]
        
        # Each section header is 40 bytes
        section_names = [b".text   ", b".data   ", b".rsrc   ", b".reloc  ", b".debug  "]
        
        for i in range(min(num_sections, len(section_names))):
            section_offset = section_header_offset + (i * 40)
            if section_offset + 8 <= len(data):
                # Section name is 8 bytes
                data[section_offset:section_offset+8] = section_names[i]
        
        # Generate output filename if not provided
        if output_file is None:
            input_path = Path(input_file)
            output_file = self.output_dir / input_path.name
        
        # Write modified file
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'wb') as f:
            f.write(data)
        
        return str(output_file)
    
    def modify_pe_headers_pefile(self, input_file: str, output_file: str = None) -> str:
        """
        Modify PE headers using pefile library (more sophisticated).
        
        Args:
            input_file: Path to input PE file
            output_file: Path to output modified file
        
        Returns:
            Path to output file
        """
        if pefile is None:
            return self.modify_pe_headers_binary(input_file, output_file)
        
        try:
            pe = pefile.PE(input_file)
            
            # Modify timestamp
            pe.FILE_HEADER.TimeDateStamp = int(time.time()) - random.randint(86400, 86400*365)
            
            # Modify checksum
            pe.OPTIONAL_HEADER.CheckSum = random.randint(0, 0xFFFFFFFF)
            
            # Modify section names
            section_names = [".text", ".data", ".rsrc", ".reloc", ".debug"]
            for i, section in enumerate(pe.sections):
                if i < len(section_names):
                    section.Name = section_names[i].encode()
            
            # Generate output filename if not provided
            if output_file is None:
                input_path = Path(input_file)
                output_file = self.output_dir / input_path.name
            
            # Write modified file
            output_file = Path(output_file)
            output_file.parent.mkdir(parents=True, exist_ok=True)
            pe.write(str(output_file))
            
            return str(output_file)
        
        except Exception as e:
            print(f"[-] Error with pefile: {e}. Falling back to binary manipulation.")
            return self.modify_pe_headers_binary(input_file, output_file)
    
    def apply_pe_header_modification(self, input_file: str, output_file: str = None) -> str:
        """
        Apply PE header modification using available method.
        
        Args:
            input_file: Path to input PE file
            output_file: Path to output modified file
        
        Returns:
            Path to output file
        """
        if pefile is not None:
            return self.modify_pe_headers_pefile(input_file, output_file)
        else:
            return self.modify_pe_headers_binary(input_file, output_file)
    
    def apply_pe_header_modification_all(self, input_dir: str) -> dict:
        """
        Apply PE header modification to all files in a directory.
        
        Args:
            input_dir: Directory containing malware samples
        
        Returns:
            Dictionary with filenames as keys and output paths as values
        """
        results = {}
        input_path = Path(input_dir)
        
        # Get all files (not directories) sorted numerically
        files = sorted([f for f in input_path.iterdir() if f.is_file()], 
                      key=lambda x: (x.name.isdigit() and int(x.name), x.name))
        
        for file_path in files:
            output_file = self.output_dir / file_path.name
            try:
                output_path = self.apply_pe_header_modification(str(file_path), str(output_file))
                if output_path:
                    results[file_path.name] = output_path
                    print(f"[+] PE Header Modified: {file_path.name} -> {output_file.name}")
                else:
                    results[file_path.name] = None
            except Exception as e:
                print(f"[-] Error modifying PE headers for {file_path.name}: {e}")
                results[file_path.name] = None
        
        return results


def main():
    """Test PE header manipulation."""
    pe_mod = PEHeaderManipulation("modified_samples/pe_header_modified")
    pe_mod.apply_pe_header_modification_all("to_be_evaded_ds")


if __name__ == "__main__":
    main()

