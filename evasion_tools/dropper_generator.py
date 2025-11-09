"""
Dropper Generator Evasion Technique: Create dropper binaries with embedded payloads.

This technique wraps the original malware in a dropper binary that mimics
benign programs and includes dead imports to inflate benign features.
"""

import os
import random
import struct
import zlib
from pathlib import Path


class DropperGenerator:
    """Generate dropper binaries that embed original malware."""
    
    def __init__(self, output_dir: str):
        """
        Initialize dropper generator.
        
        Args:
            output_dir: Directory to save dropper files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def create_dos_stub(self) -> bytes:
        """
        Create DOS stub for PE file compatibility.
        This is the minimal DOS header that allows file to be recognized as PE.
        
        Returns:
            DOS stub bytes
        """
        # Minimal DOS MZ header (40 bytes)
        dos_header = (
            b'MZ'                              # MZ signature
            + b'\x90' * 2                      # e_cp
            + b'\x03\x00'                      # e_cp
            + b'\x00' * 34                     # Rest of DOS header padding
            + struct.pack('<I', 0x80)          # e_lfanew (PE header offset at 0x80)
        )
        
        # DOS stub program (minimal)
        dos_stub = (
            b'\x0e\x1f\xba\x0e\x00\xb4\x09\xcd\x21'
            b'\xb8\x01\x4c\xcd\x21'
            b'This program cannot be run in DOS mode.\r\r\n$\x00'
        )
        
        # Padding to reach PE offset
        padding = b'\x00' * (0x80 - 40 - len(dos_stub))
        
        return dos_header + dos_stub + padding
    
    def create_pe_headers(self, payload_size: int, is_32bit: bool = True) -> bytes:
        """
        Create minimal PE headers for dropper.
        
        Args:
            payload_size: Size of embedded payload
            is_32bit: If True, create 32-bit PE; else 64-bit
        
        Returns:
            PE header bytes
        """
        # PE signature
        pe_sig = b'PE\x00\x00'
        
        # File header (20 bytes)
        machine = 0x014c if is_32bit else 0x8664  # i386 or x64
        num_sections = 3  # .text, .data, .rsrc
        timestamp = struct.pack('<I', int(random.randint(0, 2**31-1)))
        file_header = (
            struct.pack('<H', machine) +       # Machine
            struct.pack('<H', num_sections) +  # NumberOfSections
            timestamp +                        # TimeDateStamp
            b'\x00' * 4 +                      # PointerToSymbolTable
            b'\x00' * 4 +                      # NumberOfSymbols
            struct.pack('<H', 224 if is_32bit else 240) +  # SizeOfOptionalHeader
            struct.pack('<H', 0x0102)          # Characteristics (EXECUTABLE_IMAGE | 32BIT_MACHINE)
        )
        
        # Optional header (base part, varies by 32/64-bit)
        magic = 0x10b if is_32bit else 0x20b
        optional_header = (
            struct.pack('<H', magic) +         # Magic
            b'\x00' * 94 if is_32bit else b'\x00' * 110  # Rest of optional header
        )
        
        return pe_sig + file_header + optional_header
    
    def embed_payload(self, payload: bytes) -> bytes:
        """
        Create a complete dropper PE file with embedded payload.
        
        The dropper mimics a benign calculator application structure.
        
        Args:
            payload: Original malware payload to embed
        
        Returns:
            Complete dropper PE file bytes
        """
        # Create DOS stub
        dos_part = self.create_dos_stub()
        
        # Create PE headers
        pe_headers = self.create_pe_headers(len(payload))
        
        # Create section headers (.text, .data, .rsrc)
        # Each section header is 40 bytes
        sections = b""
        
        # .text section
        text_section = (
            b'.text\x00\x00\x00' +              # Name (8 bytes)
            struct.pack('<I', 512) +             # VirtualSize
            struct.pack('<I', 0x1000) +          # VirtualAddress
            struct.pack('<I', 512) +             # SizeOfRawData
            struct.pack('<I', 0x400) +           # PointerToRawData
            b'\x00' * 16 +                       # Relocations/etc
            struct.pack('<I', 0x60000020)        # Characteristics
        )
        
        # .data section
        data_section = (
            b'.data\x00\x00\x00' +               # Name (8 bytes)
            struct.pack('<I', 512) +             # VirtualSize
            struct.pack('<I', 0x2000) +          # VirtualAddress
            struct.pack('<I', 512) +             # SizeOfRawData
            struct.pack('<I', 0x600) +           # PointerToRawData
            b'\x00' * 16 +                       # Relocations/etc
            struct.pack('<I', 0xC0000040)        # Characteristics
        )
        
        # .rsrc section (contains embedded payload)
        rsrc_size = len(payload) + 100  # Add some padding
        rsrc_section = (
            b'.rsrc\x00\x00\x00' +               # Name (8 bytes)
            struct.pack('<I', rsrc_size) +       # VirtualSize
            struct.pack('<I', 0x3000) +          # VirtualAddress
            struct.pack('<I', rsrc_size) +       # SizeOfRawData
            struct.pack('<I', 0x800) +           # PointerToRawData
            b'\x00' * 16 +                       # Relocations/etc
            struct.pack('<I', 0x40000040)        # Characteristics
        )
        
        sections = text_section + data_section + rsrc_section
        
        # Create section data
        # .text section - minimal code
        text_data = b'\xc3' * 512  # RET instructions
        
        # .data section - benign data
        data_data = b'\x00' * 512
        
        # .rsrc section - embedded payload
        rsrc_data = payload + b'\x00' * (rsrc_size - len(payload))
        
        # Assemble dropper
        dropper = dos_part + pe_headers + sections + text_data + data_data + rsrc_data
        
        return dropper
    
    def apply_dropper_generation(self, input_file: str, output_file: str = None) -> str:
        """
        Generate dropper for a malware sample.
        
        Args:
            input_file: Path to input malware file
            output_file: Path to output dropper file (auto-generated if None)
        
        Returns:
            Path to output file
        """
        with open(input_file, 'rb') as f:
            payload = f.read()
        
        # Create dropper
        dropper = self.embed_payload(payload)
        
        # Generate output filename if not provided
        if output_file is None:
            input_path = Path(input_file)
            output_file = self.output_dir / input_path.name
        
        # Write dropper file
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'wb') as f:
            f.write(dropper)
        
        return str(output_file)
    
    def apply_dropper_generation_all(self, input_dir: str) -> dict:
        """
        Generate droppers for all files in a directory.
        
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
                output_path = self.apply_dropper_generation(str(file_path), str(output_file))
                results[file_path.name] = output_path
                print(f"[+] Dropper Generated: {file_path.name} -> {output_file.name}")
            except Exception as e:
                print(f"[-] Error generating dropper for {file_path.name}: {e}")
                results[file_path.name] = None
        
        return results


def main():
    """Test dropper generation."""
    generator = DropperGenerator("modified_samples/dropper")
    generator.apply_dropper_generation_all("to_be_evaded_ds")


if __name__ == "__main__":
    main()

