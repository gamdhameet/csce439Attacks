"""
Padding Evasion Technique: Append goodware or random data to malware samples.

This technique changes the frequency and distribution of bytes, confusing
raw byte models like MalConv that rely on statistical distributions.
"""

import os
import random
import hashlib
from pathlib import Path


class PaddingEvasion:
    """Apply padding/overlay attack to PE files."""
    
    def __init__(self, output_dir: str, padding_size: int = 2 * 1024 * 1024):
        """
        Initialize padding evasion.
        
        Args:
            output_dir: Directory to save padded files
            padding_size: Size of padding to append (default 2MB)
        """
        self.output_dir = Path(output_dir)
        self.padding_size = padding_size
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def generate_random_padding(self, size: int) -> bytes:
        """Generate random bytes for padding."""
        return bytes(random.randint(0, 255) for _ in range(size))
    
    def generate_goodware_padding(self, size: int) -> bytes:
        """
        Generate benign-looking goodware padding.
        Use common strings and patterns from benign Windows executables.
        """
        # Common benign strings found in legitimate Windows executables
        benign_patterns = [
            b"Windows",
            b"Microsoft",
            b"System32",
            b"kernel32.dll",
            b"ntdll.dll",
            b"user32.dll",
            b"gdi32.dll",
            b"advapi32.dll",
            b"shell32.dll",
            b"ole32.dll",
            b"oleaut32.dll",
            b"comctl32.dll",
            b"shlwapi.dll",
            b"version.dll",
            b"wininet.dll",
            b"ws2_32.dll",
            b"mswsock.dll",
            b"crypt32.dll",
            b"bcrypt.dll",
            b"mscoree.dll",
            b".text",
            b".data",
            b".rsrc",
            b".reloc",
            b"DEBUG",
            b"PE\x00\x00",
            b"MZ",
            b"\x00\x00\x00\x00",
            b"This program cannot be run in DOS mode",
            b"Rich",
            b"@(#)",
        ]
        
        # Build padding by repeating patterns
        padding = b""
        while len(padding) < size:
            pattern = random.choice(benign_patterns)
            # Add random bytes between patterns for variability
            padding += pattern + self.generate_random_padding(random.randint(10, 100))
        
        return padding[:size]
    
    def apply_padding(self, input_file: str, output_file: str = None, use_goodware: bool = False) -> str:
        """
        Apply padding to a PE file.
        
        Args:
            input_file: Path to input malware file
            output_file: Path to output padded file (auto-generated if None)
            use_goodware: If True, use benign patterns; if False, use random bytes
        
        Returns:
            Path to output file
        """
        with open(input_file, 'rb') as f:
            original_data = f.read()
        
        # Generate padding
        if use_goodware:
            padding = self.generate_goodware_padding(self.padding_size)
        else:
            padding = self.generate_random_padding(self.padding_size)
        
        # Append padding to original file (overlay attack)
        modified_data = original_data + padding
        
        # Generate output filename if not provided
        if output_file is None:
            input_path = Path(input_file)
            output_file = self.output_dir / input_path.name
        
        # Write modified file
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'wb') as f:
            f.write(modified_data)
        
        return str(output_file)
    
    def apply_padding_all(self, input_dir: str, use_goodware: bool = True) -> dict:
        """
        Apply padding to all files in a directory.
        
        Args:
            input_dir: Directory containing malware samples
            use_goodware: If True, use benign patterns; if False, use random bytes
        
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
                self.apply_padding(str(file_path), str(output_file), use_goodware)
                results[file_path.name] = str(output_file)
                print(f"[+] Padded: {file_path.name} -> {output_file.name}")
            except Exception as e:
                print(f"[-] Error padding {file_path.name}: {e}")
                results[file_path.name] = None
        
        return results


def main():
    """Test padding evasion."""
    padder = PaddingEvasion("modified_samples/padding")
    padder.apply_padding_all("to_be_evaded_ds", use_goodware=True)


if __name__ == "__main__":
    main()

