"""
XOR Encoding Evasion Technique: Encode PE file with XOR cipher.

This technique hides recognizable strings, headers, and magic numbers
from static analysis by XOR-encoding the payload with a key.
"""

import os
import random
from pathlib import Path
from typing import Tuple


class XOREncoding:
    """Apply XOR encoding to PE files."""
    
    def __init__(self, output_dir: str):
        """
        Initialize XOR encoding.
        
        Args:
            output_dir: Directory to save XOR-encoded files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def xor_encode(self, data: bytes, key: int) -> bytes:
        """
        XOR encode data with a single-byte key.
        
        Args:
            data: Input data to encode
            key: Single-byte XOR key (0-255)
        
        Returns:
            XOR-encoded data
        """
        return bytes(byte ^ key for byte in data)
    
    def create_simple_decoder_stub(self, key: int) -> bytes:
        """
        Create a simple decoder stub for runtime decoding.
        This is x86 assembly that XOR-decodes data.
        
        In a real scenario, this would be more sophisticated.
        For now, we'll create a Python wrapper that embeds the key.
        
        Args:
            key: XOR key used for encoding
        
        Returns:
            Decoder stub bytes
        """
        # Placeholder decoder info - in production this would be x86 shellcode
        # For this implementation, we encode the key in the file as metadata
        decoder_info = b"XOR_DECODER_KEY:" + bytes([key]) + b"\x00"
        return decoder_info
    
    def apply_xor_encoding(self, input_file: str, output_file: str = None, key: int = None) -> Tuple[str, int]:
        """
        Apply XOR encoding to a PE file.
        
        The file structure is:
        [Original PE Magic/Headers - NOT encoded to preserve PE validity]
        [XOR Decoder Stub/Key info]
        [XOR-encoded payload]
        
        Args:
            input_file: Path to input malware file
            output_file: Path to output XOR-encoded file (auto-generated if None)
            key: XOR key to use (random if None)
        
        Returns:
            Tuple of (output_file_path, xor_key_used)
        """
        with open(input_file, 'rb') as f:
            original_data = f.read()
        
        # Use provided key or generate random one
        if key is None:
            key = random.randint(1, 255)  # Avoid 0 to ensure modification
        
        # For PE files, preserve the MZ header and PE signature for basic compatibility
        # This is a simplified approach; real evasion would be more sophisticated
        mz_header_size = 64  # Preserve first 64 bytes (DOS header)
        
        # Split data
        preserved_header = original_data[:mz_header_size]
        payload = original_data[mz_header_size:]
        
        # XOR encode the payload
        encoded_payload = self.xor_encode(payload, key)
        
        # Recreate file with decoder stub embedded
        decoder_stub = self.create_simple_decoder_stub(key)
        modified_data = preserved_header + decoder_stub + encoded_payload
        
        # Generate output filename if not provided
        if output_file is None:
            input_path = Path(input_file)
            output_file = self.output_dir / input_path.name
        
        # Write modified file
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(output_file, 'wb') as f:
            f.write(modified_data)
        
        return str(output_file), key
    
    def apply_xor_encoding_all(self, input_dir: str) -> dict:
        """
        Apply XOR encoding to all files in a directory.
        
        Args:
            input_dir: Directory containing malware samples
        
        Returns:
            Dictionary with filenames as keys and (output_path, key) tuples as values
        """
        results = {}
        input_path = Path(input_dir)
        
        # Get all files (not directories) sorted numerically
        files = sorted([f for f in input_path.iterdir() if f.is_file()], 
                      key=lambda x: (x.name.isdigit() and int(x.name), x.name))
        
        for file_path in files:
            output_file = self.output_dir / file_path.name
            try:
                output_path, key = self.apply_xor_encoding(str(file_path), str(output_file))
                results[file_path.name] = (output_path, key)
                print(f"[+] XOR Encoded: {file_path.name} with key {key:02x} -> {output_file.name}")
            except Exception as e:
                print(f"[-] Error XOR encoding {file_path.name}: {e}")
                results[file_path.name] = None
        
        return results


def main():
    """Test XOR encoding."""
    xor = XOREncoding("modified_samples/xor_encoded")
    xor.apply_xor_encoding_all("to_be_evaded_ds")


if __name__ == "__main__":
    main()

