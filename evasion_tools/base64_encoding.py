"""
Base64 Encoding Evasion Technique: Encode PE file payload with Base64.

This technique converts binary content into harmless text strings,
bypassing string-based static analysis.
"""

import os
import base64
from pathlib import Path


class Base64Encoding:
    """Apply Base64 encoding to PE files."""
    
    def __init__(self, output_dir: str):
        """
        Initialize Base64 encoding.
        
        Args:
            output_dir: Directory to save Base64-encoded files
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def create_base64_dropper_stub(self) -> bytes:
        """
        Create a dropper stub that can decode and execute Base64-encoded payload.
        
        In a real scenario, this would be a compiled executable (C/C++/C#).
        For this implementation, we embed decoder metadata.
        
        Returns:
            Dropper stub bytes containing decoder logic
        """
        # Embedded decoder metadata and stub
        # This marks the file as containing Base64-encoded payload
        stub = (
            b"BASE64_DECODER_STUB\x00"
            b"This is a placeholder for a real dropper executable\x00"
            b"The following data is Base64-encoded payload:\x00"
        )
        return stub
    
    def apply_base64_encoding(self, input_file: str, output_file: str = None) -> str:
        """
        Apply Base64 encoding to a PE file.
        
        The file structure is:
        [Dropper Stub / Decoder metadata]
        [Base64-encoded original PE file]
        
        Args:
            input_file: Path to input malware file
            output_file: Path to output Base64-encoded file (auto-generated if None)
        
        Returns:
            Path to output file
        """
        with open(input_file, 'rb') as f:
            original_data = f.read()
        
        # Base64 encode the entire payload
        encoded_payload = base64.b64encode(original_data)
        
        # Create dropper stub
        dropper_stub = self.create_base64_dropper_stub()
        
        # Combine dropper stub with encoded payload
        # For transmission, encode the stub as well for consistency
        modified_data = dropper_stub + b"\n" + encoded_payload
        
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
    
    def apply_base64_encoding_all(self, input_dir: str) -> dict:
        """
        Apply Base64 encoding to all files in a directory.
        
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
                output_path = self.apply_base64_encoding(str(file_path), str(output_file))
                results[file_path.name] = output_path
                print(f"[+] Base64 Encoded: {file_path.name} -> {output_file.name}")
            except Exception as e:
                print(f"[-] Error Base64 encoding {file_path.name}: {e}")
                results[file_path.name] = None
        
        return results


def main():
    """Test Base64 encoding."""
    b64 = Base64Encoding("modified_samples/base64_encoded")
    b64.apply_base64_encoding_all("to_be_evaded_ds")


if __name__ == "__main__":
    main()

