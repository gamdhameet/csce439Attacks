"""
Goodware Collector: Extract benign strings for padding attacks.

This module collects goodware patterns and strings to use as padding material,
making the padding appear more benign.
"""

import os
from pathlib import Path
from typing import List, Set


class GoodwareCollector:
    """Collect benign strings and patterns for padding."""
    
    def __init__(self, output_dir: str = "goodware_strings"):
        """
        Initialize goodware collector.
        
        Args:
            output_dir: Directory to save collected goodware strings
        """
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)
    
    def get_common_benign_patterns(self) -> List[bytes]:
        """
        Get common benign patterns from Windows executables.
        
        Returns:
            List of benign byte patterns
        """
        patterns = [
            # Windows DLL names
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
            b"ntdll",
            b"kernel32",
            
            # Windows paths
            b"System32",
            b"Windows",
            b"Program Files",
            
            # PE section names
            b".text",
            b".data",
            b".rsrc",
            b".reloc",
            b".debug",
            b"CODE",
            b"DATA",
            
            # PE headers and magic numbers
            b"PE\x00\x00",
            b"MZ\x90\x00",
            
            # Common strings
            b"This program cannot be run in DOS mode",
            b"Rich",
            b"@(#)",
            b"Microsoft",
            b"Windows NT",
            b"Debug",
            
            # Export names
            b"DllMain",
            b"DllEntryPoint",
            b"GetProcAddress",
            b"LoadLibrary",
            
            # Common API functions
            b"CreateFileA",
            b"ReadFile",
            b"WriteFile",
            b"CloseHandle",
            b"GetFileSize",
            b"SetFilePointer",
            b"CreateProcessA",
            b"WaitForSingleObject",
            b"ExitProcess",
            b"GetLastError",
            
            # Registry functions
            b"RegOpenKeyEx",
            b"RegQueryValueEx",
            b"RegSetValueEx",
            b"RegCloseKey",
            
            # Memory functions
            b"VirtualAlloc",
            b"VirtualFree",
            b"VirtualProtect",
            b"HeapAlloc",
            b"HeapFree",
            
            # String functions
            b"lstrcpy",
            b"lstrlen",
            b"wsprintfA",
            b"strlen",
            b"strcpy",
            
            # CRT functions
            b"_heap_init",
            b"_heap_term",
            b"_mtinit",
            b"_mtexit",
            
            # Misc
            b"GetModuleHandle",
            b"GetModuleFileNameA",
            b"GetCurrentDirectory",
            b"SetCurrentDirectory",
        ]
        
        return patterns
    
    def extract_strings_from_file(self, file_path: str, min_length: int = 4) -> Set[bytes]:
        """
        Extract ASCII strings from a binary file.
        
        Args:
            file_path: Path to binary file
            min_length: Minimum string length
        
        Returns:
            Set of extracted strings
        """
        strings = set()
        
        try:
            with open(file_path, 'rb') as f:
                data = f.read()
            
            current_string = b""
            for byte in data:
                # Check if byte is printable ASCII or common whitespace
                if 32 <= byte <= 126 or byte in (9, 10, 13):  # tab, newline, carriage return
                    current_string += bytes([byte])
                else:
                    if len(current_string) >= min_length:
                        strings.add(current_string)
                    current_string = b""
            
            if len(current_string) >= min_length:
                strings.add(current_string)
        
        except Exception as e:
            print(f"[-] Error extracting strings from {file_path}: {e}")
        
        return strings
    
    def collect_from_directory(self, goodware_dir: str) -> Set[bytes]:
        """
        Collect strings from all files in a directory.
        
        Args:
            goodware_dir: Directory containing benign executables
        
        Returns:
            Set of collected strings
        """
        all_strings = set()
        dir_path = Path(goodware_dir)
        
        if not dir_path.exists():
            print(f"[-] Directory not found: {goodware_dir}")
            return all_strings
        
        for file_path in dir_path.iterdir():
            if file_path.is_file():
                print(f"[*] Processing: {file_path.name}")
                strings = self.extract_strings_from_file(str(file_path))
                all_strings.update(strings)
        
        return all_strings
    
    def save_patterns(self, output_file: str = None) -> str:
        """
        Save collected benign patterns to file.
        
        Args:
            output_file: Path to output file (auto-generated if None)
        
        Returns:
            Path to output file
        """
        if output_file is None:
            output_file = self.output_dir / "benign_patterns.txt"
        
        output_file = Path(output_file)
        output_file.parent.mkdir(parents=True, exist_ok=True)
        
        patterns = self.get_common_benign_patterns()
        
        with open(output_file, 'w', encoding='utf-8', errors='ignore') as f:
            for pattern in sorted(patterns):
                try:
                    f.write(pattern.decode('utf-8', errors='ignore') + "\n")
                except:
                    f.write(f"[BINARY] {pattern.hex()}\n")
        
        print(f"[+] Benign patterns saved to: {output_file}")
        return str(output_file)


def main():
    """Test goodware collector."""
    collector = GoodwareCollector()
    collector.save_patterns()


if __name__ == "__main__":
    main()

