import pefile
import os

# --- CONFIGURATION ---
INPUT_FILE = "notepad.exe"
OUTPUT_FILE = "notepad_minimal_changes.exe" 
# --- END CONFIGURATION ---

def minimal_adversarial_patch(input_path: str, output_path: str):
    print(f"[i] Loading PE file: {input_path}")
    
    # 1. Load the PE file
    try:
        pe = pefile.PE(input_path)
    except Exception as e:
        print(f"[E] Error loading file: {e}")
        return
    
    # 1: Zero Checksum 
    original_checksum = pe.OPTIONAL_HEADER.CheckSum
    pe.OPTIONAL_HEADER.CheckSum = 0
    print(f"[i] Optional Header CheckSum zeroed (original: {hex(original_checksum)}).")

    # 2: Timestamp Corruption 
    original_timestamp = pe.FILE_HEADER.TimeDateStamp
    pe.FILE_HEADER.TimeDateStamp = 0
    print(f"[i] File Header TimeDateStamp set to 0 (original: {hex(original_timestamp)}).")
    
    # 3. Write the modified PE file structure
    pe.write(filename=output_path)
    pe.close()

# Run the adversarial modification
if os.path.exists(INPUT_FILE):
    minimal_adversarial_patch(INPUT_FILE, OUTPUT_FILE)
else:
    print(f"Error")
