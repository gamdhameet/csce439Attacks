import os
import random
import argparse
import pefile
import subprocess

SAMPLES_DIR = "to_be_evaded_ds"
MODIFIED_SAMPLES_DIR = "modified_samples"

def append_random_data(input_path, output_path, data_size_kb):
    """
    Appends a specified amount of random data to a file.

    :param input_path: Path to the input file.
    :param output_path: Path to save the modified file.
    :param data_size_kb: Amount of random data to append in kilobytes.
    """
    if not os.path.exists(MODIFIED_SAMPLES_DIR):
        os.makedirs(MODIFIED_SAMPLES_DIR)

    with open(input_path, 'rb') as f_in:
        original_data = f_in.read()

    random_data = bytearray(random.getrandbits(8) for _ in range(data_size_kb * 1024))

    with open(output_path, 'wb') as f_out:
        f_out.write(original_data)
        f_out.write(random_data)

def append_benign_data(input_path, output_path, benign_path):
    """
    Appends the content of a benign file to another file.

    :param input_path: Path to the input file.
    :param output_path: Path to save the modified file.
    :param benign_path: Path to the benign file to append.
    """
    if not os.path.exists(MODIFIED_SAMPLES_DIR):
        os.makedirs(MODIFIED_SAMPLES_DIR)

    with open(input_path, 'rb') as f_in:
        original_data = f_in.read()

    with open(benign_path, 'rb') as f_benign:
        benign_data = f_benign.read()

    with open(output_path, 'wb') as f_out:
        f_out.write(original_data)
        f_out.write(benign_data)

def manipulate_pe_header(input_path, output_path):
    """
    Manipulates the PE header of a file by changing the timestamp.

    :param input_path: Path to the input PE file.
    :param output_path: Path to save the modified PE file.
    """
    if not os.path.exists(MODIFIED_SAMPLES_DIR):
        os.makedirs(MODIFIED_SAMPLES_DIR)

    try:
        pe = pefile.PE(input_path)
        pe.FILE_HEADER.TimeDateStamp = random.randint(0, 2**32 - 1)
        pe.write(output_path)
    except pefile.PEFormatError as e:
        print(f"Error processing PE file: {e}")
        # If not a PE file, just copy it
        import shutil
        shutil.copy(input_path, output_path)

def pack_upx(input_path, output_path):
    """
    Packs a file using UPX.

    :param input_path: Path to the input file.
    :param output_path: Path to save the packed file.
    """
    if not os.path.exists(MODIFIED_SAMPLES_DIR):
        os.makedirs(MODIFIED_SAMPLES_DIR)
    
    try:
        # Use absolute path for upx
        subprocess.run(["/usr/bin/upx", "-o", output_path, input_path], check=True, capture_output=True)
    except (subprocess.CalledProcessError, FileNotFoundError) as e:
        print(f"Error packing with UPX: {e}")
        # If packing fails, just copy the file
        import shutil
        shutil.copy(input_path, output_path)


def main():
    parser = argparse.ArgumentParser(description="Apply evasion techniques to malware samples.")
    parser.add_argument("-s", "--sample", required=True, help="Sample ID to modify (e.g., '1').")
    parser.add_argument("-t", "--techniques", default="append_random", help="Comma-separated list of techniques to apply (e.g., 'pe_header,append_benign'). Available: append_random, append_benign, pe_header, upx")
    parser.add_argument("--size", type=int, default=10, help="Size of data to append in KB for append_random technique.")
    parser.add_argument("--benign_file", type=str, default="/usr/bin/[", help="Path to a benign file to append for append_benign technique.")
    
    args = parser.parse_args()

    sample_filename = str(args.sample)
    input_sample_path = os.path.join(SAMPLES_DIR, sample_filename)
    
    if not os.path.exists(input_sample_path):
        print(f"Error: Sample '{sample_filename}' not found in {SAMPLES_DIR}")
        return

    output_sample_name = f"{sample_filename}_modified"
    final_output_path = os.path.join(MODIFIED_SAMPLES_DIR, output_sample_name)

    # Start with the original file
    import shutil
    current_path = os.path.join(MODIFIED_SAMPLES_DIR, f"{sample_filename}_temp_start")
    shutil.copy(input_sample_path, current_path)

    techniques = args.techniques.split(',')
    
    for i, technique in enumerate(techniques):
        temp_output_path = os.path.join(MODIFIED_SAMPLES_DIR, f"{sample_filename}_temp_{i}")
        
        if technique == "append_random":
            append_random_data(current_path, temp_output_path, args.size)
            print(f"Applied append_random with size {args.size}KB")
        elif technique == "append_benign":
            append_benign_data(current_path, temp_output_path, args.benign_file)
            print(f"Applied append_benign with file '{args.benign_file}'")
        elif technique == "pe_header":
            manipulate_pe_header(current_path, temp_output_path)
            print("Applied pe_header manipulation")
        elif technique == "upx":
            pack_upx(current_path, temp_output_path)
            print("Applied UPX packing")
        
        # Clean up the previous temp file and update current_path
        os.remove(current_path)
        current_path = temp_output_path
    
    # Move the final temp file to the desired output path
    shutil.move(current_path, final_output_path)
    
    print(f"Finished applying techniques. Final file saved as '{final_output_path}'")


if __name__ == "__main__":
    main()
