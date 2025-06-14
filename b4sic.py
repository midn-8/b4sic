#!/usr/bin/env python3
import subprocess
import sys
import os
import hashlib
import argparse
import datetime
import shutil
import base64
import binascii
import urllib.parse
import re
import struct # For parsing binary data (PNG/JPEG headers)

# --- Helper Function: Run External Commands (Keep as is) ---
def run_command(command_list, input_data=None, suppress_errors=False):
    
    try:
        process = subprocess.run(
            command_list,
            input=input_data,
            capture_output=True,
            text=True,
            check=True,
            errors='replace'
        )
        return process.stdout.strip()
    except FileNotFoundError:
        if not suppress_errors:
            return f"ERROR: Command '{command_list[0]}' not found. Please ensure it's installed and in your PATH."
        return ""
    except subprocess.CalledProcessError as e:
        if not suppress_errors:
            error_message = f"ERROR: Command '{' '.join(command_list)}' failed with exit code {e.returncode}.\n"
            error_message += f"Stderr: {e.stderr.strip()}"
            return error_message
        return ""
    except Exception as e:
        if not suppress_errors:
            return f"AN UNEXPECTED ERROR OCCURRED: {e}"
        return ""
# Add this function somewhere near the top, e.g., after run_command
def check_dependencies():
    required_tools = ["file", "strings", "exiftool", "binwalk", "md5sum", "sha256sum"]
    missing_tools = []
    for tool in required_tools:
        # Check if the command can be found in PATH
        if shutil.which(tool) is None:
            missing_tools.append(tool)

    if missing_tools:
        print_section_header("Dependency Warning!", level=2)
        print("The following external tools are required but could not be found:")
        for tool in missing_tools:
            print(f"  - {tool}")
        print("\nPlease install them using your system's package manager (e.g., 'sudo apt install <tool_name>')")
        print("Some common packages include: binutils (for strings), exiftool, binwalk, coreutils (for md5sum/sha256sum).")
        print("\nAnalysis may be incomplete or fail without these tools.")
        # Decide if you want to exit here or just warn. For now, let's warn.
        # sys.exit(1)
# --- Helper Function: Print Section Headers (Keep as is) ---
def print_section_header(title, level=1):
    # ... (same as before) ...
    if level == 1:
        print(f"\n{'='*50}\n {title.upper()}\n{'='*50}\n")
    else:
        print(f"\n{'-'*50}\n {title}\n{'-'*50}\n")

# --- String Decoding Helpers (Keep as is) ---
def decode_base64(s):
    # ... (same as before) ...
    try:
        if len(s) % 4 == 0 and all(c in 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=' for c in s):
            return base64.b64decode(s).decode('utf-8', errors='ignore')
    except (binascii.Error, UnicodeDecodeError):
        pass
    return None

def decode_hex(s):
    # ... (same as before) ...
    try:
        if len(s) % 2 == 0 and all(c in '0123456789abcdefABCDEF' for c in s):
            return binascii.unhexlify(s).decode('utf-8', errors='ignore')
    except (binascii.Error, UnicodeDecodeError):
        pass
    return None

def decode_url(s):
    # ... (same as before) ...
    if '%' in s:
        decoded = urllib.parse.unquote(s)
        if decoded != s:
            return decoded
    return None

# ... (rest of the imports and functions remain the same) ...

# --- String Analysis Logic (MODIFIED) ---
def analyze_strings(file_path, workspace_path, min_string_length=4):
    print_section_header("String Analysis", level=2)

    print(f"Strings Output (minimum length: {min_string_length}):")
    strings_command = ["strings", "-n", str(min_string_length), file_path]
    strings_output = run_command(strings_command)

    if "ERROR:" in strings_output:
        print(f"---> {strings_output}")
        return

    strings_output_path = os.path.join(workspace_path, "strings_output.txt")
    with open(strings_output_path, 'w', encoding='utf-8', errors='replace') as f:
        f.write(strings_output)
    print(f"---> Full strings output saved to: {os.path.abspath(strings_output_path)}")

    lines = strings_output.splitlines()
    display_line_limit = 20
    displayed_count = 0

    for line in lines:
        if displayed_count >= display_line_limit:
            print(f"---> (Showing first {display_line_limit} lines. See {os.path.basename(strings_output_path)} for full output.)")
            break
        print(f"---> {line}")
        displayed_count += 1

    if not lines and not strings_output.strip():
        print("---> No strings found with the specified minimum length.")
    elif not lines and strings_output.strip():
        print(f"---> {strings_output}")
        if displayed_count == 0 and len(strings_output.splitlines()) > 0:
             print(f"---> (See {os.path.basename(strings_output_path)} for full output if more lines exist.)")


    print("\nPotential Decoded Strings:")
    decoded_found = False
    for line in strings_output.splitlines():
        clean_line = line.strip()
        if not clean_line:
            continue

        b64_decoded = decode_base64(clean_line)
        if b64_decoded:
            print(f"  -> Base64: '{clean_line}' -> '{b64_decoded}'")
            decoded_found = True

        hex_decoded = decode_hex(clean_line)
        if hex_decoded:
            print(f"  -> Hex:    '{clean_line}' -> '{hex_decoded}'")
            decoded_found = True

        url_decoded = decode_url(clean_line)
        if url_decoded:
            print(f"  -> URL:    '{clean_line}' -> '{url_decoded}'")
            decoded_found = True

    if not decoded_found:
        print("  No common encoded strings found that could be automatically decoded.")

    # --- Common Flag Pattern Search (MODIFIED) ---
    print("\nCommon Flag Pattern Search:")
    flag_patterns = [
        # Specific patterns you want to keep
        r"FLAG{[a-zA-Z0-9_!@#$%^&*()\-+=\[\]{}|;:'\",.<>/?`~ ]+}",
        r"flag{[a-zA-Z0-9_!@#$%^&*()\-+=\[\]{}|;:'\",.<>/?`~ ]+}",
        r"CTF{[a-zA-Z0-9_!@#$%^&*()\-+=\[\]{}|;:'\",.<>/?`~ ]+}",
        r"ctf{[a-zA-Z0-9_!@#$%^&*()\-+=\[\]{}|;:'\",.<>/?`~ ]+}",
        r"picoCTF{[a-zA-Z0-9_!@#$%^&*()\-+=\[\]{}|!@#$%^&*()\-+=\[\]{}|;:'\",.<>/?`~ ]+}",
        r"picoCTF\{[^\}]+\}",
        r"flag\{[^\}]+\}",
        # New, more generic pattern for 3 uppercase letters followed by {
        r"[A-Z]{3}\{[a-zA-Z0-9_!@#$%^&*()\-+=\[\]{}|;:'\",.<>/?`~ ]+\}",
        r"[A-Z]{3}\{[^\}]+\}" # A more generic one for any content inside {}
    ]

    flags_found = set()

    for pattern in flag_patterns:
        found_matches = re.findall(pattern, strings_output)
        for match in found_matches:
            flags_found.add(match)

    if flags_found:
        for flag in sorted(list(flags_found)):
            print(f"  -> Potential Flag: {flag}")
    else:
        print("  No common flag patterns found.")


# --- Metadata & Embedded Data Analysis (Keep as is) ---
def analyze_metadata_and_embedded(file_path, workspace_path):
    print_section_header("Metadata & Embedded Data", level=2)

    print("Exiftool Metadata:")
    exif_output = run_command(["exiftool", file_path])
    if "ERROR:" in exif_output:
        print(f"---> {exif_output}")
    elif not exif_output.strip():
        print("---> No metadata found by Exiftool.")
    else:
        exif_output_path = os.path.join(workspace_path, "exiftool_output.txt")
        with open(exif_output_path, 'w', encoding='utf-8', errors='replace') as f:
            f.write(exif_output)
        print(f"---> Full Exiftool output saved to: {os.path.abspath(exif_output_path)}")

        exif_lines = exif_output.splitlines()
        display_limit = 15
        displayed_count = 0
        for line in exif_lines:
            if displayed_count >= display_limit:
                print(f"---> (Showing first {display_limit} lines. See {os.path.basename(exif_output_path)} for full output.)")
                break
            print(f"---> {line}")
            displayed_count += 1
        if not exif_lines and exif_output.strip():
            print(f"---> {exif_output}")


    print("\nBinwalk Scan:")
    binwalk_output = run_command(["binwalk", file_path])

    if "ERROR:" in binwalk_output:
        print(f"---> {binwalk_output}")
    elif "No entries found" in binwalk_output or not binwalk_output.strip():
        print("---> No embedded files or interesting signatures found by Binwalk.")
    else:
        binwalk_output_path = os.path.join(workspace_path, "binwalk_output.txt")
        with open(binwalk_output_path, 'w', encoding='utf-8', errors='replace') as f:
            f.write(binwalk_output)
        print(f"---> Full Binwalk output saved to: {os.path.abspath(binwalk_output_path)}")

        print(f"---> {binwalk_output}")

        relevant_lines = [line for line in binwalk_output.splitlines() if not (line.strip().startswith("DECIMAL") or line.strip().startswith("---") or line.strip() == "")]
        if len(relevant_lines) > 1:
            extracted_dir_name = os.path.basename(file_path) + ".extracted"
            print(f"\n---> Binwalk found embedded files/signatures.")
            print(f"---> To extract these, run: binwalk -e '{file_path}'") # Use the workspace copy path
            print(f"---> Extracted files will typically appear in a directory like '{os.path.join(os.path.abspath(workspace_path), extracted_dir_name)}'")
            print(f"---> After extraction, you can re-run b4sic on the extracted files.")

# --- New Function: Analyze Image Dimensions ---
def analyze_image_dimensions(file_path, file_type_output):
    print_section_header("Image Dimension Analysis", level=2)
    
    is_png = "PNG image data" in file_type_output
    is_jpeg = "JPEG image data" in file_type_output

    if not (is_png or is_jpeg):
        print("---> File does not appear to be a PNG or JPEG image. Skipping dimension analysis.")
        return

    width = -1
    height = -1

    try:
        with open(file_path, 'rb') as f:
            if is_png:
                # PNG IHDR chunk: 16 bytes into the file (after 8-byte signature)
                # IHDR chunk is 13 bytes long, followed by width (4 bytes) and height (4 bytes)
                f.seek(16)
                ihdr_data = f.read(8) # Read 8 bytes for width and height
                if len(ihdr_data) == 8:
                    width, height = struct.unpack('>II', ihdr_data) # Big-endian unsigned int
            elif is_jpeg:
                # JPEG SOF (Start of Frame) markers
                # SOF0 (Baseline JPEG) is common, marker is FF C0
                # Dimensions are typically at byte 165 for typical JPEGs, but can vary.
                # A more robust parse would scan for markers. For simplicity, we'll try common offsets.
                # Format: Length (2 bytes), Precision (1 byte), Height (2 bytes), Width (2 bytes)
                # Let's read the whole file to find the markers.
                f.seek(0)
                jpeg_data = f.read()
                
                # Search for SOF0 marker (FF C0)
                # This pattern is common, but may vary for other JPEG types (C1, C2, etc.)
                sof_marker = b'\xFF\xC0'
                marker_pos = jpeg_data.find(sof_marker)
                
                if marker_pos != -1:
                    # Dimensions are 5 bytes after the marker: Length(2) + Precision(1)
                    # Height (2 bytes) and Width (2 bytes)
                    # Example: FFC0 0011 08 0090 0100 (0090=144 height, 0100=256 width)
                    if marker_pos + 5 + 4 <= len(jpeg_data): # Ensure enough bytes are available
                        dim_data = jpeg_data[marker_pos + 5 : marker_pos + 5 + 4]
                        height, width = struct.unpack('>HH', dim_data) # Big-endian unsigned short

    except Exception as e:
        print(f"---> Error reading image dimensions: {e}")
        print("---> This could be due to file corruption or an unsupported image variant.")

    if width > 0 and height > 0:
        print(f"---> Current dimensions: {width}x{height}")
        print("\n---> Potential Steganography Hint:")
        print("     If this image looks cropped or incomplete, try manually adjusting the width/height")
        print(f"     values in a hex editor (e.g., HxD, Bless).")
        if is_png:
            print("     For PNGs, dimensions are at byte offset 0x10 (16 decimal) after the PNG signature.")
            print("     (Width: bytes 0x10-0x13, Height: bytes 0x14-0x17).")
            print("     Remember to recalculate the CRC for the IHDR chunk if you modify dimensions!")
        elif is_jpeg:
            print("     For JPEGs, dimensions are often near the `FF C0` (SOF0) marker.")
            print("     (Height: 2 bytes after length/precision, Width: 2 bytes after height).")
            print("     Be aware that JPEG structure is more complex and offsets can vary.")
    else:
        print("---> Could not determine image dimensions.")


# --- Main Analysis Logic (Updated to call analyze_image_dimensions) ---
def analyze_file(file_path, strings_min_length):
    check_dependencies()
    print_section_header(f"b4sic Analysis for: {file_path}")

    base_workspace_dir = ".b4sic_workspaces"
    os.makedirs(base_workspace_dir, exist_ok=True)

    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    file_abs_path = os.path.abspath(file_path)
    file_abs_path_hash = hashlib.md5(file_abs_path.encode()).hexdigest()[:8]
    workspace_name = f"b4sic_workspace_{timestamp}_{file_abs_path_hash}"
    workspace_path = os.path.join(base_workspace_dir, workspace_name)

    try:
        os.makedirs(workspace_path)
    except OSError as e:
        print(f"ERROR: Could not create workspace directory {workspace_path}: {e}")
        print("This might happen if a workspace with the same name already exists quickly after another.")
        print("Please try again or manually delete the conflicting directory.")
        return

    print(f"Working in temporary workspace: {os.path.abspath(workspace_path)}")
    print(f"Copying original file to workspace...")
    original_file_copy_path = os.path.join(workspace_path, os.path.basename(file_path))
    try:
        shutil.copy2(file_path, original_file_copy_path)
    except FileNotFoundError:
        print(f"ERROR: Original file '{file_path}' not found. Exiting.")
        shutil.rmtree(workspace_path)
        return
    except Exception as e:
        print(f"ERROR: Could not copy file to workspace: {e}. Exiting.")
        shutil.rmtree(workspace_path)
        return

    # Store file_type_output here so we can pass it to image analysis
    print_section_header("Basic File Information", level=2)
    print("File Type:")
    file_type_output = run_command(["file", original_file_copy_path])
    print(f"---> {file_type_output}")

    print("\nFile Size:")
    try:
        size_bytes = os.path.getsize(original_file_copy_path)
        for unit in ['bytes', 'KB', 'MB', 'GB', 'TB']:
            if size_bytes < 1024.0:
                print(f"---> {size_bytes:.2f} {unit}")
                break
            size_bytes /= 1024.0
    except Exception as e:
        print(f"---> Error getting size: {e}")

    print("\nMD5 Hash:")
    md5_hash = run_command(["md5sum", original_file_copy_path]).split(' ')[0]
    print(f"---> {md5_hash}")

    print("\nSHA256 Hash:")
    sha256_hash = run_command(["sha256sum", original_file_copy_path]).split(' ')[0]
    print(f"---> {sha256_hash}")

    analyze_strings(original_file_copy_path, workspace_path, strings_min_length)
    analyze_metadata_and_embedded(original_file_copy_path, workspace_path)

    # --- Call the new image dimension analysis function ---
    # Pass the file_type_output to avoid re-running 'file'
    analyze_image_dimensions(original_file_copy_path, file_type_output)


    print(f"\nAnalysis complete. Generated files are in: {os.path.abspath(workspace_path)}")
    print("\n" + "="*50 + "\n")

# --- Cleanup Logic (Keep as is) ---
def clean_workspaces():
    # ... (same as before) ...
    print_section_header("Cleaning b4sic Workspaces")
    base_workspace_dir = ".b4sic_workspaces"

    if not os.path.exists(base_workspace_dir):
        print(f"No '{base_workspace_dir}' directory found. Nothing to clean.")
        return

    workspaces_found = []
    for entry in os.listdir(base_workspace_dir):
        full_path = os.path.join(base_workspace_dir, entry)
        if os.path.isdir(full_path) and entry.startswith("b4sic_workspace_"):
            workspaces_found.append(full_path)

    if not workspaces_found:
        print(f"No 'b4sic_workspace_' directories found inside '{base_workspace_dir}'. Nothing to clean.")
        return

    print("The following b4sic workspaces will be deleted:")
    for ws in workspaces_found:
        print(f"  - {os.path.abspath(ws)}")

    confirm = input("Are you sure you want to delete these workspaces? [y/N]: ").lower().strip()
    if confirm == 'y':
        print("Deleting workspaces...")
        for ws in workspaces_found:
            try:
                shutil.rmtree(ws)
                print(f"  Deleted: {os.path.abspath(ws)}")
            except Exception as e:
                print(f"  ERROR: Could not delete {os.path.abspath(ws)}: {e}")
        print("Cleanup complete.")
    else:
        print("Cleanup cancelled.")

def main():
    parser = argparse.ArgumentParser(
        description="b4sic: Your essential CTF file reconnaissance and workspace management tool."
    )
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    analyze_parser = subparsers.add_parser(
        'analyze',
        help='Perform initial reconnaissance on a CTF challenge file within a dedicated workspace.'
    )
    analyze_parser.add_argument(
        'file_path',
        help='Path to the CTF file to analyze.'
    )
    analyze_parser.add_argument(
        '--strings-min-len',
        type=int,
        default=4,
        help='Minimum length of printable characters for the "strings" command (default: 4).'
    )

    clean_parser = subparsers.add_parser(
        'clean',
        help='Clean up b4sic generated workspaces in the current directory.'
    )

    args = parser.parse_args()

    if args.command == 'analyze':
        if not os.path.exists(args.file_path):
            print(f"Error: File not found at '{args.file_path}'")
            sys.exit(1)
        analyze_file(args.file_path, args.strings_min_len)
    elif args.command == 'clean':
        clean_workspaces()
    else:
        parser.print_help()

# The entry point when run directly (for development/testing)
if __name__ == "__main__":
    main()
