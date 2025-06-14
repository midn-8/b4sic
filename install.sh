#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

echo "Installing b4sic CTF Recon Tool..."

# Define installation path (common choice for local scripts)
INSTALL_PATH="/usr/local/bin"
SCRIPT_NAME="b4sic"
SCRIPT_SOURCE="./b4sic.py" # Assuming install.sh is in the same dir as b4sic.py

# Check if script exists
if [ ! -f "$SCRIPT_SOURCE" ]; then
    echo "Error: b4sic.py not found in the current directory."
    echo "Please run this script from the directory containing b4sic.py."
    exit 1
fi

echo "Copying $SCRIPT_SOURCE to $INSTALL_PATH/$SCRIPT_NAME..."
sudo cp "$SCRIPT_SOURCE" "$INSTALL_PATH/$SCRIPT_NAME"

echo "Making $INSTALL_PATH/$SCRIPT_NAME executable..."
sudo chmod +x "$INSTALL_PATH/$SCRIPT_NAME"

echo "Checking for required external tools..."
REQUIRED_TOOLS=("file" "strings" "exiftool" "binwalk" "md5sum" "sha256sum")
MISSING_TOOLS=()

for tool in "${REQUIRED_TOOLS[@]}"; do
    if ! command -v "$tool" &> /dev/null; then
        MISSING_TOOLS+=("$tool")
    fi
done

if [ ${#MISSING_TOOLS[@]} -gt 0 ]; then
    echo "WARNING: The following external tools are highly recommended but not found:"
    for tool in "${MISSING_TOOLS[@]}"; do
        echo "  - $tool"
    done
    echo "Please install them using your system's package manager (e.g., 'sudo apt install <tool_name>')."
    echo "  Common packages: binutils (for strings), exiftool, binwalk, coreutils (for md5sum/sha256sum)."
else
    echo "All recommended external tools found."
fi

echo "Installation complete! You can now run 'b4sic analyze <file>' or 'b4sic clean'."
