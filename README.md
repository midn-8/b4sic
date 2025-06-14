# b4sic: CTF File Reconnaissance Tool

`b4sic` is a command-line utility designed to perform rapid, initial reconnaissance on CTF (Capture The Flag) challenge files. It automates common file analysis tasks, extracts crucial information, and helps manage the generated output in a clean, isolated workspace, saving you time and reducing clutter.

## Features

* **Automated Basic File Information:** Gathers file type, size, MD5, and SHA256 hashes.
* **Comprehensive String Analysis:** Extracts printable strings with configurable minimum length.
    * Attempts automatic decoding of Base64, Hex, and URL-encoded strings found.
    * Searches for common CTF flag patterns.
    * Saves full string output to the workspace for deeper review.
* **Metadata Extraction (Exiftool):** Pulls embedded metadata from various file formats.
* **Embedded File Detection (Binwalk):** Scans for hidden files and partitions within the challenge file, providing clear guidance on how to extract them.
* **Image Dimension Analysis:** Extracts dimensions for PNG and JPEG images, offering hints for steganography challenges.
* **Dedicated Workspace Management:** Creates a unique temporary directory for each analysis run, containing all generated output and copies of analyzed files.
* **Safe Cleanup:** Provides a `clean` command to easily remove all `b4sic`-generated workspaces, ensuring your CTF directories remain tidy.

## Installation

1.  **Clone the repository (or download `b4sic.py`):**
    ```bash
    git clone [https://github.com/your_username/b4sic.git](https://github.com/your_username/b4sic.git) # Replace with your repo
    cd b4sic
    ```
    *(Or just `cd b4sic_project` if you haven't set up a remote repo yet)*

2.  **Set up a Python Virtual Environment (Recommended):**
    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    ```

3.  **Install Required External Tools:**
    `b4sic` relies on several common command-line tools. Install them using your system's package manager:

    ```bash
    sudo apt update
    sudo apt install file strings exiftool binwalk md5sum sha256sum vim-common # vim-common for xxd (though not directly used by b4sic right now, it's a good general CTF tool)
    ```
    *(Note: `strings` is part of `binutils`, `md5sum`/`sha256sum` are part of `coreutils`. On some systems, these might be installed with a larger package like `build-essential`.)*

4.  **Make `b4sic.py` executable:**
    ```bash
    chmod +x b4sic.py
    ```

## Usage

### Analyze a File

```bash
./b4sic.py analyze <file_path> [--strings-min-len <length>]
