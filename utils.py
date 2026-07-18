"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Utility Functions

Author : Claudias Musavini Misiko
Version: 1.0.0

Shared helper functions used throughout the toolkit.
=========================================================
"""

import hashlib
import json
import platform
import subprocess
from datetime import datetime
from pathlib import Path

from logger import logger


# =========================================================
# Operating System
# =========================================================

def get_os():
    """
    Return the current operating system.

    Returns:
        str
    """

    return platform.system()


# =========================================================
# Timestamp
# =========================================================

def current_timestamp():
    """
    Return current timestamp.

    Returns:
        str
    """

    return datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )


# =========================================================
# Directory Helper
# =========================================================

def ensure_directory(directory):
    """
    Create a directory if it does not exist.

    Args:
        directory (Path | str)
    """

    Path(directory).mkdir(
        parents=True,
        exist_ok=True,
    )


# =========================================================
# Command Execution
# =========================================================

def run_command(command):
    """
    Execute a shell command safely.

    Args:
        command (list)

    Returns:
        tuple
        (success, output)
    """

    try:

        result = subprocess.run(

            command,

            capture_output=True,

            text=True,

            check=True,

        )

        logger.info(
            "Executed command: %s",
            " ".join(command),
        )

        return True, result.stdout.strip()

    except subprocess.CalledProcessError as error:

        logger.error(
            "Command failed: %s",
            " ".join(command),
        )

        return False, error.stderr.strip()

    except Exception as error:

        logger.exception(error)

        return False, str(error)


# =========================================================
# JSON Helpers
# =========================================================

def load_json(file_path):
    """
    Read a JSON file.

    Returns:
        dict
    """

    with open(

        file_path,

        "r",

        encoding="utf-8",

    ) as file:

        return json.load(file)


def save_json(data, file_path):
    """
    Save JSON data.
    """

    with open(

        file_path,

        "w",

        encoding="utf-8",

    ) as file:

        json.dump(

            data,

            file,

            indent=4,

        )
# =========================================================
# File Hashing
# =========================================================

def calculate_hash(file_path, algorithm="sha256"):
    """
    Calculate the hash of a file.

    Args:
        file_path (str | Path)
        algorithm (str): md5, sha1 or sha256

    Returns:
        str
    """

    hash_algorithms = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha256": hashlib.sha256,
    }

    algorithm = algorithm.lower()

    if algorithm not in hash_algorithms:
        raise ValueError(
            f"Unsupported hash algorithm: {algorithm}"
        )

    hasher = hash_algorithms[algorithm]()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(4096)

            if not chunk:
                break

            hasher.update(chunk)

    return hasher.hexdigest()


# =========================================================
# File Helpers
# =========================================================

def file_exists(file_path):
    """
    Check whether a file exists.

    Returns:
        bool
    """

    return Path(file_path).exists()


def readable_size(size):
    """
    Convert bytes into a human-readable format.

    Returns:
        str
    """

    units = [

        "B",

        "KB",

        "MB",

        "GB",

        "TB",

    ]

    size = float(size)

    for unit in units:

        if size < 1024:

            return f"{size:.2f} {unit}"

        size /= 1024

    return f"{size:.2f} PB"


# =========================================================
# Banner
# =========================================================

def print_banner():
    """
    Print the CIRT banner.
    """

    print()

    print("=" * 60)

    print("Claus Incident Response Toolkit")

    print("Version 1.0.0")

    print(f"Operating System : {get_os()}")

    print("=" * 60)

    print()


# =========================================================
# Standalone Test
# =========================================================

if __name__ == "__main__":

    print_banner()

    print("Current OS:")
    print(get_os())

    print()

    print("Current Timestamp:")
    print(current_timestamp())

    print()

    print("Readable Size Example:")
    print(readable_size(15728640))

    print()

    print("Checking README.md:")

    if file_exists("README.md"):
        print("README.md found")
    else:
        print("README.md not found")

