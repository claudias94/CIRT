"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Evidence Hashing Module

Description
-----------
Generates SHA-256 hashes for forensic evidence files.

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

import hashlib
import os

from logger import logger


# ==========================================================
# Calculate SHA-256 Hash
# ==========================================================

def calculate_sha256(file_path):
    """
    Calculate the SHA-256 hash of a file.

    Parameters
    ----------
    file_path : str
        Path to the file.

    Returns
    -------
    str
        SHA-256 hash.
    """

    logger.info(f"Hashing file: {file_path}")

    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:

        while True:

            chunk = file.read(4096)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# ==========================================================
# Hash Multiple Files
# ==========================================================

def hash_directory(directory):
    """
    Generate SHA-256 hashes for every file in a directory.

    Parameters
    ----------
    directory : str

    Returns
    -------
    dict
    """

    logger.info(f"Hashing directory: {directory}")

    hashes = {}

    for root, _, files in os.walk(directory):

        for filename in files:

            path = os.path.join(root, filename)

            hashes[path] = calculate_sha256(path)

    return hashes


# ==========================================================
# Save Hash Report
# ==========================================================

def save_hash_report(hashes, output_file):
    """
    Save hashes to a text file.

    Parameters
    ----------
    hashes : dict

    output_file : str
    """

    logger.info(f"Writing hash report: {output_file}")

    with open(output_file, "w") as report:

        report.write("=" * 60 + "\n")
        report.write("SHA256 HASH REPORT\n")
        report.write("=" * 60 + "\n\n")

        for filename, digest in hashes.items():

            report.write(f"{filename}\n")
            report.write(f"{digest}\n")
            report.write("\n")

    logger.info("Hash report completed.")


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    REPORT_DIRECTORY = "reports"

    HASH_REPORT = os.path.join(

        REPORT_DIRECTORY,

        "hashes.txt",

    )

    if not os.path.exists(REPORT_DIRECTORY):

        print("Reports directory not found.")

    else:

        hashes = hash_directory(REPORT_DIRECTORY)

        save_hash_report(

            hashes,

            HASH_REPORT,

        )

        print()

        print("=" * 60)
        print("HASHING SUMMARY")
        print("=" * 60)

        print(f"Files Hashed : {len(hashes)}")

        print(f"Output File  : {HASH_REPORT}")

        print("=" * 60)
