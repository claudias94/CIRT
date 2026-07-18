"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Evidence Manifest Generator

Description
-----------
Creates a forensic manifest containing metadata for every
evidence file collected during an investigation.

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

import json
import os
from datetime import datetime

from logger import logger
from packaging.hashing import calculate_sha256


# ==========================================================
# Generate Manifest
# ==========================================================

def generate_manifest(directory):
    """
    Generate a manifest for every file inside a directory.

    Parameters
    ----------
    directory : str

    Returns
    -------
    dict
    """

    logger.info(f"Generating manifest for: {directory}")

    manifest = {

        "generated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "directory": directory,

        "file_count": 0,

        "files": []

    }

    for root, _, files in os.walk(directory):

        for filename in files:

            path = os.path.join(root, filename)

            if os.path.isdir(path):

                continue

            entry = {

                "name": filename,

                "path": path,

                "size_bytes": os.path.getsize(path),

                "sha256": calculate_sha256(path)

            }

            manifest["files"].append(entry)

    manifest["file_count"] = len(manifest["files"])

    logger.info(
        f"Manifest contains {manifest['file_count']} files."
    )

    return manifest


# ==========================================================
# Save Manifest
# ==========================================================

def save_manifest(manifest, output_file):
    """
    Save manifest as JSON.

    Parameters
    ----------
    manifest : dict

    output_file : str
    """

    logger.info(f"Saving manifest: {output_file}")

    with open(output_file, "w") as file:

        json.dump(

            manifest,

            file,

            indent=4,

        )

    logger.info("Manifest saved successfully.")


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    REPORT_DIRECTORY = "reports"

    OUTPUT_FILE = os.path.join(

        REPORT_DIRECTORY,

        "manifest.json",

    )

    if not os.path.exists(REPORT_DIRECTORY):

        print("Reports directory not found.")

    else:

        manifest = generate_manifest(

            REPORT_DIRECTORY

        )

        save_manifest(

            manifest,

            OUTPUT_FILE,

        )

        print()

        print("=" * 60)
        print("MANIFEST SUMMARY")
        print("=" * 60)

        print(f"Directory : {REPORT_DIRECTORY}")

        print(f"Files      : {manifest['file_count']}")

        print(f"Output     : {OUTPUT_FILE}")

        print("=" * 60)
