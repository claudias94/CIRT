"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Evidence ZIP Archive Generator

Description
-----------
Creates a ZIP archive containing all evidence files.

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

import os
import zipfile

from logger import logger


# ==========================================================
# Create ZIP Archive
# ==========================================================

def create_zip_archive(source_directory, output_zip):
    """
    Create a ZIP archive from an evidence directory.

    Parameters
    ----------
    source_directory : str

    output_zip : str

    Returns
    -------
    str
    """

    logger.info("Creating ZIP archive...")

    with zipfile.ZipFile(

        output_zip,

        "w",

        compression=zipfile.ZIP_DEFLATED,

    ) as archive:

        for root, _, files in os.walk(source_directory):

            for filename in files:

                file_path = os.path.join(root, filename)

                if os.path.abspath(file_path) == os.path.abspath(output_zip):

                    continue

                archive_name = os.path.relpath(

                    file_path,

                    source_directory,

                )

                archive.write(

                    file_path,

                    archive_name,

                )

                logger.info(f"Added: {archive_name}")

    logger.info("ZIP archive completed.")

    return output_zip


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    REPORT_DIRECTORY = "reports"

    OUTPUT_ZIP = os.path.join(

        REPORT_DIRECTORY,

        "CASE-001.zip",

    )

    create_zip_archive(

        REPORT_DIRECTORY,

        OUTPUT_ZIP,

    )

    print()

    print("=" * 60)
    print("ZIP PACKAGE CREATED")
    print("=" * 60)
    print(f"Archive : {OUTPUT_ZIP}")
    print("=" * 60)
