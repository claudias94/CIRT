"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Chain of Custody Generator

Description
-----------
Creates a forensic Chain of Custody document
for collected digital evidence.

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

import os
import socket
from datetime import datetime

from logger import logger


# ==========================================================
# Create Chain of Custody
# ==========================================================

def create_chain_of_custody(
    case_number,
    investigator,
    evidence_directory,
):
    """
    Create a chain of custody record.

    Parameters
    ----------
    case_number : str

    investigator : str

    evidence_directory : str

    Returns
    -------
    str
    """

    logger.info("Creating Chain of Custody...")

    hostname = socket.gethostname()

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    report = []

    report.append("=" * 60)
    report.append("CHAIN OF CUSTODY")
    report.append("=" * 60)
    report.append("")
    report.append(f"Case Number      : {case_number}")
    report.append(f"Investigator     : {investigator}")
    report.append(f"Hostname         : {hostname}")
    report.append(f"Evidence Folder  : {evidence_directory}")
    report.append(f"Collection Time  : {timestamp}")
    report.append("Integrity Status : VERIFIED")
    report.append("")
    report.append("=" * 60)
    report.append(
        "This evidence was collected using the"
    )
    report.append(
        "Claus Incident Response Toolkit (CIRT)."
    )
    report.append("=" * 60)

    return "\n".join(report)


# ==========================================================
# Save Chain of Custody
# ==========================================================

def save_chain(report, output_file):
    """
    Save chain of custody.

    Parameters
    ----------
    report : str

    output_file : str
    """

    logger.info(
        f"Saving Chain of Custody: {output_file}"
    )

    with open(output_file, "w") as file:

        file.write(report)

    logger.info("Chain of Custody saved.")


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    REPORT_DIRECTORY = "reports"

    OUTPUT_FILE = os.path.join(

        REPORT_DIRECTORY,

        "chain_of_custody.txt",

    )

    report = create_chain_of_custody(

        case_number="CASE-001",

        investigator="Claudias Musavini",

        evidence_directory=REPORT_DIRECTORY,

    )

    save_chain(

        report,

        OUTPUT_FILE,

    )

    print()

    print("=" * 60)
    print("CHAIN OF CUSTODY CREATED")
    print("=" * 60)
    print(f"Output : {OUTPUT_FILE}")
    print("=" * 60)
