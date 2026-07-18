"""
=========================================================
Claus Incident Response Toolkit (CIRT)

JSON Report Exporter

Exports collected forensic evidence to JSON format.

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

import json

from pathlib import Path
from datetime import datetime

from logger import logger


# ==========================================================
# JSON Encoder
# ==========================================================

class EvidenceEncoder(json.JSONEncoder):
    """
    JSON encoder that converts unsupported Python objects
    into strings.
    """

    def default(self, obj):

        try:
            return super().default(obj)

        except TypeError:
            return str(obj)


# ==========================================================
# Metadata Builder
# ==========================================================

def build_metadata():

    """
    Build report metadata.
    """

    return {

        "application": "Claus Incident Response Toolkit",

        "version": "1.0.0",

        "generated_at": datetime.now().strftime(
            "%Y-%m-%d %H:%M:%S"
        ),

        "report_type": "Incident Response Report",

    }


# ==========================================================
# Prepare Evidence
# ==========================================================

def prepare_json_document(evidence):

    """
    Combine metadata with collected evidence.
    """

    document = {

        "metadata": build_metadata(),

        "evidence": evidence,

    }

    return document
# ==========================================================
# Generate JSON Report
# ==========================================================

def generate_json_report(
    evidence,
    output_directory,
):
    """
    Generate a JSON incident response report.

    Parameters
    ----------
    evidence : dict
        Collected forensic evidence.

    output_directory : str | Path
        Output directory.

    Returns
    -------
    pathlib.Path
        Path to the generated JSON report.
    """

    logger.info("Generating JSON report...")

    output_directory = Path(output_directory)
    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_file = output_directory / "report.json"

    document = prepare_json_document(
        evidence,
    )

    with open(
        report_file,
        "w",
        encoding="utf-8",
    ) as file:

        json.dump(
            document,
            file,
            indent=4,
            cls=EvidenceEncoder,
            ensure_ascii=False,
        )

    logger.info(
        "JSON report written to %s",
        report_file,
    )

    return report_file


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    sample = {

        "collector": "Linux",

        "success": True,

        "system_information": {

            "hostname": "cirt-lab",

            "operating_system": "Ubuntu",

            "kernel": "6.8.0",

            "current_user": "claus",

        },

        "logged_in_users": [

            "claus",

        ],

        "running_processes": [

            "systemd",

            "python",

            "sshd",

        ],

        "disk_usage": [

            "/dev/sda1 35%",

        ],

    }

    report = generate_json_report(

        sample,

        "reports",

    )

    print()

    print("=" * 60)

    print("JSON REPORT CREATED")

    print("=" * 60)

    print(report)

    print("=" * 60)
