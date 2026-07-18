"""
=========================================================
Claus Incident Response Toolkit (CIRT)

CSV Report Exporter

Exports collected forensic evidence to CSV format.

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

import csv

from pathlib import Path

from logger import logger


# ==========================================================
# Flatten Dictionary
# ==========================================================

def flatten_dictionary(data, parent_key=""):
    """
    Flatten nested dictionaries into key/value pairs.

    Example

    system.hostname

    system.kernel

    etc.
    """

    items = []

    for key, value in data.items():

        new_key = (
            f"{parent_key}.{key}"
            if parent_key
            else key
        )

        if isinstance(value, dict):

            items.extend(

                flatten_dictionary(

                    value,

                    new_key,

                )

            )

        elif isinstance(value, list):

            items.append(

                (

                    new_key,

                    "\n".join(

                        str(v)

                        for v in value

                    ),

                )

            )

        else:

            items.append(

                (

                    new_key,

                    value,

                )

            )

    return items


# ==========================================================
# Build CSV Rows
# ==========================================================

def build_rows(evidence):
    """
    Convert evidence into CSV rows.
    """

    return flatten_dictionary(evidence)
# ==========================================================
# Generate CSV Report
# ==========================================================

def generate_csv_report(
    evidence,
    output_directory,
):
    """
    Generate a CSV incident response report.

    Parameters
    ----------
    evidence : dict
        Collected forensic evidence.

    output_directory : str | Path
        Output directory.

    Returns
    -------
    pathlib.Path
        Path to the generated CSV report.
    """

    logger.info("Generating CSV report...")

    output_directory = Path(output_directory)

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_file = output_directory / "report.csv"

    rows = build_rows(evidence)

    with open(
        report_file,
        "w",
        newline="",
        encoding="utf-8",
    ) as csv_file:

        writer = csv.writer(csv_file)

        writer.writerow(
            [
                "Artifact",
                "Value",
            ]
        )

        for artifact, value in rows:

            writer.writerow(
                [
                    artifact,
                    value,
                ]
            )

    logger.info(
        "CSV report written to %s",
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

    report = generate_csv_report(

        sample,

        "reports",

    )

    print()

    print("=" * 60)

    print("CSV REPORT CREATED")

    print("=" * 60)

    print(report)

    print("=" * 60)
