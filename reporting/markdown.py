"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Markdown Report Exporter

Creates a professional Markdown incident response report.

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

from pathlib import Path
from datetime import datetime

from logger import logger


# ==========================================================
# Markdown Helpers
# ==========================================================

def markdown_header():
    """
    Create the report header.
    """

    timestamp = datetime.now().strftime(
        "%Y-%m-%d %H:%M:%S"
    )

    return f"""# 🛡 Claus Incident Response Toolkit

## Incident Response Report

**Generated:** {timestamp}

---

"""


# ==========================================================

def markdown_dictionary(title, dictionary):
    """
    Convert a dictionary into Markdown.
    """

    text = f"## {title}\n\n"

    if not dictionary:

        text += "_No data collected._\n\n"

        return text

    for key, value in dictionary.items():

        text += f"- **{key}:** {value}\n"

    text += "\n"

    return text


# ==========================================================

def markdown_list(title, items):
    """
    Convert a list into Markdown.
    """

    text = f"## {title}\n\n"

    if not items:

        text += "_No data collected._\n\n"

        return text

    for item in items:

        text += f"- {item}\n"

    text += "\n"

    return text


# ==========================================================

def markdown_code(title, data):
    """
    Display command output inside Markdown code blocks.
    """

    text = f"## {title}\n\n"

    text += "```\n"

    if isinstance(data, list):

        text += "\n".join(
            str(line)
            for line in data
        )

    else:

        text += str(data)

    text += "\n```\n\n"

    return text

# ==========================================================
# Generate Markdown Report
# ==========================================================

def generate_markdown_report(
    evidence,
    output_directory,
):
    """
    Generate a Markdown incident response report.

    Parameters
    ----------
    evidence : dict
        Collected forensic evidence.

    output_directory : str | Path
        Directory where the report will be saved.

    Returns
    -------
    pathlib.Path
        Path to the generated report.
    """

    logger.info("Generating Markdown report...")

    output_directory = Path(output_directory)

    output_directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    report_file = output_directory / "report.md"

    report = markdown_header()

    # ------------------------------------------------------

    if "system_information" in evidence:

        report += markdown_dictionary(
            "System Information",
            evidence["system_information"],
        )

    # ------------------------------------------------------

    if "logged_in_users" in evidence:

        report += markdown_list(
            "Logged-in Users",
            evidence["logged_in_users"],
        )

    # ------------------------------------------------------

    if "uptime" in evidence:

        report += markdown_code(
            "System Uptime",
            evidence["uptime"],
        )

    # ------------------------------------------------------

    if "running_processes" in evidence:

        report += markdown_code(
            "Running Processes",
            evidence["running_processes"],
        )

    # ------------------------------------------------------

    if "listening_ports" in evidence:

        report += markdown_code(
            "Listening Ports",
            evidence["listening_ports"],
        )

    # ------------------------------------------------------

    if "network_connections" in evidence:

        report += markdown_code(
            "Network Connections",
            evidence["network_connections"],
        )

    # ------------------------------------------------------

    if "running_services" in evidence:

        report += markdown_code(
            "Running Services",
            evidence["running_services"],
        )

    # ------------------------------------------------------

    if "disk_usage" in evidence:

        report += markdown_code(
            "Disk Usage",
            evidence["disk_usage"],
        )

    # ------------------------------------------------------

    if "memory_usage" in evidence:

        report += markdown_code(
            "Memory Usage",
            evidence["memory_usage"],
        )

    # ------------------------------------------------------

    if "mounted_filesystems" in evidence:

        report += markdown_code(
            "Mounted File Systems",
            evidence["mounted_filesystems"],
        )

    # ------------------------------------------------------

    if "network_interfaces" in evidence:

        report += markdown_code(
            "Network Interfaces",
            evidence["network_interfaces"],
        )

    # ------------------------------------------------------

    if "routing_table" in evidence:

        report += markdown_code(
            "Routing Table",
            evidence["routing_table"],
        )

    with open(
        report_file,
        "w",
        encoding="utf-8",
    ) as file:

        file.write(report)

    logger.info(
        "Markdown report written to %s",
        report_file,
    )

    return report_file


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    sample = {

        "system_information": {

            "hostname": "cirt-lab",

            "operating_system": "Ubuntu Linux",

            "current_user": "claus",

        },

        "logged_in_users": [

            "claus",

        ],

        "uptime": "2 days 4 hours",

        "running_processes": [

            "systemd",

            "python",

            "sshd",

        ],

        "disk_usage": [

            "/dev/sda1 35%",

        ],

    }

    report = generate_markdown_report(

        sample,

        "reports",

    )

    print()

    print("=" * 60)

    print("MARKDOWN REPORT CREATED")

    print("=" * 60)

    print(report)

    print("=" * 60)
