"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Report Generator

Coordinates all report exporters.

Supported Formats

- HTML
- JSON
- Markdown
- CSV

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

from pathlib import Path

from logger import logger

from reporting.html import generate_html_report
from reporting.json_export import generate_json_report
from reporting.markdown import generate_markdown_report
from reporting.csv_export import generate_csv_report


# ==========================================================
# Report Generator
# ==========================================================

class ReportGenerator:
    """
    Central report generation engine.
    """

    def __init__(
        self,
        output_directory="reports",
    ):

        self.output_directory = Path(
            output_directory,
        )

        self.output_directory.mkdir(
            parents=True,
            exist_ok=True,
        )

        logger.info("=" * 60)
        logger.info(
            "Report Generator Initialized"
        )
        logger.info(
            "Output Directory: %s",
            self.output_directory,
        )
        logger.info("=" * 60)

    # ==========================================================
    # Generate Reports
    # ==========================================================

    def generate(
        self,
        evidence,
    ):
        """
        Generate every supported report format.

        Parameters
        ----------
        evidence : dict
            Collected forensic evidence.

        Returns
        -------
        dict
            Dictionary containing generated report paths.
        """

        logger.info("=" * 60)
        logger.info("Starting report generation")
        logger.info("=" * 60)

        reports = {}

        # ------------------------------------------------------
        # HTML
        # ------------------------------------------------------

        reports["html"] = generate_html_report(
            evidence,
            self.output_directory,
        )

        # ------------------------------------------------------
        # JSON
        # ------------------------------------------------------

        reports["json"] = generate_json_report(
            evidence,
            self.output_directory,
        )

        # ------------------------------------------------------
        # Markdown
        # ------------------------------------------------------

        reports["markdown"] = generate_markdown_report(
            evidence,
            self.output_directory,
        )

        # ------------------------------------------------------
        # CSV
        # ------------------------------------------------------

        reports["csv"] = generate_csv_report(
            evidence,
            self.output_directory,
        )

        logger.info("=" * 60)
        logger.info("Report generation completed")
        logger.info("=" * 60)

        return reports

    # ==========================================================
    # List Generated Reports
    # ==========================================================

    def summary(
        self,
        reports,
    ):
        """
        Print a summary of generated reports.
        """

        print()

        print("=" * 60)
        print("REPORT GENERATION SUMMARY")
        print("=" * 60)

        for report_type, path in reports.items():

            print(
                f"{report_type.upper():10} : {path}"
            )

        print("=" * 60)

        logger.info(
            "Generated %d report(s).",
            len(reports),
        )

# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    sample_evidence = {

        "success": True,

        "collector": "Linux",

        "system_information": {

            "hostname": "cirt-lab",

            "operating_system": "Ubuntu Linux",

            "kernel": "6.8.0",

            "architecture": "x86_64",

            "current_user": "claus",

            "timestamp": "2026-07-18 12:00:00",

        },

        "logged_in_users": [

            "claus",

        ],

        "uptime": "2 days 5 hours",

        "running_processes": [

            "systemd",

            "python",

            "sshd",

        ],

        "listening_ports": [

            "22/tcp",

            "80/tcp",

            "443/tcp",

        ],

        "network_connections": [

            "TCP 127.0.0.1:22",

        ],

        "running_services": [

            "ssh.service",

            "NetworkManager.service",

        ],

        "disk_usage": [

            "/dev/sda1 35%",

        ],

        "memory_usage": [

            "RAM 6GB / 16GB",

        ],

        "mounted_filesystems": [

            "/",

            "/boot",

        ],

        "network_interfaces": [

            "eth0",

            "lo",

        ],

        "routing_table": [

            "default via 192.168.1.1",

        ],

    }

    generator = ReportGenerator()

    reports = generator.generate(
        sample_evidence,
    )

    generator.summary(
        reports,
    )
