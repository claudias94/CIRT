"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Main Controller

Description
-----------
Coordinates the complete CIRT workflow:

    • Detect Operating System
    • Collect Live Evidence
    • Generate Reports
    • Package Evidence

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

import platform
import sys

from logger import logger

from reporting.generator import ReportGenerator

from packaging.package import package_evidence
from collectors.linux import collect_linux
from collectors.windows import collect_windows


# ==========================================================
# CIRT Controller
# ==========================================================

class CIRT:

    """
    Claus Incident Response Toolkit.
    """

    def __init__(self):

        logger.info("=" * 60)
        logger.info("Starting Claus Incident Response Toolkit")
        logger.info("=" * 60)

        self.operating_system = platform.system()

        logger.info(

            f"Detected Operating System: {self.operating_system}"

        )

        self.collector = None

        self.evidence = None


# ==========================================================
# Detect Collector
# ==========================================================

    def initialize_collector(self):

        """
        Select the correct evidence collector.
        """

        if self.operating_system == "Linux":

           logger.info("Initializing Linux Collector")

           self.collector = collect_linux

        elif self.operating_system == "Windows":

           logger.info("Initializing Windows Collector")

           self.collector = collect_windows

        else:

            logger.error(

                f"Unsupported operating system: {self.operating_system}"

            )

            sys.exit(1)
# ==========================================================
# Collect Evidence
# ==========================================================

    # ==========================================================
# Collect Evidence
# ==========================================================

    def collect_evidence(self):
        """
        Run the selected evidence collector.
        """

        logger.info("Starting evidence collection...")

        self.evidence = self.collector()

        if not self.evidence.get("success"):

            logger.error("Evidence collection failed.")

            sys.exit(1)

        logger.info("Evidence collection completed successfully.")


# ==========================================================
# Generate Reports
# ==========================================================

    def generate_reports(self):

        """
        Generate all report formats.
        """

        logger.info("Starting report generation...")

        generator = ReportGenerator(
            output_directory="reports"
        )

        reports = generator.generate(
            self.evidence
        )

        logger.info("Report generation completed.")

        return reports


# ==========================================================
# Package Evidence
# ==========================================================

    def package_evidence(self):

        """
        Create hashes, manifest, chain of custody,
        and ZIP archive.
        """

        logger.info("Starting evidence packaging...")

        package = package_evidence(
            evidence_directory="reports",
            case_number="CASE-001",
            investigator="Claudias Musavini",
        )

        logger.info("Evidence packaging completed.")

        return package
# ==========================================================
# Execute CIRT Workflow
# ==========================================================

    def run(self):
        """
        Execute the complete CIRT workflow.

        Returns
        -------
        bool
        """

        logger.info("=" * 60)
        logger.info("Starting Evidence Collection")
        logger.info("=" * 60)

        self.initialize_collector()

        # --------------------------------------------------
        # Collect Live Evidence
        # --------------------------------------------------

        self.evidence = self.collector()

        if not self.evidence.get("success", False):

            logger.error("Evidence collection failed.")

            return False

        logger.info("Evidence collection completed successfully.")

        # --------------------------------------------------
        # Generate Reports
        # --------------------------------------------------

        logger.info("=" * 60)
        logger.info("Generating Reports")
        logger.info("=" * 60)

        report_generator = ReportGenerator()

        reports = report_generator.generate(

            self.evidence

        )

        logger.info(

            f"Generated {len(reports)} report(s)."

        )

        # --------------------------------------------------
        # Package Evidence
        # --------------------------------------------------

        logger.info("=" * 60)
        logger.info("Packaging Evidence")
        logger.info("=" * 60)

        package_results = package_evidence()

        # --------------------------------------------------
        # Execution Summary
        # --------------------------------------------------

        print()

        print("=" * 60)
        print("CIRT EXECUTION SUMMARY")
        print("=" * 60)

        print(f"Operating System : {self.operating_system}")

        collector_name = self.evidence.get("collector", "Unknown")

        print(
            f"Collector        : {collector_name}"
        )

        print(
            f"Evidence         : {'SUCCESS' if self.evidence.get('success') else 'FAILED'}"
        )

        print(
            f"Reports          : {len(reports)} Generated"
        )

        print(
            f"Archive          : {package_results['archive']}"
        )

        print("=" * 60)

        logger.info("CIRT execution completed successfully.")

        return True
# ==========================================================
# Main Entry Point
# ==========================================================

if __name__ == "__main__":

    application = CIRT()

    success = application.run()

    if success:

        sys.exit(0)

    sys.exit(1)
