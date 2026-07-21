BANNER = r"""
============================================================
   _____ ___ ____ _____
  / ____|_ _|  _ \_   _|
 | |     | || |_) || |
 | |     | ||  _ < | |
 | |_____| || |_) || |_
  \_____|___|____/_____|

 Claus Incident Response Toolkit
 Version 1.0.0
============================================================
"""
"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Main Controller

Coordinates the complete workflow:

    • Detect Operating System
    • Collect Live Evidence
    • Run IOC Analysis
    • Generate Reports
    • Package Evidence

Author : Claudias Musavini Misiko
Version: 2.0.0
=========================================================
"""

import platform
import sys

from logger import logger

from reporting.generator import ReportGenerator

from packaging.package import package_evidence

from collectors.linux import collect_linux
from collectors.windows import collect_windows

from ioc.scanner import IOCScanner


# ==========================================================
# CIRT Controller
# ==========================================================

class CIRT:

    def __init__(self):
        print(BANNER)
        logger.info("=" * 60)
        logger.info("Starting Claus Incident Response Toolkit")
        logger.info("=" * 60)

        self.operating_system = platform.system()

        logger.info(
            f"Detected Operating System: {self.operating_system}"
        )

        self.collector = None
        self.evidence = {}
        self.reports = {}
        self.package = {}
# ==========================================================
# Collector Selection
# ==========================================================

    def initialize_collector(self):
        """
        Select the appropriate evidence collector.
        """

        if self.operating_system == "Linux":

            logger.info("Initializing Linux Collector")

            self.collector = collect_linux

        elif self.operating_system == "Windows":

            logger.info("Initializing Windows Collector")

            self.collector = collect_windows

        else:

            logger.error(
                f"Unsupported Operating System: {self.operating_system}"
            )

            sys.exit(1)
# ==========================================================
# Evidence Collection
# ==========================================================

    def collect_evidence(self):
        """
        Collect live evidence from the target operating system.
        """

        logger.info("=" * 60)
        logger.info("Starting Evidence Collection")
        logger.info("=" * 60)

        self.initialize_collector()

        self.evidence = self.collector()

        if not self.evidence.get("success", False):

            logger.error("Evidence collection failed.")

            sys.exit(1)

        logger.info("Evidence collection completed successfully.")

        return self.evidence


# ==========================================================
# IOC Analysis
# ==========================================================

    def analyze_iocs(self):
        """
        Run IOC detection against collected evidence.
        """

        logger.info("=" * 60)
        logger.info("Starting IOC Analysis")
        logger.info("=" * 60)

        scanner = IOCScanner()

        ioc_results = scanner.analyze(    self.evidence,    self.operating_system)

        self.evidence["ioc_analysis"] = ioc_results

        logger.info("IOC Analysis completed successfully.")

        return ioc_results
# ==========================================================
# Report Generation
# ==========================================================

    def generate_reports(self):
        """
        Generate all report formats.
        """

        logger.info("=" * 60)
        logger.info("Generating Reports")
        logger.info("=" * 60)

        generator = ReportGenerator(
            output_directory="reports"
        )

        self.reports = generator.generate(
            self.evidence
        )

        logger.info("Report generation completed.")

        return self.reports


# ==========================================================
# Evidence Packaging
# ==========================================================

    def package_evidence(self):
        """
        Package the investigation into a forensic archive.
        """

        logger.info("=" * 60)
        logger.info("Packaging Evidence")
        logger.info("=" * 60)

        self.package = package_evidence(
             evidence_directory="reports",
             case_number="CASE-001",
             investigator="Claudias Musavini",
)

        logger.info("Evidence packaging completed.")

        return self.package

# ==========================================================
# Execute Complete Workflow
# ==========================================================

    def run(self):
        """
        Execute the complete CIRT workflow.
        """

        # Step 1 - Collect Evidence
        self.collect_evidence()

        # Step 2 - Analyze IOCs
        self.analyze_iocs()

        # Step 3 - Generate Reports
        self.generate_reports()

        # Step 4 - Package Evidence
        self.package_evidence()

        # --------------------------------------------------
        # Execution Summary
        # --------------------------------------------------

        print()
        print("=" * 60)
        print("CIRT EXECUTION SUMMARY")
        print("=" * 60)

        print(f"Operating System : {self.operating_system}")
        print(f"Collector        : {self.evidence.get('collector', 'Unknown')}")
        print(f"Evidence         : {'SUCCESS' if self.evidence.get('success') else 'FAILED'}")
        print(f"IOC Analysis     : Completed")
        print(f"Reports          : {len(self.reports)} Generated")
        print(f"Archive          : {self.package['archive']}")

        print("=" * 60)

        logger.info("CIRT execution completed successfully.")

        return True


# ==========================================================
# Main Entry Point
# ==========================================================

if __name__ == "__main__":

    application = CIRT()

    success = application.run()

    sys.exit(0 if success else 1)
