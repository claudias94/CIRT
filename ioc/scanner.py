"""
============================================================
Claus Incident Response Toolkit (CIRT)

IOC Scanner

Author : Claudias Musavini Misiko
Version: 1.0.0

Runs every IOC detection engine and produces a single
threat assessment.

============================================================
"""

from logger import logger

from ioc.suspicious_processes import SuspiciousProcessDetector
from ioc.suspicious_ports import SuspiciousPortDetector
from ioc.suspicious_ips import SuspiciousIPDetector
from ioc.persistence import PersistenceDetector


class IOCScanner:
    """
    Central IOC scanning engine.

    Executes every IOC detector and combines their
    findings into one report.
    """

    def __init__(self):

        logger.info("=" * 60)
        logger.info("Initializing IOC Scanner")
        logger.info("=" * 60)

        self.process_detector = SuspiciousProcessDetector()

        self.port_detector = SuspiciousPortDetector()

        self.ip_detector = SuspiciousIPDetector()

        self.persistence_detector = PersistenceDetector()


    # ======================================================
    # Severity Calculation
    # ======================================================

    def calculate_severity(
        self,
        score,
    ):

        if score >= 250:

            return "CRITICAL"

        if score >= 150:

            return "HIGH"

        if score >= 75:

            return "MEDIUM"

        if score >= 25:

            return "LOW"

        return "INFORMATIONAL"


    # ======================================================
    # Run Scan
    # ======================================================

    def analyze(
        self,
        evidence,
        operating_system,
    ):

        logger.info("=" * 60)
        logger.info("Starting IOC Scan")
        logger.info("=" * 60)

        process_results = self.process_detector.analyze(
            evidence
        )

        port_results = self.port_detector.analyze(
            evidence
        )

        ip_results = self.ip_detector.analyze(
            evidence
        )

        persistence_results = self.persistence_detector.analyze(
            evidence,
            operating_system,
        )

        findings = []

        findings.extend(process_results["findings"])

        findings.extend(port_results["findings"])

        findings.extend(ip_results["findings"])

        findings.extend(persistence_results["findings"])

        overall_score = sum(

            finding["score"]

            for finding in findings

        )

        severity = self.calculate_severity(

            overall_score

        )

        logger.info("=" * 60)
        logger.info("IOC Scan Completed")
        logger.info("=" * 60)

        return {

            "success": True,

            "operating_system": operating_system,

            "overall_score": overall_score,

            "severity": severity,

            "total_findings": len(findings),

            "findings": findings,

            "modules": {

                "processes": process_results,

                "ports": port_results,

                "ips": ip_results,

                "persistence": persistence_results,

            },

        }


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    logger.info("=" * 60)
    logger.info("Standalone IOC Scanner")
    logger.info("=" * 60)

    sample_evidence = {

        "running_processes": """
powershell.exe
cmd.exe
netcat
mimikatz
""",

        "listening_ports": """
tcp LISTEN 0 128 0.0.0.0:4444
tcp LISTEN 0 128 0.0.0.0:31337
""",

        "network_connections": """
tcp ESTAB 192.168.1.10:50000 185.220.101.15:443
tcp ESTAB 192.168.1.10:50001 45.95.147.236:8080
""",

        "running_services": """
cron.service
systemd.service
""",

        "logged_in_users": """
root
ssh user
""",

        "environment_variables": """
LD_PRELOAD=/tmp/malicious.so
""",

        "scheduled_tasks": ""

    }

    scanner = IOCScanner()

    results = scanner.analyze(

        sample_evidence,

        "Linux",

    )

    print()

    print("=" * 60)
    print("IOC SCANNER SUMMARY")
    print("=" * 60)

    print(f"Operating System : {results['operating_system']}")

    print(f"Severity         : {results['severity']}")

    print(f"Threat Score     : {results['overall_score']}")

    print(f"IOC Findings     : {results['total_findings']}")

    print()

    if results["findings"]:

        print("Detected Indicators")

        print()

        for finding in results["findings"]:

            if "type" in finding:

                name = finding["type"]

            elif "process" in finding:

                name = finding["process"]

            elif "port" in finding:

                name = finding["port"]

            elif "ip" in finding:

                name = finding["ip"]

            else:

                name = "Unknown"

            print(

                f"[{finding['severity']}] "

                f"{name}"

            )

            print(

                f"Score : {finding['score']}"

            )

            print(

                f"Reason: {finding['reason']}"

            )

            print()

    else:

        print("No Indicators of Compromise detected.")

    print("=" * 60)

    logger.info("Standalone IOC Scanner completed.")
    logger.info("=" * 60)
