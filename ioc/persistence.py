"""
============================================================
Claus Incident Response Toolkit (CIRT)

Persistence Detection Engine

Author : Claudias Musavini Misiko
Version: 1.0.0

Detects common persistence mechanisms used by attackers
on Linux and Windows systems.

============================================================
"""

from logger import logger
from ioc.helpers import normalize_text
from ioc.indicators import IOC_RISK_SCORES


# ==========================================================
# Persistence Detector
# ==========================================================

class PersistenceDetector:
    """
    Detect common persistence mechanisms.
    """

    def __init__(self):

        logger.info("=" * 60)
        logger.info("Initializing Persistence Detector")
        logger.info("=" * 60)

        self.findings = []

        self.total_checks = 0

        self.total_matches = 0


# ==========================================================
# Determine Severity
# ==========================================================

    def determine_severity(
        self,
        persistence_type,
    ):
        """
        Determine severity for a persistence mechanism.
        """

        critical = {

            "Registry Run Key",

            "Registry RunOnce",

            "Winlogon",

            "IFEO",

        }

        high = {

            "Cron Job",

            "Scheduled Task",

            "Systemd Service",

            "Startup Folder",

            "Windows Service",

            "SSH Authorized Keys",

        }

        medium = {

            ".bashrc",

            ".profile",

            "rc.local",

            "Environment Variable",

        }

        if persistence_type in critical:

            return "critical"

        if persistence_type in high:

            return "high"

        if persistence_type in medium:

            return "medium"

        return "low"


# ==========================================================
# Create IOC Finding
# ==========================================================

    def create_finding(
        self,
        persistence_type,
        severity,
        reason,
    ):
        """
        Create a standardized persistence finding.
        """

        return {

            "type": persistence_type,

            "severity": severity,

            "score": IOC_RISK_SCORES[severity],

            "reason": reason,

        }


# ==========================================================
# Record Finding
# ==========================================================

    def add_finding(
        self,
        persistence_type,
        reason,
    ):
        """
        Add a persistence finding.
        """

        severity = self.determine_severity(

            persistence_type

        )

        finding = self.create_finding(

            persistence_type=persistence_type,

            severity=severity,

            reason=reason,

        )

        self.findings.append(finding)

        self.total_matches += 1

        logger.warning(

            "Persistence detected: %s",

            persistence_type,

        )
# ==========================================================
# Linux Persistence Detection
# ==========================================================

    def check_linux_persistence(
        self,
        evidence,
    ):
        """
        Detect common Linux persistence mechanisms from
        collected evidence.
        """

        logger.info("Checking Linux persistence...")

        # --------------------------------------------------
        # Running Services
        # --------------------------------------------------

        services = normalize_text(
           evidence.get("running_services")
        )

        self.total_checks += 1

        suspicious_services = [

            "rc.local",

            "systemd",

            "init.d",

            "cron",

            "crond",

        ]

        for service in suspicious_services:

            if service.lower() in services.lower():

                self.add_finding(

                    "Systemd Service",

                    f"Persistence-related service detected: {service}",

                )

        # --------------------------------------------------
        # Logged-in Users / SSH
        # --------------------------------------------------

        users = normalize_text(
           evidence.get("logged_in_users")
         )

        self.total_checks += 1

        if "ssh" in users.lower():

            self.add_finding(

                "SSH Authorized Keys",

                "SSH session detected. Verify authorized_keys for persistence.",

            )

        # --------------------------------------------------
        # Running Processes
        # --------------------------------------------------

        processes = normalize_text(
           evidence.get("running_processes")
        )

        self.total_checks += 1

        suspicious_processes = [

            "cron",

            "crond",

            "systemd",

            "bash",

        ]

        for process in suspicious_processes:

            if process.lower() in processes.lower():

                self.add_finding(

                    "Cron Job",

                    f"Persistence-related process detected: {process}",

                )

        # --------------------------------------------------
        # Environment Variables
        # --------------------------------------------------

        environment = normalize_text(
            evidence.get("environment_variables")
        )

        self.total_checks += 1

        suspicious_environment = [

            "LD_PRELOAD",

            "LD_LIBRARY_PATH",

        ]

        for variable in suspicious_environment:

            if variable in environment:

                self.add_finding(

                    "Environment Variable",

                    f"Environment variable detected: {variable}",

                )

        logger.info("Linux persistence analysis completed.")
# ==========================================================
# Windows Persistence Detection
# ==========================================================

    def check_windows_persistence(
        self,
        evidence,
    ):
        """
        Detect common Windows persistence mechanisms from
        collected evidence.
        """

        logger.info("Checking Windows persistence...")

        # --------------------------------------------------
        # Scheduled Tasks
        # --------------------------------------------------

        scheduled_tasks = normalize_text(

            "scheduled_tasks",

            "",

        )

        self.total_checks += 1

        if scheduled_tasks:

            self.add_finding(

                "Scheduled Task",

                "Scheduled tasks detected. Review for persistence.",

            )

        # --------------------------------------------------
        # Running Services
        # --------------------------------------------------

        services = normalize_text(

            "running_services",

            "",
        )
        self.total_checks += 1

        suspicious_services = [

            "RemoteRegistry",

            "WinDefend",

            "Schedule",

        ]

        for service in suspicious_services:

            if service.lower() in services.lower():

                self.add_finding(

                    "Windows Service",

                    f"Service present: {service}",

                )

        # --------------------------------------------------
        # Running Processes
        # --------------------------------------------------

        processes = normalize_text(

            "running_processes",

            "",

        )

        self.total_checks += 1

        suspicious_processes = [

            "powershell",

            "cmd.exe",

            "reg.exe",

            "wmic",

            "schtasks",

        ]

        for process in suspicious_processes:

            if process.lower() in processes.lower():

                self.add_finding(

                    "Registry Run Key",

                    f"Persistence-related process detected: {process}",

                )

        logger.info("Windows persistence analysis completed.")


# ==========================================================
# Summary
# ==========================================================

    def summary(
        self,
    ):
        """
        Return persistence analysis summary.
        """

        return {

            "success": True,

            "total_checks": self.total_checks,

            "total_findings": len(self.findings),

            "findings": self.findings,

        }
# ==========================================================
# Analyze Evidence
# ==========================================================

    def analyze(
        self,
        evidence,
        operating_system,
    ):
        """
        Analyze collected evidence for persistence mechanisms.

        Parameters
        ----------
        evidence : dict
            Collected forensic evidence.

        operating_system : str
            Linux or Windows.

        Returns
        -------
        dict
        """

        logger.info("=" * 60)
        logger.info("Starting persistence analysis")
        logger.info("=" * 60)

        self.findings = []

        self.total_checks = 0

        self.total_matches = 0

        operating_system = operating_system.lower()

        if operating_system == "linux":

            self.check_linux_persistence(
                evidence
            )

        elif operating_system == "windows":

            self.check_windows_persistence(
                evidence
            )

        else:

            logger.warning(

                "Unsupported operating system: %s",

                operating_system,

            )

        logger.info("=" * 60)
        logger.info("Persistence analysis completed")
        logger.info("=" * 60)

        return self.summary()


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    logger.info("=" * 60)
    logger.info("Standalone Persistence Detector")
    logger.info("=" * 60)

    sample_evidence = {

        "running_services": """
cron.service
systemd-journald.service
RemoteRegistry
Schedule
""",

        "running_processes": """
cron
bash
powershell.exe
cmd.exe
schtasks.exe
""",

        "logged_in_users": """
root pts/0
ssh user@192.168.1.50
""",

        "environment_variables": """
PATH=/usr/bin
LD_PRELOAD=/tmp/malicious.so
""",

        "scheduled_tasks": """
Microsoft\\Windows\\Update
CustomTask
""",

    }

    detector = PersistenceDetector()

    results = detector.analyze(

        sample_evidence,

        "Linux",

    )

    print()

    print("=" * 60)
    print("PERSISTENCE DETECTOR")
    print("=" * 60)

    print(f"Checks Performed : {results['total_checks']}")
    print(f"IOC Findings     : {results['total_findings']}")

    print()

    if results["findings"]:

        print("Detected Persistence Mechanisms")

        print()

        for finding in results["findings"]:

            print(

                f"[{finding['severity'].upper():10}] "

                f"{finding['type']}"

            )

            print(

                f"Reason : {finding['reason']}"

            )

            print(

                f"Score  : {finding['score']}"

            )

            print()

    else:

        print("No persistence mechanisms detected.")

    print("=" * 60)

    logger.info("Standalone detector completed.")
    logger.info("=" * 60)
