"""
============================================================
Claus Incident Response Toolkit (CIRT)

Suspicious Port Detection Engine

Author : Claudias Musavini Misiko
Version: 1.0.0

Analyzes listening ports and active network connections
collected from Linux and Windows systems.

============================================================
"""

import re

from logger import logger

from ioc.indicators import (
    SUSPICIOUS_PORTS,
    IOC_RISK_SCORES,
)


# ==========================================================
# Suspicious Port Detector
# ==========================================================

class SuspiciousPortDetector:
    """
    Detect suspicious listening ports and network connections.
    """

    def __init__(self):

        logger.info("=" * 60)
        logger.info("Initializing Suspicious Port Detector")
        logger.info("=" * 60)

        self.findings = []

        self.total_scanned = 0

        self.total_matches = 0


# ==========================================================
# Determine Severity
# ==========================================================

    def determine_severity(
        self,
        port,
    ):
        """
        Determine severity based on the detected port.
        """

        critical_ports = {

            31337,

            27374,

            12345,

        }

        high_ports = {

            4444,

            5555,

            6667,

            9001,

        }

        medium_ports = {

            8080,

            1080,

            1337,

        }

        if port in critical_ports:

            return "critical"

        if port in high_ports:

            return "high"

        if port in medium_ports:

            return "medium"

        return "low"


# ==========================================================
# Create IOC Finding
# ==========================================================

    def create_finding(
        self,
        port,
        severity,
        reason,
    ):
        """
        Create a standardized IOC finding.
        """

        return {

            "port": port,

            "severity": severity,

            "score": IOC_RISK_SCORES[severity],

            "reason": reason,

        }


# ==========================================================
# Extract Port Number
# ==========================================================

    def extract_port(
        self,
        line,
    ):
        """
        Extract a TCP/UDP port number from a connection line.

        Supports:

        Linux:
            0.0.0.0:22

        Windows:
            192.168.1.10:445

        IPv6:
            [::]:443
        """

        matches = re.findall(

            r":(\d{1,5})",

            line,

        )

        if not matches:

            return None

        try:

            return int(matches[-1])

        except ValueError:

            return None

# ==========================================================
# Scan Port Data
# ==========================================================

    def scan_ports(
        self,
        port_output,
    ):
        """
        Scan listening ports and active network connections.
        """

        logger.info("Scanning network ports...")

        self.findings = []

        self.total_scanned = 0

        self.total_matches = 0

        if not port_output:

            logger.warning("No port information supplied.")

            return []

        for line in port_output.splitlines():

            line = line.strip()

            if not line:

                continue

            self.total_scanned += 1

            self.scan_line(line)

        logger.info(
            "Scanned %d network entries.",
            self.total_scanned,
        )

        logger.info(
            "Detected %d suspicious ports.",
            self.total_matches,
        )

        return self.findings


# ==========================================================
# Scan Single Line
# ==========================================================

    def scan_line(
        self,
        line,
    ):
        """
        Analyze one network connection line.
        """

        port = self.extract_port(line)

        if port is None:

            return

        if port not in SUSPICIOUS_PORTS:

            return

        severity = self.determine_severity(port)

        reason = SUSPICIOUS_PORTS.get(
            port,
            "Suspicious network port detected."
        )

        finding = self.create_finding(

            port=port,

            severity=severity,

            reason=reason,

        )

        self.findings.append(finding)

        self.total_matches += 1

        logger.warning(

            "IOC Port Match: %d (%s)",

            port,

            severity.upper(),

        )
# ==========================================================
# Detect High-Risk Dynamic Ports
# ==========================================================

    def detect_high_ports(
        self,
        port_output,
    ):
        """
        Detect unusual high-numbered listening ports that are
        not already present in the IOC database.
        """

        logger.info("Checking for unusual high-numbered ports...")

        if not port_output:

            return

        for line in port_output.splitlines():

            port = self.extract_port(line)

            if port is None:

                continue

            if port in SUSPICIOUS_PORTS:

                continue

            if port >= 49152:

                finding = self.create_finding(

                    port=port,

                    severity="low",

                    reason=(
                        "High-numbered listening port detected. "
                        "Review if unexpected."
                    ),

                )

                self.findings.append(finding)

                self.total_matches += 1

                logger.info(

                    "High-numbered port detected: %d",

                    port,

                )


# ==========================================================
# Detect Multiple Suspicious Ports
# ==========================================================

    def detect_multiple_suspicious_ports(self):
        """
        Raise the severity if numerous suspicious ports are
        detected simultaneously.
        """

        if self.total_matches < 3:

            return

        finding = {

            "port": "MULTIPLE",

            "severity": "high",

            "score": IOC_RISK_SCORES["high"],

            "reason": (
                "Multiple suspicious listening ports detected "
                "on the same system."
            ),

        }

        self.findings.append(finding)

        logger.warning(

            "Multiple suspicious ports detected."

        )


# ==========================================================
# Summary
# ==========================================================

    def summary(self):
        """
        Return the port scan summary.
        """

        return {

            "success": True,

            "total_scanned": self.total_scanned,

            "total_findings": len(self.findings),

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
        Analyze collected evidence for suspicious ports.

        Parameters
        ----------
        evidence : dict

        Returns
        -------
        dict
        """

        logger.info("=" * 60)
        logger.info("Starting suspicious port analysis")
        logger.info("=" * 60)

        port_data = ""

        if "listening_ports" in evidence:

            port_data += evidence["listening_ports"]

            port_data += "\n"

        if "network_connections" in evidence:

            port_data += evidence["network_connections"]

            port_data += "\n"

        self.scan_ports(port_data)

        logger.info("=" * 60)
        logger.info("Suspicious port analysis completed")
        logger.info("=" * 60)

        return self.summary()


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    logger.info("=" * 60)
    logger.info("Standalone Suspicious Port Detector")
    logger.info("=" * 60)

    sample_ports = """
tcp LISTEN 0 128 0.0.0.0:22
tcp LISTEN 0 128 0.0.0.0:80
tcp LISTEN 0 128 0.0.0.0:443
tcp LISTEN 0 128 0.0.0.0:4444
tcp LISTEN 0 128 0.0.0.0:5555
tcp LISTEN 0 128 0.0.0.0:6667
tcp LISTEN 0 128 0.0.0.0:8080
tcp LISTEN 0 128 0.0.0.0:31337
"""

    detector = SuspiciousPortDetector()

    results = detector.analyze(

        {

            "listening_ports": sample_ports,

            "network_connections": ""

        }

    )

    print()

    print("=" * 60)
    print("SUSPICIOUS PORT DETECTOR")
    print("=" * 60)

    print(f"Ports Scanned : {results['total_scanned']}")
    print(f"IOC Findings  : {results['total_findings']}")

    print()

    if results["findings"]:

        print("Detected Suspicious Ports")

        print()

        for finding in results["findings"]:

            print(

                f"[{finding['severity'].upper():12}] "

                f"Port {finding['port']} "

                f"(Score {finding['score']})"

            )

            print(

                f"Reason : {finding['reason']}"

            )

            print()

    else:

        print("No suspicious ports detected.")

    print("=" * 60)

    logger.info("Standalone detector completed.")
    logger.info("=" * 60)
