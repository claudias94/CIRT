"""
============================================================
Claus Incident Response Toolkit (CIRT)

Suspicious IP Address Detection Engine

Author : Claudias Musavini Misiko
Version: 1.0.0

Detects suspicious and malicious IP addresses from
active network connections collected from Linux and
Windows systems.

============================================================
"""

import ipaddress
import re

from logger import logger
from ioc.helpers import normalize_text
from ioc.indicators import (
    MALICIOUS_IPS,
    IOC_RISK_SCORES,
)


# ==========================================================
# Suspicious IP Detector
# ==========================================================

class SuspiciousIPDetector:
    """
    Detect suspicious IP addresses found in collected
    network connections.
    """

    def __init__(self):

        logger.info("=" * 60)
        logger.info("Initializing Suspicious IP Detector")
        logger.info("=" * 60)

        self.findings = []

        self.total_scanned = 0

        self.total_matches = 0


# ==========================================================
# Determine Severity
# ==========================================================

    def determine_severity(
        self,
        ip_address,
    ):
        """
        Determine IOC severity.
        """

        if ip_address in MALICIOUS_IPS:

            return "critical"

        try:

            ip = ipaddress.ip_address(ip_address)

            if ip.is_multicast:

                return "medium"

            if ip.is_unspecified:

                return "medium"

            if ip.is_reserved:

                return "medium"

            return "low"

        except ValueError:

            return "low"


# ==========================================================
# Create Finding
# ==========================================================

    def create_finding(
        self,
        ip_address,
        severity,
        reason,
    ):
        """
        Create standardized IOC finding.
        """

        return {

            "ip": ip_address,

            "severity": severity,

            "score": IOC_RISK_SCORES[severity],

            "reason": reason,

        }


# ==========================================================
# Extract IP Address
# ==========================================================

    def extract_ips(
        self,
        line,
    ):
        """
        Extract IPv4 addresses from one connection line.
        """

        return re.findall(

            r"(?:\d{1,3}\.){3}\d{1,3}",

            line,

        )

# ==========================================================
# Scan Network Connections
# ==========================================================

    def scan_connections(
        self,
        connection_output,
    ):
        """
        Scan collected network connections for suspicious IPs.
        """

        logger.info("Scanning network connections...")

        self.findings = []

        self.total_scanned = 0

        self.total_matches = 0

        if not connection_output:

            logger.warning("No network connection data supplied.")

            return []

        for line in connection_output.splitlines():

            line = line.strip()

            if not line:

                continue

            self.total_scanned += 1

            self.scan_line(line)

        logger.info(

            "Scanned %d network connections.",

            self.total_scanned,

        )

        logger.info(

            "Detected %d suspicious IP addresses.",

            self.total_matches,

        )

        return self.findings


# ==========================================================
# Scan Single Connection
# ==========================================================

    def scan_line(
        self,
        line,
    ):
        """
        Analyze one network connection.
        """

        ip_addresses = self.extract_ips(line)

        if not ip_addresses:

            return

        for ip_address in ip_addresses:

            self.evaluate_ip(ip_address)


# ==========================================================
# Evaluate IP Address
# ==========================================================

    def evaluate_ip(
        self,
        ip_address,
    ):
        """
        Evaluate one IP address.
        """

        # ----------------------------------------------
        # Known Malicious IOC
        # ----------------------------------------------

        if ip_address in MALICIOUS_IPS:

            finding = self.create_finding(

                ip_address=ip_address,

                severity="critical",

                reason=MALICIOUS_IPS[ip_address],

            )

            self.findings.append(finding)

            self.total_matches += 1

            logger.warning(

                "Known malicious IP detected: %s",

                ip_address,

            )

            return

        try:

            ip = ipaddress.ip_address(ip_address)

        except ValueError:

            return
# ==========================================================
# Built-in IP Intelligence
# ==========================================================

        if ip.is_loopback:

            return

        if ip.is_private:

            return

        if ip.is_link_local:

            return

        if ip.is_multicast:

            finding = self.create_finding(

                ip_address=ip_address,

                severity="medium",

                reason="Multicast address detected.",

            )

            self.findings.append(finding)

            self.total_matches += 1

            return

        if ip.is_reserved:

            finding = self.create_finding(

                ip_address=ip_address,

                severity="medium",

                reason="Reserved IP address detected.",

            )

            self.findings.append(finding)

            self.total_matches += 1

            return

        if ip.is_unspecified:

            finding = self.create_finding(

                ip_address=ip_address,

                severity="medium",

                reason="Unspecified IP address detected.",

            )

            self.findings.append(finding)

            self.total_matches += 1

            return
# ==========================================================
# Detect Repeated Suspicious IPs
# ==========================================================

    def detect_repeated_ips(self):
        """
        Increase alerting when the same malicious IP appears
        multiple times.
        """

        ip_counter = {}

        for finding in self.findings:

            ip_address = finding["ip"]

            ip_counter[ip_address] = ip_counter.get(ip_address, 0) + 1

        for ip_address, count in ip_counter.items():

            if count >= 3:

                finding = self.create_finding(

                    ip_address=ip_address,

                    severity="high",

                    reason=(
                        f"IP address observed "
                        f"{count} times during analysis."
                    ),

                )

                self.findings.append(finding)

                logger.warning(

                    "Repeated suspicious IP detected: %s",

                    ip_address,

                )


# ==========================================================
# Detect Public Internet Connections
# ==========================================================

    def detect_public_ips(
        self,
        connection_output,
    ):
        """
        Detect outbound connections to public IP addresses.

        Public IPs are not automatically malicious but are
        useful for incident response investigations.
        """

        if not connection_output:

            return

        for line in connection_output.splitlines():

            ip_addresses = self.extract_ips(line)

            for ip_address in ip_addresses:

                try:

                    ip = ipaddress.ip_address(ip_address)

                except ValueError:

                    continue

                if (

                    not ip.is_private
                    and not ip.is_loopback
                    and not ip.is_link_local
                    and not ip.is_multicast
                    and not ip.is_reserved
                    and not ip.is_unspecified

                ):

                    finding = self.create_finding(

                        ip_address=ip_address,

                        severity="low",

                        reason=(
                            "Public IP communication "
                            "observed."
                        ),

                    )

                    self.findings.append(finding)


# ==========================================================
# Summary
# ==========================================================

    def summary(self):
        """
        Return IOC scan summary.
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
        Analyze collected evidence for suspicious IP addresses.

        Parameters
        ----------
        evidence : dict

        Returns
        -------
        dict
        """

        logger.info("=" * 60)
        logger.info("Starting suspicious IP analysis")
        logger.info("=" * 60)

        connection_data = normalize_text(
           evidence.get("network_connections")
        )
        self.scan_connections(connection_data)

        self.detect_public_ips(connection_data)

        self.detect_repeated_ips()

        logger.info("=" * 60)
        logger.info("Suspicious IP analysis completed")
        logger.info("=" * 60)

        return self.summary()


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    logger.info("=" * 60)
    logger.info("Standalone Suspicious IP Detector")
    logger.info("=" * 60)

    sample_connections = """
tcp ESTAB 192.168.1.15:52344 185.220.101.15:443
tcp ESTAB 192.168.1.15:52345 45.95.147.236:8080
tcp ESTAB 192.168.1.15:52346 8.8.8.8:53
tcp ESTAB 192.168.1.15:52347 103.27.202.85:4444
tcp ESTAB 192.168.1.15:52348 198.51.100.100:9001
tcp ESTAB 192.168.1.15:52349 185.220.101.15:443
tcp ESTAB 192.168.1.15:52350 185.220.101.15:443
"""

    detector = SuspiciousIPDetector()

    results = detector.analyze(

        {

            "network_connections": sample_connections

        }

    )

    print()

    print("=" * 60)
    print("SUSPICIOUS IP DETECTOR")
    print("=" * 60)

    print(f"Connections Scanned : {results['total_scanned']}")
    print(f"IOC Findings        : {results['total_findings']}")

    print()

    if results["findings"]:

        print("Detected Indicators")

        print()

        for finding in results["findings"]:

            print(

                f"[{finding['severity'].upper():12}] "

                f"{finding['ip']} "

                f"(Score {finding['score']})"

            )

            print(

                f"Reason : {finding['reason']}"

            )

            print()

    else:

        print("No suspicious IP addresses detected.")

    print("=" * 60)

    logger.info("Standalone detector completed.")
    logger.info("=" * 60)
