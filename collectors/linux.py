"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Linux Evidence Collector

Author : Claudias Musavini Misiko
Version: 1.0.0

Collects forensic evidence from Linux systems.
=========================================================
"""
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import os
import socket
import platform

from utils import (
    current_timestamp,
    run_command,
)

from utils import current_timestamp, run_command
from logger import logger


# ==========================================================
# System Information
# ==========================================================

def collect_system_information():
    """
    Collect basic operating system information.
    """

    logger.info("Collecting system information...")

    return {

        "hostname": socket.gethostname(),

        "operating_system": platform.system(),

        "distribution": platform.platform(),

        "kernel": platform.release(),

        "architecture": platform.machine(),

        "processor": platform.processor(),

        "current_user": os.getenv("USER"),

        "timestamp": current_timestamp(),

    }
# ==========================================================
# Logged-in Users
# ==========================================================

def collect_logged_in_users():
    """
    Collect active user sessions.
    """

    logger.info("Collecting logged-in users...")

    success, output = run_command(["who"])

    if success:

        users = []

        for line in output.splitlines():

            if line.strip():

                users.append(line)

        return users

    return []


# ==========================================================
# System Uptime
# ==========================================================

def collect_uptime():
    """
    Collect system uptime.
    """

    logger.info("Collecting uptime...")

    success, output = run_command(["uptime"])

    if success:

        return output

    return "Unavailable"
# ==========================================================
# Running Processes
# ==========================================================

def collect_running_processes():
    """
    Collect currently running processes.
    """

    logger.info("Collecting running processes...")

    success, output = run_command(

        [
            "ps",
            "-eo",
            "pid,user,%cpu,%mem,comm"
        ]

    )

    if success:

        return output.splitlines()

    return []


# ==========================================================
# Listening Network Ports
# ==========================================================

def collect_listening_ports():
    """
    Collect listening TCP and UDP ports.
    """

    logger.info("Collecting listening ports...")

    success, output = run_command(

        [
            "ss",
            "-tuln"
        ]

    )

    if success:

        return output.splitlines()

    return []


# ==========================================================
# Active Network Connections
# ==========================================================

def collect_network_connections():
    """
    Collect established network connections.
    """

    logger.info("Collecting network connections...")

    success, output = run_command(

        [
            "ss",
            "-tunap"
        ]

    )

    if success:

        return output.splitlines()

    return []


# ==========================================================
# Running Services
# ==========================================================

def collect_running_services():
    """
    Collect running systemd services.
    """

    logger.info("Collecting running services...")

    success, output = run_command(

        [
            "systemctl",
            "list-units",
            "--type=service",
            "--state=running"
        ]

    )

    if success:

        return output.splitlines()

    return []
# ==========================================================
# Disk Usage
# ==========================================================

def collect_disk_usage():
    """
    Collect filesystem disk usage.
    """

    logger.info("Collecting disk usage...")

    success, output = run_command(
        [
            "df",
            "-h"
        ]
    )

    if success:
        return output.splitlines()

    return []


# ==========================================================
# Memory Usage
# ==========================================================

def collect_memory_usage():
    """
    Collect system memory usage.
    """

    logger.info("Collecting memory usage...")

    success, output = run_command(
        [
            "free",
            "-h"
        ]
    )

    if success:
        return output.splitlines()

    return []


# ==========================================================
# Mounted File Systems
# ==========================================================

def collect_mounts():
    """
    Collect mounted file systems.
    """

    logger.info("Collecting mounted file systems...")

    success, output = run_command(
        [
            "mount"
        ]
    )

    if success:
        return output.splitlines()

    return []


# ==========================================================
# Network Interfaces
# ==========================================================

def collect_network_interfaces():
    """
    Collect network interface information.
    """

    logger.info("Collecting network interfaces...")

    success, output = run_command(
        [
            "ip",
            "addr"
        ]
    )

    if success:
        return output.splitlines()

    return []


# ==========================================================
# Routing Table
# ==========================================================

def collect_routes():
    """
    Collect routing table.
    """

    logger.info("Collecting routing table...")

    success, output = run_command(
        [
            "ip",
            "route"
        ]
    )

    if success:
        return output.splitlines()

    return []
# ==========================================================
# Main Linux Collector
# ==========================================================

def collect_linux():
    """
    Collect live forensic evidence from a Linux system.

    Returns
    -------
    dict
        Dictionary containing all collected evidence.
    """

    logger.info("=" * 60)
    logger.info("Starting Linux evidence collection")
    logger.info("=" * 60)

    evidence = {

        "success": True,

        "collector": "Linux",

        "system_information": collect_system_information(),

        "logged_in_users": collect_logged_in_users(),

        "uptime": collect_uptime(),

        "running_processes": collect_running_processes(),

        "listening_ports": collect_listening_ports(),

        "network_connections": collect_network_connections(),

        "running_services": collect_running_services(),

        "disk_usage": collect_disk_usage(),

        "memory_usage": collect_memory_usage(),

        "mounted_file_systems": collect_mounts(),

        "network_interfaces": collect_network_interfaces(),

        "routing_table": collect_routes(),

    }

    logger.info("Linux evidence collection completed.")

    return evidence


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    from pprint import pprint

    print()

    print("=" * 60)

    print("Linux Collector Test")

    print("=" * 60)

    print()

    results = collect_linux()

    pprint(results)

    print()

    print("=" * 60)

    print("Evidence collection finished.")

    print("=" * 60)
