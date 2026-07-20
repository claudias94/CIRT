"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Windows Evidence Collector

Description
-----------
Collects live forensic artifacts from Microsoft Windows
systems for incident response investigations.

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

import getpass
import platform

from logger import logger
from utils import run_command

# ==========================================================
# Collector Information
# ==========================================================

COLLECTOR_NAME = "Windows Collector"

# ==========================================================
# System Information
# ==========================================================


def system_information():
    """
    Collect basic Windows system information.
    """

    logger.info("Collecting system information...")

    information = {

        "hostname": platform.node(),

        "operating_system": platform.system(),

        "release": platform.release(),

        "version": platform.version(),

        "architecture": platform.machine(),

        "processor": platform.processor(),

        "current_user": getpass.getuser(),

    }

    return information


# ==========================================================
# Logged In Users
# ==========================================================


def logged_in_users():
    """
    Collect currently logged in users.
    """

    logger.info("Collecting logged in users...")

    users = run_command(

        "query user"

    )

    return users


# ==========================================================
# Running Processes
# ==========================================================


def running_processes():
    """
    Collect running processes.
    """

    logger.info("Collecting running processes...")

    processes = run_command(

        "tasklist"

    )

    return processes


# ==========================================================
# Running Services
# ==========================================================


def running_services():
    """
    Collect Windows services.
    """

    logger.info("Collecting running services...")

    services = run_command(

        "sc query type= service state= all"

    )

    return services
# ==========================================================
# IP Configuration
# ==========================================================


def ip_configuration():
    """
    Collect Windows IP configuration.
    """

    logger.info("Collecting IP configuration...")

    ipconfig = run_command(

        "ipconfig /all"

    )

    return ipconfig


# ==========================================================
# Listening Ports
# ==========================================================


def listening_ports():
    """
    Collect listening ports.
    """

    logger.info("Collecting listening ports...")

    ports = run_command(

        "netstat -ano"

    )

    return ports


# ==========================================================
# Active Network Connections
# ==========================================================


def network_connections():
    """
    Collect active network connections.
    """

    logger.info("Collecting active network connections...")

    connections = run_command(

        "netstat -anob"

    )

    return connections


# ==========================================================
# Routing Table
# ==========================================================


def routing_table():
    """
    Collect Windows routing table.
    """

    logger.info("Collecting routing table...")

    routes = run_command(

        "route print"

    )

    return routes


# ==========================================================
# Scheduled Tasks
# ==========================================================


def scheduled_tasks():
    """
    Collect scheduled tasks.
    """

    logger.info("Collecting scheduled tasks...")

    tasks = run_command(

        "schtasks"

    )

    return tasks


# ==========================================================
# Installed Software
# ==========================================================


def installed_software():
    """
    Collect installed software.
    """

    logger.info("Collecting installed software...")

    software = run_command(

        'wmic product get Name,Version'

    )

    return software

# ==========================================================
# Windows Firewall
# ==========================================================


def firewall_status():
    """
    Collect Windows Firewall status.
    """

    logger.info("Collecting Windows Firewall status...")

    firewall = run_command(

        "netsh advfirewall show allprofiles"

    )

    return firewall


# ==========================================================
# Windows Defender
# ==========================================================


def defender_status():
    """
    Collect Windows Defender status.
    """

    logger.info("Collecting Windows Defender status...")

    defender = run_command(

        'powershell "Get-MpComputerStatus"'

    )

    return defender


# ==========================================================
# Windows Event Log Summary
# ==========================================================


def event_log_summary():
    """
    Collect a summary of recent Windows System event logs.
    """

    logger.info("Collecting Windows Event Log summary...")

    events = run_command(

        'wevtutil qe System /c:25 /rd:true /f:text'

    )

    return events


# ==========================================================
# Local User Accounts
# ==========================================================


def local_users():
    """
    Collect local Windows user accounts.
    """

    logger.info("Collecting local user accounts...")

    users = run_command(

        "net user"

    )

    return users


# ==========================================================
# Shared Folders
# ==========================================================


def shared_folders():
    """
    Collect Windows shared folders.
    """

    logger.info("Collecting shared folders...")

    shares = run_command(

        "net share"

    )

    return shares


# ==========================================================
# Environment Variables
# ==========================================================


def environment_variables():
    """
    Collect Windows environment variables.
    """

    logger.info("Collecting environment variables...")

    environment = run_command(

        "set"

    )

    return environment

# ==========================================================
# Main Windows Evidence Collector
# ==========================================================


def collect_windows():
    """
    Main Windows evidence collection function.

    Returns
    -------
    dict
        Dictionary containing collected forensic artifacts.
    """

    logger.info("=" * 60)
    logger.info("Starting Windows evidence collection")
    logger.info("=" * 60)

    evidence = {

        "success": True,

        "collector": "Windows",

        "system_information": system_information(),

        "logged_in_users": logged_in_users(),

        "running_processes": running_processes(),

        "running_services": running_services(),

        "ip_configuration": ip_configuration(),

        "listening_ports": listening_ports(),

        "network_connections": network_connections(),

        "routing_table": routing_table(),

        "scheduled_tasks": scheduled_tasks(),

        "installed_software": installed_software(),

        "firewall_status": firewall_status(),

        "windows_defender": defender_status(),

        "event_log_summary": event_log_summary(),

        "local_users": local_users(),

        "shared_folders": shared_folders(),

        "environment_variables": environment_variables(),

    }

    logger.info("=" * 60)
    logger.info("Windows evidence collection completed.")
    logger.info("=" * 60)

    return evidence


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    from pprint import pprint

    logger.info("=" * 60)
    logger.info("Standalone Windows Collector Test")
    logger.info("=" * 60)

    results = collect_windows()

    print()

    print("=" * 60)
    print("WINDOWS COLLECTOR SUMMARY")
    print("=" * 60)

    print(f"Collector : {results['collector']}")
    print(f"Success   : {results['success']}")

    print()

    print("Evidence Collected")

    for key in results.keys():

        if key in ("collector", "success"):

            continue

        print(f"  ✓ {key}")

    print()

    pprint(results)

    logger.info("=" * 60)
    logger.info("Standalone test completed.")
    logger.info("=" * 60)
