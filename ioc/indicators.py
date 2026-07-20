"""
============================================================
Claus Incident Response Toolkit (CIRT)

IOC Indicators Database

Author : Claudias Musavini Misiko
Version: 1.0.0

Central repository of Indicators of Compromise (IOCs).

This module contains known suspicious:

- Processes
- Ports
- Windows executables
- Linux binaries
- Services
- Living-Off-The-Land Binaries (LOLBins)

All IOC detection modules import their indicators
from this file.

============================================================
"""

from logger import logger

# ==========================================================
# Suspicious Process Names
# ==========================================================

SUSPICIOUS_PROCESSES = {

    # Reverse shells

    "nc",
    "netcat",
    "ncat",
    "socat",

    # Metasploit

    "meterpreter",
    "msfconsole",
    "msfvenom",
    "multi_handler",

    # Credential dumping

    "mimikatz",
    "procdump",
    "pwdump",

    # Password attacks

    "john",
    "hashcat",
    "hydra",
    "medusa",

    # Network scanners

    "nmap",
    "masscan",
    "zmap",

    # Packet capture

    "tcpdump",
    "wireshark",
    "tshark",

    # Exploitation frameworks

    "beacon",
    "cobaltstrike",
    "empire",
    "sliver",

    # Remote administration

    "teamviewer",
    "anydesk",

    # Tunneling

    "frpc",
    "frps",
    "ngrok",

    # Python abuse

    "python",
    "python3",

    # Shell abuse

    "bash",
    "sh",
    "zsh",

}
# ==========================================================
# Suspicious Ports
# ==========================================================

SUSPICIOUS_PORTS = {

    1337: "Elite / Common Backdoor",

    4444: "Metasploit Default Listener",

    5555: "ADB / Malware Backdoor",

    6666: "Common Malware Port",

    6667: "IRC Command and Control",

    7777: "Backdoor Communication",

    8888: "Remote Administration",

    9001: "Tor Relay",

    9999: "Backdoor",

    12345: "NetBus",

    27374: "SubSeven",

    31337: "Back Orifice",

}


# ==========================================================
# Suspicious Windows Executables
# ==========================================================

SUSPICIOUS_WINDOWS_EXECUTABLES = {

    "powershell.exe",

    "pwsh.exe",

    "cmd.exe",

    "wscript.exe",

    "cscript.exe",

    "mshta.exe",

    "rundll32.exe",

    "regsvr32.exe",

    "wmic.exe",

    "certutil.exe",

    "bitsadmin.exe",

    "schtasks.exe",

    "at.exe",

    "psexec.exe",

    "procdump.exe",

    "mimikatz.exe",

    "nc.exe",

    "ncat.exe",

}


# ==========================================================
# Suspicious Linux Binaries
# ==========================================================

SUSPICIOUS_LINUX_BINARIES = {

    "/bin/bash",

    "/bin/sh",

    "/usr/bin/python",

    "/usr/bin/python3",

    "/usr/bin/perl",

    "/usr/bin/php",

    "/usr/bin/ruby",

    "/usr/bin/nc",

    "/usr/bin/netcat",

    "/usr/bin/ncat",

    "/usr/bin/socat",

    "/usr/bin/curl",

    "/usr/bin/wget",

    "/usr/bin/ssh",

    "/usr/bin/scp",

}
# ==========================================================
# Suspicious Service Names
# ==========================================================

SUSPICIOUS_SERVICES = {

    "telnet",

    "vsftpd",

    "xinetd",

    "inetd",

    "tftpd",

    "vncserver",

    "tightvnc",

    "x11vnc",

    "teamviewer",

    "anydesk",

    "tor",

    "tor.service",

    "sshd",

}


# ==========================================================
# Living-Off-The-Land Binaries (LOLBins)
#
# Legitimate system tools frequently abused by attackers.
# ==========================================================

LOLBINS = {

    "powershell.exe",

    "pwsh.exe",

    "cmd.exe",

    "wmic.exe",

    "certutil.exe",

    "bitsadmin.exe",

    "regsvr32.exe",

    "rundll32.exe",

    "mshta.exe",

    "cscript.exe",

    "wscript.exe",

    "schtasks.exe",

    "at.exe",

    "curl",

    "wget",

    "bash",

    "sh",

    "python",

    "python3",

    "perl",

    "php",

    "ruby",

}


# ==========================================================
# Linux Persistence Locations
# ==========================================================

LINUX_PERSISTENCE_LOCATIONS = [

    "/etc/crontab",

    "/etc/cron.d",

    "/etc/cron.daily",

    "/etc/cron.hourly",

    "/etc/cron.monthly",

    "/etc/cron.weekly",

    "/var/spool/cron",

    "/etc/systemd/system",

    "/usr/lib/systemd/system",

    "/etc/init.d",

    "/etc/rc.local",

    "~/.bashrc",

    "~/.profile",

    "~/.bash_profile",

]


# ==========================================================
# Windows Persistence Locations
# ==========================================================

WINDOWS_PERSISTENCE_LOCATIONS = [

    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run",

    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Run",

    r"HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce",

    r"HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce",

    r"C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup",

    r"%APPDATA%\Microsoft\Windows\Start Menu\Programs\Startup",

]
MALICIOUS_IPS = {

    "185.220.101.15": "Known TOR Exit Node",

    "45.95.147.236": "Known Command and Control Server",

    "103.27.202.85": "Known Malware Distribution Server",

    "198.51.100.100": "Known Threat Intelligence IOC",

}
# ==========================================================
# IOC Risk Scores
# ==========================================================

IOC_RISK_SCORES = {

    "critical": 100,

    "high": 75,

    "medium": 50,

    "low": 25,

    "informational": 10,

}


# ==========================================================
# Helper Functions
# ==========================================================

def get_suspicious_processes():
    """
    Return all suspicious process names.
    """
    return sorted(SUSPICIOUS_PROCESSES)


def get_suspicious_ports():
    """
    Return suspicious ports dictionary.
    """
    return SUSPICIOUS_PORTS


def get_lolbins():
    """
    Return Living-Off-The-Land Binaries.
    """
    return sorted(LOLBINS)


def get_windows_executables():
    """
    Return suspicious Windows executables.
    """
    return sorted(SUSPICIOUS_WINDOWS_EXECUTABLES)


def get_linux_binaries():
    """
    Return suspicious Linux binaries.
    """
    return sorted(SUSPICIOUS_LINUX_BINARIES)


def get_linux_persistence_locations():
    """
    Return Linux persistence locations.
    """
    return LINUX_PERSISTENCE_LOCATIONS


def get_windows_persistence_locations():
    """
    Return Windows persistence locations.
    """
    return WINDOWS_PERSISTENCE_LOCATIONS


def get_risk_score(level):
    """
    Return the numeric score associated with a risk level.
    """

    return IOC_RISK_SCORES.get(
        level.lower(),
        IOC_RISK_SCORES["informational"]
    )


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    logger.info("=" * 60)
    logger.info("IOC Indicator Database Test")
    logger.info("=" * 60)

    print()

    print("=" * 60)
    print("IOC DATABASE SUMMARY")
    print("=" * 60)

    print(f"Suspicious Processes       : {len(SUSPICIOUS_PROCESSES)}")
    print(f"Suspicious Ports           : {len(SUSPICIOUS_PORTS)}")
    print(f"Windows Executables        : {len(SUSPICIOUS_WINDOWS_EXECUTABLES)}")
    print(f"Linux Binaries             : {len(SUSPICIOUS_LINUX_BINARIES)}")
    print(f"Suspicious Services        : {len(SUSPICIOUS_SERVICES)}")
    print(f"LOLBins                    : {len(LOLBINS)}")
    print(f"Linux Persistence Paths    : {len(LINUX_PERSISTENCE_LOCATIONS)}")
    print(f"Windows Persistence Paths  : {len(WINDOWS_PERSISTENCE_LOCATIONS)}")

    print()

    print("Risk Levels")

    for level, score in IOC_RISK_SCORES.items():

        print(f"  {level:<15} -> {score}")

    print()

    logger.info("IOC indicator database loaded successfully.")
    logger.info("=" * 60)

