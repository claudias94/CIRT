"""
=========================================================
Claus Incident Response Toolkit (CIRT)
Configuration Module

Author : Claudias Musavini Misiko
Version: 1.0.0

This module centralizes all application configuration.

Every other module imports values from here instead of
hardcoding directories, versions or constants.
=========================================================
"""

from pathlib import Path
from datetime import datetime
import platform

# =========================================================
# Application Information
# =========================================================

APP_NAME = "Claus Incident Response Toolkit"

APP_SHORT_NAME = "CIRT"

VERSION = "1.0.0"

AUTHOR = "Claudias Musavini Misiko"

DESCRIPTION = (
    "Cross-platform Incident Response Toolkit "
    "for evidence collection, forensic analysis "
    "and incident reporting."
)

# =========================================================
# Operating System Information
# =========================================================

CURRENT_OS = platform.system()

SUPPORTED_SYSTEMS = [
    "Linux",
    "Windows",
    "Darwin",
]

# =========================================================
# Project Root
# =========================================================

BASE_DIR = Path(__file__).resolve().parent

# =========================================================
# Directories
# =========================================================

REPORT_DIR = BASE_DIR / "reports"

ARTIFACT_DIR = BASE_DIR / "artifacts"

SCREENSHOT_DIR = BASE_DIR / "screenshots"

STATIC_DIR = BASE_DIR / "static"

TEMPLATE_DIR = BASE_DIR / "templates"

DOCS_DIR = BASE_DIR / "docs"

COLLECTOR_DIR = BASE_DIR / "collectors"

TEST_DIR = BASE_DIR / "tests"

# =========================================================
# Automatically create required directories
# =========================================================

DIRECTORIES = [

    REPORT_DIR,

    ARTIFACT_DIR,

    SCREENSHOT_DIR,

    STATIC_DIR,

    TEMPLATE_DIR,

    DOCS_DIR,

]

for directory in DIRECTORIES:
    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

# =========================================================
# Report Files
# =========================================================

HTML_REPORT = REPORT_DIR / "incident_report.html"

JSON_REPORT = REPORT_DIR / "incident_report.json"

CSV_REPORT = REPORT_DIR / "incident_report.csv"

MARKDOWN_REPORT = REPORT_DIR / "incident_report.md"

TEXT_REPORT = REPORT_DIR / "incident_report.txt"
# =========================================================
# Logging
# =========================================================

LOG_FILE = REPORT_DIR / "cirt.log"

LOG_LEVEL = "INFO"

LOG_FORMAT = (
    "%(asctime)s | "
    "%(levelname)s | "
    "%(message)s"
)

# =========================================================
# Time Formats
# =========================================================

TIMESTAMP = datetime.now().strftime(
    "%Y-%m-%d %H:%M:%S"
)

REPORT_DATE = datetime.now().strftime(
    "%d %B %Y"
)

REPORT_TIME = datetime.now().strftime(
    "%H:%M:%S"
)

# =========================================================
# Report Formats
# =========================================================

SUPPORTED_EXPORTS = [

    "html",

    "json",

    "csv",

    "markdown",

    "txt",

]

# =========================================================
# Hash Algorithms
# =========================================================

SUPPORTED_HASHES = [

    "md5",

    "sha1",

    "sha256",

]

# =========================================================
# Severity Levels
# =========================================================

SEVERITY_LEVELS = [

    "LOW",

    "MEDIUM",

    "HIGH",

    "CRITICAL",

]

# =========================================================
# IOC Types
# =========================================================

IOC_TYPES = [

    "IP Address",

    "Domain",

    "URL",

    "Filename",

    "Process",

    "Hash",

]

# =========================================================
# Network Configuration
# =========================================================

DEFAULT_TIMEOUT = 5

MAX_REPORT_SIZE_MB = 25

# =========================================================
# Dashboard
# =========================================================

DASHBOARD_TITLE = (
    "Claus Incident Response Dashboard"
)

# =========================================================
# Banner
# =========================================================

BANNER = f"""
==========================================================
{APP_NAME}
Version : {VERSION}
Author  : {AUTHOR}
Operating System : {CURRENT_OS}
==========================================================
"""

# =========================================================
# Configuration Helper
# =========================================================

def show_configuration():
    """
    Print the active application configuration.

    Useful during development and debugging.
    """

    print(BANNER)

    print(f"Base Directory : {BASE_DIR}")
    print(f"Reports        : {REPORT_DIR}")
    print(f"Artifacts      : {ARTIFACT_DIR}")
    print(f"Screenshots    : {SCREENSHOT_DIR}")
    print(f"Templates      : {TEMPLATE_DIR}")
    print(f"Static         : {STATIC_DIR}")
    print(f"Collectors     : {COLLECTOR_DIR}")
    print(f"Operating Sys. : {CURRENT_OS}")
    print(f"Exports        : {', '.join(SUPPORTED_EXPORTS)}")
    print(f"Hashes         : {', '.join(SUPPORTED_HASHES)}")


# =========================================================
# Standalone Test
# =========================================================

if __name__ == "__main__":
    show_configuration()
