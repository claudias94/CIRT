"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Evidence Collection Controller

Author : Claudias Musavini Misiko
Version: 1.0.0

Selects the correct evidence collector
based on the operating system.
=========================================================
"""

from utils import get_os
from logger import logger

from collectors.linux import collect_linux

try:
    from collectors.windows import collect_windows
except ImportError:
    def collect_windows():
        return {
            "success": False,
            "error": "Windows collector not implemented yet."
        }

try:
    from collectors.macos import collect_macos
except ImportError:
    def collect_macos():
        return {
            "success": False,
            "error": "macOS collector not implemented yet."
        }


# ==========================================================
# Collector Controller
# ==========================================================

def collect_system_information():
    """
    Detect the operating system and execute
    the correct collector.

    Returns
    -------
    dict
        Collected evidence
    """

    operating_system = get_os()

    logger.info(
        "Detected operating system: %s",
        operating_system,
    )

    if operating_system == "Linux":

        logger.info("Loading Linux collector")

        return collect_linux()

    elif operating_system == "Windows":

        logger.info("Loading Windows collector")

        return collect_windows()

    elif operating_system == "Darwin":

        logger.info("Loading macOS collector")

        return collect_macos()

    logger.error(
        "Unsupported operating system: %s",
        operating_system,
    )

    return {

        "success": False,

        "error": "Unsupported operating system.",

        "operating_system": operating_system,

    }
# ==========================================================
# Collector Status
# ==========================================================

def collector_status():
    """
    Return information about the active collector.
    """

    operating_system = get_os()

    return {

        "application": "Claus Incident Response Toolkit",

        "version": "1.0.0",

        "operating_system": operating_system,

        "collector": f"{operating_system} Collector",

        "supported": operating_system in [

            "Linux",

            "Windows",

            "Darwin",

        ],

    }


# ==========================================================
# Health Check
# ==========================================================

def health_check():
    """
    Verify the collector controller is operational.
    """

    status = collector_status()

    logger.info(
        "Collector health check completed."
    )

    return {

        "status": "OK",

        "collector": status["collector"],

        "operating_system": status["operating_system"],

    }


# ==========================================================
# Convenience Function
# ==========================================================

def run_collection():
    """
    Main entry point for evidence collection.
    """

    logger.info(
        "Starting evidence collection..."
    )

    results = collect_system_information()

    logger.info(
        "Evidence collection finished."
    )

    return results
# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    print()

    print("=" * 60)

    print("Collector Controller Test")

    print("=" * 60)

    print()

    status = collector_status()

    for key, value in status.items():

        print(f"{key:18}: {value}")

    print()

    print("Health Check")

    print(health_check())

    print()

    print("Attempting collection...")

    print()

    results = run_collection()

    print(results)
