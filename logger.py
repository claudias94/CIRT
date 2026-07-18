"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Central Logging Module

Author : Claudias Musavini Misiko
Version: 1.0.0

Provides application-wide logging for all modules.
=========================================================
"""

import logging
from logging.handlers import RotatingFileHandler
from pathlib import Path

from config import (
    LOG_FILE,
    LOG_LEVEL,
    LOG_FORMAT,
)

# =========================================================
# Create log directory if necessary
# =========================================================

Path(LOG_FILE).parent.mkdir(
    parents=True,
    exist_ok=True,
)

# =========================================================
# Main Logger
# =========================================================

logger = logging.getLogger("CIRT")

logger.setLevel(LOG_LEVEL)

# Prevent duplicate logs
logger.handlers.clear()

# =========================================================
# Formatter
# =========================================================

formatter = logging.Formatter(LOG_FORMAT)

# =========================================================
# Console Output
# =========================================================

console_handler = logging.StreamHandler()

console_handler.setFormatter(formatter)

logger.addHandler(console_handler)

# =========================================================
# Log File
# =========================================================

file_handler = RotatingFileHandler(

    LOG_FILE,

    maxBytes=2 * 1024 * 1024,

    backupCount=5,

    encoding="utf-8",

)

file_handler.setFormatter(formatter)

logger.addHandler(file_handler)

# =========================================================
# Startup Message
# =========================================================

logger.info("=" * 60)
logger.info("Starting Claus Incident Response Toolkit")
logger.info("=" * 60)

# =========================================================
# Test
# =========================================================

if __name__ == "__main__":

    logger.debug("Debug message")

    logger.info("Information message")

    logger.warning("Warning message")

    logger.error("Error message")

    logger.critical("Critical message")

    print()

    print(f"Log file created at:\n{LOG_FILE}")
