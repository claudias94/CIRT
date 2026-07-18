"""
=========================================================
Claus Incident Response Toolkit (CIRT)

Evidence Packaging Orchestrator

Description
-----------
Coordinates all evidence packaging tasks:
    - SHA256 hashing
    - Manifest generation
    - Chain of Custody
    - ZIP archive creation

Author : Claudias Musavini Misiko
Version: 1.0.0
=========================================================
"""

import os

from logger import logger

from packaging.hashing import (
    hash_directory,
    save_hash_report,
)

from packaging.manifest import (
    generate_manifest,
    save_manifest,
)

from packaging.chain import (
    create_chain_of_custody,
    save_chain,
)

from packaging.zipper import (
    create_zip_archive,
)


# ==========================================================
# Package Evidence
# ==========================================================

def package_evidence(
    evidence_directory="reports",
    case_number="CASE-001",
    investigator="Claudias Musavini",
):
    """
    Package all collected evidence.

    Parameters
    ----------
    evidence_directory : str

    case_number : str

    investigator : str

    Returns
    -------
    dict
    """

    logger.info("=" * 60)
    logger.info("Starting Evidence Packaging")
    logger.info("=" * 60)

    # ------------------------------------------------------
    # SHA256 Hash Report
    # ------------------------------------------------------

    hashes = hash_directory(
        evidence_directory
    )

    hash_file = os.path.join(
        evidence_directory,
        "hashes.txt",
    )

    save_hash_report(
        hashes,
        hash_file,
    )

    # ------------------------------------------------------
    # Manifest
    # ------------------------------------------------------

    manifest = generate_manifest(
        evidence_directory
    )

    manifest_file = os.path.join(
        evidence_directory,
        "manifest.json",
    )

    save_manifest(
        manifest,
        manifest_file,
    )

    # ------------------------------------------------------
    # Chain of Custody
    # ------------------------------------------------------

    chain = create_chain_of_custody(
        case_number=case_number,
        investigator=investigator,
        evidence_directory=evidence_directory,
    )

    chain_file = os.path.join(
        evidence_directory,
        "chain_of_custody.txt",
    )

    save_chain(
        chain,
        chain_file,
    )

    # ------------------------------------------------------
    # ZIP Archive
    # ------------------------------------------------------

    zip_file = os.path.join(
        evidence_directory,
        f"{case_number}.zip",
    )

    create_zip_archive(
        evidence_directory,
        zip_file,
    )

    logger.info("=" * 60)
    logger.info("Evidence Packaging Completed")
    logger.info("=" * 60)

    return {

        "success": True,

        "hash_report": hash_file,

        "manifest": manifest_file,

        "chain_of_custody": chain_file,

        "archive": zip_file,

    }


# ==========================================================
# Standalone Test
# ==========================================================

if __name__ == "__main__":

    results = package_evidence()

    print()

    print("=" * 60)
    print("EVIDENCE PACKAGING SUMMARY")
    print("=" * 60)

    print(f"Hash Report       : {results['hash_report']}")
    print(f"Manifest          : {results['manifest']}")
    print(f"Chain of Custody  : {results['chain_of_custody']}")
    print(f"ZIP Archive       : {results['archive']}")

    print("=" * 60)
