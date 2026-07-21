# Claus Incident Response Toolkit (CIRT)

![Python](https://img.shields.io/badge/Python-3.12-blue)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Windows-success)
![Status](https://img.shields.io/badge/Status-Stable-brightgreen)
![License](https://img.shields.io/badge/License-MIT-yellow)

---

## Overview

Claus Incident Response Toolkit (CIRT) is a modular Digital Forensics and Incident Response (DFIR) framework designed to automate live evidence collection, indicator-of-compromise (IOC) analysis, forensic reporting, and evidence packaging across Linux and Windows systems.

The toolkit streamlines the initial stages of incident response by providing investigators with a repeatable workflow that preserves evidence integrity while producing actionable forensic artifacts.

CIRT is built with a modular architecture that allows individual components to evolve independently without impacting the overall framework.

---

## Core Capabilities

### Live Evidence Collection

- System Information
- Logged-in Users
- Running Processes
- Running Services
- Listening Ports
- Active Network Connections
- Network Interfaces
- Routing Table
- Disk Usage
- Memory Usage
- Mounted File Systems

---

### IOC Detection Engine

The IOC engine automatically analyzes collected evidence for indicators associated with compromise and persistence.

Current detection modules include:

- Suspicious Processes
- Suspicious Network Ports
- Suspicious IP Addresses
- Linux Persistence Mechanisms
- Windows Persistence Mechanisms
- Threat Severity Assessment

---

### Reporting

CIRT automatically generates investigation reports in multiple formats.

- HTML
- JSON
- Markdown
- CSV

---

### Evidence Integrity

To preserve forensic integrity, CIRT automatically generates:

- SHA256 Hashes
- Evidence Manifest
- Chain of Custody
- Compressed Evidence Archive

---

## Architecture

```
                +--------------------+
                | collector.py       |
                +---------+----------+
                          |
         +----------------+----------------+
         |                                 |
         ▼                                 ▼
 Linux Collector                  Windows Collector
         |                                 |
         +----------------+----------------+
                          |
                          ▼
                 IOC Detection Engine
                          |
         +--------+--------+--------+--------+
         |        |        |        |        |
         ▼        ▼        ▼        ▼        ▼
  Processes   Ports    IPs   Persistence Severity
                          |
                          ▼
                 Report Generation
                          |
                          ▼
                Evidence Packaging
                          |
                          ▼
              CASE-001.zip Archive
```

---

## Workflow

```
Evidence Collection

        ↓

IOC Analysis

        ↓

Report Generation

        ↓

Evidence Integrity Verification

        ↓

Evidence Packaging

        ↓

Investigation Archive
```

---

## Project Structure

```
CIRT/

├── collectors/
├── ioc/
├── packaging/
├── reporting/
├── templates/
├── tests/
├── docs/
├── screenshots/
├── reports/
├── collector.py
├── app.py
├── config.py
└── README.md
```
---

# Installation

Clone the repository

```bash
git clone https://github.com/claudias94/CIRT.git
cd CIRT
```

Install dependencies

```bash
pip install -r requirements.txt
```

Run CIRT

```bash
python collector.py
```

---

# Example Execution

```text
============================================================
Starting Claus Incident Response Toolkit
============================================================

Detected Operating System : Linux

Collecting Live Evidence...
✓ System Information
✓ Running Processes
✓ Running Services
✓ Network Connections
✓ Logged-in Users

Starting IOC Analysis...
✓ Suspicious Processes
✓ Suspicious Ports
✓ Suspicious IP Addresses
✓ Persistence Detection

Generating Reports...
✓ HTML
✓ JSON
✓ Markdown
✓ CSV

Packaging Evidence...
✓ SHA256 Hashes
✓ Manifest
✓ Chain of Custody
✓ Investigation Archive

============================================================
CIRT EXECUTION SUMMARY
============================================================

Operating System : Linux
Evidence         : SUCCESS
IOC Analysis     : Completed
Reports          : 4 Generated
Archive          : reports/CASE-001.zip
```

---

# Generated Artifacts

CIRT automatically produces:

| Artifact | Purpose |
|-----------|---------|
| report.html | Human-readable investigation report |
| report.json | Machine-readable report |
| report.md | Investigation notes |
| report.csv | Spreadsheet analysis |
| hashes.txt | Evidence integrity verification |
| manifest.json | Evidence inventory |
| chain_of_custody.txt | Forensic chain of custody |
| CASE-001.zip | Packaged investigation archive |

---

# Security Features

- Modular IOC Detection Engine
- Cross-platform Evidence Collection
- Automated Forensic Reporting
- SHA256 Integrity Verification
- Chain of Custody Generation
- Evidence Packaging
- Structured Logging
- Modular Python Architecture

---

# Use Cases

CIRT can support:

- Security Operations Centers (SOC)
- Incident Response Teams
- Digital Forensics Investigations
- Malware Triage
- Insider Threat Investigations
- Host-Based Threat Hunting
- Security Assessments
- DFIR Training Labs

---

## Design Principles

- Modular
- Platform Independent
- Extensible
- Evidence Integrity
- Automation First
- Minimal External Dependencies

---

## Supported Platforms

| Operating System | Status |
|------------------|--------|
| Ubuntu Linux | ✅ |
| Debian Linux | ✅ |
| Kali Linux | ✅ |
| Windows 10 | ✅ |
| Windows 11 | ✅ |

---

## Current Version

**CIRT v1.0**

Status:

Stable

---

## Roadmap

Future releases will introduce additional DFIR capabilities including:

- YARA Integration
- MITRE ATT&CK Mapping
- Threat Intelligence Feed Support
- Sigma Rule Processing
- Timeline Reconstruction
- Automated Threat Correlation

---

## License

MIT License

---

## Author

**Claudias Musavini Misiko**

Cybersecurity • Digital Forensics • Incident Response • Python Automation

GitHub:

https://github.com/claudias94

LinkedIn:

https://www.linkedin.com/in/claudias-musavini-3b0918116/
