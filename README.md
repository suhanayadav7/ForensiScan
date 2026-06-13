# ForensiScan — Windows File Analysis Tool

> A lightweight desktop application for digital forensics — automates file metadata extraction, signature verification, cryptographic hashing, hidden data detection, and timeline reconstruction.

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20macOS%20%7C%20Linux-lightgrey?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)

---

## Features

| Module | What it does |
|---|---|
| **Metadata Extractor** | Collects MAC timestamps (Modified, Accessed, Created), file size, owner, hidden/system/readonly flags |
| **Signature Analyzer** | Reads magic bytes and flags extension mismatches (e.g. `.exe` disguised as `.jpg`) — 35+ signatures |
| **Hashing Engine** | Computes MD5, SHA-1, SHA-256 in a single pass; detects duplicates; supports known-bad hashset matching |
| **Hidden Data Detector** | Enumerates NTFS Alternate Data Streams (ADS); flags double extensions, executables in temp folders |
| **Timeline Builder** | Orders all file events chronologically; filterable by event type and date range |
| **Report Generator** | Exports CSV bundle, styled HTML report, and optional PDF for chain-of-custody documentation |

---

## Project Structure

ForensiScan/
├── main.py                 # Entry point
├── requirements.txt
├── core/
│   ├── metadata.py         # MAC timestamps, owner, attributes
│   ├── signatures.py       # Magic byte analysis
│   ├── hasher.py           # MD5 / SHA-1 / SHA-256
│   ├── hidden_data.py      # NTFS ADS + suspicion heuristics
│   ├── timeline.py         # Chronological event builder
│   └── reporter.py         # CSV / HTML / PDF export
└── gui/
    └── app.py              # Tkinter dark-theme GUI

---

## Installation

### Prerequisites
- Python 3.10 or higher
- macOS / Windows / Linux

### Steps

```bash
# 1. Clone the repository
git clone https://github.com/suhanayadav7/ForensiScan
cd ForensiScan

# 2. macOS only — install Tkinter if missing
brew install python-tk@3.14

# 3. Install optional dependencies
pip3 install reportlab        # for PDF export
pip3 install pywin32          # Windows only — file owner & NTFS ADS

---
How to Run

cd ForensiScan
python3 main.py

The GUI window will open automatically.

Step-by-step inside the app

1. Click Browse → select any folder or drive you want to analyze
2. Tick the options you need: Recursive, Hashing, Signatures, Hidden
3. Click ▶ Scan and wait for the scan to complete
4. Switch between the 6 tabs to view results:
  - Metadata — timestamps, owner, hidden/system flags for every file
  - Signatures — files with mismatched extensions highlighted in red
  - Hashes — MD5, SHA-1, SHA-256 for every file
  - Hidden Data — files with ADS streams or suspicious flags
  - Timeline — all file events sorted by time
  - Report — enter examiner name & case name, then export
5. In the Report tab choose your export format:

┌─────────────┬─────────────────────────────────────────────────┐
│   Format    │                    Contents                     │
├─────────────┼─────────────────────────────────────────────────┤
│ CSV bundle  │ 4 files: metadata, hashes, signatures, timeline │
├─────────────┼─────────────────────────────────────────────────┤
│ HTML report │ Styled single-file report with all findings     │
├─────────────┼─────────────────────────────────────────────────┤
│ PDF report  │ Chain-of-custody document (requires reportlab)  │
└─────────────┴─────────────────────────────────────────────────┘

---
How It Works

Signature Analysis

Reads the first 512 bytes of each file and compares against 35+ magic byte signatures. Flags any file whose extension does not match its actual format.

NTFS Alternate Data Streams (Windows only)

Uses the Windows FindFirstStreamW / FindNextStreamW API via ctypes to enumerate hidden data streams — a common technique used to conceal malicious payloads.

Hashing

Computes MD5, SHA-1, and SHA-256 in a single read pass. Supports loading external hashsets (e.g. NIST NSRL) to identify known-good or known-bad files.

Timeline

Converts file Created and Modified timestamps into a unified chronological event list to help reconstruct user activity.

---
Tech Stack

- Language: Python 3
- GUI: Tkinter
- Hashing: hashlib (stdlib)
- File system: os, pathlib, ctypes
- Windows APIs: pywin32 (optional)
- PDF export: ReportLab (optional)

---
Limitations

- NTFS Alternate Data Stream detection requires Windows
- File ownership requires pywin32 on Windows
- Large directories (100k+ files) may take several minutes to hash

---
Author

Suhana 
