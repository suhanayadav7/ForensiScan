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
| **Entropy Analyzer** | Shannon entropy (0.0–8.0) flags encrypted/packed/ransomware payloads above 7.2 threshold |
| **Risk Scorer** | Combines 6 forensic signals into a 0–100 risk score per file; colour-coded in the Metadata tab |
| **Report Generator** | Exports CSV bundle, styled HTML report, and optional PDF (ReportLab) with chain-of-custody audit log |

---

## Project Structure

```
ForensiScan/
├── main.py                 # Entry point
├── requirements.txt
├── core/
│   ├── metadata.py         # MAC timestamps, owner, attributes
│   ├── signatures.py       # Magic byte analysis
│   ├── hasher.py           # MD5 / SHA-1 / SHA-256
│   ├── hidden_data.py      # NTFS ADS + suspicion heuristics + risk scorer
│   ├── timeline.py         # Chronological event builder + anomaly detection
│   ├── entropy.py          # Shannon entropy analysis
│   └── reporter.py         # CSV / HTML / PDF export + audit log
└── gui/
    └── app.py              # Tkinter dark-theme GUI (7 tabs)
```

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

# 2. (macOS only) Install Tkinter if missing
brew install python-tk@3.14

# 3. Install optional dependencies
pip3 install reportlab        # for PDF export
pip3 install pywin32          # Windows only — for file owner & attributes

# 4. Run the app
python3 main.py
```

> **Note:** The core features (hashing, signatures, timeline, entropy, CSV/HTML reports) work on all platforms with zero dependencies. `pywin32` is only needed on Windows for file ownership and NTFS ADS detection.

---

## Usage

1. Click **Browse** and select a target folder or drive
2. Choose options: **Recursive**, **Hashing**, **Signatures**, **Hidden**, **Entropy**
3. Click **▶ Scan**
4. Explore results across the 7 tabs
5. Go to the **Report** tab → enter examiner name and case name → export
6. Use **Clear** between cases to reset all scan data

### Export formats
| Format | Contents |
|---|---|
| CSV bundle | 5 files: metadata, hashes, signatures, timeline, entropy |
| HTML report | Styled single-file report with audit log as first section |
| PDF report | Chain-of-custody document (requires `reportlab`) |

---

## How It Works

### Signature Analysis
Reads the first 512 bytes of each file and compares against a database of 35+ magic byte signatures. Flags any file whose extension does not match its actual format.

### NTFS Alternate Data Streams (Windows only)
Uses the Windows `FindFirstStreamW` / `FindNextStreamW` API via `ctypes` to enumerate hidden data streams attached to files — a common technique used to conceal malicious payloads.

### Hashing
Computes MD5, SHA-1, and SHA-256 in a single read pass for efficiency. Supports loading external hashsets (e.g. NIST NSRL) to identify known-good or known-bad files.

### Shannon Entropy
Measures byte randomness on a 0.0–8.0 scale. Normal files score 3–5; encrypted files, ransomware payloads, and packed executables score 7.2–8.0 and are flagged automatically.

### Risk Scoring
Combines extension mismatch (+35), hidden+system bits (+30), high entropy (+20), double extension (+25), executable in temp dir (+20), and risky extension (+10) into a capped 0–100 score per file.

### Timestamp Anomaly Detection
Detects files where Modified < Created — forensically impossible under normal conditions. This indicates deliberate timestamp tampering by an attacker or anti-forensics tool.

### Timeline
Converts file Created and Modified timestamps into a unified, chronologically sorted event list. Access timestamps are excluded by default to reduce noise.

---

## Tech Stack

- **Language:** Python 3
- **GUI:** Tkinter
- **Hashing:** `hashlib` (stdlib)
- **File system:** `os`, `pathlib`, `ctypes`
- **Windows APIs:** `pywin32` (optional)
- **PDF export:** `ReportLab` (optional)
- **Testing datasets:** [NIST CFReDS](https://cfreds.nist.gov/)

---

## Limitations

- NTFS ADS detection requires Windows (skipped on Linux / macOS)
- File ownership (`pywin32`) requires Windows
- `st_ctime` on Linux/macOS = inode-change time, not file creation time
- No live malware execution, no network scanning, no memory forensics
- Large directories (100k+ files) may take several minutes to hash
- HTML report display is capped at 500/200/1000 rows — use CSV for full data

---

## Testing with Safe Dummy Files

1. Rename a `.exe` file to `.jpg` — Signatures tab shows mismatch
2. Set Hidden + System attributes on a file — Hidden Data tab flags it
3. Create two identical files — Hashes tab shows duplicate MD5
4. Use a timestomp tool to alter dates — Timeline anomaly table flags it

---

## Known Issues

- ADS detection returns empty on non-Windows (by design)
- HTML report display is capped at 500/200/1000 rows — use CSV for full data

---

## Contributing

Pull requests are welcome. For major changes, open an issue first to discuss what you'd like to change.

---

## License

MIT — free to use, modify, and distribute.

---

## Author

ForensiScan
