"""Cryptographic hashing engine — MD5, SHA-1, SHA-256 with duplicate detection."""

import hashlib
from pathlib import Path
from dataclasses import dataclass
from typing import Callable, Optional

CHUNK = 1 << 16  # 64 KB


@dataclass
class FileHashes:
    path: str
    md5: str
    sha1: str
    sha256: str
    size: int


def compute_hashes(path: str, progress_cb: Optional[Callable[[int], None]] = None) -> FileHashes:
    """Compute MD5/SHA-1/SHA-256 in a single pass. Read-only."""
    md5    = hashlib.md5()
    sha1   = hashlib.sha1()
    sha256 = hashlib.sha256()
    size   = 0

    with open(path, 'rb') as f:
        while chunk := f.read(CHUNK):
            md5.update(chunk)
            sha1.update(chunk)
            sha256.update(chunk)
            size += len(chunk)
            if progress_cb:
                progress_cb(size)

    return FileHashes(
        path=path,
        md5=md5.hexdigest(),
        sha1=sha1.hexdigest(),
        sha256=sha256.hexdigest(),
        size=size,
    )


def hash_all(paths: list[str], progress_cb=None) -> list[FileHashes]:
    results = []
    for path in paths:
        try:
            fh = compute_hashes(path)
            results.append(fh)
        except (OSError, PermissionError):
            pass
        if progress_cb:
            progress_cb(path)
    return results


def find_duplicates(hashes: list[FileHashes]) -> dict[str, list[str]]:
    """Return dict mapping MD5 -> [paths] for files that share a hash."""
    groups: dict[str, list[str]] = {}
    for fh in hashes:
        groups.setdefault(fh.md5, []).append(fh.path)
    return {h: paths for h, paths in groups.items() if len(paths) > 1}


def load_hashset(filepath: str) -> set[str]:
    """Load a newline-separated list of hashes (NSRL / VirusTotal / custom)."""
    result: set[str] = set()
    with open(filepath, 'r', errors='ignore') as f:
        for line in f:
            h = line.strip().lower()
            if h:
                result.add(h)
    return result


def match_against_hashset(hashes: list[FileHashes], hashset: set[str]) -> list[FileHashes]:
    """Return entries whose MD5 OR SHA-256 appears in the provided hashset."""
    return [fh for fh in hashes
            if fh.md5 in hashset or fh.sha256 in hashset]
