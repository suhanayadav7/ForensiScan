"""File signature analysis — compare magic bytes against declared extension."""

from pathlib import Path
from dataclasses import dataclass
from typing import Optional

# (magic_bytes, offset) -> canonical extensions
# Ordered longest-match first where prefixes overlap
MAGIC_DB: list[tuple[bytes, int, tuple[str, ...]]] = [
    # Executables / code
    (b'\x4d\x5a',                      0, ('.exe', '.dll', '.sys', '.scr', '.com', '.cpl', '.ocx')),
    (b'\x7fELF',                        0, ('.elf', '.so')),
    (b'\xca\xfe\xba\xbe',              0, ('.class',)),
    (b'\xcf\xfa\xed\xfe',              0, ('.macho',)),
    (b'\xce\xfa\xed\xfe',              0, ('.macho',)),
    # Archives / containers
    (b'PK\x03\x04',                    0, ('.zip', '.docx', '.xlsx', '.pptx', '.odt', '.jar', '.apk')),
    (b'Rar!\x1a\x07\x01\x00',         0, ('.rar',)),
    (b'Rar!\x1a\x07\x00',             0, ('.rar',)),
    (b'\x1f\x8b',                       0, ('.gz', '.tgz')),
    (b'7z\xbc\xaf\x27\x1c',           0, ('.7z',)),
    (b'BZh',                            0, ('.bz2',)),
    (b'\xfd7zXZ\x00',                  0, ('.xz',)),
    (b'ustar',                         257, ('.tar',)),
    # Images
    (b'\xff\xd8\xff',                   0, ('.jpg', '.jpeg')),
    (b'\x89PNG\r\n\x1a\n',             0, ('.png',)),
    (b'GIF87a',                         0, ('.gif',)),
    (b'GIF89a',                         0, ('.gif',)),
    (b'BM',                             0, ('.bmp',)),
    (b'II*\x00',                        0, ('.tif', '.tiff')),
    (b'MM\x00*',                        0, ('.tif', '.tiff')),
    (b'\x00\x00\x01\x00',              0, ('.ico',)),
    (b'WEBP',                           8, ('.webp',)),
    # Documents
    (b'%PDF',                           0, ('.pdf',)),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 0, ('.doc', '.xls', '.ppt', '.msg', '.msi')),
    # Media
    (b'fLaC',                           0, ('.flac',)),
    (b'ID3',                            0, ('.mp3',)),
    (b'\xff\xfb',                       0, ('.mp3',)),
    (b'OggS',                           0, ('.ogg', '.oga', '.ogv')),
    (b'RIFF',                           0, ('.wav', '.avi')),
    (b'ftyp',                           4, ('.mp4', '.m4v', '.m4a', '.mov', '.f4v')),
    (b'\x1a\x45\xdf\xa3',              0, ('.mkv', '.webm')),
    # Database
    (b'SQLite format 3\x00',           0, ('.db', '.sqlite', '.sqlite3')),
    # Scripts (shebang)
    (b'#!/usr/bin/env python',          0, ('.py',)),
    (b'#!/usr/bin/python',              0, ('.py',)),
    (b'#!/bin/bash',                    0, ('.sh',)),
    (b'#!/bin/sh',                      0, ('.sh',)),
    # Certificates / keys
    (b'-----BEGIN',                     0, ('.pem', '.crt', '.key', '.csr')),
]

READ_SIZE = 512


@dataclass
class SignatureResult:
    path: str
    declared_ext: str
    detected_exts: tuple[str, ...]
    magic_hex: str
    mismatch: bool
    note: str


def _read_header(path: str) -> bytes:
    try:
        with open(path, 'rb') as f:
            return f.read(READ_SIZE)
    except (OSError, PermissionError):
        return b''


def _detect_type(header: bytes) -> tuple[str, ...]:
    for magic, offset, exts in MAGIC_DB:
        end = offset + len(magic)
        if len(header) >= end and header[offset:end] == magic:
            return exts
    return ()


def analyze_signature(path: str) -> SignatureResult:
    p = Path(path)
    header = _read_header(path)
    declared = p.suffix.lower()
    detected = _detect_type(header)
    magic_hex = header[:16].hex(' ') if header else ''

    mismatch = bool(detected) and declared not in detected
    note = ''
    if mismatch:
        note = f"Extension '{declared}' does not match detected type {detected}"
    elif not detected:
        note = "Signature unknown / plain text"

    return SignatureResult(
        path=str(p),
        declared_ext=declared,
        detected_exts=detected,
        magic_hex=magic_hex,
        mismatch=mismatch,
        note=note,
    )


def analyze_all(paths: list[str], progress_cb=None) -> list[SignatureResult]:
    results = []
    for path in paths:
        results.append(analyze_signature(path))
        if progress_cb:
            progress_cb(path)
    return results
