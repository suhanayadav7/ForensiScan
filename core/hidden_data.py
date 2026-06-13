"""Hidden data detection — NTFS ADS, hidden/system files, suspicious attributes."""

import os
import ctypes
import platform
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional
from .metadata import FileMetadata

IS_WINDOWS = platform.system() == 'Windows'


@dataclass
class AltDataStream:
    host_file: str
    stream_name: str
    size: int


@dataclass
class HiddenDataResult:
    meta: FileMetadata
    ads_streams: list[AltDataStream] = field(default_factory=list)
    suspicion_flags: list[str] = field(default_factory=list)

    @property
    def is_suspicious(self) -> bool:
        return bool(self.ads_streams) or bool(self.suspicion_flags)


# ── NTFS ADS via Windows API ─────────────────────────────────────────────────

class _WIN32_FIND_STREAM_DATA(ctypes.Structure):
    _fields_ = [
        ('StreamSize', ctypes.c_longlong),
        ('cStreamName', ctypes.c_wchar * 296),
    ]


def _enumerate_ads_windows(path: str) -> list[AltDataStream]:
    streams: list[AltDataStream] = []
    k32 = ctypes.windll.kernel32
    INVALID = ctypes.c_void_p(-1).value

    data = _WIN32_FIND_STREAM_DATA()
    handle = k32.FindFirstStreamW(path, 0, ctypes.byref(data), 0)

    if handle == INVALID:
        return streams

    try:
        while True:
            name = data.cStreamName
            if name and name != '::$DATA':
                streams.append(AltDataStream(
                    host_file=path,
                    stream_name=name,
                    size=data.StreamSize,
                ))
            if not k32.FindNextStreamW(handle, ctypes.byref(data)):
                break
    finally:
        k32.FindClose(handle)

    return streams


def enumerate_ads(path: str) -> list[AltDataStream]:
    if not IS_WINDOWS:
        return []
    try:
        return _enumerate_ads_windows(path)
    except Exception:
        return []


# ── Suspicion heuristics ──────────────────────────────────────────────────────

_DOUBLE_EXT = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.ps1', '.com'}
_RISKY_EXT  = {'.exe', '.dll', '.scr', '.bat', '.cmd', '.vbs', '.ps1',
               '.com', '.jar', '.py', '.rb', '.lnk', '.hta', '.js', '.jse'}


def _suspicion_flags(meta: FileMetadata) -> list[str]:
    flags: list[str] = []
    p = Path(meta.path)

    if meta.is_hidden and meta.is_system:
        flags.append("Hidden + System attributes set")

    # Double extension: file.txt.exe
    suffixes = p.suffixes
    if len(suffixes) >= 2 and suffixes[-1].lower() in _DOUBLE_EXT:
        flags.append(f"Double extension detected: {''.join(suffixes)}")

    # Executable in temp or unusual location
    lower_path = meta.path.lower()
    for tmp in ('\\temp\\', '\\tmp\\', '\\appdata\\local\\temp\\', '/tmp/', '/var/tmp/'):
        if tmp in lower_path and meta.extension in _RISKY_EXT:
            flags.append(f"Executable in temp directory: {tmp}")
            break

    # Zero-byte file with executable extension
    if meta.size == 0 and meta.extension in _RISKY_EXT:
        flags.append("Zero-byte executable")

    # Very large file with text extension
    if meta.size > 100 * 1024 * 1024 and meta.extension in ('.txt', '.log', '.csv'):
        flags.append(f"Unusually large text file ({meta.size // (1024*1024)} MB)")

    return flags


def analyze_file(meta: FileMetadata) -> HiddenDataResult:
    return HiddenDataResult(
        meta=meta,
        ads_streams=enumerate_ads(meta.path),
        suspicion_flags=_suspicion_flags(meta),
    )


def analyze_all(metas: list[FileMetadata], progress_cb=None) -> list[HiddenDataResult]:
    results = []
    for meta in metas:
        results.append(analyze_file(meta))
        if progress_cb:
            progress_cb(meta.path)
    return results


def filter_suspicious(results: list[HiddenDataResult]) -> list[HiddenDataResult]:
    return [r for r in results if r.is_suspicious]
