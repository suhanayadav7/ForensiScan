"""Shannon entropy analysis -- detects encrypted/packed/compressed files."""

import math
from dataclasses import dataclass

CHUNK = 1 << 16  # 64 KB read buffer


@dataclass
class EntropyResult:
    path: str
    entropy: float        # 0.0 (uniform) to 8.0 (perfectly random)
    is_high_entropy: bool  # True when entropy > 7.2
    note: str


def compute_entropy(path: str) -> EntropyResult:
    counts = [0] * 256
    total = 0
    try:
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK):
                for byte in chunk:
                    counts[byte] += 1
                total += len(chunk)
    except (OSError, PermissionError):
        return EntropyResult(path, 0.0, False, "Could not read file")
    if total == 0:
        return EntropyResult(path, 0.0, False, "Empty file")
    entropy = -sum(
        (c / total) * math.log2(c / total)
        for c in counts if c > 0
    )
    high = entropy > 7.2
    note = "Likely encrypted/packed/compressed" if high else "Normal entropy"
    return EntropyResult(path=path, entropy=round(entropy, 4), is_high_entropy=high, note=note)


def analyze_all(paths: list[str], progress_cb=None) -> list[EntropyResult]:
    results = []
    for path in paths:
        results.append(compute_entropy(path))
        if progress_cb:
            progress_cb(path)
    return results
