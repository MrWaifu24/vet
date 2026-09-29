"""Writing extracted artifacts to disk safely."""

from __future__ import annotations

import re
from pathlib import Path

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def safe_name(name: str, default: str = "artifact") -> str:
    """Reduce an attacker-controlled name to a harmless basename."""
    base = name.replace("\\", "/").rsplit("/", 1)[-1]
    base = _UNSAFE.sub("_", base).strip("._")
    return base[:120] or default


class Extractor:
    """Saves artifacts under <dir>/<sample-name>/, never overwriting existing files.

    Extracted payloads get a ``.vet`` suffix appended so they cannot be
    launched by double-clicking.
    """

    def __init__(self, root: Path | None, sample: Path):
        self.dir = root / safe_name(sample.name, "sample") if root else None

    @property
    def enabled(self) -> bool:
        return self.dir is not None

    def save(self, name: str, data: bytes, defang: bool = True) -> str | None:
        if self.dir is None:
            return None
        self.dir.mkdir(parents=True, exist_ok=True)
        filename = safe_name(name)
        if defang:
            filename += ".vet"
        target = self.dir / filename
        stem, n = target.name, 1
        while target.exists():
            target = self.dir / f"{n}_{stem}"
            n += 1
        target.write_bytes(data)
        return str(target)
