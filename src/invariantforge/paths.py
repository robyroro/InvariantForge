"""Containment for InvariantForge-owned output paths."""

from __future__ import annotations

from pathlib import Path


class UnsafePathError(ValueError):
    pass


def owned_path(root: Path, relative: str) -> Path:
    base = root.resolve(strict=True)
    candidate = base / relative
    if not candidate.resolve().is_relative_to(base):
        raise UnsafePathError(f"output path escapes repository: {relative}")
    current = candidate
    while current != base:
        if current.is_symlink():
            raise UnsafePathError(f"symlinked output path: {relative}")
        current = current.parent
    return candidate
