"""Small reproducible result bundles without source excerpts."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from invariantforge import __version__
from invariantforge.checks import run
from invariantforge.models import CheckReport, Invariant
from invariantforge.paths import owned_path
from invariantforge.store import policy_path


def _canonical(value: object) -> bytes:
    return (
        json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False) + "\n"
    ).encode()


def _hash(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def prove(
    root: Path, items: list[Invariant], output: Path | None = None
) -> tuple[Path, CheckReport]:
    report = run(root, items)
    stamp = datetime.now(UTC).strftime("%Y-%m-%dT%H%M%SZ")
    directory = output or owned_path(root, f".invariantforge/evidence/{stamp}")
    directory = directory.resolve()
    directory.mkdir(parents=True, exist_ok=False)
    results = report.model_dump(mode="json")
    policy = policy_path(root).read_bytes()
    manifest = {
        "schema_version": 1,
        "tool_version": __version__,
        "created_at": datetime.now(UTC).isoformat(),
        "revision": report.revision,
        "dirty": report.dirty,
        "approved_rules": {
            item.id: item.rule_digest() for item in items if item.approved_and_intact()
        },
        "policy_sha256": _hash(policy),
        "result_sha256": _hash(_canonical(results)),
        "limits": {"max_files": 2500, "max_file_bytes": 128000},
        "note": ("Hashes bind results to policy bytes; they are not a signature or formal proof."),
    }
    summary = [
        "# InvariantForge evidence",
        "",
        f"Revision: {report.revision or 'none'}",
        f"Dirty: {report.dirty}",
        "",
    ]
    summary.extend(f"- {item.id}: {item.outcome} ({item.detail})" for item in report.results)
    for name, blob in {
        "manifest.json": _canonical(manifest),
        "results.json": _canonical(results),
        "summary.md": ("\n".join(summary) + "\n").encode(),
    }.items():
        (directory / name).write_bytes(blob)
    hashes = {
        name: _hash((directory / name).read_bytes())
        for name in ("manifest.json", "results.json", "summary.md")
    }
    (directory / "hashes.json").write_bytes(_canonical(hashes))
    return directory, report
