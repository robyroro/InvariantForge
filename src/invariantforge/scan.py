"""Bounded, read-only repository inventory and context selection."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from pathlib import Path

MAX_FILES = 2500
MAX_WALK_ENTRIES = 10_000
MAX_FILE_BYTES = 128_000
MAX_CONTEXT_BYTES = 80_000
SKIP_DIRS = {
    ".git",
    ".invariantforge",
    ".venv",
    "venv",
    "node_modules",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}
SKIP_NAMES = re.compile(
    r"(^\.git$|^\.env(?:\.|$)|\.pem$|\.key$|credentials|secrets|\.p12$|\.pfx$)", re.I
)
SIGNALS = re.compile(
    r"auth|permission|approv|sandbox|secret|token|crypt|webhook|upload|middleware|"
    r"subprocess|shell|request|fetch|socket|network|filesystem|path|mcp|security|threat|"
    r"architecture|workflow|docker|policy",
    re.I,
)
REDACTIONS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\b(?:gh[pousr][_-]|github_pat[_-]|sk-proj-|sk-)[A-Za-z0-9_-]{12,}\b"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/-]{12,}"),
    re.compile(
        r"(?i)\b[A-Z0-9_]*(?:PASSWORD|SECRET|TOKEN|KEY|CREDENTIAL)"
        r"[A-Z0-9_]*\s*[:=]\s*['\"]?[^\s'\"]{4,}"
    ),
    re.compile(r"(?i)\b(?:postgres|mysql|mongodb)://[^\s@]+@"),
]


def redact(text: str) -> str:
    for pattern in REDACTIONS:
        text = pattern.sub("[REDACTED]", text)
    return text


@dataclass
class Inventory:
    files: list[str] = field(default_factory=list)
    omitted: dict[str, int] = field(default_factory=dict)
    omitted_files: dict[str, str] = field(default_factory=dict)
    languages: list[str] = field(default_factory=list)
    package_managers: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)
    test_frameworks: list[str] = field(default_factory=list)
    ci: list[str] = field(default_factory=list)
    monorepo: bool = False
    truncated: bool = False

    def omit(self, reason: str, path: str | None = None) -> None:
        self.omitted[reason] = self.omitted.get(reason, 0) + 1
        if path is not None:
            self.omitted_files[path] = reason


def inventory(root: Path) -> Inventory:
    root = root.resolve(strict=True)
    result = Inventory()
    stack = [root]
    seen = 0
    while stack:
        base = stack.pop()
        entries: list[os.DirEntry[str]] = []
        try:
            with os.scandir(base) as iterator:
                for entry in iterator:
                    seen += 1
                    if seen > MAX_WALK_ENTRIES:
                        result.omit("walk_limit")
                        result.truncated = True
                        break
                    entries.append(entry)
        except OSError:
            result.omit("unreadable_directory", base.relative_to(root).as_posix())
            result.truncated = True
            continue
        if result.truncated:
            break
        children: list[Path] = []
        for entry in sorted(entries, key=lambda value: value.name):
            path = Path(entry.path)
            rel = path.relative_to(root).as_posix()
            if entry.is_symlink():
                result.omit("symlink_or_nonregular", rel)
                continue
            if entry.is_dir(follow_symlinks=False):
                if entry.name not in SKIP_DIRS:
                    children.append(path)
                continue
            if not entry.is_file(follow_symlinks=False):
                result.omit("symlink_or_nonregular", rel)
                continue
            name = entry.name
            if SKIP_NAMES.search(name):
                result.omit("sensitive_name", rel)
                continue
            try:
                size = entry.stat(follow_symlinks=False).st_size
            except (OSError, ValueError):
                result.omit("unreadable", rel)
                continue
            if size > MAX_FILE_BYTES:
                result.omit("oversized", rel)
                continue
            if len(result.files) >= MAX_FILES:
                result.omit("file_limit")
                result.truncated = True
                break
            result.files.append(rel)
        if result.truncated:
            break
        stack.extend(reversed(children))
    names = set(result.files)
    present = names | set(result.omitted_files)
    suffixes = {Path(p).suffix for p in names}
    result.languages = [
        label
        for suffix, label in [
            (".py", "Python"),
            (".ts", "TypeScript"),
            (".js", "JavaScript"),
            (".rs", "Rust"),
            (".go", "Go"),
            (".php", "PHP"),
        ]
        if suffix in suffixes
    ]
    result.package_managers = [
        label
        for marker, label in [
            ("uv.lock", "uv"),
            ("pyproject.toml", "Python packaging"),
            ("package-lock.json", "npm"),
            ("pnpm-lock.yaml", "pnpm"),
            ("yarn.lock", "Yarn"),
            ("Cargo.lock", "Cargo"),
            ("composer.lock", "Composer"),
        ]
        if marker in present
    ]
    result.frameworks = [
        label
        for marker, label in [
            ("manage.py", "Django"),
            ("artisan", "Laravel"),
            ("next.config.js", "Next.js"),
            ("next.config.ts", "Next.js"),
        ]
        if marker in present
    ]
    result.test_frameworks = [
        label
        for marker, label in [
            ("pytest.ini", "pytest"),
            ("vitest.config.ts", "Vitest"),
            ("jest.config.js", "Jest"),
        ]
        if marker in present
    ]
    if "pyproject.toml" in names and "pytest" not in result.test_frameworks:
        try:
            if "pytest" in (root / "pyproject.toml").read_text(encoding="utf-8"):
                result.test_frameworks.append("pytest")
        except (OSError, UnicodeError):
            pass
    result.ci = ["GitHub Actions"] if any(p.startswith(".github/workflows/") for p in names) else []
    result.monorepo = (
        sum(
            p.endswith(("pyproject.toml", "package.json", "Cargo.toml", "composer.json"))
            for p in present
        )
        > 1
    )
    return result


def context(root: Path, data: Inventory) -> tuple[list[dict[str, str]], dict[str, int]]:
    """Return bounded, redacted source excerpts as data, never instructions."""
    selected: list[dict[str, str]] = []
    omissions = dict(data.omitted)
    used = 0
    ranked = sorted(
        data.files,
        key=lambda p: (
            0 if p.lower().endswith(("security.md", "threat-model.md", "architecture.md")) else 1,
            0 if SIGNALS.search(p) else 1,
            p,
        ),
    )
    for rel in ranked:
        if not SIGNALS.search(rel) and len(selected) >= 20:
            continue
        path = root / rel
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                omissions["symlink_or_escape"] = omissions.get("symlink_or_escape", 0) + 1
                continue
            raw = path.read_bytes()
            if b"\x00" in raw[:4096]:
                omissions["binary"] = omissions.get("binary", 0) + 1
                continue
            content = redact(raw.decode("utf-8"))
        except (OSError, UnicodeError):
            omissions["unreadable"] = omissions.get("unreadable", 0) + 1
            continue
        excerpt = content[:5000]
        cost = len(excerpt.encode("utf-8"))
        if used + cost > MAX_CONTEXT_BYTES:
            omissions["context_limit"] = omissions.get("context_limit", 0) + 1
            continue
        selected.append({"path": redact(rel), "content": excerpt})
        used += cost
        if len(selected) >= 50:
            omissions["context_file_limit"] = omissions.get("context_file_limit", 0) + 1
            break
    return selected, omissions
