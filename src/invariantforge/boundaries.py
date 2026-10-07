"""Conservative, evidence-backed classification of changed paths and lines."""

from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass
from pathlib import Path

from invariantforge.gitops import GitError, git, resolve_commit
from invariantforge.models import Invariant, Status
from invariantforge.scan import redact

CATEGORIES: dict[str, re.Pattern[str]] = {
    "authentication": re.compile(r"auth|login|session|jwt|oauth|token|password", re.I),
    "authorization": re.compile(r"permi|authoriz|role|admin|approv|privileg", re.I),
    "filesystem": re.compile(r"path|file|open\(|unlink|remove\(|read_text|write_text|upload", re.I),
    "network": re.compile(r"https?://|request|fetch|socket|urllib|httpx|egress|redirect", re.I),
    "secrets": re.compile(r"secret|api_key|credential|private.key|bearer", re.I),
    "subprocess": re.compile(r"subprocess|shell=true|popen|exec\(|eval\(|os\.system", re.I),
    "mcp": re.compile(r"mcp|tool.call|tool.register|mutat", re.I),
    "sandbox": re.compile(r"sandbox|container|privileged|cap_add|seccomp", re.I),
    "cryptography": re.compile(r"crypt|cipher|hash|signatur|verify", re.I),
    "dependency": re.compile(
        r"pyproject|lock|requirements|package.json|cargo.toml|composer.json|setup.py", re.I
    ),
    "ci": re.compile(
        r"\.github/workflows|permissions:|pull_request_target|workflow_dispatch", re.I
    ),
    "webhook": re.compile(r"webhook|postback|callback|hmac", re.I),
    "serialization": re.compile(r"pickle|deserialize|yaml\.load|json\.loads|parse", re.I),
    "repository_policy": re.compile(r"\.gitignore|\.invariantforge/invariants\.yaml", re.I),
}


@dataclass
class Finding:
    path: str
    change: str
    categories: list[str]
    invariant_ids: list[str]
    certainty: str
    evidence: str

    def as_dict(self) -> dict[str, object]:
        return {
            "path": self.path,
            "change": self.change,
            "categories": self.categories,
            "invariant_ids": self.invariant_ids,
            "certainty": self.certainty,
            "evidence": self.evidence,
        }


def _diff_args(root: Path, base: str | None, head: str | None) -> list[str]:
    if base is None and head is None:
        return ["HEAD"]
    if base is None or head is None:
        raise GitError("provide both base and head revisions")
    return [resolve_commit(root, base), resolve_commit(root, head)]


def analyze(
    root: Path, items: list[Invariant], base: str | None = None, head: str | None = None
) -> tuple[list[Finding], list[str]]:
    refs = _diff_args(root, base, head)
    flags = ["--no-ext-diff", "--no-textconv", "--no-color", "--find-renames"]
    raw = git(root, "diff", *flags, "--name-status", "-z", *refs, "--")
    parts = raw.decode("utf-8", "replace").split("\x00")
    changes: list[tuple[str, str]] = []
    i = 0
    while i < len(parts) - 1:
        status = parts[i]
        i += 1
        if not status:
            break
        if status[0] in {"R", "C"}:
            if i + 1 >= len(parts):
                raise GitError("malformed rename in git diff")
            old, new = parts[i], parts[i + 1]
            changes.extend([(old, "renamed_from"), (new, "renamed_to")])
            i += 2
        else:
            changes.append(
                (parts[i], {"A": "added", "D": "deleted", "M": "modified"}.get(status[0], status))
            )
            i += 1
    warnings: list[str] = []
    if any(path.endswith(".gitignore") for path, _ in changes):
        warnings.append("ignore rules changed; ignored working-tree files are not assessed")
    if base is None:
        untracked = git(root, "ls-files", "--others", "--exclude-standard", "-z").decode(
            "utf-8", "replace"
        )
        for path in filter(None, untracked.split("\x00")):
            changes.append((path, "untracked"))
            warnings.append("untracked files are classified by path only")
    try:
        patch = git(root, "diff", *flags, "--unified=0", *refs, "--", max_bytes=500_000).decode(
            "utf-8", "replace"
        )
    except GitError:
        patch = ""
        warnings.append("patch exceeded limit or could not be read; line content not assessed")
    if "Binary files " in patch or "GIT binary patch" in patch:
        warnings.append("binary diff content not assessed")
    chunks: dict[str, list[str]] = {}
    current: str | None = None
    for line in patch.splitlines():
        if line.startswith("diff --git "):
            current = None
        elif line.startswith("--- a/"):
            current = line[6:]
        elif line.startswith("+++ b/"):
            current = line[6:]
        elif (
            current
            and (line.startswith("+") or line.startswith("-"))
            and not line.startswith(("+++", "---"))
        ):
            chunks.setdefault(current, []).append(redact(line))
    findings: list[Finding] = []
    for path, change in changes:
        lines = chunks.get(path, [])
        corpus = path + "\n" + "\n".join(lines)
        categories = sorted(
            category for category, pattern in CATEGORIES.items() if pattern.search(corpus)
        )
        mapped = sorted(
            item.id
            for item in items
            if item.status == Status.approved
            and (
                any(fnmatch.fnmatchcase(path, scope) or path == scope for scope in item.scope)
                or item.category in categories
                or bool(set(item.boundaries) & set(categories))
            )
        )
        if not categories and not mapped and change in {"added", "modified"}:
            continue
        evidence = next(
            (
                line
                for line in lines
                if any(pattern.search(line) for pattern in CATEGORIES.values())
            ),
            "path or metadata changed",
        )
        findings.append(
            Finding(redact(path), change, categories, mapped, "possible", evidence[:300])
        )
    return findings, sorted(set(warnings))
