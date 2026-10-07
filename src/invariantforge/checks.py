"""Closed, deterministic enforcement engine."""

from __future__ import annotations

import ast
import fnmatch
from pathlib import Path
from typing import Literal

from invariantforge.gitops import dirty, git, resolve_commit, revision
from invariantforge.models import CheckReport, CheckResult, Invariant, Status
from invariantforge.scan import MAX_FILE_BYTES, inventory
from invariantforge.store import parse_policy


def _matches(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) or path == pattern for pattern in patterns)


def _call_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _call_name(node.value)
        return f"{parent}.{node.attr}" if parent else None
    return None


def _call_matches(
    node: ast.Call,
    target: str,
    keyword: str | None,
    value: bool | str | None,
    aliases: dict[str, str],
) -> Literal["match", "unknown", "none"]:
    name = _call_name(node.func)
    if name is None:
        return "none"
    prefix, _, suffix = name.partition(".")
    canonical = aliases.get(prefix, prefix) + (f".{suffix}" if suffix else "")
    if canonical != target:
        return "none"
    if keyword is None:
        return "match"
    unknown = False
    for kw in node.keywords:
        if kw.arg == keyword:
            if value is None:
                return "match"
            if isinstance(kw.value, ast.Constant):
                return "match" if kw.value.value == value else "none"
            return "unknown"
        if kw.arg is None:
            if isinstance(kw.value, ast.Dict):
                for key, entry in zip(kw.value.keys, kw.value.values, strict=True):
                    if isinstance(key, ast.Constant) and key.value == keyword:
                        if value is None:
                            return "match"
                        if isinstance(entry, ast.Constant):
                            return "match" if entry.value == value else "none"
                        return "unknown"
                if any(not isinstance(key, ast.Constant) for key in kw.value.keys):
                    unknown = True
            else:
                unknown = True
    return "unknown" if unknown else "none"


def check_one(
    root: Path,
    item: Invariant,
    known_files: list[str] | None = None,
    omissions: dict[str, str] | None = None,
    truncated: bool = False,
) -> CheckResult:
    if item.status != Status.approved:
        raise ValueError("only approved invariants can be checked")
    if not item.approved_and_intact():
        return CheckResult(
            id=item.id, outcome="fail", detail="approved rule changed since approval"
        )
    rule = item.enforcement
    if rule is None:
        return CheckResult(id=item.id, outcome="unenforced", detail="no enforcement rule")
    if rule.strategy == "path_exists":
        candidate = root / rule.target
        if candidate.is_symlink() or not candidate.resolve().is_relative_to(root.resolve()):
            return CheckResult(
                id=item.id, outcome="fail", detail="required path escapes repository"
            )
        return CheckResult(
            id=item.id,
            outcome="pass" if candidate.is_file() else "fail",
            detail=f"required path: {rule.target}",
            files_checked=1,
        )
    if known_files is None:
        data = inventory(root)
        known_files, omissions = data.files, data.omitted_files
        truncated = data.truncated
    if truncated:
        return CheckResult(
            id=item.id,
            outcome="not_assessed",
            detail="repository inventory exceeded a safety limit",
        )
    matched = [path for path in known_files if _matches(path, item.scope)]
    relevant_omissions = {
        path: reason for path, reason in (omissions or {}).items() if _matches(path, item.scope)
    }
    if relevant_omissions:
        return CheckResult(
            id=item.id,
            outcome="not_assessed",
            detail=f"scope contains omitted files: {relevant_omissions}",
        )
    if not matched:
        return CheckResult(
            id=item.id, outcome="not_assessed", detail="scope matches no readable files"
        )
    hits: list[str] = []
    unknown_calls: list[str] = []
    inspected = 0
    for rel in matched:
        path = root / rel
        try:
            if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
                return CheckResult(id=item.id, outcome="not_assessed", detail=f"unsafe file: {rel}")
            if path.stat().st_size > MAX_FILE_BYTES:
                return CheckResult(
                    id=item.id, outcome="not_assessed", detail=f"oversized file: {rel}"
                )
            raw = path.read_bytes()
            if b"\x00" in raw[:4096]:
                return CheckResult(id=item.id, outcome="not_assessed", detail=f"binary file: {rel}")
            source = raw.decode("utf-8")
        except (OSError, UnicodeError):
            return CheckResult(id=item.id, outcome="not_assessed", detail=f"unreadable file: {rel}")
        inspected += 1
        if rule.strategy == "text_not_contain":
            if rule.target in source:
                hits.append(rel)
            continue
        if not rel.endswith(".py"):
            return CheckResult(
                id=item.id, outcome="not_assessed", detail=f"non-Python file in Python rule: {rel}"
            )
        try:
            tree = ast.parse(source, filename=rel)
        except SyntaxError:
            return CheckResult(
                id=item.id, outcome="not_assessed", detail=f"Python parse failed: {rel}"
            )
        aliases: dict[str, str] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                aliases.update({alias.asname or alias.name: alias.name for alias in node.names})
            elif isinstance(node, ast.ImportFrom) and node.module:
                aliases.update(
                    {
                        alias.asname or alias.name: f"{node.module}.{alias.name}"
                        for alias in node.names
                    }
                )
        nodes: list[ast.AST] = [tree]
        if rule.function:
            nodes = [
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.name == rule.function
            ]
            if not nodes:
                return CheckResult(
                    id=item.id,
                    outcome="not_assessed",
                    detail=f"function {rule.function} absent in {rel}",
                )
        found: list[int] = []
        unresolved: list[int] = []
        for parent in nodes:
            for node in ast.walk(parent):
                if not isinstance(node, ast.Call):
                    continue
                match = _call_matches(node, rule.target, rule.keyword, rule.keyword_value, aliases)
                if match == "match":
                    found.append(node.lineno)
                elif match == "unknown":
                    unresolved.append(node.lineno)
        if rule.strategy == "python_no_call" and found:
            hits.extend(f"{rel}:{line}" for line in found[:5])
        elif rule.strategy == "python_required_call" and not found and not unresolved:
            hits.append(rel)
        unknown_calls.extend(f"{rel}:{line}" for line in unresolved[:5])
    if hits:
        detail = (
            (
                "forbidden match"
                if rule.strategy != "python_required_call"
                else "required call missing"
            )
            + ": "
            + ", ".join(hits[:10])
        )
        return CheckResult(id=item.id, outcome="fail", detail=detail, files_checked=inspected)
    if unknown_calls:
        return CheckResult(
            id=item.id,
            outcome="not_assessed",
            detail="dynamic call arguments at " + ", ".join(unknown_calls[:10]),
            files_checked=inspected,
        )
    outcome: Literal["pass", "partial"] = (
        "pass" if item.enforcement_strength == "strong" else "partial"
    )
    return CheckResult(
        id=item.id,
        outcome=outcome,
        detail=f"rule satisfied in {inspected} file(s); strength: {item.enforcement_strength}",
        files_checked=inspected,
    )


def run(root: Path, items: list[Invariant]) -> CheckReport:
    data = inventory(root)
    results = [
        check_one(root, item, data.files, data.omitted_files, data.truncated)
        for item in items
        if item.status == Status.approved
    ]
    return CheckReport(revision=revision(root), dirty=dirty(root), results=results)


def baseline_result(root: Path, current: list[Invariant], ref: str) -> CheckResult | None:
    """Detect removed or modified approved rules against a trusted ref."""
    sha = resolve_commit(root, ref)
    baseline_bytes = git(
        root, "show", f"{sha}:.invariantforge/invariants.yaml", max_bytes=2_000_000
    )
    baseline = parse_policy(baseline_bytes.decode("utf-8"))
    expected = {item.id: item.rule_digest() for item in baseline if item.approved_and_intact()}
    actual = {item.id: item.rule_digest() for item in current if item.approved_and_intact()}
    changed = sorted(id_ for id_, digest in expected.items() if actual.get(id_) != digest)
    if not changed:
        return None
    return CheckResult(
        id="POLICY-BASELINE",
        outcome="fail",
        detail=f"approved rules removed or changed since {sha[:12]}: {', '.join(changed)}",
    )
