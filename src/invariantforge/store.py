"""Versioned YAML persistence. Policy writes are atomic."""

from __future__ import annotations

import json
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import yaml
from pydantic import ValidationError

from invariantforge.models import Invariant, Proposal, Status
from invariantforge.paths import UnsafePathError, owned_path


class PolicyError(ValueError):
    pass


def policy_path(root: Path) -> Path:
    try:
        return owned_path(root, ".invariantforge/invariants.yaml")
    except UnsafePathError as exc:
        raise PolicyError(str(exc)) from exc


def parse_policy(content: str) -> list[Invariant]:
    try:
        raw = yaml.safe_load(content)
        if not isinstance(raw, dict) or raw.get("schema_version") != 1:
            raise PolicyError("unsupported or malformed policy schema")
        items = raw.get("invariants")
        if not isinstance(items, list) or len(items) > 500:
            raise PolicyError("invariants must be a bounded list")
        parsed = [Invariant.model_validate(item) for item in items]
        if len({item.id for item in parsed}) != len(parsed):
            raise PolicyError("duplicate invariant IDs")
        return parsed
    except (yaml.YAMLError, UnicodeError, ValidationError, TypeError) as exc:
        raise PolicyError(f"invalid invariants.yaml: {exc}") from exc


def load(root: Path) -> list[Invariant]:
    path = policy_path(root)
    if not path.exists():
        raise PolicyError("run 'invariantforge init' first")
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 2_000_000:
        raise PolicyError("unsafe or oversized invariants.yaml")
    try:
        return parse_policy(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError) as exc:
        raise PolicyError("could not read invariants.yaml") from exc


def save(root: Path, items: list[Invariant]) -> None:
    path = policy_path(root)
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists() and path.is_symlink():
        raise PolicyError("refusing to replace symlinked policy")
    data = {"schema_version": 1, "invariants": [item.model_dump(mode="json") for item in items]}
    content = yaml.safe_dump(data, sort_keys=False, allow_unicode=True)
    fd, name = tempfile.mkstemp(prefix=".invariants-", suffix=".yaml", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(content)
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def next_id(items: list[Invariant]) -> str:
    return f"INV-{max((int(item.id[4:]) for item in items), default=0) + 1:03d}"


def add_proposals(root: Path, proposals: list[Proposal]) -> list[Invariant]:
    items = load(root)

    def key(item: Invariant) -> str:
        return json.dumps(
            {
                "title": item.title,
                "category": item.category,
                "scope": item.scope,
                "statement": item.statement,
                "enforcement": item.enforcement.model_dump(mode="json")
                if item.enforcement
                else None,
            },
            sort_keys=True,
        )

    existing = {key(item) for item in items}
    added: list[Invariant] = []
    for proposal in proposals:
        item = Invariant(id=next_id(items), **proposal.model_dump())
        if key(item) not in existing:
            items.append(item)
            added.append(item)
            existing.add(key(item))
    if added:
        save(root, items)
    return added


def transition(root: Path, invariant_id: str, target: Status) -> Invariant:
    items = load(root)
    item = next((value for value in items if value.id == invariant_id), None)
    if item is None:
        raise PolicyError(f"unknown invariant: {invariant_id}")
    allowed = {
        Status.proposed: {Status.approved, Status.rejected},
        Status.approved: {Status.deprecated},
    }
    if target not in allowed.get(item.status, set()):
        raise PolicyError(f"cannot change {item.status} to {target}")
    if target == Status.approved:
        if item.enforcement is None:
            raise PolicyError("approval requires a concrete enforcement rule")
        item.approval_digest = item.rule_digest()
    item.status = target
    item.updated_at = datetime.now(UTC)
    save(root, items)
    return item
