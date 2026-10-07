from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from invariantforge.models import Enforcement, Invariant, Proposal, Status
from invariantforge.store import PolicyError, add_proposals, load, save, transition


def proposal() -> Proposal:
    return Proposal(
        title="Subprocess calls must not enable a shell",
        description="Shell syntax must not reinterpret caller arguments.",
        category="subprocess",
        scope=["*.py"],
        statement="No subprocess.run call enables a shell.",
        enforcement=Enforcement(
            strategy="python_no_call",
            target="subprocess.run",
            keyword="shell",
            keyword_value=True,
        ),
    )


def test_schema_rejects_path_traversal_and_extra_fields() -> None:
    with pytest.raises(ValidationError):
        Invariant(
            id="BAD-1",
            title="A valid title",
            description="Long enough description",
            category="filesystem",
            scope=["src/**"],
            statement="Long enough statement",
        )
    with pytest.raises(ValidationError):
        Invariant(
            id="INV-001",
            scope=["../secret"],
            title="A valid title",
            description="Long enough description",
            category="filesystem",
            statement="Long enough statement",
        )
    with pytest.raises(ValidationError):
        Enforcement(strategy="path_exists", target="../secret")
    with pytest.raises(ValidationError):
        Enforcement(strategy="path_exists", target="C:\\outside.txt")
    with pytest.raises(ValidationError):
        Proposal.model_validate({**proposal().model_dump(), "status": "approved"})
    with pytest.raises(ValidationError):
        Proposal.model_validate({**proposal().model_dump(), "enforcement_strength": "strong"})
    with pytest.raises(ValidationError):
        Proposal.model_validate({**proposal().model_dump(), "sources": ["../outside"]})


def test_id_lifecycle_digest_and_dedup(repo: Path) -> None:
    save(repo, [])
    assert [item.id for item in add_proposals(repo, [proposal(), proposal()])] == ["INV-001"]
    assert add_proposals(repo, [proposal()]) == []
    same_rule = proposal()
    same_rule.sources = ["new-source.py"]
    assert add_proposals(repo, [same_rule]) == []
    item = transition(repo, "INV-001", Status.approved)
    assert item.approved_and_intact()
    with pytest.raises(PolicyError):
        transition(repo, "INV-001", Status.rejected)
    items = load(repo)
    items[0].statement = "Another statement with changed security meaning"
    save(repo, items)
    assert not load(repo)[0].approved_and_intact()


def test_reject_missing_enforcement_and_malformed_yaml(repo: Path) -> None:
    save(repo, [])
    plain = proposal()
    plain.enforcement = None
    add_proposals(repo, [plain])
    with pytest.raises(PolicyError, match="concrete"):
        transition(repo, "INV-001", Status.approved)
    (repo / ".invariantforge" / "invariants.yaml").write_text("schema_version: [broken\n")
    with pytest.raises(PolicyError, match="invalid"):
        load(repo)
