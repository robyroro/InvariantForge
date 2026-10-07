from __future__ import annotations

from pathlib import Path

import pytest
from conftest import git
from typer.testing import CliRunner

from invariantforge.checks import baseline_result, run
from invariantforge.cli import app
from invariantforge.gitops import GitError
from invariantforge.models import Enforcement, Invariant, Status
from invariantforge.store import save, transition


def test_removed_approved_rule_fails_against_baseline(repo: Path) -> None:
    item = Invariant(
        id="INV-001",
        title="Subprocess calls must not enable a shell",
        description="Shell syntax must not reinterpret caller arguments.",
        category="subprocess",
        scope=["app.py"],
        statement="No subprocess.run call enables a shell.",
        enforcement=Enforcement(strategy="python_no_call", target="subprocess.run"),
    )
    save(repo, [item])
    transition(repo, item.id, Status.approved)
    git(repo, "add", ".invariantforge/invariants.yaml")
    git(repo, "commit", "-qm", "approve policy")
    baseline = git(repo, "rev-parse", "HEAD")
    save(repo, [])
    assert run(repo, []).failed  # an empty policy is never a clean check
    result = baseline_result(repo, [], baseline)
    assert result is not None
    assert result.outcome == "fail"
    assert "INV-001" in result.detail
    checked = CliRunner().invoke(
        app,
        ["check", "--path", str(repo), "--allow-empty", "--baseline-ref", baseline],
    )
    assert checked.exit_code == 1
    with pytest.raises(GitError):
        baseline_result(repo, [], "--help")
