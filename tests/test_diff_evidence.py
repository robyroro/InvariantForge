from __future__ import annotations

import json
from pathlib import Path

from conftest import git

from invariantforge.boundaries import analyze
from invariantforge.evidence import prove
from invariantforge.models import Enforcement, Invariant, Status
from invariantforge.store import save, transition


def policy(repo: Path) -> Invariant:
    item = Invariant(
        id="INV-001",
        title="Subprocess calls must not enable a shell",
        description="Shell parsing must not reinterpret caller arguments.",
        category="subprocess",
        scope=["*.py"],
        statement="No subprocess.run call enables a shell.",
        enforcement=Enforcement(
            strategy="python_no_call", target="subprocess.run", keyword="shell", keyword_value=True
        ),
    )
    save(repo, [item])
    return transition(repo, item.id, Status.approved)


def test_diff_maps_changed_boundary_and_rename(repo: Path) -> None:
    item = policy(repo)
    (repo / "app.py").write_text("import subprocess\nsubprocess.run('x', shell=True)\n")
    findings, warnings = analyze(repo, [item])
    assert warnings  # the new policy is untracked at this point
    assert findings[0].invariant_ids == ["INV-001"]
    assert "subprocess" in findings[0].categories
    git(repo, "add", ".")
    git(repo, "commit", "-qm", "change boundary")
    git(repo, "mv", "app.py", "runner.py")
    findings, _ = analyze(repo, [item])
    assert {finding.change for finding in findings} >= {"renamed_from", "renamed_to"}


def test_deleted_file_and_untracked_warning(repo: Path) -> None:
    item = policy(repo)
    (repo / "app.py").unlink()
    (repo / "new_auth.py").write_text("verify_token()\n")
    findings, warnings = analyze(repo, [item])
    assert any(finding.change == "deleted" for finding in findings)
    assert any(finding.change == "untracked" for finding in findings)
    assert warnings


def test_unclassified_deletion_and_late_sensitive_line(repo: Path) -> None:
    (repo / "plain.py").write_text("safe = True\n")
    git(repo, "add", "plain.py")
    git(repo, "commit", "-qm", "add plain file")
    (repo / "plain.py").unlink()
    findings, _ = analyze(repo, [])
    assert any(f.path == "plain.py" and f.change == "deleted" for f in findings)
    git(repo, "reset", "--hard", "HEAD")
    (repo / "plain.py").write_text("\n".join(["unchanged = 1"] * 120) + "\nsecret_token = 'x'\n")
    findings, _ = analyze(repo, [])
    assert any("secrets" in f.categories for f in findings)


def test_gitignore_change_is_review_target(repo: Path) -> None:
    (repo / ".gitignore").write_text("*.py\n")
    git(repo, "add", ".gitignore")
    findings, warnings = analyze(repo, [])
    assert any(f.path == ".gitignore" for f in findings)
    assert any("ignored" in warning for warning in warnings)


def test_binary_change_is_marked_unassessed(repo: Path) -> None:
    (repo / "binary.bin").write_bytes(b"\x00before")
    git(repo, "add", "binary.bin")
    git(repo, "commit", "-qm", "add binary")
    (repo / "binary.bin").write_bytes(b"\x00after")
    _, warnings = analyze(repo, [])
    assert any("binary" in warning for warning in warnings)


def test_secret_line_is_classified_before_redaction(repo: Path) -> None:
    (repo / "app.py").write_text("PASSWORD=topsecretvalue\n")
    findings, _ = analyze(repo, [])
    assert any("secrets" in finding.categories for finding in findings)
    assert "topsecretvalue" not in json.dumps([finding.as_dict() for finding in findings])


def test_evidence_has_no_source_content(repo: Path) -> None:
    item = policy(repo)
    output, report = prove(repo, [item], repo / "bundle")
    assert report.results[0].outcome == "partial"
    manifest = json.loads((output / "manifest.json").read_text())
    assert manifest["approved_rules"] == {"INV-001": item.rule_digest()}
    assert len(manifest["policy_sha256"]) == 64
    assert "subprocess.run(['true']" not in "".join(p.read_text() for p in output.iterdir())
