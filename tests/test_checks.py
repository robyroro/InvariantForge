from __future__ import annotations

from pathlib import Path

from invariantforge.checks import check_one, run
from invariantforge.models import Enforcement, Invariant, Status
from invariantforge.store import save, transition


def approved(repo: Path, scope: list[str], rule: Enforcement) -> Invariant:
    item = Invariant(
        id="INV-001",
        title="Subprocess calls must not enable a shell",
        description="Shell parsing must not reinterpret caller arguments.",
        category="subprocess",
        scope=scope,
        statement="No subprocess.run call enables a shell.",
        enforcement=rule,
    )
    save(repo, [item])
    return transition(repo, item.id, Status.approved)


def test_ast_check_detects_alias_and_literal_true(repo: Path) -> None:
    item = approved(
        repo,
        ["*.py"],
        Enforcement(
            strategy="python_no_call", target="subprocess.run", keyword="shell", keyword_value=True
        ),
    )
    assert check_one(repo, item).outcome == "partial"
    (repo / "app.py").write_text("import subprocess as sp\nsp.run('echo x', shell=True)\n")
    result = check_one(repo, item)
    assert result.outcome == "fail"
    assert "app.py:2" in result.detail
    (repo / "app.py").write_text(
        "from subprocess import run as launch\nlaunch('echo x', shell=True)\n"
    )
    assert check_one(repo, item).outcome == "fail"
    (repo / "app.py").write_text("import subprocess\nsubprocess.run('x', **{'shell': True})\n")
    assert check_one(repo, item).outcome == "fail"
    (repo / "app.py").write_text(
        "import subprocess\nsubprocess.run('x', **{'shell': False, 'shell': True})\n"
    )
    assert check_one(repo, item).outcome == "fail"
    (repo / "app.py").write_text("import subprocess\nsubprocess.run('x', **options)\n")
    assert check_one(repo, item).outcome == "not_assessed"
    (repo / "app.py").write_text(
        "import subprocess\nsubprocess.run('x', **{'shell': False, **options})\n"
    )
    assert check_one(repo, item).outcome == "not_assessed"


def test_omitted_scoped_file_is_not_assessed(repo: Path) -> None:
    item = approved(repo, ["*.py"], Enforcement(strategy="python_no_call", target="subprocess.run"))
    (repo / "huge.py").write_bytes(b"x" * 128_001)
    assert check_one(repo, item).outcome == "not_assessed"


def test_required_call_is_only_partial(repo: Path) -> None:
    item = approved(
        repo, ["app.py"], Enforcement(strategy="python_required_call", target="subprocess.run")
    )
    assert run(repo, [item]).results[0].outcome == "partial"
    (repo / "app.py").write_text("print('no call')\n")
    assert run(repo, [item]).results[0].outcome == "fail"


def test_path_exists_rejects_symlink(repo: Path, tmp_path: Path) -> None:
    item = approved(repo, ["app.py"], Enforcement(strategy="path_exists", target="app.py"))
    assert check_one(repo, item).outcome == "pass"
    (repo / "app.py").unlink()
    assert check_one(repo, item).outcome == "fail"
