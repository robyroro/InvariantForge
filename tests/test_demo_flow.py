from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from invariantforge.cli import app

runner = CliRunner()


def command(repo: Path, *args: str) -> tuple[int, str]:
    result = runner.invoke(app, [*args, "--path", str(repo)])
    return result.exit_code, result.output


def test_full_offline_demo_flow(repo: Path) -> None:
    assert command(repo, "init")[0] == 0
    assert command(repo, "discover", "--provider", "static")[0] == 0
    assert command(repo, "show", "INV-001")[0] == 0
    assert command(repo, "approve", "INV-001")[0] == 0
    assert command(repo, "generate")[0] == 0
    clean_code, clean_output = command(repo, "check", "--format", "json")
    assert clean_code == 0
    assert json.loads(clean_output)["results"][0]["outcome"] == "partial"

    (repo / "app.py").write_text("import subprocess\nsubprocess.run('echo unsafe', shell=True)\n")
    diff_code, diff_output = command(repo, "diff", "--format", "json")
    assert diff_code == 0
    findings = json.loads(diff_output)["findings"]
    assert any("INV-001" in finding["invariant_ids"] for finding in findings)
    broken_code, broken_output = command(repo, "check", "--format", "json")
    assert broken_code == 1
    assert json.loads(broken_output)["results"][0]["outcome"] == "fail"

    (repo / "app.py").write_text(
        "import subprocess\nsubprocess.run(['echo', 'safe'], check=True)\n"
    )
    assert command(repo, "check")[0] == 0
    output = repo / "security-evidence"
    prove_code, _ = command(repo, "prove", "--output", str(output))
    assert prove_code == 0
    assert (output / "manifest.json").exists()
