from __future__ import annotations

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from invariantforge.cli import app
from invariantforge.models import BoundaryReview
from invariantforge.providers import DaybreakProvider, ProviderError, StaticProvider
from invariantforge.scan import inventory

runner = CliRunner()


def test_offline_cli_lifecycle(repo: Path) -> None:
    for args in (["init"], ["discover"], ["list"], ["approve", "INV-001"], ["generate"]):
        result = runner.invoke(app, [*args, "--path", str(repo)])
        assert result.exit_code == 0, result.output
    result = runner.invoke(app, ["check", "--path", str(repo), "--format", "json"])
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["results"][0]["outcome"] == "partial"
    assert (repo / "tests" / "security" / "test_invariantforge_generated.py").exists()


def test_cli_invalid_policy_exits_two(repo: Path) -> None:
    result = runner.invoke(app, ["check", "--path", str(repo)])
    assert result.exit_code == 2


def test_allow_empty_only_applies_before_approval(repo: Path) -> None:
    assert runner.invoke(app, ["init", "--path", str(repo)]).exit_code == 0
    empty = runner.invoke(app, ["check", "--path", str(repo), "--allow-empty"])
    assert empty.exit_code == 0
    assert "no enforcement" in empty.output
    assert runner.invoke(app, ["discover", "--path", str(repo)]).exit_code == 0
    assert runner.invoke(app, ["approve", "INV-001", "--path", str(repo)]).exit_code == 0
    (repo / "app.py").write_text("import subprocess\nsubprocess.run('x', shell=True)\n")
    checked = runner.invoke(app, ["check", "--path", str(repo), "--allow-empty"])
    assert checked.exit_code == 1
    assert "FAIL" in checked.output


def test_daybreak_requires_explicit_context_and_previews_without_key(repo: Path) -> None:
    assert runner.invoke(app, ["init", "--path", str(repo)]).exit_code == 0
    missing = runner.invoke(app, ["discover", "--path", str(repo), "--provider", "daybreak"])
    assert missing.exit_code == 2
    preview = runner.invoke(
        app,
        [
            "discover",
            "--path",
            str(repo),
            "--provider",
            "daybreak",
            "--include",
            "app.py",
            "--preview-context",
        ],
    )
    assert preview.exit_code == 0, preview.output
    assert "app.py" in preview.output
    assert "proposals" not in preview.output


def test_daybreak_malformed_response_does_not_persist(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class FakeResponse:
        headers = {"Content-Length": "20"}

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self, _: int) -> bytes:
            return b'{"status":"completed","output":[]}'

    monkeypatch.setattr("urllib.request.urlopen", lambda *_args, **_kwargs: FakeResponse())
    with pytest.raises(ProviderError, match="structured"):
        DaybreakProvider("test-key").discover_invariants(repo, inventory(repo))
    assert not (repo / ".invariantforge").exists()


def test_daybreak_timeout_is_reported(repo: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def timeout(*_args: object, **_kwargs: object) -> object:
        raise TimeoutError("test timeout")

    monkeypatch.setattr("urllib.request.urlopen", timeout)
    with pytest.raises(ProviderError, match="timed out"):
        DaybreakProvider("test-key").discover_invariants(repo, inventory(repo))


def test_daybreak_validates_structured_output_and_redacts_context(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    (repo / "auth.py").write_text('STRIPE_SECRET_KEY = "sk_live_abcdefghijkl"\n')
    proposal = StaticProvider().discover_invariants(repo, inventory(repo))[0]
    proposal.sources = ["auth.py"]
    output = json.dumps({"proposals": [proposal.model_dump(mode="json")]})
    response_data = {
        "status": "completed",
        "output": [{"type": "message", "content": [{"type": "output_text", "text": output}]}],
    }
    captured: dict[str, object] = {}

    class FakeResponse:
        headers = {}

        def __enter__(self) -> FakeResponse:
            return self

        def __exit__(self, *_: object) -> None:
            return None

        def read(self, _: int) -> bytes:
            return json.dumps(response_data).encode()

    def fake_urlopen(request: object, timeout: int) -> FakeResponse:
        captured["body"] = request.data  # type: ignore[attr-defined]
        captured["timeout"] = timeout
        return FakeResponse()

    monkeypatch.setattr("urllib.request.urlopen", fake_urlopen)
    proposals = DaybreakProvider("test-key").discover_invariants(repo, inventory(repo))
    assert len(proposals) == 1
    body = captured["body"]
    assert isinstance(body, bytes)
    assert b"sk_live_abcdefghijkl" not in body
    request_data = json.loads(body)
    assert request_data["store"] is False
    assert request_data["access_programs"] == {"cyber": "daybreak_blue"}
    assert request_data["text"]["format"]["type"] == "json_schema"


def test_static_provider_proposes_without_model(repo: Path) -> None:
    proposals = StaticProvider().discover_invariants(repo, inventory(repo))
    assert len(proposals) == 1
    assert proposals[0].enforcement is not None
    assert proposals[0].enforcement.strategy == "python_no_call"


def test_static_provider_prefers_owned_source_scope(repo: Path) -> None:
    source = repo / "src" / "sample"
    source.mkdir(parents=True)
    (source / "runner.py").write_text("import subprocess\n")
    proposals = StaticProvider().discover_invariants(repo, inventory(repo))
    assert proposals[0].scope == ["src/**/*.py"]
    assert proposals[0].sources == ["src/sample/runner.py"]


def test_credential_does_not_switch_default_provider(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "unused-test-value")
    assert runner.invoke(app, ["init", "--path", str(repo)]).exit_code == 0
    result = runner.invoke(app, ["discover", "--path", str(repo)])
    assert result.exit_code == 0, result.output
    assert "Discovery: static" in result.output


def test_deep_diff_json_is_clean_and_requires_include(
    repo: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert runner.invoke(app, ["init", "--path", str(repo)]).exit_code == 0
    (repo / "app.py").write_text("import subprocess\nsubprocess.run('x', shell=True)\n")
    missing = runner.invoke(app, ["diff", "--path", str(repo), "--deep"])
    assert missing.exit_code == 2
    preview = runner.invoke(
        app,
        ["diff", "--path", str(repo), "--deep", "--include", "app.py", "--preview-context"],
    )
    assert preview.exit_code == 0
    monkeypatch.setenv("OPENAI_API_KEY", "unused-test-value")
    monkeypatch.setattr(
        "invariantforge.providers.DaybreakProvider.analyze_boundary_diff",
        lambda *_args: [
            BoundaryReview(
                path="app.py",
                certainty="possible",
                summary="Shell option changed",
                reason="The changed line enables a shell.",
                affected_invariants=[],
                test_ideas=[],
            )
        ],
    )
    result = runner.invoke(
        app,
        ["diff", "--path", str(repo), "--deep", "--include", "app.py", "--format", "json"],
    )
    assert result.exit_code == 0, result.output
    assert json.loads(result.output)["deep_reviews"][0]["path"] == "app.py"
