"""InvariantForge command line interface."""

from __future__ import annotations

import fnmatch
import json
import os
import sys
from dataclasses import replace
from pathlib import Path
from typing import Annotated, Literal

import typer
import yaml
from rich.console import Console
from rich.table import Table

from invariantforge import __version__
from invariantforge.boundaries import analyze
from invariantforge.checks import baseline_result, run
from invariantforge.evidence import prove as create_evidence
from invariantforge.gitops import GitError, git
from invariantforge.models import Status
from invariantforge.paths import UnsafePathError, owned_path
from invariantforge.providers import (
    DaybreakProvider,
    ProviderError,
    StaticProvider,
    validate_manual_proposals,
)
from invariantforge.scan import inventory
from invariantforge.store import PolicyError, add_proposals, load, policy_path, save, transition

app = typer.Typer(
    no_args_is_help=True, help="Versioned security invariants and boundary-aware change review"
)
console = Console()


def _root(path: Path) -> Path:
    path = path.resolve()
    if not path.is_dir():
        raise PolicyError(f"repository path does not exist: {path}")
    return path


def _error(exc: Exception) -> None:
    if os.environ.get("INVARIANTFORGE_DEBUG") == "1":
        raise exc
    Console(stderr=True).print(f"[red]Error:[/red] {exc}")
    raise typer.Exit(2)


@app.command()
def init(
    path: Annotated[Path, typer.Option("--path", help="Repository directory")] = Path("."),
) -> None:
    """Inventory a repository and create versioned local policy files."""
    try:
        root = _root(path)
        folder = owned_path(root, ".invariantforge")
        owned_path(root, ".invariantforge/cache")
        owned_path(root, ".invariantforge/evidence")
        data = inventory(root)
        folder.mkdir(exist_ok=True)
        (folder / "cache").mkdir(exist_ok=True)
        (folder / "evidence").mkdir(exist_ok=True)
        config = owned_path(root, ".invariantforge/config.yaml")
        overview = {
            "schema_version": 1,
            "repository": ".",
            "languages": data.languages,
            "package_managers": data.package_managers,
            "frameworks": data.frameworks,
            "test_frameworks": data.test_frameworks,
            "ci": data.ci,
            "monorepo": data.monorepo,
            "security_docs": [
                p for p in data.files if "security" in p.lower() or "threat" in p.lower()
            ],
            "architecture_docs": [p for p in data.files if "architecture" in p.lower()],
            "docker_files": [p for p in data.files if Path(p).name.lower().startswith("docker")],
            "mcp_files": [p for p in data.files if "mcp" in p.lower()],
            "policy_files": [
                p
                for p in data.files
                if Path(p).name.lower() in {"policy.yaml", "policy.yml"}
                or Path(p).suffix.lower() == ".rego"
            ],
            "dependency_manifests": [
                p
                for p in data.files
                if Path(p).name
                in {
                    "pyproject.toml",
                    "package.json",
                    "Cargo.toml",
                    "composer.json",
                    "requirements.txt",
                }
            ],
            "omitted": data.omitted,
        }
        with config.open("w", encoding="utf-8", newline="\n") as stream:
            stream.write(yaml.safe_dump(overview, sort_keys=False))
        if not policy_path(root).exists():
            save(root, [])
        console.print(f"Initialized {folder} ({len(data.files)} readable files)")
    except (PolicyError, UnsafePathError, OSError) as exc:
        _error(exc)


@app.command()
def discover(
    path: Annotated[Path, typer.Option("--path")] = Path("."),
    provider: Annotated[
        Literal["static", "daybreak", "manual"], typer.Option("--provider")
    ] = "static",
    input_file: Annotated[
        Path | None, typer.Option("--input-file", help="Validated proposal JSON for manual mode")
    ] = None,
    include: Annotated[
        list[str] | None,
        typer.Option("--include", help="Files or globs explicitly allowed in Daybreak context"),
    ] = None,
    preview_context: Annotated[
        bool,
        typer.Option("--preview-context", help="Show selected Daybreak files without sending them"),
    ] = False,
) -> None:
    """Propose reviewable invariants; static mode works offline."""
    try:
        root = _root(path)
        load(root)
        data = inventory(root)
        if provider == "manual":
            if input_file is None:
                raise ProviderError("manual mode requires --input-file")
            proposals = validate_manual_proposals(input_file)
        elif provider == "daybreak":
            if not include:
                raise ProviderError(
                    "Daybreak requires at least one explicit --include path or glob"
                )
            selected_files = sorted(
                path
                for path in data.files
                if any(fnmatch.fnmatchcase(path, pattern) for pattern in include)
            )
            if not selected_files or any(
                not any(fnmatch.fnmatchcase(path, pattern) for path in selected_files)
                for pattern in include
            ):
                raise ProviderError("an --include pattern matches no safe inventory file")
            console.print(f"Daybreak context selection: {len(selected_files)} file(s)")
            for selected_file in selected_files:
                console.print(f"  {selected_file}")
            if preview_context:
                return
            proposals = DaybreakProvider().discover_invariants(
                root, replace(data, files=selected_files)
            )
        else:
            proposals = StaticProvider().discover_invariants(root, data)
        added = add_proposals(root, proposals)
        console.print(
            f"Discovery: {provider}; {len(added)} new proposal(s). All require review and approval."
        )
        if provider == "static":
            console.print(
                "Offline syntax analysis only; no Daybreak security reasoning was performed."
            )
        for item in added:
            console.print(f"  {item.id}  {item.title}")
        if data.omitted:
            console.print(f"Inventory incomplete: {data.omitted}")
    except (PolicyError, ProviderError, OSError) as exc:
        _error(exc)


@app.command(name="list")
def list_invariants(path: Annotated[Path, typer.Option("--path")] = Path(".")) -> None:
    """Show invariant IDs, status, and titles."""
    try:
        items = load(_root(path))
        table = Table("ID", "Status", "Strength", "Title")
        for item in items:
            table.add_row(item.id, item.status, item.enforcement_strength, item.title)
        console.print(table)
    except PolicyError as exc:
        _error(exc)


@app.command()
def show(invariant_id: str, path: Annotated[Path, typer.Option("--path")] = Path(".")) -> None:
    """Show the complete reviewed or proposed invariant."""
    try:
        item = next((x for x in load(_root(path)) if x.id == invariant_id), None)
        if item is None:
            raise PolicyError(f"unknown invariant: {invariant_id}")
        console.print(
            yaml.safe_dump(item.model_dump(mode="json"), sort_keys=False, allow_unicode=True)
        )
    except PolicyError as exc:
        _error(exc)


@app.command()
def approve(invariant_id: str, path: Annotated[Path, typer.Option("--path")] = Path(".")) -> None:
    """Explicitly approve a concrete rule by its current content digest."""
    try:
        item = transition(_root(path), invariant_id, Status.approved)
        console.print(f"Approved {item.id} ({item.approval_digest})")
    except PolicyError as exc:
        _error(exc)


@app.command()
def reject(invariant_id: str, path: Annotated[Path, typer.Option("--path")] = Path(".")) -> None:
    """Reject a proposal."""
    try:
        item = transition(_root(path), invariant_id, Status.rejected)
        console.print(f"Rejected {item.id}")
    except PolicyError as exc:
        _error(exc)


@app.command()
def deprecate(invariant_id: str, path: Annotated[Path, typer.Option("--path")] = Path(".")) -> None:
    """Record an explicit retirement of an approved invariant."""
    try:
        item = transition(_root(path), invariant_id, Status.deprecated)
        console.print(f"Deprecated {item.id}")
    except PolicyError as exc:
        _error(exc)


@app.command()
def generate(path: Annotated[Path, typer.Option("--path")] = Path(".")) -> None:
    """Write a pytest entrypoint that runs the approved deterministic rules."""
    try:
        root = _root(path)
        items = load(root)
        approved = [item for item in items if item.status == Status.approved]
        if not approved:
            raise PolicyError("no approved invariants to generate")
        target = owned_path(root, "tests/security/test_invariantforge_generated.py")
        target.parent.mkdir(parents=True, exist_ok=True)
        marker = "# Generated by invariantforge. Edit the policy, then regenerate."
        if target.exists() and not target.read_text(encoding="utf-8").startswith(marker):
            raise PolicyError("refusing to overwrite a non-InvariantForge test")
        body = """# Generated by invariantforge. Edit the policy, then regenerate.
from pathlib import Path

from invariantforge.checks import run
from invariantforge.store import load


def test_approved_invariants() -> None:
    root = Path(__file__).resolve().parents[2]
    report = run(root, load(root))
    assert report.results, "no approved invariants"
    failures = {
        item.id: item.detail
        for item in report.results
        if item.outcome in {"fail", "unenforced", "not_assessed"}
    }
    assert not failures, failures
"""
        target.write_text(body, encoding="utf-8")
        console.print(f"Generated {target} for {len(approved)} approved invariant(s)")
    except (PolicyError, UnsafePathError, OSError) as exc:
        _error(exc)


@app.command()
def check(
    path: Annotated[Path, typer.Option("--path")] = Path("."),
    format: Annotated[Literal["text", "json"], typer.Option("--format")] = "text",
    allow_empty: Annotated[
        bool,
        typer.Option("--allow-empty", help="Allow a bootstrap policy with no approved rules"),
    ] = False,
    baseline_ref: Annotated[
        str | None,
        typer.Option("--baseline-ref", help="Trusted Git revision containing approved policy"),
    ] = None,
) -> None:
    """Execute approved rules without a model call."""
    try:
        root = _root(path)
        items = load(root)
        report = run(root, items)
        if baseline_ref is not None:
            baseline = baseline_result(root, items, baseline_ref)
            if baseline is not None:
                report.results.append(baseline)
        if format == "json":
            typer.echo(json.dumps(report.model_dump(mode="json"), sort_keys=True))
        else:
            console.print(
                f"InvariantForge {__version__}: "
                f"{sum(item.status == Status.approved for item in items)} approved invariant(s)"
            )
            if not report.results:
                console.print("No approved rules were checked.")
            for result in report.results:
                console.print(f"{result.outcome.upper():12} {result.id}  {result.detail}")
        if allow_empty and not report.results:
            typer.echo("No approved invariants; bootstrap check has no enforcement.", err=True)
        if report.failed and not (allow_empty and not report.results):
            raise typer.Exit(1)
    except (PolicyError, UnsafePathError, GitError, OSError) as exc:
        _error(exc)


@app.command()
def diff(
    base: str | None = typer.Argument(None),
    head: str | None = typer.Argument(None),
    path: Annotated[Path, typer.Option("--path")] = Path("."),
    format: Annotated[Literal["text", "json"], typer.Option("--format")] = "text",
    fail_on_findings: Annotated[bool, typer.Option("--fail-on-findings")] = False,
    deep: Annotated[
        bool, typer.Option("--deep", help="Ask Daybreak to review explicitly selected findings")
    ] = False,
    include: Annotated[
        list[str] | None, typer.Option("--include", help="Paths or globs allowed in deep review")
    ] = None,
    preview_context: Annotated[bool, typer.Option("--preview-context")] = False,
) -> None:
    """Classify security-sensitive git changes and map affected invariants."""
    try:
        root = _root(path)
        items = load(root)
        findings, warnings = analyze(root, items, base, head)
        reviews = []
        if deep:
            if not include:
                raise ProviderError("deep review requires explicit --include paths or globs")
            selected = [
                finding
                for finding in findings
                if any(fnmatch.fnmatchcase(finding.path, pattern) for pattern in include)
            ]
            if not selected or len(selected) > 30:
                raise ProviderError("deep review needs 1 to 30 selected findings")
            if preview_context or format == "text":
                console.print(f"Daybreak review selection: {len(selected)} finding(s)")
                for finding in selected:
                    console.print(f"  {finding.path}")
            if preview_context:
                return
            reviews = DaybreakProvider().analyze_boundary_diff(selected, items)
        if format == "json":
            typer.echo(
                json.dumps(
                    {
                        "schema_version": 1,
                        "comparison": [base or "HEAD", head or "working-tree"],
                        "findings": [item.as_dict() for item in findings],
                        "deep_reviews": [item.model_dump(mode="json") for item in reviews],
                        "warnings": warnings,
                    },
                    sort_keys=True,
                )
            )
        else:
            console.print(f"BoundaryDiff: {len(findings)} review target(s)")
            for item in findings:
                console.print(
                    f"{item.path} [{item.change}] {', '.join(item.categories) or 'unclassified'}"
                )
                console.print(
                    f"  possible impact: {', '.join(item.invariant_ids) or 'no mapped invariant'}; "
                    f"evidence: {item.evidence}"
                )
            for warning in warnings:
                console.print(f"Not assessed: {warning}")
            for review in reviews:
                console.print(f"Daybreak {review.certainty}: {review.path}: {review.summary}")
                console.print(f"  {review.reason}")
        if fail_on_findings and (findings or warnings):
            raise typer.Exit(3)
    except (PolicyError, GitError, ProviderError, OSError) as exc:
        _error(exc)


@app.command()
def prove(
    path: Annotated[Path, typer.Option("--path")] = Path("."),
    output: Annotated[Path | None, typer.Option("--output")] = None,
) -> None:
    """Write a hash-bound local evidence bundle for this run."""
    try:
        root = _root(path)
        target, report = create_evidence(root, load(root), output)
        console.print(f"Evidence: {target}")
        if report.failed:
            raise typer.Exit(1)
    except (PolicyError, UnsafePathError, OSError) as exc:
        _error(exc)


@app.command()
def doctor(path: Annotated[Path, typer.Option("--path")] = Path(".")) -> None:
    """Check local installation and repository readiness without revealing credentials."""
    try:
        root = _root(path)
        console.print(f"InvariantForge {__version__}; Python {sys.version.split()[0]}")
        try:
            console.print(f"Git: {git(root, 'rev-parse', '--show-toplevel').decode().strip()}")
        except GitError:
            console.print("Git: unavailable or directory is not a repository")
        console.print(f"Policy: {'ready' if policy_path(root).is_file() else 'run init'}")
        availability = (
            "configured" if os.environ.get("OPENAI_API_KEY") else "unavailable; static mode works"
        )
        console.print(f"Daybreak API: {availability}")
    except (PolicyError, OSError) as exc:
        _error(exc)


if __name__ == "__main__":
    app()
