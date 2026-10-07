# InvariantForge

Security assumptions disappear easily. A repository may rely on an approval
check, a path constraint, or a restricted subprocess call without a durable
way to notice when that property changes. InvariantForge records reviewed
security invariants, runs deterministic checks, and highlights changes to
security-sensitive boundaries.

BoundaryDiff is the `invariantforge diff` command. It maps changed files and
lines to approved invariants. A match is a review target, not a vulnerability
claim.

## Quick start

Requires Python 3.12 or newer. With [uv](https://docs.astral.sh/uv/):

```sh
uv sync
uv run invariantforge init
uv run invariantforge discover
uv run invariantforge list
uv run invariantforge show INV-001
uv run invariantforge approve INV-001
uv run invariantforge generate
uv run invariantforge check
uv run invariantforge diff HEAD~1 HEAD
uv run invariantforge prove
```

Without uv, install with `python -m pip install -e .` and call
`invariantforge` directly. `discover` uses conservative static proposals by
default, even when a credential exists. It clearly labels that mode. No API key
is needed for `init`, `list`, `show`, `approve`, `reject`, `generate`, `check`,
`diff`, `prove`, or `doctor`.

To request Daybreak reasoning, select the files explicitly:

```sh
invariantforge discover --provider daybreak --include SECURITY.md --include 'src/auth/**' --preview-context
invariantforge discover --provider daybreak --include SECURITY.md --include 'src/auth/**'
```

This requires an approved Daybreak project and an `OPENAI_API_KEY` in the
environment. Only selected files are sent as bounded, redacted excerpts.
Daybreak proposals stay `proposed` until a
person reviews and approves them. Daybreak can be wrong, and this tool does
not provide formal verification.

## Policy example

```yaml
schema_version: 1
invariants:
  - id: INV-001
    title: Subprocess calls must not enable a shell
    description: Shell parsing may reinterpret user-controlled arguments.
    category: subprocess
    severity: high
    status: proposed
    confidence: medium
    sources: [src/runner.py]
    scope: ['src/**/*.py']
    statement: No subprocess.run call uses shell=True.
    enforcement:
      strategy: python_no_call
      target: subprocess.run
      keyword: shell
      keyword_value: true
    enforcement_strength: partial
    boundaries: [subprocess]
```

The real schema also records timestamps, rationale, attacker, bypasses and an
approval digest. Use `discover` or `show` to see a complete serialized record.
Approved rules are checked against their approved digest. A policy edit
invalidates that approval and causes `check` to fail until the rule is reviewed
again. A branch protection rule and code review must protect the YAML policy
itself; the digest is not a cryptographic signature against a malicious
committer. In CI, `check --baseline-ref <trusted-sha>` also detects removal or
modification of previously approved rules. Pin that SHA from a protected base
branch, not from an untrusted PR branch.

## BoundaryDiff

```text
BoundaryDiff: 1 review target(s)
src/runner.py [modified] subprocess
  possible impact: INV-001; evidence: +subprocess.run(command, shell=True)
```

The classifier inspects paths and changed lines. It reports `possible` impact
and does not assert that a code change created a vulnerability. Use
`invariantforge diff --format json` in CI. Add `--fail-on-findings` to exit 3
when a review target or incomplete comparison is found.

For optional Daybreak reasoning over selected findings, run
`invariantforge diff --deep --include 'src/auth/**' --preview-context`, then
repeat without `--preview-context`. This also requires approved API access.

## What it does and does not do

- Runs a closed set of syntax and literal checks without importing inspected
  code, running builds, or installing inspected dependencies.
- Creates a pytest entrypoint under `tests/security/` that invokes the same
  deterministic engine as `check`.
- Records small evidence bundles with policy and result hashes. These are
  review artifacts, not signed attestations.
- Does not prove data flow, control flow, runtime behavior, or the absence of
  all bypasses. `partial` means the specified check passed but the larger
  property needs additional review or tests.

See [ARCHITECTURE.md](ARCHITECTURE.md), [SECURITY.md](SECURITY.md),
[docs/threat-model.md](docs/threat-model.md), and [docs/usage.md](docs/usage.md)
for the trust model, supported rules, exit codes, and limits.

## Development

```sh
uv sync
uv run ruff check .
uv run mypy src
uv run pytest
```

The normal test suite runs offline. See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Apache-2.0. See [LICENSE](LICENSE). It includes an explicit patent grant,
which is useful for a security tool that others may extend and embed.
