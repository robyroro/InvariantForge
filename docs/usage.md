# Usage and limits

`init` inventories known language, package, CI, security document, and
dependency markers. It creates `.invariantforge/config.yaml` and an empty
`.invariantforge/invariants.yaml` without changing application code. Commit
the policy files. Re-running `init` refreshes the inventory config without
replacing invariants. Exclude cache and evidence from version control.

`discover` makes proposals. Offline static discovery currently recognizes
Python subprocess imports and suggests a literal `shell=True` restriction.
This is intentionally conservative. `--provider daybreak` requires explicit
`--include` file paths or globs. Review selected names with `--preview-context`
before sending bounded excerpts to an approved Daybreak project. It never
activates automatically because a credential happens to exist. `--provider manual --input-file
proposals.json` accepts a validated `{"proposals": [...]}` batch produced by
another review process. All modes create proposed records only.

Review `show INV-001`, including scope, strength, sources, and bypasses, before
running `approve`. Approval requires a concrete rule. Reject unsupported
properties or implement a meaningful regression test in the application.
`deprecate` records an explicit retirement of an approved rule. A trusted
baseline check flags that retirement for review.

The v0.1 enforcement DSL has four strategies:

| Strategy | Meaning | Limit |
| --- | --- | --- |
| `python_no_call` | Reject a literal AST call, optionally with a keyword/value. | Aliases and wrappers may bypass it. |
| `python_required_call` | Require a literal call in each scoped Python file or named function. | Presence does not prove ordering or reachability. |
| `text_not_contain` | Reject an exact literal string. | Does not understand semantics. |
| `path_exists` | Require a contained regular file. | Does not validate contents. |

`check --format json` reports `pass`, `fail`, `partial`, `unenforced`, or
`not_assessed`. With no approved rules, `check` exits 1. Use
`check --allow-empty` only while bootstrapping a repository. It prints a warning
and exits 0 when no rule is approved; approved rule failures still exit 1.
The project CI uses this mode until its first self-invariant is reviewed.
Use
`check --baseline-ref <trusted-sha>` in a pull request to reject removed or
changed approved rules from a protected base revision. New approved rules are
allowed; intentional changes to existing approved rules require a separate
reviewed baseline update. Exit codes: 0 when no blocking result, 1 for failed or
unassessed approved rules, 2 for malformed policy or operational errors.
`diff --fail-on-findings` uses exit 3 for review targets or incomplete diff
coverage. A `partial` rule passes its narrow check but is never presented as
full proof of the larger security property.

`diff --deep --include <path-or-glob>` sends only matching, redacted findings
to Daybreak for a structured review. `--preview-context` lists those findings
without a provider call. The deep result is supplementary and never silently
approves or rewrites a policy.

`prove` writes a bundle under `.invariantforge/evidence/` or `--output`. It
records the commit, dirty state, policy digest, approved rule digests,
results, and hashes. For a reproducible CI run, use a clean checkout at a
pinned revision. A dirty working tree is recorded but cannot be reconstructed
from this bundle alone.

Set `INVARIANTFORGE_DEBUG=1` to see a traceback for an operational error.

## Provider security

Repository files can contain prompt injection. InvariantForge presents them
as bounded JSON data under a fixed instruction that says not to follow their
contents. This is a defense, not a guarantee. Provider proposals are schema
validated, source paths must belong to the inventory, and the model cannot
approve or execute a rule. Redaction covers common tokens and keys, but may
miss custom secret formats, encoded values, and sensitive path names.

The [Daybreak provider](https://developers.openai.com/api/docs/guides/daybreak)
uses the Responses API with a structured JSON schema,
`store=false`, an explicit Daybreak Blue access program, no model tools, and a
request timeout. The normal check path makes no provider call.
