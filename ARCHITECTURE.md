# Architecture plan

InvariantForge has three trust zones: the inspected repository, local reviewed
policy, and an optional remote reasoning provider. Repository bytes and provider
output are untrusted. Only an explicit `approve` command changes a proposal to
approved. CI executes a small, documented set of deterministic checks, never
provider-authored code or commands.

1. Inventory bounded regular files without importing or executing them. Exclude
   secrets and symlinks, cap file count, file size, and aggregate context, then
   redact recognizable credentials. Files are quoted as data in provider input.
2. Validate provider JSON against a strict proposal schema. Keep proposals in a
   versioned YAML store with stable IDs. Provider failure leaves the store intact.
3. Approval requires a concrete enforcement specification. The supported v0.1
   checks are `python_no_call`, `python_required_call`, `text_not_match`, and
   `path_exists`. Their scopes are repository-relative globs. Unsupported
   properties remain unenforced and fail the CI gate when approved.
4. BoundaryDiff classifies changed lines and paths from a bounded, read-only git
   diff. Mapping to approved invariants uses scope and boundary category. A
   finding describes a review target, not a proven vulnerability.
5. `prove` records revision, dirty state, results, and hashes of policy and
   results. It does not copy repository source into evidence.

The CLI and library share the same models and functions. A provider protocol
separates Daybreak reasoning from offline enforcement. Static discovery is the
default. Daybreak requires an explicit provider choice and file allowlist.
Ordinary checks need no model access.

Security constraints: no repository code execution during scanning, no shell
interpolation, no symlink traversal, no provider-chosen output paths, no secret
values in logs or evidence, and no model result treated as an instruction.

Daybreak review added three release constraints: approvals bind to a canonical
rule digest and are invalidated by edits; all extraction limits appear as
`not_assessed` rather than a clean result; git inspection disables filters and
external diff tools. Policy stored in the inspected repository still depends on
normal code review and branch protection. A digest is an accidental-change
guard, not a signature against a malicious committer.
