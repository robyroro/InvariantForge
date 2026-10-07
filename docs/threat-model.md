# Threat model

InvariantForge has four inputs with different trust levels:

| Input | Trust assumption | Main risk |
| --- | --- | --- |
| Inspected repository | Hostile | Malicious files, symlinks, huge trees, crafted Git metadata, prompt injection, secrets. |
| Policy YAML | Reviewed only when protected by repository controls | A branch can remove or rewrite approved rules. |
| Daybreak response | Untrusted suggestion | Fabricated source locations, false confidence, invalid rule fields. |
| CLI options | User supplied | Path or revision escape, unintended provider upload. |

Discovery does not import or execute repository modules. Inventory uses
`scandir` with file, entry, file-size, and context budgets. Files with common
secret names and symlinks are excluded. Text is redacted before optional
provider upload. Remote analysis is opt-in and requires an explicit file
allowlist. These controls reduce risk but cannot identify every private value.

The model receives repository material as marked JSON data and has no tools in
the Responses API request. Its output is schema validated, source references
must come from the selected inventory, and proposals start as `proposed`.
Repository instructions cannot approve rules or select output paths.

Approval binds a rule digest to its exact content. This detects accidental
edits. A malicious committer who controls the branch can still recalculate the
digest or remove the policy. CI can compare the current policy with a pinned
protected base revision using `check --baseline-ref`. Branch protection and
review of `.invariantforge/invariants.yaml` and workflows remain necessary.

The enforcement DSL runs syntax and literal checks on bounded files. It does
not execute application tests or arbitrary generated code. AST rules are
limited to `partial` or `advisory` because aliases, wrappers, reflection, and
runtime control flow may bypass them. Dynamic keyword arguments produce
`not_assessed` where the checker cannot decide the property.

BoundaryDiff uses read-only Git operations with external diff, text conversion,
fsmonitor, and global configuration disabled. It reports unclassified
deletions, binary content it cannot inspect, changed ignore rules, and
truncated patches. Findings are review targets. They do not establish attacker
reachability or exploitability.

Evidence bundles store results and digests, not source excerpts. They are
neither signed attestations nor a substitute for a clean, pinned checkout.
