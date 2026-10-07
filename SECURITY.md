# Security policy

Report suspected vulnerabilities privately through GitHub's security advisory
flow for this repository. Include a minimal reproducer, affected version, and
impact. Please avoid posting live credentials or private repository content.

InvariantForge reads potentially hostile repositories. It never executes
inspected code during `init`, `discover`, `check`, or `diff`. Discovery excludes
common secret filenames, bounds context, redacts recognizable credentials,
and treats source text as data. Redaction is best effort. Do not send a highly
sensitive repository to a model provider without reviewing the selected
context and your organization's data policy.

Provider output is untrusted. It cannot approve its own proposals, run shell
commands, or choose arbitrary generation paths. Approved YAML policy should
be protected by branch review. The local digest detects edits after approval
but is not tamperproof against someone who can edit both the rule and digest.

The static checks are deliberately narrow. A passing `python_no_call` check
does not prove that no equivalent behavior exists through imports, wrappers,
runtime code generation, or other languages. Review the declared enforcement
strength and bypasses for each rule.
