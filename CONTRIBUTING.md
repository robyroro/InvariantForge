# Contributing

Open an issue with a concrete boundary or reproducible defect before adding a
new enforcement strategy. A strategy needs a defined security property,
bounded inputs, an honest strength rating, and tests that show both passing
and failing cases. Avoid checks that only inspect a preferred coding style.

Run `ruff check .`, `mypy src`, and `pytest` before a pull request. Keep the
offline test suite independent of provider credentials. Do not include real
secrets, private repository content, or model transcripts in fixtures.
