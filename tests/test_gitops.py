from __future__ import annotations

from pathlib import Path

import pytest
from conftest import git as raw_git

from invariantforge.gitops import GitError, git


def test_git_output_is_bounded(repo: Path) -> None:
    (repo / "large.txt").write_text("x" * 10_000)
    raw_git(repo, "add", "large.txt")
    raw_git(repo, "commit", "-qm", "large file")
    with pytest.raises(GitError, match="safety limit"):
        git(repo, "show", "HEAD:large.txt", max_bytes=100)
