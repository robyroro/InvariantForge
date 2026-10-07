from __future__ import annotations

from pathlib import Path

import pytest

from invariantforge.paths import UnsafePathError, owned_path
from invariantforge.store import PolicyError, save


def test_owned_path_rejects_parent_traversal(repo: Path) -> None:
    with pytest.raises(UnsafePathError):
        owned_path(repo, "../outside")


def test_policy_parent_symlink_cannot_redirect_write(repo: Path, tmp_path: Path) -> None:
    outside = tmp_path.parent / "outside-policy-test"
    outside.mkdir(exist_ok=True)
    try:
        (repo / ".invariantforge").symlink_to(outside, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("symlink creation unavailable")
    with pytest.raises(PolicyError):
        save(repo, [])
    assert not (outside / "invariants.yaml").exists()
