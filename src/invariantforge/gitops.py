"""Read-only Git subprocess wrapper with disabled external helpers."""

from __future__ import annotations

import os
import re
import subprocess
import threading
from pathlib import Path
from typing import BinaryIO


class GitError(ValueError):
    pass


def resolve_commit(root: Path, ref: str) -> str:
    if ref.startswith("-") or not re.fullmatch(r"[A-Za-z0-9_./@{}~^+-]{1,120}", ref):
        raise GitError("invalid revision argument")
    return git(root, "rev-parse", "--verify", f"{ref}^{{commit}}").decode().strip()


def git(root: Path, *args: str, max_bytes: int = 2_000_000) -> bytes:
    env = os.environ.copy()
    env.update(
        {
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "GIT_NO_REPLACE_OBJECTS": "1",
            "GIT_EXTERNAL_DIFF": "",
            "GIT_PAGER": "cat",
            "GIT_CONFIG_COUNT": "3",
            "GIT_CONFIG_KEY_0": "diff.external",
            "GIT_CONFIG_VALUE_0": "",
            "GIT_CONFIG_KEY_1": "core.pager",
            "GIT_CONFIG_VALUE_1": "cat",
            "GIT_CONFIG_KEY_2": "core.fsmonitor",
            "GIT_CONFIG_VALUE_2": "false",
        }
    )
    try:
        process = subprocess.Popen(
            ["git", "-C", str(root), "--no-pager", *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )
    except OSError as exc:
        raise GitError(f"git inspection failed: {type(exc).__name__}") from exc
    assert process.stdout is not None and process.stderr is not None
    stdout_parts: list[bytes] = []
    stderr_parts: list[bytes] = []
    exceeded = threading.Event()

    def collect(stream: BinaryIO, parts: list[bytes], limit: int) -> None:
        size = 0
        while True:
            chunk = stream.read(8192)
            if not chunk:
                break
            remaining = limit - size
            if len(chunk) > remaining:
                parts.append(chunk[:remaining])
                exceeded.set()
                try:
                    process.kill()
                except OSError:
                    pass
                break
            parts.append(chunk)
            size += len(chunk)

    out_thread = threading.Thread(
        target=collect, args=(process.stdout, stdout_parts, max_bytes), daemon=True
    )
    err_thread = threading.Thread(
        target=collect, args=(process.stderr, stderr_parts, 4096), daemon=True
    )
    out_thread.start()
    err_thread.start()
    try:
        process.wait(timeout=15)
    except subprocess.TimeoutExpired as exc:
        process.kill()
        process.wait()
        raise GitError("git inspection timed out") from exc
    finally:
        out_thread.join(timeout=2)
        err_thread.join(timeout=2)
        process.stdout.close()
        process.stderr.close()
    if exceeded.is_set():
        raise GitError("git output exceeds safety limit; comparison not assessed")
    if process.returncode:
        raise GitError(
            b"".join(stderr_parts).decode("utf-8", "replace")[:500].strip() or "git failed"
        )
    return b"".join(stdout_parts)


def revision(root: Path) -> str | None:
    try:
        return git(root, "rev-parse", "HEAD").decode().strip()
    except GitError:
        return None


def dirty(root: Path) -> bool:
    try:
        return bool(git(root, "status", "--porcelain", "--untracked-files=normal"))
    except GitError:
        return True
