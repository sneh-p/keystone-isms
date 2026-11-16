"""scripts/check-suppressions.sh enforces SC-AGT-001 and SC-AGT-002 (run in a throwaway git repository)."""

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
GIT = shutil.which("git") or "/usr/bin/git"
BASH = shutil.which("bash") or "/bin/bash"

REGISTER = """---
type: Exception Register
---

# Register

| ID | Rule | Location | Reason and compensating control | Approved by | Expires |
|---|---|---|---|---|---|
{rows}

# Examples

| EX-900 | SC-CRY-002 | x | example only | human:x | 2099-01-01 |
"""


def git(repo: Path, *args: str) -> None:
    subprocess.run([GIT, *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "repo"
    (r / "scripts").mkdir(parents=True)
    (r / ".knowledge" / "secure-coding").mkdir(parents=True)
    shutil.copy(ROOT / "scripts" / "check-suppressions.sh", r / "scripts" / "check-suppressions.sh")
    (r / ".knowledge" / "secure-coding" / "exceptions.md").write_text(REGISTER.format(rows=""))
    (r / "app.py").write_text("x = 1\n")
    git(r, "init", "-q", "-b", "main")
    git(r, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "add", ".")
    git(r, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qm", "base")
    git(r, "checkout", "-qb", "work")
    return r


def check(repo: Path, **env) -> subprocess.CompletedProcess:
    return subprocess.run([BASH, "scripts/check-suppressions.sh"], cwd=repo, capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "BASE_REF": "main", **env})


def register(repo: Path, rows: str) -> None:
    """Simulates AppSec registering an exception on the base branch."""
    git(repo, "checkout", "-q", "main")
    (repo / ".knowledge" / "secure-coding" / "exceptions.md").write_text(REGISTER.format(rows=rows))
    git(repo, "-c", "user.email=t@example.invalid", "-c", "user.name=t", "commit", "-qam", "register")
    git(repo, "checkout", "-q", "work")
    git(repo, "rebase", "-q", "main")


def test_clean_change_passes(repo):
    (repo / "app.py").write_text("x = 2\n")
    assert check(repo).returncode == 0


@pytest.mark.parametrize("line", ["eval(x)  # noqa: S307", "import os  # nosec", "y: int = 'a'  # type: ignore", "@pytest.mark.skip", "it.only('x', f)", "// eslint-disable-next-line react/no-danger"])
def test_unregistered_suppression_fails(repo, line):
    (repo / "new.py").write_text(line + "\n")  # untracked file: still checked
    r = check(repo)
    assert r.returncode == 1 and "SC-AGT-001" in r.stdout


def test_registered_exception_passes_and_expiry_and_examples_are_enforced(repo):
    (repo / "app.py").write_text("x = 2  # noqa: S311 -- security-exception: EX-007 retry jitter\n")
    assert "not registered" in check(repo).stdout  # not in the register yet
    register(repo, "| EX-007 | SC-CRY-002 | app.py | jitter only | human:appsec | 2099-12-31 |")
    (repo / "app.py").write_text("x = 2  # noqa: S311 -- security-exception: EX-007 retry jitter\n")
    assert check(repo).returncode == 0
    (repo / "app.py").write_text("x = 3  # noqa: S311 -- security-exception: EX-900 example rows don't count\n")
    assert "not registered" in check(repo).stdout


def test_expired_exception_fails(repo):
    register(repo, "| EX-008 | SC-CRY-002 | app.py | jitter only | human:appsec | 2020-01-01 |")
    (repo / "app.py").write_text("x = 2  # noqa: S311 -- security-exception: EX-008\n")
    r = check(repo)
    assert r.returncode == 1 and "expired" in r.stdout


def test_protected_files_need_human_approval(repo):
    (repo / "AGENTS.md").write_text("relaxed rules\n")
    r = check(repo)
    assert r.returncode == 1 and "SC-AGT-002" in r.stdout and "AGENTS.md" in r.stdout
    assert check(repo, ALLOW_PROTECTED="1").returncode == 0
