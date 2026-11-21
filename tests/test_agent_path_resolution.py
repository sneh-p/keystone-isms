"""Security review fix (2026-11-21): content-reading probes must not reach refused files through another name. The
server refuses the alias locations; each agent also refuses them, and checks the real path after following every
symbolic link before it reads anything."""

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from keystone.configcheck import custom

ROOT = Path(__file__).resolve().parents[1]
SH = shutil.which("dash") or "/bin/sh"


@pytest.mark.parametrize("platform,path", [
    ("macos", "/System/Volumes/Data/Users/alice/.aws/credentials"),
    ("macos", "/System/Volumes/Data/private/var/db/dslocal/nodes/Default/users/alice.plist"),
    ("macos", "/Volumes/Macintosh HD/Users/alice/.netrc"),
    ("linux", "/proc/1/root/etc/shadow"),
    ("linux", "/proc/self/cwd/secret.conf"),
    ("linux", "/proc/1/fd/3"),
])
def test_server_refuses_other_names_for_refused_files(platform, path):
    with pytest.raises(custom.CheckInvalid, match="doesn't read"):
        custom.validate(platform, "file_setting", {"path": path, "key": "k", "separator": "equals"}, "str")


def _run(script: str, defs: Path, tmp: Path, extra_env: dict | None = None) -> dict:
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp), "LC_ALL": "C", **(extra_env or {})}
    out = subprocess.run([SH, str(ROOT / script), "collect-custom", str(defs)], capture_output=True, text=True, timeout=120, env=env, check=True)
    return json.loads(out.stdout)


@pytest.fixture
def links(tmp_path):
    """Refused files made in the test folder (a *.key file, a .ssh folder), and links to them."""
    (tmp_path / "real.conf").write_text("MaxAuthTries 3\n")
    (tmp_path / "secret.key").write_text("root:topsecret\n")
    (tmp_path / "home" / ".ssh").mkdir(parents=True)
    (tmp_path / "home" / ".ssh" / "config").write_text("root IdentityFile\n")
    (tmp_path / "ok.conf").symlink_to(tmp_path / "real.conf")  # a link to an allowed file still works
    (tmp_path / "secret.conf").symlink_to(tmp_path / "secret.key")  # a link straight to a refused file
    (tmp_path / "sshdir").symlink_to(tmp_path / "home" / ".ssh")  # a linked folder on the way to a refused file
    (tmp_path / "chain.conf").symlink_to(tmp_path / "secret.conf")  # a chain of links
    return tmp_path


def _defs(tmp: Path) -> Path:
    rows = [
        ["custom.ok", "file_setting", "int", f"path={tmp}/ok.conf", "key=MaxAuthTries", "separator=whitespace"],
        ["custom.link", "file_contains", "bool", f"path={tmp}/secret.conf", "text=root"],
        ["custom.dirlink", "file_setting", "str", f"path={tmp}/sshdir/config", "key=root", "separator=whitespace"],
        ["custom.chain", "file_contains", "bool", f"path={tmp}/chain.conf", "text=root"],
        ["custom.proc", "file_contains", "bool", "path=/proc/1/root/etc/passwd", "text=root"],
        ["custom.mac_alias", "file_contains", "bool", "path=/System/Volumes/Data/Users/alice/.netrc", "text=x"],
    ]
    f = tmp / "defs.tsv"
    f.write_text("".join("\t".join(r) + "\n" for r in rows))
    return f


def test_linux_agent_follows_links_before_reading(links):
    r = _run("agents/linux/keystone-agent.sh", _defs(links), links)
    assert r["facts"].get("custom.ok") == 3
    assert {k: r["check_errors"][k] for k in ("custom.link", "custom.dirlink", "custom.chain", "custom.proc", "custom.mac_alias")} == dict.fromkeys(
        ("custom.link", "custom.dirlink", "custom.chain", "custom.proc", "custom.mac_alias"), "refused")
    assert not any(k in r["facts"] for k in ("custom.link", "custom.dirlink", "custom.chain", "custom.proc"))


def test_macos_agent_follows_links_before_reading(links):
    from tests.test_integration_health_agents import STUBS

    bin_dir = links / "bin"
    bin_dir.mkdir()
    for name, body in STUBS.items():
        p = bin_dir / name
        p.write_text(f"#!/bin/sh\n{body}\n")
        p.chmod(0o755)
    r = _run("agents/macos/keystone-agent.sh", _defs(links), links, {"KEYSTONE_AGENT_EXTRA_PATH": str(bin_dir)})
    assert r["facts"].get("custom.ok") == 3
    for k in ("custom.link", "custom.dirlink", "custom.chain", "custom.proc", "custom.mac_alias"):
        assert r["check_errors"].get(k) == "refused", k
