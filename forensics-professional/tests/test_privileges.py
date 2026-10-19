"""Regression tests for the root privilege boundary."""
from __future__ import annotations

import runpy
import stat
import struct
from pathlib import Path
from types import SimpleNamespace

ROOT = Path(__file__).resolve().parent.parent
HELPER_PATH = ROOT / "config" / "forensics-privileged"
SUDOERS_PATH = ROOT / "config" / "sudoers" / "sherlock"


def _load_helper():
    return runpy.run_path(str(HELPER_PATH), run_name="forensics_privileged_test")


def _pretend_root(monkeypatch, helper):
    monkeypatch.setattr(helper["os"], "geteuid", lambda: 0)


def test_sudoers_only_grants_the_validating_helper():
    rules = [
        line.strip()
        for line in SUDOERS_PATH.read_text(encoding="utf-8").splitlines()
        if "NOPASSWD:" in line
    ]
    assert rules == [
        "sherlock ALL=(root) NOPASSWD: /usr/local/sbin/forensics-privileged *"
    ]


def test_package_helper_accepts_only_exact_allowlisted_packages(monkeypatch):
    helper = _load_helper()
    _pretend_root(monkeypatch, helper)
    calls = []

    def fake_run(command, *, env, check):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(helper["subprocess"], "run", fake_run)

    assert helper["run"](["apt-install", "curl", "unzip"]) == 0
    assert calls == [[
        "/usr/bin/apt-get", "install", "-y", "--no-install-recommends",
        "curl", "unzip",
    ]]

    assert helper["run"](["apt-install", "bash"]) == 2
    assert helper["run"](["apt-install", "--help"]) == 2
    assert helper["run"](["apt-install", "/tmp/evil.deb"]) == 2
    assert len(calls) == 1


def test_package_remove_is_allowlisted_and_has_fixed_arguments(monkeypatch):
    helper = _load_helper()
    _pretend_root(monkeypatch, helper)
    calls = []

    def fake_run(command, *, env, check):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(helper["subprocess"], "run", fake_run)

    assert helper["run"](["apt-remove", "tcpdump"]) == 0
    assert calls == [["/usr/bin/apt-get", "remove", "-y", "tcpdump"]]
    assert helper["run"](["apt-remove", "bash"]) == 2
    assert len(calls) == 1


def test_helper_rejects_arbitrary_operations(monkeypatch):
    helper = _load_helper()
    _pretend_root(monkeypatch, helper)
    calls = []

    def fake_run(command, *, env, check):
        calls.append(command)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(helper["subprocess"], "run", fake_run)

    assert helper["run"](["shell", "bash"]) == 2
    assert helper["run"](["apt-update", "anything"]) == 2
    assert calls == []


def test_audit_append_only_helper_uses_fixed_fd_and_sets_only_append(monkeypatch):
    helper = _load_helper()
    _pretend_root(monkeypatch, helper)
    calls = []
    closed = []

    monkeypatch.setattr(helper["os"], "open", lambda path, flags: (
        calls.append(("open", path, flags)) or 123
    ))
    monkeypatch.setattr(
        helper["os"],
        "fstat",
        lambda fd: SimpleNamespace(st_mode=stat.S_IFREG, st_uid=1000),
    )
    monkeypatch.setattr(helper["os"], "close", lambda fd: closed.append(fd))
    monkeypatch.setattr(helper["pwd"], "getpwnam", lambda name: SimpleNamespace(pw_uid=1000))

    def fake_ioctl(fd, command, data):
        calls.append(("ioctl", fd, command, struct.unpack("I", data)[0]))
        if command == helper["FS_IOC_GETFLAGS"]:
            return struct.pack("I", 0x00000010)
        return 0

    monkeypatch.setattr(helper["fcntl"], "ioctl", fake_ioctl)

    assert helper["run"](["audit-append-only"]) == 0
    assert calls[0][0:2] == ("open", "/var/log/forensics/audit.log")
    set_calls = [call for call in calls if len(call) > 2 and call[0] == "ioctl"
                 and call[2] == helper["FS_IOC_SETFLAGS"]]
    assert set_calls == [("ioctl", 123, helper["FS_IOC_SETFLAGS"], 0x30)]
    assert closed == [123]


def test_audit_append_only_rejects_symlinks_and_wrong_owners(monkeypatch):
    helper = _load_helper()
    _pretend_root(monkeypatch, helper)
    monkeypatch.setattr(helper["os"], "open", lambda path, flags: 123)
    monkeypatch.setattr(
        helper["os"],
        "fstat",
        lambda fd: SimpleNamespace(st_mode=stat.S_IFLNK, st_uid=1000),
    )
    monkeypatch.setattr(helper["os"], "close", lambda fd: None)
    monkeypatch.setattr(helper["pwd"], "getpwnam", lambda name: SimpleNamespace(pw_uid=1000))
    monkeypatch.setattr(helper["fcntl"], "ioctl", lambda *args: b"\\x00\\x00\\x00\\x00")

    assert helper["run"](["audit-append-only"]) == 1
