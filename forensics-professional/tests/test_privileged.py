"""Regression tests for the root-owned privilege helper.

These tests mock the privileged system calls; they do not install/remove
packages or mutate real filesystem flags.
"""
from __future__ import annotations

import runpy
import stat
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest


@pytest.fixture()
def privileged_helper():
    helper_path = Path(__file__).resolve().parent.parent / "config" / "forensics-privileged"
    return runpy.run_path(str(helper_path))


def test_helper_refuses_non_root(privileged_helper, monkeypatch):
    monkeypatch.setattr(privileged_helper["os"], "geteuid", lambda: 1000)
    assert privileged_helper["run"](["apt-update"]) == 1


def test_apt_install_uses_fixed_command_and_allowlisted_packages(
    privileged_helper, monkeypatch
):
    calls = []

    def fake_run(argv, *, env, check):
        calls.append((argv, env, check))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(privileged_helper["os"], "geteuid", lambda: 0)
    monkeypatch.setattr(privileged_helper["subprocess"], "run", fake_run)

    assert privileged_helper["run"](["apt-install", "curl", "unzip"]) == 0
    assert len(calls) == 1
    assert calls[0][0] == [
        "/usr/bin/apt-get",
        "install",
        "-y",
        "--no-install-recommends",
        "curl",
        "unzip",
    ]
    assert calls[0][1] == privileged_helper["SAFE_ENV"]
    assert calls[0][2] is False


@pytest.mark.parametrize(
    "package",
    [
        "--help",
        "/tmp/untrusted.deb",
        "curl;id",
        "bash",
        "../curl",
    ],
)
def test_apt_install_rejects_options_paths_and_unlisted_packages(
    privileged_helper, monkeypatch, package
):
    calls = []

    def fake_run(argv, *, env, check):
        calls.append(argv)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(privileged_helper["os"], "geteuid", lambda: 0)
    monkeypatch.setattr(privileged_helper["subprocess"], "run", fake_run)

    assert privileged_helper["run"](["apt-install", package]) == 2
    assert calls == []


def test_remove_has_a_separate_allowlist(privileged_helper, monkeypatch):
    calls = []

    def fake_run(argv, *, env, check):
        calls.append(argv)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(privileged_helper["os"], "geteuid", lambda: 0)
    monkeypatch.setattr(privileged_helper["subprocess"], "run", fake_run)

    assert privileged_helper["run"](["apt-remove", "curl"]) == 2
    assert calls == []
    assert privileged_helper["run"](["apt-remove", "tcpdump"]) == 0
    assert calls == [["/usr/bin/apt-get", "remove", "-y", "tcpdump"]]


def test_audit_append_only_rejects_user_supplied_paths(
    privileged_helper, monkeypatch
):
    monkeypatch.setattr(privileged_helper["os"], "geteuid", lambda: 0)

    def forbidden_open(*args, **kwargs):
        raise AssertionError("helper must not open a user-supplied path")

    monkeypatch.setattr(privileged_helper["os"], "open", forbidden_open)
    assert privileged_helper["run"](["audit-append-only", "/tmp/other.log"]) == 2


def test_audit_append_only_opens_fixed_path_nonblocking_and_sets_only_append(
    privileged_helper, monkeypatch
):
    helper_os = privileged_helper["os"]
    helper_fcntl = privileged_helper["fcntl"]
    opened = []
    ioctls = []

    def fake_open(path, flags):
        opened.append((path, flags))
        return 77

    monkeypatch.setattr(helper_os, "geteuid", lambda: 0)
    monkeypatch.setattr(helper_os, "open", fake_open)
    monkeypatch.setattr(
        helper_os,
        "fstat",
        lambda fd: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o640,
            st_uid=1001,
        ),
    )
    monkeypatch.setattr(helper_os, "close", lambda fd: None)
    monkeypatch.setattr(
        privileged_helper["pwd"],
        "getpwnam",
        lambda name: SimpleNamespace(pw_uid=1001),
    )

    def fake_ioctl(fd, request, argument):
        ioctls.append((fd, request, argument))
        if request == privileged_helper["FS_IOC_GETFLAGS"]:
            return struct.pack("I", 0)
        assert request == privileged_helper["FS_IOC_SETFLAGS"]
        assert struct.unpack("I", argument)[0] == privileged_helper["FS_APPEND_FL"]
        return argument

    monkeypatch.setattr(helper_fcntl, "ioctl", fake_ioctl)

    assert privileged_helper["run"](["audit-append-only"]) == 0
    assert len(opened) == 1
    path, flags = opened[0]
    assert path == privileged_helper["AUDIT_LOG"]
    assert flags & helper_os.O_NOFOLLOW
    assert flags & helper_os.O_NONBLOCK
    assert flags & helper_os.O_CLOEXEC
    assert [call[1] for call in ioctls] == [
        privileged_helper["FS_IOC_GETFLAGS"],
        privileged_helper["FS_IOC_SETFLAGS"],
    ]


def test_unknown_operation_fails_closed(privileged_helper, monkeypatch):
    monkeypatch.setattr(privileged_helper["os"], "geteuid", lambda: 0)
    assert privileged_helper["run"](["run-shell", "id"]) == 2
