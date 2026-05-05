"""Tests for forensics.modules."""

from __future__ import annotations

from pathlib import Path

import pytest


def test_registry_loads(tmp_audit_env):
    """Production registry parses cleanly into typed dataclasses."""
    from forensics.modules.registry import Registry, ModuleSpec

    repo = Path(__file__).resolve().parent.parent
    reg = Registry.load(repo / "modules" / "registry.json")

    # All categories declared
    assert "memory" in reg.categories()
    assert "disk" in reg.categories()

    # Sanity-check a specific module
    mem = reg["memory-forensics"]
    assert isinstance(mem, ModuleSpec)
    assert mem.stable_version != ""
    assert mem.estimated_size_mb > 0
    assert any(s.name == "volatility" for s in mem.submodules)


def test_every_submodule_has_installer():
    """No submodule is declared in the registry without an installer."""
    from forensics.modules.installers import INSTALLERS
    from forensics.modules.registry import Registry

    repo = Path(__file__).resolve().parent.parent
    reg = Registry.load(repo / "modules" / "registry.json")

    missing = []
    for name in reg.names():
        spec = reg[name]
        for sm in spec.submodules:
            if sm.name not in INSTALLERS.get(name, {}):
                missing.append(f"{name}/{sm.name}")
    assert not missing, f"submodules without installers: {missing}"


def test_every_submodule_has_verify_hint():
    """We refuse to ship a submodule we can't verify."""
    from forensics.modules.registry import Registry

    repo = Path(__file__).resolve().parent.parent
    reg = Registry.load(repo / "modules" / "registry.json")

    missing = []
    for name in reg.names():
        for sm in reg[name].submodules:
            if not sm.verify:
                missing.append(f"{name}/{sm.name}")
    assert not missing, f"submodules without verify hints: {missing}"


def test_verifier_resolves_hint_types():
    """check_hint understands binary / py: / file: prefixes."""
    from forensics.modules.verifier import check_hint

    # 'python3' is in PATH on every CI runner
    assert check_hint("python3")

    # py:os is always importable
    assert check_hint("py:os")

    # Nonexistent file/module returns False (never raises)
    assert not check_hint("file:/this/path/does/not/exist")
    assert not check_hint("py:nonexistent.module.path")
    assert not check_hint("definitely-not-a-real-binary-name-12345")


def test_module_manager_list_and_install_dry_run(tmp_audit_env):
    """The manager loads the registry and dry-runs without side effects."""
    from forensics.modules.manager import ModuleManager
    from forensics.modules.registry import Registry

    repo = Path(__file__).resolve().parent.parent
    reg = Registry.load(repo / "modules" / "registry.json")
    mgr = ModuleManager(registry=reg)

    assert len(mgr.list_modules()) > 0
    result = mgr.install("memory-forensics", dry_run=True, force=False)
    # dry run should not write a manifest
    assert not (mgr.installed_dir / "memory-forensics.json").exists()
    # nothing actually ran, so no submodule entries
    assert result.submodules == []


def test_module_manager_unknown_module_raises(tmp_audit_env):
    from forensics.modules.manager import ModuleManager
    from forensics.modules.registry import Registry

    repo = Path(__file__).resolve().parent.parent
    reg = Registry.load(repo / "modules" / "registry.json")
    mgr = ModuleManager(registry=reg)

    with pytest.raises(KeyError):
        mgr.install("does-not-exist", dry_run=True)


def test_chain_logger_noise_filter():
    from forensics.chain.logger import _is_noisy

    assert _is_noisy("ls -la")
    assert _is_noisy("cd /tmp")
    assert _is_noisy("")
    assert _is_noisy("clear")
    assert not _is_noisy("dd if=/dev/sda1 of=/tmp/disk.img")
    assert not _is_noisy("tcpdump -i eth0 -w out.pcap")
    assert not _is_noisy("openssl x509 -in cert.pem -text")
    # cat is never noisy (used for evidence)
    assert not _is_noisy("cat /evidence/file.txt")


def test_quantum_keygen_round_trip(tmp_audit_env):
    """Encrypted key blobs round-trip via the file format."""
    from forensics.quantum.keygen import encrypt_secret, decrypt_secret

    secret = b"\x00" * 4032           # ML-DSA-65 secret-key length
    passphrase = "very-strong-passphrase"

    blob = encrypt_secret(secret, passphrase)
    assert blob[:4] == b"MDSA"
    assert blob[4] == 1                # version
    assert len(blob) == 4 + 1 + 16 + 12 + 4032 + 16

    recovered = decrypt_secret(blob, passphrase)
    assert recovered == secret


def test_quantum_keygen_wrong_passphrase_fails(tmp_audit_env):
    from forensics.quantum.keygen import encrypt_secret, decrypt_secret

    blob = encrypt_secret(b"X" * 4032, "right-passphrase")
    with pytest.raises(Exception):
        decrypt_secret(blob, "wrong-passphrase")
