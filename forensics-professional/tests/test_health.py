"""Tests for forensics.health."""

from __future__ import annotations


def test_overall_verdict_logic():
    from forensics.health.monitor import (
        HealthMonitor, Probe, Section,
        STATUS_FAIL, STATUS_OK, STATUS_WARN,
    )
    healthy = [Section("a", [Probe("x", STATUS_OK), Probe("y", STATUS_OK)])]
    degraded = [Section("a", [Probe("x", STATUS_OK), Probe("y", STATUS_WARN)])]
    failed = [Section("a", [Probe("x", STATUS_FAIL), Probe("y", STATUS_OK)])]

    assert HealthMonitor.overall(healthy) == "healthy"
    assert HealthMonitor.overall(degraded) == "degraded"
    assert HealthMonitor.overall(failed) == "failed"


def test_quick_check_returns_int():
    """quick_check must return an exit code suitable for HEALTHCHECK."""
    from forensics.health.monitor import quick_check
    rc = quick_check(silent=True)
    assert rc in (0, 1)


def test_probe_objects_are_safe_when_paths_missing():
    """Probes never raise — they always return a Section."""
    from forensics.health.monitor import (
        probe_directories, probe_audit, probe_modules,
        probe_resources, probe_tools,
    )
    for fn in [probe_directories, probe_audit, probe_modules,
               probe_resources, probe_tools]:
        section = fn()
        assert section.title
        assert isinstance(section.probes, list)
