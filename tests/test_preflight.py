"""Unit tests for guest/host preflight gates (harness.preflight)."""

from pathlib import Path

from harness import preflight, ssh


def test_marker_present_returns_none(tmp_path):
    marker = tmp_path / ".warm-marker"
    marker.touch()
    assert preflight.image_warm_check(tmp_path / "img.qcow2", marker) is None


def test_marker_missing_returns_skip(tmp_path):
    marker = tmp_path / "nope"
    r = preflight.image_warm_check(tmp_path / "img.qcow2", marker)
    assert r is not None
    assert r["verdict"] == "skip:image-not-warm"
    assert "make image-warm" in r["remediation"]


def test_no_image_no_check():
    assert preflight.image_warm_check(None, None) is None


def test_host_share_mounted_returns_none(monkeypatch):
    target = ssh.SshTarget(host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null"))
    monkeypatch.setattr(
        ssh, "run", lambda *a, **kw: ssh.SshResult(returncode=0, stdout="", stderr="")
    )
    assert preflight.host_share_check(target) is None


def test_host_share_unmounted_returns_skip(monkeypatch):
    target = ssh.SshTarget(host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null"))
    monkeypatch.setattr(
        ssh,
        "run",
        lambda *a, **kw: ssh.SshResult(returncode=32, stdout="", stderr="not a mountpoint"),
    )
    r = preflight.host_share_check(target)
    assert r is not None
    assert r["verdict"] == "skip:fixture-missing"
