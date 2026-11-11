"""Unit tests for evidence bundle writing/dedup (harness.bundle)."""

import json
from pathlib import Path

import pytest
from harness import bundle


def _make_artifact(root: Path, cell_id: str) -> Path:
    art = root / "runs" / cell_id
    art.mkdir(parents=True, exist_ok=True)
    (art / "serial.log").write_text("[serial output]\n")
    (art / "dmesg.log").write_text(
        "[    1.234] BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30\n"
        "Call Trace:\n"
        " lua_lvm_alloc+0x10/0x30\n"
    )
    return art


def _sources(art, cell_id, root, commands=None, policies=None) -> bundle.BundleSources:
    return bundle.BundleSources(
        cell_id=cell_id,
        artifact_dir=art,
        cmdline="lsm=capability,bpf,lua lua.lvm_pool_max=16",
        kernel_tree=None,
        kernel_config_path=None,
        kernel_config_baseline=None,
        rootfs_image=None,
        policies=tuple(policies or ()),
        commands=tuple(commands or ()),
        decode_script=None,
        splat_slice=(
            "BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30",
            "Call Trace:",
            " lua_lvm_alloc+0x10/0x30",
        ),
    )


def test_first_occurrence_writes_full_payload(tmp_path):
    art = _make_artifact(tmp_path, "cell1")
    store = bundle.BundleStore()
    sources = _sources(
        art,
        "cell1",
        tmp_path,
        commands=["echo hello", "ls /sys/kernel/security/lua"],
        policies=[],
    )
    bdir = bundle.write_bundle(store, sources, signature_sha1="a" * 40, signature_kind="primary")

    # Bundle now lives inside the cell's artifact_dir as `bundle/`.
    assert bdir == art / "bundle"

    for name in (
        "kernel.sha",
        ".config",
        "config.diff",
        "cmdline",
        "commands.sh",
        "rootfs.sha256",
        "serial.log",
        "dmesg.txt",
        "decoded.txt",
        "signature",
        "metadata.json",
    ):
        assert (bdir / name).exists(), f"missing: {name}"
    # policies is a directory; the reproducer payload lists it as
    # one entry even when no policies were registered.
    assert (bdir / "policies").is_dir()

    # cmdline + commands.sh + signature contents.
    assert (bdir / "cmdline").read_text().strip() == "lsm=capability,bpf,lua lua.lvm_pool_max=16"
    assert "echo hello" in (bdir / "commands.sh").read_text()
    sig_text = (bdir / "signature").read_text().splitlines()
    assert sig_text[0] == "a" * 40
    assert sig_text[1] == "primary"

    meta = json.loads((bdir / "metadata.json").read_text())
    assert meta["signature_kind"] == "primary"
    assert meta["signature_sha1"] == "a" * 40
    assert meta["dup_of"] is None


def test_second_occurrence_is_dup_pointer(tmp_path):
    art1 = _make_artifact(tmp_path, "cell1")
    art2 = _make_artifact(tmp_path, "cell2")
    store = bundle.BundleStore()

    sig = "b" * 40
    b1 = bundle.write_bundle(
        store, _sources(art1, "cell1", tmp_path), signature_sha1=sig, signature_kind="primary"
    )
    b2 = bundle.write_bundle(
        store, _sources(art2, "cell2", tmp_path), signature_sha1=sig, signature_kind="primary"
    )

    assert b1 != b2
    # First bundle has full payload.
    assert (b1 / "serial.log").exists()
    assert (b1 / "kernel.sha").exists()
    # Second bundle has only metadata.json + dup_of.txt.
    assert (b2 / "metadata.json").exists()
    assert (b2 / "dup_of.txt").exists()
    assert not (b2 / "serial.log").exists()
    assert not (b2 / "kernel.sha").exists()
    meta2 = json.loads((b2 / "metadata.json").read_text())
    assert meta2["dup_of"] is not None
    # dup_of is a relative path from the duplicate bundle dir to the
    # first-occurrence bundle dir, so `cd "$(cat dup_of.txt)"` works
    # from inside any duplicate.
    assert (b2 / meta2["dup_of"]).resolve() == b1.resolve()
    assert (b2 / "dup_of.txt").read_text().strip() == meta2["dup_of"]


def test_signature_kind_fallback_round_trips(tmp_path):
    art = _make_artifact(tmp_path, "cell1")
    store = bundle.BundleStore()
    bdir = bundle.write_bundle(
        store,
        _sources(art, "cell1", tmp_path),
        signature_sha1="c" * 40,
        signature_kind="fallback",
    )
    meta = json.loads((bdir / "metadata.json").read_text())
    assert meta["signature_kind"] == "fallback"
    sig_lines = (bdir / "signature").read_text().splitlines()
    assert sig_lines[1] == "fallback"


def test_invalid_signature_kind_rejected(tmp_path):
    store = bundle.BundleStore()
    art = _make_artifact(tmp_path, "cell1")
    with pytest.raises(ValueError):
        bundle.write_bundle(
            store,
            _sources(art, "cell1", tmp_path),
            signature_sha1="d" * 40,
            signature_kind="bogus",
        )


def test_policies_dir_populated_when_provided(tmp_path):
    art = _make_artifact(tmp_path, "cell1")
    pol_src = tmp_path / "examples"
    pol_src.mkdir()
    (pol_src / "hello.lua").write_text("-- hello policy\n")
    (pol_src / "deny.lua").write_text("-- deny policy\n")
    store = bundle.BundleStore()
    sources = _sources(
        art, "cell1", tmp_path, policies=[pol_src / "hello.lua", pol_src / "deny.lua"]
    )
    bdir = bundle.write_bundle(store, sources, signature_sha1="e" * 40, signature_kind="primary")
    assert (bdir / "policies" / "hello.lua").exists()
    assert (bdir / "policies" / "deny.lua").exists()
