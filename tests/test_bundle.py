import json
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

from harness import bundle


def _make_artifact(td: Path, cell_id: str) -> Path:
    art = td / "runs" / cell_id
    art.mkdir(parents=True, exist_ok=True)
    (art / "serial.log").write_text("[serial output]\n")
    (art / "dmesg.log").write_text(
        "[    1.234] BUG: KASAN: use-after-free in lua_lvm_alloc+0x10/0x30\n"
        "Call Trace:\n"
        " lua_lvm_alloc+0x10/0x30\n"
    )
    return art


def _sources(
    art: Path, cell_id: str, td: Path, commands=None, policies=None
) -> bundle.BundleSources:
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


class BundleTests(unittest.TestCase):
    def test_first_occurrence_writes_full_payload(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = _make_artifact(tdp, "cell1")
            store = bundle.BundleStore()
            sources = _sources(
                art,
                "cell1",
                tdp,
                commands=["echo hello", "ls /sys/kernel/security/lua"],
                policies=[],
            )
            bdir = bundle.write_bundle(
                store, sources, signature_sha1="a" * 40, signature_kind="primary"
            )

            # Bundle now lives inside the cell's artifact_dir as `bundle/`.
            self.assertEqual(bdir, art / "bundle")

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
                self.assertTrue((bdir / name).exists(), f"missing: {name}")
            # policies is a directory; the reproducer payload lists it as
            # one entry even when no policies were registered.
            self.assertTrue((bdir / "policies").is_dir())

            # cmdline + commands.sh + signature contents.
            self.assertEqual(
                (bdir / "cmdline").read_text().strip(),
                "lsm=capability,bpf,lua lua.lvm_pool_max=16",
            )
            self.assertIn("echo hello", (bdir / "commands.sh").read_text())
            sig_text = (bdir / "signature").read_text().splitlines()
            self.assertEqual(sig_text[0], "a" * 40)
            self.assertEqual(sig_text[1], "primary")

            meta = json.loads((bdir / "metadata.json").read_text())
            self.assertEqual(meta["signature_kind"], "primary")
            self.assertEqual(meta["signature_sha1"], "a" * 40)
            self.assertIsNone(meta["dup_of"])

    def test_second_occurrence_is_dup_pointer(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art1 = _make_artifact(tdp, "cell1")
            art2 = _make_artifact(tdp, "cell2")
            store = bundle.BundleStore()

            sig = "b" * 40
            b1 = bundle.write_bundle(
                store, _sources(art1, "cell1", tdp), signature_sha1=sig, signature_kind="primary"
            )
            b2 = bundle.write_bundle(
                store, _sources(art2, "cell2", tdp), signature_sha1=sig, signature_kind="primary"
            )

            self.assertNotEqual(b1, b2)
            # First bundle has full payload.
            self.assertTrue((b1 / "serial.log").exists())
            self.assertTrue((b1 / "kernel.sha").exists())
            # Second bundle has only metadata.json + dup_of.txt.
            self.assertTrue((b2 / "metadata.json").exists())
            self.assertTrue((b2 / "dup_of.txt").exists())
            self.assertFalse((b2 / "serial.log").exists())
            self.assertFalse((b2 / "kernel.sha").exists())
            meta2 = json.loads((b2 / "metadata.json").read_text())
            self.assertIsNotNone(meta2["dup_of"])
            # dup_of is a relative path from the duplicate bundle dir to the
            # first-occurrence bundle dir, so `cd "$(cat dup_of.txt)"` works
            # from inside any duplicate.
            self.assertEqual((b2 / meta2["dup_of"]).resolve(), b1.resolve())
            self.assertEqual(
                (b2 / "dup_of.txt").read_text().strip(),
                meta2["dup_of"],
            )

    def test_signature_kind_fallback_round_trips(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = _make_artifact(tdp, "cell1")
            store = bundle.BundleStore()
            bdir = bundle.write_bundle(
                store,
                _sources(art, "cell1", tdp),
                signature_sha1="c" * 40,
                signature_kind="fallback",
            )
            meta = json.loads((bdir / "metadata.json").read_text())
            self.assertEqual(meta["signature_kind"], "fallback")
            sig_lines = (bdir / "signature").read_text().splitlines()
            self.assertEqual(sig_lines[1], "fallback")

    def test_invalid_signature_kind_rejected(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            store = bundle.BundleStore()
            art = _make_artifact(tdp, "cell1")
            with self.assertRaises(ValueError):
                bundle.write_bundle(
                    store,
                    _sources(art, "cell1", tdp),
                    signature_sha1="d" * 40,
                    signature_kind="bogus",
                )

    def test_policies_dir_populated_when_provided(self):
        with TemporaryDirectory() as td:
            tdp = Path(td)
            art = _make_artifact(tdp, "cell1")
            pol_src = tdp / "examples"
            pol_src.mkdir()
            (pol_src / "hello.lua").write_text("-- hello policy\n")
            (pol_src / "deny.lua").write_text("-- deny policy\n")
            store = bundle.BundleStore()
            sources = _sources(
                art, "cell1", tdp, policies=[pol_src / "hello.lua", pol_src / "deny.lua"]
            )
            bdir = bundle.write_bundle(
                store, sources, signature_sha1="e" * 40, signature_kind="primary"
            )
            self.assertTrue((bdir / "policies" / "hello.lua").exists())
            self.assertTrue((bdir / "policies" / "deny.lua").exists())


if __name__ == "__main__":
    unittest.main()
