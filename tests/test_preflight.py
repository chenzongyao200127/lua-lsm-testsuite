import unittest
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest.mock import patch

from harness import preflight, ssh


class ImageWarmTests(unittest.TestCase):
    def test_marker_present_returns_none(self):
        with TemporaryDirectory() as td:
            marker = Path(td) / ".warm-marker"
            marker.touch()
            self.assertIsNone(preflight.image_warm_check(Path(td) / "img.qcow2", marker))

    def test_marker_missing_returns_skip(self):
        with TemporaryDirectory() as td:
            marker = Path(td) / "nope"
            r = preflight.image_warm_check(Path(td) / "img.qcow2", marker)
            self.assertIsNotNone(r)
            self.assertEqual(r["verdict"], "skip:image-not-warm")
            self.assertIn("make image-warm", r["remediation"])

    def test_no_image_no_check(self):
        self.assertIsNone(preflight.image_warm_check(None, None))


class GuestPreflightTests(unittest.TestCase):
    def _target(self) -> ssh.SshTarget:
        return ssh.SshTarget(host="127.0.0.1", port=10023, user="root", key_path=Path("/dev/null"))

    def test_host_share_mounted_returns_none(self):
        with patch.object(
            ssh, "run", return_value=ssh.SshResult(returncode=0, stdout="", stderr="")
        ):
            self.assertIsNone(preflight.host_share_check(self._target()))

    def test_host_share_unmounted_returns_skip(self):
        with patch.object(
            ssh,
            "run",
            return_value=ssh.SshResult(returncode=32, stdout="", stderr="not a mountpoint"),
        ):
            r = preflight.host_share_check(self._target())
            self.assertIsNotNone(r)
            self.assertEqual(r["verdict"], "skip:fixture-missing")


if __name__ == "__main__":
    unittest.main()
