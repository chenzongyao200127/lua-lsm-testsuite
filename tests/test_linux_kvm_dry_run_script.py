"""Static-shape pinning tests for scripts/linux-kvm-dry-run.sh.

The dry-run script is the reproducible operator entry point for live KVM
acceptance evidence (the AC-9 deferred path). The harness REFUSES to plan
on Darwin so we cannot execute the script in this dev-host CI; instead
these tests pin the operator-facing CONTRACT in the script source:

- bash syntax is clean (`bash -n` exits 0)
- file is executable
- the new --prereqs-only operator mode is documented in the header
- check_prereqs() function is defined (the prereq logic is factored, not
  duplicated inline anywhere)
- the documented env contract (WORKSPACE/KERNEL/ROOTFS) is preserved
- the artifact-path map block is present so the reviewer's paste-back
  checklist is unambiguous from the script source alone
- the audit-trail tee log destination is documented

These tests deliberately do NOT execute the script's full body. A
regression in the operator contract would silently degrade the deferred
path's reliability without an executable signal otherwise.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import unittest
from pathlib import Path

import pytest

pytestmark = pytest.mark.slow

PROJECT_ROOT = Path(__file__).resolve().parents[1]
SCRIPT_PATH = PROJECT_ROOT / "scripts" / "linux-kvm-dry-run.sh"


class LinuxKvmDryRunScriptShapeTests(unittest.TestCase):
    """Static-shape tests pinning the operator contract of the dry-run script."""

    def test_script_file_exists(self):
        self.assertTrue(
            SCRIPT_PATH.is_file(),
            f"expected operator script at {SCRIPT_PATH}",
        )

    def test_script_is_executable(self):
        mode = SCRIPT_PATH.stat().st_mode
        self.assertTrue(
            bool(mode & stat.S_IXUSR),
            f"{SCRIPT_PATH} must be executable by the owner",
        )

    def test_bash_syntax_check_passes(self):
        # `bash -n` parses the script without executing. We require bash
        # to be on PATH; on a sane dev host this is always the case.
        bash = shutil.which("bash")
        self.assertIsNotNone(bash, "bash must be available on PATH")
        result = subprocess.run(
            [bash, "-n", str(SCRIPT_PATH)],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(
            result.returncode,
            0,
            f"bash -n failed: stdout={result.stdout!r} stderr={result.stderr!r}",
        )

    def test_check_prereqs_function_defined(self):
        # The prereq logic must be factored into a function so --prereqs-only
        # can invoke it without running the full body. Inline duplication
        # would silently let the two code paths drift.
        body = SCRIPT_PATH.read_text()
        self.assertIn(
            "check_prereqs() {",
            body,
            "check_prereqs() function definition must be present",
        )

    def test_prereqs_only_flag_documented_and_handled(self):
        body = SCRIPT_PATH.read_text()
        self.assertIn(
            "--prereqs-only",
            body,
            "--prereqs-only operator mode must appear in the script",
        )
        # The flag must be parsed in the arg loop, not just documented.
        # We check for a case branch matching the literal flag spelling.
        self.assertRegex(
            body,
            r"--prereqs-only\s*\)",
            "--prereqs-only must have a parsed case branch in the arg loop",
        )

    def test_env_contract_documented(self):
        # The header must mention every required env var by name so
        # operator paste-back doesn't depend on tribal knowledge.
        body = SCRIPT_PATH.read_text()
        for env_var in ("WORKSPACE", "KERNEL", "ROOTFS"):
            self.assertIn(
                env_var,
                body,
                f"required env var {env_var} must be documented in the script",
            )
        for env_var in ("RUNS_ROOT", "PORT_BASE", "PARALLEL"):
            self.assertIn(
                env_var,
                body,
                f"optional env var {env_var} must be documented in the script",
            )

    def test_artifact_path_map_block_present(self):
        # The header must enumerate the artifact paths each step produces
        # so the reviewer's paste-back checklist is unambiguous from the
        # script source alone.
        body = SCRIPT_PATH.read_text()
        self.assertIn(
            "Artifact-path map per step",
            body,
            "header must include the 'Artifact-path map per step' block",
        )
        # And the per-step artifact filenames must appear so the operator
        # knows what to look for at each step.
        for required_artifact in (
            "cell.json",
            "serial.log",
            "dmesg.log",
            "journalctl-kb.txt",
            "result.json",
            "matrix.json",
            "system.txt",
            "command.txt",
            "unixbench.log",
            "file_post_open",
        ):
            self.assertIn(
                required_artifact,
                body,
                f"artifact-path map must mention {required_artifact}",
            )

    def test_audit_trail_tee_log_documented(self):
        # The script auto-tees full output to a per-run log so the
        # operator's paste-back path is unambiguous. The mechanism must
        # be both documented in the header and present in the body.
        body = SCRIPT_PATH.read_text()
        self.assertIn(
            "Audit-trail log",
            body,
            "header must mention the audit-trail tee log",
        )
        self.assertIn(
            "DRY_RUN_LOG=",
            body,
            "DRY_RUN_LOG variable must be assigned in the script body",
        )
        self.assertRegex(
            body,
            r"tee -a\s+\"\$\{DRY_RUN_LOG\}\"",
            "audit-trail tee must reference ${DRY_RUN_LOG}",
        )

    def test_step5_uses_env_override_not_no_kvm_flag(self):
        # Round 6 fix that must not regress: Step 5 must NOT pass --no-kvm
        # to the harness, and MUST set LUA_LSM_TESTSUITE_KVM_PATH instead.
        body = SCRIPT_PATH.read_text()
        self.assertIn(
            "LUA_LSM_TESTSUITE_KVM_PATH=/nonexistent",
            body,
            "Step 5 must use the env override to exercise skip:no-kvm",
        )
        # Soft check: --no-kvm must not appear as an argv flag to harness.
        # We allow it to appear in the explanatory comment, so we check
        # for the actual invocation pattern: `--no-kvm \` or `--no-kvm$`
        # on a line that does not start with a comment marker.
        for line in body.splitlines():
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            self.assertNotIn(
                "--no-kvm",
                stripped,
                "Step 5 must not pass --no-kvm to the harness; "
                "it bypasses the skip branch instead of exercising it",
            )

    def test_darwin_host_gate_present(self):
        # The harness refuses to plan on Darwin and the script must fail
        # fast with a clear diagnostic before reaching any harness call.
        body = SCRIPT_PATH.read_text()
        self.assertRegex(
            body,
            r'"?\$\(uname -s\)"?\s*=\s*"Darwin"',
            "Darwin host gate must be present so the script fails fast on macOS",
        )
        self.assertIn(
            "must run on a Linux KVM host",
            body,
            "Darwin gate diagnostic must mention Linux KVM host requirement",
        )

    def test_dev_kvm_precondition_present(self):
        # /dev/kvm must be checked inside check_prereqs() so the operator
        # learns about a missing KVM device before the harness wastes
        # time spawning QEMU and failing.
        body = SCRIPT_PATH.read_text()
        self.assertIn(
            "/dev/kvm",
            body,
            "/dev/kvm must be referenced (precondition check)",
        )
        self.assertRegex(
            body,
            r"!\s*-e\s*/dev/kvm",
            "/dev/kvm existence check must be present in check_prereqs",
        )

    def test_launcher_env_default_present(self):
        # The dry-run script must pin an explicit absolute launcher path
        # rooted in this repo's vendored tools/ directory.
        body = SCRIPT_PATH.read_text()
        self.assertRegex(
            body,
            r'LAUNCHER="\$\{LAUNCHER:-\$\{WORKSPACE\}/lua-lsm-testsuite/tools/run_qemu_anolis\.sh\}"',
            "LAUNCHER env default must point at the vendored launcher",
        )

    def test_launcher_and_repo_preconditions_present(self):
        # check_prereqs() must validate the harness repo checkout AND
        # the resolved LAUNCHER file. Without these checks, the
        # operator would only learn the launcher is wrong when QEMU
        # spawn fails several seconds into the run.
        body = SCRIPT_PATH.read_text()
        self.assertRegex(
            body,
            r'!\s*-d\s*"\$\{WORKSPACE\}/lua-lsm-testsuite"',
            "check_prereqs() must verify ${WORKSPACE}/lua-lsm-testsuite exists",
        )
        self.assertRegex(
            body,
            r'!\s*-r\s*"\$\{LAUNCHER\}"',
            "check_prereqs() must verify ${LAUNCHER} is readable",
        )
        self.assertRegex(
            body,
            r'!\s*-x\s*"\$\{LAUNCHER\}"',
            "check_prereqs() must verify ${LAUNCHER} is executable",
        )

    def _harness_invocation_blocks(self, subcommand: str) -> list[str]:
        """Return the multi-line argv text for every non-comment
        `python3 -m harness <subcommand>` invocation in the script.

        The script uses backslash line-continuation; each invocation is
        a single logical command spanning consecutive backslash-terminated
        lines. We walk non-comment lines, find each `-m harness <sub>`
        anchor, then accumulate continuation lines until one does not
        end in backslash.
        """
        body = SCRIPT_PATH.read_text()
        lines = body.splitlines()
        blocks: list[str] = []
        i = 0
        while i < len(lines):
            stripped = lines[i].lstrip()
            if stripped.startswith("#"):
                i += 1
                continue
            if f"-m harness {subcommand}" in lines[i]:
                start = i
                while i < len(lines) and lines[i].rstrip().endswith("\\"):
                    i += 1
                # Include the final line of the invocation too.
                blocks.append("\n".join(lines[start : i + 1]))
            i += 1
        return blocks

    def test_every_harness_run_passes_launcher_and_share_dir(self):
        # Every `python3 -m harness run` invocation in the script must
        # pass --launcher "${LAUNCHER}" AND --share-dir "${WORKSPACE}".
        # Without --share-dir
        # _base_env() does not set SHARE_DIR/ENABLE_SHARE, so guest
        # workloads do not see /mnt/host/lua-lsm-tools.
        blocks = self._harness_invocation_blocks("run")
        self.assertGreaterEqual(
            len(blocks),
            4,
            "expected at least 4 `harness run` invocations (steps 1, 3, 4, 5); "
            f"found {len(blocks)} -- did the script structure change?",
        )
        for block in blocks:
            self.assertIn(
                '--launcher "${LAUNCHER}"',
                block,
                f"harness run invocation missing --launcher: {block!r}",
            )
            self.assertIn(
                '--share-dir "${WORKSPACE}"',
                block,
                f"harness run invocation missing --share-dir: {block!r}",
            )

    def test_matrix_invocation_passes_launcher_and_share_dir(self):
        # The single `python3 -m harness matrix` invocation must pass
        # both flags too. matrix.assert_share_dir refuses to run if
        # SHARE_DIR is missing required entries, but only when
        # --share-dir is supplied; without the flag, planning silently
        # skips the workspace check entirely.
        blocks = self._harness_invocation_blocks("matrix")
        self.assertEqual(
            len(blocks),
            1,
            f"expected exactly 1 `harness matrix` invocation; got {len(blocks)}",
        )
        block = blocks[0]
        self.assertIn(
            '--launcher "${LAUNCHER}"',
            block,
            f"harness matrix invocation missing --launcher: {block!r}",
        )
        self.assertIn(
            '--share-dir "${WORKSPACE}"',
            block,
            f"harness matrix invocation missing --share-dir: {block!r}",
        )

    def test_artifact_path_map_unchanged(self):
        # Regression guard: the Round 7 artifact-path map block must
        # survive Round 8 edits. If a future round trims the header,
        # the reviewer's paste-back checklist degrades silently.
        body = SCRIPT_PATH.read_text()
        self.assertIn(
            "Artifact-path map per step",
            body,
            "Round 7 artifact-path map header block was removed",
        )
        for required_artifact in (
            "cell.json",
            "serial.log",
            "matrix.json",
            "unixbench.log",
            "file_post_open",
        ):
            self.assertIn(
                required_artifact,
                body,
                f"artifact-path map no longer mentions {required_artifact}",
            )

    def test_step3_perf_proof_path_matches_emitted_schema(self):
        # Round 9 fix: the dry-run script documents the operator's
        # paste-back proof path for the AC-5.1 hook-delta acceptance
        # evidence. The harness writes perf data under
        #   result["perf"] = {"snapshots": {"before","after"}, "deltas": ...}
        # (harness/cell_runner.py:465-467), and perf_snapshot.diff()
        # keys deltas under lsm_funcs.<hook>.count
        # (harness/perf_snapshot.py:121-133).
        #
        # The pre-Round-9 spelling pointed at nonexistent fields:
        #   result.json.perf.counters_before.file_post_open.count
        #   result.json.perf.counters_after.file_post_open.count
        # Neither "counters_before" nor "counters_after" exists at
        # perf.* in the emitted schema -- the snapshot's own "counters"
        # key holds top-level kernel stats, not per-hook counts. An
        # operator following the old spelling would paste back null
        # values even when the perf cell succeeded.
        #
        # This test pins the corrected schema path AND forbids the
        # wrong spellings so a future round cannot silently regress
        # the operator-facing contract on a host where the script
        # itself cannot execute (Darwin).
        body = SCRIPT_PATH.read_text()
        self.assertIn(
            "perf.deltas.lsm_funcs.file_post_open.count",
            body,
            "Step 3 hook-delta proof must reference the actually-emitted "
            "schema path: result.json.perf.deltas.lsm_funcs.file_post_open.count",
        )
        for wrong_path in ("perf.counters_before", "perf.counters_after"):
            self.assertNotIn(
                wrong_path,
                body,
                f"Step 3 hook-delta proof must not reference {wrong_path} -- "
                "neither key exists at perf.* in the emitted result.json",
            )


class DarwinHostInvocationTests(unittest.TestCase):
    """Drive --prereqs-only on the current (Darwin) test host and assert
    the Darwin gate fires before any further precondition runs.
    """

    def test_prereqs_only_exits_2_on_darwin(self):
        # This test is meaningful only on Darwin; skip on other systems
        # so a Linux CI run doesn't false-fail.
        import platform

        if platform.system() != "Darwin":
            self.skipTest("Darwin-host-specific gate test")
        bash = shutil.which("bash")
        self.assertIsNotNone(bash)
        result = subprocess.run(
            [bash, str(SCRIPT_PATH), "--prereqs-only"],
            capture_output=True,
            text=True,
            check=False,
            env={**os.environ, "WORKSPACE": "/tmp"},
        )
        self.assertEqual(
            result.returncode,
            2,
            f"expected exit 2 on Darwin, got {result.returncode}; "
            f"stdout={result.stdout!r} stderr={result.stderr!r}",
        )
        self.assertIn(
            "must run on a Linux KVM host",
            result.stderr,
            "Darwin gate diagnostic must mention Linux KVM host requirement",
        )


if __name__ == "__main__":
    unittest.main()
