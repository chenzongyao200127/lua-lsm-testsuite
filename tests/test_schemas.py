import unittest

from harness.schemas import (
    BUNDLE_FILES,
    LSM_FUNCS_ROW_KEYS,
    REQUIRED_COUNTER_KEYS,
    SCHEMA_VERSION,
    SIGNATURE_KINDS,
    VERDICT_CLASSIFICATION,
    aggregate_totals,
    aggregate_verdict,
    empty_bundle_metadata,
    empty_matrix,
    empty_result,
    is_fail,
    is_pass,
    is_skip,
    lsm_funcs_row,
)


class SchemasTests(unittest.TestCase):
    def test_empty_result_required_fields(self):
        r = empty_result("c123")
        for key in ("schema_version", "cell_id", "verdict", "classifier_hits",
                    "perf", "artifacts", "host", "cmdline"):
            self.assertIn(key, r)
        self.assertEqual(r["schema_version"], SCHEMA_VERSION)
        self.assertEqual(r["cell_id"], "c123")
        # journalctl_kb was renamed to journalctl_log; the old name must not leak.
        self.assertIn("journalctl_log", r["artifacts"])
        self.assertNotIn("journalctl_kb", r["artifacts"])

    def test_verdict_classification(self):
        self.assertTrue(is_pass("pass"))
        self.assertTrue(is_fail("kernel-bug"))
        self.assertTrue(is_skip("skip:no-kvm"))
        self.assertTrue(is_skip("skip:stats-unavailable"))
        self.assertFalse(is_pass("kernel-bug"))
        self.assertFalse(is_skip("pass"))
        # The bare "stats-unavailable" verdict was renamed; the old form must
        # no longer classify as skip.
        self.assertFalse(is_skip("stats-unavailable"))

    def test_normative_classification_table(self):
        # Every entry in the table must agree with the helper functions, so
        # TAP/KTAP and bisect-run never disagree about a verdict.
        for verdict, klass in VERDICT_CLASSIFICATION.items():
            if klass == "pass":
                self.assertTrue(is_pass(verdict), verdict)
            elif klass == "fail":
                self.assertTrue(is_fail(verdict), verdict)
            elif klass == "skip":
                self.assertTrue(is_skip(verdict), verdict)
            else:
                self.fail(f"unknown classification {klass!r} for {verdict!r}")

    def test_aggregate_totals(self):
        cells = [
            {"verdict": "pass"},
            {"verdict": "pass"},
            {"verdict": "kernel-bug"},
            {"verdict": "skip:no-kvm"},
            {"verdict": "skip:stats-unavailable"},
            {"verdict": "aborted"},
            {"verdict": None},  # not yet executed
        ]
        t = aggregate_totals(cells)
        self.assertEqual(t["planned"], 7)
        self.assertEqual(t["executed"], 6)
        self.assertEqual(t["passed"], 2)
        self.assertEqual(t["failed"], 1)
        self.assertEqual(t["skipped"], 2)
        self.assertEqual(t["aborted"], 1)

    def test_aggregate_verdict(self):
        self.assertEqual(aggregate_verdict({"executed": 0}), "no-cells")
        self.assertEqual(
            aggregate_verdict({"executed": 3, "passed": 3, "failed": 0, "skipped": 0, "aborted": 0}),
            "pass",
        )
        self.assertEqual(
            aggregate_verdict({"executed": 3, "passed": 2, "failed": 1, "skipped": 0, "aborted": 0}),
            "fail",
        )
        self.assertEqual(
            aggregate_verdict({"executed": 2, "passed": 1, "failed": 0, "skipped": 0, "aborted": 1}),
            "fail",
        )
        self.assertEqual(
            aggregate_verdict({"executed": 4, "passed": 0, "failed": 0, "skipped": 4, "aborted": 0}),
            "skip-all",
        )

    def test_empty_matrix_shape(self):
        m = empty_matrix()
        self.assertEqual(m["schema_version"], SCHEMA_VERSION)
        self.assertEqual(m["totals"]["planned"], 0)

    def test_required_counter_keys_cover_ac_5_1(self):
        # AC-5.1: lvm.{nalloc,nfree,nusage}, lmem.{nalloc,nrealloc,nfree,total,
        # average,minimum,maximum}, kvcache.{nalloc,nfree,nusage}.
        expected = {
            "lvm.nalloc", "lvm.nfree", "lvm.nusage",
            "lmem.nalloc", "lmem.nrealloc", "lmem.nfree",
            "lmem.total", "lmem.average", "lmem.minimum", "lmem.maximum",
            "kvcache.nalloc", "kvcache.nfree", "kvcache.nusage",
        }
        self.assertEqual(set(REQUIRED_COUNTER_KEYS), expected)

    def test_lsm_funcs_row_shape(self):
        row = lsm_funcs_row("file_open", nlsm=1, count=5, total=5000, average=1000, maxtime=2500)
        self.assertEqual(set(row.keys()), set(LSM_FUNCS_ROW_KEYS))
        self.assertEqual(row["name"], "file_open")
        self.assertEqual(row["count"], 5)

    def test_bundle_metadata_requires_signature_kind(self):
        m = empty_bundle_metadata("c123", "abc123", "primary")
        self.assertEqual(m["schema_version"], SCHEMA_VERSION)
        self.assertEqual(m["signature_kind"], "primary")
        self.assertEqual(m["files"], list(BUNDLE_FILES))

        m2 = empty_bundle_metadata("c123", "abc123", "fallback")
        self.assertEqual(m2["signature_kind"], "fallback")

        for kind in SIGNATURE_KINDS:
            empty_bundle_metadata("c", "h", kind)  # must not raise

        with self.assertRaises(ValueError):
            empty_bundle_metadata("c123", "abc123", "primary-typo")


if __name__ == "__main__":
    unittest.main()
