import unittest

from harness import lkdtm_cell


class LkdtmCellTests(unittest.TestCase):
    def test_provoke_missing_is_skip(self):
        r = {"verdict": "pass", "classifier_hits": []}
        out = lkdtm_cell.adjust_verdict_for_lkdtm(r, workload_returncode=77)
        self.assertEqual(out["verdict"], "skip:no-lkdtm")
        self.assertIn("CONFIG_LKDTM", out["reason"])

    def test_splat_observed_inverts_to_pass(self):
        # The regular cell would have classified this as kernel-bug; LKDTM
        # wrapper inverts that to pass since the splat was the desired output.
        r = {
            "verdict": "kernel-bug",
            "classifier_hits": [
                {"pattern": "BUG: KASAN", "line": 5, "substring": "BUG: KASAN: ..."}
            ],
        }
        out = lkdtm_cell.adjust_verdict_for_lkdtm(r, workload_returncode=0)
        self.assertEqual(out["verdict"], "pass")
        self.assertIn("classifier caught", out["reason"])

    def test_splat_missing_is_failure_of_classifier(self):
        # No classifier hits despite LKDTM running successfully: classifier
        # likely regressed. Report kernel-bug at the matrix level.
        r = {"verdict": "pass", "classifier_hits": []}
        out = lkdtm_cell.adjust_verdict_for_lkdtm(r, workload_returncode=0)
        self.assertEqual(out["verdict"], "kernel-bug")
        self.assertIn("classifier saw no splat", out["reason"])


if __name__ == "__main__":
    unittest.main()
