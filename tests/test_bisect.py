import unittest

from harness import bisect


class BisectTests(unittest.TestCase):
    def test_all_pass_is_zero(self):
        self.assertEqual(
            bisect.exit_code_from_totals(
                {"executed": 4, "passed": 4, "failed": 0, "skipped": 0, "aborted": 0}
            ),
            0,
        )

    def test_any_fail_is_one(self):
        self.assertEqual(
            bisect.exit_code_from_totals(
                {"executed": 4, "passed": 3, "failed": 1, "skipped": 0, "aborted": 0}
            ),
            1,
        )

    def test_aborted_treated_as_fail(self):
        self.assertEqual(
            bisect.exit_code_from_totals(
                {"executed": 4, "passed": 3, "failed": 0, "skipped": 0, "aborted": 1}
            ),
            1,
        )

    def test_all_skip_is_125(self):
        self.assertEqual(
            bisect.exit_code_from_totals(
                {"executed": 4, "passed": 0, "failed": 0, "skipped": 4, "aborted": 0}
            ),
            125,
        )

    def test_no_cells_is_128(self):
        self.assertEqual(
            bisect.exit_code_from_totals({"executed": 0}),
            128,
        )

    def test_partial_skip_with_pass_is_zero(self):
        # Non-trivial signal: 3 cells passed and 1 skipped -> bisect treats commit as good.
        self.assertEqual(
            bisect.exit_code_from_totals(
                {"executed": 4, "passed": 3, "failed": 0, "skipped": 1, "aborted": 0}
            ),
            0,
        )

    def test_exit_code_from_matrix_dict(self):
        m = {"totals": {"executed": 1, "passed": 1, "failed": 0, "skipped": 0, "aborted": 0}}
        self.assertEqual(bisect.exit_code_from_matrix(m), 0)

    def test_exit_code_from_matrix_missing_totals(self):
        self.assertEqual(bisect.exit_code_from_matrix({}), 128)


if __name__ == "__main__":
    unittest.main()
