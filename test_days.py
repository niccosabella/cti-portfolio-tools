import unittest
from datetime import date

from pivot_out import resolution_is_recent


class TestResolutionAge(unittest.TestCase):
    TODAY = date(2026, 11, 17)

    def test_no_filter_keeps_old_records(self):
        self.assertTrue(
            resolution_is_recent("2020-12-27", None, self.TODAY)
        )

    def test_recent_record_is_kept(self):
        self.assertTrue(
            resolution_is_recent("2026-09-26", 90, self.TODAY)
        )

    def test_old_record_is_excluded(self):
        self.assertFalse(
            resolution_is_recent("2020-12-27", 90, self.TODAY)
        )

    def test_exact_boundary_is_kept(self):
        self.assertTrue(
            resolution_is_recent("2026-11-10", 7, self.TODAY)
        )

    def test_one_day_beyond_boundary_is_excluded(self):
        self.assertFalse(
            resolution_is_recent("2026-11-09", 7, self.TODAY)
        )

    def test_zero_days_keeps_today(self):
        self.assertTrue(
            resolution_is_recent("2026-11-17", 0, self.TODAY)
        )

    def test_missing_or_invalid_dates_are_excluded(self):
        for value in (None, "", "not-a-date"):
            with self.subTest(value=value):
                self.assertFalse(
                    resolution_is_recent(value, 90, self.TODAY)
                )

    def test_future_date_is_excluded(self):
        self.assertFalse(
            resolution_is_recent("2026-11-18", 90, self.TODAY)
        )


if __name__ == "__main__":
    unittest.main()