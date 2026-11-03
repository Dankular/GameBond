import unittest
from gamebond.pacing import BulkPacer


class PacingTests(unittest.TestCase):
    def test_burst_is_bounded_and_idle_does_not_accumulate_unlimited_credit(self):
        now = [0.0]
        pacer = BulkPacer(1000, 2000, clock=lambda: now[0])
        self.assertEqual(pacer.reserve(1000), 0)
        self.assertEqual(pacer.reserve(1000), 0)
        self.assertEqual(pacer.reserve(1000), 1)
        now[0] = 1
        self.assertEqual(pacer.reserve(1000), 1)
        now[0] = 100
        self.assertEqual(pacer.reserve(2000), 0)
        self.assertEqual(pacer.reserve(1000), 1)

    def test_rejects_invalid_rates_and_sizes(self):
        for rate in (0, -1, float('nan'), float('inf')):
            with self.assertRaises(ValueError):
                BulkPacer(rate, 1000)
        pacer = BulkPacer(1000, 1000)
        with self.assertRaises(ValueError):
            pacer.reserve(0)
