"""Pure state machines: replicated-copy ledger and per-path MTU search."""
import unittest

from gamebond import path_quality
from gamebond.path_quality import CopyLedger, MtuProber, MTU_STRIKES, MTU_RECHECK_SECONDS

A, B = (0, ("h", 1)), (1, ("h", 2))


class CopyLedgerTests(unittest.TestCase):
    def test_both_paths_delivering_is_seen_on_both(self):
        ledger = CopyLedger()
        ledger.first(7, A, [A, B], 0.0)
        self.assertEqual(ledger.duplicate(7, B, 0.004), ("pending", 0.004))
        self.assertEqual(sorted(ledger.resolve(1.0, .05)), [(A, "seen"), (B, "seen")])

    def test_absent_copy_is_missed_then_reversed_when_it_turns_up_late(self):
        ledger = CopyLedger()
        ledger.first(7, A, [A, B], 0.0)
        self.assertEqual(sorted(ledger.resolve(.1, .05)), [(A, "seen"), (B, "missed")])
        state, lag = ledger.duplicate(7, B, .2)
        self.assertEqual(state, "late")
        self.assertAlmostEqual(lag, .2)
        self.assertIsNone(ledger.duplicate(7, B, .3))  # reversed once only

    def test_not_resolved_before_delay_and_single_path_gives_no_comparison(self):
        ledger = CopyLedger()
        ledger.first(1, A, [A, B], 0.0)
        ledger.first(2, A, [A], 0.001)
        self.assertEqual(ledger.resolve(.02, .05), [])
        self.assertEqual(sorted(ledger.resolve(.06, .05)), [(A, "seen"), (B, "missed")])
        self.assertEqual(ledger.resolve(.2, .05), [])

    def test_unknown_or_repeated_copy_is_ignored(self):
        ledger = CopyLedger()
        self.assertIsNone(ledger.duplicate(99, A, 0.0))
        ledger.first(3, A, [A, B], 0.0)
        self.assertIsNone(ledger.duplicate(3, A, .01))  # same path twice

    def test_memory_is_bounded(self):
        ledger = CopyLedger(capacity=8)
        for n in range(100):
            ledger.first(n, A, [A, B], float(n))
        self.assertLessEqual(ledger.stats()["pending"], 8)
        ledger.resolve(1000.0, .05)
        self.assertLessEqual(ledger.stats()["resolved"], 8)
        with self.assertRaises(ValueError):
            CopyLedger(capacity=0)


class MtuProberTests(unittest.TestCase):
    def nonces(self):
        counter = iter(range(1, 10**6))
        return lambda: next(counter)

    def run_search(self, true_mtu, answers=True, seconds=200):
        prober, new = MtuProber(1365, 548), self.nonces()
        now = 0.0
        while now < seconds:
            for nonce, size in prober.due(now, new):
                if answers and size <= true_mtu:
                    prober.acknowledge(nonce, size)
            now += .25
        return prober

    def test_full_size_path_confirms_ceiling(self):
        prober = self.run_search(1500)
        self.assertEqual((prober.path_mtu, prober.capable), (1365, True))

    def test_small_path_settles_on_largest_ladder_size_that_fits(self):
        prober = self.run_search(1250)
        self.assertEqual(prober.path_mtu, 1232)
        self.assertIn(1365, prober.stats()["failed_sizes"])

    def test_silent_peer_never_shrinks_the_path(self):
        # A peer that predates the probe message looks like a path dropping
        # everything large; no answer at all must not be read as a tiny MTU.
        prober = self.run_search(1500, answers=False)
        self.assertEqual((prober.path_mtu, prober.capable), (1365, False))

    def test_failed_sizes_are_retried_after_the_recheck_interval(self):
        prober, new = MtuProber(1365, 548), self.nonces()
        now = 0.0
        while now < 30:  # answers for <=1232 only
            for nonce, size in prober.due(now, new):
                if size <= 1232:
                    prober.acknowledge(nonce, size)
            now += .25
        self.assertEqual(prober.path_mtu, 1232)
        sent_after = []
        while now < 30 + MTU_RECHECK_SECONDS + 5:  # link now carries everything
            for nonce, size in prober.due(now, new):
                sent_after.append(size)
                prober.acknowledge(nonce, size)
            now += .25
        self.assertIn(1365, sent_after)
        self.assertEqual(prober.path_mtu, 1365)

    def test_wrong_size_or_nonce_is_not_an_answer(self):
        prober, new = MtuProber(1365, 548), self.nonces()
        (nonce, size), *_ = prober.due(0.0, new)
        self.assertFalse(prober.acknowledge(nonce, size - 1))
        self.assertFalse(prober.acknowledge(nonce + 10**9, size))
        self.assertFalse(prober.capable)
        self.assertTrue(prober.acknowledge(nonce, size))
        self.assertFalse(prober.acknowledge(nonce, size))  # not replayable

    def test_probe_volume_per_round_is_bounded_by_ladder(self):
        prober = MtuProber(1365, 548)
        self.assertLessEqual(len(prober.due(0.0, self.nonces())), len(path_quality.MTU_LADDER) + 1)
        self.assertGreater(MTU_STRIKES, 1)

    def test_invalid_bounds(self):
        for ceiling, floor in ((100, 200), (0, 0), (1365, 0)):
            with self.assertRaises(ValueError):
                MtuProber(ceiling, floor)


if __name__ == "__main__":
    unittest.main()
