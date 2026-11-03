import unittest

from gamebond.reorder import ReorderBuffer, UINT64_MAX


class ReorderTests(unittest.TestCase):
    def test_missing_requests_wait_for_skew_and_bound_large_sequence_gaps(self):
        reorder=ReorderBuffer(timeout=.2)
        reorder.push(7,100,b'end',now=0)
        self.assertEqual(reorder.missing(now=.005),[])
        self.assertEqual(reorder.missing(limit=3,now=.02),[(7,0),(7,1),(7,2)])
        reorder.push(7,0,b'start',now=.021)
        self.assertEqual(reorder.missing(limit=1,now=.022),[(7,1)])

    def test_late_first_arrival_survives_gap_release_but_duplicate_does_not(self):
        reorder=ReorderBuffer(timeout=.03,allow_late=True)
        reorder.push(1,2,b'two',now=0)
        self.assertEqual(reorder.poll(now=.03),[b'two'])
        self.assertEqual(reorder.push(1,0,b'zero',now=.04),[b'zero'])
        self.assertEqual(reorder.push(1,0,b'duplicate',now=.041),[])
        self.assertEqual(reorder.push(1,1,b'one',now=.05),[b'one'])
        self.assertEqual(reorder.stats()['late_releases'],2)
        self.assertEqual(reorder.stats()['duplicate_drops'],1)

    def test_out_of_order_then_contiguous_and_duplicate_suppression(self):
        reorder = ReorderBuffer(timeout=.03)
        self.assertEqual(reorder.push(1, 2, b"two", now=0), [])
        self.assertEqual(reorder.push(1, 2, b"duplicate", now=.001), [])
        self.assertEqual(reorder.push(1, 0, b"zero", now=.002), [b"zero"])
        self.assertEqual(reorder.push(1, 1, b"one", now=.003), [b"one", b"two"])
        self.assertEqual(reorder.push(1, 0, b"old", now=.004), [])
        self.assertEqual(reorder.stats()["duplicate_drops"], 2)
        self.assertEqual(reorder.stats()["buffered_packets"], 0)
        self.assertEqual(reorder.stats()["gap_events"], 0)

    def test_loss_deadline_does_not_wait_for_unrelated_flow(self):
        reorder = ReorderBuffer(timeout=.03)
        self.assertEqual(reorder.push(1, 2, b"two", now=0), [])
        self.assertEqual(reorder.push(1, 3, b"three", now=.01), [])
        self.assertEqual(reorder.push(2, 0, b"independent", now=.02), [b"independent"])
        self.assertEqual(reorder.poll(now=.029), [])
        self.assertEqual(reorder.poll(now=.03), [b"two", b"three"])
        self.assertEqual(reorder.stats()["skipped_sequences"], 2)
        self.assertEqual(reorder.stats()["gap_events"], 1)
        self.assertEqual(reorder.push(1, 1, b"too late", now=.031), [])

    def test_each_old_pending_gap_keeps_its_original_age(self):
        reorder = ReorderBuffer(timeout=.03)
        reorder.push(1, 2, b"two", now=0)
        reorder.push(1, 5, b"five", now=.001)
        self.assertEqual(reorder.poll(now=.031), [b"two", b"five"])
        self.assertEqual(reorder.stats()["gap_events"], 2)
        self.assertEqual(reorder.stats()["skipped_sequences"], 4)

    def test_packet_capacity_forces_oldest_gap_release(self):
        reorder = ReorderBuffer(max_packets=1, timeout=1)
        self.assertEqual(reorder.push(1, 3, b"older", now=0), [])
        self.assertEqual(reorder.push(2, 5, b"newer", now=.01), [b"older"])
        stats = reorder.stats()
        self.assertEqual(stats["capacity_flushes"], 1)
        self.assertEqual(stats["buffered_packets"], 1)
        self.assertEqual(stats["peak_buffered_packets"], 1)
        self.assertEqual(stats["dropped_packets"], 0)

    def test_capacity_preserves_arriving_predecessor_in_same_flow(self):
        reorder = ReorderBuffer(max_packets=1, timeout=1)
        reorder.push(1, 2, b"two", now=0)
        self.assertEqual(reorder.push(1, 1, b"one", now=.01), [b"one", b"two"])
        self.assertEqual(reorder.push(1, 1, b"old one", now=.02), [])
        self.assertEqual(reorder.stats()["buffered_packets"], 0)
        self.assertEqual(reorder.stats()["skipped_sequences"], 1)

    def test_byte_capacity_and_oversized_payload_do_not_grow_retained_memory(self):
        reorder = ReorderBuffer(max_bytes=5, timeout=1)
        reorder.push(1, 1, b"111", now=0)
        self.assertEqual(reorder.push(2, 1, b"222", now=.01), [b"111"])
        self.assertLessEqual(reorder.stats()["buffered_bytes"], 5)
        self.assertEqual(reorder.push(2, 2, b"oversized", now=.02), [b"222", b"oversized"])
        self.assertEqual(reorder.stats()["oversize_releases"], 1)
        self.assertEqual(reorder.stats()["buffered_bytes"], 0)
        self.assertLessEqual(reorder.stats()["peak_buffered_bytes"], 5)

    def test_flow_capacity_eviction_reports_exact_buffered_drops(self):
        reorder = ReorderBuffer(max_flows=1, timeout=1)
        reorder.push(1, 1, b"lost", now=0)
        self.assertEqual(reorder.push(2, 0, b"new flow", now=.01), [b"new flow"])
        stats = reorder.stats()
        self.assertEqual(stats["flows"], 1)
        self.assertEqual(stats["evicted_flows"], 1)
        self.assertEqual(stats["dropped_packets"], 1)
        self.assertEqual(stats["dropped_bytes"], 4)
        self.assertEqual(stats["buffered_packets"], 0)

    def test_idle_expiry_and_injected_clock(self):
        clock = [0]
        reorder = ReorderBuffer(timeout=.03, clock=lambda: clock[0])
        reorder.push(1, 1, b"expired")
        clock[0] = 120
        self.assertEqual(reorder.poll(), [])
        stats = reorder.stats()
        self.assertEqual(stats["expired_flows"], 1)
        self.assertEqual(stats["dropped_packets"], 1)
        self.assertEqual(stats["flows"], 0)

    def test_huge_sequence_gap_is_arithmetic_and_counter_saturates(self):
        reorder = ReorderBuffer(timeout=.03)
        self.assertEqual(reorder.push(1, UINT64_MAX, b"last", now=0), [])
        self.assertEqual(reorder.push(2, UINT64_MAX, b"another", now=0), [])
        self.assertEqual(reorder.poll(now=.03), [b"last", b"another"])
        self.assertEqual(reorder.stats()["skipped_sequences"], UINT64_MAX)
        self.assertEqual(reorder.stats()["gap_events"], 2)
        self.assertEqual(reorder.stats()["buffered_packets"], 0)

    def test_invalid_capacities_sequences_and_clock_rejected(self):
        for kwargs in ({"max_flows": 0}, {"max_packets": True}, {"max_bytes": -1},
                       {"timeout": -1}, {"timeout": float("nan")}):
            with self.assertRaises(ValueError):
                ReorderBuffer(**kwargs)
        reorder = ReorderBuffer()
        for flow, sequence in ((-1, 0), (0, -1), (True, 0), (0, UINT64_MAX + 1)):
            with self.assertRaises(ValueError):
                reorder.push(flow, sequence, b"invalid", now=0)
        with self.assertRaises(ValueError):
            reorder.poll(now=float("inf"))


if __name__ == "__main__":
    unittest.main()
