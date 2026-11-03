import math
import heapq
import unittest

from gamebond.bonding import (MAX_PENDING, MAX_PACING_CATCHUP_SECONDS,
                              MAX_PRIORITY_DEBT_SECONDS, PathBudget)


class PathBudgetTests(unittest.TestCase):
    def test_real_pacing_backlog_is_not_mistaken_for_application_idle(self):
        budget=PathBudget(1,8)
        for sequence in range(24):
            now=sequence*.014
            budget.sent(sequence,1200,now)
            budget.record_pacing_wait(now,now+.008)
            self.assertTrue(budget.acknowledge(sequence,(sequence+1)*1200,now+.01))
        self.assertGreater(budget.rate_mbps,1)
        self.assertGreater(budget.stats()['pacing_wait_ratio'],.1)

    def test_path_score_does_not_hide_bulk_queueing_behind_fast_probes(self):
        queued=PathBudget(4,20);clear=PathBudget(4,20)
        queued.sent(0,1200,0);clear.sent(0,1200,0)
        self.assertTrue(queued.acknowledge(0,1200,.2))
        self.assertTrue(clear.acknowledge(0,1200,.06))
        # The lower probe RTT on the queued path must not win over observed
        # DATA delivery delay when both have pacing credit.
        self.assertLess(clear.score(1200,.21,60),queued.score(1200,.21,30))

    def test_one_epoch_reordered_feedback_deficit_does_not_end_startup(self):
        budget=PathBudget(3,20)
        budget.sent(0,1200,0)
        self.assertTrue(budget.acknowledge(0,1200,.05))
        for sequence in range(1,101):budget.sent(sequence,1200,.1)
        self.assertTrue(budget.acknowledge(100,115200,.34))
        self.assertGreater(budget.stats()['settled_loss_ratio'],.01)
        self.assertTrue(budget.stats()['startup'])
        self.assertEqual(budget.stats()['backoffs'],0)

    def test_acknowledged_backlog_discovers_capacity_without_a_long_additive_ramp(self):
        budget=PathBudget(1,8)
        events=[];sequence=delivered=0
        for tick in range(2500):
            now=tick/1000
            while events and events[0][0]<=now:
                at,seq,size=heapq.heappop(events);delivered+=size
                self.assertTrue(budget.acknowledge(seq,delivered,at))
            while budget.ready_at(1200,now)<=now+1e-9:
                budget.sent(sequence,1200,now)
                heapq.heappush(events,(now+.05,sequence,1200));sequence+=1
        self.assertGreaterEqual(budget.rate_mbps,6)
        self.assertLessEqual(budget.rate_mbps,8)
        self.assertGreater(budget.stats()['startup_increases'],0)
        self.assertEqual(budget.stats()['backoffs'],0)

    def test_control_traffic_reserves_service_without_claiming_data_delivery(self):
        budget = PathBudget(1)
        delay = budget.control_sent(100, 1)
        stats = budget.stats()
        self.assertAlmostEqual(delay, 128 / 125000)
        self.assertEqual(stats['control_wire_bytes'], 128)
        self.assertEqual(stats['priority_wire_bytes'], 0)
        self.assertEqual(stats['sent_bytes'], 0)
        self.assertEqual(stats['inflight_bytes'], 0)
        self.assertEqual(stats['rate_mbps'], 1)

    def test_pacing_and_asymmetric_capacity_finish_score(self):
        slow = PathBudget(initial_rate_mbps=1)
        fast = PathBudget(initial_rate_mbps=8)
        # For a larger packet, capacity can outweigh a modest latency advantage.
        self.assertLess(fast.score(60000, 0, 160), slow.score(60000, 0, 100))
        self.assertTrue(fast.sent(1, 1200, 0))
        self.assertAlmostEqual(fast.ready_at(1200, 0), .001228)
        self.assertTrue(math.isfinite(fast.score(1200, 0, None)))

    def test_window_stops_bulk_until_ack_or_finite_expiry(self):
        budget = PathBudget()
        now = 0.0
        sequence = 0
        while budget.inflight_bytes + 1200 <= budget.window_bytes:
            now = budget.ready_at(1200, now)
            self.assertTrue(budget.sent(sequence, 1200, now))
            sequence += 1
        self.assertGreater(budget.ready_at(1200, now), now)
        self.assertTrue(math.isfinite(budget.ready_at(1200, now)))
        self.assertTrue(budget.acknowledge(sequence - 1, sequence * 1200, now + .1))
        self.assertEqual(budget.inflight_bytes, 0)
        self.assertEqual(budget.stats()["pending_packets"], 0)

    def test_priority_wire_accounting_preserves_ack_units_and_never_needs_credit(self):
        budget = PathBudget(1, 1)
        budget.sent(1, 1200, 0)
        before = budget.stats()
        delay = budget.priority_sent(400, 0)
        self.assertAlmostEqual(delay, (1228 + 428) / 125000)
        after = budget.stats()
        for key in ("sent_bytes", "sent_packets", "pending_packets", "inflight_bytes",
                    "delivered_bytes", "rate_mbps"):
            self.assertEqual(before[key], after[key])
        self.assertEqual(after["priority_wire_bytes"], 428)
        self.assertTrue(budget.acknowledge(1, 1200, .01))
        self.assertEqual(budget.stats()["delivered_bytes"], 1200)
        # No pending ACK exists for priority; it is still immediately chargeable.
        budget.priority_sent(400, .02)
        self.assertEqual(budget.inflight_bytes, 0)

    def test_urgent_overload_debt_is_bounded_and_drains_without_capacity_cut(self):
        budget = PathBudget(.05, .05)
        for _ in range(10000):
            budget.priority_sent(1200, 0)
        self.assertAlmostEqual(budget.next_send, MAX_PRIORITY_DEBT_SECONDS)
        self.assertGreater(budget.stats()["priority_debt_saturations"], 0)
        self.assertEqual(budget.stats()["pending_packets"], 0)
        self.assertEqual(budget.rate_mbps, .05)
        self.assertEqual(budget.ready_at(1200, 1), 1)
        self.assertEqual(budget.stats()["pacing_debt_ms"], 0)

    def test_wire_overhead_and_priority_validation(self):
        for overhead in (-1, 129, True, 28.0):
            with self.assertRaises(ValueError):
                PathBudget(wire_overhead=overhead)
        budget = PathBudget(1, 1, wire_overhead=0)
        self.assertAlmostEqual(budget.priority_sent(1000, 1), .008)
        self.assertEqual(budget.stats()["priority_wire_bytes"], 1000)
        for size, now in ((0, 1), (1000, math.nan), (1000, .9)):
            with self.assertRaises(ValueError):
                budget.priority_sent(size, now)

    def test_shaped_fifo_shared_wire_budget_prevents_game_queue_growth(self):
        # Independent FIFO serialization models a modem with no knowledge of
        # inner DSCP. Bulk is always backlogged, gameplay emits 100Hz. Delivery
        # feedback is ideal here so this isolates physical wire accounting from
        # congestion estimation or a rate cut. No sockets/network are involved.
        def run(account_priority):
            budget = PathBudget(1, 1)
            network_tail = 0.0
            game_delays = []
            sequence = delivered = bulk_packets = 0
            for tick in range(50000):
                now = tick / 10000
                if tick % 100 == 0:
                    network_tail = max(now, network_tail) + 428 / 125000
                    game_delays.append(network_tail - now)
                    if account_priority:
                        budget.priority_sent(400, now)
                if budget.ready_at(1200, now) <= now:
                    network_tail = max(now, network_tail) + 1228 / 125000
                    budget.sent(sequence, 1200, now)
                    delivered += 1200
                    self.assertTrue(budget.acknowledge(sequence, delivered, now))
                    sequence += 1
                    bulk_packets += 1
            self.assertEqual(budget.rate_mbps, 1)
            self.assertEqual(budget.stats()["backoffs"], 0)
            return max(game_delays), bulk_packets
        unaccounted_delay, baseline_bulk = run(False)
        accounted_delay, shared_bulk = run(True)
        self.assertGreater(unaccounted_delay, 1)
        self.assertLess(accounted_delay, .02)
        self.assertGreater(shared_bulk, baseline_bulk * .5)
        self.assertLess(shared_bulk, baseline_bulk)

    def test_late_wakeup_credit_recovers_rate_but_long_idle_burst_stays_bounded(self):
        budget = PathBudget(100, 100)
        budget.sent(0, 1000, 0)
        self.assertTrue(budget.acknowledge(0, 1000, .001))
        sequence, delivered = 1, 1000
        for now in (.01, 10.):
            count = 0
            while budget.ready_at(1000, now) <= now + 1e-12:
                self.assertTrue(budget.sent(sequence, 1000, now))
                sequence += 1
                count += 1
                self.assertLess(count, 100)
            credit_packets = math.ceil(MAX_PACING_CATCHUP_SECONDS * budget.rate_bytes_per_second / 1000)
            self.assertGreater(count, 10)
            self.assertLessEqual(count, credit_packets + 1)
            self.assertGreater(budget.next_send, now)
            delivered += count * 1000
            self.assertTrue(budget.acknowledge(sequence - 1, delivered, now + .001))

    def test_ready_path_scheduling_uses_both_asymmetric_links_for_one_sequence_stream(self):
        paths = [PathBudget(1, 8), PathBudget(4, 8)]
        rtts = [.02, .15]
        counts, delivered, events = [0, 0], [0, 0], []
        now = 0.
        for sequence in range(200):
            while True:
                while events and events[0][0] <= now:
                    ack_at, index, ack_sequence, size = heapq.heappop(events)
                    delivered[index] += size
                    self.assertTrue(paths[index].acknowledge(ack_sequence, delivered[index], ack_at))
                ready = [index for index, budget in enumerate(paths)
                         if budget.ready_at(1200, now) <= now + 1e-9]
                if ready:
                    break
                now = min(budget.ready_at(1200, now) for budget in paths)
            index = min(ready, key=lambda i: paths[i].score(1200, now, rtts[i] * 1000))
            self.assertTrue(paths[index].sent(sequence, 1200, now))
            counts[index] += 1
            heapq.heappush(events, (now + rtts[index], index, sequence, 1200))
        self.assertGreater(counts[0], 10)
        self.assertGreater(counts[1], counts[0])
        self.assertEqual(sum(counts), 200)

    def test_sparse_application_does_not_inflate_capacity(self):
        budget = PathBudget(initial_rate_mbps=4)
        for sequence in range(10):
            now = sequence * .5
            budget.sent(sequence, 1000, now)
            self.assertTrue(budget.acknowledge(sequence, (sequence + 1) * 1000, now + .1))
        self.assertEqual(budget.rate_mbps, 4)
        self.assertEqual(budget.stats()["rate_increases"], 0)
        self.assertTrue(budget.stats()["app_limited"])

    def _shared_discovery(self, *, traffic="priority", acknowledge=True, bulk="backlogged"):
        budget = PathBudget(1, 1.5)
        sequence = delivered = 0
        growth_epochs = []
        for tick in range(30000):
            now = tick / 10000
            if tick % 100 == 0:
                if traffic == "priority":
                    budget.priority_sent(800, now)  # 0.6624 Mbps physical load.
                else:
                    budget.priority_sent(386, now)
                    budget.control_sent(386, now)  # Same combined physical load.
            before = budget.rate_mbps
            ready = budget.ready_at(1200, now) <= now
            if budget.rate_mbps > before:
                growth_epochs.append(budget.stats())
            if ready and bulk != "none" and (bulk != "sparse" or tick % 1000 == 0):
                budget.sent(sequence, 1200, now)
                if acknowledge:
                    delivered += 1200
                    self.assertTrue(budget.acknowledge(sequence, delivered, now))
                sequence += 1
        return budget, growth_epochs

    def test_shared_priority_service_does_not_hide_acknowledged_bulk_backlog(self):
        for traffic in ("priority", "mixed_control"):
            with self.subTest(traffic=traffic):
                budget, epochs = self._shared_discovery(traffic=traffic)
                self.assertGreater(budget.rate_mbps, 1.2)
                self.assertLessEqual(budget.rate_mbps, 1.5)
                self.assertEqual(budget.stats()["backoffs"], 0)
                self.assertTrue(epochs)
                # First growth occurs despite original bulk-only utilization
                # being app-limited. Loss/cut predicates retain that old value.
                self.assertTrue(epochs[0]["app_limited"])
                self.assertFalse(epochs[0]["growth_app_limited"])
                self.assertGreaterEqual(epochs[0]["growth_bulk_utilization"], .8)
                self.assertGreater(epochs[0]["growth_bulk_allowance_bytes"], 6000)

    def test_unacknowledged_priority_or_missing_bulk_feedback_cannot_probe_capacity(self):
        for bulk, acknowledge in (("none", False), ("backlogged", False)):
            with self.subTest(bulk=bulk):
                budget, epochs = self._shared_discovery(bulk=bulk, acknowledge=acknowledge)
                self.assertEqual(budget.rate_mbps, 1)
                self.assertEqual(budget.stats()["rate_increases"], 0)
                self.assertEqual(budget.stats()["delivered_bytes"], 0)
                self.assertEqual(epochs, [])

    def test_sparse_bulk_is_still_app_limited_after_shared_service_normalization(self):
        budget, epochs = self._shared_discovery(bulk="sparse")
        self.assertEqual(budget.rate_mbps, 1)
        self.assertTrue(budget.stats()["growth_app_limited"])
        self.assertEqual(epochs, [])

    def test_sustained_utilization_supports_only_bounded_additive_growth(self):
        budget = PathBudget(initial_rate_mbps=1, max_rate_mbps=1.3)
        events = []
        for sequence in range(100):
            now = sequence * .01
            events.extend(((now, 0, sequence), (now + .05, 1, sequence)))
        for now, acknowledgement, sequence in sorted(events):
            if acknowledgement:
                self.assertTrue(budget.acknowledge(sequence, (sequence + 1) * 1250, now))
            else:
                budget.sent(sequence, 1250, now)
        self.assertGreater(budget.rate_mbps, 1)
        self.assertLessEqual(budget.rate_mbps, 1.3)
        self.assertLessEqual(budget.stats()["rate_increases"], 4)

    def test_queue_delay_backoff_and_loss_timeout_do_not_explode(self):
        budget = PathBudget(initial_rate_mbps=4, max_rate_mbps=4)
        budget.sent(0, 1000, 0)
        self.assertTrue(budget.acknowledge(0, 1000, .05))
        # Real offered backlog waits at a filled window. ACKs retire a complete
        # cohort but report40% missing DATA bytes, so pressure has a second cause.
        sequence, counter, now = 1, 1000, .1
        for _ in range(8):
            packet_count = budget.window_bytes // 1250
            for _ in range(packet_count):
                self.assertTrue(budget.sent(sequence, 1250, now))
                sequence += 1
            self.assertGreater(budget.ready_at(1250, now), now)
            now += .2
            counter += int(packet_count * .6) * 1250
            self.assertTrue(budget.acknowledge(sequence - 1, counter, now))
        self.assertLess(budget.rate_mbps, 4)
        self.assertGreater(budget.stats()["backoffs"], 0)
        self.assertEqual(budget.stats()["delay_backoffs"], 0)
        self.assertGreater(budget.stats()["queue_delay_ms"], 0)
        before = budget.rate_mbps
        budget.sent(sequence, 1200, 3)
        budget.sent(sequence + 1, 1200, 3.001)
        self.assertEqual(budget.expire(5.1), 2)
        self.assertEqual(budget.rate_mbps, before)  # timeoutbackoffdoesnotclaimlostcapacity
        self.assertEqual(budget.inflight_bytes, 0)
        self.assertEqual(budget.expire(6), 0)
        self.assertGreaterEqual(budget.rate_mbps, .05)
        self.assertLessEqual(budget.timeout, 2)

    def test_light_load_ack_batching_and_radio_jitter_never_reduce_rate(self):
        budget = PathBudget(initial_rate_mbps=4)
        budget.sent(0, 1000, 0)
        self.assertTrue(budget.acknowledge(0, 1000, .04))
        for sequence in range(1, 301):
            now = sequence * .2
            budget.sent(sequence, 1000, now)
            # 40ms propagation + up to20ms ACK holding + ordinary radio jitter.
            sample = (.060, .074, .080, .066, .078)[sequence % 5]
            self.assertTrue(budget.acknowledge(sequence, (sequence + 1) * 1000, now + sample))
        self.assertEqual(budget.rate_mbps, 4)
        self.assertEqual(budget.stats()["backoffs"], 0)
        self.assertEqual(budget.stats()["delay_backoffs"], 0)
        self.assertEqual(budget.stats()["expired_packets"], 0)
        self.assertTrue(budget.stats()["app_limited"])
        self.assertGreater(budget.stats()["queue_delay_ms"], 10)

    def test_starlink_sparse_bursts_ack_hold_and_occasional_loss_do_not_collapse_capacity(self):
        budget = PathBudget(4)
        budget.sent(0, 1000, 0)
        self.assertTrue(budget.acknowledge(0, 1000, .034))
        sequence, counter = 1, 1000
        for burst in range(1, 501):
            now = float(burst)
            for offset in range(3):
                self.assertTrue(budget.sent(sequence, 1000, now + offset * .002))
                sequence += 1
            counter += 2000 if burst % 53 == 0 else 3000
            # Gameplay/controlusesotherwiresequencevaluesbutisnotpacedbulk.
            highest = sequence - 1
            sequence += 20
            hold_us = (0, 20000, 12000, 4000)[burst % 4]
            corrected_rtt = (.050, .070, .065, .060)[burst % 4]
            if burst % 37:  # Lostfeedbackeventuallyexpires, notlostcapacity.
                self.assertTrue(budget.acknowledge(highest, counter,
                    now + .004 + corrected_rtt + hold_us / 1_000_000, ack_delay_us=hold_us))
            self.assertEqual(budget.rate_mbps, 4)
        self.assertEqual(budget.stats()["backoffs"], 0)
        self.assertEqual(budget.stats()["delay_backoffs"], 0)
        self.assertGreater(budget.stats()["timeout_backoffs"], 0)
        self.assertGreater(budget.stats()["expired_packets"], 0)
        self.assertEqual(budget.stats()["invalid_acks"], 0)
        self.assertAlmostEqual(budget.min_rtt, .034)

    def test_rtt_step_recovers_feedback_instead_of_rejecting_every_late_ack(self):
        budget = PathBudget()
        budget.sent(0, 1000, 0)
        self.assertTrue(budget.acknowledge(0, 1000, .05))
        self.assertAlmostEqual(budget.timeout, .25)
        accepted = []
        for sequence in range(1, 9):
            now = float(sequence)
            budget.sent(sequence, 1000, now)
            # All datagrams arrived; the path's actual RTT rose from 50 to400ms.
            accepted.append(budget.acknowledge(sequence, (sequence + 1) * 1000, now + .4))
            self.assertLessEqual(budget.timeout, 2)
        self.assertFalse(accepted[0])
        self.assertTrue(any(accepted[1:4]))
        self.assertTrue(all(accepted[-3:]))
        self.assertGreater(budget.srtt, .2)
        self.assertGreaterEqual(budget.timeout, .4)
        self.assertEqual(budget.stats()["rto_backoff"], 1)

    def test_forged_stale_and_inconsistent_acks_cannot_create_credit(self):
        budget = PathBudget()
        budget.sent(10, 1000, 0)
        for sequence, counter, now in ((99, 1000, .1), (10, 1001, .1),
                                       (10, 0, .1), (10, 500, .1)):
            self.assertFalse(budget.acknowledge(sequence, counter, now))
            self.assertEqual(budget.inflight_bytes, 1000)
            self.assertEqual(budget.rate_mbps, 1)
        self.assertTrue(budget.acknowledge(10, 1000, .1))
        self.assertFalse(budget.acknowledge(10, 1000, .2))
        budget.sent(12, 1000, .3)
        self.assertFalse(budget.acknowledge(12, 999, .4))
        self.assertEqual(budget.inflight_bytes, 1000)
        self.assertFalse(budget.acknowledge(12, 2000, 1.1))
        self.assertEqual(budget.inflight_bytes, 0)

    def test_metadata_is_bounded_even_if_caller_bypasses_window(self):
        budget = PathBudget()
        for sequence in range(MAX_PENDING):
            self.assertTrue(budget.sent(sequence, 1, 0))
        self.assertFalse(budget.sent(MAX_PENDING, 1, 0))
        self.assertEqual(budget.stats()["pending_packets"], MAX_PENDING)
        self.assertEqual(budget.stats()["untracked_packets"], 1)
        self.assertEqual(budget.expire(2), MAX_PENDING)
        self.assertEqual(budget.stats()["pending_packets"], 0)
        self.assertEqual(budget.inflight_bytes, 0)

    def test_validation_duplicate_send_and_one_packet_larger_than_window(self):
        for initial, maximum in ((0, 100), (2, 1), (math.inf, 100)):
            with self.assertRaises(ValueError):
                PathBudget(initial, maximum)
        budget = PathBudget(.01)
        self.assertEqual(budget.ready_at(60000, 0), 0)
        self.assertTrue(budget.sent(1, 60000, 0))
        self.assertFalse(budget.sent(1, 60000, 0))
        with self.assertRaises(ValueError):
            budget.sent(2, 1, -.1)
        with self.assertRaises(ValueError):
            budget.ready_at(0, 0)
        with self.assertRaises(ValueError):
            budget.score(100, math.nan, None)


if __name__ == "__main__":
    unittest.main()
