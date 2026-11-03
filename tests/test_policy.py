import struct
import random
import threading
import unittest

from gamebond.policy import (Classification, Classifier, PacketInfo,
                             PriorityScheduler, QueuePolicy, parse_packet)


def ipv4(dscp=0, source=b"\x0a\x00\x00\x01", destination=b"\x0a\x00\x00\x02",
         sport=1000, dport=2000, fragment=0):
    udp = struct.pack("!HHHH", sport, dport, 9, 0) + b"x"
    return struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2 | 3, 20 + len(udp),
                       0, fragment, 64, 17, 0, source, destination) + udp


def ipv6(dscp=0, extension=False, fragment=False):
    udp = struct.pack("!HHHH", 1000, 2000, 9, 0) + b"x"
    proto = 17
    if fragment:
        udp = bytes([17, 0]) + b"\x00\x01" + b"\x00" * 4 + udp
        proto = 44
    if extension:
        udp = bytes([proto, 0]) + b"\x00" * 6 + udp
        proto = 0
    return struct.pack("!IHBB16s16s", (6 << 28) | ((dscp << 2 | 3) << 20),
                       len(udp), proto, 64, b"\x01" * 16, b"\x02" * 16) + udp


def ipv4_fragment(*, first=True, identification=123, sport=3075, dport=2000,
                  dscp=0, source=b"\x0a\0\0\1", destination=b"\x0a\0\0\2",
                  protocol=17, declared_udp_length=32, payload=None):
    if payload is None:
        payload = (struct.pack("!HHHH", sport, dport, declared_udp_length, 0) + b"a" * 8
                   if first else b"b" * 16)
    flags_offset = 0x2000 if first else 2  # First16bytes, followed by offset16.
    return struct.pack("!BBHHHBBH4s4s", 0x45, dscp << 2, 20 + len(payload),
                       identification, flags_offset, 64, protocol, 0, source, destination) + payload


class PolicyTests(unittest.TestCase):
    def setUp(self):
        self.gaming = QueuePolicy(priority=True, replicate=True, max_age_ms=20, capacity=2)
        self.classifier = Classifier({46: self.gaming})

    def test_ipv4_and_ipv6_ecn_does_not_change_dscp(self):
        for packet in (ipv4(46), ipv6(46), ipv6(46, extension=True)):
            result = self.classifier.classify(packet)
            self.assertEqual(result.dscp, 46)
            self.assertEqual(result.policy, self.gaming)
            self.assertEqual(result.info.destination_port, 2000)

    def test_reverse_flow_inherits_tag_and_expires(self):
        now = [0.]
        classifier = Classifier({46: self.gaming}, clock=lambda: now[0], flow_ttl=1)
        classifier.classify(ipv4(46))
        reply = ipv4(source=b"\x0a\x00\x00\x02", destination=b"\x0a\x00\x00\x01",
                     sport=2000, dport=1000)
        self.assertEqual(classifier.classify(reply).dscp, 46)
        now[0] = 2
        self.assertEqual(classifier.classify(reply).dscp, 0)

    def test_flow_cache_eviction(self):
        classifier = Classifier({46: self.gaming}, cache_size=1)
        classifier.classify(ipv4(46))
        classifier.classify(ipv4(sport=3000))
        self.assertEqual(classifier.classify(ipv4()).dscp, 0)

    def test_priority_flow_survives_unconfigured_nonzero_reply_tag(self):
        now = [0.]
        classifier = Classifier({46: self.gaming}, clock=lambda: now[0], flow_ttl=1)
        outgoing = ipv4(46)  # Neither port is in a game allowlist.
        reply = ipv4(10, source=b"\x0a\x00\x00\x02", destination=b"\x0a\x00\x00\x01",
                     sport=2000, dport=1000)
        classifier.classify(outgoing)
        result = classifier.classify(reply)
        self.assertEqual(result.info.dscp, 10)  # Original IP bytes are unchanged.
        self.assertEqual(result.dscp, 46)
        self.assertEqual(result.policy, self.gaming)
        self.assertEqual(classifier.classify(ipv4(10, sport=3000)).dscp, 10)
        now[0] = 2
        self.assertEqual(classifier.classify(reply).dscp, 10)

    def test_explicit_nonzero_rule_overrides_learned_priority(self):
        for policy in (QueuePolicy(), QueuePolicy(priority=True, replicate=False)):
            with self.subTest(policy=policy):
                classifier = Classifier({46: self.gaming, 10: policy})
                classifier.classify(ipv4(46))
                reply = ipv4(10, source=b"\x0a\x00\x00\x02",
                             destination=b"\x0a\x00\x00\x01", sport=2000, dport=1000)
                result = classifier.classify(reply)
                self.assertEqual(result.dscp, 10)
                self.assertEqual(result.policy, policy)
                self.assertEqual(classifier.classify(ipv4()).dscp, 10)

    def test_removed_priority_rule_does_not_pin_unknown_reply_tag(self):
        self.classifier.classify(ipv4(46))
        self.classifier.policies[46] = QueuePolicy()
        self.assertEqual(self.classifier.classify(ipv4(10)).dscp, 10)

    def test_replication_alone_does_not_pin_unknown_reply_tag(self):
        classifier = Classifier({46: QueuePolicy(replicate=True)})
        classifier.classify(ipv4(46))
        self.assertEqual(classifier.classify(ipv4(10)).dscp, 10)

    def test_configured_game_port_overrides_tags_in_both_directions(self):
        classifier = Classifier({46: self.gaming, 10: QueuePolicy()}, game_ports=[3075])
        for packet in (ipv4(10, sport=3075),
                       ipv4(10, source=b"\x0a\x00\x00\x02",
                            destination=b"\x0a\x00\x00\x01", sport=2000, dport=3075)):
            result = classifier.classify(packet)
            self.assertEqual(result.dscp, 46)
            self.assertEqual(result.policy, self.gaming)

    def test_preparsed_classification_retains_flow_and_reverse_policy(self):
        outgoing = parse_packet(ipv4(46))
        result = self.classifier.classify_info(outgoing)
        self.assertEqual(result.info.flow, outgoing.flow)
        reply = parse_packet(ipv4(source=outgoing.destination, destination=outgoing.source,
                                  sport=2000, dport=1000))
        result = self.classifier.classify_info(reply)
        self.assertEqual(result.dscp, 46)
        self.assertEqual(result.info.flow, outgoing.flow)
        self.assertTrue(result.policy.priority)

    def test_ports_must_be_explicit_and_later_fragments_never_parse_ports(self):
        classifier = Classifier({46: self.gaming}, game_ports=[2000])
        self.assertEqual(self.classifier.classify(ipv4()).dscp, 0)
        self.assertEqual(classifier.classify(ipv4()).dscp, 46)
        for packet in (ipv4(fragment=1),
                       ipv6(fragment=True), ipv6(extension=True, fragment=True)):
            info = parse_packet(packet)
            self.assertIsNone(info.flow)
            self.assertIsNone(info.destination_port)
            self.assertEqual(classifier.classify(packet).dscp, 0)

    def test_ipv4_game_fragments_are_replicated_without_exposing_a_flow(self):
        classifier = Classifier({46: self.gaming}, game_ports=[3075])
        for first in (True, False):
            result = classifier.classify(ipv4_fragment(first=first))
            self.assertEqual(result.dscp, 46)
            self.assertTrue(result.policy.priority)
            self.assertTrue(result.policy.replicate)
            self.assertIsNone(result.info.flow)
            self.assertEqual(result.info.fragment_offset, 0 if first else 16)
            self.assertEqual(result.info.source_port, 3075 if first else None)
            self.assertEqual(result.reason, "game_port" if first else "fragment_cache")
        self.assertEqual(classifier.stats()["fragment_first"], 1)
        self.assertEqual(classifier.stats()["fragment_hits"], 1)

    def test_first_fragment_can_inherit_previously_learned_reverse_flow(self):
        self.classifier.classify(ipv4(46))
        for first in (True, False):
            result = self.classifier.classify(ipv4_fragment(
                first=first, source=b"\x0a\0\0\2", destination=b"\x0a\0\0\1",
                sport=2000, dport=1000))
            self.assertEqual(result.dscp, 46)
            self.assertTrue(result.policy.replicate)
            self.assertIsNone(result.info.flow)

    def test_realistic_game_datagram_over_inner_mtu_keeps_both_fragments_priority(self):
        classifier = Classifier({46: self.gaming}, game_ports=[3075])
        # A 1504-byte UDP datagram split at 1256 payload bytes for a 1280 IP MTU.
        udp = struct.pack("!HHHH", 3075, 2000, 1504, 0) + b"x" * 1496
        first = ipv4_fragment(payload=udp[:1256])
        last = bytearray(ipv4_fragment(first=False, payload=udp[1256:]))
        last[6:8] = (1256 // 8).to_bytes(2, "big")
        self.assertGreater(len(udp) + 20, 1280)
        for packet in (first, bytes(last)):
            self.assertLessEqual(len(packet), 1280)
            result = classifier.classify(packet)
            self.assertTrue(result.policy.priority)
            self.assertTrue(result.policy.replicate)
            self.assertIsNone(result.info.flow)

    def test_bulk_fragments_and_orphans_are_never_promoted_by_port_shaped_payload(self):
        classifier = Classifier({46: self.gaming}, game_ports=[3075])
        orphan = classifier.classify(ipv4_fragment(first=False))
        self.assertEqual(orphan.reason, "fragment_orphan")
        self.assertFalse(orphan.policy.replicate)
        classifier.classify(ipv4_fragment(sport=9000))
        # Later bytes happen to resemble a gameplay UDP header; never parse it.
        later = ipv4_fragment(first=False, payload=struct.pack("!HHHH", 3075, 2000, 32, 0) + b"x"*8)
        result = classifier.classify(later)
        self.assertEqual(result.dscp, 0)
        self.assertFalse(result.policy.priority)
        self.assertIsNone(result.info.source_port)
        self.assertEqual(classifier.stats()["fragment_orphans"], 1)

    def test_fragment_associations_expire_without_refresh_and_evict_at_capacity(self):
        now = [0.]
        classifier = Classifier({46: self.gaming}, game_ports=[3075],
                                fragment_ttl=1, fragment_cache_size=1, clock=lambda: now[0])
        classifier.classify(ipv4_fragment())
        now[0] = .8
        self.assertEqual(classifier.classify(ipv4_fragment(first=False)).dscp, 46)
        now[0] = 1.01
        self.assertEqual(classifier.classify(ipv4_fragment(first=False)).reason, "fragment_orphan")
        self.assertEqual(classifier.stats()["fragment_expired"], 1)
        classifier.classify(ipv4_fragment(identification=1))
        classifier.classify(ipv4_fragment(identification=2))
        self.assertEqual(classifier.classify(ipv4_fragment(first=False, identification=1)).dscp, 0)
        self.assertEqual(classifier.stats()["fragment_evicted"], 1)
        self.assertEqual(classifier.stats()["fragment_cache_entries"], 1)

    def test_fragment_identity_includes_direction_addresses_protocol_and_id(self):
        classifier = Classifier({46: self.gaming}, game_ports=[3075])
        classifier.classify(ipv4_fragment())
        for kwargs in ({'identification': 124}, {'source': b"\x0a\0\0\3"},
                       {'destination': b"\x0a\0\0\3"}, {'protocol': 6},
                       {'source': b"\x0a\0\0\2", 'destination': b"\x0a\0\0\1"}):
            with self.subTest(kwargs=kwargs):
                result = classifier.classify(ipv4_fragment(first=False, **kwargs))
                self.assertEqual(result.dscp, 0)
                self.assertEqual(result.reason, "fragment_orphan")
        # A new first fragment with reused ID explicitly replaces the old policy.
        classifier.classify(ipv4_fragment(sport=9000))
        self.assertEqual(classifier.classify(ipv4_fragment(first=False)).dscp, 0)

    def test_fragment_udp_length_validation_accepts_partial_datagram_only(self):
        info = parse_packet(ipv4_fragment(declared_udp_length=1400))
        self.assertEqual(info.source_port, 3075)
        self.assertTrue(info.more_fragments)
        for packet in (ipv4_fragment(declared_udp_length=7),
                       ipv4_fragment(declared_udp_length=16),
                       ipv4_fragment(declared_udp_length=65535),
                       ipv4_fragment(payload=b"x" * 7), ipv4_fragment(payload=b"x" * 9)):
            with self.subTest(packet=packet), self.assertRaises(ValueError):
                parse_packet(packet)
        # Ordinary UDP still requires its complete declared payload.
        ordinary = bytearray(ipv4())
        ordinary[24:26] = (1400).to_bytes(2, "big")
        with self.assertRaisesRegex(ValueError, "UDP length"):
            parse_packet(ordinary)

    def test_malformed_lengths(self):
        bad_udp = bytearray(ipv4())
        bad_udp[24:26] = b"\x00\x08"
        for packet in (b"", b"\x45", ipv4()[:-1], ipv6()[:-1], bytes(bad_udp),
                       b"\x30" * 30):
            with self.subTest(packet=packet):
                with self.assertRaises(ValueError):
                    parse_packet(packet)

    def test_policy_validation_and_no_silent_retransmission(self):
        for kwargs in ({"capacity": 0}, {"max_age_ms": 0}, {"max_age_ms": float("nan")},
                       {"retransmissions": 2}, {"priority": "on"}):
            with self.assertRaises(ValueError):
                QueuePolicy(**kwargs)
        with self.assertRaises(ValueError):
            Classifier({64: self.gaming})

    def test_queue_capacity_staleness_and_fairness(self):
        now = [0.]
        scheduler = PriorityScheduler(capacity=4, priority_burst=2, clock=lambda: now[0])
        high = self.classifier.classify(ipv4(46))
        normal = self.classifier.classify(ipv4(sport=9000))
        self.assertTrue(scheduler.push(b"h1", high))
        self.assertTrue(scheduler.push(b"h2", high))
        self.assertFalse(scheduler.push(b"h3", high))
        self.assertTrue(scheduler.push(b"n1", normal))
        self.assertEqual(scheduler.pop(0).packet, b"h1")
        self.assertTrue(scheduler.push(b"h4", high))
        self.assertEqual(scheduler.pop(0).packet, b"h2")
        self.assertEqual(scheduler.pop(0).packet, b"n1")
        now[0] = .03
        self.assertIsNone(scheduler.pop(0))
        self.assertEqual(scheduler.stats()["dropped_stale"], 1)
        self.assertEqual(scheduler.stats()["dropped_full"], 1)

    def test_expired_packets_free_capacity_on_push(self):
        now = [0.]
        scheduler = PriorityScheduler(capacity=1, clock=lambda: now[0])
        high = self.classifier.classify(ipv4(46))
        scheduler.push(b"old", high)
        now[0] = .1
        self.assertTrue(scheduler.push(b"fresh", high))
        self.assertEqual(scheduler.pop(0).packet, b"fresh")

    def test_close_unblocks_waiting_consumer(self):
        scheduler = PriorityScheduler()
        result = []
        thread = threading.Thread(target=lambda: result.append(scheduler.pop()))
        thread.start()
        scheduler.close()
        thread.join(1)
        self.assertFalse(thread.is_alive())
        self.assertEqual(result, [None])


def classification(tag, **policy):
    info = PacketInfo(4, tag, 17, b"\x0a\0\0\1", b"\x0a\0\0\2", 3075, 4000)
    return Classification(info, tag, QueuePolicy(**policy))


class SchedulerTests(unittest.TestCase):
    def test_short_deadline_behind_long_deadline_expires_without_reordering_fifo(self):
        now = [0.]
        scheduler = PriorityScheduler(clock=lambda: now[0])
        long = classification(0, max_age_ms=1000)
        short = classification(10, max_age_ms=10)
        medium = classification(12, max_age_ms=40)
        scheduler.push(b"long-first", long)
        now[0] = .001
        scheduler.push(b"short-middle", short)
        now[0] = .002
        scheduler.push(b"medium-last", medium)
        now[0] = .02
        self.assertEqual(scheduler.pop(0).packet, b"long-first")
        self.assertEqual(scheduler.pop(0).packet, b"medium-last")
        self.assertIsNone(scheduler.pop(0))
        self.assertEqual(scheduler.stats()["per_dscp_stats"][10]["dropped_stale"], 1)

    def test_per_dscp_accounting_and_delivered_residence(self):
        now = [0.]
        scheduler = PriorityScheduler(clock=lambda: now[0])
        game = classification(46, priority=True, max_age_ms=20, capacity=2)
        scheduler.push(b"delivered", game)
        scheduler.push(b"stale", game)
        self.assertFalse(scheduler.push(b"full", game))
        now[0] = .005
        self.assertEqual(scheduler.pop(0).packet, b"delivered")
        now[0] = .03
        self.assertIsNone(scheduler.pop(0))
        stats = scheduler.stats()
        per_tag = stats["per_dscp_stats"][46]
        self.assertEqual({key: per_tag[key] for key in (
            "queued", "enqueued", "dequeued", "dropped_stale", "dropped_full")},
            {"queued": 0, "enqueued": 2, "dequeued": 1,
             "dropped_stale": 1, "dropped_full": 1})
        self.assertEqual(per_tag["residence_ms"]["count"], 1)
        self.assertAlmostEqual(per_tag["residence_ms"]["mean"], 5)
        self.assertAlmostEqual(per_tag["residence_ms"]["max"], 5)
        self.assertAlmostEqual(stats["residence_ms"]["mean"], 5)

    def test_deadline_memory_does_not_accumulate_delivered_priority_packets(self):
        now = [0.]
        scheduler = PriorityScheduler(capacity=128, priority_burst=100000,
                                      clock=lambda: now[0])
        bulk = classification(0, max_age_ms=100000, capacity=64)
        game = classification(46, priority=True, max_age_ms=1000)
        for _ in range(64):
            scheduler.push(b"bulk", bulk)
        for sequence in range(10000):
            now[0] += .00001
            self.assertTrue(scheduler.push(str(sequence).encode(), game))
            self.assertEqual(scheduler.pop(0).packet, str(sequence).encode())
        # This checks the resource invariant, not heap layout or ordering.
        self.assertEqual(len(scheduler._deadlines), scheduler.stats()["queued"])
        self.assertEqual(len(scheduler._deadlines._positions), 64)
        self.assertEqual(len(scheduler._deadlines._heap), 64)
        self.assertEqual(scheduler.stats()["per_dscp"][46], 0)

    def test_game_bursts_are_served_with_bounded_bulk_progress_and_no_drops(self):
        now = [0.]
        scheduler = PriorityScheduler(capacity=512, priority_burst=8, clock=lambda: now[0])
        bulk = classification(0, max_age_ms=10000, capacity=400)
        game = classification(46, priority=True, max_age_ms=20, capacity=32)
        for _ in range(256):
            self.assertTrue(scheduler.push(b"bulk", bulk))
        delivered_game = delivered_bulk = 0
        for _ in range(100):
            for _ in range(8):
                self.assertTrue(scheduler.push(b"game", game))
            for _ in range(9):
                now[0] += .0001
                item = scheduler.pop(0)
                if item.packet == b"game":
                    delivered_game += 1
                else:
                    delivered_bulk += 1
                    self.assertTrue(scheduler.push(b"bulk", bulk))
            self.assertEqual(scheduler.stats()["per_dscp"][46], 0)
        self.assertEqual((delivered_game, delivered_bulk), (800, 100))
        stats = scheduler.stats()
        self.assertEqual(stats.get("dropped_stale", 0), 0)
        self.assertEqual(stats.get("dropped_full", 0), 0)
        self.assertLess(stats["per_dscp_stats"][46]["residence_ms"]["max"], 1)

    def test_randomized_deadline_and_fifo_behavior_matches_simple_reference(self):
        randomizer = random.Random(871)
        now = [0.]
        scheduler = PriorityScheduler(capacity=16, priority_burst=3, clock=lambda: now[0])
        policies = [classification(0, max_age_ms=90, capacity=8),
                    classification(10, max_age_ms=12, capacity=5),
                    classification(46, priority=True, max_age_ms=20, capacity=6),
                    classification(48, priority=True, max_age_ms=55, capacity=4)]
        priority, normal = [], []
        counts = dict(enqueued=0, dequeued=0, dropped_stale=0, dropped_full=0)
        burst = 0

        def expire_reference():
            for fifo in (priority, normal):
                retained = []
                for entry in fifo:
                    if now[0] >= entry[2] + entry[1].policy.max_age_ms / 1000:
                        counts["dropped_stale"] += 1
                    else:
                        retained.append(entry)
                fifo[:] = retained

        for sequence in range(1500):
            now[0] += randomizer.random() * .006
            expire_reference()
            if randomizer.random() < .65:
                rule = randomizer.choice(policies)
                packet = str(sequence).encode()
                full = (len(priority) + len(normal) >= 16 or
                        sum(entry[1].dscp == rule.dscp for entry in priority + normal)
                        >= rule.policy.capacity)
                self.assertEqual(scheduler.push(packet, rule), not full)
                if full:
                    counts["dropped_full"] += 1
                else:
                    (priority if rule.policy.priority else normal).append((packet, rule, now[0]))
                    counts["enqueued"] += 1
            else:
                if priority and (not normal or burst < 3):
                    expected = priority.pop(0)[0]
                    burst = min(burst + 1, 3)
                elif normal:
                    expected = normal.pop(0)[0]
                    burst = 0
                else:
                    expected = None
                actual = scheduler.pop(0)
                self.assertEqual(actual.packet if actual else None, expected)
                if expected is not None:
                    counts["dequeued"] += 1
        stats = scheduler.stats()
        for key, value in counts.items():
            self.assertEqual(stats.get(key, 0), value, key)
        self.assertEqual(stats["queued"], len(priority) + len(normal))
        self.assertEqual(len(scheduler._deadlines), stats["queued"])


if __name__ == "__main__":
    unittest.main()
