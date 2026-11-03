import unittest
from gamebond.policy import Classifier, PacketInfo, QueuePolicy
from gamebond.telemetry import PriorityFlowTelemetry


class FlowTelemetryTests(unittest.TestCase):
    def test_records_effective_priority_direction_and_observed_gaps_without_payloads(self):
        clock = [1.0]
        monitor = PriorityFlowTelemetry([3075], capacity=2, clock=lambda: clock[0])
        classifier = Classifier({46: QueuePolicy(priority=True, replicate=True)}, game_ports=[3075])
        info = PacketInfo(4, 0, 17, b'\x0a\x4d\x00\x02', b'\xcb\x00\x71\x01', 3075, 45000)
        item = classifier.classify_info(info)
        monitor.observe(item, 100, incoming=False)
        clock[0] += .12
        monitor.observe(item, 120, incoming=False)
        record = monitor.stats()[0]
        self.assertEqual(record['original_dscp'], 0)
        self.assertEqual(record['effective_dscp'], 46)
        self.assertEqual(record['reason'], 'configured_game_port')
        self.assertTrue(record['replicate'])
        self.assertEqual(record['packets'], 2)
        self.assertEqual(record['observed_gaps_over_100ms'], 1)
        self.assertNotIn('payload', record)
        monitor.observe(item, 100, incoming=True)
        another = PacketInfo(4, 46, 17, info.source, info.destination, 5000, 45000)
        monitor.observe(classifier.classify_info(another), 20, incoming=False)
        self.assertEqual(len(monitor.stats()), 2)
        self.assertEqual(monitor.stats()[0]['direction'], 'incoming')
