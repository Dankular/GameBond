import unittest

from gamebond.adaptive_qos import AdaptiveQoS, QoSSettings


def path(slot, seen=0, missed=0, rtt=30):
    return dict(slot=slot, local=["127.0.0.1", slot], remote=["127.0.0.1", 1], healthy=True,
                rtt_ms=rtt + slot, rtt_jitter_ms=1,
                peer_copy_quality=dict(seen=seen, missed=missed),
                bonding=dict(expired_packets=0, acked_packets=100, queue_delay_ms=0, delivered_bytes=0))


class CopyLossTests(unittest.TestCase):
    def observe(self, qos, t, first, second):
        qos.observe(dict(paths=[first, second]), now=t)
        return qos.stats()

    def test_copy_loss_on_the_best_path_turns_redundancy_on(self):
        qos = AdaptiveQoS(QoSSettings(), clock=lambda: 0)
        self.observe(qos, 0, path(0), path(1))
        stats = self.observe(qos, 1, path(0, seen=80, missed=20), path(1, seen=100))
        self.assertIn("copy_loss", stats["redundancy"]["call"]["reason"])
        self.assertAlmostEqual(stats["path_quality"][0]["copy_loss"], .2)

    def test_a_handful_of_comparisons_is_noise_not_a_rate(self):
        qos = AdaptiveQoS(QoSSettings(), clock=lambda: 0)
        self.observe(qos, 0, path(0), path(1))
        stats = self.observe(qos, 1, path(0, seen=2, missed=3), path(1, seen=5))
        self.assertEqual(stats["path_quality"][0]["copy_loss"], 0)
        self.assertNotIn("copy_loss", stats["redundancy"]["call"]["reason"])

    def test_a_lossy_path_that_is_not_the_best_does_not_force_redundancy(self):
        qos = AdaptiveQoS(QoSSettings(), clock=lambda: 0)
        self.observe(qos, 0, path(0), path(1))
        stats = self.observe(qos, 1, path(0, seen=100), path(1, seen=50, missed=50))
        self.assertNotIn("copy_loss", stats["redundancy"]["call"]["reason"])

    def test_peer_counter_reset_is_not_negative_loss(self):
        qos = AdaptiveQoS(QoSSettings(), clock=lambda: 0)
        self.observe(qos, 0, path(0, seen=500, missed=10), path(1))
        stats = self.observe(qos, 1, path(0, seen=3, missed=0), path(1))
        self.assertEqual(stats["path_quality"][0]["copy_loss"], 0)


if __name__ == "__main__":
    unittest.main()
