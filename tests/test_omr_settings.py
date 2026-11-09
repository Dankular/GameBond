import unittest

from gamebond.omr_settings import load_server_mode

GOOD = dict(role="client", server_type="both", omr=dict(server=["203.0.113.10", 65001], key_file="secrets/glorytun.key"))


class ServerModeTests(unittest.TestCase):
    def test_defaults_and_full_form(self):
        mode, settings = load_server_mode(GOOD)
        self.assertEqual((mode, settings.server, settings.tunnel_ip, settings.rate_mbps, settings.beat_ms, settings.gamebond_dscp),
                         ("both", ("203.0.113.10", 65001), "10.255.254.2", 100.0, 100, (46, 26)))
        mode, settings = load_server_mode(dict(GOOD, omr=dict(GOOD["omr"], tunnel_ip="10.255.254.9", rate_mbps=250, beat_ms=20, gamebond_dscp=[46])))
        self.assertEqual((settings.tunnel_ip, settings.rate_mbps, settings.beat_ms, settings.gamebond_dscp), ("10.255.254.9", 250.0, 20, (46,)))

    def test_plain_gamebond_is_the_default_and_takes_no_omr_block(self):
        self.assertEqual(load_server_mode(dict(role="client")), ("gamebond", None))
        with self.assertRaises(ValueError):
            load_server_mode(dict(role="client", omr=GOOD["omr"]))

    def test_omr_alone_is_refused_with_a_clear_message(self):
        with self.assertRaisesRegex(ValueError, "not available yet"):
            load_server_mode(dict(GOOD, server_type="omr"))
        with self.assertRaises(ValueError):
            load_server_mode(dict(GOOD, server_type="nonsense"))

    def test_bad_blocks_are_rejected(self):
        bad = [dict(GOOD, omr=None), dict(GOOD, omr=dict(server=["203.0.113.10", 65001])),
               dict(GOOD, omr=dict(GOOD["omr"], surprise=1)), dict(GOOD, omr=dict(GOOD["omr"], server=["0.0.0.0", 65001])),
               dict(GOOD, omr=dict(GOOD["omr"], server=["203.0.113.10", 0])), dict(GOOD, omr=dict(GOOD["omr"], key_file="")),
               dict(GOOD, omr=dict(GOOD["omr"], rate_mbps=0)), dict(GOOD, omr=dict(GOOD["omr"], beat_ms=5)),
               dict(GOOD, omr=dict(GOOD["omr"], gamebond_dscp=[64])), dict(GOOD, omr=dict(GOOD["omr"], tunnel_ip="224.0.0.1")),
               dict(GOOD, role="server")]
        for config in bad:
            with self.assertRaises(ValueError, msg=str(config)):
                load_server_mode(config)


if __name__ == "__main__":
    unittest.main()
