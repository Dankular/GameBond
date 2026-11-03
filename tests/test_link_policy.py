from datetime import datetime, date
import json
from pathlib import Path
import tempfile
import unittest

from gamebond.link_policy import LinkPolicy, WirePacer, UsageLedger, cycle_start, eligible_roles
from gamebond.link_policy import encode_state, decode_state, operational_state


class LinkPolicyTests(unittest.TestCase):
    def test_authenticated_policy_encoding_preserves_all_operational_controls(self):
        policy=LinkPolicy(role='backup',upload_mbps=2.5,download_mbps=12)
        state=operational_state(policy,dict(daily_bytes=0,monthly_bytes=0))
        self.assertEqual(decode_state(encode_state(17,state)),(17,state))
        state['upload_mbps']=float('inf')
        with self.assertRaises(ValueError):encode_state(18,state)

    def test_roles_use_secondary_for_boost_and_backup_only_after_failure(self):
        def link(role,healthy=True):return dict(healthy=healthy,policy=LinkPolicy(role=role).effective(dict(daily_bytes=0,monthly_bytes=0)))
        primary,secondary,backup,never=[link(r) for r in ('primary','secondary','backup','never')]
        links=[primary,secondary,backup,never]
        self.assertEqual(eligible_roles(links),[primary])
        self.assertEqual(eligible_roles(links,True),[primary,secondary])
        primary['healthy']=False;self.assertEqual(eligible_roles(links),[secondary])
        secondary['healthy']=False;self.assertEqual(eligible_roles(links),[backup])

    def test_cap_stop_and_directional_throttle(self):
        usage=dict(daily_bytes=1000,monthly_bytes=1500)
        self.assertTrue(LinkPolicy(daily_bytes=1000).effective(usage)['blocked'])
        policy=LinkPolicy(daily_bytes=1000,overlimit='throttle',upload_mbps=.1,download_mbps=5)
        effective=policy.effective(usage)
        self.assertFalse(effective['blocked']);self.assertEqual(effective['upload_mbps'],.1)
        self.assertEqual(effective['download_mbps'],.2)
        for bad in (dict(role='invalid'),dict(download_mbps=float('nan')),dict(daily_bytes=-1),dict(reset_day=32),dict(overlimit='throttle',overlimit_mbps=0)):
            with self.assertRaises(ValueError):LinkPolicy(**bad)

    def test_wire_ceiling_counts_every_packet_and_preserves_debt_when_rate_changes(self):
        pacer=WirePacer(1);sent=0
        for tick in range(1000):
            now=tick/1000
            while pacer.ready_at(1000,now)<=now:
                pacer.sent(1000,now);sent+=1000
        self.assertLessEqual(sent,125000+2800)
        self.assertGreater(sent,120000)
        pacer=WirePacer(1);pacer.sent(10000,0)
        pacer.set_rate(.5,0)
        self.assertGreater(pacer.ready_at(1000,0),.1)

    def test_usage_survives_restart_rolls_daily_and_obeys_monthly_billing_day(self):
        now=[datetime(2026,11,9,12)]
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'usage.json';ledger=UsageLedger(path,lambda:now[0])
            policy=LinkPolicy(reset_day=10)
            ledger.add('phone',1000,2000);ledger.save()
            ledger=UsageLedger(path,lambda:now[0]);self.assertEqual(ledger.usage('phone',policy)['monthly_bytes'],3000)
            now[0]=datetime(2026,11,10,12)
            self.assertEqual(ledger.usage('phone',policy)['monthly_bytes'],0)
            ledger.add('phone',2000,3000)
            now[0]=datetime(2026,11,11,12)
            self.assertEqual(ledger.usage('phone',policy)['daily_bytes'],0)
            self.assertEqual(ledger.usage('phone',policy)['monthly_bytes'],5000)
            self.assertEqual(cycle_start(date(2026,2,28),31),date(2026,2,28))
            self.assertEqual(cycle_start(date(2026,2,27),31),date(2026,1,31))
            path.write_text(json.dumps(dict(version=1,links={'phone':{'2026-11-10':dict(upload=-1,download=0)}})))
            with self.assertRaises(ValueError):UsageLedger(path)
