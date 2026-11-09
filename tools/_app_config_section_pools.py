"""Value pools for the adaptive_qos / outer_transport / stream_relays /
link_policies sections used by generate_native_app_config_vectors.py."""

RELAY_HOSTS = [
    '1.2.3.4', '1', '1.2', '1.2.3', '0x7f.1', '010.1.1.1', '1.2.3.4.5', '1.2.3.4 ', '', 'a', '256.1.1.1', '1..2.3',
    '4294967295', '4294967296', '1.2.3.256', '0.0.0.0', '00', '0x', '1.2.3.0x4', '1.2.3.4\0', ' 1.2.3.4',
    '1.2.3.-4', '+1.2.3.4', '1.2.3.4abc', '09.1.1.1', '1.2.3.4\t', '1.2.3.4 x', '255', '256', '65535', '65536',
    '16777215', '16777216', '1.65535', '1.65536', '1.2.65535', '1.2.65536', '0x7f000001', '0X7F.1', '1.2.3.04',
    '1.2.3.08', '1.2.3.4\n', '255.255.255.255', '255.255.255.255 ', '255.255.255.255x', '0xffffffff',
    '255.255.255.0377', '1.2.3.', '.1.2.3', '1.2.3.4.', '0x1.2', '0x.1', '1.0x', '1.2.3.4\r', '1.2.3.4\x0b',
    '1.2.3.4 ', '1.2.3.4 ', '0377.0377.0377.0377', '0400.1', '1.0400', '0x100.1', '1.0x1000000',
    '1.0xffffff', '99999999999', '4294967294', '0.0.0.256', '1e3', '١.٢.٣.٤', '1.2.3.0',
    'localhost']

TCP = {'mode': 'tcp', 'port': 1}


def _ep(port, **kw):
    return dict({'mode': 'tcp', 'port': port}, **kw)


SECTION_POOLS = {
    'adaptive_qos': [
        {}, None, [], {'enabled': False}, {'enabled': 1}, {'bogus': 1}, {'loss_threshold': 0}, {'loss_threshold': 1},
        {'loss_threshold': 1.01}, {'loss_threshold': True}, {'loss_threshold': '1'}, {'jitter_threshold_ms': -1},
        {'recovery_seconds': 60}, {'recovery_seconds': 60.5}, {'duplicate_mbps': 1000}, {'duplicate_mbps': 1001},
        {'call_deadline_ms': 0.5}, {'call_deadline_ms': 1}, {'call_deadline_ms': 2000}, {'call_deadline_ms': 2001},
        {'stream_deadline_ms': 2001}, {'game_deadline_ms': 0}, {'game_deadline_ms': 2000},
        {'game_deadline_ms': 2000.5}],
    'outer_transport': [
        None, {}, [], {'endpoints': []}, {'endpoints': [_ep(443)]}, {'endpoints': [_ep(443), _ep(443)]},
        {'endpoints': [_ep(443), {'mode': 'tls', 'port': 443, 'ca_file': 'ca.pem'}]},
        {'endpoints': [_ep(p) for p in (1, 2, 3)]}, {'endpoints': [_ep(p) for p in (1, 2, 3, 4)]},
        {'endpoints': [{'mode': 'tls', 'port': 443}]}, {'endpoints': [{'mode': 'tls', 'port': 443, 'ca_file': ''}]},
        {'endpoints': [{'mode': 'https', 'port': 443, 'ca_file': 'c'}]},
        {'endpoints': [{'mode': 'udp', 'port': 443}]}, {'endpoints': [_ep(0)]}, {'endpoints': [_ep(65536)]},
        {'endpoints': [_ep(True)]}, {'endpoints': [_ep(1.0)]}, {'endpoints': [{'mode': 'tcp'}]},
        {'endpoints': [_ep(1, x=1)]}, {'endpoints': [_ep(1, server_name='a' * 253)]},
        {'endpoints': [_ep(1, server_name='a' * 254)]}, {'endpoints': [_ep(1, server_name='a\0b')]},
        {'endpoints': [_ep(1, server_name=5)]}, {'endpoints': [_ep(1, server_name=None)]},
        {'endpoints': [TCP], 'fallback_after': 0.1}, {'endpoints': [TCP], 'fallback_after': 0.09},
        {'endpoints': [TCP], 'fallback_after': 300}, {'endpoints': [TCP], 'recovery_interval': 301},
        {'endpoints': [TCP], 'recovery_interval': True}, {'endpoints': [TCP], 'queue_packets': 0},
        {'endpoints': [TCP], 'queue_packets': 128}, {'endpoints': [TCP], 'queue_packets': 129},
        {'endpoints': [TCP], 'queue_packets': 5.0}, {'endpoints': [TCP], 'bogus': 1}],
    'stream_relays': [
        [], None, 'x', {}, [{'bind': ['0.0.0.0', 443], 'mode': 'tcp'}],
        [{'bind': ['0.0.0.0', 443], 'mode': 'tcp'}, {'bind': ['0.0.0.0', 443], 'mode': 'tcp'}],
        [{'bind': ['0.0.0.0', 443], 'mode': 'tcp'}, {'bind': ['0.0.0.0', 444], 'mode': 'tcp'}],
        [{'bind': ['0.0.0.0', p], 'mode': 'tcp'} for p in (1, 2, 3, 4)],
        [{'bind': ['0.0.0.0', 443]}], [{'bind': ['0.0.0.0', 443], 'cert_file': 'c', 'key_file': 'k'}],
        [{'bind': ['0.0.0.0', 443], 'cert_file': '', 'key_file': 'k'}],
        [{'bind': ['0.0.0.0', 443], 'mode': 'udp'}], [{'bind': ['0.0.0.0', 0], 'mode': 'tcp'}],
        [{'bind': ['0.0.0.0'], 'mode': 'tcp'}], [{'bind': ['0.0.0.0', 1, 2], 'mode': 'tcp'}],
        [{'mode': 'tcp'}], [{'bind': ['0.0.0.0', 443], 'mode': 'tcp', 'max_clients': 0}],
        [{'bind': ['0.0.0.0', 443], 'mode': 'tcp', 'max_clients': 32}],
        [{'bind': ['0.0.0.0', 443], 'mode': 'tcp', 'max_clients': 33}],
        [{'bind': ['0.0.0.0', 443], 'mode': 'tcp', 'max_clients': True}],
        [{'bind': ['0.0.0.0', 443], 'mode': 'tcp', 'x': 1}], [5], [None]
    ] + [[{'bind': [h, 443], 'mode': 'tcp'}] for h in RELAY_HOSTS],
    'link_policies': [
        {}, None, [], {'1': {}}, {'0': {}}, {'x': {}}, {'1': 5}, {'٣': {}}, {'²': {}}, {'-1': {}},
        {'01': {}}, {str(i): {} for i in range(1, 65)}, {str(i): {} for i in range(1, 66)},
        {'1': {'role': 'never'}}, {'1': {'role': 'bogus'}}, {'1': {'role': 5}},
        {'1': {'upload_mbps': 10000}}, {'1': {'upload_mbps': 10001}}, {'1': {'upload_mbps': -1}},
        {'1': {'upload_mbps': True}}, {'1': {'download_mbps': '5'}}, {'1': {'overlimit_mbps': 10000.5}},
        {'1': {'daily_bytes': 10 ** 16}}, {'1': {'daily_bytes': 10 ** 16 + 1}}, {'1': {'monthly_bytes': -1}},
        {'1': {'monthly_bytes': 1.0}}, {'1': {'reset_day': 0}}, {'1': {'reset_day': 31}}, {'1': {'reset_day': 32}},
        {'1': {'reset_day': True}}, {'1': {'overlimit': 'throttle'}},
        {'1': {'overlimit': 'throttle', 'overlimit_mbps': 0}}, {'1': {'overlimit': 'throttle', 'overlimit_mbps': 0.0}},
        {'1': {'overlimit': 'stop', 'overlimit_mbps': 0}}, {'1': {'overlimit': 'x'}}, {'1': {'bogus': 1}},
        {'1': {}, '2': {'role': 'x'}}],
}


def _dns(**kw):
    return dict({'records': {'game.example.com': {'A': ['203.0.113.5']}}, 'bind': ['10.77.0.2', 53]}, **kw)


SECTION_POOLS['admin'] = [
    None, {}, [], {'password_hash': 'scrypt$x'}, {'password_hash': 'scrypt$x', 'enabled': False},
    {'enabled': False}, {'enabled': 1}, {'password_hash': 'x'}, {'password_hash': 5}, {'password_hash': 'scrypt$'}, {'password_hash': 'scrypt'}, {'password_hash': 'scryptx'},
    {'password_hash': 'scrypt$x', 'bind': ['0.0.0.0', 8443]},
    {'password_hash': 'scrypt$x', 'bind': ['0.0.0.0', 8443], 'tls_cert': 'c', 'tls_key': 'k'},
    {'password_hash': 'scrypt$x', 'bind': ['0.0.0.0', 8443], 'tls_cert': 'c'},
    {'password_hash': 'scrypt$x', 'bind': ['0.0.0.0', 8443], 'tls_cert': 'c', 'tls_key': ''},
    {'password_hash': 'scrypt$x', 'bind': ['127.0.0.5', 8443]}, {'password_hash': 'scrypt$x', 'bind': ['127.0.0.1', 0]},
    {'password_hash': 'scrypt$x', 'bind': ['127.0.0.1', 65536]}, {'password_hash': 'scrypt$x', 'bind': ['x', 80]},
    {'password_hash': 'scrypt$x', 'bind': ['127.0.0.1']}, {'password_hash': 'scrypt$x', 'bind': 'ab'},
    {'password_hash': 'scrypt$x', 'bind': [2130706433, 80]},
    {'password_hash': 'scrypt$x', 'log_lines': 9}, {'password_hash': 'scrypt$x', 'log_lines': 10},
    {'password_hash': 'scrypt$x', 'log_lines': 2000}, {'password_hash': 'scrypt$x', 'log_lines': 2001},
    {'password_hash': 'scrypt$x', 'log_lines': True}, {'password_hash': 'scrypt$x', 'bogus': 1}]
SECTION_POOLS['dns'] = [
    None, {}, [], _dns(), _dns(enabled=False), _dns(enabled=1), _dns(bogus=1), _dns(bind=['10.77.0.3', 53]),
    _dns(bind=['10.77.0.2', 54]), _dns(bind=['127.0.0.1', 0]), _dns(bind=['127.0.0.1', 5353]),
    _dns(bind=['10.77.0.2']), _dns(bind=['x', 53]), _dns(ttl=300), _dns(ttl=301), _dns(ttl=-1), _dns(ttl=True),
    _dns(ttl=1.0), _dns(workers=0), _dns(workers=8), _dns(workers=9), _dns(pending=0), _dns(pending=32),
    _dns(pending=33), _dns(timeout=0.05), _dns(timeout=0.04), _dns(timeout=3), _dns(timeout=3.1), _dns(timeout=True),
    _dns(records={}), _dns(records={}, enabled=False), _dns(records=[]), _dns(records={'a': {}}),
    _dns(records={'game.example.com': {}}), _dns(records={'game.example.com': {'A': []}}),
    _dns(records={'game.example.com': {'A': ['203.0.113.%d' % i for i in range(1, 17)]}}),
    _dns(records={'game.example.com': {'A': ['203.0.113.%d' % i for i in range(1, 18)]}}),
    _dns(records={'game.example.com': {'AAAA': ['2001:db8::1']}}),
    _dns(records={'game.example.com': {'A': ['2001:db8::1']}}),
    _dns(records={'game.example.com': {'AAAA': ['203.0.113.5']}}),
    _dns(records={'game.example.com': {'MX': ['x']}}), _dns(records={'game.example.com': {'A': [5]}}),
    _dns(records={'game.example.com': {'A': ['nope']}}),
    _dns(records={'Game.Example.com': {'A': ['203.0.113.5']}, 'game.example.com.': {'A': ['203.0.113.6']}}),
    _dns(records={'game.example.com.': {'A': ['203.0.113.5']}}),
    _dns(records={'example': {'A': ['203.0.113.5']}}), _dns(records={'*.example.com': {'A': ['203.0.113.5']}}),
    _dns(records={'1.2.3.4': {'A': ['203.0.113.5']}}), _dns(records={'a_b.example.com': {'A': ['203.0.113.5']}}),
    _dns(records={'-a.example.com': {'A': ['203.0.113.5']}}),
    _dns(records={'%s.example.com' % ('a' * 63): {'A': ['203.0.113.5']}}),
    _dns(records={'%s.example.com' % ('a' * 64): {'A': ['203.0.113.5']}}),
    _dns(records={'h%d.example.com' % i: {'A': ['203.0.113.5']} for i in range(64)}),
    _dns(records={'h%d.example.com' % i: {'A': ['203.0.113.5']} for i in range(65)}),
    _dns(upstream=['8.8.8.8', 53]), _dns(upstream=['10.0.0.1', 53]), _dns(upstream=['8.8.8.8', 0]),
    _dns(upstream=['8.8.8.8']), _dns(upstream=None), _dns(upstream=['x', 53])]
