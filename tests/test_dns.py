"""Exact-host DNS protocol behavior on ephemeral loopback UDP/TCP only."""
import socket
import struct
import threading
import time
import unittest
from unittest.mock import Mock, patch

from gamebond.dns import (DNSConfig, DNSFormatError, DNSResponder, HEADER,
                          load_dns_config, normalize_name, parse_question,
                          source_is_local)

HOST = "sat-wingdk-loginservice.prod.demonware.net"


def query(name=HOST, kind=1, transaction=0x1234):
    labels = name.rstrip(".").split(".")
    return (HEADER.pack(transaction, 0x0100, 1, 0, 0, 0) +
            b"".join(bytes([len(label)]) + label.encode() for label in labels) +
            b"\0" + struct.pack("!HH", kind, 1))


def exact(sock, size):
    result = bytearray()
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise ConnectionError("short test frame")
        result.extend(chunk)
    return bytes(result)


def answers(packet):
    question = parse_question(packet, response=True)
    offset = 12 + len(question.wire)
    result = []
    for _ in range(HEADER.unpack_from(packet)[3]):
        assert packet[offset:offset + 2] == b"\xc0\x0c"
        kind, cls, ttl, length = struct.unpack_from("!HHIH", packet, offset + 2)
        raw = packet[offset + 12:offset + 12 + length]
        result.append((kind, cls, ttl, raw))
        offset += 12 + length
    return question, result


class DNSTests(unittest.TestCase):
    def test_ephemeral_retries_escape_a_consecutive_udp_exclusion_range(self):
        original=socket.socket;failed=[];requested=[]
        def create(family,kind,*args,**kwargs):
            real=original(family,kind,*args,**kwargs)
            if kind==socket.SOCK_STREAM:
                wrapped=Mock(wraps=real)
                def bind(address):requested.append(address);return real.bind(address)
                wrapped.bind.side_effect=bind
                return wrapped
            if kind==socket.SOCK_DGRAM and len(failed)<16:
                failed.append(True);wrapped=Mock(wraps=real)
                wrapped.bind.side_effect=PermissionError(10013,'reserved UDP range')
                return wrapped
            return real
        with patch('gamebond.dns.socket.socket',side_effect=create):
            responder=DNSResponder(self.config()).start()
        try:
            self.assertEqual(len(failed),16)
            self.assertEqual(requested[0],('127.0.0.1',0))
            self.assertTrue(all(49152<=address[1]<=65535 for address in requested[1:]))
            self.assertGreater(len({address[1] for address in requested[1:]}),1)
            self.assertEqual(responder.udp.getsockname(),responder.tcp.getsockname())
        finally:responder.close()

    def test_ephemeral_binding_retries_a_port_reserved_for_the_other_protocol(self):
        original=socket.socket;failed=[]
        def create(family,kind,*args,**kwargs):
            real=original(family,kind,*args,**kwargs)
            if kind==socket.SOCK_DGRAM and not failed:
                failed.append(True)
                wrapped=Mock(wraps=real)
                wrapped.bind.side_effect=PermissionError(10013,'reserved ephemeral port')
                return wrapped
            return real
        with patch('gamebond.dns.socket.socket',side_effect=create):
            responder=DNSResponder(self.config()).start()
        try:
            self.assertEqual(responder.udp.getsockname(),responder.tcp.getsockname())
            self.assertTrue(failed)
        finally:responder.close()

    def config(self, **kwargs):
        return DNSConfig(records={HOST: {"A": ["127.0.0.1"]}}, bind=("127.0.0.1", 0), **kwargs)

    def responder(self, **kwargs):
        responder = DNSResponder(self.config(**kwargs)).start()
        self.addCleanup(responder.close)
        return responder

    def test_udp_exact_answer_case_trailingdot_id_and_low_ttl(self):
        server = self.responder(ttl=15)
        packet = query(HOST.upper() + ".")
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client:
            client.settimeout(1)
            client.sendto(packet, server.address)
            response, source = client.recvfrom(4096)
        self.assertEqual(source, server.address)
        self.assertEqual(response[:2], b"\x12\x34")
        flags = HEADER.unpack_from(response)[1]
        self.assertEqual(flags & 15, 0)
        self.assertTrue(flags & 0x0400)
        self.assertFalse(flags & 0x0020)  # Never assert DNSSEC authentication.
        question, records = answers(response)
        self.assertEqual(question.name, HOST)
        self.assertEqual(records, [(1, 1, 15, b"\x7f\0\0\1")])

    def test_tcp_length_framing_fragmentation_and_connection_reuse(self):
        server = self.responder()
        with socket.create_connection(server.address, timeout=1) as client:
            for kind in (1, 28):
                packet = query(kind=kind)
                frame = struct.pack("!H", len(packet)) + packet
                client.sendall(frame[:1])
                client.sendall(frame[1:7])
                client.sendall(frame[7:])
                size = struct.unpack("!H", exact(client, 2))[0]
                response = exact(client, size)
                self.assertEqual(HEADER.unpack_from(response)[3], 1 if kind == 1 else 0)
                self.assertEqual(HEADER.unpack_from(response)[1] & 15, 0)

    def test_aaaa_without_ipv6_override_is_authoritative_nodata_and_never_forwarded(self):
        server = self.responder(upstream=("1.1.1.1", 53))
        with patch.object(server, "_exchange") as exchange:
            response = server.answer(query(kind=28))
        exchange.assert_not_called()
        _, flags, qd, an, ns, ar = HEADER.unpack_from(response)
        self.assertEqual((flags & 15, qd, an, ns, ar), (0, 1, 0, 0, 0))
        self.assertTrue(flags & 0x0400)

    def test_unknown_name_and_suffix_lookalike_are_refused(self):
        server = self.responder()
        for name in ("example.net", "evil." + HOST, HOST + ".evil"):
            with self.subTest(name=name):
                response = server.answer(query(name))
                self.assertEqual(HEADER.unpack_from(response)[1] & 15, 5)

    def test_explicit_ipv6_answer_and_udp_truncation_then_full_tcp_answer(self):
        long_host = "longer-label-for-truncation." + HOST
        config = DNSConfig(records={long_host: {"AAAA": ["::1"] * 16}}, bind=("127.0.0.1", 0))
        server = DNSResponder(config)
        self.addCleanup(server.close)
        udp = server.answer(query(long_host, kind=28))
        self.assertTrue(HEADER.unpack_from(udp)[1] & 0x0200)
        self.assertEqual(HEADER.unpack_from(udp)[3], 0)
        tcp = server.answer(query(long_host, kind=28), tcp=True)
        self.assertFalse(HEADER.unpack_from(tcp)[1] & 0x0200)
        _, records = answers(tcp)
        self.assertEqual(len(records), 16)
        self.assertEqual(records[0][-1], b"\0" * 15 + b"\x01")

    def test_malformed_multiquestion_pointer_loops_and_bounds_return_formerr(self):
        server = self.responder()
        packets = [b"", b"\x12\x34", HEADER.pack(1, 0x100, 2, 0, 0, 0) + query()[12:],
                   HEADER.pack(1, 0x100, 1, 0, 0, 0) + b"\xc0\x0c\0\x01\0\x01",
                   HEADER.pack(1, 0x100, 1, 0, 0, 0) + b"\xc0\xff\0\x01\0\x01",
                   HEADER.pack(1, 0x100, 1, 0, 0, 0) + b"\x3fabc",
                   query() + b"trailing", query() * 100]
        for packet in packets:
            with self.subTest(packet=packet[:30]):
                response = server.answer(packet)
                self.assertEqual(HEADER.unpack_from(response)[1] & 15, 1)
        self.assertEqual(server.stats()["malformed"], len(packets))

    def test_forward_pointer_with_unaccounted_payload_is_rejected(self):
        # A bounded pointer does not excuse unaccounted trailing message bytes.
        tail = query()[12:-4]
        packet = HEADER.pack(7, 0x100, 1, 0, 0, 0) + b"\xc0\x12\0\x01\0\x01" + tail
        with self.assertRaises(DNSFormatError):
            parse_question(packet)  # Unaccounted trailing bytes are rejected.

    def test_upstream_validates_transaction_question_and_binds_tunnel_source(self):
        server = self.responder(upstream=("1.1.1.1", 53))
        packet = query("unmatched.example")

        def valid_exchange(forwarded, *, tcp):
            return forwarded[:2] + struct.pack("!H", 0x8180) + forwarded[4:]

        with patch.object(server, "_exchange", side_effect=valid_exchange):
            response = server.answer(packet)
            self.assertEqual(response[:2], packet[:2])
            self.assertEqual(HEADER.unpack_from(response)[1] & 15, 0)
        for corrupt in (lambda data: bytes([data[0] ^ 255]) + data[1:],
                        lambda data: query("wrong.example", transaction=int.from_bytes(data[:2], "big"))[:2] +
                            b"\x81\x80" + query("wrong.example")[4:]):
            with patch.object(server, "_exchange", side_effect=lambda data, tcp: corrupt(valid_exchange(data, tcp=tcp))):
                self.assertEqual(HEADER.unpack_from(server.answer(packet))[1] & 15, 2)
        fake = Mock()
        fake.recv.return_value = b"response"
        with patch("gamebond.dns.socket.socket", return_value=fake):
            self.assertEqual(server._exchange(packet, tcp=False), b"response")
        fake.bind.assert_called_once_with(("127.0.0.1", 0))
        fake.connect.assert_called_once_with(("1.1.1.1", 53))

    def test_worker_admission_is_bounded_and_close_interrupts_idle_tcp(self):
        server = self.responder(workers=1, pending=0, timeout=.1)
        release, entered = threading.Event(), threading.Event()

        def block():
            entered.set()
            release.wait(1)

        try:
            self.assertTrue(server._submit(block))
            self.assertTrue(entered.wait(1))
            self.assertFalse(server._submit(lambda: None))
            self.assertEqual(server.stats()["busy"], 1)
        finally:
            release.set()
        client = socket.create_connection(server.address, timeout=1)
        try:
            start = time.monotonic()
            server.close()
            self.assertLess(time.monotonic() - start, 1)
        finally:
            client.close()


class DNSConfigTests(unittest.TestCase):
    def test_disabled_profile_retains_validation_and_exact_name_normalization(self):
        self.assertIsNone(load_dns_config(None))
        self.assertFalse(load_dns_config({"enabled": False}).enabled)
        config = load_dns_config({"records": {HOST.upper() + ".": {"A": ["127.0.0.1"]}}})
        self.assertIn(HOST, config.records)
        self.assertEqual(config.bind, ("10.77.0.2", 53))
        self.assertEqual(normalize_name(HOST.upper() + "."), HOST)

    def test_public_wildcard_other_private_bind_and_bad_config_are_refused(self):
        for change in ({"bind": ["0.0.0.0", 53]}, {"bind": ["1.1.1.1", 53]},
                       {"bind": ["192.168.1.1", 53]}, {"bind": ["10.77.0.2", 5353]},
                       {"records": {"*.example.net": {"A": ["127.0.0.1"]}}},
                       {"records": {HOST: {"AAAA": ["127.0.0.1"]}}},
                       {"ttl": 301}, {"workers": 9}, {"pending": 33},
                       {"upstream": ["127.0.0.1", 53]}, {"enabled": 1}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                load_dns_config({"records": {HOST: {"A": ["127.0.0.1"]}}, **change})

    def test_local_source_filter_rejects_other_lan_and_public_clients(self):
        self.assertTrue(source_is_local("10.77.0.2", "10.77.0.2"))
        self.assertTrue(source_is_local("127.0.0.1", "10.77.0.2"))
        for source in ("10.77.0.1", "192.168.1.10", "1.1.1.1", "::1", "invalid"):
            self.assertFalse(source_is_local(source, "10.77.0.2"))


if __name__ == "__main__":
    unittest.main()
