"""Layer-2 gateway that lets one LAN device (for example a console) join the bond.

A physical adapter (typically a USB Ethernet dongle) is dedicated to a single
device. This module answers that device's DHCP and ARP requests, assigns it its
own tunnel-subnet IPv4 address, and exchanges plain IPv4 packets with the
bonded tunnel. Packets are forwarded unchanged (no NAT on the workstation); the
VPS sees the device's own tunnel address.

Scope: IPv4 only, one device per adapter, no IPv6, no multicast forwarding.
Raw frame I/O is supplied by `frame_io`; this module is platform independent.
"""
from __future__ import annotations

import ipaddress
import re
import struct
import threading
import time
from dataclasses import dataclass

ETH_IPV4 = 0x0800
ETH_ARP = 0x0806
BROADCAST_MAC = b"\xff" * 6
MAX_LAN_DEVICES = 4
DEFAULT_DNS = ("1.1.1.1", "8.8.8.8")
DEFAULT_LEASE_SECONDS = 86400
DEVICE_MTU = 1500
_MAC = re.compile(r"^[0-9a-f]{2}([:-][0-9a-f]{2}){5}$")
_GUID = re.compile(r"^\{[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}$")
_NAME = re.compile(r"^[A-Za-z0-9 ._()-]{1,32}$")


def parse_mac(text: str) -> bytes:
    if not isinstance(text, str) or not _MAC.match(text.lower()):
        raise ValueError("MAC address must look like aa:bb:cc:dd:ee:ff")
    return bytes.fromhex(re.sub(r"[:-]", "", text))


def format_mac(raw: bytes) -> str:
    return ":".join(f"{b:02x}" for b in raw)


# --- configuration -----------------------------------------------------------

@dataclass(frozen=True)
class LanDevice:
    """One device-facing adapter and the tunnel address its device receives."""
    name: str
    tunnel_ip: str
    interface_id: str = ""      # Windows adapter GUID, e.g. {xxxxxxxx-...}
    interface_index: int = 0    # Windows ifIndex (observation; GUID is identity)
    interface_name: str = ""    # Linux interface name
    device_mac: str = ""        # optional pin; otherwise first DHCP client wins
    dns: tuple = DEFAULT_DNS

    def validate(self, client_tunnel_ip: str) -> "LanDevice":
        if not isinstance(self.name, str) or not _NAME.match(self.name):
            raise ValueError("LAN device name must be 1-32 letters, digits, spaces or ._()-")
        subnet = tunnel_subnet(client_tunnel_ip)
        validate_lan_tunnel_ip(self.tunnel_ip, client_tunnel_ip)
        if ipaddress.IPv4Address(self.tunnel_ip) not in subnet:
            raise ValueError("LAN device tunnel_ip must share the client tunnel /24")
        if not (self.interface_id or self.interface_name):
            raise ValueError("LAN device needs interface_id (Windows) or interface_name (Linux)")
        if self.interface_id and not _GUID.match(self.interface_id.lower()):
            raise ValueError("LAN device interface_id must be a Windows adapter GUID in braces")
        if self.interface_name and not re.match(r"^[A-Za-z0-9_.:-]{1,15}$", self.interface_name):
            raise ValueError("LAN device interface_name must be a valid Linux interface name")
        if type(self.interface_index) is not int or self.interface_index < 0:
            raise ValueError("LAN device interface_index must be a nonnegative integer")
        if self.device_mac:
            parse_mac(self.device_mac)
        if (not isinstance(self.dns, (list, tuple)) or not 1 <= len(self.dns) <= 3
                or any(not _is_unicast_v4(d) for d in self.dns)):
            raise ValueError("LAN device dns must list one to three unicast IPv4 addresses")
        return self

    @property
    def identity(self) -> str:
        return (self.interface_id or self.interface_name).casefold()


def _is_unicast_v4(text) -> bool:
    try:
        ip = ipaddress.IPv4Address(text)
    except (ValueError, TypeError):
        return False
    return not (ip.is_unspecified or ip.is_loopback or ip.is_multicast or ip.is_link_local or ip == ipaddress.IPv4Address("255.255.255.255"))


def tunnel_subnet(client_tunnel_ip: str) -> ipaddress.IPv4Network:
    return ipaddress.IPv4Network(f"{client_tunnel_ip}/24", strict=False)


def validate_lan_tunnel_ip(address: str, client_tunnel_ip: str) -> None:
    """Addresses .0 .1 (VPS) .2 (default client) and .255 are reserved."""
    ip = ipaddress.IPv4Address(address)
    subnet = tunnel_subnet(client_tunnel_ip)
    reserved = {subnet.network_address, subnet.network_address + 1, subnet.broadcast_address,
                ipaddress.IPv4Address(client_tunnel_ip)}
    if ip not in subnet or ip in reserved:
        raise ValueError(f"{address} is not a usable device address in {subnet} (not .0, .1, .255 or the client address)")


def load_lan_devices(config: dict) -> list[LanDevice]:
    """Validate the client's `lan_devices` list. Empty when unconfigured."""
    raw = config.get("lan_devices", [])
    if not isinstance(raw, list) or len(raw) > MAX_LAN_DEVICES:
        raise ValueError(f"lan_devices must be a list of at most {MAX_LAN_DEVICES} devices")
    if raw and config.get("role") != "client":
        raise ValueError("lan_devices belong to the client configuration; the server uses lan_tunnel_ips")
    devices = []
    for entry in raw:
        if not isinstance(entry, dict):
            raise ValueError("Each lan_devices entry must be an object")
        unknown = set(entry) - {"name", "tunnel_ip", "interface_id", "interface_index", "interface_name", "device_mac", "dns"}
        if unknown:
            raise ValueError("Unknown lan_devices field: " + ", ".join(sorted(unknown)))
        values = dict(entry)
        if "dns" in values:
            values["dns"] = tuple(values["dns"]) if isinstance(values["dns"], list) else values["dns"]
        devices.append(LanDevice(**values).validate(config["client_tunnel_ip"]))
    for field_name in ("name", "tunnel_ip", "identity"):
        seen = [getattr(d, field_name).casefold() for d in devices]
        if len(set(seen)) != len(seen):
            raise ValueError(f"lan_devices must have distinct {field_name.replace('identity', 'adapters')}")
    macs = [d.device_mac.lower() for d in devices if d.device_mac]
    if len(set(macs)) != len(macs):
        raise ValueError("lan_devices must have distinct device_mac values")
    uplink_ids = {v.casefold() for v in config.get("interface_ids", []) if v}
    uplink_indices = set(config.get("interface_indices", []))
    for device in devices:
        if device.interface_id and device.interface_id.casefold() in uplink_ids:
            raise ValueError(f"{device.name}: adapter is already selected as a bonded uplink")
        if device.interface_index and device.interface_index in uplink_indices and not device.interface_id:
            raise ValueError(f"{device.name}: adapter is already selected as a bonded uplink")
    return devices


def load_lan_tunnel_ips(config: dict) -> list[str]:
    """Validate the server's `lan_tunnel_ips` (addresses it will accept and NAT)."""
    raw = config.get("lan_tunnel_ips", [])
    if not isinstance(raw, list) or len(raw) > 32:
        raise ValueError("lan_tunnel_ips must be a list of at most 32 addresses")
    for address in raw:
        validate_lan_tunnel_ip(address, config["client_tunnel_ip"])
    if len(set(raw)) != len(raw):
        raise ValueError("lan_tunnel_ips must be distinct")
    return list(raw)


# --- packet helpers ----------------------------------------------------------

def inet_checksum(data: bytes, initial: int = 0) -> int:
    if len(data) % 2:
        data += b"\0"
    total = initial + sum(struct.unpack(f"!{len(data) // 2}H", data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def build_ipv4(src: bytes, dst: bytes, protocol: int, payload: bytes, *, ttl: int = 64, ident: int = 0, flags_frag: int = 0) -> bytes:
    header = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident & 0xFFFF, flags_frag, ttl, protocol, 0, src, dst)
    return header[:10] + struct.pack("!H", inet_checksum(header)) + header[12:] + payload


def build_udp(src_ip: bytes, dst_ip: bytes, sport: int, dport: int, payload: bytes) -> bytes:
    length = 8 + len(payload)
    segment = struct.pack("!HHHH", sport, dport, length, 0) + payload
    pseudo = src_ip + dst_ip + struct.pack("!BBH", 0, 17, length)
    checksum = inet_checksum(pseudo + segment) or 0xFFFF
    return segment[:6] + struct.pack("!H", checksum) + segment[8:]


def parse_ipv4(packet: bytes):
    """Return (header_length, protocol, src, dst, total_length) or None if invalid."""
    if len(packet) < 20 or packet[0] >> 4 != 4:
        return None
    header = (packet[0] & 15) * 4
    total = struct.unpack_from("!H", packet, 2)[0]
    if header < 20 or total < header or total > len(packet):
        return None
    return header, packet[9], packet[12:16], packet[16:20], total


def _refresh_ip_checksum(packet: bytearray, header: int) -> None:
    packet[10:12] = b"\0\0"
    packet[10:12] = struct.pack("!H", inet_checksum(bytes(packet[:header])))


def decrement_ttl(packet: bytes) -> bytes | None:
    """Router behavior: refuse to forward an expiring packet."""
    if packet[8] <= 1:
        return None
    data = bytearray(packet)
    data[8] -= 1
    _refresh_ip_checksum(data, (data[0] & 15) * 4)
    return bytes(data)


def clamp_tcp_mss(packet: bytes, limit: int) -> bytes:
    """Lower the MSS option of SYN segments so full-size segments fit the tunnel."""
    parsed = parse_ipv4(packet)
    if not parsed or parsed[1] != 6:
        return packet
    header, _, src, dst, total = parsed
    if struct.unpack_from("!H", packet, 6)[0] & 0x1FFF:
        return packet  # non-first fragment carries no TCP header
    if total < header + 20 or not packet[header + 13] & 0x02:
        return packet
    offset = (packet[header + 12] >> 4) * 4
    if offset < 20 or header + offset > total:
        return packet
    data = bytearray(packet[:total])
    index = header + 20
    end = header + offset
    changed = False
    while index < end:
        kind = data[index]
        if kind == 0:
            break
        if kind == 1:
            index += 1
            continue
        if index + 1 >= end or data[index + 1] < 2 or index + data[index + 1] > end:
            break
        if kind == 2 and data[index + 1] == 4:
            if struct.unpack_from("!H", data, index + 2)[0] > limit:
                struct.pack_into("!H", data, index + 2, limit)
                changed = True
            break
        index += data[index + 1]
    if not changed:
        return packet
    segment_length = total - header
    data[header + 16:header + 18] = b"\0\0"
    pseudo = src + dst + struct.pack("!BBH", 0, 6, segment_length)
    data[header + 16:header + 18] = struct.pack("!H", inet_checksum(pseudo + bytes(data[header:total])))
    return bytes(data)


def fragment_ipv4(packet: bytes, mtu: int) -> list[bytes]:
    """Split a packet whose DF bit is clear. Honors existing fragment fields."""
    header = (packet[0] & 15) * 4
    payload = packet[header:]
    flags_frag = struct.unpack_from("!H", packet, 6)[0]
    base_offset = flags_frag & 0x1FFF
    more = bool(flags_frag & 0x2000)
    step = (mtu - header) // 8 * 8
    if step <= 0:
        raise ValueError("MTU too small to fragment")
    pieces = []
    for start in range(0, len(payload), step):
        chunk = payload[start:start + step]
        last = start + step >= len(payload)
        field = (base_offset + start // 8) & 0x1FFF
        if more or not last:
            field |= 0x2000
        data = bytearray(packet[:header]) + chunk
        data[2:4] = struct.pack("!H", len(data))
        data[6:8] = struct.pack("!H", field)
        _refresh_ip_checksum(data, header)
        pieces.append(bytes(data))
    return pieces


# --- the gateway -------------------------------------------------------------

@dataclass
class _Counters:
    frames_in: int = 0
    frames_out: int = 0
    packets_to_tunnel: int = 0
    packets_from_tunnel: int = 0
    dhcp_offers: int = 0
    dhcp_acks: int = 0
    dhcp_naks: int = 0
    arp_replies: int = 0
    foreign_mac_dropped: int = 0
    spoofed_source_dropped: int = 0
    local_only_dropped: int = 0
    ttl_expired: int = 0
    fragmented: int = 0
    frag_needed_sent: int = 0
    wrong_destination: int = 0
    no_device_mac: int = 0
    malformed: int = 0
    write_errors: int = 0

    def snapshot(self) -> dict:
        return dict(self.__dict__)


class LanGateway:
    """Serves one device on one adapter. Thread-safe `deliver`; one reader thread."""

    def __init__(self, device: LanDevice, io, on_packet, *, client_tunnel_ip: str, gateway_ip: str = "",
                 tunnel_mtu: int = 1280, lease_seconds: int = DEFAULT_LEASE_SECONDS,
                 stale_seconds: float = 120.0, clock=time.monotonic):
        self.device, self.io, self.on_packet, self.clock = device, io, on_packet, clock
        self.subnet = tunnel_subnet(client_tunnel_ip)
        # Default gateway is the VPS tunnel address; the workstation answers ARP for it.
        self.gateway_ip = ipaddress.IPv4Address(gateway_ip or (self.subnet.network_address + 1))
        self.device_ip = ipaddress.IPv4Address(device.tunnel_ip)
        self.gateway_raw, self.device_raw = self.gateway_ip.packed, self.device_ip.packed
        self.mac = bytes(io.mac)
        if len(self.mac) != 6:
            raise ValueError("adapter MAC address must be six bytes")
        self.pinned_mac = parse_mac(device.device_mac) if device.device_mac else None
        self.device_mac = self.pinned_mac
        self.last_seen = clock() if self.pinned_mac else None
        self.tunnel_mtu, self.lease_seconds, self.stale_seconds = tunnel_mtu, lease_seconds, stale_seconds
        self.mss_limit = tunnel_mtu - 40
        self.counters = _Counters()
        self._write_lock = threading.Lock()
        self._ident = 0
        self._stop = threading.Event()
        self._thread = None
        self.error = None
        self.leased = False

    # lifecycle
    def start(self) -> "LanGateway":
        self._thread = threading.Thread(target=self._run, daemon=True, name="gamebond-lan-" + self.device.name)
        self._thread.start()
        return self

    def _run(self) -> None:
        try:
            while not self._stop.is_set():
                frame = self.io.read(0.25)
                if frame is not None:
                    self.handle_frame(frame)
        except Exception as exc:  # adapter removed, driver closed, ...
            if not self._stop.is_set():
                self.error = str(exc) or exc.__class__.__name__

    @property
    def alive(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and self.error is None

    def close(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(2)
        self.io.close()

    def stats(self) -> dict:
        return dict(name=self.device.name, tunnel_ip=self.device.tunnel_ip, adapter_mac=format_mac(self.mac),
                    device_mac=format_mac(self.device_mac) if self.device_mac else "",
                    leased=self.leased, up=self.alive, error=self.error, **self.counters.snapshot())

    # frame input
    def handle_frame(self, frame: bytes) -> None:
        c = self.counters
        c.frames_in += 1
        if len(frame) < 14:
            c.malformed += 1
            return
        dst, src, ethertype = frame[0:6], frame[6:12], struct.unpack_from("!H", frame, 12)[0]
        if src == self.mac or (dst != self.mac and dst != BROADCAST_MAC):
            return
        if ethertype == ETH_ARP:
            self._arp(src, frame[14:])
        elif ethertype == ETH_IPV4:
            self._ipv4(src, frame[14:])

    def _may_claim(self, src: bytes) -> bool:
        """True if `src` is the device: pinned/learned MAC, or first/replacement when unpinned."""
        if src == self.device_mac:
            return True
        return self.pinned_mac is None and (self.device_mac is None or self._stale())

    def _touch(self, src: bytes) -> None:
        self.device_mac, self.last_seen = src, self.clock()

    def _stale(self) -> bool:
        return (self.pinned_mac is None and self.last_seen is not None
                and self.clock() - self.last_seen >= self.stale_seconds)

    def _arp(self, src_mac: bytes, body: bytes) -> None:
        if len(body) < 28 or body[:6] != b"\x00\x01\x08\x00\x06\x04":
            self.counters.malformed += 1
            return
        op = struct.unpack_from("!H", body, 6)[0]
        sender_mac, sender_ip, target_ip = body[8:14], body[14:18], body[24:28]
        if sender_mac != src_mac or op not in (1, 2):
            self.counters.malformed += 1
            return
        # Only the configured device may speak. A probe (sender 0.0.0.0) teaches nothing;
        # a message from the device's own address (re)learns its MAC.
        if sender_ip == self.device_raw:
            if not self._may_claim(src_mac):
                self.counters.foreign_mac_dropped += 1
                return
            self._touch(src_mac)
        elif sender_ip == b"\0\0\0\0":
            if self.device_mac is not None and src_mac != self.device_mac and not self._stale():
                self.counters.foreign_mac_dropped += 1
                return
        else:
            self.counters.spoofed_source_dropped += 1
            return
        if op != 1:
            return
        target = ipaddress.IPv4Address(target_ip)
        # Never answer for the device's own address (that would defeat its duplicate-address probe).
        if target == self.device_ip or target not in self.subnet or target == self.subnet.broadcast_address:
            return
        reply = (b"\x00\x01\x08\x00\x06\x04\x00\x02" + self.mac + target_ip + sender_mac + sender_ip)
        self._send_frame(src_mac, ETH_ARP, reply)
        self.counters.arp_replies += 1

    def _ipv4(self, src_mac: bytes, packet: bytes) -> None:
        c = self.counters
        parsed = parse_ipv4(packet)
        if not parsed:
            c.malformed += 1
            return
        header, protocol, src, dst, total = parsed
        packet = packet[:total]  # strip Ethernet padding
        if protocol == 17 and total >= header + 8 and struct.unpack_from("!H", packet, header + 2)[0] == 67:
            self._dhcp(src_mac, packet[header + 8:])
            return
        if not self._may_claim(src_mac):
            c.foreign_mac_dropped += 1
            return
        if src != self.device_raw:
            c.spoofed_source_dropped += 1
            return
        self._touch(src_mac)
        destination = ipaddress.IPv4Address(dst)
        if (destination.is_multicast or destination.is_unspecified or destination.is_loopback
                or dst == b"\xff\xff\xff\xff" or destination == self.subnet.broadcast_address
                or destination == self.device_ip):
            c.local_only_dropped += 1
            return
        forwarded = decrement_ttl(packet)
        if forwarded is None:
            c.ttl_expired += 1
            return
        forwarded = clamp_tcp_mss(forwarded, self.mss_limit)
        if len(forwarded) > self.tunnel_mtu:
            if struct.unpack_from("!H", forwarded, 6)[0] & 0x4000:
                self._frag_needed(forwarded)
                return
            pieces = fragment_ipv4(forwarded, self.tunnel_mtu)
            c.fragmented += 1
        else:
            pieces = [forwarded]
        for piece in pieces:
            c.packets_to_tunnel += 1
            self.on_packet(piece)

    # DHCP
    def _dhcp(self, src_mac: bytes, payload: bytes) -> None:
        if len(payload) < 240 or payload[0] != 1 or payload[1] != 1 or payload[2] != 6 or payload[236:240] != b"\x63\x82\x53\x63":
            self.counters.malformed += 1
            return
        chaddr = payload[28:34]
        if chaddr != src_mac:
            self.counters.malformed += 1
            return
        options = {}
        index = 240
        while index < len(payload):
            kind = payload[index]
            if kind == 255:
                break
            if kind == 0:
                index += 1
                continue
            if index + 1 >= len(payload) or index + 2 + payload[index + 1] > len(payload):
                break
            options[kind] = payload[index + 2:index + 2 + payload[index + 1]]
            index += 2 + payload[index + 1]
        kind = options.get(53, b"\0")[0]
        if kind not in (1, 3):  # DISCOVER, REQUEST; RELEASE/INFORM/DECLINE need no action here
            return
        if self.pinned_mac is not None:
            if src_mac != self.pinned_mac:
                self.counters.foreign_mac_dropped += 1
                return
        elif self.device_mac is not None and src_mac != self.device_mac and not self._stale():
            self.counters.foreign_mac_dropped += 1
            return
        self._touch(src_mac)
        xid, flags = payload[4:8], payload[10:12]
        if kind == 1:
            self._dhcp_reply(2, xid, flags, chaddr, self.device_raw)
            self.counters.dhcp_offers += 1
            return
        server = options.get(54)
        if server is not None and server != self.gateway_raw:
            return  # the client accepted another server's offer
        requested = options.get(50) or (payload[12:16] if payload[12:16] != b"\0\0\0\0" else b"")
        if requested == self.device_raw:
            self._dhcp_reply(5, xid, flags, chaddr, self.device_raw)
            self.counters.dhcp_acks += 1
            self.leased = True
        else:
            self._dhcp_reply(6, xid, flags, chaddr, b"\0\0\0\0")
            self.counters.dhcp_naks += 1

    def _dhcp_reply(self, message: int, xid: bytes, flags: bytes, chaddr: bytes, yiaddr: bytes) -> None:
        body = struct.pack("!BBBB4sH2s4s4s4s4s", 2, 1, 6, 0, xid, 0, flags, b"\0" * 4, yiaddr, self.gateway_raw, b"\0" * 4)
        body += chaddr + b"\0" * 10 + b"\0" * 64 + b"\0" * 128 + b"\x63\x82\x53\x63"
        options = bytes([53, 1, message]) + bytes([54, 4]) + self.gateway_raw
        if message != 6:
            options += bytes([51, 4]) + struct.pack("!I", self.lease_seconds)
            options += bytes([58, 4]) + struct.pack("!I", self.lease_seconds // 2)
            options += bytes([59, 4]) + struct.pack("!I", self.lease_seconds * 7 // 8)
            options += bytes([1, 4]) + self.subnet.netmask.packed
            options += bytes([3, 4]) + self.gateway_raw
            dns = b"".join(ipaddress.IPv4Address(d).packed for d in self.device.dns)
            options += bytes([6, len(dns)]) + dns
            options += bytes([26, 2]) + struct.pack("!H", self.tunnel_mtu)
            options += bytes([28, 4]) + self.subnet.broadcast_address.packed
        options += b"\xff"
        udp = build_udp(self.gateway_raw, b"\xff" * 4, 67, 68, body + options)
        # Always broadcast: valid before the client has configured an address.
        self._send_frame(BROADCAST_MAC, ETH_IPV4, build_ipv4(self.gateway_raw, b"\xff" * 4, 17, udp, ident=self._next_ident()))

    # tunnel -> device
    def deliver(self, packet: bytes) -> bool:
        """Send a packet received from the VPS to the device. Returns True if sent."""
        c = self.counters
        parsed = parse_ipv4(packet)
        if not parsed:
            c.malformed += 1
            return False
        _, _, _, dst, total = parsed
        if dst != self.device_raw:
            c.wrong_destination += 1
            return False
        if self.device_mac is None:
            c.no_device_mac += 1
            return False
        packet = decrement_ttl(packet[:total])
        if packet is None:
            c.ttl_expired += 1
            return False
        packet = clamp_tcp_mss(packet, self.mss_limit)
        if len(packet) > DEVICE_MTU:
            c.malformed += 1
            return False
        c.packets_from_tunnel += 1
        return self._send_frame(self.device_mac, ETH_IPV4, packet)

    def _frag_needed(self, original: bytes) -> None:
        header = (original[0] & 15) * 4
        quoted = original[:header + 8]
        icmp = struct.pack("!BBHHH", 3, 4, 0, 0, self.tunnel_mtu) + quoted
        icmp = icmp[:2] + struct.pack("!H", inet_checksum(icmp)) + icmp[4:]
        if self.device_mac is not None:
            self._send_frame(self.device_mac, ETH_IPV4,
                             build_ipv4(self.gateway_raw, self.device_raw, 1, icmp, ident=self._next_ident()))
            self.counters.frag_needed_sent += 1

    def _next_ident(self) -> int:
        self._ident = (self._ident + 1) & 0xFFFF
        return self._ident

    def _send_frame(self, dst_mac: bytes, ethertype: int, payload: bytes) -> bool:
        frame = dst_mac + self.mac + struct.pack("!H", ethertype) + payload
        if len(frame) < 60:
            frame += b"\0" * (60 - len(frame))
        with self._write_lock:
            try:
                self.io.write(frame)
            except OSError:
                self.counters.write_errors += 1
                return False
        self.counters.frames_out += 1
        return True
