"""Explicitly configured, single-peer tunnel runner. Does not install routes."""
import argparse
import ipaddress
import json
import math
import os
from pathlib import Path
import queue
import secrets
import signal
import threading
import time
from datetime import datetime, timezone

from .policy import Classifier, QueuePolicy, PriorityScheduler, parse_packet,is_tcp_control
from .transport import Node, OVERHEAD, BOND_OVERHEAD
from .tun import open_tun
from .pacing import BulkPacer
from . import __version__
from .dns import DNSResponder, load_dns_config
from .telemetry import PriorityFlowTelemetry


def load_config(path,*,allow_unavailable_links=False):
    config = json.loads(Path(path).read_text(encoding="utf-8"))
    from .adaptive_qos import QoSSettings
    QoSSettings(**config.get('adaptive_qos',{}))
    if config.get('outer_transport') is not None:
        from .outer_transport import OuterSettings
        if config.get('role')!='client':raise ValueError('Outer fallback belongs to the client')
        OuterSettings(**config['outer_transport'])
    relays=config.get('stream_relays',[])
    if not isinstance(relays,list) or len(relays)>3 or (relays and config.get('role')!='server'):raise ValueError('Invalid server stream relays')
    from .stream_carrier import RelaySettings
    for relay in relays:RelaySettings(**relay)
    if len({tuple(relay['bind']) for relay in relays})!=len(relays):raise ValueError('Duplicate relay listener')
    from .link_policy import LinkPolicy
    policies=config.get('link_policies',{})
    if not isinstance(policies,dict) or len(policies)>64:raise ValueError('Invalid link policies')
    for index,policy in policies.items():
        if not index.isdigit() or int(index)<=0 or not isinstance(policy,dict):raise ValueError('Invalid link policy adapter')
        LinkPolicy(**policy)
    if config["role"] not in ("client", "server"):
        raise ValueError("role must be client or server")
    if not config["bind"] or (config["role"] == "server" and len(config["bind"]) != 1):
        raise ValueError("server requires one bind address")
    for host, port in config["bind"]:
        ipaddress.IPv4Address(host)
        if type(port) is not int or not 0 <= port <= 65535:
            raise ValueError("invalid bind port")
    if config["role"] == "client":
        identities=config.get('interface_ids')
        stable=(isinstance(identities,list) and len(identities)==2 and all(isinstance(v,str) and len(v)==38 and v.startswith('{') and v.endswith('}') for v in identities)
                and len({v.casefold() for v in identities})==2)
        hosts=[b[0] for b in config['bind']]
        if len(hosts)!=2 or (len(set(hosts))!=2 and not (allow_unavailable_links and stable and hosts==['0.0.0.0','0.0.0.0'])):
            raise ValueError("client requires two distinct physical adapter IPv4 addresses")
        for position,(host, _) in enumerate(config["bind"]):
            ip = ipaddress.IPv4Address(host)
            if ip.is_unspecified and allow_unavailable_links and stable:continue
            if ip.is_unspecified or ip.is_loopback or ip.is_link_local:
                raise ValueError("client paths need usable physical adapter IPv4 addresses")
        indices = config.get("interface_indices", [])
        identities=config.get('interface_ids')
        if identities is not None and (not isinstance(identities,list) or len(identities)!=len(config['bind']) or
                any(not isinstance(value,str) or (value and (len(value)!=38 or value[0]!='{' or value[-1]!='}')) for value in identities)):
            raise ValueError('interface_ids must contain one stable adapter identifier per selected link')
        if os.name == "nt" and (len(indices) != 2 or len(set(indices)) != 2 or
                                 any(type(i) is not int or i <= 0 for i in indices)):
            raise ValueError("Windows client needs two distinct positive interface_indices")
        peer = config["peer"]
        peer_ip = ipaddress.IPv4Address(peer[0])  # Avoid DNS route ambiguity.
        if peer_ip.is_unspecified or peer_ip.is_multicast or peer_ip.is_link_local:
            raise ValueError("peer must be a usable unicast IPv4 address")
        if type(peer[1]) is not int or not 1 <= peer[1] <= 65535:
            raise ValueError("invalid peer port")
    mtu = config.get("mtu", 1280)
    if not isinstance(mtu, int) or not 1280 <= mtu <= 1400:
        raise ValueError("inner MTU must be 1280..1400")
    # Reject unsupported policy values instead of silently pretending to implement them.
    for dscp, policy in config.get("queues", {}).items():
        if not str(dscp).isdigit() or not 0 <= int(dscp) <= 63:
            raise ValueError("DSCP must be 0..63")
        QueuePolicy(**policy)
    if type(config.get("redundant_mode", True)) is not bool:
        raise ValueError("redundant_mode must be a boolean")
    if type(config.get("bonding_mode", False)) is not bool:
        raise ValueError("bonding_mode must be a boolean")
    if config.get("bonding_mode", False) and config.get("redundant_mode", True):
        raise ValueError("bonding_mode requires redundant_mode=false; gameplay replication belongs in its DSCP queue")
    initial_rate = config.get("bonding_initial_rate_mbps", 1)
    max_rate = config.get("bonding_max_rate_mbps", 100)
    for name, value in (("bonding_initial_rate_mbps", initial_rate),
                        ("bonding_max_rate_mbps", max_rate)):
        if type(value) not in (int, float) or not math.isfinite(value) or value <= 0:
            raise ValueError(f"{name} must be finite and positive")
    if initial_rate > max_rate:
        raise ValueError("bonding_initial_rate_mbps must not exceed bonding_max_rate_mbps")
    reorder_timeout = config.get("reorder_timeout_ms", 30)
    if (type(reorder_timeout) not in (int, float) or not math.isfinite(reorder_timeout)
            or not 1 <= reorder_timeout <= 200):
        raise ValueError("reorder_timeout_ms must be finite and between 1 and 200")
    if type(config.get("direct_priority", True)) is not bool:
        raise ValueError("direct_priority must be a boolean")
    bulk_rate = config.get("bulk_rate_mbps", 0)
    if type(bulk_rate) not in (int, float) or not math.isfinite(bulk_rate) or bulk_rate < 0:
        raise ValueError("bulk_rate_mbps must be finite and nonnegative")
    if any(type(port) is not int or not 1 <= port <= 65535 for port in config.get("game_udp_ports", [])):
        raise ValueError("game_udp_ports must contain ports 1..65535")
    if config.get("game_udp_ports"):
        game_policy = QueuePolicy(**config.get("queues", {}).get("46", {}))
        if not game_policy.priority or not game_policy.replicate or not config.get("direct_priority", True):
            raise ValueError("game_udp_ports require direct_priority and a priority, replicated DSCP46 queue")
    if len(bytes.fromhex(config["session"])) != 16:
        raise ValueError("session must contain 16 random bytes in hex")
    ipaddress.IPv4Address(config["client_tunnel_ip"])
    dns_config = load_dns_config(config.get("dns"))
    if dns_config is not None:
        if config["role"] != "client":
            raise ValueError("managed DNS overrides belong to the client configuration")
        from .windows_dns import _hostname
        for name in dns_config.records:
            _hostname(name)
        if dns_config.enabled and dns_config.bind != (config["client_tunnel_ip"], 53):
            raise ValueError("managed DNS must bind the client's own tunnel IPv4 address on port 53")
    return config


def run(config, key_path, configure=False, *, stop_event=None, on_ready=None):
    if configure and (os.name != "nt" or config["role"] != "client"):
        raise ValueError("automatic network setup is for the Windows client only")
    dns_config = load_dns_config(config.get("dns"))
    if dns_config is not None and dns_config.enabled and not configure:
        raise ValueError("managed DNS requires the Windows client with --configure")
    key = Path(key_path).read_bytes()
    if len(key) != 32:
        raise ValueError("key file must contain exactly 32 random bytes")
    policies = {int(dscp): QueuePolicy(**policy) for dscp, policy in config.get("queues", {}).items()}
    from .adaptive_qos import AdaptiveQoS,QoSSettings,profile_policies
    qos=AdaptiveQoS(QoSSettings(**config.get('adaptive_qos',{})))
    if qos.settings.enabled:
        for tag,policy in profile_policies(qos.settings).items():policies.setdefault(tag,policy)
    classifier = Classifier(policies, game_ports=config.get("game_udp_ports", []))
    flow_telemetry = PriorityFlowTelemetry(config.get("game_udp_ports", []))
    scheduler = PriorityScheduler()
    bonding_mode = config.get("bonding_mode", False)
    tunnel_overhead = OVERHEAD + (BOND_OVERHEAD if bonding_mode else 0)
    bulk_rate = config.get("bulk_rate_mbps", 0) * 1_000_000 / 8
    pacer = BulkPacer(bulk_rate, 2 * (config.get("mtu", 1280) + tunnel_overhead + 28)) if bulk_rate else None
    stop = stop_event if stop_event is not None else threading.Event()
    errors = queue.Queue()
    counters = {"malformed": 0, "unsupported_ipv6": 0, "parse_errors": {},
                "wrong_tunnel_address": 0, "mtu_drop": 0,
                "direct_priority_packets": 0, "direct_priority_by_dscp": {},
                "no_path_drops": 0, "bulk_pacing_wait_ms": 0,
                "classified_outbound": {}, "classified_inbound": {},
                "priority_send_ms": {"count": 0, "mean": 0.0, "max": 0.0},
                "priority_inject_ms": {"count": 0, "mean": 0.0, "max": 0.0}}

    def observe_timing(name, started):
        elapsed = (time.perf_counter() - started) * 1000
        record = counters[name]
        record["count"] += 1
        record["mean"] += (elapsed - record["mean"]) / record["count"]
        record["max"] = max(record["max"], elapsed)
    client_ip = ipaddress.IPv4Address(config["client_tunnel_ip"]).packed
    node = Node(key, config["role"], bytes.fromhex(config["session"]),
                [tuple(b) for b in config["bind"]],
                tuple(config["peer"]) if config.get("peer") else None,
                mtu=config.get("mtu", 1280) + tunnel_overhead,
                interface_indices=config.get("interface_indices"),
                bonding_mode=bonding_mode,
                initial_rate_mbps=config.get("bonding_initial_rate_mbps", 1),
                max_rate_mbps=config.get("bonding_max_rate_mbps", 100),
                reorder_timeout=config.get("reorder_timeout_ms", 30) / 1000,
                outer_transport=config.get('outer_transport'))
    tun = None
    network = None
    dns = None
    dns_scope = None
    workers = []
    stream_relays=[]

    def valid(packet, incoming):
        if packet and packet[0] >> 4 == 6:
            counters["unsupported_ipv6"] += 1
            return None
        try:
            info = parse_packet(packet)
        except ValueError as exc:
            counters["malformed"] += 1
            reason = str(exc)
            counters["parse_errors"][reason] = counters["parse_errors"].get(reason, 0) + 1
            return None
        # This first deployment supports a single IPv4 client and IPv4 NAT only.
        # Enforce anti-spoofing before injecting authenticated peer traffic.
        if packet[0] >> 4 != 4:
            counters["malformed"] += 1
            return None
        is_client_packet = (config["role"] == "server") == incoming
        addr = packet[12:16] if is_client_packet else packet[16:20]
        if addr != client_ip:
            counters["wrong_tunnel_address"] += 1
            return None
        classification = classifier.classify_info(info)
        qos.refresh(node.stats)
        classification=qos.classify(classification)
        tags = counters["classified_inbound" if incoming else "classified_outbound"]
        tag = str(classification.dscp)
        tags[tag] = tags.get(tag, 0) + 1
        flow_telemetry.observe(classification, len(packet), incoming=incoming)
        return classification

    def send_packet(packet, classification):
        urgent,replicate=qos.transmission(classification,len(packet))
        copies = node.send(packet, replicate=config.get("redundant_mode", True) or replicate,
                           flow_id=classification.info.flow,urgent=urgent)
        if not copies:
            counters["no_path_drops"] += 1

    def guarded(fn):
        def invoke():
            try:
                fn()
            except Exception as exc:
                errors.put(exc)
                stop.set()
        return invoke

    def capture():
        while not stop.is_set():
            packet = tun.read(timeout=.25)
            if packet is None:
                continue
            if len(packet) > config.get("mtu", 1280):
                counters["mtu_drop"] += 1
                continue
            classification = valid(packet, incoming=False)
            if classification:
                if (classification.policy.priority and config.get("direct_priority", True)) or is_tcp_control(packet):
                    # Avoid a second thread handoff/age-drop queue for gameplay.
                    # Bulk pacing runs in a different worker, outside Node locks.
                    started = time.perf_counter()
                    send_packet(packet, classification)
                    observe_timing("priority_send_ms", started)
                    counters["direct_priority_packets"] += 1
                    tag = str(classification.dscp)
                    counters["direct_priority_by_dscp"][tag] = counters["direct_priority_by_dscp"].get(tag, 0) + 1
                else:
                    scheduler.push(packet, classification)

    def transmit():
        while not stop.is_set():
            item = scheduler.pop(timeout=.25)
            if item is not None:
                if pacer is not None and not item.classification.policy.priority:
                    copies = 2 if config.get("redundant_mode", True) else 1
                    delay = pacer.reserve((len(item.packet) + tunnel_overhead + 28) * copies)
                    counters["bulk_pacing_wait_ms"] += delay * 1000
                    if stop.wait(delay):
                        break
                send_packet(item.packet, item.classification)

    def inject():
        while not stop.is_set():
            try:
                packet = node.recv(timeout=.25)
            except (queue.Empty, TimeoutError):
                continue
            classification = valid(packet, incoming=True)
            if classification:
                started = time.perf_counter()
                tun.write(packet)
                if classification.policy.priority:
                    observe_timing("priority_inject_ms", started)

    previous = {}
    try:
        tun = open_tun(config.get("tun_name", "GameBond"), mtu=config.get("mtu", 1280),
                       dll_path=config.get("wintun_dll"))
        if configure:
            from .windows_network import WindowsNetwork
            from .windows_dns import recover_journals as recover_dns_journals
            # Recover a crashed DNS-enabled run even if this profile disables DNS.
            recover_dns_journals()
            network = WindowsNetwork(config, cod_executables=config.get("cod_executables", []))
            network.prepare()
        node.start()
        if config.get('stream_relays'):
            from .stream_carrier import CarrierRelay,RelaySettings
            for settings in config['stream_relays']:
                settings=RelaySettings(**settings)
                relay=CarrierRelay(settings.bind,('127.0.0.1',node.addresses[0][1]),key,bytes.fromhex(config['session']),
                    mode=settings.mode,context=settings.context(),max_clients=settings.max_clients)
                stream_relays.append(relay);relay.start()
        for sig in (signal.SIGINT, signal.SIGTERM):
            previous[sig] = signal.signal(sig, lambda *_: stop.set())
        if configure:
            print(json.dumps({"status": "waiting_for_two_healthy_physical_paths"}), flush=True)
            deadline = time.perf_counter() + 12
            while time.perf_counter() < deadline and not stop.wait(.05):
                paths = node.stats()["paths"]
                if len(paths) == 2 and all(path["healthy"] for path in paths):
                    break
            else:
                if stop.is_set():
                    return  # Cooperative startup stop still executes cleanup below.
                raise RuntimeError("both physical paths must authenticate before tunnel routes are activated; disconnect other VPNs and check endpoint/routes")
        for fn in (capture, transmit, inject):
            thread = threading.Thread(target=guarded(fn), daemon=True)
            workers.append(thread)
            thread.start()
        if dns_config is not None and dns_config.enabled:
            from .windows_dns import WindowsDnsScope
            dns = DNSResponder(dns_config).start()
            dns_scope = WindowsDnsScope(dns_config.records.keys(), dns_config.bind[0])
        if network is not None:
            network.activate()
            print(json.dumps({"status": "qos_policy_readback", "policies": network.qos_status()}), flush=True)
        if dns_scope is not None:
            dns_scope.activate()
            print(json.dumps({"status": "dns_overrides_active", "scope": dns_scope.status()}), flush=True)
        print(json.dumps({"status": "running", "version": __version__, "tun": tun.name,
                          "bind": node.addresses, "bonding_mode": bonding_mode}), flush=True)
        if on_ready is not None:
            on_ready()
        while not stop.wait(5):
            telemetry = {"version": __version__, "pid": os.getpid(),
                         "observed_at": datetime.now(timezone.utc).isoformat(),
                         "transport": node.stats(), "queues": scheduler.stats(), "packets": counters,
                         "priority_flows": flow_telemetry.stats(), "classifier": classifier.stats(),"qos":qos.stats(),
                         "stream_relays":[relay.stats() for relay in stream_relays]}
            if dns is not None:
                telemetry["dns"] = dns.stats()
            print(json.dumps(telemetry), flush=True)
        if not errors.empty():
            raise RuntimeError("tunnel worker failed") from errors.get()
    finally:
        stop.set()
        try:
            try:
                if dns_scope is not None:
                    dns_scope.close()
            finally:
                if dns is not None:
                    dns.close()
        finally:
            scheduler.close()
            for relay in stream_relays:relay.close()
            for thread in workers:
                thread.join(2)
            node.close()
            try:
                if network is not None:
                    network.close()
            finally:
                try:
                    if tun is not None:
                        tun.close()
                finally:
                    for sig, handler in previous.items():
                        signal.signal(sig, handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="version", version=__version__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("keygen", help="write a new shared key and print a fresh session ID")
    init.add_argument("path")
    check = sub.add_parser("check", help="validate config without changing networking")
    check.add_argument("config")
    start = sub.add_parser("run", help="open tunnel; requires separately configured routes")
    start.add_argument("config")
    start.add_argument("--key", required=True)
    start.add_argument("--configure", action="store_true", help="Windows: configure routes and CoD QoS after both links authenticate; Administrator required")
    dns_command = sub.add_parser("dns", help="manage project DNS overrides; applies on the next client restart")
    dns_command.add_argument("action", choices=("show", "set", "remove", "enable", "disable"))
    dns_command.add_argument("hostname", nargs="?")
    dns_command.add_argument("address", nargs="?")
    dns_command.add_argument("--config", default="configs/local-client.json")
    args = parser.parse_args()
    if args.command == "keygen":
        # Refuse overwrite. Never print key material into logs.
        fd = os.open(args.path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as file:
            file.write(secrets.token_bytes(32))
        print(json.dumps({"session": secrets.token_hex(16), "key_file": args.path}))
    elif args.command == "check":
        config = load_config(args.config)
        print(json.dumps({"valid": True, "role": config["role"]}))
    elif args.command == "dns":
        from .dns_management import manage
        print(json.dumps(manage(args.config, args.action, args.hostname, args.address), indent=2))
    else:
        run(load_config(args.config), args.key, configure=args.configure)
