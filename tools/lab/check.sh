#!/usr/bin/env bash
# Reports what this host can do for the lab, by trying it. Exit status 1 if a required capability is missing.
# Required: root, network namespaces, veth, nftables, tbf rate limiting, iperf3, conntrack.
# Optional: netem (delay, jitter, loss with tc), /dev/net/tun (running the real edge), tshark.
fail=0
ok()   { printf '  ok       %s\n' "$1"; }
no()   { printf '  MISSING  %s\n' "$1"; fail=1; }
opt()  { printf '  n/a      %s\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

echo "GameBond lab capabilities"
[ "$(id -u)" = 0 ] && ok "root" || no "root (namespaces and nftables need it)"
for t in ip nft tc iperf3 conntrack python3 go; do have "$t" && ok "$t" || no "$t"; done
for t in tshark tcpdump node; do have "$t" && ok "$t" || opt "$t (optional)"; done

a=gblchk$$a; b=gblchk$$b
cleanup() { ip netns del "$a" 2>/dev/null; ip netns del "$b" 2>/dev/null; ip link del gblchk0 2>/dev/null; }
trap cleanup EXIT
if ip netns add "$a" 2>/dev/null && ip netns add "$b" 2>/dev/null; then
  ok "network namespaces"
  if ip link add gblchk0 type veth peer name gblchk1 2>/dev/null; then
    ok "veth"
    ip link set gblchk0 netns "$a"; ip link set gblchk1 netns "$b"
    ip netns exec "$a" tc qdisc add dev gblchk0 root tbf rate 10mbit burst 32kb latency 50ms 2>/dev/null && ok "tbf rate limiting" || no "tbf rate limiting"
    if ip netns exec "$a" tc qdisc add dev gblchk0 parent 1:1 handle 10: netem delay 1ms 2>/dev/null || { ip netns exec "$a" tc qdisc replace dev gblchk0 root netem delay 1ms 2>/dev/null; }; then
      ok "netem (delay, jitter, loss with tc)"
    else
      opt "netem is not in this kernel: use nft 'numgen random' for loss, tbf for rate, and cmd/soak's proxy for delay and jitter"
    fi
    ip netns exec "$a" nft -f - <<'NFT' 2>/dev/null && ok "nftables random loss" || no "nftables random loss"
table ip gblchk {
  chain out {
    type filter hook output priority 0;
    ip protocol icmp numgen random mod 100 < 1 drop
  }
}
NFT
  else no "veth"; fi
else no "network namespaces"; fi
[ -c /dev/net/tun ] && ok "/dev/net/tun" || opt "/dev/net/tun (needed to run the real edge or client)"
echo "$(nproc) CPUs, $(awk '/MemTotal/{printf "%d", $2/1024}' /proc/meminfo) MB RAM"
exit $fail
