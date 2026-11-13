#!/usr/bin/env bash
# Installs the packages the GameBond benchmark and test lab needs on a Debian/Ubuntu host. Idempotent; run as root.
#   iperf3            throughput between namespaces
#   conntrack         flow table (the server's flow report and "end open connections")
#   tshark, tcpdump   packet capture (SentinelWire's wire monitor, protocol checks)
#   dnsutils, ethtool DNS queries and link settings
# iproute2, nftables, python3, Go and Node are expected to be present already.
set -euo pipefail
[ "$(id -u)" = 0 ] || { echo "run as root" >&2; exit 1; }
export DEBIAN_FRONTEND=noninteractive
echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections 2>/dev/null || true
apt-get update -qq
apt-get install -y -qq --no-install-recommends conntrack iperf3 tshark tcpdump dnsutils ethtool
exec "$(dirname "$0")/check.sh"
