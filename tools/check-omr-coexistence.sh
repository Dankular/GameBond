#!/usr/bin/env bash
# Dry-run (nft -c) deploy/omr-coexist/gamebond.nft against a checkout of openmptcprouter-vps.
# Loads nothing into the kernel. Usage: check-omr-coexistence.sh PATH_TO_openmptcprouter-vps
set -euo pipefail
SRC=${1:?Usage: check-omr-coexistence.sh PATH_TO_openmptcprouter-vps}
HERE=$(cd "$(dirname "$0")/.." && pwd)
for f in nftables.conf nftables/omr.nft nftables/omr-vars.nft; do [[ -f "$SRC/$f" ]] || { echo "missing $SRC/$f" >&2; exit 1; }; done
WORK=$(mktemp -d); trap 'rm -rf "$WORK"' EXIT
mkdir -p "$WORK/custom.d"
cp "$SRC/nftables/omr.nft" "$SRC/nftables/omr-vars.nft" "$WORK/"
cp "$HERE/deploy/omr-coexist/gamebond.nft" "$WORK/custom.d/"
sed "s#/etc/nftables#$WORK#g" "$SRC/nftables.conf" > "$WORK/nftables.conf"
echo "== OMR alone"; rm -f "$WORK/custom.d/gamebond.nft.off"
mv "$WORK/custom.d/gamebond.nft" "$WORK/gamebond.nft.off"; nft -c -f "$WORK/nftables.conf" && echo ok
echo "== OMR + GameBond"; mv "$WORK/gamebond.nft.off" "$WORK/custom.d/gamebond.nft"; nft -c -f "$WORK/nftables.conf" && echo ok
echo "== negative control (unknown chain must fail)"
sed 's/custom_dnat_bypass/no_such_chain/' "$HERE/deploy/omr-coexist/gamebond.nft" > "$WORK/custom.d/gamebond.nft"
if nft -c -f "$WORK/nftables.conf" 2>/dev/null; then echo "FAIL: broken file was accepted" >&2; exit 1; else echo "ok (rejected as expected)"; fi
