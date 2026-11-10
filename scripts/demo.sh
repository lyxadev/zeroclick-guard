#!/usr/bin/env bash
#
# demo.sh — memutar demo "brutal" zeroclick-guard untuk rekaman/presentasi.
#
# Serangan terkoordinasi gaya APT (zero-click di 2 messenger + spyware
# menyamar) ditangkal LIVE oleh engine asli. Penyerangnya simulator jinak;
# defender-nya engine produk yang sesungguhnya — tidak ada yang dipalsukan.
#
# Pakai:  ./scripts/demo.sh [skenario] [speed]
#   skenario : brutal (default) | zeroclick | spyware | benign
#   speed    : faktor percepatan replay (default 40; makin besar makin cepat)
#
# Contoh rekaman rapi:  asciinema rec -c './scripts/demo.sh' demo.cast

set -euo pipefail
cd "$(dirname "$0")/.."

SCENARIO="${1:-brutal}"
SPEED="${2:-40}"
IOC="examples/ioc-testlab.json"

export TERM="${TERM:-xterm-256color}"

echo "» Membangun zeroclick-guard…"
cargo build --workspace --quiet
echo "» Siap. Memutar skenario: ${SCENARIO} (speed ${SPEED})"
echo
sleep 1

./target/debug/zcg-testlab "${SCENARIO}" \
  | ./target/debug/zcg --ioc "${IOC}" --replay --speed "${SPEED}"
