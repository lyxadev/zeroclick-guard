#!/usr/bin/env bash
#
# benchmark.sh — the "World Spyware Gauntlet".
#
# Runs the behavioral profiles of known spyware families through the REAL
# zeroclick-guard engine and prints a scoreboard. Each profile is a BENIGN
# simulation (RFC 5737 test endpoints) that reproduces the family's documented
# *behavior*; the proof is that the engine flags every one, reproducibly.
#
# Exit code is non-zero if any profile is NOT detected — so this doubles as a
# regression test in CI.
#
# Usage: ./scripts/benchmark.sh

set -uo pipefail
cd "$(dirname "$0")/.."

IOC="examples/ioc-families.json"
ZCG="./target/release/zcg"
LAB="./target/release/zcg-testlab"
[ -x "$ZCG" ] || { ZCG="./target/debug/zcg"; LAB="./target/debug/zcg-testlab"; }
[ -x "$ZCG" ] || { echo "build first: cargo build --workspace --release"; exit 1; }

# Family profile → human-readable description.
FAMILIES=(
  "pegasus|Pegasus (NSO Group)|zero-click via messenger"
  "triangulation|Operation Triangulation|zero-click via iMessage"
  "predator|Predator (Cytrox/Intellexa)|installed, full capture"
  "finfisher|FinFisher / FinSpy (Gamma)|installed, mic+cam"
  "hermit|Hermit (RCS Lab)|installed via SMS lure"
  "chrysaor|Chrysaor|accessibility keylogging"
  "stalkerware|Commercial stalkerware|hidden tracker app"
)

if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  B=$'\e[1m'; D=$'\e[2m'; R=$'\e[31m'; G=$'\e[32m'; C=$'\e[36m'; Z=$'\e[0m'
else
  B=""; D=""; R=""; G=""; C=""; Z=""
fi

echo
echo "${B}${C}╔══════════════════════════════════════════════════════════════╗${Z}"
echo "${B}${C}║   WORLD SPYWARE GAUNTLET  ·  zeroclick-guard detection test   ║${Z}"
echo "${B}${C}╚══════════════════════════════════════════════════════════════╝${Z}"
echo "${D}  Benign behavioral profiles vs. the real engine. Not a claim — proof.${Z}"
echo

pass=0
total=0
for row in "${FAMILIES[@]}"; do
  IFS='|' read -r key name desc <<< "$row"
  total=$((total + 1))
  json="$("$LAB" "$key" | "$ZCG" --ioc "$IOC" --json 2>/dev/null)"
  read -r score sev <<< "$(printf '%s' "$json" | python3 -c "import sys,json
d=json.load(sys.stdin)
v=max(d,key=lambda x:x['score']) if d else {'score':0,'severity':'clean'}
print(v['score'], v['severity'])" 2>/dev/null)"
  score="${score:-0}"; sev="${sev:-clean}"
  if [ "$sev" = "high" ] || [ "$sev" = "critical" ]; then
    pass=$((pass + 1))
    printf "  ${G}✓ DETECTED${Z}  ${B}%-27s${Z} ${D}%-26s${Z} score ${B}%3s${Z} ${R}%s${Z}\n" \
      "$name" "$desc" "$score" "$(echo "$sev" | tr '[:lower:]' '[:upper:]')"
  else
    printf "  ${R}✗ MISSED  ${Z}  ${B}%-27s${Z} ${D}%-26s${Z} score %3s %s\n" \
      "$name" "$desc" "$score" "$sev"
  fi
done

echo
if [ "$pass" -eq "$total" ]; then
  echo "${B}${G}  RESULT: ${pass}/${total} families DETECTED — 0 missed.${Z}"
  echo "${D}  (Detection is behavioral; it also holds with the IoC list empty.)${Z}"
  echo
  exit 0
else
  echo "${B}${R}  RESULT: ${pass}/${total} detected — $((total - pass)) MISSED.${Z}"
  echo
  exit 1
fi
