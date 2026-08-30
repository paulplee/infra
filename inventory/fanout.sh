#!/usr/bin/env bash
# fanout.sh — run host_inventory.py on remote hosts via ssh, gather the JSONs.
# Run from ae86 (cron) or atom (manual). Zero install on targets: the script is piped.
#
# Usage:
#   fanout.sh [--all | host1 host2 ...] [--push <zima-ip>] [--local] [--out DIR]
#     --all     use hosts.txt
#     --push IP rsync results to IP:~/netinv/data/inventory/
#     --local   also inventory this machine
# Examples:
#   fanout.sh --all --push 10.10.1.2              (cron, on ae86)
#   fanout.sh zima ae86 --local --push 10.10.1.2  (manual)
set -u
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${OUT:-$HERE/output/fanout}"
DATE="$(date +%F)"
PUSH=""
LOCAL=0
HOSTS=()

while [ $# -gt 0 ]; do
  case "$1" in
    --all)  HOSTS+=($(grep -vE '^\s*(#|$)' "$HERE/hosts.txt" 2>/dev/null));;
    --push) PUSH="$2"; shift;;
    --local) LOCAL=1;;
    --out)  OUT="$2"; shift;;
    -h|--help) echo "see header"; exit 0;;
    *) HOSTS+=("$1");;
  esac
  shift
done
mkdir -p "$OUT"

run_local() {
  local out="$OUT/inventory-$(hostname -s | tr 'A-Z' 'a-z')-$DATE.json"
  if python3 "$HERE/host_inventory.py" --stdout > "$out" 2>/dev/null \
     && python3 -m json.tool "$out" >/dev/null 2>&1; then
    echo "ok       local"
  else
    echo "FAIL     local"; rm -f "$out"
  fi
}

run_remote() {
  local h="$1" out="$OUT/inventory-${h}-$DATE.json"
  if ssh -o BatchMode=yes -o ConnectTimeout=8 "$h" 'python3 - --stdout' \
       < "$HERE/host_inventory.py" > "$out" 2>/dev/null \
     && python3 -m json.tool "$out" >/dev/null 2>&1; then
    echo "ok       $h"
  else
    echo "FAIL     $h"; rm -f "$out"
  fi
}

[ "$LOCAL" -eq 1 ] && run_local
for h in "${HOSTS[@]:-}"; do
  [ -n "$h" ] || continue
  run_remote "$h"
done

if [ -n "$PUSH" ] && ls "$OUT"/inventory-*-"$DATE".json >/dev/null 2>&1; then
  ssh -o BatchMode=yes -o ConnectTimeout=8 "$PUSH" 'mkdir -p ~/netinv/data/inventory' \
    && scp -q "$OUT"/inventory-*-"$DATE".json "$PUSH":~/netinv/data/inventory/ \
    && echo "pushed to $PUSH:~/netinv/data/inventory/"
fi
