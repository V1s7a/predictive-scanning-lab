#!/usr/bin/env bash
# smart_scan.sh — run Nmap ONLY on ML-predicted (host,port) pairs
# Repo layout assumed:
#   ~/predictive-scanning-lab/
#     ├── results/predicted_pairs.csv   (from train_predictive.py)
#     ├── scans/                        (smart_<host>.xml goes here)
#     └── scripts/smart_scan.sh         (this file)

set -euo pipefail

# Resolve repo root no matter where this script is run from
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRED="$ROOT/results/predicted_pairs.csv"
OUTDIR="$ROOT/scans"
PORTLISTS="$ROOT/results/smart_portlists.txt"

# Optional env overrides:
#   NMAP_BIN=/usr/bin/nmap
#   NMAP_OPTS="-sS -Pn -n --max-retries 2 --host-timeout 30s"
#   SERVICE_DETECTION=1      # adds -sV
#   CAPTURE=1                # tcpdump a pcap per host
#   IFACE=eth0               # capture interface (auto-detected if unset)
NMAP_BIN="${NMAP_BIN:-nmap}"
NMAP_OPTS="${NMAP_OPTS:--sS -Pn -n --max-retries 2}"

if [[ "${SERVICE_DETECTION:-0}" == "1" ]]; then
  NMAP_OPTS="$NMAP_OPTS -sV"
fi

# Preconditions
if [[ ! -s "$PRED" ]]; then
  echo "ERROR: $PRED not found or empty. Run: python3 scripts/train_predictive.py" >&2
  exit 1
fi

mkdir -p "$OUTDIR" "$ROOT/targets" "$ROOT/results" "$ROOT/pcaps"

# Build per-host comma port lists from predicted_pairs.csv (expects header with host,port)
# Output format (one per line):  <host>:p1,p2,p3
tr -d '\r' < "$PRED" \
  | awk -F, 'NR>1 && $1!="" && $2!="" {print $1","$2}' \
  | sort -t, -k1,1 -k2,2n | uniq \
  | awk -F, '{a[$1]=a[$1] (a[$1]?",":"") $2} END {for (h in a) print h ":" a[h]}' \
  > "$PORTLISTS"

if [[ ! -s "$PORTLISTS" ]]; then
  echo "ERROR: no predicted (host,port) pairs to scan (empty $PORTLISTS)." >&2
  exit 1
fi

echo "[*] Built port lists -> $PORTLISTS"

# If capturing, determine interface if not provided
if [[ "${CAPTURE:-0}" == "1" && -z "${IFACE:-}" ]]; then
  IFACE="$(ip -o -4 route show to default | awk '{print $5}' | head -n1)"
  export IFACE
  if [[ -z "$IFACE" ]]; then
    echo "ERROR: could not auto-detect capture interface. Set IFACE=..." >&2
    exit 1
  fi
fi

# Scan each host with its predicted ports
while IFS= read -r line; do
  [[ -z "$line" ]] && continue
  host="${line%%:*}"
  ports="${line#*:}"
  ports="${ports#,}"; ports="${ports%,}"

  if [[ -z "$ports" ]]; then
    echo "[!] No ports for $host; skipping."
    continue
  fi

  xml="$OUTDIR/smart_${host}.xml"
  echo "[*] Scanning $host  ports: $ports"
  if [[ "${CAPTURE:-0}" == "1" ]]; then
    pcap="$ROOT/pcaps/smart_${host}.pcap"
    echo "    (capturing -> $pcap on $IFACE)"
    sudo tcpdump -i "$IFACE" -w "$pcap" host "$host" >/dev/null 2>&1 &
    tdpid=$!
    "$NMAP_BIN" $NMAP_OPTS -p "$ports" -oX "$xml" "$host" || true
    kill "$tdpid" >/dev/null 2>&1 || true
  else
    "$NMAP_BIN" $NMAP_OPTS -p "$ports" -oX "$xml" "$host" || true
  fi
done < "$PORTLISTS"

echo "[+] Smart scan complete. Results: $OUTDIR/smart_<host>.xml"
