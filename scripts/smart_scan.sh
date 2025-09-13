#!/usr/bin/env bash
# smart_scan.sh — run Nmap ONLY on ML-predicted (host,port) pairs
# This script reads predicted host/port pairs from a CSV file,
# builds per-host port lists, and runs Nmap scans only on those pairs.
# Optionally, it can capture traffic with tcpdump for each scan.

set -euo pipefail

# Resolve repo root no matter where this script is run from
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PRED="$ROOT/results/predicted_pairs.csv"      # CSV of predicted (host,port) pairs
OUTDIR="$ROOT/scans"                          # Directory to save scan results
PORTLISTS="$ROOT/results/smart_portlists.txt" # Per-host port lists

# Optional environment overrides for Nmap and capture settings
NMAP_BIN="${NMAP_BIN:-nmap}"
NMAP_OPTS="${NMAP_OPTS:--sS -Pn -n --max-retries 2}"

if [[ "${SERVICE_DETECTION:-0}" == "1" ]]; then
  NMAP_OPTS="$NMAP_OPTS -sV"
fi

# Check that predicted_pairs.csv exists and is not empty
if [[ ! -s "$PRED" ]]; then
  echo "ERROR: $PRED not found or empty. Run: python3 scripts/train_predictive.py" >&2
  exit 1
fi

# Create necessary directories
mkdir -p "$OUTDIR" "$ROOT/targets" "$ROOT/results" "$ROOT/pcaps"

# Build per-host comma-separated port lists from predicted_pairs.csv
# Output format: <host>:p1,p2,p3
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

# If capturing packets, determine network interface if not provided
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
  host="${line%%:*}"         # Extract host
  ports="${line#*:}"         # Extract port list
  ports="${ports#,}"; ports="${ports%,}"

  if [[ -z "$ports" ]]; then
    echo "[!] No ports for $host; skipping."
    continue
  fi

  xml="$OUTDIR/smart_${host}.xml"   # Output XML file for scan results
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
