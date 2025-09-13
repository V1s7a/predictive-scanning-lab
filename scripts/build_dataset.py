# This script builds a dataset for predictive port scanning.
# It reads Nmap scan results, extracts open ports for each host,
# and creates a CSV file with features and labels for machine learning.

import pandas as pd, xmltodict
from pathlib import Path

# Set the root directory of the project
ROOT = Path(__file__).resolve().parents[1]

# Read the list of ports to scan from a file
PORTS = [int(p) for p in (ROOT/"targets/ports.txt").read_text().strip().split(",")]

# Read the list of seed ports (initial ports to scan) from a file, or use defaults if file doesn't exist
SEEDS_FILE = ROOT/"targets/seeds.txt"
SEED_PORTS = [int(p) for p in SEEDS_FILE.read_text().strip().split(",")] if SEEDS_FILE.exists() else [22,80,443]

def parse_hosts(xml_path: Path):
    """
    Parse an Nmap XML scan file and extract open ports for each host.
    Returns a dictionary: {host_ip: set(open_ports)}
    """
    doc = xmltodict.parse(xml_path.read_text())
    hosts = (doc.get("nmaprun", {}) or {}).get("host", []) or []
    if isinstance(hosts, dict): hosts = [hosts]
    res = {}
    for h in hosts:
        # Only consider hosts that are 'up'
        if (h.get("status", {}) or {}).get("@state") != "up": continue
        addrs = h.get("address", []) or []
        if isinstance(addrs, dict): addrs = [addrs]
        ip = None
        for a in addrs:
            # Find the IP address of the host
            if a.get("@addrtype") in ("ipv4","ipv6"):
                ip = a.get("@addr"); break
        if not ip:
            # If no IP found, skip this host
            if addrs and "@addr" in addrs[0]: ip = addrs[0]["@addr"]
            else: continue
        opens = set()
        psec = (h.get("ports", {}) or {}).get("port", []) or []
        if isinstance(psec, dict): psec=[psec]
        for p in psec:
            try:
                # Add port to set if its state is 'open'
                if (p.get("state", {}) or {}).get("@state") == "open":
                    opens.add(int(p.get("@portid")))
            except Exception:
                pass
        res[ip] = opens
    return res

# Parse ground truth scan results (all ports)
gt   = parse_hosts(ROOT/"scans"/"nmap_groundtruth_all.xml")
# Parse seed scan results (only seed ports)
seed = parse_hosts(ROOT/"scans"/"nmap_seed.xml")

rows=[]
for host in gt:
    seed_set = seed.get(host, set())
    # Create features indicating which seed ports are open for this host
    feats = {f"seed_{p}_open": int(p in seed_set) for p in SEED_PORTS}
    for port in PORTS:
        # For each port, create a row with host, port, seed features, and label (is port open?)
        rows.append({
            "host": host,
            "port": port,
            **feats,
            "label_open": int(port in gt.get(host,set())),
        })

# Build a DataFrame from all rows
df = pd.DataFrame(rows)

# Save the dataset to a CSV file
out = ROOT/"results"/"dataset.csv"
out.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(out, index=False)

# Print summary statistics
print(f"Hosts: {len(gt)} | Rows: {len(df)} | Positives: {(df['label_open']==1).sum()}")
print("Seed ports:", SEED_PORTS)
