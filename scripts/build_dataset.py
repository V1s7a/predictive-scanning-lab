import pandas as pd, xmltodict
from pathlib import Path

root = Path.home() / "predictive-scanning-lab"
ports = [int(p) for p in root.joinpath("targets/ports.txt").read_text().strip().split(",")]
SEED_PORTS = [22, 80, 443]

def parse_hosts(xml_path: Path):
    """Return {ip_addr: set(open_ports)} from an Nmap XML file.
       Handles address/port fields that may be dicts or lists."""
    doc = xmltodict.parse(xml_path.read_text())
    hosts = (doc.get("nmaprun", {}) or {}).get("host", [])
    if isinstance(hosts, dict):
        hosts = [hosts]

    result = {}
    for h in hosts:
        # Only consider hosts that are 'up'
        if (h.get("status", {}) or {}).get("@state") != "up":
            continue

        # Address field can be a dict or a list (ipv4, ipv6, mac, etc.)
        addrs = h.get("address", [])
        if isinstance(addrs, dict):
            addrs = [addrs]

        ip = None
        for a in addrs:
            # Prefer ipv4/ipv6; skip MAC
            if a.get("@addrtype") in ("ipv4", "ipv6"):
                ip = a.get("@addr")
                break
        if not ip:
            # Fallback: first address if we didn't find ipv4/ipv6
            if addrs and "@addr" in addrs[0]:
                ip = addrs[0]["@addr"]
            else:
                # No usable address; skip
                continue

        # Ports field can be missing, a dict, or a list
        opens = set()
        psec = (h.get("ports", {}) or {}).get("port", []) or []
        if isinstance(psec, dict):
            psec = [psec]
        for p in psec:
            try:
                if (p.get("state", {}) or {}).get("@state") == "open":
                    opens.add(int(p.get("@portid")))
            except Exception:
                # Be permissive if anything is oddly shaped
                continue

        result[ip] = opens
    return result

# Parse ground-truth (all states) and seed-scan (features)
gt   = parse_hosts(root / "scans" / "nmap_groundtruth_all.xml")
seed = parse_hosts(root / "scans" / "nmap_seed.xml")

# Build the ML dataset: one row per (host,port)
rows = []
for host in gt.keys():
    seed_set = seed.get(host, set())
    for port in ports:
        rows.append({
            "host": host,
            "port": port,
            "seed22":  int(22  in seed_set),
            "seed80":  int(80  in seed_set),
            "seed443": int(443 in seed_set),
            "label_open": int(port in gt.get(host, set())),
        })

df = pd.DataFrame(rows)
out = root / "results" / "dataset.csv"
out.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(out, index=False)

print(f"Hosts parsed: {len(gt)}")
print(f"Total rows written: {len(df)} -> {out}")
print("Open labels (positives):", int((df['label_open']==1).sum()))
