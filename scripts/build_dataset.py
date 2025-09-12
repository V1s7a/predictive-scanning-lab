# ~/predictive-scanning-lab/scripts/build_dataset.py
import pandas as pd, xmltodict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PORTS = [int(p) for p in (ROOT/"targets/ports.txt").read_text().strip().split(",")]
SEEDS_FILE = ROOT/"targets/seeds.txt"
SEED_PORTS = [int(p) for p in SEEDS_FILE.read_text().strip().split(",")] if SEEDS_FILE.exists() else [22,80,443]

def parse_hosts(xml_path: Path):
    doc = xmltodict.parse(xml_path.read_text())
    hosts = (doc.get("nmaprun", {}) or {}).get("host", []) or []
    if isinstance(hosts, dict): hosts = [hosts]
    res = {}
    for h in hosts:
        if (h.get("status", {}) or {}).get("@state") != "up": continue
        addrs = h.get("address", []) or []
        if isinstance(addrs, dict): addrs = [addrs]
        ip = None
        for a in addrs:
            if a.get("@addrtype") in ("ipv4","ipv6"):
                ip = a.get("@addr"); break
        if not ip:
            if addrs and "@addr" in addrs[0]: ip = addrs[0]["@addr"]
            else: continue
        opens = set()
        psec = (h.get("ports", {}) or {}).get("port", []) or []
        if isinstance(psec, dict): psec=[psec]
        for p in psec:
            try:
                if (p.get("state", {}) or {}).get("@state") == "open":
                    opens.add(int(p.get("@portid")))
            except Exception:
                pass
        res[ip] = opens
    return res

gt   = parse_hosts(ROOT/"scans"/"nmap_groundtruth_all.xml")
seed = parse_hosts(ROOT/"scans"/"nmap_seed.xml")

rows=[]
for host in gt:
    seed_set = seed.get(host, set())
    feats = {f"seed_{p}_open": int(p in seed_set) for p in SEED_PORTS}
    for port in PORTS:
        rows.append({
            "host": host,
            "port": port,
            **feats,
            "label_open": int(port in gt.get(host,set())),
        })

df = pd.DataFrame(rows)
out = ROOT/"results"/"dataset.csv"
out.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(out, index=False)
print(f"Hosts: {len(gt)} | Rows: {len(df)} | Positives: {(df['label_open']==1).sum()}")
print("Seed ports:", SEED_PORTS)
