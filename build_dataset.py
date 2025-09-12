import pandas as pd, xmltodict
from pathlib import Path

root = Path.home()/ "predictive-scan"
ports = [int(p) for p in root.joinpath("targets/ports.txt").read_text().strip().split(",")]
seed_ports = [int(p) for p in "22,80,443".split(",")]

def parse(xml_path):
    doc = xmltodict.parse(xml_path.read_text())
    res = {}
    hosts = doc["nmaprun"].get("host", []) or []
    if isinstance(hosts, dict): hosts = [hosts]
    for h in hosts:
        if h.get("status", {}).get("@state") != "up": continue
        addr = h["address"]["@addr"]
        opens = set()
        psec = (h.get("ports", {}) or {}).get("port", []) or []
        if isinstance(psec, dict): psec=[psec]
        for p in psec:
            if p.get("state", {}).get("@state") == "open":
                opens.add(int(p["@portid"]))
        res[addr] = opens
    return res

gt   = parse(root/"scans/nmap_groundtruth_all.xml")
seed = parse(root/"scans/nmap_seed.xml")

rows=[]
for host in gt:
    seeds = seed.get(host, set())
    for port in ports:
        rows.append({
            "host": host,
            "port": port,
            "seed22":  int(22  in seeds),
            "seed80":  int(80  in seeds),
            "seed443": int(443 in seeds),
            "label_open": int(port in gt.get(host,set())),
        })

df = pd.DataFrame(rows)
out = root/"results/dataset.csv"
out.parent.mkdir(parents=True, exist_ok=True)
df.to_csv(out, index=False)
print("Wrote", out, "rows:", len(df))