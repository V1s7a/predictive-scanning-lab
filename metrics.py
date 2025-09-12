import pandas as pd
from pathlib import Path

root = Path.home()/ "predictive-scan"
ports = [int(p) for p in root.joinpath("targets/ports.txt").read_text().strip().split(",")]
targets = [l.strip() for l in root.joinpath("targets/targets.txt").read_text().splitlines() if l.strip()]
seed_ports = [22,80,443]

df = pd.read_csv(root/"results/dataset.csv")            # labels + seed features
pred = pd.read_csv(root/"results/predicted_pairs.csv")  # predicted (host,port)

full_probes = len(targets) * len(ports)
seed_probes = len(targets) * len(seed_ports)
smart_probes = seed_probes + len(pred)

# Found by seed + smart
seed_df = df[df["port"].isin(seed_ports) & (df["label_open"]==1)]
smart_df = pd.concat([seed_df,
                      df.merge(pred[["host","port"]].drop_duplicates(),
                               on=["host","port"], how="inner")],
                     ignore_index=True).drop_duplicates()

total_open = int((df["label_open"]==1).sum())
found_open = len(smart_df.drop_duplicates(subset=["host","port"]))
coverage = 100.0 * (found_open / total_open if total_open else 0)

ppf_full  = full_probes / max(1,total_open)
ppf_smart = smart_probes / max(1,found_open)

summary = pd.DataFrame([
    ["Naive-Full", full_probes, total_open, 100.0, round(ppf_full,2)],
    ["Seed+Smart(ML)", smart_probes, found_open, round(coverage,2), round(ppf_smart,2)]
], columns=["Policy","Probes","Open Found","Coverage %","Probes/Find"])

print(summary.to_string(index=False))
summary.to_csv(root/"results/summary.csv", index=False)