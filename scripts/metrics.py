# This script calculates metrics for predictive port scanning.
# It compares the effectiveness of scanning all ports (naive),
# scanning only seed ports, and scanning predicted ports using ML.
# Outputs a summary CSV and prints results.

import pandas as pd
from pathlib import Path

# Set the root directory of the project
ROOT = Path(__file__).resolve().parents[1]

# Read the list of ports to scan
ports = [int(p) for p in (ROOT/"targets/ports.txt").read_text().strip().split(",")]

# Read the list of target hosts
targets = [l.strip() for l in (ROOT/"targets/targets.txt").read_text().splitlines() if l.strip()]

# Load seed ports (fallback to classic trio if file doesn't exist)
seeds_file = ROOT/"targets/seeds.txt"
if seeds_file.exists():
    seed_ports = [int(p) for p in seeds_file.read_text().strip().split(",") if p.strip()]
else:
    seed_ports = [22,80,443]

# Load the dataset (ground truth) and predicted pairs
df   = pd.read_csv(ROOT/"results/dataset.csv")            # one row per (host,port), with label_open
pred = pd.read_csv(ROOT/"results/predicted_pairs.csv")    # (host,port[,p_open])

# --- Probe counts ---
full_probes  = len(targets) * len(ports)      # Probes if scanning all ports on all hosts
seed_probes  = len(targets) * len(seed_ports) # Probes if scanning only seed ports
smart_probes = seed_probes + len(pred)        # Probes for seed stage + predicted stage

# --- True opens in ground truth ---
open_df = df[df["label_open"] == 1][["host","port"]].drop_duplicates()
total_open = len(open_df)                     # Total open ports found in ground truth

# --- Found-by-Seed = opens that are in seed ports ---
seed_found = open_df[open_df["port"].isin(seed_ports)]    # Open ports found by scanning seed ports

# --- Found-by-Pred = opens that appear in predictions ---
pred_pairs = pred[["host","port"]].drop_duplicates()      # Predicted open ports
smart_found = open_df.merge(pred_pairs, on=["host","port"], how="inner") # Open ports found by prediction

# Union: Seed ∪ Pred
found = pd.concat([seed_found, smart_found], ignore_index=True).drop_duplicates()
found_open = len(found)                      # Total open ports found by seed or prediction

# Calculate coverage percentage
coverage = (100.0 * found_open / total_open) if total_open else 0.0
coverage = min(coverage, 100.0)  # never exceed 100

# Calculate probes per find (efficiency)
ppf_full  = full_probes / max(1, total_open)
ppf_smart = smart_probes / max(1, found_open)

# Build summary table
summary = pd.DataFrame([
    ["Naive-Full",     full_probes,  total_open, round(100.0,2),     round(ppf_full,2)],
    ["Seed+Smart(ML)", smart_probes, found_open, round(coverage,2),  round(ppf_smart,2)],
], columns=["Policy","Probes","Open Found","Coverage %","Probes/Find"])

# Print and save summary
print(summary.to_string(index=False))
summary.to_csv(ROOT/"results/summary.csv", index=False)

# Helpful debug info
print("\n[info] seeds used:", seed_ports)
print("[info] total (host,port) open =", total_open)
print("[info] predicted pairs =", len(pred_pairs))
print("[info] seed_probes =", seed_probes, "smart_probes =", smart_probes, "full_probes =", full_probes)
