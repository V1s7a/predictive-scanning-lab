# This script trains a predictive model for port scanning using logistic regression.
# It reads the dataset, splits data by host to avoid leakage, trains the model,
# evaluates performance, and outputs predicted open ports for scanning.

import pandas as pd, numpy as np
from pathlib import Path
from sklearn.model_selection import GroupShuffleSplit
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score

ROOT = Path(__file__).resolve().parents[1]
df = pd.read_csv(ROOT/"results/dataset.csv")

# Auto-detect seed feature columns (e.g., seed_22_open)
seed_cols = [c for c in df.columns if c.startswith("seed_") and c.endswith("_open")]
if not seed_cols:
    seed_cols = [c for c in df.columns if c.startswith("seed") and c[4:].isdigit()]
if not seed_cols:
    raise SystemExit("No seed features found. Re-run build_dataset.py after you run a seed scan.")

y = df["label_open"].values        # Labels: 1 if port is open, else 0
groups = df["host"].values         # Group by host to avoid data leakage

# Split data into train/test by host (not by row) for fair evaluation
gss = GroupShuffleSplit(n_splits=1, test_size=0.34, random_state=42)
tr, te = next(gss.split(df[seed_cols].values, y, groups=groups))
train_df = df.iloc[tr].copy()
test_df  = df.iloc[te].copy()

# Add per-port prior probability (from training set only)
port_prior = train_df.groupby("port")["label_open"].mean()
df["port_prior"] = df["port"].map(port_prior).fillna(0.01)

feat_cols = seed_cols + ["port_prior"]    # Features for the model
Xtr = df.loc[train_df.index, feat_cols].values
Xte = df.loc[test_df.index,  feat_cols].values
ytr, yte = y[tr], y[te]

# Train logistic regression model
model = LogisticRegression(max_iter=2000, class_weight="balanced", solver="lbfgs", random_state=42)
model.fit(Xtr, ytr)

# Evaluate model on test set
pte = model.predict_proba(Xte)[:,1]   # Predicted probability port is open
print("Features used:", feat_cols)
print("AUC-PR:", round(average_precision_score(yte, pte),4),
      "AUC-ROC:", round(roc_auc_score(yte, pte),4))

# Calculate coverage and efficiency for different probability thresholds (tau)
rows=[]; total_open = int((yte==1).sum())
for tau in np.linspace(0.10,0.90,17):
    sel = pte >= tau
    probes = int(sel.sum())
    tp = int(((sel==True) & (yte==1)).sum())
    cov = 100.0*(tp/total_open if total_open else 0.0)
    ppf = probes/max(1,tp)
    rows.append({"tau":round(tau,2),"probes":probes,"coverage%":round(cov,2),"probes_per_finding":round(ppf,2)})
curve = pd.DataFrame(rows)
print("\nCoverage vs Probes (test set):\n", curve.to_string(index=False))

# Choose threshold tau to achieve target coverage (default 98%)
target = float((ROOT/"results/coverage_target.txt").read_text().strip()) if (ROOT/"results/coverage_target.txt").exists() else 98.0
cands = curve[curve["coverage%"] >= target]
rec_tau = float(cands.sort_values("probes").tau.iloc[0]) if not cands.empty else float(curve.sort_values("coverage%", ascending=False).tau.iloc[0])
print("\nRecommended tau:", rec_tau)

# Compute predicted probabilities for ALL rows in the dataset
p_all = model.predict_proba(df[feat_cols])[:,1]

# Save predicted (host,port) pairs with probability above threshold
out = df.loc[:, ["host","port"]].copy()
out["p_open"] = p_all
pred = out[out["p_open"] >= rec_tau].copy()
pred.to_csv(ROOT/"results/predicted_pairs.csv", index=False)
print("Predicted pairs:", len(pred), "->", ROOT/"results/predicted_pairs.csv")

# Save probabilities for all (host,port) pairs for further analysis
df_all = df.loc[:, ["host","port"]].copy()
df_all["p_open"] = p_all
df_all.to_csv(ROOT/"results/all_probs.csv", index=False)
print("Wrote all probs ->", ROOT/"results/all_probs.csv")
