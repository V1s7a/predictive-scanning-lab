import pandas as pd, numpy as np
from pathlib import Path
from sklearn.model_selection import GroupShuffleSplit
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import average_precision_score, roc_auc_score

root = Path.home()/ "predictive-scan"
df = pd.read_csv(root/"results/dataset.csv")
X = df[["seed22","seed80","seed443"]].values
y = df["label_open"].values
groups = df["host"].values  # split by host to avoid leakage

gss = GroupShuffleSplit(n_splits=1, test_size=0.3, random_state=42)
tr, te = next(gss.split(X, y, groups=groups))
Xtr, Xte, ytr, yte = X[tr], X[te], y[tr], y[te]

model = LogisticRegression(max_iter=1000).fit(Xtr, ytr)
p = model.predict_proba(Xte)[:,1]
print("AUC-PR:", round(average_precision_score(yte, p),4),
      "AUC-ROC:", round(roc_auc_score(yte, p),4))

# Coverage vs Probes curve on test set
rows=[]; total_open = int((yte==1).sum())
for tau in np.linspace(0.10,0.90,17):
    sel = p >= tau
    probes = int(sel.sum())
    tp = int(((sel==True) & (yte==1)).sum())
    coverage = 100.0 * (tp / total_open if total_open else 0)
    ppf = probes / tp if tp else float('inf')
    rows.append({"tau": round(tau,2), "probes": probes, "coverage%": round(coverage,2), "probes_per_finding": round(ppf,2)})
curves = pd.DataFrame(rows); print("\nCoverage vs Probes on test set:"); print(curves)

# Choose τ near ~98% coverage if available
target=98.0
candidates = curves[curves["coverage%"]>=target]
rec_tau = float(candidates.sort_values("probes").tau.iloc[0]) if not candidates.empty else float(curves.sort_values("coverage%", ascending=False).tau.iloc[0])
print("\nRecommended tau:", rec_tau)

# Predict for ALL rows using chosen τ → this is your "smart" scan list
df["p_open"] = model.predict_proba(df[["seed22","seed80","seed443"]])[:,1]
pred = df[df["p_open"] >= rec_tau].copy()
pred.to_csv(root/"results/predicted_pairs.csv", index=False)
print("Predicted pairs with tau=", rec_tau, ":", len(pred))