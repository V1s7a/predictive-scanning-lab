import pandas as pd, matplotlib.pyplot as plt
from pathlib import Path

# --- 1) Load data ---
ROOT = Path.home() / "predictive-scanning-lab"
df    = pd.read_csv(ROOT/"results/dataset.csv")          # has columns: host,port,label_open
allp  = pd.read_csv(ROOT/"results/all_probs.csv")        # has columns: host,port,p_open
hints_path = ROOT/"results/host_hints.csv"
hints = pd.read_csv(hints_path) if hints_path.exists() else pd.DataFrame(columns=["host","profile"])
seeds = [int(x) for x in (ROOT/"targets/seeds.txt").read_text().strip().split(",")]

# --- quick sanity prints ---
print("[sanity] rows in dataset:", len(df), "opens:", df["label_open"].sum())
print("[sanity] rows with probs:", len(allp), "unique hosts:", allp["host"].nunique())
print("[sanity] seeds:", seeds)
if hints.empty:
    print("[sanity] host_hints.csv not found or empty -> all weights default to 1.0")
else:
    print("[sanity] host hints:", dict(hints.values))

# --- 2) Build candidate pool: EXCLUDE seed ports (seeds are always scanned anyway) ---
candidates = allp[~allp["port"].isin(seeds)].copy()
print("[sanity] candidate pairs (non-seed):", len(candidates))

# --- 3) Risk weights (adjust if you changed profiles/ports) ---
profiles = {
  "db":      {3306: 2.0},
  "windows": {445: 1.8, 3389: 2.0, 5985: 2.0},
  "mail":    {25: 1.2, 110: 1.2, 143: 1.2, 993: 2.8, 995: 2.8},
  "adds":    {53:2.0, 88:2.5, 135:2.2, 139:2.2, 389:2.5, 445:2.0,
              464:2.2, 593:2.0, 636:2.2, 3268:2.5, 3269:2.5, 3389:2.0, 5985:2.0, 9389:2.2},
}
h2p = dict(hints.values) if not hints.empty else {}

def weight(h, p):
    prof = h2p.get(h, "")
    return profiles.get(prof, {}).get(int(p), 1.0)

candidates["weight"]  = [weight(h, p) for h,p in candidates[["host","port"]].values]
candidates["utility"] = candidates["p_open"] * candidates["weight"]

# --- 4) Ground-truth sets ---
open_set   = set(map(tuple, df[df.label_open==1][["host","port"]].itertuples(index=False, name=None)))
hosts_all  = sorted(df["host"].unique())
seed_open  = {(h,p) for (h,p) in open_set if int(p) in seeds}
print("[sanity] total opens:", len(open_set), "| opens on seed ports:", len(seed_open))

# --- 5) Must set (Mode 2) ---
def must_set():
    M = set()
    for h, prof in h2p.items():
        if prof == "adds":
            for p in [53,88,135,139,389,445,464,593,636,3268,3269,3389,5985,9389]:
                if ((h,int(p)) in set(map(tuple, candidates[["host","port"]].itertuples(index=False, name=None)))):
                    M.add((h,int(p)))
        if prof == "windows":
            for p in [445,3389,5985]:
                if ((h,int(p)) in set(map(tuple, candidates[["host","port"]].itertuples(index=False, name=None)))):
                    M.add((h,int(p)))
    return M

# --- 6) Evaluators ---
def eval_budget(B, mode2=False):
    # select Top-B by utility from the candidate pool
    sel = candidates.sort_values("utility", ascending=False).head(B)[["host","port"]]
    S = set(map(tuple, sel.itertuples(index=False, name=None)))
    if mode2:
        M = must_set()
        S |= M
        if len(S) > B:
            # drop lowest-utility items that are NOT must
            dfS = candidates.merge(pd.DataFrame(list(S), columns=["host","port"]), on=["host","port"], how="inner")
            Mset = set(M)
            dfS["is_must"] = dfS.apply(lambda r: (r["host"], int(r["port"])) in Mset, axis=1)
            need_drop = len(S) - B
            drop = dfS[~dfS["is_must"]].sort_values("utility").head(need_drop)
            S -= set(map(tuple, drop[["host","port"]].itertuples(index=False, name=None)))

    found = len(open_set & (S | seed_open))
    smart_probes = len(hosts_all)*len(seeds) + len(S)
    coverage = 100.0 * found / len(open_set) if open_set else 0.0
    return smart_probes, coverage

# --- 7) Sweep budgets and collect points ---
rows=[]
rows2=[]
for B in range(0, 61, 3):     # predicted budget 0..60
    sp,c1  = eval_budget(B, mode2=False)
    sp2,c2 = eval_budget(B, mode2=True)
    rows.append({"smart_probes":sp, "coverage%":round(c1,2), "mode":"Mode 1"})
    rows2.append({"smart_probes":sp2, "coverage%":round(c2,2), "mode":"Mode 2"})

tab = pd.DataFrame(rows + rows2)
print(tab.head(8))
tab.to_csv(ROOT/"results/budget_sweep_weighted.csv", index=False)

# --- 8) Plot (and show) ---
plt.figure()
for m, dfm in tab.groupby("mode"):
    dfm = dfm.sort_values("smart_probes")
    plt.plot(dfm["smart_probes"], dfm["coverage%"], marker="o", label=m)
plt.axvline(88, linestyle="--", label="Full scan = 88 probes")  # your full baseline
plt.xlabel("Smart probes (seeds + predicted)")
plt.ylabel("Coverage (%)")
plt.title("Coverage vs Probes (Weighted Policy)")
plt.legend()
plt.grid(True); plt.tight_layout()
plt.savefig(ROOT/"results/coverage_vs_probes_weighted.png", dpi=180)
plt.show()
print("Wrote:", ROOT/"results/budget_sweep_weighted.csv", "and", ROOT/"results/coverage_vs_probes_weighted.png")

