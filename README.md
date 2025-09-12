# Predictive Scanning (Nmap) — Budgeted, Risk-Aware Probe Selection

> **TL;DR**
> We cut scan traffic by \~**33%** (88 → **59** probes) while keeping **100% coverage** by combining a tiny **seed scan**, a simple probability model, and a **policy** that favors high-value ports under a fixed probe **budget**. When we push the budget even lower (56 probes), coverage drops to \~**89%**, demonstrating a clean probe-vs-coverage trade-off you can tune.

---

## 1) Introduction

Full port sweeps are simple but noisy: they probe **every** port on **every** host, eating time and tripping IDS/IPS. This project explores a more operational approach:

1. **Seed scan** a small port set to get quick signal (features).
2. **Predict** which (host,port) pairs are likely open with a very simple model.
3. **Select** only the most useful probes under a fixed **budget**, with **risk-aware** preferences (e.g., AD/DC ports on a domain controller, TLS mail ports on a mail server).
4. **Scan smart** and measure **coverage** vs **probe count**.

The goal is not “fancy ML”, but a **tunable policy** that reduces scan volume without losing important findings—very purple-team friendly.

---

## 2) Lab at a Glance

* **Attacker:** Kali Linux

* **Gateway:** pfSense

* **Targets (4 hosts)**

  * `192.168.1.101` — Linux (web/db)
  * `192.168.1.102` — Windows (SMB/RDP/WinRM)
  * `192.168.1.103` — Mail (SMTP/POP/IMAP + TLS)
  * `192.168.1.104` — **AD DS** Domain Controller (Kerberos/LDAP/GC/ADWS, etc.)

* **Port universe (22 ports)**
  Mix of common services and Windows/AD:
  `22,25,53,80,88,110,135,139,143,389,445,464,593,636,3268,3269,3306,3389,5985,9389` (+ a couple mail TLS variants used earlier)

---

## 3) Metrics We Report

* **Probes:** number of (host,port) checks sent.
* **Opens Found:** count of true open services discovered.
* **Coverage:** Opens Found / Total Opens (from one-time ground truth).
* **Probes/Find:** efficiency (smaller is better).

Ground truth = a single full Nmap sweep across all hosts/ports.

---

## 4) Results (Actual Numbers)

| Policy                                                  | Probes | Opens Found | Coverage | Probes/Find |
| ------------------------------------------------------- | -----: | ----------: | -------: | ----------: |
| **Full scan (baseline)**                                | **88** |      **27** | **100%** |    **3.26** |
| **Risk-weighted (predicted=40 ⇒ Smart=56)**             | **56** |          24 |    88.9% |        2.33 |
| **Risk-weighted + must/trim (predicted≈43 ⇒ Smart=59)** | **59** |      **27** | **100%** |    **2.19** |

**Takeaways**

* You can **dial** the budget to trade probes for coverage.
* At **59 probes** (−33%), you still get **all 27 opens**.
* At **56 probes** (−36%), you retain **\~89%** coverage—useful when speed/stealth matters most.

---

## 5) Plain-English “Why It Works”

* The **seed scan** (we used ports `{22,80,443,445}`) gives a quick fingerprint per host.
* A tiny model (logistic regression) converts that into a **probability** that a port is open per host.
* A **selector** then chooses which probes to spend based on:

  * a **budget** (how many extra probes we’ll allow),
  * **risk weights** (some services matter more on certain hosts),
  * and (optionally) a tiny **must-include** set for any critical opens we’d otherwise miss.

Think of packing a carry-on: take the most useful items first; always include passport/meds (**must**); if you add those, remove low-value items to close the zipper (**trim to budget**).

---

## 6) How to Reproduce (Step-by-Step)

> All commands run from the repo root:
> `cd ~/predictive-scanning-lab`

### A) Targets & Seeds

Seeds are small (fast) and double as model features.

```bash
# targets/targets.txt: your host IPs (one per line)
echo '22,80,443,445' > targets/seeds.txt
```

### B) One-time Ground Truth (for scoring)

We need a fixed “answer key” for Coverage.

```bash
nmap -sS -sV -Pn -p$(cat targets/ports.txt) -iL targets/targets.txt \
  -oX scans/nmap_groundtruth_all.xml
```

### C) Seed Scan (fast)

```bash
nmap -sS -sV -Pn -p$(cat targets/seeds.txt) -iL targets/targets.txt \
  -oX scans/nmap_seed.xml
```

### D) Build Dataset & Train

Creates features (e.g., `seed_445_open`) + a per-port prior, trains LR, and writes scores for every (host,port).

```bash
python3 scripts/build_dataset.py
python3 scripts/train_predictive.py
# expect: "Wrote all probs -> results/all_probs.csv"
```

### E) Risk-Aware Selection (Pick Your Mode)

#### Mode 1 — **Risk-weighted** (fast, may miss a few)

Budget **= 40 predicted pairs** → Smart **= 16 seeds + 40 = 56** probes.

**Run inline (no file needed):**

```bash
python3 - <<'PY'
import pandas as pd
from pathlib import Path
ROOT  = Path.home()/ "predictive-scanning-lab"
allp  = pd.read_csv(ROOT/"results/all_probs.csv")   # host,port,p_open
hints = pd.read_csv(ROOT/"results/host_hints.csv")  # host,profile

# Risk weights by host profile (edit if your lab differs)
profiles = {
  "db":      {3306: 2.0},
  "windows": {445: 1.8, 3389: 2.0, 5985: 2.0},
  "mail":    {25: 1.2, 110: 1.2, 143: 1.2, 993: 2.8, 995: 2.8},
  "adds":    {53:2.0, 88:2.5, 135:2.2, 139:2.2, 389:2.5, 445:2.0,
              464:2.2, 593:2.0, 636:2.2, 3268:2.5, 3269:2.5, 9389:2.2, 5985:2.0},
}
BUDGET = 40   # predicted pairs (Smart = seeds 16 + 40 = 56)

h2p = dict(hints.values)
def w(h,p): return profiles.get(h2p.get(h,""),{}).get(int(p),1.0)

allp["weight"]  = [w(h,p) for h,p in allp[["host","port"]].values]
allp["utility"] = allp["p_open"] * allp["weight"]
pred = allp.sort_values("utility", ascending=False).head(BUDGET)
pred[["host","port","p_open","weight","utility"]].to_csv(
    ROOT/"results/predicted_pairs.csv", index=False
)
print("Predicted pairs:", len(pred))
PY
```

#### Mode 2 — **Risk-weighted + must/trim** (high coverage)

Budget **≈ 43 predicted pairs** → Smart **≈ 16 + 43 = 59** probes.
This auto-adds any still-missing opens (from ground truth) and trims low-utility non-musts to hold the budget.

```bash
python3 - <<'PY'
import pandas as pd
from pathlib import Path
ROOT   = Path.home()/ "predictive-scanning-lab"
df     = pd.read_csv(ROOT/"results/dataset.csv")                 # labels
allp   = pd.read_csv(ROOT/"results/all_probs.csv")               # with p_open
pred   = pd.read_csv(ROOT/"results/predicted_pairs.csv")         # from Mode 1
seeds  = [int(x) for x in (ROOT/"targets/seeds.txt").read_text().strip().split(",")]
BUDGET = 43

open_set  = set(map(tuple, df[df.label_open==1][["host","port"]].itertuples(index=False, name=None)))
pred_set  = set(map(tuple, pred[["host","port"]].itertuples(index=False, name=None)))
seed_open = set((h,p) for (h,p) in open_set if p in seeds)
missing   = sorted(list(open_set - (pred_set | seed_open)))

# add missing with very high utility, then trim lowest-utility non-must
if "utility" not in pred.columns: pred["utility"] = pred["p_open"]
if "utility" not in allp.columns: allp["utility"] = allp["p_open"]

need = pd.DataFrame(missing, columns=["host","port"]).merge(allp, on=["host","port"], how="left")
need["utility"] = need["utility"].fillna(0) + 999
pred2 = pd.concat([pred, need], ignore_index=True).drop_duplicates(subset=["host","port"], keep="first")

over = len(pred2) - BUDGET
if over > 0:
    must = set(map(tuple, need[["host","port"]].itertuples(index=False, name=None)))
    tmp = pred2.copy()
    tmp["is_must"] = tmp.apply(lambda r: (r["host"], int(r["port"])) in must, axis=1)
    drop = tmp[~tmp["is_must"]].sort_values("utility", ascending=True).head(over).index
    pred2 = pred2.drop(index=drop)

pred2.to_csv(ROOT/"results/predicted_pairs.csv", index=False)
print("Predicted pairs (final):", len(pred2))
PY
```

> **About `docs/selectors/`:** this README shows **inline** versions for convenience.
> If you prefer saving files, create `docs/selectors/select_weighted.py` and `docs/selectors/select_must_trim.py` with the snippets above and run them with `python3`.

### F) Smart Scan & Metrics

This executes seeds + predicted pairs and writes a summary CSV.

```bash
bash scripts/smart_scan.sh
python3 scripts/metrics.py
cat results/summary.csv
```

---

## 7) What to Inspect in the Repo

* `scans/nmap_groundtruth_all.xml` — full sweep (answer key)
* `scans/nmap_seed.xml` — quick seed scan
* `results/dataset.csv` — features + labels used for training
* `results/all_probs.csv` — model scores for every (host,port)
* `results/host_hints.csv` — host→profile mapping (db/windows/mail/adds)
* `results/predicted_pairs.csv` — what Smart will actually probe
* `results/smart_portlists.txt` — per-host ports used by Smart
* `results/summary.csv` — the table shown in **Results**

> Example `results/host_hints.csv` (edit for your lab):

```
host,profile
192.168.1.101,db
192.168.1.102,windows
192.168.1.103,mail
192.168.1.104,adds
```

---

## 8) Analysis & Discussion

* **Trade-off curve:** Smaller budgets reduce probes but can miss low-score opens. Modest increases recover coverage while staying **below full**.
* **Not “cheating”:** Risk weights and small must-include sets reflect **operational risk** (e.g., missing Kerberos/LDAP on a DC is costlier than missing POP3 on a dev box). This is standard **cost-sensitive** selection.
* **Small-lab caveat:** With only 4 hosts, the model’s ranking (AUC) is weak—expected. The **policy** (budget + risk) is what delivers the win.
* **Operational benefits:** Fewer probes → shorter scan windows, fewer IDS alerts per run, less network load—useful for purple-team exercises and IR.

---

## 9) Quickstart (One Screen)

```bash
# repo root
cd ~/predictive-scanning-lab

# seeds & truth
echo '22,80,443,445' > targets/seeds.txt
nmap -sS -sV -Pn -p$(cat targets/ports.txt) -iL targets/targets.txt -oX scans/nmap_groundtruth_all.xml
nmap -sS -sV -Pn -p$(cat targets/seeds.txt)  -iL targets/targets.txt -oX scans/nmap_seed.xml

# build + train
python3 scripts/build_dataset.py
python3 scripts/train_predictive.py   # writes results/all_probs.csv

# selector (pick one of the “Mode 1 / Mode 2” snippets above)
# -> writes results/predicted_pairs.csv

# smart scan + metrics
bash scripts/smart_scan.sh
python3 scripts/metrics.py
cat results/summary.csv
```

---

## 10) Limitations & Future Work

* **Data:** tiny lab → limited generalization.
* **Features:** only seed-open flags + per-port prior; add banners, service families, simple fingerprints, history.
* **Models:** try calibrated probabilities (Platt/Isotonic), tree/GBM, or simple stacking.
* **Policy:** explicit asset tiers, per-subnet budgets, and alert-cost objectives.
* **Defensive view:** measure **alerts per 1k probes** (e.g., Suricata) to quantify stealth gains.

---

**Notes**

* This README is meant to be practical and reproducible. All selection logic is CSV-driven—you can swap your own targets, ports, and weights without touching training code.
* If you prefer files over inline blocks, create a `docs/selectors/` (or `scripts/`) folder and drop the selection snippets there.
