"""Validación externa con NF-ToN-IoT-v3 (Luay et al., 2025, UQ; doi:10.48610/44d7c5e).

Dataset NetFlow (nProbe) con marcas de tiempo. En el archivo publicado el
tráfico benigno corre en paralelo a los ataques (solo 1 de 108 h está libre de
ataques), pero cada tipo de ataque ocupa su propio intervalo y aparecen en orden
cronológico. Por eso el protocolo es una división temporal (pasado -> futuro):

  fit  : antes del (n_seen+1)-ésimo tipo de ataque, salvo las últimas cal_hours
         - no supervisados: solo flujos etiquetados benignos (semi-supervisado)
         - supervisados: todos los flujos (ven los primeros n_seen ataques)
  cal  : las cal_hours previas a la prueba; solo benignos, para el umbral
  test : del (n_seen+1)-ésimo ataque al final; todos sus ataques son nuevos
         para los supervisados

No se muestrean flujos sueltos (rompería las ventanas por host): se eligen
bloques completos de 10 min, alineados con la ventana w10, hasta cubrir un
presupuesto de flujos por partición y por tipo de ataque.

Uso:
  python -m safecampus.nf3 profile            # 1.ª pasada: conteos por día/bloque/clase
  python -m safecampus.nf3 build              # 2.ª pasada: subconjunto -> data/nf3_subset.pkl
  python -m safecampus.nf3 run --seeds 5      # experimento -> results/nf3/
"""
import os

for _v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_v, "1")

import argparse
import json
import time
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = ROOT / "data" / "external"
PROFILE = ROOT / "results" / "nf3" / "profile.csv"
SUBSET = ROOT / "data" / "nf3_subset.pkl"
OUT = ROOT / "results" / "nf3"
CHUNK = 2_000_000
BLOCK = 600                              # s; mismo tamaño que la ventana w10

COLS = {  # columna NF3 -> esquema de safecampus.generator
    "FLOW_START_MILLISECONDS": "ts", "FLOW_DURATION_MILLISECONDS": "duration",
    "IPV4_SRC_ADDR": "src_ip", "IPV4_DST_ADDR": "dst_ip", "L4_SRC_PORT": "src_port", "L4_DST_PORT": "dst_port",
    "PROTOCOL": "proto", "IN_PKTS": "packets", "IN_BYTES": "bytes", "CLIENT_TCP_FLAGS": "tcp_flags",
    "Label": "label", "Attack": "attack",
}


def find_dataset():
    # El paquete de UQ viene en formato BagIt: el CSV queda en <bolsa>/data/
    files = sorted((p for p in EXTERNAL.rglob("*") if p.suffix.lower() in (".zip", ".csv", ".gz")
                    and "ton" in p.name.lower() and "features" not in p.name.lower()),
                   key=lambda p: -p.stat().st_size)
    if not files:
        raise SystemExit(f"No encontré el dataset en {EXTERNAL} (se espera un .zip/.csv con 'ToN' en el nombre)")
    return files[0]


def _reader(path, usecols):
    """Lee el CSV por bloques, directo del .zip si hace falta (sin descomprimir a disco)."""
    if path.suffix.lower() == ".zip":
        z = zipfile.ZipFile(path)
        csvs = [n for n in z.namelist() if n.lower().endswith(".csv")]
        if len(csvs) != 1:
            raise SystemExit(f"El zip contiene {len(csvs)} CSV: {csvs[:5]}")
        handle = z.open(csvs[0])
    else:
        handle = path
    return pd.read_csv(handle, usecols=usecols, chunksize=CHUNK, low_memory=False)


def _norm_attack(s):
    s = s.astype(str).str.strip().str.lower()
    return s.where(s != "benign", "normal")


def profile(path=None):
    path = Path(path) if path else find_dataset()
    t0 = time.perf_counter()
    parts, n = [], 0
    for ch in _reader(path, ["FLOW_START_MILLISECONDS", "Attack"]):
        ts = ch["FLOW_START_MILLISECONDS"].to_numpy() // 1000
        parts.append(pd.DataFrame({"block": ts // BLOCK, "attack": _norm_attack(ch["Attack"])})
                     .value_counts().rename("n").reset_index())
        n += len(ch)
        print(f"  {n:,} filas leídas ({time.perf_counter() - t0:.0f} s)", flush=True)
    p = pd.concat(parts).groupby(["block", "attack"], as_index=False)["n"].sum()
    p["date"] = pd.to_datetime(p["block"] * BLOCK, unit="s").dt.date.astype(str)
    days = sorted(p["date"].unique())
    p["day"] = p["date"].map({d: i + 1 for i, d in enumerate(days)})
    PROFILE.parent.mkdir(parents=True, exist_ok=True)
    p.to_csv(PROFILE, index=False)
    print(f"\nPerfil guardado en {PROFILE} ({n:,} flujos, {time.perf_counter() - t0:.0f} s)")
    print(p.pivot_table(index=["day", "date"], columns="attack", values="n", aggfunc="sum", fill_value=0)
          .to_string())


def plan_blocks(p, benign_cap, cal_cap, attack_cap, n_seen, cal_hours=12, seed=0):
    """Elige bloques de 10 min por partición (fit/cal/test). Devuelve ({block: split}, cortes)."""
    rng = np.random.default_rng(seed)
    starts = p[p["attack"] != "normal"].groupby("attack")["block"].min().sort_values()
    if len(starts) <= n_seen:
        raise SystemExit(f"Solo hay {len(starts)} tipos de ataque; n_seen={n_seen} no deja ninguno para prueba")
    test_from = int(starts.iloc[n_seen])
    cal_from = test_from - cal_hours * 3600 // BLOCK
    period = np.select([p["block"] >= test_from, p["block"] >= cal_from], ["test", "cal"], "fit")
    benign = p[p["attack"] == "normal"].groupby("block")["n"].sum()
    chosen = {}

    def take(blocks, cap, counts, split):
        acc = 0
        for b in rng.permutation(blocks):
            if acc >= cap:
                break
            if b not in chosen:
                chosen[b] = split
                acc += counts.get(b, 0)

    for split in ("fit", "test"):      # primero cubrir cada ataque, luego completar benignos
        q = p[(period == split) & (p["attack"] != "normal")]
        for _, g in q.groupby("attack"):
            take(g["block"].unique(), attack_cap, g.set_index("block")["n"], split)
    for split, cap in (("fit", benign_cap), ("cal", cal_cap), ("test", benign_cap // 2)):
        already = sum(benign.get(b, 0) for b, s in chosen.items() if s == split)
        take(p.loc[period == split, "block"].unique(), cap - already, benign, split)

    when = lambda b: pd.to_datetime(b * BLOCK, unit="s")
    cuts = {"cal_from": str(when(cal_from)), "test_from": str(when(test_from)),
            "seen": list(starts.index[:n_seen]), "unseen": list(starts.index[n_seen:])}
    print(f"fit < {cuts['cal_from']} <= cal < {cuts['test_from']} <= test (UTC)")
    print(f"Ataques vistos por supervisados: {cuts['seen']} | nuevos en prueba: {cuts['unseen']}")
    return chosen, cuts


def build(benign_cap=400_000, cal_cap=200_000, attack_cap=60_000, n_seen=4, path=None):
    path = Path(path) if path else find_dataset()
    p = pd.read_csv(PROFILE)
    chosen, cuts = plan_blocks(p, benign_cap, cal_cap, attack_cap, n_seen)
    blocks = np.fromiter(chosen.keys(), dtype=np.int64)
    t0, parts, n = time.perf_counter(), [], 0
    for ch in _reader(path, list(COLS)):
        ts = ch["FLOW_START_MILLISECONDS"].to_numpy() // 1000
        m = np.isin(ts // BLOCK, blocks)
        n += len(ch)
        if m.any():
            parts.append(ch[m])
        print(f"  {n:,} filas leídas, {sum(len(x) for x in parts):,} seleccionadas "
              f"({time.perf_counter() - t0:.0f} s)", flush=True)
    df = pd.concat(parts, ignore_index=True).rename(columns=COLS)
    df["ts"] = df["ts"] / 1000.0
    df["duration"] = df["duration"] / 1000.0
    df["attack"] = _norm_attack(df["attack"])
    df["label"] = (df["attack"] != "normal").astype(int)
    for c in ("src_port", "dst_port", "proto", "packets", "bytes", "tcp_flags"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(np.int64)
    df["packets"] = df["packets"].clip(lower=1)
    df["src_ip"] = df["src_ip"].astype(str)
    df["dst_ip"] = df["dst_ip"].astype(str)
    df["split"] = (df["ts"] // BLOCK).astype(np.int64).map(chosen)
    df = df.sort_values("ts", kind="stable").reset_index(drop=True)
    df.to_pickle(SUBSET)
    cuts["flows_per_split"] = {k: int(v) for k, v in df["split"].value_counts().items()}
    SUBSET.with_suffix(".json").write_text(json.dumps(cuts, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSubconjunto: {len(df):,} flujos -> {SUBSET}")
    print(df.groupby(["split", "attack"]).size().unstack(fill_value=0).to_string())


def _cap(mask, n, rng, strata=None):
    """Submuestrea hasta n filas de mask (estratificado por strata si se da)."""
    idx = np.flatnonzero(mask)
    if len(idx) <= n:
        return mask
    if strata is None:
        keep = rng.choice(idx, n, replace=False)
    else:
        keep = np.concatenate([rng.choice(g, max(1, round(n * len(g) / len(idx))), replace=False)
                               for g in (idx[strata[idx] == s] for s in np.unique(strata[idx]))])
    out = np.zeros_like(mask)
    out[keep] = True
    return out


def run(seeds=5, train_cap=300_000, cal_cap=200_000):
    """Las características se calculan sobre los bloques completos (ventanas exactas);
    después se submuestrean solo las filas de entrenamiento y calibración."""
    from .experiment import evaluate, save_all
    from .features import RFC1918, NetContext, extract

    df = pd.read_pickle(SUBSET)
    # Sin hora del día: en ToN-IoT cada ataque se lanzó en un horario fijo y el
    # árbol la usaba como atajo (AUC 0.07 con hora vs 0.90 sin hora en la semilla 0).
    ctx = NetContext(internal_prefixes=RFC1918, use_hour=False)
    t0 = time.perf_counter()
    X = extract(df, ctx)
    feat_us = (time.perf_counter() - t0) / len(df) * 1e6
    split = df["split"].to_numpy()
    y = df["label"].to_numpy()
    masks = {"unsup": (split == "fit") & (y == 0), "cal": (split == "cal") & (y == 0),
             "sup": split == "fit", "test": split == "test"}
    seen = set(df.loc[split == "fit", "attack"]) - {"normal"}
    unseen = sorted(set(df.loc[split == "test", "attack"]) - seen - {"normal"})
    print(f"Ataques de prueba no vistos por los supervisados: {unseen}")
    attack = df["attack"].to_numpy()
    rows, pa = [], []
    for seed in range(seeds):
        print(f"Semilla {seed}")
        rng = np.random.default_rng(seed)
        m = {"unsup": _cap(masks["unsup"], train_cap, rng), "cal": _cap(masks["cal"], cal_cap, rng),
             "sup": _cap(masks["sup"], train_cap, rng, attack), "test": masks["test"]}
        r, a = evaluate(df, X, m, seed, feat_us)
        rows += r
        pa += a
    save_all(rows, pa, OUT, f"no vistos por supervisados: {', '.join(unseen) or 'ninguno'}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Validación con NF-ToN-IoT-v3")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("profile").add_argument("--path")
    b = sub.add_parser("build")
    b.add_argument("--path")
    b.add_argument("--benign-cap", type=int, default=400_000)
    b.add_argument("--cal-cap", type=int, default=200_000)
    b.add_argument("--attack-cap", type=int, default=60_000)
    b.add_argument("--seen", type=int, default=4, help="tipos de ataque (en orden cronológico) que ven los supervisados")
    r = sub.add_parser("run")
    r.add_argument("--seeds", type=int, default=5)
    r.add_argument("--train-cap", type=int, default=300_000)
    a = ap.parse_args()
    if a.cmd == "profile":
        profile(a.path)
    elif a.cmd == "build":
        build(a.benign_cap, a.cal_cap, a.attack_cap, a.seen, a.path)
    else:
        run(a.seeds, a.train_cap)
