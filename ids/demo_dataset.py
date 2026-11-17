"""Demo en vivo: el IDS con el dataset real NF-ToN-IoT-v3.

Entrena el bosque ligero con el pasado (scanning, dos, injection, ddos) y lo prueba
con el futuro, donde los 5 ataques son nuevos. Reproduce la semilla 0 de
`python -m safecampus.nf3 run` (misma partición y mismo submuestreo).

Uso:
  python demo_dataset.py            # bosque ligero (~1 min)
  python demo_dataset.py --pesado   # también el Random Forest de 300 árboles (+2 min)
"""
import os

for _v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_v, "1")

import argparse
import pickle
import time

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score

from safecampus import models
from safecampus.features import RFC1918, NetContext, extract
from safecampus.nf3 import SUBSET, _cap


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--pesado", action="store_true", help="comparar también con el Random Forest de 300 árboles")
    args = ap.parse_args()

    t0 = time.perf_counter()
    df = pd.read_pickle(SUBSET)
    split, y, attack = df["split"].to_numpy(), df["label"].to_numpy(), df["attack"].to_numpy()
    print(f"Subconjunto de NF-ToN-IoT-v3: {len(df):,} flujos ({time.perf_counter() - t0:.0f} s)")
    print(df.groupby(["split", "attack"]).size().unstack(0, fill_value=0).to_string(), "\n")

    t0 = time.perf_counter()
    X = extract(df, NetContext(internal_prefixes=RFC1918, use_hour=False))
    print(f"{X.shape[1]} características calculadas ({time.perf_counter() - t0:.0f} s)")

    # mismo orden de submuestreo que nf3.run para la semilla 0
    rng = np.random.default_rng(0)
    _cap((split == "fit") & (y == 0), 300_000, rng)
    _cap((split == "cal") & (y == 0), 200_000, rng)
    sup = _cap(split == "fit", 300_000, rng, attack)
    test = split == "test"
    print(f"Entrenamiento: {sup.sum():,} flujos · Prueba: {test.sum():,} flujos "
          f"(ataques nuevos: {', '.join(sorted(set(attack[test]) - {'normal'}))})\n")

    chosen = [models.LightForest] + ([models.BigForest] if args.pesado else [])
    for cls in chosen:
        det = cls(seed=0)
        t0 = time.perf_counter()
        det.fit(X[sup], y[sup])
        train_s = time.perf_counter() - t0
        t0 = time.process_time()
        p = det.predict(X[test])
        us = (time.process_time() - t0) / test.sum() * 1e6
        yt, at = y[test], attack[test]
        print(f"== {det.name} ==")
        print(f"  F1 {f1_score(yt, p):.3f} · precisión {precision_score(yt, p):.3f} · recall {recall_score(yt, p):.3f} "
              f"· falsas alarmas {p[yt == 0].mean():.2%}")
        print(f"  tamaño {len(pickle.dumps(det)) / 2**20:.1f} MB · {us:.2f} µs de CPU por flujo · entrenó en {train_s:.0f} s")
        for a in sorted(set(at) - {"normal"}):
            print(f"  recall {a:<11} {p[at == a].mean():.2f}")
        print()


if __name__ == "__main__":
    main()
