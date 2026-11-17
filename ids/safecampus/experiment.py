"""Experimento principal: precisión vs. recursos de detectores ligeros y pesados.

Protocolo (por semilla): día 0 = entrenamiento no supervisado (solo normal),
día 1 = calibración de umbrales (FPR objetivo), días 0+2 = entrenamiento
supervisado, día 3 = prueba común (incluye 'exfil', ausente en entrenamiento).

Uso:  python -m safecampus.experiment --seeds 3
"""
import os

# Un solo hilo para BLAS/OpenMP: medición conservadora y comparable con un gateway edge.
for _v in ("OMP_NUM_THREADS", "OPENBLAS_NUM_THREADS", "MKL_NUM_THREADS"):
    os.environ.setdefault(_v, "1")

import argparse
import pickle
import time
import tracemalloc
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score, roc_auc_score

from . import models
from .features import extract
from .generator import ScenarioConfig, generate
from .inventory import load_inventory

RESULTS = Path(__file__).resolve().parents[1] / "results"
# Supuesto para la energía aproximada: potencia de CPU de un gateway tipo Raspberry Pi 4 bajo carga.
EDGE_CPU_WATTS = 5.0


def resources(det, X_test):
    # process_time en Windows tiene resolución de ~15 ms: repetir hasta acumular >= 1 s
    reps, t0, c0 = 0, time.perf_counter(), time.process_time()
    while reps == 0 or time.perf_counter() - t0 < 1.0:
        det.score(X_test)
        reps += 1
    wall, cpu = time.perf_counter() - t0, time.process_time() - c0
    n = len(X_test) * reps

    rows = X_test.sample(200, random_state=0)
    lat = []
    for i in range(len(rows)):
        x = rows.iloc[[i]]
        t = time.perf_counter()
        det.predict(x)
        lat.append((time.perf_counter() - t) * 1000)

    tracemalloc.start()
    det.score(X_test.iloc[:10_000])
    peak = tracemalloc.get_traced_memory()[1]
    tracemalloc.stop()

    return {
        "throughput_flows_s": n / wall,
        "cpu_us_per_flow": cpu / n * 1e6,
        "latency_p50_ms": float(np.percentile(lat, 50)),
        "latency_p95_ms": float(np.percentile(lat, 95)),
        "peak_ram_mb_10k": peak / 2**20,
        "model_kb": len(pickle.dumps(det)) / 1024,
        "energy_uj_per_flow": cpu / n * EDGE_CPU_WATTS * 1e6,
    }


def operational(df_test, p):
    """Métricas a nivel de host: lo que le importa al técnico del laboratorio.

    - fpr_clean_hosts: falsas alarmas sobre flujos de hosts que no atacaron ese día
      (los flujos normales de un host comprometido comparten ventana con el ataque).
    - host-ventana (10 min): positivo real si el host emitió algún flujo malicioso.
    - ttd: minutos desde el inicio de cada ataque hasta la primera alerta sobre sus hosts.
    """
    y = df_test["label"].to_numpy()
    src = df_test["src_ip"].to_numpy()
    bad_hosts = set(src[y == 1])
    clean = ~np.isin(src, list(bad_hosts))
    fpr_clean = float(p[clean & (y == 0)].mean()) if (clean & (y == 0)).any() else 0.0
    # macro por host: cada host limpio pesa igual (un host muy ruidoso no domina la métrica)
    ben = clean & (y == 0)
    fpr_host_macro = float(pd.Series(p[ben]).groupby(src[ben]).mean().mean()) if ben.any() else 0.0

    key = pd.DataFrame({"src": src, "w": (df_test["ts"].to_numpy() // 600).astype(int), "y": y, "p": p})
    hw = key.groupby(["src", "w"]).agg(y=("y", "max"), p=("p", "max"))
    ttd = {}
    ts = df_test["ts"].to_numpy()
    for a in sorted(set(df_test["attack"]) - {"normal"}):
        m = (df_test["attack"] == a).to_numpy()
        start, end = ts[m].min(), ts[m].max()
        hosts = set(src[m])
        hit = np.isin(src, list(hosts)) & (p == 1) & (ts >= start) & (ts <= end + 600)
        ttd[a] = (ts[hit].min() - start) / 60 if hit.any() else np.nan
    return {
        "fpr_clean_hosts": fpr_clean,
        "fpr_host_macro": fpr_host_macro,
        "host_precision": precision_score(hw["y"], hw["p"], zero_division=0),
        "host_recall": recall_score(hw["y"], hw["p"]),
        "host_f1": f1_score(hw["y"], hw["p"]),
    }, ttd


def run_seed(seed, inv):
    df = generate(ScenarioConfig(seed=seed), inv)
    t0 = time.perf_counter()
    X = extract(df, inv)
    feat_us = (time.perf_counter() - t0) / len(df) * 1e6
    day, y = df["day"].to_numpy(), df["label"].to_numpy()
    masks = {"unsup": day == 0, "cal": (day == 1) & (y == 0), "sup": (day == 0) | (day == 2), "test": day == 3}
    return evaluate(df, X, masks, seed, feat_us)


def evaluate(df, X, masks, seed, feat_us):
    """Entrena, calibra y evalúa todos los detectores sobre las particiones dadas.

    masks: arreglos booleanos 'unsup' (normal para no supervisados), 'cal' (normal
    para calibrar), 'sup' (entrenamiento supervisado) y 'test'.
    """
    y, attack = df["label"].to_numpy(), df["attack"].to_numpy()
    X_unsup, X_cal = X[masks["unsup"]], X[masks["cal"]]
    X_sup, y_sup = X[masks["sup"]], y[masks["sup"]]
    test = masks["test"]
    X_test, y_test, a_test = X[test], y[test], attack[test]
    df_test = df[test]
    test_hours = max((df_test["ts"].max() - df_test["ts"].min()) / 3600, 1e-9)

    rows, per_attack = [], []
    for cls in models.ALL:
        det = models.build(cls, seed)
        t = time.perf_counter()
        det.fit(X_sup, y_sup) if det.supervised else det.fit(X_unsup)
        train_s = time.perf_counter() - t
        det.calibrate(X_cal)

        s = det.score(X_test)
        p = (s > det.threshold).astype(np.int8)
        fp = int(((p == 1) & (y_test == 0)).sum())
        ops, ttd = operational(df_test, p)
        rows.append({
            "seed": seed, "model": det.name, "family": det.family,
            "type": "supervisado" if det.supervised else "no supervisado",
            "precision": precision_score(y_test, p, zero_division=0),
            "recall": recall_score(y_test, p),
            "f1": f1_score(y_test, p),
            "fpr": fp / max((y_test == 0).sum(), 1),
            "roc_auc": roc_auc_score(y_test, s),
            "alerts_fp_per_hour": fp / test_hours,
            **ops,
            "ttd_median_min": float(np.nanmedian(list(ttd.values()))) if any(np.isfinite(list(ttd.values()))) else np.nan,
            "attacks_detected": int(np.isfinite(list(ttd.values())).sum()),
            "train_s": train_s,
            "feature_us_per_flow": feat_us,
            **resources(det, X_test),
        })
        for a in sorted(set(a_test) - {"normal"}):
            m = a_test == a
            per_attack.append({"seed": seed, "model": det.name, "attack": a, "recall": p[m].mean(),
                               "ttd_min": ttd[a], "n": int(m.sum())})
        print(f"  [{seed}] {det.name:<40} F1={rows[-1]['f1']:.3f} FPRlimpio={rows[-1]['fpr_clean_hosts']:.4f} "
              f"hostF1={rows[-1]['host_f1']:.3f} "
              f"p50={rows[-1]['latency_p50_ms']:.2f} ms  {rows[-1]['model_kb']:.0f} KB")
    return rows, per_attack


def summarize(m, pa):
    num = [c for c in m.columns if c not in ("seed", "model", "family", "type")]
    g = m.groupby(["model", "family", "type"], sort=False)[num]
    summary = g.mean().join(g.std().add_suffix("_std")).reset_index()
    order = [c.name for c in models.ALL]
    summary["model"] = pd.Categorical(summary["model"], order, ordered=True)
    summary = summary.sort_values("model")
    attack_table = pa.groupby(["model", "attack"])["recall"].mean().unstack().reindex(order)
    return summary, attack_table


def figures(summary, attack_table, out=RESULTS, unseen_note="'exfil' no visto en entrenamiento"):
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    colors = {"ligero": "#2a7fbf", "pesado": "#d1495b"}
    fig, ax = plt.subplots(figsize=(12.5, 5.4))
    legend_rows = []
    for k, (_, r) in enumerate(summary.iterrows(), start=1):
        size = 40 + 45 * np.log10(r["model_kb"] + 1)        # log: el RF de >100 MB no tapa al resto
        ax.errorbar(r["cpu_us_per_flow"], r["f1"], yerr=r["f1_std"], color="#555", capsize=3, lw=.8, zorder=1)
        ax.scatter(r["cpu_us_per_flow"], r["f1"], s=size, color=colors[r["family"]], alpha=.85,
                   edgecolor="black", linewidth=.6, zorder=2)
        ax.annotate(str(k), (r["cpu_us_per_flow"], r["f1"]), ha="center", va="center", fontsize=8,
                    fontweight="bold", color="white", zorder=3)
        kb = r["model_kb"]
        legend_rows.append(f"{k}. {r['model']:<38} F1 {r['f1']:.2f}  {kb / 1024:6.1f} MB" if kb >= 1024
                           else f"{k}. {r['model']:<38} F1 {r['f1']:.2f}  {kb:6.1f} KB")
    fig.text(0.585, 0.5, "\n".join(legend_rows), va="center", fontsize=8.5, family="monospace")
    ax.set_xscale("log")
    ax.set_xlabel("Costo de inferencia (µs de CPU por flujo, escala log)")
    ax.set_ylabel("F1 en la partición de prueba")
    ax.set_title("Precisión vs. costo (tamaño del punto ∝ log del tamaño del modelo)")
    for fam, c in colors.items():
        ax.scatter([], [], color=c, label=fam.capitalize())
    ax.legend(loc="lower left")
    ax.grid(alpha=.3)
    fig.subplots_adjust(left=.07, right=.57, top=.92, bottom=.11)
    fig.savefig(out / "fig_tradeoff.png", dpi=160)

    fig, ax = plt.subplots(figsize=(max(8.5, 1.3 * attack_table.shape[1] + 4), 4))
    im = ax.imshow(attack_table.to_numpy(), cmap="Blues", vmin=0, vmax=1, aspect="auto")
    ax.set_xticks(range(attack_table.shape[1]), attack_table.columns, rotation=20)
    ax.set_yticks(range(attack_table.shape[0]), attack_table.index)
    for i in range(attack_table.shape[0]):
        for j in range(attack_table.shape[1]):
            v = attack_table.iat[i, j]
            ax.text(j, i, f"{v:.2f}", ha="center", va="center", fontsize=8.5, color="white" if v > .6 else "black")
    ax.set_title(f"Recall por tipo de ataque (prueba; {unseen_note})")
    fig.colorbar(im, ax=ax, fraction=.025)
    fig.tight_layout()
    fig.savefig(out / "fig_per_attack.png", dpi=160)


def save_all(rows, pa, out=RESULTS, unseen_note="'exfil' no visto en entrenamiento"):
    out.mkdir(parents=True, exist_ok=True)
    m, pa = pd.DataFrame(rows), pd.DataFrame(pa)
    m.to_csv(out / "metrics_per_seed.csv", index=False)
    pa.to_csv(out / "per_attack_per_seed.csv", index=False)
    summary, attack_table = summarize(m, pa)
    summary.to_csv(out / "summary.csv", index=False)
    attack_table.to_csv(out / "per_attack_recall.csv")
    ttd_table = pa.groupby(["model", "attack"])["ttd_min"].median().unstack().reindex(attack_table.index)
    ttd_table.to_csv(out / "per_attack_ttd_min.csv")
    figures(summary, attack_table, out, unseen_note)
    cols = ["model", "f1", "f1_std", "recall", "fpr", "fpr_clean_hosts", "fpr_host_macro", "roc_auc", "host_f1",
            "ttd_median_min",
            "attacks_detected", "cpu_us_per_flow", "latency_p50_ms", "peak_ram_mb_10k", "model_kb",
            "energy_uj_per_flow", "train_s"]
    with pd.option_context("display.width", 250, "display.max_columns", 30, "display.float_format", "{:.4g}".format):
        print(summary[cols].to_string(index=False))
        print(attack_table.round(3).to_string())
        print("Tiempo hasta detección (min):")
        print(ttd_table.round(1).to_string())


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=3)
    args = ap.parse_args()
    inv = load_inventory()
    rows, pa = [], []
    for seed in range(args.seeds):
        print(f"Semilla {seed}")
        r, a = run_seed(seed, inv)
        rows += r
        pa += a
    save_all(rows, pa)


if __name__ == "__main__":
    main()
