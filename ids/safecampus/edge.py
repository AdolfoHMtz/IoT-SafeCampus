"""Prototipo del gateway edge de IoT-SafeCampus.

Arquitectura (sección 9 del proyecto):
  dispositivos IoT -> gateway edge -> extractor de flujos -> modelo ligero ->
  alertas -> reglas de aislamiento -> tablero docente/técnico

El gateway procesa los registros NetFlow por minuto (así llegan del exportador
con timeout activo de 60 s), mantiene 10 min de historia para las ventanas,
agrega las detecciones por host para no alertar por flujos aislados, y cuando
un host persiste genera los comandos IOS para moverlo a la VLAN 99.

Uso:
  python -m safecampus.edge train --model zscore
  python -m safecampus.edge run   --day 3
"""
import argparse
import json
import pickle
import time
from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from html import escape
from pathlib import Path

import numpy as np
import pandas as pd

from . import models
from .features import extract
from .generator import DAY, ScenarioConfig, generate
from .inventory import C2_SERVER, DASHBOARD, MQTT_BROKER, load_inventory

ROOT = Path(__file__).resolve().parents[1]
MODEL_PATH = ROOT / "models" / "edge_model.pkl"
OUT = ROOT / "results" / "edge"
CHOICES = {"zscore": models.ProfileZScore, "autoencoder": models.TinyAutoencoder,
           "tree": models.SmallTree, "iforest": models.IForest, "hybrid": models.HybridTreeAE}

MIN_FLAGGED = 3           # flujos marcados por host en un minuto para levantar alerta
QUARANTINE_AFTER = 2      # minutos consecutivos con alerta para proponer aislamiento


@dataclass
class Alert:
    ts: float
    host: str
    ip: str
    category: str
    flagged: int
    total: int
    severity: str
    evidence: dict = field(default_factory=dict)


def categorize(flows):
    """Explicación legible para el tablero a partir de los flujos marcados."""
    syn = ((flows["tcp_flags"] & 2) > 0) & ((flows["tcp_flags"] & 16) == 0)
    ext = ~flows["dst_ip"].str.startswith("10.10.")
    hour = (flows["ts"].iloc[0] % DAY) / 3600
    if flows.loc[ext, "bytes"].sum() > 5e6 and (hour < 6 or hour > 22):
        return "Posible exfiltración de datos (volumen nocturno)"
    if (flows["dst_port"].isin([23, 2323]) & syn).mean() > .5:
        return "Escaneo telnet tipo Mirai (posible bot)"
    if syn.mean() > .5 and flows["dst_ip"].nunique() > 5:
        return "Escaneo de red/puertos"
    if (flows["dst_ip"] == C2_SERVER).any() or (ext & ~flows["dst_port"].isin([80, 443])).mean() > .5:
        return "Posible canal de mando y control (C2)"
    if (flows["dst_ip"] == MQTT_BROKER).mean() > .5:
        return "Inundación o fuerza bruta contra el broker MQTT"
    if (flows["dst_ip"] == DASHBOARD).mean() > .5:
        return "Saturación HTTP del dashboard (DoS)"
    if (flows["dst_port"] == 23).any():
        return "Intentos de acceso telnet (credenciales débiles)"
    return "Comportamiento anómalo respecto a su perfil"


def isolation_commands(dev, qip):
    """Comandos IOS para mover el dispositivo a la VLAN de cuarentena (99).

    qip sale de un pool secuencial: reutilizar el último octeto colisiona entre
    VLANs (p. ej. 10.10.20.12 y 10.10.40.12 acabarían ambos en 10.10.99.12).
    """
    return [
        f"! {dev.name} ({dev.ip}) -> cuarentena",
        f"{dev.switch}# configure terminal",
        f"{dev.switch}(config)# interface {dev.port}",
        f"{dev.switch}(config-if)# switchport access vlan 99",
        f"{dev.switch}(config-if)# end",
        f"! Reasignar en el host: IP {qip}/24, gateway 10.10.99.1 (ACL 199 solo permite hacia gestión/IDS)",
    ]


class EdgeGateway:
    def __init__(self, detector, inventory):
        self.det = detector
        self.inv = inventory
        self.by_ip = {d.ip: d for d in inventory.values()}
        self.history = deque()          # flujos de los últimos 10 min (para ventanas w10)
        self.streak = defaultdict(int)  # minutos consecutivos con alerta por host
        self.quarantined = {}
        self.next_qip = 100     # pool de cuarentena: 10.10.99.100-254
        self.alerts = []
        self.minute_ms = []

    def process_minute(self, flows):
        t = time.perf_counter()
        self.history.append(flows)
        while len(self.history) > 10:
            self.history.popleft()
        buf = pd.concat(self.history, ignore_index=True)
        X = extract(buf, self.inv).iloc[len(buf) - len(flows):]
        flagged = self.det.predict(X).astype(bool)
        flows = flows.assign(flag=flagged)

        hosts_alerted = set()
        for ip, g in flows.groupby("src_ip"):
            dev = self.by_ip.get(ip)
            if dev is None or ip in self.quarantined:      # externos o ya aislados
                continue
            k = int(g["flag"].sum())
            if k < MIN_FLAGGED:
                continue
            hosts_alerted.add(ip)
            self.streak[ip] += 1
            sev = "alta" if k >= 50 or self.streak[ip] >= QUARANTINE_AFTER else "media"
            bad = g[g["flag"]]
            self.alerts.append(Alert(float(g["ts"].max()), dev.name, ip, categorize(bad), k, len(g), sev, {
                "destinos_unicos": int(bad["dst_ip"].nunique()),
                "puertos_destino": sorted(map(int, bad["dst_port"].unique()))[:6],
                "bytes": int(bad["bytes"].sum()),
            }))
            if self.streak[ip] >= QUARANTINE_AFTER and dev.switch and self.next_qip <= 254:
                qip = f"10.10.99.{self.next_qip}"
                self.next_qip += 1
                self.quarantined[ip] = {"ts": float(g["ts"].max()), "host": dev.name, "ip_cuarentena": qip,
                                        "motivo": self.alerts[-1].category,
                                        "comandos": isolation_commands(dev, qip)}
        for ip in list(self.streak):
            if ip not in hosts_alerted:
                self.streak[ip] = 0
        self.minute_ms.append((time.perf_counter() - t) * 1000)


def train(model_key, seed=0):
    inv = load_inventory()
    df = generate(ScenarioConfig(seed=seed), inv)
    X = extract(df, inv)
    day, y = df["day"].to_numpy(), df["label"].to_numpy()
    det = models.build(CHOICES[model_key], seed)
    if det.supervised:
        m = (day == 0) | (day == 2)
        det.fit(X[m], y[m])
    else:
        det.fit(X[day == 0])
    det.calibrate(X[(day == 1) & (y == 0)])
    MODEL_PATH.parent.mkdir(exist_ok=True)
    MODEL_PATH.write_bytes(pickle.dumps(det))
    print(f"Modelo '{det.name}' guardado en {MODEL_PATH} ({MODEL_PATH.stat().st_size / 1024:.1f} KB)")


def run(day=3, seed=0):
    import psutil

    inv = load_inventory()
    det = pickle.loads(MODEL_PATH.read_bytes())
    df = generate(ScenarioConfig(seed=seed + 100), inv)   # semilla distinta a la del entrenamiento
    df = df[df["day"] == day]
    gw = EdgeGateway(det, inv)
    proc = psutil.Process()
    rss0 = proc.memory_info().rss
    for _, flows in df.groupby((df["ts"] // 60).astype(int), sort=True):
        gw.process_minute(flows.drop(columns=["label", "attack", "day"]))
    rss = proc.memory_info().rss

    OUT.mkdir(parents=True, exist_ok=True)
    with open(OUT / "alerts.jsonl", "w", encoding="utf-8") as f:
        for a in gw.alerts:
            f.write(json.dumps(asdict(a), ensure_ascii=False) + "\n")
    with open(OUT / "isolation_commands.txt", "w", encoding="utf-8") as f:
        for q in gw.quarantined.values():
            f.write("\n".join(q["comandos"]) + "\n\n")

    truth = df.groupby("src_ip")["label"].max()
    bad = set(truth[truth == 1].index) & set(gw.by_ip)
    alerted = {a.ip for a in gw.alerts}
    stats = {
        "modelo": det.name,
        "flujos": len(df),
        "minutos": len(gw.minute_ms),
        "ms_por_minuto_p50": float(np.percentile(gw.minute_ms, 50)),
        "ms_por_minuto_p95": float(np.percentile(gw.minute_ms, 95)),
        "rss_mb": rss / 2**20,
        "rss_incremento_mb": (rss - rss0) / 2**20,
        "alertas": len(gw.alerts),
        "hosts_comprometidos": sorted(gw.by_ip[i].name for i in bad),
        "hosts_alertados": sorted(gw.by_ip[i].name for i in alerted),
        "hosts_aislados": sorted(q["host"] for q in gw.quarantined.values()),
        "falsos_aislamientos": sorted(q["host"] for ip, q in gw.quarantined.items() if ip not in bad),
    }
    (OUT / "edge_stats.json").write_text(json.dumps(stats, indent=2, ensure_ascii=False), encoding="utf-8")
    dashboard(gw, stats, day)
    print(json.dumps(stats, indent=2, ensure_ascii=False))


def dashboard(gw, stats, day):
    """Tablero estático para el docente/técnico (results/edge/dashboard.html)."""
    def hhmm(ts):
        s = int(ts % DAY)
        return f"{s // 3600:02d}:{s % 3600 // 60:02d}"

    by_host = defaultdict(list)
    for a in gw.alerts:
        by_host[a.host].append(a)
    rows = []
    for host, al in sorted(by_host.items(), key=lambda kv: -len(kv[1])):
        q = next((q for q in gw.quarantined.values() if q["host"] == host), None)
        estado = f'<span class="tag q">En cuarentena desde {hhmm(q["ts"])}</span>' if q else '<span class="tag w">Vigilado</span>'
        cats = sorted({a.category for a in al})
        rows.append(f"<tr><td><b>{escape(host)}</b><br><small>{al[0].ip}</small></td><td>{estado}</td>"
                    f"<td>{len(al)}</td><td>{hhmm(al[0].ts)} – {hhmm(al[-1].ts)}</td>"
                    f"<td>{'<br>'.join(escape(c) for c in cats)}</td></tr>")
    cmds = "\n\n".join("\n".join(q["comandos"]) for q in gw.quarantined.values()) or "Sin aislamientos."
    recent = "".join(f"<li><b>{hhmm(a.ts)}</b> · {escape(a.host)} · {escape(a.category)} "
                     f"<small>({a.flagged}/{a.total} flujos, severidad {a.severity})</small></li>"
                     for a in gw.alerts[-25:][::-1])
    html = f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>IoT-SafeCampus · Tablero</title>
<style>
:root{{--bg:#f6f7f9;--card:#fff;--ink:#1f2328;--mut:#5b6470;--line:#e3e6ea;--acc:#2a7fbf;--bad:#c0392b;--warn:#b7791f}}
@media (prefers-color-scheme:dark){{:root{{--bg:#14171b;--card:#1d2127;--ink:#e8eaed;--mut:#9aa3ad;--line:#2c323a}}}}
body{{margin:0;background:var(--bg);color:var(--ink);font:15px/1.5 system-ui,Segoe UI,sans-serif}}
main{{max-width:1100px;margin:0 auto;padding:24px 16px}}
h1{{margin:0 0 4px;font-size:24px}} .mut{{color:var(--mut)}}
.kpis{{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:12px;margin:20px 0}}
.k{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:14px}}
.k b{{display:block;font-size:26px}} section{{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:16px;margin:14px 0;overflow-x:auto}}
table{{border-collapse:collapse;width:100%}} td,th{{border-bottom:1px solid var(--line);padding:8px;text-align:left;vertical-align:top}}
.tag{{border-radius:99px;padding:2px 10px;font-size:13px;white-space:nowrap}} .q{{background:#c0392b22;color:var(--bad)}} .w{{background:#b7791f22;color:var(--warn)}}
pre{{background:#0f1318;color:#d7e3ee;border-radius:8px;padding:12px;overflow-x:auto;font-size:13px}} ul{{padding-left:18px}}
</style></head><body><main>
<h1>IoT-SafeCampus · Tablero del gateway edge</h1>
<div class="mut">Día simulado {day} · modelo: {escape(stats['modelo'])} · {stats['flujos']:,} flujos analizados</div>
<div class="kpis">
<div class="k"><b>{stats['alertas']}</b><span class="mut">alertas por host</span></div>
<div class="k"><b>{len(stats['hosts_aislados'])}</b><span class="mut">hosts en cuarentena</span></div>
<div class="k"><b>{len(stats['falsos_aislamientos'])}</b><span class="mut">aislamientos erróneos</span></div>
<div class="k"><b>{stats['ms_por_minuto_p95']:.0f} ms</b><span class="mut">p95 de proceso por minuto</span></div>
<div class="k"><b>{stats['rss_mb']:.0f} MB</b><span class="mut">memoria del proceso</span></div>
</div>
<section><h2>Hosts con alertas</h2><table><tr><th>Host</th><th>Estado</th><th>Alertas</th><th>Ventana</th><th>Diagnóstico</th></tr>
{''.join(rows) or '<tr><td colspan=5>Sin alertas</td></tr>'}</table></section>
<section><h2>Últimas alertas</h2><ul>{recent}</ul></section>
<section><h2>Reglas de aislamiento propuestas</h2><pre>{escape(cmds)}</pre></section>
</main></body></html>"""
    (OUT / "dashboard.html").write_text(html, encoding="utf-8")


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="Gateway edge de IoT-SafeCampus")
    sub = ap.add_subparsers(dest="cmd", required=True)
    t = sub.add_parser("train")
    t.add_argument("--model", choices=sorted(CHOICES), default="zscore")
    r = sub.add_parser("run")
    r.add_argument("--day", type=int, default=3)
    a = ap.parse_args()
    train(a.model) if a.cmd == "train" else run(a.day)
