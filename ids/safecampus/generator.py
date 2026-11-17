"""Generador de flujos NetFlow sintéticos y etiquetados para IoT-SafeCampus.

Emula lo que exporta R-EDGE (flow monitor de entrada en las VLAN 10/20/30/40/99
y en el enlace a Internet): un registro por flujo con timeout activo de 60 s.
El tráfico de las VLAN 50/60 (servidores, gestión) no se monitorea, así que
solo aparecen sus efectos (p. ej., las respuestas ICMP de los IoT al admin).

Calendario por defecto (4 días): día 0 limpio (entrenar no supervisados),
día 1 limpio (calibrar umbrales), día 2 con ataques (entrenar supervisados),
día 3 con ataques variados + exfiltración nunca vista (prueba común).
"""
import zlib
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .inventory import C2_SERVER, DASHBOARD, INTERNET_WEB, MQTT_BROKER, by_role, load_inventory

DAY = 86400
FIN, SYN, RST, PSH, ACK = 1, 2, 4, 8, 16
TCP, UDP, ICMP = 6, 17, 1
ICMP_ECHO_REPLY = 0          # NetFlow codifica ICMP como dst_port = tipo*256 + código
ICMP_ECHO = 8 * 256

COLUMNS = ["ts", "duration", "src_ip", "dst_ip", "src_port", "dst_port", "proto",
           "packets", "bytes", "tcp_flags", "label", "attack"]


@dataclass
class ScenarioConfig:
    days: int = 4
    clean_days: tuple = (0, 1)
    seed: int = 7
    # ataques por día: nombre -> parámetros (los del día 3 difieren a propósito)
    attacks: dict = field(default_factory=lambda: {
        2: {
            "scan": dict(start=10.0, rate_s=40, minutes=3, slow=False),
            "mqtt_flood": dict(start=11.5, per_min=220, minutes=10),
            "http_ddos": dict(start=15.2, sources=["PC-ATACANTE", "PROTO-LAB1", "PROTO-LAB2"], per_min=300, minutes=5),
            "bruteforce": dict(start=18.0, every_s=2.0, minutes=30, telnet=False),
            "botnet": dict(start=8.0, devices=["SENS-A3"], beacon_s=300, scan_start=13.0, scan_minutes=20),
        },
        3: {
            "scan": dict(start=9.3, rate_s=1 / 3, minutes=60, slow=True),
            "mqtt_flood": dict(start=12.4, per_min=90, minutes=15),
            "http_ddos": dict(start=16.6, sources=["PC-ATACANTE", "PROTO-LAB2", "LAPTOP-EST"], per_min=180, minutes=6),
            "bruteforce": dict(start=19.1, every_s=4.0, minutes=40, telnet=True),
            "botnet": dict(start=6.5, devices=["CAM-A2", "SENS-A5"], beacon_s=420, scan_start=14.2, scan_minutes=12),
            "exfil": dict(start=2.0, device="CAM-A4", minutes=60),
        },
    })


class FlowBuffer:
    """Acumula columnas como arreglos para construir el DataFrame de una vez."""

    def __init__(self):
        self.parts = []

    def add(self, ts, src, dst, sport, dport, proto, pkts, nbytes, dur, flags, attack="normal"):
        ts = np.atleast_1d(np.asarray(ts, dtype=float))
        n = len(ts)
        if n == 0:
            return

        def col(v, dtype):
            a = np.asarray(v, dtype=dtype)
            return np.full(n, a, dtype=dtype) if a.ndim == 0 else a

        self.parts.append(pd.DataFrame({
            "ts": ts, "duration": col(dur, float), "src_ip": col(src, object), "dst_ip": col(dst, object),
            "src_port": col(sport, int), "dst_port": col(dport, int), "proto": col(proto, int),
            "packets": np.maximum(col(pkts, int), 1), "bytes": np.maximum(col(nbytes, int), 40),
            "tcp_flags": col(flags, int), "label": int(attack != "normal"), "attack": attack,
        }))

    def frame(self):
        df = pd.concat(self.parts, ignore_index=True)
        return df.sort_values("ts", kind="stable").reset_index(drop=True)[COLUMNS]


def activity(ts, kind="class"):
    """Intensidad 0..1 según la hora del día (horario de clases o de laboratorio)."""
    h = (np.asarray(ts) % DAY) / 3600
    if kind == "class":
        a = np.where((h >= 7) & (h < 21), 1.0, 0.04)
        a = np.where((h >= 14) & (h < 15), 0.5, a)            # comida
    else:  # laboratorio: dos bloques
        a = np.where(((h >= 9) & (h < 13)) | ((h >= 16) & (h < 20)), 1.0, 0.02)
    return a


def poisson_times(rng, t0, t1, rate_per_s, kind=None):
    """Llegadas de Poisson no homogéneas (thinning) en [t0, t1)."""
    n = rng.poisson(rate_per_s * (t1 - t0))
    t = np.sort(rng.uniform(t0, t1, n))
    if kind:
        t = t[rng.random(n) < activity(t, kind)]
    return t


def eph(rng, n):
    return rng.integers(49152, 65535, n)


# ------------------------------------------------------------------ normal
def normal_traffic(buf, rng, inv, t0, t1):
    sensors, cams = by_role(inv, "sensor"), by_role(inv, "camera")
    teachers, protos = by_role(inv, "teacher"), by_role(inv, "prototype")
    students = by_role(inv, "student")

    for d in sensors:
        # MQTT persistente: un registro por minuto (timeout activo), sport fijo
        t = np.arange(t0, t1, 60.0) + rng.uniform(0, 60)
        t = t[rng.random(len(t)) > 0.03]
        n = len(t)
        pk = rng.poisson(4, n) + 2
        buf.add(t, d.ip, MQTT_BROKER, 50000 + zlib.crc32(d.name.encode()) % 9000, 1883, TCP, pk,
                pk * rng.normal(92, 8, n), rng.uniform(50, 60, n), PSH | ACK)
        # re-registro HTTP con el dashboard cada ~10 min
        t = np.arange(t0, t1, 600.0) + rng.normal(0, 40, int(np.ceil((t1 - t0) / 600)))
        n = len(t)
        pk = rng.integers(8, 15, n)
        buf.add(t, d.ip, DASHBOARD, eph(rng, n), 80, TCP, pk, rng.integers(600, 1300, n),
                rng.uniform(0.1, 1.0, n), SYN | ACK | PSH | FIN)

    for d in cams:
        t = np.arange(t0, t1, 60.0) + rng.uniform(0, 60)
        n = len(t)
        pk = rng.poisson(6, n) + 2
        buf.add(t, d.ip, MQTT_BROKER, 50000 + zlib.crc32(d.name.encode()) % 9000, 1883, TCP, pk,
                pk * rng.normal(140, 15, n), rng.uniform(50, 60, n), PSH | ACK)
        # instantáneas/clips al dashboard: frecuentes en clase, escasas de noche
        t = poisson_times(rng, t0, t1, 1 / 70, "class")
        t = np.concatenate([t, poisson_times(rng, t0, t1, 1 / 900)])
        n = len(t)
        b = rng.lognormal(np.log(60_000), 0.6, n)
        buf.add(t, d.ip, DASHBOARD, eph(rng, n), 80, TCP, b / 1200 + 4, b, rng.uniform(0.3, 4, n),
                SYN | ACK | PSH | FIN)

    # respuestas ICMP de IoT al monitoreo del admin (barrido cada 5 min)
    iot = sensors + cams + protos
    for k in np.arange(t0, t1, 300.0):
        n = len(iot)
        buf.add(k + rng.uniform(0, 2, n), [d.ip for d in iot], "10.10.60.20", 0, ICMP_ECHO_REPLY, ICMP,
                1, 74, 0.0, 0)

    for d in teachers + students:
        kind = "class" if d.role == "teacher" else "lab"
        rate = 1 / 45 if d.role == "teacher" else 1 / 35
        t = poisson_times(rng, t0, t1, rate, kind)
        n = len(t)
        u = rng.random(n)
        dst = np.where(u < 0.7, INTERNET_WEB, DASHBOARD)
        dport = np.where(rng.random(n) < 0.8, 443, 80)
        b = rng.lognormal(np.log(25_000), 1.1, n)
        buf.add(t, d.ip, dst, eph(rng, n), dport, TCP, b / 1000 + 6, b * 0.08 + 400, rng.lognormal(0, 1, n),
                SYN | ACK | PSH | FIN)
        # respuestas desde Internet (entran por Gi0/0/1)
        m = dst == INTERNET_WEB
        buf.add(t[m] + 0.05, INTERNET_WEB, d.ip, dport[m], eph(rng, m.sum()), TCP, b[m] / 900 + 6, b[m],
                rng.lognormal(0, 1, m.sum()), ACK | PSH | FIN)
        # DNS antes de ~la mitad de las conexiones
        td = t[rng.random(n) < 0.5] - 0.02
        buf.add(td, d.ip, MQTT_BROKER, eph(rng, len(td)), 53, UDP, 1, rng.integers(60, 90, len(td)), 0.0, 0)

    for d in protos:
        # prototipos estudiantiles: ráfagas de reconexión MQTT (parecidas a una inundación leve)
        for tb in poisson_times(rng, t0, t1, 1 / 1500, "lab"):
            n = rng.integers(10, 45)
            t = tb + np.sort(rng.uniform(0, rng.uniform(40, 150), n))
            pk = rng.integers(3, 8, n)
            buf.add(t, d.ip, MQTT_BROKER, eph(rng, n), 1883, TCP, pk, pk * rng.normal(80, 10, n),
                    rng.uniform(0.05, 2, n), SYN | ACK | PSH | FIN)
        t = poisson_times(rng, t0, t1, 1 / 400, "lab")
        n = len(t)
        buf.add(t, d.ip, DASHBOARD, eph(rng, n), 80, TCP, rng.integers(6, 20, n),
                rng.integers(500, 4000, n), rng.uniform(0.1, 2, n), SYN | ACK | PSH | FIN)


# ----------------------------------------------------------------- ataques
def attacks(buf, rng, inv, base, spec):
    ip = {n: d.ip for n, d in inv.items()}
    iot_net = [f"10.10.10.{i}" for i in range(2, 255)] + [f"10.10.20.{i}" for i in range(2, 255)]
    h = lambda x: base + x * 3600

    if "scan" in spec:
        s = spec["scan"]
        dur = s["minutes"] * 60
        n = int(s["rate_s"] * dur)
        t = h(s["start"]) + np.sort(rng.uniform(0, dur, n))
        ports = np.array([22, 23, 80, 443, 1883, 2323, 8080, 8883])
        buf.add(t, ip["PC-ATACANTE"], rng.choice(iot_net, n), eph(rng, n), rng.choice(ports, n), TCP,
                1, rng.integers(40, 60, n), 0.0, SYN, "scan")

    if "mqtt_flood" in spec:
        s = spec["mqtt_flood"]
        n = s["per_min"] * s["minutes"]
        t = h(s["start"]) + np.sort(rng.uniform(0, s["minutes"] * 60, n))
        pk = rng.integers(2, 6, n)
        buf.add(t, ip["PC-ATACANTE"], MQTT_BROKER, eph(rng, n), 1883, TCP, pk, pk * rng.normal(75, 12, n),
                rng.uniform(0, 0.4, n), np.where(rng.random(n) < 0.6, SYN | ACK | PSH, SYN | RST), "mqtt_flood")

    if "http_ddos" in spec:
        s = spec["http_ddos"]
        for src in s["sources"]:
            n = s["per_min"] * s["minutes"]
            t = h(s["start"]) + rng.uniform(0, 20) + np.sort(rng.uniform(0, s["minutes"] * 60, n))
            pk = rng.integers(1, 4, n)
            buf.add(t, ip[src], DASHBOARD, eph(rng, n), 80, TCP, pk, pk * rng.normal(90, 20, n),
                    rng.uniform(0, 0.2, n), np.where(pk == 1, SYN, SYN | ACK | PSH), "http_ddos")

    if "bruteforce" in spec:
        s = spec["bruteforce"]
        dur = s["minutes"] * 60
        t = h(s["start"]) + np.arange(0, dur, s["every_s"]) + rng.normal(0, 0.3, int(np.ceil(dur / s["every_s"])))
        n = len(t)
        pk = rng.integers(5, 8, n)
        buf.add(t, ip["PC-ATACANTE"], MQTT_BROKER, eph(rng, n), 1883, TCP, pk, rng.integers(330, 460, n),
                rng.uniform(0.2, 0.9, n), SYN | ACK | PSH | FIN, "bruteforce")
        if s.get("telnet"):
            cams = [d.ip for d in by_role(inv, "camera")]
            t2 = t[::2] + 1
            m = len(t2)
            buf.add(t2, ip["PC-ATACANTE"], rng.choice(cams, m), eph(rng, m), 23, TCP, rng.integers(4, 9, m),
                    rng.integers(260, 420, m), rng.uniform(0.3, 1.5, m), SYN | ACK | PSH | FIN, "bruteforce")

    if "botnet" in spec:
        s = spec["botnet"]
        for name in s["devices"]:
            src = ip[name]
            # beacon C2 con jitter y tamaño parecido a MQTT (sigiloso)
            t = np.arange(h(s["start"]), base + DAY, s["beacon_s"]) + rng.normal(0, 30, int(np.ceil((base + DAY - h(s["start"])) / s["beacon_s"])))
            t = t[t < base + DAY]
            n = len(t)
            buf.add(t, src, C2_SERVER, eph(rng, n), 6667, TCP, rng.integers(3, 6, n), rng.integers(180, 270, n),
                    rng.uniform(0.2, 1.2, n), SYN | ACK | PSH | FIN, "botnet")
            buf.add(t + 0.1, C2_SERVER, src, 6667, eph(rng, n), TCP, rng.integers(2, 5, n),
                    rng.integers(120, 300, n), rng.uniform(0.1, 1.0, n), ACK | PSH | FIN, "botnet")
            # escaneo tipo Mirai a telnet de otros IoT
            dur = s["scan_minutes"] * 60
            n = int(2 * dur)
            t = h(s["scan_start"]) + np.sort(rng.uniform(0, dur, n))
            buf.add(t, src, rng.choice(iot_net, n), eph(rng, n), rng.choice([23, 2323], n, p=[0.9, 0.1]), TCP,
                    1, 44, 0.0, SYN, "botnet")

    if "exfil" in spec:
        s = spec["exfil"]
        t = h(s["start"]) + np.arange(0, s["minutes"] * 60, 60.0) + rng.uniform(0, 5, s["minutes"])
        n = len(t)
        b = rng.uniform(5e6, 15e6, n)
        buf.add(t, ip[s["device"]], INTERNET_WEB, eph(rng, n), 443, TCP, b / 1400, b, rng.uniform(40, 60, n),
                ACK | PSH, "exfil")


def generate(cfg=None, inventory=None):
    cfg = cfg or ScenarioConfig()
    inv = inventory or load_inventory()
    rng = np.random.default_rng(cfg.seed)
    buf = FlowBuffer()
    for d in range(cfg.days):
        base = d * DAY
        normal_traffic(buf, rng, inv, base, base + DAY)
        if d in cfg.attacks:
            attacks(buf, rng, inv, base, cfg.attacks[d])
    df = buf.frame()
    df["day"] = (df["ts"] // DAY).astype(int)
    df = df[(df["day"] >= 0) & (df["day"] < cfg.days)].reset_index(drop=True)
    return df


if __name__ == "__main__":
    import argparse
    from pathlib import Path

    p = argparse.ArgumentParser(description="Genera el dataset sintético de flujos IoT-SafeCampus")
    p.add_argument("--out", default=str(Path(__file__).resolve().parents[1] / "data" / "flows.csv.gz"))
    p.add_argument("--seed", type=int, default=7)
    a = p.parse_args()
    df = generate(ScenarioConfig(seed=a.seed))
    Path(a.out).parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(a.out, index=False)
    print(f"{len(df):,} flujos -> {a.out}")
    print(df.groupby(["day", "attack"]).size().unstack(fill_value=0))
