"""Extracción de características ligeras a partir de registros NetFlow.

Se usa igual offline (experimentos) y online (gateway edge): las ventanas son
cubetas de 60 s y 600 s por IP de origen, que es como llegan los registros del
exportador (timeout activo de 60 s), así que el edge puede calcularlas al
cerrar cada minuto sin estado adicional más que la ventana de 10 min.
"""
from dataclasses import dataclass, field

import numpy as np
import pandas as pd

from .generator import ACK, FIN, ICMP, PSH, RST, SYN, TCP, UDP

PORT_GROUPS = {"p_mqtt": [1883, 8883], "p_http": [80, 8080], "p_https": [443], "p_dns": [53], "p_telnet": [23, 2323]}
RFC1918 = ("10.", "192.168.", *(f"172.{i}." for i in range(16, 32)))


@dataclass
class NetContext:
    """Lo que el extractor necesita saber de la red monitoreada.

    En el campus los roles salen del inventario; en un dataset público sin
    inventario, los hosts internos comparten el rol 'internal'.
    """
    internal_prefixes: tuple
    server_prefixes: tuple = ()
    roles: list = field(default_factory=lambda: ["internal", "external"])
    role_of: dict = field(default_factory=dict)      # ip -> rol (si no está: internal/external)
    # La hora del día es legítima en el campus (un volumen nocturno es anómalo), pero en
    # datasets con ataques agendados a horas fijas se vuelve un atajo espurio (fuga de etiqueta).
    use_hour: bool = True


def campus_context(inventory):
    return NetContext(internal_prefixes=("10.10.",), server_prefixes=("10.10.50.",),
                      roles=["sensor", "camera", "teacher", "prototype", "student", "external"],
                      role_of={d.ip: d.role for d in inventory.values()})


def _context(ctx):
    return ctx if isinstance(ctx, NetContext) else campus_context(ctx)


def _window(df, size, prefix):
    key = [df["src_ip"], (df["ts"] // size).astype(np.int64)]
    g = df.groupby(key, sort=False)
    out = pd.DataFrame({
        f"{prefix}_flows": g["ts"].transform("size"),
        f"{prefix}_uniq_dst": g["dst_ip"].transform("nunique"),
        f"{prefix}_uniq_dport": g["dst_port"].transform("nunique"),
        f"{prefix}_syn_only": g["_syn_only"].transform("mean"),
    }, index=df.index)
    if prefix == "w1":
        out["w1_log_bytes"] = np.log1p(g["bytes"].transform("sum"))
        out["w1_small"] = g["_small"].transform("mean")
        out["w1_ext"] = g["_dst_ext"].transform("mean")
    return out


def extract(df, ctx):
    """Devuelve la matriz de características (DataFrame) alineada con df.

    ctx: NetContext, o el inventario del campus (se convierte con campus_context).
    """
    ctx = _context(ctx)
    df = df.copy()
    flags = df["tcp_flags"].to_numpy()
    df["_syn_only"] = ((flags & SYN) > 0) & ((flags & ACK) == 0)
    df["_small"] = df["packets"] <= 2
    src_int = df["src_ip"].str.startswith(ctx.internal_prefixes)
    df["_dst_ext"] = ~df["dst_ip"].str.startswith(ctx.internal_prefixes)

    X = pd.DataFrame(index=df.index)
    X["log_bytes"] = np.log1p(df["bytes"])
    X["log_pkts"] = np.log1p(df["packets"])
    X["log_dur"] = np.log1p(df["duration"])
    X["bytes_per_pkt"] = df["bytes"] / df["packets"]
    X["log_pkt_rate"] = np.log1p(df["packets"] / (df["duration"] + 0.01))
    X["is_tcp"] = (df["proto"] == TCP).astype(np.int8)
    X["is_udp"] = (df["proto"] == UDP).astype(np.int8)
    X["is_icmp"] = (df["proto"] == ICMP).astype(np.int8)
    for name, bit in (("f_syn", SYN), ("f_ack", ACK), ("f_fin", FIN), ("f_rst", RST), ("f_psh", PSH)):
        X[name] = ((flags & bit) > 0).astype(np.int8)
    X["syn_only"] = df["_syn_only"].astype(np.int8)
    for name, ports in PORT_GROUPS.items():
        X[name] = (df["dst_port"].isin(ports) & (df["proto"] != ICMP)).astype(np.int8)
    X["p_other"] = (X[list(PORT_GROUPS)].sum(axis=1) == 0).astype(np.int8)
    X["src_ext"] = (~src_int).astype(np.int8)
    X["dst_ext"] = df["_dst_ext"].astype(np.int8)
    X["dst_server"] = (df["dst_ip"].str.startswith(ctx.server_prefixes) if ctx.server_prefixes
                       else pd.Series(False, index=df.index)).astype(np.int8)
    if ctx.use_hour:
        hour = (df["ts"] % 86400) / 3600
        X["hour_sin"] = np.sin(2 * np.pi * hour / 24)
        X["hour_cos"] = np.cos(2 * np.pi * hour / 24)
    default = "internal" if "internal" in ctx.roles else "external"
    roles = df["src_ip"].map(ctx.role_of).fillna(pd.Series(np.where(src_int, default, "external"), index=df.index))
    for r in ctx.roles:
        X[f"r_{r}"] = (roles == r).astype(np.int8)
    X = X.join(_window(df, 60, "w1")).join(_window(df, 600, "w10"))
    for c in ("w1_flows", "w1_uniq_dst", "w1_uniq_dport", "w10_flows", "w10_uniq_dst", "w10_uniq_dport"):
        X[c] = np.log1p(X[c])
    return X.astype(np.float32)
