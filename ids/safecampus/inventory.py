"""Inventario de dispositivos derivado del plan de topología de Packet Tracer.

Une la parte 1 (infraestructura) con la parte 2 (IDS): las IPs, VLANs y el
puerto de switch de cada host salen de infra/iot_safecampus_plan.json, de modo
que el dataset y las reglas de aislamiento corresponden a la red desplegada.
"""
import json
from dataclasses import dataclass
from pathlib import Path

PLAN = Path(__file__).resolve().parents[2] / "infra" / "iot_safecampus_plan.json"

# Prefijo de nombre -> rol de comportamiento
ROLE_PREFIX = [
    ("SENS-", "sensor"), ("MOV-", "sensor"), ("PUERTA-", "sensor"),
    ("CAM-", "camera"), ("PC-DOC", "teacher"),
    ("PROTO-LAB", "prototype"), ("LAPTOP-EST", "student"), ("PC-ATACANTE", "student"),
    ("PC-ADMIN", "admin"), ("SRV-", "server"), ("IDS-EDGE", "server"),
]

MQTT_BROKER = "10.10.50.10"     # SRV-MQTT (también DNS/NTP)
DASHBOARD = "10.10.50.11"       # SRV-DASHBOARD (HTTP/HTTPS, registro IoT)
INTERNET_WEB = "203.0.113.10"   # SRV-INTERNET
C2_SERVER = "203.0.113.66"      # servidor de mando y control simulado (no existe en la topología)


@dataclass(frozen=True)
class Device:
    name: str
    ip: str
    vlan: int
    role: str
    switch: str = ""
    port: str = ""


def _role(name):
    for prefix, role in ROLE_PREFIX:
        if name.startswith(prefix):
            return role
    return "other"


def load_inventory(plan_path=PLAN):
    plan = json.loads(Path(plan_path).read_text(encoding="utf-8"))
    access = {(a["switch"], a["port"]): a["vlan_id"] for a in plan["access_ports"]}
    attach = {}
    for link in plan["links"]:
        for a, pa, b, pb in ((link["device_a"], link["port_a"], link["device_b"], link["port_b"]),
                             (link["device_b"], link["port_b"], link["device_a"], link["port_a"])):
            if (a, pa) in access:
                attach[b] = (a, pa)
    devices = {}
    for d in plan["devices"]:
        ip = d["interfaces"].get("FastEthernet0", "").split("/")[0]
        if not ip or not ip.startswith("10.10."):
            continue
        sw, port = attach.get(d["name"], ("", ""))
        devices[d["name"]] = Device(d["name"], ip, d["vlan"], _role(d["name"]), sw, port)
    return devices


def by_role(devices, role):
    return [d for d in devices.values() if d.role == role]
