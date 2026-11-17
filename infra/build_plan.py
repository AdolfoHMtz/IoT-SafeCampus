"""Genera el plan de topología IoT-SafeCampus para el MCP de Packet Tracer.

Uso: python build_plan.py  ->  escribe iot_safecampus_plan.json junto a este script.

Diseño (router-on-a-stick en R-EDGE, que actúa como gateway edge):
  R-ISP --- R-EDGE --trunk--- SW-CORE --+-- SW-AULA1..10 (5 dispositivos por aula)
                                         +-- SW-LAB       (prototipos, laptop, atacante)
                                         +-- SW-DC        (MQTT, dashboard, IDS-EDGE, admin)

Nota: pt_live_deploy no aplica IP a los WiredEndDevice-PT (sensores, cámaras, PROTO-LAB).
Tras desplegar, asignarlas por pt_send_raw con port.setIpSubnetMask() y
port.setDefaultGateway() (el gateway va en el puerto, no en el dispositivo).
SBC-PT no se usa: su FastEthernet (módulo PT-IOT-NM-1CFE) no levanta vía script.
"""
import json
from pathlib import Path

VLANS = [
    (10, "IOT-SENSORES", "10.10.10"),
    (20, "IOT-CAMARAS", "10.10.20"),
    (30, "DOCENTES", "10.10.30"),
    (40, "LAB-PROTOTIPOS", "10.10.40"),
    (50, "SERVIDORES", "10.10.50"),
    (60, "GESTION-IDS", "10.10.60"),
    (99, "CUARENTENA", "10.10.99"),
]
NET = {vid: prefix for vid, _, prefix in VLANS}
ALL_VLANS = [vid for vid, _, _ in VLANS]

devices, links, access_ports, trunks = [], [], [], []


def dev(name, model, category, role, x, y, interfaces=None, gateway="", vlan=0):
    devices.append({
        "name": name, "model": model, "category": category, "role": role,
        "x": x, "y": y, "interfaces": interfaces or {}, "gateway": gateway,
        "interfaces_v6": {}, "gateway_v6": "", "vlan": vlan, "wireless": False,
    })


def link(a, pa, b, pb, cable="straight"):
    links.append({"device_a": a, "port_a": pa, "device_b": b, "port_b": pb, "cable": cable})


def host(name, model, category, sw, port, vlan, octet, x, y):
    """Host con IP estática (facilita etiquetar el dataset por dirección)."""
    dev(name, model, category, "end_host", x, y,
        {"FastEthernet0": f"{NET[vlan]}.{octet}/24"}, f"{NET[vlan]}.1", vlan)
    link(sw, port, name, "FastEthernet0")
    access_ports.append({"switch": sw, "port": port, "vlan_id": vlan})


def trunk(sw, port):
    trunks.append({"switch": sw, "port": port, "allowed_vlans": ALL_VLANS,
                   "native_vlan": 1, "encapsulation": "dot1q"})


# --- Núcleo y borde -------------------------------------------------------
dev("R-ISP", "2911", "router", "edge_router", 796, 50,
    {"GigabitEthernet0/0": "200.0.0.2/30", "GigabitEthernet0/1": "203.0.113.1/24"})
dev("SRV-INTERNET", "Server-PT", "server", "server_host", 563, 34,
    {"FastEthernet0": "203.0.113.10/24"}, "203.0.113.1")
link("R-ISP", "GigabitEthernet0/1", "SRV-INTERNET", "FastEthernet0", "cross")

dev("R-EDGE", "ISR4331", "router", "core_router", 790, 160,
    {"GigabitEthernet0/0/1": "200.0.0.1/30",
     **{f"GigabitEthernet0/0/0.{vid}": f"{NET[vid]}.1/24" for vid in ALL_VLANS}})
link("R-EDGE", "GigabitEthernet0/0/1", "R-ISP", "GigabitEthernet0/0", "cross")

dev("SW-CORE", "2960-24TT", "switch", "distribution_switch", 790, 270)
link("R-EDGE", "GigabitEthernet0/0/0", "SW-CORE", "GigabitEthernet0/1")
trunk("SW-CORE", "GigabitEthernet0/1")

# --- 10 aulas inteligentes, 5 dispositivos finales cada una ----------------
# Dos filas de 5 (la segunda desplazada media columna para que los troncales no
# pasen encima de otra aula). IPs: docente/sensor/cámara conservan .1x originales;
# MOV = 10.10.10.3x y PUERTA = 10.10.10.5x (x = número de aula).
# (nombre, modelo, categoría, puerto, vlan, octeto(i), dx, dy)
AULA_HOSTS = [
    ("PC-DOC{i}", "PC-PT", "pc", 1, 30, lambda i: 10 + i, -110, 110),
    ("SENS-A{i}", "WiredEndDevice-PT", "wired_end_device", 2, 10, lambda i: 10 + i, -55, 200),
    ("CAM-A{i}", "WiredEndDevice-PT", "wired_end_device", 3, 20, lambda i: 10 + i, 0, 110),
    ("MOV-A{i}", "WiredEndDevice-PT", "wired_end_device", 4, 10, lambda i: 30 + i, 55, 200),
    ("PUERTA-A{i}", "WiredEndDevice-PT", "wired_end_device", 5, 10, lambda i: 50 + i, 110, 110),
]
for i in range(1, 11):
    sw, row = f"SW-AULA{i}", (i - 1) // 5
    x, y = 150 + ((i - 1) % 5) * 320 + row * 160, 400 + row * 330
    up = f"FastEthernet0/{i if i <= 5 else i + 1}"  # Fa0/6 es del laboratorio
    dev(sw, "2960-24TT", "switch", "access_switch", x, y)
    link("SW-CORE", up, sw, "GigabitEthernet0/1", "cross")
    trunk("SW-CORE", up)
    trunk(sw, "GigabitEthernet0/1")
    for name, model, cat, port, vlan, octet, dx, dy in AULA_HOSTS:
        host(name.format(i=i), model, cat, sw, f"FastEthernet0/{port}", vlan, octet(i), x + dx, y + dy)

# --- Laboratorio de prototipos -------------------------------------------
dev("SW-LAB", "2960-24TT", "switch", "access_switch", 1790, 400)
link("SW-CORE", "FastEthernet0/6", "SW-LAB", "GigabitEthernet0/1", "cross")
trunk("SW-CORE", "FastEthernet0/6")
trunk("SW-LAB", "GigabitEthernet0/1")
host("PROTO-LAB1", "WiredEndDevice-PT", "wired_end_device", "SW-LAB", "FastEthernet0/1", 40, 11, 1695, 510)
host("PROTO-LAB2", "WiredEndDevice-PT", "wired_end_device", "SW-LAB", "FastEthernet0/2", 40, 12, 1740, 600)
host("LAPTOP-EST", "Laptop-PT", "laptop", "SW-LAB", "FastEthernet0/3", 40, 21, 1790, 510)
host("PC-ATACANTE", "PC-PT", "pc", "SW-LAB", "FastEthernet0/4", 40, 66, 1885, 510)

# --- Centro de datos / edge ----------------------------------------------
dev("SW-DC", "2960-24TT", "switch", "access_switch", 1130, 270)
link("SW-CORE", "GigabitEthernet0/2", "SW-DC", "GigabitEthernet0/1", "cross")
trunk("SW-CORE", "GigabitEthernet0/2")
trunk("SW-DC", "GigabitEthernet0/1")
host("SRV-MQTT", "Server-PT", "server", "SW-DC", "FastEthernet0/1", 50, 10, 1016, 150)
host("SRV-DASHBOARD", "Server-PT", "server", "SW-DC", "FastEthernet0/2", 50, 11, 1136, 150)
host("IDS-EDGE", "Server-PT", "server", "SW-DC", "FastEthernet0/3", 60, 10, 1256, 150)
host("PC-ADMIN", "PC-PT", "pc", "SW-DC", "FastEthernet0/4", 60, 20, 1376, 150)

plan = {
    "name": "IoT-SafeCampus",
    "devices": devices,
    "modules": [],
    "links": links,
    "dhcp_pools": [],
    "static_routes": [
        {"router": "R-EDGE", "destination": "0.0.0.0", "mask": "0.0.0.0",
         "next_hop": "200.0.0.2", "admin_distance": 1},
        {"router": "R-ISP", "destination": "10.10.0.0", "mask": "255.255.0.0",
         "next_hop": "200.0.0.1", "admin_distance": 1},
    ],
    "ospf_configs": [], "rip_configs": [], "eigrp_configs": [],
    "vlans": [{"vlan_id": vid, "name": name, "subnet": f"{p}.0/24"} for vid, name, p in VLANS],
    "access_ports": access_ports,
    "trunks": trunks,
    "subinterfaces": [
        {"router": "R-EDGE", "parent_port": "GigabitEthernet0/0/0", "vlan_id": vid,
         "ip_cidr": f"{NET[vid]}.1/24", "encapsulation": "dot1Q"} for vid in ALL_VLANS
    ],
    "validations": [
        {"check_type": "ping", "from_device": "PC-DOC1", "to_target": "SRV-DASHBOARD", "expected": "Reply"},
        {"check_type": "ping", "from_device": "SENS-A1", "to_target": "SRV-MQTT", "expected": "Reply"},
        {"check_type": "ping", "from_device": "PC-ADMIN", "to_target": "SRV-INTERNET", "expected": "Reply"},
    ],
    "dual_stack": False,
    "errors": [],
    "warnings": [],
}

out = Path(__file__).with_name("iot_safecampus_plan.json")
out.write_text(json.dumps(plan, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"{out} -> {len(devices)} dispositivos, {len(links)} enlaces")
