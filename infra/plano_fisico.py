"""Genera el plano físico (planta del edificio) de IoT-SafeCampus.

Uso: python plano_fisico.py  ->  docs/plano_fisico.svg
Misma distribución que el fondo de la vista física de PT (fondo_fisico.py):
laboratorio y SITE a la izquierda, AULA 1-5 arriba, pasillo, AULA 6-10 abajo.
Escala: 304 px = 10 m. Las longitudes de cable se calculan de la geometría
(recorrido por charola en el pasillo + 3 m de holgura/bajadas).
"""
from pathlib import Path

W = 1600
S = 10 / 304                      # metros por píxel
X0, X1 = 40, 1560
LW = 300                          # bloque izquierdo (laboratorio / site)
AX0 = X0 + LW                     # inicio de las aulas
AW = (X1 - AX0) / 5
TOP, MID0, MID1, BOT = 110, 470, 550, 930   # muros: aulas 1-5 | pasillo | aulas 6-10
TRAY_Y = (MID0 + MID1) / 2
H = BOT + 470

C = {
    "wall": "#2b2f36", "aula": "#eaf2fb", "lab": "#eaf6ee", "site": "#fdf0e3",
    "corr": "#f3f3f1", "tray": "#d9d4c7", "cat6": "#e07b1f",
    "patch": "#2f6db5", "wan": "#7b3fb0", "text": "#1f2328", "muted": "#5b6470",
}
out = []
add = out.append


def text(x, y, s, size=13, weight="normal", color=None, anchor="start"):
    add(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" '
        f'fill="{color or C["text"]}" text-anchor="{anchor}">{s}</text>')


def room(x, y, w, h, fill, name, sub="", bottom=False):
    """Cuarto con rótulo arriba o, si bottom=True, junto al muro inferior."""
    add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{fill}" '
        f'stroke="{C["wall"]}" stroke-width="5"/>')
    ty = y + h - 34 if bottom else y + 26
    text(x + 14, ty, name, 16, "bold")
    if sub:
        text(x + 14, ty + 18, sub, 11.5, color=C["muted"])


def door(x, y, w=46, down=False):
    """Hueco de puerta sobre un muro horizontal + arco de abatimiento hacia dentro del cuarto."""
    s = 1 if down else -1
    add(f'<line x1="{x}" y1="{y}" x2="{x + w}" y2="{y}" stroke="{C["corr"]}" stroke-width="7"/>')
    add(f'<path d="M{x},{y} A{w},{w} 0 0 {0 if down else 1} {x + w},{y + s * w}" fill="none" '
        f'stroke="{C["muted"]}" stroke-width="1" stroke-dasharray="3 3"/>')
    add(f'<line x1="{x + w}" y1="{y}" x2="{x + w}" y2="{y + s * w}" stroke="{C["muted"]}" stroke-width="1.5"/>')


def gabinete(x, y, label, below=False):
    add(f'<rect x="{x - 18}" y="{y - 12}" width="36" height="24" rx="2" fill="#3a4250" stroke="#11151b"/>')
    for i in range(4):
        add(f'<circle cx="{x - 10 + i * 6.5}" cy="{y}" r="1.8" fill="#7fd36b"/>')
    text(x, y + 28 if below else y - 18, label, 11, "bold", anchor="middle")


def pc(x, y, label):
    add(f'<rect x="{x - 26}" y="{y - 14}" width="52" height="28" fill="#c9b79c" stroke="#8a7656"/>')
    add(f'<rect x="{x - 9}" y="{y - 10}" width="18" height="12" fill="#2b2f36"/>')
    text(x, y + 28, label, 10.5, anchor="middle")


def sensor(x, y, label):
    add(f'<circle cx="{x}" cy="{y}" r="9" fill="#2a9d8f" stroke="#1d6f65" stroke-width="2"/>')
    add(f'<circle cx="{x}" cy="{y}" r="3" fill="#fff"/>')
    text(x, y + 24, label, 10.5, anchor="middle")


def camara(x, y, label):
    add(f'<path d="M{x - 10},{y - 7} L{x + 6},{y - 7} L{x + 6},{y + 7} L{x - 10},{y + 7} Z M{x + 6},{y - 3} '
        f'L{x + 14},{y - 8} L{x + 14},{y + 8} L{x + 6},{y + 3}" fill="#e76f51" stroke="#9c3f27" stroke-width="1.5"/>')
    text(x, y + 24, label, 10.5, anchor="middle")


def cerradura(x, y, label, above=False):
    add(f'<path d="M{x - 5},{y - 3} L{x - 5},{y - 8} A5,5 0 0 1 {x + 5},{y - 8} L{x + 5},{y - 3}" '
        f'fill="none" stroke="#7a5a12" stroke-width="2"/>')
    add(f'<rect x="{x - 9}" y="{y - 3}" width="18" height="13" rx="2" fill="#e9b949" stroke="#7a5a12" stroke-width="1.5"/>')
    text(x, y - 14 if above else y + 26, label, 10.5, anchor="middle")


def patch(pts):
    """Patch cord ortogonal por una lista de puntos (equipo -> gabinete)."""
    d = "M" + " L".join(f"{x},{y}" for x, y in pts)
    add(f'<path d="{d}" fill="none" stroke="{C["patch"]}" stroke-width="1.6" stroke-dasharray="5 3"/>')


runs = []   # (tramo, puertos, cable, metros)
wires = []  # troncales: se dibujan después de los cuartos para que no queden tapados

# Rack del SITE-TELECOM (abajo a la izquierda): destino de todos los troncales.
rx, ry, rw, rh = X0 + 140, MID1 + 70, 150, 270


def lane_x(lane):
    return rx + 14 + lane * 11


def backbone(pts, label, ports):
    """Troncal Cat6 por charola hasta la parte superior del rack."""
    d = "M" + " L".join(f"{x},{y}" for x, y in pts)
    wires.append(f'<path d="{d}" fill="none" stroke="{C["cat6"]}" stroke-width="2.4"/>')
    px = sum(abs(pts[i + 1][0] - pts[i][0]) + abs(pts[i + 1][1] - pts[i][1]) for i in range(len(pts) - 1))
    runs.append((label, ports, "UTP Cat6 (troncal 802.1Q)", round(px * S + 3, 1)))


# ---------------------------------------------------------------- lienzo
add(f'<rect width="{W}" height="{H}" fill="#ffffff"/>')
text(X0, 44, "IoT-SafeCampus · Plano físico (planta del edificio de aulas)", 24, "bold")
text(X0, 70, "10 aulas inteligentes (5 equipos c/u), laboratorio y SITE. Escala aproximada 1:300 — "
             "recorridos horizontales &lt; 90 m (ANSI/TIA-568).", 13, color=C["muted"])

# pasillo + charola
add(f'<rect x="{X0}" y="{MID0}" width="{X1 - X0}" height="{MID1 - MID0}" fill="{C["corr"]}"/>')
add(f'<rect x="{X0 + 10}" y="{TRAY_Y - 18}" width="{X1 - X0 - 20}" height="36" fill="{C["tray"]}" '
    f'opacity=".55" stroke="#b3ab97" stroke-dasharray="8 4"/>')
text(X1 - 20, MID1 - 6, "PASILLO · charola portacables sobre plafón", 12, "bold", C["muted"], "end")


def aula(i):
    """Aula i: fila superior (1-5) o inferior (6-10), espejada respecto al pasillo."""
    k = (i - 1) % 5
    top = i <= 5
    x = AX0 + k * AW
    y0, y1 = (TOP, MID0) if top else (MID1, BOT)
    wall = MID0 if top else MID1          # muro del pasillo
    s = 1 if top else -1                  # hacia dentro del aula = wall - s*d

    def at(d):
        return wall - s * d

    room(x, y0, AW, y1 - y0, C["aula"], f"AULA {i}", "Aula inteligente · VLAN 10/20/30", bottom=not top)
    door(x + 20, wall, down=not top)
    gx, gy = x + AW - 48, at(56)
    far = 280                              # equipos junto al muro opuesto al pasillo
    devs = [  # (dibujo, x, distancia al pasillo, nombre, entra por)
        (pc, x + 150, 190, f"PC-DOC{i}", "L"),
        (sensor, x + 40, far, f"SENS-A{i}", "L"),
        (sensor, x + 100, far, f"MOV-A{i}", "L"),
        (camara, x + AW - 40, far, f"CAM-A{i}", "R"),
        (cerradura, x + 110, 40, f"PUERTA-A{i}", "L"),
    ]
    for j, (fn, dx, d, name, side) in enumerate(devs):
        yy = at(d)
        lane = gy + (j - 2) * 4
        if side == "R":
            patch([(dx, yy), (dx, gy), (gx + 18, gy)])
        else:
            patch([(dx, yy), (dx, lane), (gx - 18, lane)])
        if fn is cerradura:
            fn(dx, yy, name, above=not top)
        else:
            fn(dx, yy, name)
    gabinete(gx, gy, f"SW-AULA{i}", below=not top)
    ty = TRAY_Y - 14 + k * 3 if top else TRAY_Y + 2 + k * 3
    edge = gy + 12 * s
    lane_n = k if top else 5 + k
    backbone([(gx, edge), (gx, ty), (lane_x(lane_n), ty), (lane_x(lane_n), ry)],
             f"SW-CORE ↔ SW-AULA{i}", f"Fa0/{i if i <= 5 else i + 1} ↔ Gi0/1")


for i in range(1, 11):
    aula(i)

# laboratorio (arriba a la izquierda)
room(X0, TOP, LW, MID0 - TOP, C["lab"], "LABORATORIO", "Prototipos · VLAN 40")
door(X0 + 20, MID0)
lgx, lgy = X0 + LW - 48, MID0 - 56
benches = [("PROTO-LAB1", "s", 60, TOP + 120), ("PROTO-LAB2", "s", 160, TOP + 120),
           ("LAPTOP-EST", "p", 110, TOP + 240), ("PC-ATACANTE", "p", 210, TOP + 240)]
for j, (n, kind, bx, by) in enumerate(benches):
    bx += X0
    add(f'<rect x="{bx - 45}" y="{by - 30}" width="90" height="62" fill="#d8ccb8" stroke="#8a7656"/>')
    lane = lgy - 6 + j * 4
    patch([(bx, by + 32), (bx, lane), (lgx - 18, lane)])
    (sensor if kind == "s" else pc)(bx, by, n)
gabinete(lgx, lgy, "SW-LAB")
lab_ty = TRAY_Y + 17
backbone([(lgx, lgy + 12), (lgx, lab_ty), (lane_x(10), lab_ty), (lane_x(10), ry)],
         "SW-CORE ↔ SW-LAB", "Fa0/6 ↔ Gi0/1")

# SITE-TELECOM (abajo a la izquierda)
room(X0, MID1, LW, BOT - MID1, C["site"], "SITE (MDF)", "VLAN 50/60", bottom=True)
door(X0 + 20, MID1, down=True)

out.extend(wires)

# rack 42U (elevación simplificada)
add(f'<rect x="{rx}" y="{ry}" width="{rw}" height="{rh}" fill="#20252c" stroke="#0c0f13" stroke-width="2"/>')
units = [("R-ISP (CPE del ISP)", "#7b3fb0"), ("R-EDGE · ISR4331", "#3a7bd5"), ("SW-CORE · 2960", "#2f9e6f"),
         ("SW-DC · 2960", "#2f9e6f"), ("Patch panel 24p", "#6b7280"), ("SRV-MQTT", "#9aa3ad"),
         ("SRV-DASHBOARD", "#9aa3ad"), ("IDS-EDGE (colector)", "#e07b1f"), ("PDU", "#4b5563")]
for u, (name, col) in enumerate(units):
    uy = ry + 10 + u * 28
    add(f'<rect x="{rx + 8}" y="{uy}" width="{rw - 16}" height="22" rx="2" fill="{col}"/>')
    text(rx + rw / 2, uy + 15, name, 10.5, "bold", "#ffffff", "middle")
add(f'<rect x="{X0 + 18}" y="{MID1 + 190}" width="80" height="56" fill="#d8ccb8" stroke="#8a7656"/>')
patch([(X0 + 58, MID1 + 190), (X0 + 58, ry + 108), (rx, ry + 108)])
pc(X0 + 58, MID1 + 214, "PC-ADMIN")

# acometida ISP
ax = rx + rw / 2
add(f'<path d="M{ax},{BOT + 90} L{ax},{ry + rh}" fill="none" stroke="{C["wan"]}" stroke-width="3" '
    f'stroke-dasharray="10 5"/>')
add(f'<rect x="{ax - 110}" y="{BOT + 90}" width="220" height="44" rx="6" fill="#f3ecfa" stroke="{C["wan"]}"/>')
text(ax, BOT + 109, "PROVEEDOR ISP / Internet simulado", 11.5, "bold", C["wan"], "middle")
text(ax, BOT + 125, "SRV-INTERNET · 203.0.113.10", 10.5, color=C["wan"], anchor="middle")
text(ax + 8, BOT + 60, "Acometida", 10.5, "bold", C["wan"])
runs.append(("R-ISP ↔ R-EDGE", "Gi0/0 ↔ Gi0/0/1", "UTP Cat6 (WAN, mismo rack)", 2.0))
runs.append(("R-EDGE ↔ SW-CORE", "Gi0/0/0 ↔ Gi0/1", "Patch cord Cat6 (troncal router-on-a-stick)", 1.0))
runs.append(("SW-CORE ↔ SW-DC", "Gi0/2 ↔ Gi0/1", "Patch cord Cat6", 1.0))

# ------------------------------------------------------------ leyenda + tabla
LY = BOT + 175
lx = X0
text(lx, LY, "Simbología", 15, "bold")
items = [("line", C["cat6"], "Troncal horizontal UTP Cat6 (gabinete ↔ SITE)"),
         ("dash", C["patch"], "Patch cord Cat6 a equipo final (≤ 5 m)"),
         ("wan", C["wan"], "Acometida del proveedor (WAN)"),
         ("tray", C["tray"], "Charola portacables")]
for i, (kind, col, lab) in enumerate(items):
    y = LY + 22 + i * 22
    if kind == "tray":
        add(f'<rect x="{lx}" y="{y - 8}" width="36" height="12" fill="{col}" stroke="#b3ab97"/>')
    else:
        dash = {"line": "", "dash": ' stroke-dasharray="5 3"', "wan": ' stroke-dasharray="10 5"'}[kind]
        add(f'<line x1="{lx}" y1="{y - 2}" x2="{lx + 36}" y2="{y - 2}" stroke="{col}" stroke-width="2.6"{dash}/>')
    text(lx + 46, y + 2, lab, 11.5)
sym = [("gab", "Gabinete de pared / switch de acceso"), ("sen", "Sensor IoT (temperatura SENS, movimiento MOV)"),
       ("cam", "Cámara IP"), ("lock", "Cerradura inteligente (PUERTA)"), ("pc", "PC / laptop")]
for i, (kind, lab) in enumerate(sym):
    y = LY + 22 + i * 22
    gx = lx + 360
    if kind == "gab":
        add(f'<rect x="{gx}" y="{y - 10}" width="28" height="14" rx="2" fill="#3a4250"/>')
    elif kind == "sen":
        add(f'<circle cx="{gx + 14}" cy="{y - 3}" r="7" fill="#2a9d8f"/>')
    elif kind == "cam":
        add(f'<rect x="{gx + 4}" y="{y - 9}" width="16" height="12" fill="#e76f51"/>')
    elif kind == "lock":
        add(f'<rect x="{gx + 6}" y="{y - 9}" width="14" height="12" rx="2" fill="#e9b949" stroke="#7a5a12"/>')
    else:
        add(f'<rect x="{gx}" y="{y - 10}" width="28" height="14" fill="#c9b79c" stroke="#8a7656"/>')
    text(gx + 40, y + 2, lab, 11.5)

tx = X0 + 760
text(tx, LY, "Tabla de enlaces físicos", 15, "bold")
cols = [0, 165, 285, 570]
for j, h in enumerate(["Enlace", "Puertos", "Medio", "Long. aprox."]):
    text(tx + cols[j], LY + 22, h, 11.5, "bold", C["muted"])
add(f'<line x1="{tx}" y1="{LY + 28}" x2="{X1}" y2="{LY + 28}" stroke="#c8ccd2"/>')
for i, (a, p, m, L) in enumerate(runs):
    y = LY + 44 + i * 17
    for j, v in enumerate([a, p, m, f"{L:.1f} m"]):
        text(tx + cols[j], y, v, 11)

svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{W}" height="{H}" viewBox="0 0 {W} {H}" '
       f'font-family="Segoe UI, Arial, sans-serif">' + "".join(out) + "</svg>")
dst = Path(__file__).resolve().parent.parent / "docs" / "plano_fisico.svg"
dst.write_text(svg, encoding="utf-8")
print(dst)
for r in runs:
    print(r)
