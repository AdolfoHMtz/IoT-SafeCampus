"""Genera la imagen de fondo para la vista física (edificio) de Packet Tracer.

Uso: python fondo_fisico.py  ->  docs/fondo_fisico_pt.svg (renderizar a PNG 1920x1080)
Solo arquitectura (muros, cuartos, puertas, pasillo): PT dibuja encima los
cuartos de cableado y los enlaces. Las posiciones de cada cuarto se exportan
en ROOM_CENTERS para alinear los closets de PT con su habitación.
"""
from pathlib import Path

# Diseño en 1920x1150 (proporción del área del edificio en PT, ~1.67) y se
# renderiza a 3390x2030: PT muestra el fondo a tamaño real y ese es el tamaño
# del área en coordenadas de PT (1 px = 1 unidad).
W, H = 1920, 1150
OUT_W, OUT_H = 3390, 2030
M = 50                       # margen exterior
LEFT = 420                   # ancho del bloque izquierdo (laboratorio + site)
TOP0, TOP1 = M, 500          # fila superior (aulas 1-5)
COR0, COR1 = 500, 620        # pasillo
BOT0, BOT1 = 620, H - M      # fila inferior (aulas 6-10)
WALL = "#3b4048"

rooms = []                   # (x, y, w, h, nombre, subtítulo, relleno)
rooms.append((M, TOP0, LEFT - M, TOP1 - TOP0, "LABORATORIO", "Prototipos · VLAN 40", "#e6f3ea"))
rooms.append((M, BOT0, LEFT - M, BOT1 - BOT0, "SITE-TELECOM", "Cuarto de telecom. (MDF)", "#fbeadb"))
aw = (W - M - LEFT) / 5
for i in range(10):
    x = LEFT + (i % 5) * aw
    y0, y1 = (TOP0, TOP1) if i < 5 else (BOT0, BOT1)
    rooms.append((x, y0, aw, y1 - y0, f"AULA {i + 1}", "VLAN 10 / 20 / 30", "#e4eef9"))

ROOM_CENTERS = {n: (x + w / 2, y + h / 2) for x, y, w, h, n, _, _ in rooms}

o = []
o.append(f'<rect width="{W}" height="{H}" fill="#f7f6f2"/>')
# rejilla tenue de plano
for gx in range(0, W, 40):
    o.append(f'<line x1="{gx}" y1="0" x2="{gx}" y2="{H}" stroke="#ebe9e2" stroke-width="1"/>')
for gy in range(0, H, 40):
    o.append(f'<line x1="0" y1="{gy}" x2="{W}" y2="{gy}" stroke="#ebe9e2" stroke-width="1"/>')

# pasillo + charola
o.append(f'<rect x="{M}" y="{COR0}" width="{W - 2 * M}" height="{COR1 - COR0}" fill="#efede6"/>')
o.append(f'<rect x="{M + 20}" y="{(COR0 + COR1) / 2 - 16}" width="{W - 2 * M - 40}" height="32" '
         f'fill="#ddd6c4" opacity=".6" stroke="#bdb39b" stroke-dasharray="10 6"/>')
o.append(f'<text x="{W / 2}" y="{(COR0 + COR1) / 2 + 7}" font-size="20" font-weight="600" fill="#8c8270" '
         f'text-anchor="middle" letter-spacing="6">PASILLO · CHAROLA PORTACABLES</text>')

for x, y, w, h, n, sub, f in rooms:
    o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="{f}"/>')
    o.append(f'<text x="{x + 22}" y="{y + 44}" font-size="30" font-weight="700" fill="#2b2f36">{n}</text>')
    o.append(f'<text x="{x + 22}" y="{y + 72}" font-size="17" fill="#6a717b">{sub}</text>')

# muros (encima de rellenos)
for x, y, w, h, *_ in rooms:
    o.append(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" fill="none" stroke="{WALL}" stroke-width="8"/>')
o.append(f'<rect x="{M}" y="{M}" width="{W - 2 * M}" height="{H - 2 * M}" fill="none" stroke="{WALL}" stroke-width="14"/>')


def door(x, y, down, w=70):
    s = 1 if down else -1
    o.append(f'<line x1="{x}" y1="{y}" x2="{x + w}" y2="{y}" stroke="#efede6" stroke-width="10"/>')
    o.append(f'<path d="M{x},{y} A{w},{w} 0 0 {0 if down else 1} {x + w},{y + s * w}" '
             f'fill="none" stroke="#8a919b" stroke-width="2" stroke-dasharray="6 5"/>')
    o.append(f'<line x1="{x + w}" y1="{y}" x2="{x + w}" y2="{y + s * w}" stroke="#8a919b" stroke-width="3"/>')


# puertas hacia el pasillo: fila superior abre hacia arriba, inferior hacia abajo
for x, y, w, h, n, *_ in rooms:
    if y == TOP0:
        door(x + w - 110, TOP1, down=False)
    else:
        door(x + w - 110, BOT0, down=True)
# acceso principal
o.append(f'<line x1="{W - M}" y1="{COR0 + 25}" x2="{W - M}" y2="{COR1 - 25}" stroke="#efede6" stroke-width="16"/>')
o.append(f'<text x="{W - M - 14}" y="{COR0 + 24}" font-size="15" fill="#6a717b" text-anchor="end">Acceso principal →</text>')

# rótulo
o.append(f'<text x="{M + 24}" y="{COR1 - 12}" font-size="16" fill="#8c8270">IoT-SafeCampus · Edificio de aulas (10 aulas) · Planta baja</text>')
# norte
nx, ny = W - M - 60, H - M - 70
o.append(f'<path d="M{nx},{ny - 30} L{nx + 14},{ny + 12} L{nx},{ny + 2} L{nx - 14},{ny + 12} Z" fill="#3b4048"/>')
o.append(f'<text x="{nx}" y="{ny + 36}" font-size="18" font-weight="700" fill="#3b4048" text-anchor="middle">N</text>')

svg = (f'<svg xmlns="http://www.w3.org/2000/svg" width="{OUT_W}" height="{OUT_H}" viewBox="0 0 {W} {H}" '
       f'font-family="Segoe UI, Arial, sans-serif">' + "".join(o) + "</svg>")
dst = Path(__file__).resolve().parent.parent / "docs" / "fondo_fisico_pt.svg"
dst.write_text(svg, encoding="utf-8")
print(dst)
ICON = 356   # tamaño del ícono de closet en unidades PT; setX/setY ubican su esquina sup. izq.
for n, (cx, cy) in ROOM_CENTERS.items():
    print(f"{n}: {round(cx / W * OUT_W - ICON / 2)}, {round(cy / H * OUT_H - ICON / 2)}")
