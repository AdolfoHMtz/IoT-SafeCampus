# IoT-SafeCampus · IDS ligero (parte 2)

IDS para redes IoT educativas que corre en un gateway edge. Toma los registros
NetFlow que exporta R-EDGE (parte 1, `../infra`) y compara detectores ligeros
contra pesados en precisión y consumo de recursos.

## Reproducir

```bash
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows (Linux: .venv/bin/python)

.venv/Scripts/python -m pytest                            # pruebas
.venv/Scripts/python -m safecampus.generator              # dataset -> data/flows.csv.gz
.venv/Scripts/python -m safecampus.experiment --seeds 5   # experimento -> results/
.venv/Scripts/python -m safecampus.edge train --model zscore
.venv/Scripts/python -m safecampus.edge run --day 3       # gateway -> results/edge/
```

## Módulos

| Archivo | Rol |
|---|---|
| `safecampus/inventory.py` | Hosts, IPs, VLANs, roles y puerto de switch, leídos de `infra/iot_safecampus_plan.json` |
| `safecampus/generator.py` | Flujos NetFlow sintéticos etiquetados: tráfico normal por perfil + 6 escenarios de ataque |
| `safecampus/features.py` | Características por flujo y por ventana de 1 y 10 min por host (las mismas offline y en el edge) |
| `safecampus/models.py` | Detectores: z-score por perfil, Isolation Forest, autoencoder, árbol, híbrido, RF 300, MLP profunda |
| `safecampus/experiment.py` | Protocolo, métricas de seguridad, operativas y de recursos, figuras |
| `safecampus/edge.py` | Gateway: extractor → modelo → alertas → aislamiento (VLAN 99) → tablero HTML |

## Protocolo

Cada semilla genera 4 días:

- **Día 0:** solo tráfico normal; entrena los modelos no supervisados.
- **Día 1:** solo tráfico normal; calibra el umbral para un FPR objetivo de 0.5 %.
- **Días 0 + 2:** entrenan los modelos supervisados (el día 2 ya trae ataques).
- **Día 3:** prueba común, con variantes de cada ataque más una **exfiltración que nunca aparece en entrenamiento**.

Los recursos se miden con un solo hilo de BLAS. La energía es aproximada: tiempo
de CPU × 5 W, que es el supuesto para un gateway tipo Raspberry Pi 4.

## Validación externa: NF-ToN-IoT-v3

Dataset NetFlow con marcas de tiempo (Luay et al., 2025, UQ, doi:10.48610/44d7c5e;
27.5 M flujos). Descárgalo desde el navegador en https://espace.library.uq.edu.au/view/UQ:44d7c5e
(el servidor bloquea descargas automáticas) y guárdalo en `data/external/`.

```bash
.venv/Scripts/python -m safecampus.nf3 profile          # conteos por día / bloque de 10 min / clase
.venv/Scripts/python -m safecampus.nf3 build            # subconjunto por bloques completos -> data/nf3_subset.pkl
.venv/Scripts/python -m safecampus.nf3 run --seeds 5    # -> results/nf3/
```

Se seleccionan bloques completos de 10 min, no flujos sueltos, para no romper las
ventanas por host. El protocolo replica el sintético: los días benignos (salvo el
último) entrenan los no supervisados, el último día benigno calibra, los primeros
días con ataque entrenan los supervisados y los restantes forman la prueba. Como
el dataset no trae inventario, los perfiles son `internal`/`external` (RFC 1918).

## Limitaciones

El tráfico es sintético: está calibrado con la topología real, pero no capturado.
Antes de publicar, los resultados deben validarse con un dataset público de IoT
(p. ej. CIC-IoT2023 o TON_IoT) y, si es posible, con capturas de un laboratorio físico.
