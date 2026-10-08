"""Genera los puntos de tierra firme del globo del panel (mailsentry/web/static/js/tierra.js).

Entrada: land-110m.json del paquete npm world-atlas (Natural Earth, dominio público).
Uso:     python herramientas/generar_tierra.py ruta/land-110m.json

Se ejecuta una sola vez: el resultado (puntos codificados por filas) queda dentro del
proyecto, así el panel funciona sin internet.
"""

from __future__ import annotations

import json
import math
import sys
from pathlib import Path

import numpy as np

PASO = 1.0  # grados entre puntos (aprox. 111 km)
SALIDA = Path(__file__).resolve().parent.parent / "mailsentry" / "web" / "static" / "js" / "tierra.js"


def anillos(topologia: dict) -> list[np.ndarray]:
    escala = topologia["transform"]["scale"]
    traslado = topologia["transform"]["translate"]
    arcos = []
    for arco in topologia["arcs"]:
        acumulado = np.cumsum(np.array(arco, dtype=float), axis=0)
        arcos.append(acumulado * escala + traslado)

    def arco(i: int) -> np.ndarray:
        return arcos[i] if i >= 0 else arcos[~i][::-1]

    resultado = []
    for geometria in topologia["objects"]["land"]["geometries"]:
        poligonos = geometria["arcs"] if geometria["type"] == "MultiPolygon" else [geometria["arcs"]]
        for poligono in poligonos:
            for anillo in poligono:
                partes = [arco(i) if n == 0 else arco(i)[1:] for n, i in enumerate(anillo)]
                resultado.append(np.concatenate(partes))
    return resultado


def main(ruta: str) -> None:
    topologia = json.loads(Path(ruta).read_text(encoding="utf-8"))
    lista_anillos = anillos(topologia)

    filas = []  # (lat, n_celdas)
    lons, lats, fila_de = [], [], []
    for i, lat in enumerate(np.arange(-90 + PASO / 2, 90, PASO)):
        n = max(1, round(360 * math.cos(math.radians(lat)) / PASO))
        filas.append((float(lat), n))
        for j in range(n):
            lons.append(-180 + (j + 0.5) * 360 / n)
            lats.append(lat)
            fila_de.append((i, j))
    px, py = np.array(lons), np.array(lats)
    dentro = np.zeros(len(px), dtype=bool)

    for anillo in lista_anillos:
        x, y = anillo[:, 0], anillo[:, 1]
        candidatos = np.nonzero((px >= x.min()) & (px <= x.max()) & (py >= y.min()) & (py <= y.max()))[0]
        if not len(candidatos):
            continue
        cx, cy = px[candidatos][:, None], py[candidatos][:, None]
        x1, y1, x2, y2 = x[:-1], y[:-1], x[1:], y[1:]
        cruza = (y1 > cy) != (y2 > cy)
        with np.errstate(divide="ignore", invalid="ignore"):
            corte = (x2 - x1) * (cy - y1) / (y2 - y1) + x1
        impar = (np.sum(cruza & (cx < corte), axis=1) % 2) == 1
        dentro[candidatos] ^= impar  # par/impar entre anillos: los huecos (lagos) quedan fuera

    # Codificación por filas: [índice_fila, celdas, inicio, largo, inicio, largo, ...]
    salida = []
    total = 0
    por_fila: dict[int, list[int]] = {}
    for (i, j), es_tierra in zip(fila_de, dentro):
        if es_tierra:
            por_fila.setdefault(i, []).append(j)
    for i, columnas in sorted(por_fila.items()):
        tramos = []
        inicio = previo = columnas[0]
        for c in columnas[1:] + [None]:
            if c is not None and c == previo + 1:
                previo = c
                continue
            tramos += [inicio, previo - inicio + 1]
            if c is not None:
                inicio = previo = c
        salida.append([i, filas[i][1], *tramos])
        total += len(columnas)

    SALIDA.parent.mkdir(parents=True, exist_ok=True)
    SALIDA.write_text(
        "// Generado por herramientas/generar_tierra.py a partir de Natural Earth (dominio público).\n"
        f"window.MAILSENTRY_TIERRA = {{paso: {PASO}, filas: {json.dumps(salida, separators=(',', ':'))}}};\n",
        encoding="utf-8",
    )
    print(f"{total} puntos de tierra en {len(salida)} filas -> {SALIDA} ({SALIDA.stat().st_size // 1024} KB)")


if __name__ == "__main__":
    main(sys.argv[1])
