"""Geolocalización de IPs por país, sin consultar servicios externos al analizar.

Usa la base gratuita "IP to Country Lite" de DB-IP (licencia CC BY 4.0, se actualiza cada
mes). Se descarga una vez con  python main.py actualizar-geoip  y se convierte a un archivo
binario compacto que se consulta en memoria (búsqueda binaria, microsegundos por IP).

Atribución requerida por la licencia: "IP Geolocation by DB-IP" (https://db-ip.com).
"""

from __future__ import annotations

import csv
import gzip
import io
import ipaddress
import logging
import struct
import urllib.request
from datetime import date
from pathlib import Path

from .config import DIR_DATOS

log = logging.getLogger(__name__)
CABECERA = b"CGEO1"
ATRIBUCION = "IP Geolocation by DB-IP"
URL_DBIP = "https://download.db-ip.com/free/dbip-country-lite-{anio}-{mes:02d}.csv.gz"
TAM4, TAM6 = 10, 34  # bytes por rango: inicio + fin + código de país (2)


class BaseGeo:
    def __init__(self, v4: bytes, v6: bytes) -> None:
        self.v4, self.v6 = v4, v6

    @property
    def rangos(self) -> int:
        return len(self.v4) // TAM4 + len(self.v6) // TAM6

    def pais(self, ip_texto: str | None) -> str | None:
        if not ip_texto:
            return None
        try:
            ip = ipaddress.ip_address(ip_texto)
        except ValueError:
            return None
        datos, tam, ancho = (self.v4, TAM4, 4) if ip.version == 4 else (self.v6, TAM6, 16)
        valor = int(ip)
        bajo, alto = 0, len(datos) // tam - 1
        while bajo <= alto:
            medio = (bajo + alto) // 2
            base = medio * tam
            inicio = int.from_bytes(datos[base:base + ancho], "big")
            if valor < inicio:
                alto = medio - 1
                continue
            fin = int.from_bytes(datos[base + ancho:base + 2 * ancho], "big")
            if valor > fin:
                bajo = medio + 1
                continue
            codigo = datos[base + 2 * ancho:base + tam].decode("ascii")
            return None if codigo in ("ZZ", "--") else codigo
        return None


def convertir(filas) -> tuple[bytes, bytes]:
    """filas: iterable de (ip_inicio, ip_fin, código). Devuelve los bloques binarios ordenados."""
    v4, v6 = [], []
    for fila in filas:
        if len(fila) < 3 or not fila[2].strip():
            continue
        try:
            inicio, fin = ipaddress.ip_address(fila[0].strip()), ipaddress.ip_address(fila[1].strip())
        except ValueError:
            continue
        codigo = fila[2].strip().upper()[:2].encode("ascii", "replace").ljust(2, b"-")
        (v4 if inicio.version == 4 else v6).append((int(inicio), int(fin), codigo))
    v4.sort()
    v6.sort()
    b4 = b"".join(i.to_bytes(4, "big") + f.to_bytes(4, "big") + c for i, f, c in v4)
    b6 = b"".join(i.to_bytes(16, "big") + f.to_bytes(16, "big") + c for i, f, c in v6)
    return b4, b6


def guardar(ruta: Path, v4: bytes, v6: bytes) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    temporal = ruta.with_suffix(".tmp")
    temporal.write_bytes(CABECERA + struct.pack(">II", len(v4), len(v6)) + v4 + v6)
    temporal.replace(ruta)


_cache: dict[Path, tuple[float, BaseGeo]] = {}


def cargar(ruta: Path) -> BaseGeo | None:
    """Carga la base (binaria o CSV pequeño). Se cachea y se recarga si el archivo cambia."""
    if not ruta.exists():
        return None
    mtime = ruta.stat().st_mtime
    guardado = _cache.get(ruta)
    if guardado and guardado[0] == mtime:
        return guardado[1]
    try:
        if ruta.suffix == ".csv":
            with ruta.open(encoding="utf-8") as archivo:
                v4, v6 = convertir(csv.reader(l for l in archivo if l.strip() and not l.startswith("#")))
        else:
            datos = ruta.read_bytes()
            if not datos.startswith(CABECERA):
                raise ValueError("formato desconocido")
            n4, n6 = struct.unpack(">II", datos[5:13])
            v4, v6 = datos[13:13 + n4], datos[13 + n4:13 + n4 + n6]
    except Exception as error:
        log.error("No se pudo cargar la base de geolocalización %s: %s", ruta, error)
        return None
    base = BaseGeo(v4, v6)
    _cache[ruta] = (mtime, base)
    return base


def actualizar(ruta: Path | None = None) -> dict:
    """Descarga la base mensual de DB-IP (prueba el mes actual y los dos anteriores)."""
    ruta = ruta or DIR_DATOS / "geoip" / "ip-pais.bin"
    hoy = date.today()
    errores = []
    for atras in range(3):
        anio, mes = hoy.year, hoy.month - atras
        while mes < 1:
            anio, mes = anio - 1, mes + 12
        url = URL_DBIP.format(anio=anio, mes=mes)
        try:
            peticion = urllib.request.Request(url, headers={"User-Agent": "MailSentry-Phishing-Detector/1.0"})
            with urllib.request.urlopen(peticion, timeout=120) as respuesta:
                comprimido = respuesta.read(200 * 1024 * 1024)
        except Exception as error:
            errores.append(f"{url}: {error}")
            continue
        with gzip.open(io.BytesIO(comprimido), "rt", encoding="utf-8") as texto:
            v4, v6 = convertir(csv.reader(texto))
        guardar(ruta, v4, v6)
        return {"url": url, "rangos": len(v4) // TAM4 + len(v6) // TAM6, "archivo": str(ruta),
                "tamano_kb": ruta.stat().st_size // 1024}
    raise RuntimeError("No se pudo descargar la base de DB-IP:\n  " + "\n  ".join(errores))
