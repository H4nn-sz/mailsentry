"""Inteligencia de amenazas: listas públicas de phishing (feeds) y VirusTotal (opcional)."""

from __future__ import annotations

import json
import logging
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from ..config import DIR_DATOS
from .datos import ACORTADORES, HOSTING_ABUSADO
from .dominios import dominio_registrable, es_subdominio_de, host_de_url

log = logging.getLogger(__name__)
DIR_FEEDS = DIR_DATOS / "feeds"
USER_AGENT = "MailSentry-Phishing-Detector/1.0"

# Plataformas compartidas: un feed puede listar una página concreta, pero nunca el host entero
PLATAFORMAS_COMPARTIDAS = {
    "google.com", "googleapis.com", "microsoft.com", "live.com", "sharepoint.com", "dropbox.com",
    "github.com", "githubusercontent.com", "amazonaws.com", "windows.net", "wetransfer.com",
    "forms.gle", "1drv.ms", "office.com", "linkedin.com", "facebook.com", "notion.site",
}


@dataclass
class Feeds:
    hosts: set[str] = field(default_factory=set)
    urls: set[str] = field(default_factory=set)

    def __len__(self) -> int:
        return len(self.urls) + len(self.hosts)

    def contiene(self, url: str) -> bool:
        if url.rstrip("/").lower() in self.urls:
            return True
        host = host_de_url(url)
        if not host or host not in self.hosts:
            return False
        if host in ACORTADORES or dominio_registrable(host) in PLATAFORMAS_COMPARTIDAS:
            return False
        return not any(host == h for h in HOSTING_ABUSADO)


_cache: tuple[tuple, Feeds] | None = None


def cargar_feeds(directorio: Path = DIR_FEEDS) -> Feeds:
    """Carga los archivos .txt de data/feeds (una URL o dominio por línea). Se cachea por fecha."""
    global _cache
    archivos = sorted(directorio.glob("*.txt")) if directorio.exists() else []
    firma = tuple((a.name, a.stat().st_mtime) for a in archivos)
    if _cache and _cache[0] == firma:
        return _cache[1]
    feeds = Feeds()
    for archivo in archivos:
        for linea in archivo.read_text(encoding="utf-8", errors="ignore").splitlines():
            linea = linea.strip()
            if not linea or linea.startswith("#"):
                continue
            if "://" in linea:
                feeds.urls.add(linea.rstrip("/").lower())
                host = host_de_url(linea)
            else:
                host = linea.lower()
            if host:
                feeds.hosts.add(host)
    _cache = (firma, feeds)
    return feeds


def actualizar_feeds(urls: list[str], directorio: Path = DIR_FEEDS) -> dict[str, str]:
    """Descarga las listas configuradas. Devuelve {url: resultado}."""
    directorio.mkdir(parents=True, exist_ok=True)
    resultados = {}
    for url in urls:
        nombre = re.sub(r"[^a-z0-9]+", "_", url.lower().split("://", 1)[-1]).strip("_")[:80] + ".txt"
        try:
            peticion = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
            with urllib.request.urlopen(peticion, timeout=60) as respuesta:
                contenido = respuesta.read(50 * 1024 * 1024).decode("utf-8", errors="ignore")
            lineas = [l for l in contenido.splitlines() if l.strip() and not l.startswith("#")]
            (directorio / nombre).write_text("\n".join(lineas), encoding="utf-8")
            resultados[url] = f"{len(lineas)} entradas"
        except Exception as error:  # red caída, feed movido, etc.
            resultados[url] = f"error: {error}"
    return resultados


class VirusTotal:
    """Consulta de reputación de dominios (API v3). Cuota gratuita: 4 consultas/minuto."""

    BASE = "https://www.virustotal.com/api/v3"
    TTL = 24 * 3600

    def __init__(self, api_key: str) -> None:
        self.api_key = api_key
        self._cache: dict[str, tuple[float, int | None]] = {}

    def dominio_malicioso(self, dominio: str) -> int | None:
        """Número de motores que marcan el dominio como malicioso (None si no se pudo consultar)."""
        dominio = dominio_registrable(dominio)
        en_cache = self._cache.get(dominio)
        if en_cache and time.time() - en_cache[0] < self.TTL:
            return en_cache[1]
        peticion = urllib.request.Request(
            f"{self.BASE}/domains/{dominio}", headers={"x-apikey": self.api_key, "User-Agent": USER_AGENT}
        )
        try:
            with urllib.request.urlopen(peticion, timeout=10) as respuesta:
                datos = json.loads(respuesta.read())
            valor = int(datos["data"]["attributes"]["last_analysis_stats"].get("malicious", 0))
        except urllib.error.HTTPError as error:
            valor = 0 if error.code == 404 else None
            if error.code == 429:
                log.warning("VirusTotal: cuota agotada")
        except Exception as error:
            log.warning("VirusTotal no disponible: %s", error)
            valor = None
        self._cache[dominio] = (time.time(), valor)
        return valor


def es_plataforma_compartida(host: str) -> bool:
    return dominio_registrable(host) in PLATAFORMAS_COMPARTIDAS or any(es_subdominio_de(host, h) for h in HOSTING_ABUSADO)
