"""Utilidades generales: tiempo, normalización de texto y 'desarmado' de URLs."""

from __future__ import annotations

import re
import unicodedata
from datetime import datetime, timedelta, timezone, tzinfo
from functools import lru_cache
from urllib.parse import urlsplit


def ahora() -> datetime:
    """Hora actual en UTC, sin zona (así se guarda en la base de datos)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


@lru_cache(maxsize=8)
def zona(nombre: str) -> tzinfo:
    try:
        from zoneinfo import ZoneInfo

        return ZoneInfo(nombre)
    except Exception:  # sin base de zonas horarias: Perú no tiene horario de verano
        return timezone(timedelta(hours=-5))


def a_local(dt: datetime | None, tz: tzinfo) -> datetime | None:
    if dt is None:
        return None
    return dt.replace(tzinfo=timezone.utc).astimezone(tz)


def normalizar(texto: str) -> str:
    """Minúsculas, sin tildes y con espacios colapsados (para comparar frases)."""
    if not texto:
        return ""
    texto = unicodedata.normalize("NFKD", texto)
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", texto.lower()).strip()


def desarmar_url(url: str) -> str:
    """Convierte una URL en texto no clicable (hxxps://dominio[.]com/...)."""
    if not url:
        return ""
    try:
        partes = urlsplit(url)
    except ValueError:
        return url.replace(".", "[.]")
    esquema = partes.scheme.replace("http", "hxxp") if partes.scheme else ""
    host = (partes.netloc or "").replace(".", "[.]")
    resto = partes.path + (f"?{partes.query}" if partes.query else "")
    if not partes.netloc:
        return url.replace("http", "hxxp").replace(".", "[.]")
    return f"{esquema}://{host}{resto}"


def desarmar_texto(texto: str) -> str:
    """Desarma todas las URLs dentro de un texto."""
    return re.sub(r"https?://[^\s<>\"')\]]+", lambda m: desarmar_url(m.group(0)), texto or "")


def recortar(texto: str, largo: int) -> str:
    texto = texto or ""
    return texto if len(texto) <= largo else texto[: largo - 1] + "…"
