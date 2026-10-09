"""Bucle de vigilancia de todos los buzones configurados."""

from __future__ import annotations

import logging
import threading

from ..config import Config
from . import graph, imap

log = logging.getLogger(__name__)
_candado = threading.Lock()


def revisar_todos(config: Config) -> list[dict]:
    """Revisa todos los buzones activos una vez. Evita revisiones simultáneas."""
    if not _candado.acquire(blocking=False):
        return [{"buzon": "*", "error": "Ya hay una revisión en curso"}]
    try:
        resultados = []
        for buzon in config.buzones:
            if not buzon.activo:
                continue
            modulo = graph if buzon.conexion == "graph" else imap
            resultado = modulo.revisar(buzon, config)
            log.info("Buzón %s: %s nuevos, %s amenazas", buzon.nombre, resultado["procesados"], resultado["amenazas"])
            resultados.append(resultado)
        return resultados
    finally:
        _candado.release()


def bucle(config: Config, detener: threading.Event) -> None:
    if not config.buzones:
        log.info("No hay buzones configurados en config.toml; la vigilancia automática está inactiva.")
        detener.set()
        return
    log.info("Vigilando %d buzón(es) cada %d s", len(config.buzones), config.intervalo_buzones)
    while not detener.is_set():
        try:
            revisar_todos(config)
        except Exception:
            log.exception("Error inesperado al revisar buzones")
        detener.wait(config.intervalo_buzones)


_activo: threading.Event | None = None


def iniciar_en_segundo_plano(config: Config) -> threading.Event:
    """Arranca la vigilancia periódica una sola vez (se puede llamar de nuevo al agregar un buzón)."""
    global _activo
    if _activo is not None and not _activo.is_set():
        return _activo
    _activo = threading.Event()
    threading.Thread(target=bucle, args=(config, _activo), name="vigilante", daemon=True).start()
    return _activo


def vigilando() -> bool:
    return _activo is not None and not _activo.is_set()
