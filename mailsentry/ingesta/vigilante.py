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
        return
    log.info("Vigilando %d buzón(es) cada %d s", len(config.buzones), config.intervalo_buzones)
    while not detener.is_set():
        try:
            revisar_todos(config)
        except Exception:
            log.exception("Error inesperado al revisar buzones")
        detener.wait(config.intervalo_buzones)


def iniciar_en_segundo_plano(config: Config) -> threading.Event:
    detener = threading.Event()
    threading.Thread(target=bucle, args=(config, detener), name="vigilante", daemon=True).start()
    return detener
