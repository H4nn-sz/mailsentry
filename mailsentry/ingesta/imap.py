"""Vigilancia de buzones por IMAP (Gmail/Google Workspace, hosting cPanel, Zoho, Yahoo...).

Lee los correos sin marcarlos como leídos (BODY.PEEK) y recuerda el último UID
procesado. Solo mueve correos si se configura una carpeta de cuarentena.
"""

from __future__ import annotations

import imaplib
import logging
import re
import ssl
from datetime import timedelta

from sqlalchemy import select

from .. import db
from ..config import Buzon, Config
from ..db import EstadoBuzon
from ..servicio import construir_contexto, procesar_desde_buzon
from ..util import ahora

log = logging.getLogger(__name__)
MESES = ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")


def _carpeta(nombre: str) -> str:
    return f'"{nombre}"' if " " in nombre and not nombre.startswith('"') else nombre


def _uidvalidity(conexion: imaplib.IMAP4) -> int | None:
    _, datos = conexion.response("UIDVALIDITY")
    try:
        return int(datos[0]) if datos and datos[0] else None
    except (TypeError, ValueError):
        return None


def revisar(buzon: Buzon, config: Config) -> dict:
    """Procesa los correos nuevos de un buzón. Devuelve un resumen de la revisión."""
    resumen = {"buzon": buzon.nombre, "procesados": 0, "amenazas": 0, "movidos": 0, "error": None}
    if not buzon.password:
        resumen["error"] = f"Falta la contraseña (variable de entorno {buzon.password_env})"
        _guardar_estado(buzon.nombre, error=resumen["error"])
        return resumen

    try:
        with imaplib.IMAP4_SSL(buzon.servidor, buzon.puerto, ssl_context=ssl.create_default_context(), timeout=60) as m:
            m.login(buzon.usuario, buzon.password)
            tipo, _ = m.select(_carpeta(buzon.carpeta), readonly=not buzon.cuarentena)
            if tipo != "OK":
                raise RuntimeError(f"No se pudo abrir la carpeta {buzon.carpeta}")
            validez = _uidvalidity(m)

            with db.sesion() as s:
                estado = s.get(EstadoBuzon, buzon.nombre) or EstadoBuzon(nombre=buzon.nombre, ultimo_uid=0)
                primera_vez = estado.uidvalidity is None or estado.uidvalidity != validez
                ultimo = 0 if primera_vez else estado.ultimo_uid
                ctx = construir_contexto(s, config)

            if primera_vez:
                desde = ahora() - timedelta(days=config.historial_inicial_dias)
                criterio = f"SINCE {desde.day:02d}-{MESES[desde.month - 1]}-{desde.year}"
                _, datos = m.uid("SEARCH", None, criterio)
            else:
                _, datos = m.uid("SEARCH", None, f"UID {ultimo + 1}:*")
            uids = sorted(int(u) for u in (datos[0] or b"").split() if int(u) > ultimo)[: config.lote_maximo]

            puede_mover = bool(buzon.cuarentena) and "MOVE" in m.capabilities
            for uid in uids:
                _, partes = m.uid("FETCH", str(uid), "(BODY.PEEK[])")
                crudo = next((p[1] for p in partes if isinstance(p, tuple) and len(p) > 1), None)
                if crudo:
                    for p in procesar_desde_buzon(crudo, config, buzon=buzon, ctx=ctx, fuente="imap"):
                        resumen["procesados"] += int(p.nuevo)
                        if p.correo.veredicto_efectivo == "phishing":
                            resumen["amenazas"] += 1
                            if puede_mover and buzon.tipo == "entrada":
                                tipo, _ = m.uid("MOVE", str(uid), _carpeta(buzon.cuarentena))
                                resumen["movidos"] += int(tipo == "OK")
                ultimo = max(ultimo, uid)

            _guardar_estado(buzon.nombre, uidvalidity=validez, ultimo_uid=ultimo, procesados=resumen["procesados"])
    except (imaplib.IMAP4.error, OSError, RuntimeError) as error:
        mensaje = re.sub(r"\s+", " ", str(error))[:500]
        log.error("Buzón %s: %s", buzon.nombre, mensaje)
        resumen["error"] = mensaje
        _guardar_estado(buzon.nombre, error=mensaje)
    return resumen


def _guardar_estado(nombre: str, *, uidvalidity=None, ultimo_uid=None, procesados: int = 0,
                    cursor_fecha: str | None = None, error: str | None = None) -> None:
    with db.sesion() as s:
        estado = s.get(EstadoBuzon, nombre)
        if estado is None:
            estado = EstadoBuzon(nombre=nombre, ultimo_uid=0, total_procesados=0)
            s.add(estado)
        if uidvalidity is not None:
            estado.uidvalidity = uidvalidity
        if ultimo_uid is not None:
            estado.ultimo_uid = ultimo_uid
        if cursor_fecha is not None:
            estado.cursor_fecha = cursor_fecha
        estado.total_procesados = (estado.total_procesados or 0) + procesados
        estado.ultima_revision = ahora()
        estado.ultimo_error = error
        s.commit()


def estados() -> dict[str, EstadoBuzon]:
    with db.sesion() as s:
        return {e.nombre: e for e in s.scalars(select(EstadoBuzon))}
