"""Vigilancia de buzones Microsoft 365 / Exchange Online vía Microsoft Graph.

Microsoft desactivó la autenticación básica por IMAP, así que para Microsoft 365
se usa una aplicación registrada en Azure (Entra ID) con el permiso de aplicación
Mail.Read (Mail.ReadWrite si se quiere mover a cuarentena) y un secreto de cliente.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import timedelta

from .. import db
from ..config import Buzon, Config
from ..db import EstadoBuzon
from ..servicio import construir_contexto, procesar_desde_buzon
from ..util import ahora
from .imap import _guardar_estado

log = logging.getLogger(__name__)
GRAPH = "https://graph.microsoft.com/v1.0"
_tokens: dict[str, tuple[float, str]] = {}


def _token(buzon: Buzon) -> str:
    clave = f"{buzon.tenant_id}:{buzon.client_id}"
    guardado = _tokens.get(clave)
    if guardado and guardado[0] > time.time() + 60:
        return guardado[1]
    cuerpo = urllib.parse.urlencode({
        "client_id": buzon.client_id,
        "client_secret": buzon.secreto,
        "scope": "https://graph.microsoft.com/.default",
        "grant_type": "client_credentials",
    }).encode()
    url = f"https://login.microsoftonline.com/{urllib.parse.quote(buzon.tenant_id)}/oauth2/v2.0/token"
    with urllib.request.urlopen(urllib.request.Request(url, data=cuerpo), timeout=30) as r:
        datos = json.loads(r.read())
    _tokens[clave] = (time.time() + int(datos.get("expires_in", 3600)), datos["access_token"])
    return datos["access_token"]


def _pedir(buzon: Buzon, url: str, *, metodo: str = "GET", cuerpo: dict | None = None, crudo: bool = False):
    datos = json.dumps(cuerpo).encode() if cuerpo is not None else None
    peticion = urllib.request.Request(url, data=datos, method=metodo, headers={
        "Authorization": f"Bearer {_token(buzon)}",
        "Content-Type": "application/json",
    })
    with urllib.request.urlopen(peticion, timeout=60) as r:
        contenido = r.read()
    return contenido if crudo else (json.loads(contenido) if contenido else {})


def revisar(buzon: Buzon, config: Config) -> dict:
    resumen = {"buzon": buzon.nombre, "procesados": 0, "amenazas": 0, "movidos": 0, "error": None}
    if not (buzon.tenant_id and buzon.client_id and buzon.secreto):
        resumen["error"] = f"Faltan tenant_id, client_id o el secreto (variable {buzon.secret_env})"
        _guardar_estado(buzon.nombre, error=resumen["error"])
        return resumen

    usuario = urllib.parse.quote(buzon.usuario)
    carpeta = urllib.parse.quote(buzon.carpeta if buzon.carpeta.upper() != "INBOX" else "inbox")
    try:
        with db.sesion() as s:
            estado = s.get(EstadoBuzon, buzon.nombre)
            cursor = estado.cursor_fecha if estado and estado.cursor_fecha else None
            ctx = construir_contexto(s, config)
        if not cursor:
            cursor = (ahora() - timedelta(days=config.historial_inicial_dias)).strftime("%Y-%m-%dT%H:%M:%SZ")

        consulta = urllib.parse.urlencode({
            "$select": "id,receivedDateTime",
            "$filter": f"receivedDateTime gt {cursor}",
            "$orderby": "receivedDateTime asc",
            "$top": "50",
        }, safe="$,:", quote_via=urllib.parse.quote)
        url = f"{GRAPH}/users/{usuario}/mailFolders/{carpeta}/messages?{consulta}"
        while url and resumen["procesados"] < config.lote_maximo:
            pagina = _pedir(buzon, url)
            for mensaje in pagina.get("value", []):
                crudo = _pedir(buzon, f"{GRAPH}/users/{usuario}/messages/{mensaje['id']}/$value", crudo=True)
                for p in procesar_desde_buzon(crudo, config, buzon=buzon, ctx=ctx, fuente="graph"):
                    resumen["procesados"] += int(p.nuevo)
                    if p.correo.veredicto_efectivo == "phishing":
                        resumen["amenazas"] += 1
                        if buzon.cuarentena and buzon.tipo == "entrada":
                            try:
                                _pedir(buzon, f"{GRAPH}/users/{usuario}/messages/{mensaje['id']}/move",
                                       metodo="POST", cuerpo={"destinationId": buzon.cuarentena})
                                resumen["movidos"] += 1
                            except urllib.error.HTTPError as error:
                                log.warning("No se pudo mover a cuarentena: %s", error)
                cursor = mensaje["receivedDateTime"]
            url = pagina.get("@odata.nextLink")
        _guardar_estado(buzon.nombre, cursor_fecha=cursor, procesados=resumen["procesados"])
    except urllib.error.HTTPError as error:
        detalle = error.read().decode("utf-8", errors="ignore")[:300]
        resumen["error"] = f"Graph HTTP {error.code}: {detalle}"
        _guardar_estado(buzon.nombre, error=resumen["error"])
    except Exception as error:
        resumen["error"] = str(error)[:500]
        _guardar_estado(buzon.nombre, error=resumen["error"])
    if resumen["error"]:
        log.error("Buzón %s: %s", buzon.nombre, resumen["error"])
    return resumen
