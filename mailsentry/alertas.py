"""Alertas en tiempo real por webhook (Microsoft Teams, Slack, Discord o Google Chat)."""

from __future__ import annotations

import json
import logging
import threading
import urllib.request

from .config import NIVELES, Config
from .deteccion.modelos import CATEGORIAS, NIVELES as NOMBRES_NIVEL

log = logging.getLogger(__name__)


def _enviar(url: str, texto: str) -> None:
    # "text" lo entienden Teams, Slack y Google Chat; "content" lo usa Discord
    cuerpo = json.dumps({"text": texto, "content": texto}).encode("utf-8")
    peticion = urllib.request.Request(url, data=cuerpo, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(peticion, timeout=15).close()
    except Exception as error:
        log.warning("No se pudo enviar la alerta por webhook: %s", error)


def notificar(correo, config: Config) -> None:
    if not config.webhook_url:
        return
    if NIVELES.index(correo.nivel_riesgo) < NIVELES.index(config.alerta_nivel_minimo):
        return
    texto = (
        f"🚨 MailSentry · {config.empresa_nombre}\n"
        f"Riesgo {NOMBRES_NIVEL[correo.nivel_riesgo].upper()} ({correo.puntaje}/100) · {CATEGORIAS[correo.categoria]}\n"
        f"De: {correo.remitente_nombre} <{correo.remitente_email}>\n"
        f"Para: {correo.destinatario_principal}\n"
        f"Asunto: {correo.asunto[:150]}\n"
        f"Revise el correo #{correo.id} en el panel de MailSentry."
    )
    threading.Thread(target=_enviar, args=(config.webhook_url, texto), daemon=True).start()
