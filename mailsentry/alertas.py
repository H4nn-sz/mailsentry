"""Alertas en tiempo real por webhook (n8n, Microsoft Teams, Slack, Discord o Google Chat)."""

from __future__ import annotations

import json
import logging
import threading
import urllib.request

from .config import NIVELES, Config
from .deteccion.modelos import CATEGORIAS, NIVELES as NOMBRES_NIVEL

log = logging.getLogger(__name__)


def _enviar(url: str, cuerpo: dict) -> None:
    peticion = urllib.request.Request(url, data=json.dumps(cuerpo).encode("utf-8"),
                                      headers={"Content-Type": "application/json"})
    urllib.request.urlopen(peticion, timeout=15).close()


def _enviar_sin_fallar(url: str, cuerpo: dict) -> None:
    try:
        _enviar(url, cuerpo)
    except Exception as error:
        log.warning("No se pudo enviar la alerta por webhook: %s", error)


def _cuerpo(texto: str, **datos) -> dict:
    # "text" lo entienden Teams, Slack y Google Chat; "content" lo usa Discord.
    # El resto de campos son para n8n y otras automatizaciones: llegan ya separados, sin tener que leer el texto.
    return {"text": texto, "content": texto, **datos}


def _con_ajustes_del_panel(config: Config) -> Config:
    """La vigilancia en segundo plano recibe la configuración del archivo; el webhook se guarda desde el panel."""
    try:
        from . import db

        with db.sesion() as s:
            return config.con_ajustes(db.leer_ajustes(s))
    except Exception:
        return config


def notificar(correo, config: Config) -> None:
    config = _con_ajustes_del_panel(config)
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
    cuerpo = _cuerpo(
        texto, evento="phishing_detectado", empresa=config.empresa_nombre, correo_id=correo.id,
        nivel=correo.nivel_riesgo, puntaje=correo.puntaje, categoria=correo.categoria,
        categoria_nombre=CATEGORIAS[correo.categoria], remitente_nombre=correo.remitente_nombre,
        remitente_email=correo.remitente_email, destinatario=correo.destinatario_principal,
        asunto=correo.asunto[:300], buzon=getattr(correo, "buzon", ""),
    )
    threading.Thread(target=_enviar_sin_fallar, args=(config.webhook_url, cuerpo), daemon=True).start()


def enviar_prueba(config: Config) -> tuple[bool, str]:
    """Manda un aviso de ejemplo y dice si el destino lo recibió (para el botón «Enviar prueba»)."""
    if not config.webhook_url:
        return False, "Primero guarde la dirección del webhook."
    cuerpo = _cuerpo(
        f"✅ MailSentry · {config.empresa_nombre}\nPrueba de conexión: las alertas de phishing llegarán aquí.",
        evento="prueba", empresa=config.empresa_nombre, nivel="critico", puntaje=0, categoria="prueba",
        categoria_nombre="Prueba de conexión", remitente_nombre="MailSentry", remitente_email="prueba@mailsentry.local",
        destinatario="", asunto="Mensaje de prueba", correo_id=0, buzon="",
    )
    try:
        _enviar(config.webhook_url, cuerpo)
    except Exception as error:
        return False, f"No se pudo entregar: {error}"
    return True, "Prueba enviada. Revise que haya llegado a su flujo de n8n."
