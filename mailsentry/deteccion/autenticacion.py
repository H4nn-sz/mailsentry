"""Capa 1: autenticación del remitente (SPF, DKIM, DMARC)."""

from __future__ import annotations

from ..parser import CorreoParseado
from .contexto import Contexto
from .modelos import Indicador

SUPLANTACION = {"bec": 0.4, "suplantacion_marca": 0.3, "credenciales": 0.3}


def analizar(correo: CorreoParseado, ctx: Contexto) -> list[Indicador]:
    auth = correo.autenticacion
    indicadores: list[Indicador] = []
    if not auth:
        indicadores.append(Indicador(
            "AUTH_SIN_DATOS", "Sin resultados de autenticación",
            "El correo no trae cabeceras SPF/DKIM/DMARC (p. ej. archivo subido manualmente); "
            "no se pudo verificar al remitente.", 0, "info"))
        return indicadores

    if auth.get("dmarc") == "fail":
        indicadores.append(Indicador(
            "AUTH_DMARC_FALLA", "Falla DMARC",
            f"El dominio {correo.remitente_dominio} no autoriza este envío (dmarc=fail): "
            "es muy probable que el remitente esté falsificado.", 25, "alta", SUPLANTACION))
    spf = auth.get("spf")
    if spf == "fail":
        indicadores.append(Indicador(
            "AUTH_SPF_FALLA", "Falla SPF",
            "El servidor que envió el correo no está autorizado por el dominio remitente (spf=fail).",
            15, "alta", SUPLANTACION))
    elif spf == "softfail":
        indicadores.append(Indicador(
            "AUTH_SPF_SOFTFAIL", "SPF dudoso (softfail)",
            "El dominio remitente no reconoce del todo al servidor de envío (spf=softfail).", 8, "media", SUPLANTACION))
    if auth.get("dkim") == "fail":
        indicadores.append(Indicador(
            "AUTH_DKIM_FALLA", "Firma DKIM inválida",
            "La firma digital del correo no es válida: pudo ser alterado o falsificado.", 10, "media", SUPLANTACION))
    if all(auth.get(m) == "pass" for m in ("spf", "dkim", "dmarc")):
        indicadores.append(Indicador(
            "AUTH_OK", "Autenticación correcta",
            f"SPF, DKIM y DMARC válidos para {correo.remitente_dominio}. Ojo: solo prueba que el correo "
            "viene de ese dominio, no que el dominio sea confiable.", 0, "info"))
    return indicadores
