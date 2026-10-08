"""Capa 4: contenido del mensaje (lenguaje de ingeniería social y estructura HTML)."""

from __future__ import annotations

import re
from functools import lru_cache

from ..parser import CorreoParseado
from ..util import normalizar
from .contexto import Contexto
from .datos import GRUPOS_FRASES
from .dominios import dominio_de_marca, host_de_url, marcas_en_texto
from .modelos import Indicador

RE_RESPUESTA = re.compile(r"^\s*(re|rv|res|fw|fwd|reenviar|reenviado)\s*:", re.IGNORECASE)


@lru_cache(maxsize=1)
def _patrones() -> dict[str, re.Pattern]:
    return {
        codigo: re.compile(r"\b(?:" + "|".join(re.escape(f) for f in sorted(g["frases"], key=len, reverse=True)) + r")\b")
        for codigo, g in GRUPOS_FRASES.items()
    }


def frases_encontradas(texto_normalizado: str) -> dict[str, set[str]]:
    encontradas = {}
    for codigo, patron in _patrones().items():
        coincidencias = set(patron.findall(texto_normalizado))
        if coincidencias:
            encontradas[codigo] = coincidencias
    return encontradas


def analizar(correo: CorreoParseado, ctx: Contexto) -> list[Indicador]:
    ind: list[Indicador] = []
    texto = normalizar(f"{correo.asunto}\n{correo.cuerpo}")[:60000]

    for codigo, frases in frases_encontradas(texto).items():
        grupo = GRUPOS_FRASES[codigo]
        puntos = min(grupo["maximo"], grupo["base"] + grupo["extra"] * (len(frases) - 1))
        muestra = ", ".join(f"«{f}»" for f in sorted(frases)[:4])
        ind.append(Indicador(codigo, grupo["titulo"], f"Frases detectadas: {muestra}.", puntos,
                             grupo["severidad"], dict(grupo["categorias"])))

    # Marca mencionada en asunto/cuerpo con enlaces que no son de esa marca
    marcas = marcas_en_texto(normalizar(correo.asunto + " " + correo.cuerpo[:3000]))
    hosts = {host_de_url(e.url) for e in correo.enlaces if e.url.lower().startswith("http")}
    hosts.discard("")
    for marca in marcas:
        if dominio_de_marca(correo.remitente_dominio, marca):
            continue
        ajenos = [h for h in hosts if not dominio_de_marca(h, marca) and not ctx.es_propio(h)]
        ind.append(Indicador("MARCA_MENCIONADA", f"Menciona a {marca}",
                             f"El mensaje habla de {marca} pero no fue enviado por {marca}"
                             + (f" y enlaza a {len(ajenos)} sitio(s) ajeno(s)." if ajenos else "."),
                             0, "info", marca=marca))
        break

    info = correo.info_html
    if info.campos_password:
        ind.append(Indicador("HTML_CAMPO_CLAVE", "Formulario que pide contraseña dentro del correo",
                             "El correo incluye un campo de contraseña: ningún servicio legítimo lo hace.", 30,
                             "critica", {"credenciales": 1.0}))
    elif info.formularios:
        ind.append(Indicador("HTML_FORMULARIO", "Formulario incrustado en el correo",
                             f"Contiene {len(info.formularios)} formulario(s) para enviar datos.", 15, "media",
                             {"credenciales": 1.0}))
    if info.scripts:
        ind.append(Indicador("HTML_SCRIPT", "Código JavaScript en el correo",
                             "Los correos legítimos no incluyen scripts.", 15, "media", {"malware": 0.5, "credenciales": 0.5}))
    if info.iframes:
        ind.append(Indicador("HTML_IFRAME", "Marco incrustado (iframe)",
                             "Puede cargar contenido externo dentro del correo.", 10, "media", {"credenciales": 1.0}))
    if info.meta_refresh:
        ind.append(Indicador("HTML_REDIRECCION", "Redirección automática",
                             "El HTML intenta redirigir automáticamente a otra página.", 15, "media", {"credenciales": 1.0}))
    if info.elementos_ocultos >= 3:
        ind.append(Indicador("HTML_TEXTO_OCULTO", "Texto oculto",
                             f"{info.elementos_ocultos} elementos invisibles: técnica para engañar a los filtros.",
                             8, "baja"))
    if correo.html and len(correo.cuerpo) < 40 and info.imagenes and correo.enlaces:
        ind.append(Indicador("HTML_SOLO_IMAGEN", "Mensaje formado solo por imágenes",
                             "Sin texto legible: típico para evadir filtros de contenido.", 10, "media",
                             {"credenciales": 0.5, "malware": 0.5}))

    if RE_RESPUESTA.match(correo.asunto) and not (correo.en_respuesta_a or correo.referencias):
        ind.append(Indicador("RESPUESTA_FALSA", "Falsa respuesta a una conversación",
                             f"El asunto «{correo.asunto[:60]}» simula ser una respuesta, pero no pertenece a "
                             "ninguna conversación previa.", 10, "media", {"bec": 0.5, "fraude_pagos": 0.5}))

    letras = [c for c in correo.asunto if c.isalpha()]
    if len(letras) >= 12 and sum(c.isupper() for c in letras) / len(letras) > 0.8 or correo.asunto.count("!") >= 3:
        ind.append(Indicador("ASUNTO_ALARMISTA", "Asunto alarmista", "Asunto en mayúsculas o con exceso de signos.", 3,
                             "baja"))
    return ind
