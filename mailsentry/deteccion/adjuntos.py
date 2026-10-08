"""Capa 5: adjuntos (ejecutables, macros, dobles extensiones, comprimidos y HTML de captura)."""

from __future__ import annotations

import io
import re
import zipfile

from ..parser import Adjunto, CorreoParseado
from ..util import normalizar
from .contexto import Contexto
from .datos import (
    EXT_COMPRIMIDOS,
    EXT_DOCUMENTO,
    EXT_EJECUTABLES,
    EXT_HTML,
    EXT_IMAGEN_DISCO,
    EXT_MACROS,
    EXT_OFFICE_ANTIGUO,
)
from .modelos import Indicador

MALWARE = {"malware": 1.0}
RE_CLAVE = re.compile(r"\b(?:clave|contrasena|password|pass|pwd|codigo)\b\s*[:=]?\s*\S+")
RE_HTML_ACTIVO = re.compile(rb"<form|type=[\"']?password|atob\(|window\.location|document\.write\(|eval\(|fetch\(", re.I)


def _extension(nombre: str) -> str:
    return nombre.rsplit(".", 1)[-1].lower().strip() if "." in nombre else ""


def _analizar_zip(adj: Adjunto) -> list[Indicador]:
    ind = []
    try:
        with zipfile.ZipFile(io.BytesIO(adj.contenido)) as z:
            infos = z.infolist()[:500]
    except (zipfile.BadZipFile, Exception):
        return ind
    if any(i.flag_bits & 0x1 for i in infos):
        ind.append(Indicador("ADJ_ZIP_CIFRADO", "Comprimido protegido con contraseña",
                             f"«{adj.nombre}» está cifrado: así el antivirus no puede revisarlo. Técnica muy usada "
                             "para entregar malware.", 35, "alta", MALWARE))
    peligrosos = [i.filename for i in infos if _extension(i.filename) in EXT_EJECUTABLES | EXT_IMAGEN_DISCO | EXT_HTML]
    if peligrosos:
        ind.append(Indicador("ADJ_ZIP_PELIGROSO", "Comprimido con archivos peligrosos",
                             f"«{adj.nombre}» contiene: {', '.join(peligrosos[:4])}.", 40, "critica", MALWARE))
    macros = any(i.filename.lower().endswith("vbaproject.bin") for i in infos)
    if macros:
        ind.append(Indicador("ADJ_MACROS", "Documento con macros",
                             f"«{adj.nombre}» contiene macros (código VBA) que pueden instalar malware.", 30, "alta",
                             MALWARE))
    return ind


def _analizar_adjunto(adj: Adjunto) -> list[Indicador]:
    ind: list[Indicador] = []
    nombre = adj.nombre
    ext = _extension(nombre)
    datos = adj.contenido or b""
    partes = nombre.lower().split(".")

    if "‮" in nombre:
        ind.append(Indicador("ADJ_RTLO", "Nombre de archivo con inversión de texto",
                             f"«{nombre!r}» usa un carácter invisible que invierte el texto para disfrazar la extensión.",
                             40, "critica", MALWARE))
    if len(partes) >= 3 and partes[-2] in EXT_DOCUMENTO and (ext in EXT_EJECUTABLES or ext in EXT_HTML):
        ind.append(Indicador("ADJ_DOBLE_EXTENSION", "Doble extensión engañosa",
                             f"«{nombre}» aparenta ser .{partes[-2]} pero en realidad es .{ext}.", 35, "critica", MALWARE))

    if ext in EXT_EJECUTABLES:
        ind.append(Indicador("ADJ_EJECUTABLE", "Adjunto ejecutable o script",
                             f"«{nombre}»: los archivos .{ext} pueden tomar el control del equipo.", 45, "critica",
                             MALWARE))
    elif datos[:2] == b"MZ":
        ind.append(Indicador("ADJ_EJECUTABLE_OCULTO", "Programa disfrazado de documento",
                             f"«{nombre}» es en realidad un programa de Windows (cabecera MZ).", 45, "critica", MALWARE))
    if ext in EXT_IMAGEN_DISCO:
        ind.append(Indicador("ADJ_IMAGEN_DISCO", "Imagen de disco adjunta",
                             f"«{nombre}»: los .{ext} se usan para saltarse las protecciones de Windows.", 30, "alta",
                             MALWARE))
    if ext in EXT_MACROS:
        ind.append(Indicador("ADJ_MACROS", "Documento Office con macros",
                             f"«{nombre}» admite macros, el método clásico para infectar equipos.", 30, "alta", MALWARE))
    if ext in EXT_OFFICE_ANTIGUO and datos[:4] == b"\xd0\xcf\x11\xe0" and (b"_VBA_PROJECT" in datos or b"Attribute VB_" in datos):
        ind.append(Indicador("ADJ_MACROS", "Documento Office con macros",
                             f"«{nombre}» contiene macros VBA.", 30, "alta", MALWARE))
    if ext in EXT_HTML:
        activo = bool(RE_HTML_ACTIVO.search(datos[:2_000_000]))
        ind.append(Indicador("ADJ_HTML", "Página web adjunta" + (" con formulario o código" if activo else ""),
                             f"«{nombre}»: los adjuntos .{ext} suelen ser páginas falsas de inicio de sesión que se "
                             "abren sin pasar por ningún filtro.", 40 if activo else 25, "critica" if activo else "alta",
                             {"credenciales": 0.7, "malware": 0.3}))
    if ext == "pdf" or datos[:5] == b"%PDF-":
        if re.search(rb"/JavaScript|/JS\s*\(|/Launch|/EmbeddedFile", datos[:5_000_000]):
            ind.append(Indicador("ADJ_PDF_ACTIVO", "PDF con código o archivos incrustados",
                                 f"«{nombre}» contiene acciones automáticas (JavaScript/Launch/archivo incrustado).",
                                 25, "alta", MALWARE))
    if datos[:2] == b"PK" or ext in EXT_COMPRIMIDOS:
        hallazgos = _analizar_zip(adj) if datos[:2] == b"PK" else []
        ind.extend(hallazgos)
        if not hallazgos and ext in EXT_COMPRIMIDOS:
            ind.append(Indicador("ADJ_COMPRIMIDO", "Archivo comprimido adjunto",
                                 f"«{nombre}»: revise su contenido antes de abrirlo.", 6, "baja", MALWARE))
    return ind


def analizar(correo: CorreoParseado, ctx: Contexto) -> list[Indicador]:
    vistos: dict[str, Indicador] = {}
    for adj in correo.adjuntos:
        if adj.tipo_mime == "message/rfc822":
            continue
        for indicador in _analizar_adjunto(adj):
            previo = vistos.get(indicador.codigo)
            if previo is None or indicador.puntos > previo.puntos:
                vistos[indicador.codigo] = indicador

    # Comprimido cifrado + contraseña escrita en el mismo correo: táctica de Emotet/Qakbot
    # (en secuestros de conversaciones reales), pensada solo para esquivar el antivirus.
    if "ADJ_ZIP_CIFRADO" in vistos and RE_CLAVE.search(normalizar(correo.cuerpo)):
        externo = not ctx.es_propio(correo.remitente_dominio)
        vistos["ADJ_ZIP_CLAVE_EN_CORREO"] = Indicador(
            "ADJ_ZIP_CLAVE_EN_CORREO", "La contraseña del comprimido viene en el mismo correo",
            "Si la clave viaja junto al archivo, el cifrado no protege nada: solo sirve para que el "
            "antivirus no pueda revisarlo.", 20, "critica" if externo else "alta", MALWARE)
    return list(vistos.values())
