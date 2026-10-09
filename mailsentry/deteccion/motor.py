"""Motor de detección: combina las capas, calcula el puntaje y clasifica la amenaza."""

from __future__ import annotations

from collections import defaultdict

from ..parser import CorreoParseado
from . import adjuntos, autenticacion, contenido, enlaces, remitente
from .contexto import Contexto
from .dominios import dominio_de_alguna_marca, dominio_registrable, host_de_url
from .inteligencia import es_plataforma_compartida
from .ml import texto_para_modelo
from .modelos import Indicador, Resultado

CAPAS = (autenticacion, remitente, enlaces, contenido, adjuntos)

SUPLANTACION_INTERNA = {
    "SUPLANTACION_DIRECTIVO", "SUPLANTACION_EMPLEADO", "DOMINIO_SIMILAR_PROPIO", "SUPLANTACION_DOMINIO_PROPIO",
    "PROPIO_RESPONDER_EXTERNO", "GRATUITO_CORPORATIVO", "RESPONDER_A_DISTINTO", "DOMINIO_SIMILAR_CONOCIDO",
}
ENLACES_RIESGOSOS = {
    "URL_LISTA_NEGRA", "URL_SIMILAR_PROPIO", "URL_SIMILAR_MARCA", "ENLACE_ENGANOSO", "URL_MARCA_FUERA_DE_DOMINIO",
    "URL_IP", "URL_PUNYCODE", "URL_ARROBA", "URL_HOSTING_GRATUITO", "URL_ACORTADA", "URL_TLD", "URL_DATOS",
    "FORMULARIO_EXTERNO",
}
# Señales de enlace que por sí solas son comunes en publicidad legítima (acortadores, extensiones baratas):
# cuentan para el puntaje, pero no bastan para activar los combos de credenciales o marca.
ENLACES_FUERTES = ENLACES_RIESGOSOS - {"URL_ACORTADA", "URL_TLD"}
SUPLANTACION_MARCA = {"MARCA_EN_NOMBRE", "DOMINIO_SIMILAR_MARCA", "URL_SIMILAR_MARCA", "URL_MARCA_FUERA_DE_DOMINIO"}
ADJUNTOS_PELIGROSOS = {
    "ADJ_EJECUTABLE", "ADJ_EJECUTABLE_OCULTO", "ADJ_DOBLE_EXTENSION", "ADJ_ZIP_CIFRADO", "ADJ_ZIP_PELIGROSO",
    "ADJ_MACROS", "ADJ_IMAGEN_DISCO", "ADJ_HTML", "ADJ_PDF_ACTIVO", "ADJ_RTLO",
}


def _sinergias(ind: list[Indicador]) -> list[Indicador]:
    """Señales que juntas son mucho más graves que por separado."""
    codigos = {i.codigo for i in ind}
    extra: list[Indicador] = []
    pide_dinero = codigos & {"KW_FINANZAS", "KW_BEC"}
    if codigos & SUPLANTACION_INTERNA and (pide_dinero or "KW_CONTACTO_INICIAL" in codigos):
        extra.append(Indicador("COMBO_BEC", "Suplantación + pedido de dinero o favor",
                               "Combina una identidad falsa o desviada con una solicitud de pago, cambio de cuenta o "
                               "favor urgente: patrón clásico de fraude del CEO.", 20, "critica",
                               {"bec": 0.6, "fraude_pagos": 0.4}))
    if "KW_QR" in codigos and codigos & {"KW_CREDENCIALES", "KW_URGENCIA", "REMITENTE_NUEVO"}:
        extra.append(Indicador("COMBO_QR", "Código QR para iniciar sesión o reactivar la cuenta",
                               "El enlace va dentro de una imagen QR para que el celular lo abra fuera de los "
                               "filtros de la empresa (quishing).", 15, "alta", {"credenciales": 1.0}))
    if "KW_CREDENCIALES" in codigos and codigos & ENLACES_FUERTES:
        extra.append(Indicador("COMBO_CREDENCIALES", "Pide credenciales y enlaza a un sitio riesgoso",
                               "Solicita iniciar sesión o confirmar datos mediante un enlace de destino sospechoso.",
                               15, "alta", {"credenciales": 1.0}))
    menciona = next((i for i in ind if i.codigo == "MARCA_MENCIONADA"), None)
    # Solo si la marca es el pretexto (enlaces dudosos) y no se está suplantando a alguien de la empresa:
    # "compra tarjetas de Google Play" en un fraude del CEO no es suplantar a Google.
    if (menciona and not codigos & SUPLANTACION_MARCA and not codigos & SUPLANTACION_INTERNA
            and codigos & {"KW_CREDENCIALES", "KW_URGENCIA"} and codigos & ENLACES_FUERTES):
        extra.append(Indicador("COMBO_MARCA", f"Usa el nombre de {menciona.marca} para presionar",
                               f"Menciona a {menciona.marca}, presiona o pide datos, y los enlaces o la autenticación "
                               "no corresponden a esa marca.", 20, "alta",
                               {"suplantacion_marca": 0.6, "credenciales": 0.4}, marca=menciona.marca))
    if codigos & ADJUNTOS_PELIGROSOS and codigos & {"KW_URGENCIA", "KW_FINANZAS", "KW_AMENAZA_LEGAL"}:
        extra.append(Indicador("COMBO_ADJUNTO", "Adjunto peligroso con pretexto urgente",
                               "Presiona para abrir un adjunto de alto riesgo (factura, notificación, deuda).", 10,
                               "alta", {"malware": 1.0}))
    return extra


def _inteligencia_externa(correo: CorreoParseado, ctx: Contexto) -> list[Indicador]:
    """Consulta VirusTotal para el remitente y hasta 3 dominios enlazados (solo correos ya dudosos)."""
    dominios = []
    for host in [correo.remitente_dominio, *(host_de_url(e.url) for e in correo.enlaces)]:
        reg = dominio_registrable(host)
        if (reg and reg not in dominios and not ctx.es_propio(reg) and not dominio_de_alguna_marca(reg)
                and not es_plataforma_compartida(reg)):
            dominios.append(reg)
    malos = []
    for dominio in dominios[:4]:
        detecciones = ctx.intel.dominio_malicioso(dominio)  # type: ignore[union-attr]
        if detecciones and detecciones >= 2:
            malos.append(f"{dominio} ({detecciones} motores)")
    if not malos:
        return []
    return [Indicador("INTEL_VIRUSTOTAL", "Dominio reportado como malicioso en VirusTotal",
                      "; ".join(malos), 40, "critica", {"credenciales": 0.5, "malware": 0.5})]


def _categoria(indicadores: list[Indicador]) -> str:
    votos: dict[str, float] = defaultdict(float)
    for i in indicadores:
        if i.puntos > 0:
            for categoria, peso in i.categorias.items():
                votos[categoria] += i.puntos * peso
    return max(votos, key=votos.get) if votos else "otro"


def analizar(correo: CorreoParseado, ctx: Contexto) -> Resultado:
    indicadores: list[Indicador] = []
    for capa in CAPAS:
        indicadores.extend(capa.analizar(correo, ctx))
    indicadores.extend(_sinergias(indicadores))

    preliminar = sum(i.puntos for i in indicadores)
    if ctx.intel is not None and preliminar >= ctx.umbral_sospechoso // 2:
        indicadores.extend(_inteligencia_externa(correo, ctx))

    heuristico = max(0, min(100, sum(i.puntos for i in indicadores)))
    puntaje = heuristico
    prob = None
    if ctx.modelo is not None and ctx.peso_ml > 0:
        prob = ctx.modelo.predecir(texto_para_modelo(correo))  # type: ignore[union-attr]
        if prob is not None:
            puntaje = round(heuristico * (1 - ctx.peso_ml) + prob * 100 * ctx.peso_ml)
            indicadores.append(Indicador("IA_PROBABILIDAD", "Evaluación del modelo de IA",
                                         f"El modelo entrenado con sus correos estima {prob:.0%} de probabilidad "
                                         "de phishing.", 0, "info"))

    # Una señal crítica nunca puede quedar como legítima por efecto del promedio con la IA
    # (salvo remitentes que la empresa marcó como confiables y que pasaron la autenticación)
    permitido = any(i.codigo == "LISTA_PERMITIDA" for i in indicadores)
    if not permitido and any(i.severidad == "critica" and i.puntos > 0 for i in indicadores):
        puntaje = max(puntaje, ctx.umbral_phishing)
    if any(i.codigo == "LISTA_BLOQUEADA" for i in indicadores):
        puntaje = 100
    puntaje = max(0, min(100, puntaje))

    if puntaje >= ctx.umbral_phishing:
        veredicto = "phishing"
    elif puntaje >= ctx.umbral_sospechoso:
        veredicto = "sospechoso"
    else:
        veredicto = "legitimo"

    if puntaje >= ctx.umbral_critico:
        nivel = "critico"
    elif puntaje >= ctx.umbral_phishing:
        nivel = "alto"
    elif puntaje >= ctx.umbral_sospechoso:
        nivel = "medio"
    else:
        nivel = "bajo"

    # Solo cuenta como suplantada si se usó la identidad de la marca (no basta con mencionarla:
    # "compra tarjetas de Google Play" no es suplantar a Google)
    marca = next((i.marca for i in indicadores if i.marca and i.codigo != "MARCA_MENCIONADA"), None)

    indicadores.sort(key=lambda i: (-i.puntos, i.codigo))
    return Resultado(
        puntaje=puntaje,
        puntaje_heuristico=heuristico,
        prob_ml=prob,
        veredicto=veredicto,
        nivel=nivel,
        categoria=_categoria(indicadores) if veredicto != "legitimo" else "ninguna",
        marca=marca,
        indicadores=indicadores,
    )
