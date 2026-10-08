"""Capa 3: enlaces (destinos engañosos, dominios parecidos, acortadores, hosting gratuito, listas negras)."""

from __future__ import annotations

import re
from collections import OrderedDict
from urllib.parse import urlsplit

from ..parser import CorreoParseado
from ..util import desarmar_url
from .contexto import Contexto
from .datos import ACORTADORES, HOSTING_ABUSADO, RUTAS_SOSPECHOSAS, TLD_SOSPECHOSOS
from .dominios import (
    buscar_parecido,
    desenvolver,
    dominio_de_alguna_marca,
    dominio_registrable,
    es_ip,
    es_redirector_legitimo,
    es_subdominio_de,
    host_de_url,
    marca_en_subdominio_o_ruta,
    parecido_a_marca,
    subdominio,
    tld,
)
from .modelos import Indicador

# Texto de enlace que "parece" una dirección: con esquema/www, o un dominio con extensión conocida
RE_DOMINIO_VISIBLE = re.compile(
    r"^(?:https?://|www\.)((?:[a-z0-9-]+\.)+[a-z]{2,})"
    r"|^((?:[a-z0-9-]+\.)+(?:com|net|org|pe|es|io|co|info|biz|us|mx|ar|cl|br|ec|bo|gob|edu|app))(?:[/:?#]\S*)?$",
    re.IGNORECASE,
)
CRED = {"credenciales": 1.0}
MAX_ENLACES = 150

# código -> (título, puntos, severidad, categorías)
REGLAS = {
    "URL_LISTA_NEGRA": ("Enlace en listas de phishing conocidas", 60, "critica", {"credenciales": 0.7, "malware": 0.3}),
    "URL_SIMILAR_PROPIO": ("Enlace a un dominio que imita al de la empresa", 45, "critica", {"bec": 0.5, "credenciales": 0.5}),
    "URL_SIMILAR_MARCA": ("Enlace a un dominio que imita a una marca", 35, "alta", {"suplantacion_marca": 0.5, "credenciales": 0.5}),
    "ENLACE_ENGANOSO": ("El texto del enlace no coincide con su destino", 30, "alta", {"credenciales": 0.7, "suplantacion_marca": 0.3}),
    "URL_DATOS": ("Enlace con página incrustada (data:)", 30, "alta", CRED),
    "URL_MARCA_FUERA_DE_DOMINIO": ("Marca conocida dentro de un dominio ajeno", 20, "alta", {"suplantacion_marca": 0.6, "credenciales": 0.4}),
    "URL_IP": ("Enlace a una dirección IP", 20, "alta", {"credenciales": 0.5, "malware": 0.5}),
    "URL_PUNYCODE": ("Enlace con caracteres internacionales (punycode)", 20, "alta", {"suplantacion_marca": 0.5, "credenciales": 0.5}),
    "URL_ARROBA": ("Enlace con '@' para ocultar el destino", 20, "alta", CRED),
    "URL_HOSTING_GRATUITO": ("Página alojada en servicio gratuito", 15, "media", CRED),
    "URL_ACORTADA": ("Enlace acortado que oculta el destino", 10, "media", {"credenciales": 0.5, "malware": 0.5}),
    "URL_PUERTO": ("Enlace con puerto no estándar", 10, "media", {"malware": 0.5, "credenciales": 0.5}),
    "URL_TLD": ("Enlace con extensión de dominio de alto riesgo", 8, "baja", CRED),
    "URL_HTTP_LOGIN": ("Página de acceso sin cifrado (http)", 8, "media", CRED),
    "URL_SUBDOMINIOS": ("Enlace con exceso de subdominios", 6, "baja", CRED),
    "URL_RUTA_SOSPECHOSA": ("Ruta típica de página de captura", 5, "baja", CRED),
    "ENLACE_SEGUIMIENTO": ("Enlace que pasa por un rastreador de clics", 5, "baja", CRED),
    "FORMULARIO_EXTERNO": ("Formulario que envía datos a un sitio externo", 25, "alta", CRED),
}


def _confiable(host: str, ctx: Contexto) -> bool:
    return ctx.es_propio(host) or dominio_de_alguna_marca(host) is not None or ctx.permitido(host)


def analizar(correo: CorreoParseado, ctx: Contexto) -> list[Indicador]:
    hallazgos: "OrderedDict[str, list[str]]" = OrderedDict()
    marcas: dict[str, str] = {}
    auth = correo.autenticacion
    auth_falla = auth.get("dmarc") == "fail" or auth.get("spf") in ("fail", "softfail")

    def marcar(codigo: str, evidencia: str, marca: str | None = None) -> None:
        lista = hallazgos.setdefault(codigo, [])
        if evidencia not in lista:
            lista.append(evidencia)
        if marca:
            marcas.setdefault(codigo, marca)

    for enlace in correo.enlaces[:MAX_ENLACES]:
        url = desenvolver(enlace.url.strip())
        esquema = url.split(":", 1)[0].lower() if ":" in url else ""
        if esquema == "data":
            marcar("URL_DATOS", "data:" + url[5:40])
            continue
        if esquema in ("mailto", "tel", "cid", "sms", "javascript") or url.startswith("#"):
            continue
        try:
            partes = urlsplit(url)
        except ValueError:
            continue
        host = host_de_url(url)
        if not host:
            continue
        visible = desarmar_url(url)[:90]

        if ctx.feeds is not None and ctx.feeds.contiene(url):
            marcar("URL_LISTA_NEGRA", visible)
        if ctx.bloqueado(host):
            marcar("URL_LISTA_NEGRA", f"{visible} (lista de bloqueo de la empresa)")

        if enlace.origen == "formulario" and not ctx.es_propio(host):
            marcar("FORMULARIO_EXTERNO", visible)

        # Texto visible que muestra un dominio distinto al destino real
        if enlace.texto and not es_redirector_legitimo(host):
            m = RE_DOMINIO_VISIBLE.search(enlace.texto.strip())
            if m:
                mostrado = (m.group(1) or m.group(2)).lower()
                mostrado = mostrado[4:] if mostrado.startswith("www.") else mostrado
                if dominio_registrable(mostrado) != dominio_registrable(host) and not es_subdominio_de(host, mostrado):
                    # Boletines legítimos muestran su propio dominio pero pasan por un rastreador de clics;
                    # el engaño real muestra un dominio (marca, banco, la empresa) distinto al del remitente.
                    if dominio_registrable(mostrado) == dominio_registrable(correo.remitente_dominio) and not auth_falla:
                        marcar("ENLACE_SEGUIMIENTO", f"muestra «{mostrado}» y pasa por {desarmar_url(host)}")
                    else:
                        marcar("ENLACE_ENGANOSO", f"muestra «{mostrado}» pero lleva a {desarmar_url(host)}")

        if _confiable(host, ctx):
            continue

        if es_ip(host):
            marcar("URL_IP", visible)
        if "@" in (partes.netloc or ""):
            marcar("URL_ARROBA", visible)
        if "xn--" in host:
            marcar("URL_PUNYCODE", visible)
        if host in ACORTADORES:
            marcar("URL_ACORTADA", visible)
        if any(es_subdominio_de(host, h) for h in HOSTING_ABUSADO):
            marcar("URL_HOSTING_GRATUITO", visible)
        if tld(host) in TLD_SOSPECHOSOS:
            marcar("URL_TLD", visible)
        try:
            puerto = partes.port
        except ValueError:
            puerto = None
        if puerto and puerto not in (80, 443):
            marcar("URL_PUERTO", visible)
        if subdominio(host).count(".") >= 3:
            marcar("URL_SUBDOMINIOS", visible)

        ruta = (partes.path + "?" + partes.query).lower()
        ruta_sospechosa = any(p in ruta for p in RUTAS_SOSPECHOSAS)
        if ruta_sospechosa:
            marcar("URL_RUTA_SOSPECHOSA", visible)
            if partes.scheme == "http":
                marcar("URL_HTTP_LOGIN", visible)

        if not es_ip(host):
            propio = buscar_parecido(host, ctx.dominios_propios)
            if propio:
                marcar("URL_SIMILAR_PROPIO", f"{desarmar_url(host)} imita a {propio[0]}: {propio[1]}")
            else:
                marca = parecido_a_marca(host)
                if marca:
                    marcar("URL_SIMILAR_MARCA", f"{desarmar_url(host)} imita a {marca[1]}: {marca[2]}", marca[0])
                else:
                    en_ruta = marca_en_subdominio_o_ruta(url)
                    if en_ruta:
                        marcar("URL_MARCA_FUERA_DE_DOMINIO", f"«{en_ruta}» en {visible}", en_ruta)

    indicadores = []
    for codigo, evidencias in hallazgos.items():
        titulo, puntos, severidad, categorias = REGLAS[codigo]
        detalle = "; ".join(evidencias[:3]) + (f" (y {len(evidencias) - 3} más)" if len(evidencias) > 3 else "")
        indicadores.append(Indicador(codigo, titulo, detalle, puntos, severidad, dict(categorias),
                                     marca=marcas.get(codigo)))
    return indicadores
