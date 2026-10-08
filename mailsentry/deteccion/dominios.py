"""Análisis de dominios: dominio registrable, homógrafos y dominios parecidos (typosquatting)."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from functools import lru_cache
from urllib.parse import parse_qs, unquote, urlsplit

from .datos import CORREO_GRATUITO, MARCAS, REDIRECTORES_LEGITIMOS, SUFIJOS_DOBLES

# Letras de otros alfabetos que se ven idénticas a las latinas
HOMOGLIFOS = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i", "ј": "j",
    "ѕ": "s", "ԁ": "d", "ɡ": "g", "ӏ": "l", "һ": "h", "ԛ": "q", "ԝ": "w", "ꮃ": "w", "α": "a",
    "ο": "o", "ν": "v", "τ": "t", "ρ": "p", "κ": "k", "ι": "i", "ı": "i", "ɩ": "l", "ǀ": "l",
}
# Sustituciones visuales de caracteres latinos (orden importa: secuencias primero)
SUSTITUCIONES = (
    ("rn", "m"), ("vv", "w"), ("cl", "d"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"),
    ("5", "s"), ("7", "t"), ("8", "b"), ("9", "g"), ("$", "s"), ("@", "a"), ("i", "l"),
)


def limpiar_host(host: str) -> str:
    host = (host or "").strip().lower().rstrip(".")
    if "@" in host:
        host = host.rsplit("@", 1)[1]
    if host.startswith("["):
        return host.strip("[]")
    if host.count(":") == 1:
        host = host.split(":", 1)[0]
    return host


def es_ip(host: str) -> bool:
    host = limpiar_host(host)
    if not host:
        return False
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        # IPs ofuscadas en decimal o hexadecimal (http://3232235777/)
        return bool(re.fullmatch(r"\d{8,10}|0x[0-9a-f]{6,8}", host))


@lru_cache(maxsize=4096)
def dominio_registrable(host: str) -> str:
    host = limpiar_host(host)
    if not host or es_ip(host):
        return host
    partes = host.split(".")
    if len(partes) >= 3 and ".".join(partes[-2:]) in SUFIJOS_DOBLES:
        return ".".join(partes[-3:])
    return ".".join(partes[-2:])


def etiqueta(dominio: str) -> str:
    """Nombre principal del dominio: 'viabcp' para 'www.viabcp.com'."""
    return dominio_registrable(dominio).split(".")[0]


def tld(host: str) -> str:
    return limpiar_host(host).rsplit(".", 1)[-1]


def subdominio(host: str) -> str:
    host = limpiar_host(host)
    reg = dominio_registrable(host)
    return host[: -len(reg)].rstrip(".") if host != reg else ""


def es_subdominio_de(host: str, dominio: str) -> bool:
    host, dominio = limpiar_host(host), limpiar_host(dominio)
    return bool(dominio) and (host == dominio or host.endswith("." + dominio))


def decodificar_punycode(host: str) -> str:
    partes = []
    for parte in limpiar_host(host).split("."):
        if parte.startswith("xn--"):
            try:
                parte = parte[4:].encode("ascii").decode("punycode")
            except Exception:
                pass
        partes.append(parte)
    return ".".join(partes)


def esqueleto(texto: str) -> str:
    """Forma 'visual' de un nombre: dos dominios con el mismo esqueleto se ven iguales."""
    texto = decodificar_punycode(texto).lower()
    texto = "".join(HOMOGLIFOS.get(c, c) for c in texto)
    texto = unicodedata.normalize("NFKD", texto)
    texto = "".join(c for c in texto if not unicodedata.combining(c))
    for origen, destino in SUSTITUCIONES:
        texto = texto.replace(origen, destino)
    return texto


def levenshtein(a: str, b: str, tope: int = 3) -> int:
    if abs(len(a) - len(b)) > tope:
        return tope + 1
    anterior = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        actual = [i]
        for j, cb in enumerate(b, 1):
            actual.append(min(anterior[j] + 1, actual[j - 1] + 1, anterior[j - 1] + (ca != cb)))
        anterior = actual
    return anterior[-1]


def _variacion(a: str, b: str) -> bool:
    """Error tipográfico plausible. En nombres cortos solo se aceptan letras cambiadas
    (micros0ft, paypa1): quitar una letra produce palabras comunes (gmail -> mail)."""
    distancia = levenshtein(a, b)
    if len(b) <= 6:
        return distancia == 1 and len(a) == len(b)
    return distancia == 1 or (distancia == 2 and len(b) >= 9)


def tecnica_parecido(candidato: str, protegido: str, estricto: bool = False) -> str | None:
    """Indica cómo 'candidato' imita a 'protegido' (o None si no se parecen)."""
    reg_c, reg_p = dominio_registrable(candidato), dominio_registrable(protegido)
    if not reg_c or not reg_p or reg_c == reg_p or es_ip(reg_c):
        return None
    ec, ep = etiqueta(reg_c), etiqueta(reg_p)
    if len(ep) < 3:
        return None
    if ec == ep:
        return f"mismo nombre con otra terminación ({reg_c} en vez de {reg_p})"
    if esqueleto(ec) == esqueleto(ep):
        return "usa caracteres visualmente idénticos (ataque homógrafo)"
    if ec.replace("-", "") == ep:
        return "mismo nombre separado con guiones"
    if len(ep) >= 5 and _variacion(ec, ep):
        return f"error tipográfico intencional ({levenshtein(ec, ep)} carácter(es) de diferencia)"
    fichas = [f for f in re.split(r"[-_.]+", ec) if f]
    if len(fichas) > 1:
        for ficha in fichas:
            if ficha == ep or re.sub(r"\d+", "", ficha) == ep:
                return "combina el nombre legítimo con otras palabras"
            if esqueleto(ficha) == esqueleto(ep):
                return "combina una imitación visual del nombre con otras palabras"
            if len(ep) >= 5 and len(ficha) >= len(ep) and _variacion(ficha, ep):
                return "combina una variación del nombre con otras palabras"
    if re.sub(r"\d+", "", ec) == ep:
        return "agrega números al nombre legítimo"
    if not estricto and len(ep) >= 6 and ep in ec:
        return "contiene el nombre legítimo dentro de otro dominio"
    return None


def buscar_parecido(host: str, protegidos: set[str] | list[str], estricto: bool = False) -> tuple[str, str] | None:
    """Devuelve (dominio_protegido, técnica) si el host imita alguno de los protegidos."""
    reg = dominio_registrable(host)
    if any(es_subdominio_de(host, p) for p in protegidos):
        return None
    for protegido in protegidos:
        tecnica = tecnica_parecido(reg, protegido, estricto)
        if tecnica:
            return protegido, tecnica
    return None


# ---------------------------------------------------------------- marcas

def dominio_de_marca(host: str, marca: str) -> bool:
    return any(es_subdominio_de(host, d) for d in MARCAS[marca]["dominios"])


def dominio_de_alguna_marca(host: str) -> str | None:
    for nombre, datos in MARCAS.items():
        if any(es_subdominio_de(host, d) for d in datos["dominios"]):
            return nombre
    return None


@lru_cache(maxsize=1)
def _patrones_marcas() -> list[tuple[str, re.Pattern, bool]]:
    resultado = []
    for nombre, datos in MARCAS.items():
        patron = re.compile(r"\b(?:" + "|".join(re.escape(p) for p in datos["patrones"]) + r")\b")
        resultado.append((nombre, patron, bool(datos.get("solo_remitente"))))
    return resultado


def marcas_en_texto(texto_normalizado: str, es_remitente: bool = False) -> list[str]:
    encontradas = []
    for nombre, patron, solo_remitente in _patrones_marcas():
        if solo_remitente and not es_remitente:
            continue
        if patron.search(texto_normalizado):
            encontradas.append(nombre)
    return encontradas


def parecido_a_marca(host: str) -> tuple[str, str, str] | None:
    """Devuelve (marca, dominio_legítimo, técnica) si el host imita a una marca conocida."""
    if dominio_de_alguna_marca(host) or dominio_registrable(host) in CORREO_GRATUITO:
        return None
    reg = dominio_registrable(host)
    for nombre, datos in MARCAS.items():
        for legitimo in datos["dominios"]:
            tecnica = tecnica_parecido(reg, legitimo)
            if tecnica:
                return nombre, legitimo, tecnica
    return None


def marca_en_subdominio_o_ruta(url_o_host: str) -> str | None:
    """Detecta 'viabcp.com.seguridad-web.xyz' o 'sitio.xyz/bcp/login' (marca fuera de su dominio)."""
    partes = urlsplit(url_o_host if "://" in url_o_host else f"http://{url_o_host}")
    host = limpiar_host(partes.hostname or "")
    if not host or dominio_de_alguna_marca(host):
        return None
    fichas_sub = set(re.split(r"[.\-_]+", subdominio(host)))
    fichas_ruta = {s.lower() for s in partes.path.split("/") if s}
    for nombre, datos in MARCAS.items():
        if datos.get("solo_remitente"):
            continue
        patrones = {p for p in datos["patrones"] if " " not in p and len(p) >= 3}
        etiquetas = {e for e in (etiqueta(d) for d in datos["dominios"]) if len(e) >= 4} | patrones
        if etiquetas & fichas_sub or patrones & fichas_ruta:
            return nombre
    return None


# ---------------------------------------------------------------- URLs

def host_de_url(url: str) -> str:
    try:
        return limpiar_host(urlsplit(url).hostname or "")
    except ValueError:
        return ""


def desenvolver(url: str) -> str:
    """Obtiene el destino real de enlaces reescritos por filtros (Safe Links, google.com/url)."""
    try:
        partes = urlsplit(url)
    except ValueError:
        return url
    host = limpiar_host(partes.hostname or "")
    consulta = parse_qs(partes.query)
    if host.endswith("safelinks.protection.outlook.com") and "url" in consulta:
        return unquote(consulta["url"][0])
    if host in ("www.google.com", "google.com") and partes.path == "/url":
        destino = consulta.get("q") or consulta.get("url")
        if destino:
            return unquote(destino[0])
    return url


def es_redirector_legitimo(host: str) -> bool:
    return any(es_subdominio_de(host, r) for r in REDIRECTORES_LEGITIMOS)
