"""Rastreo del origen de un correo: IP y país del servidor que lo entregó.

Qué se puede saber con certeza: la IP del servidor que se conectó al servidor de correo
de la empresa. Esa línea la escribe el servidor receptor, así que el atacante no puede
falsificarla. Las cabeceras Received más antiguas (más abajo) sí pueden ser inventadas.

Qué NO se puede saber: dónde está físicamente la persona. Si usó Gmail, Outlook u otro
servicio, la IP es la de ese proveedor (su origen real queda oculto), y si usó una VPN o
un servidor hackeado, el país es el de ese servidor.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass

from .deteccion.datos import CORREO_GRATUITO
from .deteccion.dominios import es_subdominio_de, limpiar_host
from .parser import CorreoParseado

RE_CLIENT_IP = re.compile(r"client-ip=\s*([0-9a-fA-F:.]+)", re.I)
RE_SENDER_IP = re.compile(r"sender IP is\s+([0-9a-fA-F:.]+)", re.I)  # Microsoft 365
RE_SMTP_IP = re.compile(r"smtp\.(?:remote-ip|client-ip)\s*=\s*([0-9a-fA-F:.]+)", re.I)
RE_DESDE = re.compile(r"^\s*from\s+(\S+)(.*?)(?:\bby\b|$)", re.I | re.S)
RE_IP_CORCHETES = re.compile(r"\[(?:IPv6:)?([0-9a-fA-F:.]+)\]")
RE_IPV4 = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")
RE_HOST_PARENTESIS = re.compile(r"\(\s*([a-z0-9][a-z0-9.-]*\.[a-z]{2,})\b", re.I)

# Rangos reservados para documentación: solo se aceptan en el modo demostración
DOCUMENTACION = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24")]

# Servicios de correo cuyos servidores ocultan el origen real del remitente
PROVEEDORES = {
    "google.com": "Google (Gmail)", "googlemail.com": "Google (Gmail)",
    "outlook.com": "Microsoft (Outlook)", "hotmail.com": "Microsoft (Outlook)",
    "protection.outlook.com": "Microsoft (Outlook)", "office365.com": "Microsoft (Outlook)",
    "yahoo.com": "Yahoo", "yahoodns.net": "Yahoo", "icloud.com": "Apple (iCloud)",
    "me.com": "Apple (iCloud)", "amazonses.com": "Amazon SES", "sendgrid.net": "SendGrid",
    "mailgun.org": "Mailgun", "mailgun.net": "Mailgun", "mcsv.net": "Mailchimp",
    "mandrillapp.com": "Mailchimp", "sparkpostmail.com": "SparkPost", "zoho.com": "Zoho",
    "protonmail.ch": "Proton Mail", "proton.me": "Proton Mail", "gmx.net": "GMX",
    "mail.ru": "Mail.ru", "yandex.net": "Yandex", "brevo.com": "Brevo", "sendinblue.com": "Brevo",
}
GRATUITO_A_PROVEEDOR = {
    "gmail.com": "Google (Gmail)", "googlemail.com": "Google (Gmail)", "outlook.com": "Microsoft (Outlook)",
    "outlook.es": "Microsoft (Outlook)", "hotmail.com": "Microsoft (Outlook)", "hotmail.es": "Microsoft (Outlook)",
    "live.com": "Microsoft (Outlook)", "yahoo.com": "Yahoo", "yahoo.es": "Yahoo", "icloud.com": "Apple (iCloud)",
    "proton.me": "Proton Mail", "protonmail.com": "Proton Mail", "gmx.com": "GMX", "mail.ru": "Mail.ru",
    "yandex.com": "Yandex", "zoho.com": "Zoho",
}


@dataclass
class Origen:
    ip: str | None = None
    metodo: str = ""  # spf | autenticacion | received
    servidor: str = ""  # nombre que el servidor declaró al conectarse
    proveedor: str | None = None  # si llegó a través de un servicio de correo masivo/gratuito


def ip_publica(texto: str, permitir_documentacion: bool = False) -> str | None:
    try:
        ip = ipaddress.ip_address(texto.strip().strip("[]"))
    except ValueError:
        return None
    if getattr(ip, "ipv4_mapped", None):
        ip = ip.ipv4_mapped
    if ip.is_global:
        return str(ip)
    if permitir_documentacion and any(ip in red for red in DOCUMENTACION):
        return str(ip)
    return None


def _saltos(correo: CorreoParseado) -> list[tuple[str, str | None]]:
    """(servidor declarado, ip) de cada cabecera Received, de la más reciente a la más antigua."""
    saltos = []
    for cabecera in correo.recibidos:
        m = RE_DESDE.search(cabecera)
        if not m:
            continue
        servidor, resto = m.group(1), m.group(2)
        ips = RE_IP_CORCHETES.findall(resto) or RE_IPV4.findall(resto)
        nombre_inverso = RE_HOST_PARENTESIS.search(resto)
        if nombre_inverso:  # el nombre verificado por DNS inverso es más fiable que el declarado (HELO)
            servidor = nombre_inverso.group(1)
        saltos.append((limpiar_host(servidor), ips[0] if ips else None))
    return saltos


def _proveedor_de(servidor: str) -> str | None:
    for dominio, nombre in PROVEEDORES.items():
        if servidor and es_subdominio_de(servidor, dominio):
            return nombre
    return None


def determinar(correo: CorreoParseado, permitir_documentacion: bool = False) -> Origen:
    cabeceras = " ".join(correo.cabeceras_autenticacion)
    ip, metodo = None, ""
    for patron, nombre_metodo in ((RE_CLIENT_IP, "spf"), (RE_SENDER_IP, "autenticacion"), (RE_SMTP_IP, "autenticacion")):
        for candidato in patron.findall(cabeceras):
            ip = ip_publica(candidato, permitir_documentacion)
            if ip:
                metodo = nombre_metodo
                break
        if ip:
            break

    saltos = _saltos(correo)
    servidor = ""
    if ip:
        servidor = next((s for s, i in saltos if i and ip_publica(i, permitir_documentacion) == ip), "")
    else:
        # El salto más reciente con IP pública: la conexión que registró el servidor de la empresa
        for s, i in saltos:
            publica = ip_publica(i, permitir_documentacion) if i else None
            if publica:
                ip, servidor, metodo = publica, s, "received"
                break

    proveedor = _proveedor_de(servidor)
    if proveedor is None and correo.remitente_dominio in CORREO_GRATUITO and ip:
        proveedor = GRATUITO_A_PROVEEDOR.get(correo.remitente_dominio, "Correo gratuito")
    return Origen(ip=ip, metodo=metodo, servidor=servidor[:255], proveedor=proveedor)
