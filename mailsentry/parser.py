"""Lectura de correos en formato RFC 822 (.eml) a una estructura fácil de analizar.

Nunca se ejecuta ni se renderiza el contenido: el HTML se recorre como texto
para extraer enlaces, formularios y otras señales.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from email.utils import getaddresses, parseaddr, parsedate_to_datetime
from html.parser import HTMLParser

LIMITE_ADJUNTO = 15 * 1024 * 1024  # bytes que se inspeccionan por adjunto
RE_URL_TEXTO = re.compile(r"(?:https?://|www\.)[^\s<>\"'()\[\]{}]+", re.IGNORECASE)
RE_AUTH = re.compile(r"\b(spf|dkim|dmarc)\s*=\s*([a-z]+)", re.IGNORECASE)


@dataclass
class Enlace:
    url: str
    texto: str = ""
    origen: str = "texto"  # texto | html | formulario | refresh


@dataclass
class Adjunto:
    nombre: str
    tipo_mime: str
    tamano: int
    sha256: str
    contenido: bytes = field(default=b"", repr=False)


@dataclass
class InfoHTML:
    formularios: list[str] = field(default_factory=list)  # valores de action
    campos_password: int = 0
    campos_texto: int = 0
    scripts: int = 0
    iframes: int = 0
    elementos_ocultos: int = 0
    imagenes: int = 0
    meta_refresh: str = ""


@dataclass
class CorreoParseado:
    crudo: bytes
    message_id: str = ""
    fecha: datetime | None = None
    remitente_nombre: str = ""
    remitente_email: str = ""
    remitente_dominio: str = ""
    responder_a: str = ""
    return_path: str = ""
    destinatarios: list[str] = field(default_factory=list)
    cc: list[str] = field(default_factory=list)
    asunto: str = ""
    texto: str = ""
    html: str = ""
    texto_html: str = ""
    enlaces: list[Enlace] = field(default_factory=list)
    adjuntos: list[Adjunto] = field(default_factory=list)
    mensajes_adjuntos: list[bytes] = field(default_factory=list, repr=False)
    autenticacion: dict[str, str] = field(default_factory=dict)
    cabeceras_autenticacion: list[str] = field(default_factory=list)  # Authentication-Results / Received-SPF
    recibidos: list[str] = field(default_factory=list)
    en_respuesta_a: str = ""
    referencias: str = ""
    x_mailer: str = ""
    info_html: InfoHTML = field(default_factory=InfoHTML)

    @property
    def cuerpo(self) -> str:
        """Texto legible del cuerpo (prefiere la parte de texto plano)."""
        return self.texto.strip() or self.texto_html.strip()

    @property
    def texto_completo(self) -> str:
        return f"{self.asunto}\n{self.texto}\n{self.texto_html}"

    @property
    def huella(self) -> str:
        return hashlib.sha256(self.crudo).hexdigest()


class _LectorHTML(HTMLParser):
    BLOQUES = {"p", "div", "br", "tr", "li", "h1", "h2", "h3", "h4", "table", "td", "section"}
    ESTILOS_OCULTOS = ("display:none", "visibility:hidden", "font-size:0", "font-size:1px", "opacity:0", "max-height:0")

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.partes: list[str] = []
        self.enlaces: list[Enlace] = []
        self.info = InfoHTML()
        self._ancla: Enlace | None = None
        self._ignorar = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        estilo = a.get("style", "").replace(" ", "").lower()
        if any(e in estilo for e in self.ESTILOS_OCULTOS) or "hidden" in a:
            self.info.elementos_ocultos += 1
        if tag in ("script", "style"):
            self._ignorar += 1
            if tag == "script":
                self.info.scripts += 1
        elif tag in ("a", "area") and a.get("href"):
            self._ancla = Enlace(url=a["href"].strip(), texto="", origen="html")
            if tag == "area":
                self.enlaces.append(self._ancla)
                self._ancla = None
        elif tag == "form":
            self.info.formularios.append(a.get("action", ""))
            if a.get("action"):
                self.enlaces.append(Enlace(url=a["action"].strip(), origen="formulario"))
        elif tag == "input":
            tipo = a.get("type", "text").lower()
            if tipo == "password":
                self.info.campos_password += 1
            elif tipo in ("text", "email", "tel", "number"):
                self.info.campos_texto += 1
        elif tag == "iframe":
            self.info.iframes += 1
        elif tag == "img":
            self.info.imagenes += 1
        elif tag == "meta" and a.get("http-equiv", "").lower() == "refresh":
            m = re.search(r"url\s*=\s*['\"]?([^'\";]+)", a.get("content", ""), re.IGNORECASE)
            if m:
                self.info.meta_refresh = m.group(1).strip()
                self.enlaces.append(Enlace(url=self.info.meta_refresh, origen="refresh"))
        if tag in self.BLOQUES:
            self.partes.append("\n")

    def handle_endtag(self, tag: str) -> None:
        if tag in ("script", "style"):
            self._ignorar = max(0, self._ignorar - 1)
        elif tag == "a" and self._ancla is not None:
            self._ancla.texto = re.sub(r"\s+", " ", self._ancla.texto).strip()
            self.enlaces.append(self._ancla)
            self._ancla = None
        if tag in self.BLOQUES:
            self.partes.append("\n")

    def handle_data(self, data: str) -> None:
        if self._ignorar:
            return
        self.partes.append(data)
        if self._ancla is not None:
            self._ancla.texto += data

    def texto(self) -> str:
        texto = "".join(self.partes)
        texto = re.sub(r"[ \t\r\f\v]+", " ", texto)
        return re.sub(r"\n\s*\n+", "\n\n", texto).strip()


def _texto_parte(parte: Message) -> str:
    try:
        contenido = parte.get_content()  # type: ignore[attr-defined]
        if isinstance(contenido, bytes):
            return contenido.decode("utf-8", errors="replace")
        return str(contenido)
    except Exception:
        datos = parte.get_payload(decode=True) or b""
        charset = parte.get_content_charset() or "utf-8"
        try:
            return datos.decode(charset, errors="replace")
        except LookupError:
            return datos.decode("utf-8", errors="replace")


def _cabecera(msg: Message, nombre: str) -> str:
    try:
        valor = msg.get(nombre)
        return str(valor).strip() if valor is not None else ""
    except Exception:
        crudos = msg.get_all(nombre, failobj=[]) if hasattr(msg, "get_all") else []
        return str(crudos[0]).strip() if crudos else ""


def _direcciones(msg: Message, nombre: str) -> list[str]:
    try:
        valores = [str(v) for v in msg.get_all(nombre, failobj=[])]
        return [d.lower() for _, d in getaddresses(valores) if d and "@" in d]
    except Exception:
        return []


def _autenticacion(msg: Message) -> dict[str, str]:
    resultado: dict[str, str] = {}
    # La primera cabecera Authentication-Results la agrega el servidor receptor (la más confiable)
    for cabecera in msg.get_all("Authentication-Results", failobj=[])[:2]:
        for mecanismo, valor in RE_AUTH.findall(str(cabecera)):
            resultado.setdefault(mecanismo.lower(), valor.lower())
    if "spf" not in resultado:
        spf = _cabecera(msg, "Received-SPF")
        if spf:
            resultado["spf"] = spf.split()[0].lower()
    return resultado


def _fecha(msg: Message) -> datetime | None:
    try:
        dt = parsedate_to_datetime(_cabecera(msg, "Date"))
    except Exception:
        return None
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).replace(tzinfo=None)


def parsear(crudo: bytes) -> CorreoParseado:
    msg: EmailMessage = BytesParser(policy=policy.default).parsebytes(crudo)  # type: ignore[assignment]

    nombre, email = parseaddr(_cabecera(msg, "From"))
    email = email.strip().lower()
    _, responder = parseaddr(_cabecera(msg, "Reply-To"))
    _, return_path = parseaddr(_cabecera(msg, "Return-Path"))

    correo = CorreoParseado(
        crudo=crudo,
        message_id=_cabecera(msg, "Message-ID")[:500],
        fecha=_fecha(msg),
        remitente_nombre=nombre.strip().strip('"'),
        remitente_email=email,
        remitente_dominio=email.rsplit("@", 1)[-1] if "@" in email else "",
        responder_a=responder.strip().lower(),
        return_path=return_path.strip().lower(),
        destinatarios=_direcciones(msg, "To"),
        cc=_direcciones(msg, "Cc"),
        asunto=re.sub(r"\s+", " ", _cabecera(msg, "Subject"))[:990],
        autenticacion=_autenticacion(msg),
        cabeceras_autenticacion=[str(c) for c in (msg.get_all("Authentication-Results", failobj=[])[:2]
                                                  + msg.get_all("Received-SPF", failobj=[])[:1])],
        recibidos=[str(r) for r in msg.get_all("Received", failobj=[])],
        en_respuesta_a=_cabecera(msg, "In-Reply-To"),
        referencias=_cabecera(msg, "References"),
        x_mailer=_cabecera(msg, "X-Mailer"),
    )

    textos: list[str] = []
    htmls: list[str] = []
    _recorrer(msg, correo, textos, htmls)
    correo.texto = "\n".join(textos).strip()
    correo.html = "\n".join(htmls)

    if correo.html:
        lector = _LectorHTML()
        try:
            lector.feed(correo.html)
            lector.close()
        except Exception:
            pass
        correo.texto_html = lector.texto()
        correo.info_html = lector.info
        correo.enlaces.extend(lector.enlaces)

    vistos = {e.url for e in correo.enlaces}
    for m in RE_URL_TEXTO.finditer(f"{correo.texto}\n{correo.texto_html}"):
        url = m.group(0).rstrip(".,;:!?»”")
        if url.lower().startswith("www."):
            url = "http://" + url
        if url not in vistos:
            vistos.add(url)
            correo.enlaces.append(Enlace(url=url, origen="texto"))
    return correo


def _recorrer(parte: Message, correo: CorreoParseado, textos: list[str], htmls: list[str]) -> None:
    tipo = parte.get_content_type()
    if tipo == "message/rfc822":
        try:
            interno = parte.get_payload(0)
            datos = interno.as_bytes() if hasattr(interno, "as_bytes") else bytes(str(interno), "utf-8")
        except Exception:
            datos = b""
        if datos:
            correo.mensajes_adjuntos.append(datos)
            correo.adjuntos.append(
                Adjunto(
                    nombre=parte.get_filename() or "mensaje_adjunto.eml",
                    tipo_mime=tipo,
                    tamano=len(datos),
                    sha256=hashlib.sha256(datos).hexdigest(),
                )
            )
        return
    if parte.is_multipart():
        for sub in parte.get_payload():  # type: ignore[union-attr]
            if isinstance(sub, Message):
                _recorrer(sub, correo, textos, htmls)
        return

    nombre = parte.get_filename()
    disposicion = parte.get_content_disposition()
    if not nombre and disposicion != "attachment" and tipo in ("text/plain", "text/html"):
        (textos if tipo == "text/plain" else htmls).append(_texto_parte(parte))
        return

    try:
        datos = parte.get_payload(decode=True) or b""
    except Exception:
        datos = b""
    if not nombre and not datos:
        return
    correo.adjuntos.append(
        Adjunto(
            nombre=(nombre or f"sin_nombre.{tipo.split('/')[-1]}").strip(),
            tipo_mime=tipo,
            tamano=len(datos),
            sha256=hashlib.sha256(datos).hexdigest(),
            contenido=datos[:LIMITE_ADJUNTO],
        )
    )
