"""Servicio central: analiza un correo, lo guarda y dispara alertas.

Lo usan todas las entradas (buzones IMAP/Graph, carga manual, CLI y API),
así que el comportamiento es idéntico venga de donde venga el correo.
"""

from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from . import alertas, db, geoip, origen
from .config import Config
from .db import Correo, Empleado, ReglaLista
from .deteccion import Contexto, Persona, analizar
from .deteccion.dominios import dominio_registrable
from .deteccion.inteligencia import VirusTotal, cargar_feeds
from .deteccion.ml import modelo_cacheado, texto_para_modelo
from .deteccion.modelos import Resultado
from .parser import CorreoParseado, parsear
from .util import ahora, recortar

log = logging.getLogger(__name__)
_virustotal: dict[str, VirusTotal] = {}


@dataclass
class Procesado:
    correo: Correo
    nuevo: bool
    resultado: Resultado | None = None


def construir_contexto(s: Session, config: Config) -> Contexto:
    propios = set(config.dominios_propios)
    permitidos, bloqueados = set(), set()
    for regla in s.scalars(select(ReglaLista)):
        {"propio": propios, "permitido": permitidos, "bloqueado": bloqueados}.get(regla.tipo, set()).add(regla.valor)

    vips, empleados = [], []
    for e in s.scalars(select(Empleado).where(Empleado.nombre != "")):
        (vips if e.es_vip else empleados).append(Persona(e.nombre, e.email, e.cargo))

    conocidos = {
        dominio_registrable(d)
        for d in s.scalars(select(Correo.remitente_dominio).where(Correo.veredicto == "legitimo").distinct())
        if d
    }
    clave_vt = config.virustotal_key
    if clave_vt and clave_vt not in _virustotal:
        _virustotal[clave_vt] = VirusTotal(clave_vt)

    return Contexto(
        dominios_propios=propios,
        vips=vips,
        empleados=empleados,
        permitidos=permitidos,
        bloqueados=bloqueados,
        dominios_conocidos=conocidos,
        feeds=cargar_feeds(),
        modelo=modelo_cacheado(config.ruta_modelo) if config.peso_ml > 0 else None,
        intel=_virustotal.get(clave_vt) if clave_vt else None,
        umbral_sospechoso=config.umbral_sospechoso,
        umbral_phishing=config.umbral_phishing,
        umbral_critico=config.umbral_critico,
        peso_ml=config.peso_ml,
    )


def _aplicar_resultado(correo: Correo, parseado: CorreoParseado, resultado: Resultado) -> None:
    correo.puntaje = resultado.puntaje
    correo.puntaje_heuristico = resultado.puntaje_heuristico
    correo.prob_ml = resultado.prob_ml
    correo.veredicto = resultado.veredicto
    correo.nivel_riesgo = resultado.nivel
    correo.categoria = resultado.categoria
    correo.marca_suplantada = resultado.marca
    correo.indicadores = [i.a_dict() for i in resultado.indicadores]
    correo.analizado_en = ahora()
    correo.texto = texto_para_modelo(parseado)


def _aplicar_origen(correo: Correo, parseado: CorreoParseado, config: Config) -> None:
    """IP y país del servidor que entregó el correo (ver origen.py: qué se puede y qué no se puede saber)."""
    datos = origen.determinar(parseado, permitir_documentacion=config.geoip_demo)
    base = geoip.cargar(config.ruta_geoip)
    correo.ip_origen = datos.ip
    correo.metodo_origen = datos.metodo or None
    correo.servidor_origen = datos.servidor or None
    correo.proveedor_origen = datos.proveedor
    correo.pais_origen = base.pais(datos.ip) if base and datos.ip else None


def _fecha_confiable(fecha):
    """La cabecera Date la escribe el remitente: si dice venir del futuro, se usa la hora de llegada."""
    actual = ahora()
    if fecha is None or fecha > actual + timedelta(minutes=10):
        return actual
    return fecha


def _registrar_empleados(s: Session, parseado: CorreoParseado, ctx: Contexto, resultado: Resultado) -> None:
    """Da de alta al personal automáticamente.

    - Los destinatarios internos (para estadísticas por persona y área).
    - El nombre de quien escribe desde un correo interno auténtico: así MailSentry aprende quién es
      quién y puede detectar cuando alguien externo usa ese nombre, sin configuración manual.
    """
    for direccion in {*parseado.destinatarios, *parseado.cc}:
        if ctx.es_propio(direccion.rsplit("@", 1)[-1]) and not s.scalar(
            select(Empleado.id).where(Empleado.email == direccion)
        ):
            s.add(Empleado(email=direccion))
            s.flush()

    auth = parseado.autenticacion
    autentico = auth.get("dmarc") == "pass" or (auth.get("spf") == "pass" and auth.get("dkim") == "pass")
    nombre = parseado.remitente_nombre.strip()
    if (autentico and nombre and "@" not in nombre and ctx.es_propio(parseado.remitente_dominio)
            and resultado.veredicto == "legitimo"):
        empleado = s.scalar(select(Empleado).where(Empleado.email == parseado.remitente_email))
        if empleado is None:
            s.add(Empleado(email=parseado.remitente_email, nombre=nombre[:200]))
        elif not empleado.nombre:
            empleado.nombre = nombre[:200]
        s.flush()


def procesar(
    crudo: bytes,
    config: Config,
    *,
    fuente: str = "carga",
    buzon: str | None = None,
    reportado_por: str | None = None,
    ctx: Contexto | None = None,
    alertar: bool = True,
    recibido_en=None,
) -> Procesado:
    """Analiza y guarda un correo. Si ya existía (misma huella), devuelve el registro previo."""
    huella = hashlib.sha256(crudo).hexdigest()
    with db.sesion() as s:
        existente = s.scalar(select(Correo).where(Correo.huella == huella))
        if existente:
            return Procesado(existente, False)

        parseado = parsear(crudo)
        ctx = ctx or construir_contexto(s, config)
        resultado = analizar(parseado, ctx)
        destinatarios = parseado.destinatarios + parseado.cc
        internos = [d for d in destinatarios if ctx.es_propio(d.rsplit("@", 1)[-1])]

        correo = Correo(
            huella=huella,
            message_id=parseado.message_id or None,
            fuente=fuente,
            buzon=buzon,
            reportado_por=reportado_por,
            recibido_en=recibido_en or _fecha_confiable(parseado.fecha),
            remitente_nombre=recortar(parseado.remitente_nombre, 300),
            remitente_email=parseado.remitente_email[:320],
            remitente_dominio=parseado.remitente_dominio[:255],
            responder_a=parseado.responder_a[:320],
            destinatarios=", ".join(destinatarios)[:5000],
            destinatario_principal=(internos or destinatarios or [""])[0][:320],
            asunto=parseado.asunto,
            resumen=recortar(parseado.cuerpo, 4000),
            urls=[{"url": e.url[:2000], "texto": e.texto[:200], "origen": e.origen} for e in parseado.enlaces[:100]],
            adjuntos=[{"nombre": a.nombre, "tipo": a.tipo_mime, "tamano": a.tamano, "sha256": a.sha256}
                      for a in parseado.adjuntos],
            autenticacion=parseado.autenticacion,
            original=db.comprimir(crudo) if config.guardar_original else None,
            estado="nuevo",
        )
        _aplicar_resultado(correo, parseado, resultado)
        _aplicar_origen(correo, parseado, config)
        s.add(correo)
        _registrar_empleados(s, parseado, ctx, resultado)
        s.commit()

    log.info("Analizado: %s | %s | %s", correo.remitente_email, recortar(correo.asunto, 60), resultado.resumen())
    if alertar and resultado.es_amenaza:
        alertas.notificar(correo, config)
    return Procesado(correo, True, resultado)


def procesar_desde_buzon(crudo: bytes, config: Config, *, buzon, ctx: Contexto | None, fuente: str) -> list[Procesado]:
    """En buzones de 'reportes' se analiza el correo reenviado como adjunto, no el reenvío."""
    if buzon.tipo == "reportes":
        externo = parsear(crudo)
        if externo.mensajes_adjuntos:
            return [
                procesar(interno, config, fuente=fuente, buzon=buzon.nombre, ctx=ctx,
                         reportado_por=externo.remitente_email)
                for interno in externo.mensajes_adjuntos
            ]
    return [procesar(crudo, config, fuente=fuente, buzon=buzon.nombre, ctx=ctx)]


def reanalizar(s: Session, correo: Correo, config: Config, ctx: Contexto | None = None) -> Resultado | None:
    """Vuelve a analizar un correo guardado (útil tras actualizar listas, directivos o el modelo de IA)."""
    crudo = correo.original_bytes()
    if not crudo:
        return None
    parseado = parsear(crudo)
    resultado = analizar(parseado, ctx or construir_contexto(s, config))
    _aplicar_resultado(correo, parseado, resultado)
    _aplicar_origen(correo, parseado, config)
    return resultado


def reanalizar_todo(config: Config) -> int:
    with db.sesion() as s:
        ctx = construir_contexto(s, config)
        total = 0
        for correo in s.scalars(select(Correo).where(Correo.original.is_not(None))):
            if reanalizar(s, correo, config, ctx):
                total += 1
        s.commit()
    return total


def datos_entrenamiento(s: Session, implicitos: bool = True) -> tuple[list[str], list[int]]:
    """Datos para la IA.

    - Correos con etiqueta confirmada por un analista (la 'verdad').
    - Opcionalmente, correos claramente legítimos (puntaje <= 10) que nadie reportó en más de
      7 días, como ejemplos negativos implícitos (hasta 3 por cada phishing confirmado).
    """
    filas = s.execute(select(Correo.texto, Correo.etiqueta).where(Correo.etiqueta.is_not(None))).all()
    textos = [t for t, _ in filas]
    etiquetas = [1 if e == "phishing" else 0 for _, e in filas]
    if implicitos:
        positivos = sum(etiquetas)
        cupo = max(0, positivos * 3 - (len(etiquetas) - positivos))
        if cupo:
            limite = ahora() - timedelta(days=7)
            extra = s.scalars(
                select(Correo.texto)
                .where(Correo.etiqueta.is_(None), Correo.veredicto == "legitimo", Correo.puntaje <= 10,
                       Correo.recibido_en < limite)
                .order_by(Correo.recibido_en.desc())
                .limit(cupo)
            ).all()
            textos += list(extra)
            etiquetas += [0] * len(extra)
    return textos, etiquetas


def conteo_etiquetas(s: Session) -> dict[str, int]:
    filas = s.execute(select(Correo.etiqueta, func.count()).where(Correo.etiqueta.is_not(None)).group_by(Correo.etiqueta))
    return {etiqueta: total for etiqueta, total in filas}
