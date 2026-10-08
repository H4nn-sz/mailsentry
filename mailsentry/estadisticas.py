"""Estadísticas para el panel, el reporte ejecutivo y la API."""

from __future__ import annotations

from collections import Counter
from datetime import date, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from . import geoip, paises
from .config import Config
from .db import Correo, Empleado, efectivo
from .deteccion.modelos import CATEGORIAS, ESTADOS, NIVELES
from .util import a_local, ahora, zona

PERIODOS = {
    "7d": ("Últimos 7 días", 7),
    "30d": ("Últimos 30 días", 30),
    "90d": ("Últimos 90 días", 90),
    "12m": ("Últimos 12 meses", 365),
    "todo": ("Todo el historial", None),
}
AMENAZAS = ("phishing", "sospechoso")
MESES_CORTOS = ("ene", "feb", "mar", "abr", "may", "jun", "jul", "ago", "sep", "oct", "nov", "dic")


def rango(periodo: str) -> tuple[datetime | None, datetime]:
    dias = PERIODOS.get(periodo, PERIODOS["30d"])[1]
    hasta = ahora()
    return (hasta - timedelta(days=dias) if dias else None), hasta


def _consulta(s: Session, desde: datetime | None, hasta: datetime, buzon: str | None):
    q = select(
        Correo.id, Correo.recibido_en, Correo.veredicto, Correo.etiqueta, Correo.categoria, Correo.nivel_riesgo,
        Correo.marca_suplantada, Correo.remitente_dominio, Correo.destinatario_principal, Correo.estado,
        Correo.pais_origen, Correo.proveedor_origen, Correo.ip_origen,
    ).where(Correo.recibido_en <= hasta)
    if desde is not None:
        q = q.where(Correo.recibido_en > desde)
    if buzon:
        q = q.where(Correo.buzon == buzon)
    return s.execute(q).all()


def _totales(filas) -> dict:
    efectivos = [efectivo(f.veredicto, f.etiqueta) for f in filas]
    total = len(filas)
    phishing = efectivos.count("phishing")
    return {
        "analizados": total,
        "phishing": phishing,
        "sospechosos": efectivos.count("sospechoso"),
        "legitimos": efectivos.count("legitimo"),
        "tasa_phishing": round(phishing * 100 / total, 1) if total else 0.0,
        "pendientes": sum(1 for f, e in zip(filas, efectivos) if e in AMENAZAS and f.estado == "nuevo"),
        "malware": sum(1 for f, e in zip(filas, efectivos) if e == "phishing" and f.categoria == "malware"),
    }


def _serie(filas, desde: date, hasta: date, tz) -> dict:
    """Amenazas por día, semana o mes según la amplitud del periodo."""
    dias = (hasta - desde).days + 1
    if dias <= 92:
        unidad = "día"
        clave = lambda d: d  # noqa: E731
        etiqueta = lambda d: f"{d.day} {MESES_CORTOS[d.month - 1]}"  # noqa: E731
        paso = lambda d: d + timedelta(days=1)  # noqa: E731
        inicio = desde
    elif dias <= 730:
        unidad = "semana"
        clave = lambda d: d - timedelta(days=d.weekday())  # noqa: E731
        etiqueta = lambda d: f"{d.day} {MESES_CORTOS[d.month - 1]}"  # noqa: E731
        paso = lambda d: d + timedelta(days=7)  # noqa: E731
        inicio = clave(desde)
    else:
        unidad = "mes"
        clave = lambda d: d.replace(day=1)  # noqa: E731
        etiqueta = lambda d: f"{MESES_CORTOS[d.month - 1]} {d.year}"  # noqa: E731
        paso = lambda d: (d.replace(day=28) + timedelta(days=4)).replace(day=1)  # noqa: E731
        inicio = clave(desde)

    cubetas: list[date] = []
    actual = inicio
    while actual <= hasta:
        cubetas.append(actual)
        actual = paso(actual)
    indice = {c: i for i, c in enumerate(cubetas)}
    phishing = [0] * len(cubetas)
    sospechosos = [0] * len(cubetas)
    for f in filas:
        e = efectivo(f.veredicto, f.etiqueta)
        if e not in AMENAZAS:
            continue
        i = indice.get(clave(a_local(f.recibido_en, tz).date()))
        if i is not None:
            (phishing if e == "phishing" else sospechosos)[i] += 1
    return {
        "unidad": unidad,
        "etiquetas": [etiqueta(c) for c in cubetas],
        "fechas": [c.isoformat() for c in cubetas],
        "phishing": phishing,
        "sospechosos": sospechosos,
    }


def _origenes(amenazas, config: Config) -> dict:
    """De dónde vienen las amenazas: país del servidor de envío (solo envíos directos).

    Los correos que llegan vía Gmail, Outlook u otro gran proveedor se cuentan aparte:
    la IP es la del proveedor y no dice nada del atacante.
    """
    directos = [f for f in amenazas if f.pais_origen and not f.proveedor_origen]
    por_pais = Counter(f.pais_origen for f in directos)
    phishing_pais = Counter(f.pais_origen for f in directos if efectivo(f.veredicto, f.etiqueta) == "phishing")
    origenes = []
    for codigo, valor in por_pais.most_common():
        coordenadas = paises.coordenadas(codigo)
        origenes.append({
            "codigo": codigo, "pais": paises.nombre(codigo), "region": paises.region(codigo),
            "lat": coordenadas[0] if coordenadas else None, "lon": coordenadas[1] if coordenadas else None,
            "valor": valor, "phishing": phishing_pais.get(codigo, 0),
        })
    regiones = Counter(paises.region(f.pais_origen) for f in directos)
    proveedores = Counter(f.proveedor_origen for f in amenazas if f.proveedor_origen)
    return {
        "origenes": origenes,
        "regiones": [{"etiqueta": k, "valor": v} for k, v in regiones.most_common()],
        "via_proveedor": [{"etiqueta": k, "valor": v} for k, v in proveedores.most_common()],
        "sin_origen": sum(1 for f in amenazas if not f.pais_origen and not f.proveedor_origen),
        "con_ip_sin_pais": sum(1 for f in amenazas if f.ip_origen and not f.pais_origen and not f.proveedor_origen),
        "geoip_disponible": geoip.cargar(config.ruta_geoip) is not None,
        "demo": config.geoip_demo,
        "ubicacion": list(config.ubicacion),
    }


def calcular(s: Session, config: Config, periodo: str = "30d", buzon: str | None = None) -> dict:
    tz = zona(config.zona_horaria)
    desde, hasta = rango(periodo)
    filas = _consulta(s, desde, hasta, buzon)
    if desde is None:
        primero = min((f.recibido_en for f in filas), default=hasta - timedelta(days=30))
        desde_efectivo = primero - timedelta(seconds=1)
        previas = None
    else:
        desde_efectivo = desde
        previas = _consulta(s, desde - (hasta - desde), desde, buzon)

    amenazas = [f for f in filas if efectivo(f.veredicto, f.etiqueta) in AMENAZAS]
    phishing = [f for f in filas if efectivo(f.veredicto, f.etiqueta) == "phishing"]
    empleados = {e.email: e for e in s.scalars(select(Empleado))}

    def persona(email: str) -> dict:
        e = empleados.get(email)
        return {"email": email, "nombre": (e.nombre if e and e.nombre else email) or "(sin destinatario)",
                "departamento": e.departamento if e else "Externo / sin asignar"}

    categorias = Counter(f.categoria for f in amenazas if f.categoria not in ("ninguna", None))
    objetivos = Counter(f.destinatario_principal for f in amenazas if f.destinatario_principal)
    departamentos = Counter(persona(f.destinatario_principal)["departamento"] for f in amenazas)
    marcas = Counter(f.marca_suplantada for f in amenazas if f.marca_suplantada)
    dominios = Counter(f.remitente_dominio for f in phishing if f.remitente_dominio)
    niveles = Counter(f.nivel_riesgo for f in amenazas)

    recientes_ids = [f.id for f in sorted(amenazas, key=lambda f: f.recibido_en, reverse=True)[:8]]
    recientes = []
    if recientes_ids:
        por_id = {c.id: c for c in s.scalars(select(Correo).where(Correo.id.in_(recientes_ids)))}
        for i in recientes_ids:
            c = por_id[i]
            recientes.append({
                "id": c.id,
                "fecha": a_local(c.recibido_en, tz).strftime("%d/%m %H:%M"),
                "remitente": c.remitente_nombre or c.remitente_email,
                "remitente_email": c.remitente_email,
                "asunto": c.asunto,
                "destinatario": persona(c.destinatario_principal)["nombre"],
                "categoria": CATEGORIAS.get(c.categoria, c.categoria),
                "nivel": c.nivel_riesgo,
                "nivel_txt": NIVELES.get(c.nivel_riesgo, c.nivel_riesgo),
                "veredicto": c.veredicto_efectivo,
                "estado": ESTADOS.get(c.estado, c.estado),
                "puntaje": c.puntaje,
            })

    return {
        "periodo": periodo,
        "periodo_txt": PERIODOS.get(periodo, PERIODOS["30d"])[0],
        "desde": a_local(desde_efectivo, tz).strftime("%d/%m/%Y"),
        "hasta": a_local(hasta, tz).strftime("%d/%m/%Y"),
        "totales": _totales(filas),
        # Sin correos en el periodo anterior no hay comparación honesta posible
        # (si el periodo anterior casi no tiene datos, p. ej. recién se instaló, la comparación engaña)
        "previo": _totales(previas) if previas and len(previas) >= 0.2 * max(1, len(filas)) else None,
        "serie": _serie(filas, a_local(desde_efectivo, tz).date(), a_local(hasta, tz).date(), tz),
        "categorias": [{"clave": k, "etiqueta": CATEGORIAS.get(k, k), "valor": v} for k, v in categorias.most_common()],
        "objetivos": [{**persona(k), "valor": v} for k, v in objetivos.most_common(8)],
        "departamentos": [{"etiqueta": k, "valor": v} for k, v in departamentos.most_common(8)],
        "marcas": [{"etiqueta": k, "valor": v} for k, v in marcas.most_common(8)],
        "dominios": [{"dominio": k, "valor": v} for k, v in dominios.most_common(8)],
        "niveles": {n: niveles.get(n, 0) for n in NIVELES},
        "recientes": recientes,
        "origen": _origenes(amenazas, config),
    }


def codigos_indicadores(s: Session, desde: datetime | None, hasta: datetime) -> Counter:
    """Cuántas amenazas del periodo presentan cada indicador (para recomendaciones)."""
    q = select(Correo.indicadores, Correo.veredicto, Correo.etiqueta).where(Correo.recibido_en <= hasta)
    if desde is not None:
        q = q.where(Correo.recibido_en > desde)
    conteo: Counter = Counter()
    for indicadores, veredicto, etiqueta in s.execute(q):
        if efectivo(veredicto, etiqueta) in AMENAZAS:
            conteo.update({i["codigo"] for i in indicadores or [] if i.get("puntos", 0) > 0})
    return conteo


def recomendaciones(s: Session, datos: dict) -> list[dict]:
    """Recomendaciones concretas a partir de lo que realmente se recibió."""
    desde, hasta = rango(datos["periodo"])
    codigos = codigos_indicadores(s, desde, hasta)
    categorias = {c["clave"]: c["valor"] for c in datos["categorias"]}
    total_amenazas = sum(categorias.values())
    lista: list[dict] = []

    def agregar(prioridad: str, titulo: str, texto: str) -> None:
        lista.append({"prioridad": prioridad, "titulo": titulo, "texto": texto})

    fraude = categorias.get("bec", 0) + categorias.get("fraude_pagos", 0)
    if fraude:
        agregar("alta", "Verificar por teléfono todo pago o cambio de cuenta",
                f"Se recibieron {fraude} intentos de fraude del CEO o de facturas. Establezca que ningún pago urgente "
                "ni cambio de datos bancarios se ejecute sin confirmar por teléfono con un número ya conocido.")
    if codigos.get("DOMINIO_SIMILAR_PROPIO") or codigos.get("URL_SIMILAR_PROPIO"):
        n = codigos.get("DOMINIO_SIMILAR_PROPIO", 0) + codigos.get("URL_SIMILAR_PROPIO", 0)
        agregar("alta", "Hay dominios que imitan al de su empresa",
                f"{n} correos usaron dominios parecidos al suyo. Registre las variantes más obvias de su dominio "
                "y avise a clientes y proveedores para que desconfíen de ellas.")
    if codigos.get("SUPLANTACION_DOMINIO_PROPIO"):
        agregar("alta", "Están falsificando su propio dominio",
                "Configure SPF, DKIM y DMARC con política p=reject en su dominio para que los servidores rechacen "
                "correos falsificados a su nombre.")
    if categorias.get("credenciales") or categorias.get("suplantacion_marca"):
        agregar("media", "Activar la verificación en dos pasos (MFA)",
                "Hubo intentos de robo de contraseñas. Con MFA, una contraseña robada no basta para entrar a las "
                "cuentas de correo, banca y sistemas.")
    if categorias.get("malware"):
        agregar("media", "Bloquear adjuntos peligrosos en el servidor de correo",
                "Se recibieron adjuntos maliciosos. Bloquee .exe, .js, .vbs, .iso, .html y archivos de Office con "
                "macros desde el panel de su proveedor de correo.")
    if datos["departamentos"] and total_amenazas >= 5:
        principal = datos["departamentos"][0]
        porcentaje = round(principal["valor"] * 100 / max(1, total_amenazas))
        if porcentaje >= 30:
            agregar("media", f"Priorizar la capacitación de {principal['etiqueta']}",
                    f"Esa área recibió el {porcentaje}% de los ataques. Una sesión práctica corta reduce mucho el "
                    "riesgo de que alguien caiga.")
    if datos["totales"]["pendientes"]:
        agregar("baja", "Revisar correos pendientes",
                f"Hay {datos['totales']['pendientes']} amenazas sin revisar. Confirmarlas o descartarlas también "
                "entrena al modelo de IA de MailSentry.")
    if not lista:
        agregar("baja", "Sin hallazgos relevantes", "No se detectaron patrones que requieran acción en este periodo.")
    return lista
