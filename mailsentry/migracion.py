"""Herramientas de base de datos: verificar la conexión y copiar datos entre bases (p. ej. SQLite → Supabase)."""

from __future__ import annotations

import time

from sqlalchemy import create_engine, func, inspect, select, text

from .config import describir_url_bd
from .db import Base, _migrar

LOTE = 500


def _motor(url: str):
    argumentos = {}
    if not url.startswith("sqlite"):
        argumentos = {"pool_pre_ping": True, "connect_args": {"prepare_threshold": None, "connect_timeout": 15}}
    return create_engine(url, future=True, **argumentos)


def verificar(url: str) -> dict:
    """Conecta, mide la latencia y cuenta los registros de cada tabla."""
    motor = _motor(url)
    inicio = time.perf_counter()
    with motor.connect() as c:
        version = c.execute(text("select version()" if not url.startswith("sqlite") else "select sqlite_version()")).scalar()
    latencia = (time.perf_counter() - inicio) * 1000
    Base.metadata.create_all(motor)
    _migrar(motor)
    conteo = {}
    with motor.connect() as c:
        for tabla in Base.metadata.sorted_tables:
            conteo[tabla.name] = c.execute(select(func.count()).select_from(tabla)).scalar()
    motor.dispose()
    return {"url": describir_url_bd(url), "version": str(version).split(",")[0], "latencia_ms": round(latencia),
            "tablas": conteo}


def copiar(origen: str, destino: str, forzar: bool = False, al_avanzar=print) -> dict:
    """Copia todas las tablas de MailSentry de una base a otra. El destino debe estar vacío (o usar forzar)."""
    m_origen, m_destino = _motor(origen), _motor(destino)
    for motor in (m_origen, m_destino):
        Base.metadata.create_all(motor)
        _migrar(motor)

    with m_destino.connect() as c:
        ocupadas = {t.name: c.execute(select(func.count()).select_from(t)).scalar() for t in Base.metadata.sorted_tables}
    if any(ocupadas.values()):
        if not forzar:
            raise RuntimeError(f"El destino ya tiene datos ({ {k: v for k, v in ocupadas.items() if v} }). "
                               "Use --forzar para vaciarlo y reemplazarlo.")
        with m_destino.begin() as c:
            for tabla in reversed(Base.metadata.sorted_tables):
                c.execute(tabla.delete())

    copiados = {}
    with m_origen.connect() as lectura, m_destino.begin() as escritura:
        for tabla in Base.metadata.sorted_tables:
            columnas_origen = {col["name"] for col in inspect(m_origen).get_columns(tabla.name)}
            columnas = [c for c in tabla.columns if c.name in columnas_origen]
            total = 0
            resultado = lectura.execute(select(*columnas)).mappings()
            while True:
                filas = resultado.fetchmany(LOTE)
                if not filas:
                    break
                escritura.execute(tabla.insert(), [dict(f) for f in filas])
                total += len(filas)
            copiados[tabla.name] = total
            al_avanzar(f"  {tabla.name}: {total} registros")
        # En PostgreSQL, los contadores de id deben continuar después del último copiado
        if m_destino.dialect.name == "postgresql":
            for tabla in Base.metadata.sorted_tables:
                pk = list(tabla.primary_key.columns)
                if len(pk) == 1 and pk[0].autoincrement is not False and str(pk[0].type).upper().startswith("INT"):
                    escritura.execute(text(
                        f"select setval(pg_get_serial_sequence('{tabla.name}', '{pk[0].name}'), "
                        f"coalesce((select max({pk[0].name}) from {tabla.name}), 0) + 1, false)"))
    m_origen.dispose()
    m_destino.dispose()
    return copiados
