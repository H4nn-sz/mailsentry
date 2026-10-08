"""Modelo de datos (SQLAlchemy). Funciona con SQLite y con PostgreSQL sin cambios."""

from __future__ import annotations

import zlib
from contextlib import contextmanager
from datetime import datetime
from typing import Iterator

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    Integer,
    LargeBinary,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    inspect,
    text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .util import ahora


class Base(DeclarativeBase):
    pass


class Correo(Base):
    """Un correo analizado y el resultado de su análisis."""

    __tablename__ = "correos"

    id: Mapped[int] = mapped_column(primary_key=True)
    huella: Mapped[str] = mapped_column(String(64), unique=True)  # sha256 del original
    message_id: Mapped[str | None] = mapped_column(String(512), index=True)
    fuente: Mapped[str] = mapped_column(String(20), default="carga")  # imap | graph | carga | cli | api | demo
    buzon: Mapped[str | None] = mapped_column(String(120), index=True)
    reportado_por: Mapped[str | None] = mapped_column(String(320))

    recibido_en: Mapped[datetime] = mapped_column(DateTime, index=True)
    analizado_en: Mapped[datetime] = mapped_column(DateTime, default=ahora)

    remitente_nombre: Mapped[str] = mapped_column(String(320), default="")
    remitente_email: Mapped[str] = mapped_column(String(320), default="", index=True)
    remitente_dominio: Mapped[str] = mapped_column(String(255), default="", index=True)
    responder_a: Mapped[str] = mapped_column(String(320), default="")
    destinatarios: Mapped[str] = mapped_column(Text, default="")
    destinatario_principal: Mapped[str] = mapped_column(String(320), default="", index=True)
    asunto: Mapped[str] = mapped_column(String(998), default="")
    resumen: Mapped[str] = mapped_column(Text, default="")
    texto: Mapped[str] = mapped_column(Text, default="")  # texto usado por el modelo de IA

    puntaje: Mapped[int] = mapped_column(Integer, default=0, index=True)
    puntaje_heuristico: Mapped[int] = mapped_column(Integer, default=0)
    prob_ml: Mapped[float | None] = mapped_column(Float)
    veredicto: Mapped[str] = mapped_column(String(20), index=True)  # legitimo | sospechoso | phishing
    nivel_riesgo: Mapped[str] = mapped_column(String(10), index=True)  # bajo | medio | alto | critico
    categoria: Mapped[str] = mapped_column(String(40), index=True)
    marca_suplantada: Mapped[str | None] = mapped_column(String(80), index=True)

    indicadores: Mapped[list] = mapped_column(JSON, default=list)
    urls: Mapped[list] = mapped_column(JSON, default=list)
    adjuntos: Mapped[list] = mapped_column(JSON, default=list)
    autenticacion: Mapped[dict] = mapped_column(JSON, default=dict)

    # Origen: servidor que entregó el correo (ver origen.py para sus límites)
    ip_origen: Mapped[str | None] = mapped_column(String(45))
    pais_origen: Mapped[str | None] = mapped_column(String(2), index=True)
    servidor_origen: Mapped[str | None] = mapped_column(String(255))
    proveedor_origen: Mapped[str | None] = mapped_column(String(60))
    metodo_origen: Mapped[str | None] = mapped_column(String(20))

    # Flujo de trabajo del analista
    estado: Mapped[str] = mapped_column(String(20), default="nuevo", index=True)
    etiqueta: Mapped[str | None] = mapped_column(String(20))  # verdad confirmada: phishing | legitimo
    revisado_por: Mapped[str | None] = mapped_column(String(120))
    revisado_en: Mapped[datetime | None] = mapped_column(DateTime)
    notas: Mapped[str] = mapped_column(Text, default="")

    original: Mapped[bytes | None] = mapped_column(LargeBinary, deferred=True)  # .eml comprimido con zlib

    @property
    def veredicto_efectivo(self) -> str:
        """Veredicto teniendo en cuenta la corrección del analista."""
        return efectivo(self.veredicto, self.etiqueta)

    def original_bytes(self) -> bytes | None:
        return zlib.decompress(self.original) if self.original else None


def efectivo(veredicto: str, etiqueta: str | None) -> str:
    if etiqueta == "phishing":
        return "phishing"
    if etiqueta == "legitimo":
        return "legitimo"
    return veredicto


class Empleado(Base):
    """Personal de la empresa: permite ver a quién atacan y detectar suplantación de directivos."""

    __tablename__ = "empleados"

    id: Mapped[int] = mapped_column(primary_key=True)
    email: Mapped[str] = mapped_column(String(320), unique=True)
    nombre: Mapped[str] = mapped_column(String(200), default="")
    departamento: Mapped[str] = mapped_column(String(120), default="Sin asignar", index=True)
    cargo: Mapped[str] = mapped_column(String(120), default="")
    es_vip: Mapped[bool] = mapped_column(Boolean, default=False)  # directivos: objetivo típico de suplantación
    creado_en: Mapped[datetime] = mapped_column(DateTime, default=ahora)


class ReglaLista(Base):
    """Listas administrables: dominios propios, remitentes permitidos y bloqueados."""

    __tablename__ = "listas"
    __table_args__ = (UniqueConstraint("tipo", "valor"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    tipo: Mapped[str] = mapped_column(String(20), index=True)  # propio | permitido | bloqueado
    valor: Mapped[str] = mapped_column(String(320))  # dominio o dirección de correo
    nota: Mapped[str] = mapped_column(String(300), default="")
    creado_por: Mapped[str] = mapped_column(String(120), default="")
    creado_en: Mapped[datetime] = mapped_column(DateTime, default=ahora)


class Usuario(Base):
    __tablename__ = "usuarios"

    id: Mapped[int] = mapped_column(primary_key=True)
    usuario: Mapped[str] = mapped_column(String(80), unique=True)
    nombre: Mapped[str] = mapped_column(String(160), default="")
    password_hash: Mapped[str] = mapped_column(String(300))
    rol: Mapped[str] = mapped_column(String(20), default="analista")  # admin | analista | lector
    activo: Mapped[bool] = mapped_column(Boolean, default=True)
    creado_en: Mapped[datetime] = mapped_column(DateTime, default=ahora)
    ultimo_acceso: Mapped[datetime | None] = mapped_column(DateTime)


class EstadoBuzon(Base):
    """Punto de avance de cada buzón vigilado (para no reanalizar correos)."""

    __tablename__ = "estado_buzones"

    nombre: Mapped[str] = mapped_column(String(120), primary_key=True)
    uidvalidity: Mapped[int | None] = mapped_column(Integer)
    ultimo_uid: Mapped[int] = mapped_column(Integer, default=0)
    cursor_fecha: Mapped[str | None] = mapped_column(String(40))
    ultima_revision: Mapped[datetime | None] = mapped_column(DateTime)
    ultimo_error: Mapped[str | None] = mapped_column(Text)
    total_procesados: Mapped[int] = mapped_column(Integer, default=0)


class Ajuste(Base):
    """Configuración editable desde el panel (nombre de la empresa, ubicación, asistente completado)."""

    __tablename__ = "ajustes"

    clave: Mapped[str] = mapped_column(String(60), primary_key=True)
    valor: Mapped[dict | list | str | None] = mapped_column(JSON)


def leer_ajustes(s: Session) -> dict:
    from sqlalchemy import select

    return {a.clave: a.valor for a in s.scalars(select(Ajuste))}


def guardar_ajuste(s: Session, clave: str, valor) -> None:
    ajuste = s.get(Ajuste, clave)
    if ajuste is None:
        s.add(Ajuste(clave=clave, valor=valor))
    else:
        ajuste.valor = valor


class Evento(Base):
    """Bitácora de auditoría de acciones de los usuarios."""

    __tablename__ = "eventos"

    id: Mapped[int] = mapped_column(primary_key=True)
    fecha: Mapped[datetime] = mapped_column(DateTime, default=ahora, index=True)
    usuario: Mapped[str] = mapped_column(String(80), default="sistema")
    accion: Mapped[str] = mapped_column(String(60))
    detalle: Mapped[str] = mapped_column(Text, default="")


_motor = None
_Sesion: sessionmaker | None = None
_url_actual: str | None = None


def inicializar(url: str) -> None:
    """Crea el motor de base de datos y las tablas (idempotente)."""
    global _motor, _Sesion, _url_actual
    if _url_actual == url and _motor is not None:
        return
    argumentos = {}
    if url.startswith("sqlite"):
        argumentos["connect_args"] = {"check_same_thread": False, "timeout": 30}
    _motor = create_engine(url, future=True, **argumentos)
    if url.startswith("sqlite"):

        @event.listens_for(_motor, "connect")
        def _pragmas(conexion, _registro):
            cursor = conexion.cursor()
            cursor.execute("PRAGMA journal_mode=WAL")
            cursor.execute("PRAGMA synchronous=NORMAL")
            cursor.close()

    Base.metadata.create_all(_motor)
    _migrar(_motor)
    _Sesion = sessionmaker(bind=_motor, expire_on_commit=False)
    _url_actual = url


def _migrar(motor) -> None:
    """Agrega las columnas nuevas a bases de datos creadas con versiones anteriores."""
    inspector = inspect(motor)
    for tabla in Base.metadata.sorted_tables:
        if not inspector.has_table(tabla.name):
            continue
        existentes = {c["name"] for c in inspector.get_columns(tabla.name)}
        for columna in tabla.columns:
            if columna.name in existentes or not columna.nullable:
                continue
            tipo = columna.type.compile(dialect=motor.dialect)
            with motor.begin() as conexion:
                conexion.execute(text(f"ALTER TABLE {tabla.name} ADD COLUMN {columna.name} {tipo}"))
            for indice in tabla.indexes:
                if columna in indice.columns:
                    indice.create(motor, checkfirst=True)


@contextmanager
def sesion() -> Iterator[Session]:
    if _Sesion is None:
        raise RuntimeError("Base de datos no inicializada: llame a db.inicializar(url)")
    s = _Sesion()
    try:
        yield s
    except Exception:
        s.rollback()
        raise
    finally:
        s.close()


def registrar_evento(s: Session, usuario: str, accion: str, detalle: str = "") -> None:
    s.add(Evento(usuario=usuario or "sistema", accion=accion, detalle=detalle[:2000]))


def comprimir(datos: bytes) -> bytes:
    return zlib.compress(datos, 6)
