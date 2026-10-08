"""Simulación de ataque: mide qué tan bien detecta MailSentry en una empresa ficticia.

Genera meses de correo (normal + ataques), lo procesa con el motor real y compara
cada veredicto con la verdad conocida. Sirve para validar cambios en las reglas.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field, replace

from sqlalchemy import delete

from . import db
from .config import Config
from .db import Correo, Empleado, ReglaLista
from .demo import DOMINIO_DEMO, EMPLEADOS, EMPRESA_DEMO, area_de, email_de, generar
from .servicio import construir_contexto, procesar


@dataclass
class Informe:
    total: int = 0
    vp: int = 0  # phishing detectado (phishing o sospechoso)
    fn: int = 0  # phishing que pasó como legítimo
    fp: int = 0  # legítimo marcado como phishing
    dudosos: int = 0  # legítimo marcado como sospechoso (va a revisión)
    vn: int = 0
    por_plantilla: dict = field(default_factory=lambda: defaultdict(Counter))
    errores: list = field(default_factory=list)

    @property
    def deteccion(self) -> float:
        return self.vp / max(1, self.vp + self.fn)

    @property
    def tasa_fp(self) -> float:
        return self.fp / max(1, self.fp + self.dudosos + self.vn)


def preparar_empresa(config: Config) -> Config:
    """Configura la base de datos con el personal y dominio de la empresa ficticia."""
    config = replace(config, empresa_nombre=f"{EMPRESA_DEMO} (DEMO)", dominios_propios=[DOMINIO_DEMO], buzones=[],
                     webhook_url="")
    db.inicializar(config.db_url)
    with db.sesion() as s:
        s.execute(delete(Correo))
        s.execute(delete(Empleado))
        s.execute(delete(ReglaLista))
        for usuario, nombre, area, cargo, vip in EMPLEADOS:
            s.add(Empleado(email=email_de(usuario), nombre=nombre, departamento=area, cargo=cargo, es_vip=vip))
        s.commit()
    return config


def simular(config: Config, dias: int = 90, semilla: int = 7, al_procesar=None) -> Informe:
    config = preparar_empresa(config)
    informe = Informe()
    ctx = None
    for i, (muestra, fecha, crudo) in enumerate(generar(dias, semilla)):
        if i % 20 == 0:  # el contexto "aprende" qué remitentes son habituales a medida que pasa el tiempo
            with db.sesion() as s:
                ctx = construir_contexto(s, config)
        area = area_de(muestra.para[0])
        buzon = {"Gerencia": "Gerencia", "Finanzas": "Finanzas", "Ventas": "Ventas"}.get(area, "Operaciones")
        p = procesar(crudo, config, fuente="demo", buzon=buzon, ctx=ctx, alertar=False)
        if not p.nuevo:
            continue
        veredicto = p.correo.veredicto
        informe.total += 1
        informe.por_plantilla[muestra.plantilla][veredicto] += 1
        if muestra.etiqueta == "phishing":
            if veredicto == "legitimo":
                informe.fn += 1
                informe.errores.append(("NO DETECTADO", muestra.plantilla, p.correo))
            else:
                informe.vp += 1
        else:
            if veredicto == "phishing":
                informe.fp += 1
                informe.errores.append(("FALSO POSITIVO", muestra.plantilla, p.correo))
            elif veredicto == "sospechoso":
                informe.dudosos += 1
            else:
                informe.vn += 1
        if al_procesar:
            al_procesar(muestra, p.correo)
    return informe
