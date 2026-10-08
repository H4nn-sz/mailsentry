"""Estructuras del resultado de un análisis."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field

CATEGORIAS = {
    "credenciales": "Robo de credenciales",
    "bec": "Fraude del CEO / BEC",
    "fraude_pagos": "Fraude de facturas y pagos",
    "malware": "Malware / adjunto malicioso",
    "suplantacion_marca": "Suplantación de marca",
    "extorsion": "Extorsión / sextorsión",
    "estafa": "Estafa / premio falso",
    "otro": "Otro / sin clasificar",
    "ninguna": "Sin amenaza",
}

VEREDICTOS = {"legitimo": "Legítimo", "sospechoso": "Sospechoso", "phishing": "Phishing"}
NIVELES = {"bajo": "Bajo", "medio": "Medio", "alto": "Alto", "critico": "Crítico"}
SEVERIDADES = ("info", "baja", "media", "alta", "critica")
ESTADOS = {
    "nuevo": "Nuevo",
    "en_revision": "En revisión",
    "confirmado": "Phishing confirmado",
    "falso_positivo": "Falso positivo",
    "resuelto": "Resuelto",
}


@dataclass
class Indicador:
    codigo: str
    titulo: str
    detalle: str
    puntos: int
    severidad: str = "media"
    categorias: dict[str, float] = field(default_factory=dict)
    marca: str | None = None

    def a_dict(self) -> dict:
        return asdict(self)


@dataclass
class Resultado:
    puntaje: int
    puntaje_heuristico: int
    prob_ml: float | None
    veredicto: str
    nivel: str
    categoria: str
    marca: str | None
    indicadores: list[Indicador]

    @property
    def es_amenaza(self) -> bool:
        return self.veredicto != "legitimo"

    def resumen(self) -> str:
        principales = sorted((i for i in self.indicadores if i.puntos > 0), key=lambda i: -i.puntos)[:3]
        motivos = "; ".join(i.titulo for i in principales) or "sin señales de riesgo"
        return f"{VEREDICTOS[self.veredicto]} ({self.puntaje}/100) · {CATEGORIAS[self.categoria]} · {motivos}"
