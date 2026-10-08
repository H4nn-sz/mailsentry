"""Contexto de la empresa que el motor necesita para analizar (dominios, directivos, listas)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..util import normalizar
from .dominios import es_subdominio_de, limpiar_host

PALABRAS_VACIAS = {"de", "del", "la", "las", "los", "y", "e", "da", "dos", "van", "von"}


def fichas_nombre(nombre: str) -> tuple[str, ...]:
    return tuple(f for f in re.split(r"[^a-z]+", normalizar(nombre)) if len(f) >= 2 and f not in PALABRAS_VACIAS)


@dataclass(frozen=True)
class Persona:
    nombre: str
    email: str
    cargo: str = ""

    @property
    def fichas(self) -> tuple[str, ...]:
        return fichas_nombre(self.nombre)


@dataclass
class Contexto:
    dominios_propios: set[str] = field(default_factory=set)
    vips: list[Persona] = field(default_factory=list)
    empleados: list[Persona] = field(default_factory=list)
    permitidos: set[str] = field(default_factory=set)
    bloqueados: set[str] = field(default_factory=set)
    dominios_conocidos: set[str] = field(default_factory=set)
    feeds: object | None = None  # inteligencia.Feeds
    modelo: object | None = None  # ml.ModeloML
    intel: object | None = None  # inteligencia.VirusTotal
    umbral_sospechoso: int = 35
    umbral_phishing: int = 65
    umbral_critico: int = 85
    peso_ml: float = 0.30

    def es_propio(self, host: str) -> bool:
        host = limpiar_host(host)
        return any(es_subdominio_de(host, d) for d in self.dominios_propios)

    @staticmethod
    def _en_lista(lista: set[str], direccion: str) -> bool:
        direccion = (direccion or "").strip().lower()
        if not direccion:
            return False
        if direccion in lista:
            return True
        host = limpiar_host(direccion)
        return any(es_subdominio_de(host, v) for v in lista if "@" not in v)

    def bloqueado(self, direccion: str) -> bool:
        return self._en_lista(self.bloqueados, direccion)

    def permitido(self, direccion: str) -> bool:
        return self._en_lista(self.permitidos, direccion)

    @staticmethod
    def buscar_persona(nombre_visible: str, personas: list[Persona]) -> Persona | None:
        """Busca si el nombre visible coincide con alguien (nombre + apellido)."""
        visibles = set(fichas_nombre(nombre_visible))
        if not visibles:
            return None
        for persona in personas:
            propias = persona.fichas
            if len(propias) >= 2 and propias[0] in visibles and len(set(propias) & visibles) >= 2:
                return persona
            if len(propias) == 1 and visibles == set(propias):
                return persona
        return None
