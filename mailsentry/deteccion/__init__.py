"""Motor de detección de phishing por capas."""

from .contexto import Contexto, Persona
from .modelos import CATEGORIAS, ESTADOS, NIVELES, VEREDICTOS, Indicador, Resultado
from .motor import analizar

__all__ = [
    "CATEGORIAS", "ESTADOS", "NIVELES", "VEREDICTOS", "Contexto", "Indicador", "Persona", "Resultado", "analizar",
]
