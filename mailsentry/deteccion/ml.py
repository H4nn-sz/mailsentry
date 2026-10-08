"""Capa de inteligencia artificial: clasificador de texto que aprende de los correos etiquetados.

Se entrena con los correos que los analistas confirman (phishing / falso positivo),
así que mejora con el uso y se adapta al tipo de ataques que recibe cada empresa.
Requiere scikit-learn; si no está instalado, MailSentry funciona solo con heurísticas.
"""

from __future__ import annotations

import logging
from datetime import datetime
from pathlib import Path

from ..config import DIR_DATOS
from ..parser import CorreoParseado
from .dominios import host_de_url

log = logging.getLogger(__name__)

try:
    import joblib
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.model_selection import StratifiedKFold, cross_validate
    from sklearn.pipeline import FeatureUnion, Pipeline

    SKLEARN_DISPONIBLE = True
except ImportError:  # pragma: no cover - depende del entorno
    SKLEARN_DISPONIBLE = False

RUTA_MODELO = DIR_DATOS / "modelo_ml.joblib"
MINIMO_POR_CLASE = 20


def texto_para_modelo(correo: CorreoParseado) -> str:
    """Texto que 've' el modelo: asunto, cuerpo, dominios de los enlaces y nombres de adjuntos."""
    hosts = {host_de_url(e.url) for e in correo.enlaces[:100]}
    partes = [
        correo.asunto,
        correo.remitente_nombre,
        f"dominio_{correo.remitente_dominio}",
        correo.cuerpo[:15000],
        " ".join(f"enlace_{h}" for h in sorted(h for h in hosts if h)),
        " ".join(f"adjunto_{a.nombre}" for a in correo.adjuntos),
    ]
    return "\n".join(p for p in partes if p)[:20000]


class ModeloML:
    def __init__(self, ruta: Path = RUTA_MODELO) -> None:
        self.ruta = ruta
        self.pipeline = None
        self.meta: dict = {}
        self._mtime: float | None = None
        self.recargar()

    def recargar(self) -> None:
        if not SKLEARN_DISPONIBLE or not self.ruta.exists():
            self.pipeline, self.meta, self._mtime = None, {}, None
            return
        mtime = self.ruta.stat().st_mtime
        if mtime == self._mtime:
            return
        try:
            datos = joblib.load(self.ruta)
            self.pipeline, self.meta, self._mtime = datos["pipeline"], datos["meta"], mtime
        except Exception as error:
            log.error("No se pudo cargar el modelo de IA: %s", error)
            self.pipeline, self.meta = None, {}

    @property
    def disponible(self) -> bool:
        return self.pipeline is not None

    def predecir(self, texto: str) -> float | None:
        if not self.disponible:
            return None
        try:
            return float(self.pipeline.predict_proba([texto])[0][1])
        except Exception as error:
            log.error("Error del modelo de IA: %s", error)
            return None


_modelos: dict[Path, ModeloML] = {}


def modelo_cacheado(ruta: Path = RUTA_MODELO) -> ModeloML | None:
    """Modelo cargado en memoria; se recarga solo si el archivo cambió (p. ej. tras reentrenar)."""
    if not SKLEARN_DISPONIBLE:
        return None
    modelo = _modelos.get(ruta)
    if modelo is None:
        modelo = _modelos[ruta] = ModeloML(ruta)
    else:
        modelo.recargar()
    return modelo if modelo.disponible else None


def _crear_pipeline():
    caracteristicas = FeatureUnion([
        ("palabras", TfidfVectorizer(strip_accents="unicode", lowercase=True, ngram_range=(1, 2),
                                     min_df=2, max_features=30000, sublinear_tf=True)),
        ("caracteres", TfidfVectorizer(strip_accents="unicode", lowercase=True, analyzer="char_wb",
                                       ngram_range=(3, 5), min_df=2, max_features=40000, sublinear_tf=True)),
    ])
    return Pipeline([
        ("caracteristicas", caracteristicas),
        ("clasificador", LogisticRegression(max_iter=2000, class_weight="balanced", C=4.0)),
    ])


def entrenar(textos: list[str], etiquetas: list[int], ruta: Path = RUTA_MODELO) -> dict:
    """Entrena y guarda el modelo. etiquetas: 1 = phishing, 0 = legítimo."""
    if not SKLEARN_DISPONIBLE:
        raise RuntimeError("scikit-learn no está instalado (pip install scikit-learn)")
    positivos, negativos = sum(etiquetas), len(etiquetas) - sum(etiquetas)
    if positivos < MINIMO_POR_CLASE or negativos < MINIMO_POR_CLASE:
        raise ValueError(
            f"Se necesitan al menos {MINIMO_POR_CLASE} correos confirmados de cada tipo "
            f"(hay {positivos} phishing y {negativos} legítimos)."
        )
    pipeline = _crear_pipeline()
    pliegues = min(5, positivos, negativos)
    validacion = cross_validate(
        pipeline, textos, etiquetas,
        cv=StratifiedKFold(n_splits=pliegues, shuffle=True, random_state=42),
        scoring=("accuracy", "precision", "recall", "f1"),
    )
    pipeline.fit(textos, etiquetas)
    meta = {
        "entrenado_en": datetime.now().isoformat(timespec="seconds"),
        "muestras": len(textos),
        "phishing": positivos,
        "legitimos": negativos,
        "exactitud": round(float(validacion["test_accuracy"].mean()), 3),
        "precision": round(float(validacion["test_precision"].mean()), 3),
        "sensibilidad": round(float(validacion["test_recall"].mean()), 3),
        "f1": round(float(validacion["test_f1"].mean()), 3),
        "pliegues": pliegues,
    }
    ruta.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump({"pipeline": pipeline, "meta": meta}, ruta)
    return meta


def info_modelo(ruta: Path = RUTA_MODELO) -> dict | None:
    modelo = ModeloML(ruta)
    return modelo.meta if modelo.disponible else None
