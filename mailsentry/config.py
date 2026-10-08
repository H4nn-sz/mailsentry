"""Carga de configuración (config.toml + variables de entorno / .env)."""

from __future__ import annotations

import os
import secrets
import shutil
import tomllib
from dataclasses import dataclass, field, replace
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
DIR_DATOS = RAIZ / "data"
RUTA_CONFIG = RAIZ / "config.toml"
RUTA_CONFIG_EJEMPLO = RAIZ / "config.example.toml"

NIVELES = ("bajo", "medio", "alto", "critico")


@dataclass
class Buzon:
    nombre: str
    usuario: str
    conexion: str = "imap"  # "imap" | "graph"
    servidor: str = ""
    puerto: int = 993
    password_env: str = ""
    carpeta: str = "INBOX"
    cuarentena: str = ""
    tipo: str = "entrada"  # "entrada" | "reportes"
    activo: bool = True
    tenant_id: str = ""
    client_id: str = ""
    secret_env: str = ""

    @property
    def password(self) -> str:
        return os.environ.get(self.password_env, "") if self.password_env else ""

    @property
    def secreto(self) -> str:
        return os.environ.get(self.secret_env, "") if self.secret_env else ""

    @property
    def credencial_configurada(self) -> bool:
        return bool(self.secreto if self.conexion == "graph" else self.password)


@dataclass
class Config:
    empresa_nombre: str = "Mi Empresa"
    dominios_propios: list[str] = field(default_factory=list)
    zona_horaria: str = "America/Lima"
    host: str = "127.0.0.1"
    puerto: int = 8050
    abrir_navegador: bool = True
    db_url: str = ""
    guardar_original: bool = True
    umbral_sospechoso: int = 35
    umbral_phishing: int = 65
    umbral_critico: int = 85
    peso_ml: float = 0.30
    intervalo_buzones: int = 120
    historial_inicial_dias: int = 30
    lote_maximo: int = 200
    webhook_url: str = ""
    alerta_nivel_minimo: str = "alto"
    virustotal_env: str = "VT_API_KEY"
    feeds: list[str] = field(default_factory=list)
    api_token_env: str = "MAILSENTRY_API_TOKEN"
    buzones: list[Buzon] = field(default_factory=list)
    secret_key: str = ""
    archivo_modelo: str = "modelo_ml.joblib"
    ubicacion: tuple[float, float] = (-12.046, -77.043)  # latitud, longitud de la empresa (Lima)
    archivo_geoip: str = "geoip/ip-pais.bin"
    geoip_demo: bool = False  # acepta IPs de documentación (solo para la demostración)

    def con_ajustes(self, ajustes: dict) -> "Config":
        """Aplica lo configurado desde el panel (tiene prioridad sobre config.toml)."""
        cambios = {}
        if ajustes.get("empresa_nombre"):
            cambios["empresa_nombre"] = str(ajustes["empresa_nombre"])
        if isinstance(ajustes.get("ubicacion"), (list, tuple)) and len(ajustes["ubicacion"]) == 2:
            cambios["ubicacion"] = (float(ajustes["ubicacion"][0]), float(ajustes["ubicacion"][1]))
        return replace(self, **cambios) if cambios else self

    @property
    def ruta_geoip(self) -> Path:
        return DIR_DATOS / self.archivo_geoip

    @property
    def virustotal_key(self) -> str:
        return os.environ.get(self.virustotal_env, "") if self.virustotal_env else ""

    @property
    def api_token(self) -> str:
        return os.environ.get(self.api_token_env, "") if self.api_token_env else ""

    @property
    def ruta_modelo(self) -> Path:
        return DIR_DATOS / self.archivo_modelo


def _cargar_env(ruta: Path) -> None:
    """Lector mínimo de archivos .env (CLAVE=valor). No pisa variables ya definidas."""
    if not ruta.exists():
        return
    for linea in ruta.read_text(encoding="utf-8").splitlines():
        linea = linea.strip()
        if not linea or linea.startswith("#") or "=" not in linea:
            continue
        clave, valor = linea.split("=", 1)
        valor = valor.strip().strip('"').strip("'")
        if valor:
            os.environ.setdefault(clave.strip(), valor)


def _url_sqlite(url: str) -> str:
    """Convierte rutas SQLite relativas en absolutas respecto a la raíz del proyecto."""
    prefijo = "sqlite:///"
    if not url.startswith("sqlite:") or url == "sqlite://":
        return url
    ruta = url[len(prefijo):] if url.startswith(prefijo) else url.split(":", 1)[1]
    ruta_p = Path(ruta)
    if not ruta_p.is_absolute():
        ruta_p = RAIZ / ruta_p
    ruta_p.parent.mkdir(parents=True, exist_ok=True)
    return prefijo + ruta_p.as_posix()


def _clave_secreta() -> str:
    ruta = DIR_DATOS / ".secret_key"
    if ruta.exists():
        return ruta.read_text(encoding="utf-8").strip()
    clave = secrets.token_hex(32)
    ruta.write_text(clave, encoding="utf-8")
    return clave


def cargar(ruta: Path | None = None) -> Config:
    DIR_DATOS.mkdir(parents=True, exist_ok=True)
    _cargar_env(RAIZ / ".env")
    ruta = ruta or RUTA_CONFIG
    if not ruta.exists() and RUTA_CONFIG_EJEMPLO.exists():
        shutil.copyfile(RUTA_CONFIG_EJEMPLO, ruta)
    datos = tomllib.loads(ruta.read_text(encoding="utf-8")) if ruta.exists() else {}

    emp = datos.get("empresa", {})
    srv = datos.get("servidor", {})
    bd = datos.get("base_datos", {})
    det = datos.get("deteccion", {})
    mon = datos.get("monitoreo", {})
    ale = datos.get("alertas", {})
    intel = datos.get("inteligencia", {})
    api = datos.get("api", {})

    campos_buzon = set(Buzon.__dataclass_fields__)
    buzones = [Buzon(**{k: v for k, v in b.items() if k in campos_buzon}) for b in datos.get("buzones", [])]

    nivel = str(ale.get("nivel_minimo", "alto")).lower()
    return Config(
        empresa_nombre=emp.get("nombre", "Mi Empresa"),
        dominios_propios=[d.strip().lower() for d in emp.get("dominios", []) if d.strip()],
        zona_horaria=emp.get("zona_horaria", "America/Lima"),
        ubicacion=tuple(emp.get("ubicacion", (-12.046, -77.043)))[:2],
        host=srv.get("host", "127.0.0.1"),
        puerto=int(srv.get("puerto", 8050)),
        abrir_navegador=bool(srv.get("abrir_navegador", True)),
        db_url=_url_sqlite(bd.get("url", "sqlite:///data/mailsentry.db")),
        guardar_original=bool(bd.get("guardar_original", True)),
        umbral_sospechoso=int(det.get("umbral_sospechoso", 35)),
        umbral_phishing=int(det.get("umbral_phishing", 65)),
        umbral_critico=int(det.get("umbral_critico", 85)),
        peso_ml=float(det.get("peso_ml", 0.30)),
        intervalo_buzones=int(mon.get("intervalo_segundos", 120)),
        historial_inicial_dias=int(mon.get("historial_inicial_dias", 30)),
        lote_maximo=int(mon.get("lote_maximo", 200)),
        webhook_url=ale.get("webhook_url", ""),
        alerta_nivel_minimo=nivel if nivel in NIVELES else "alto",
        virustotal_env=intel.get("virustotal_api_key_env", "VT_API_KEY"),
        feeds=list(intel.get("feeds", [])),
        api_token_env=api.get("token_env", "MAILSENTRY_API_TOKEN"),
        buzones=buzones,
        secret_key=_clave_secreta(),
    )
