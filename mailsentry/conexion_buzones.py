"""Conectar buzones IMAP sin editar archivos: prueba la conexión y guarda config.toml + .env.

Lo usan el formulario de la página Buzones y el comando  main.py agregar-buzon.
La contraseña se guarda solo en .env (en esta PC); config.toml guarda el nombre de la variable.
"""

from __future__ import annotations

import imaplib
import re
import ssl
from pathlib import Path

from .config import RAIZ, RUTA_CONFIG, Buzon

SERVIDORES_IMAP = {
    "gmail.com": "imap.gmail.com", "googlemail.com": "imap.gmail.com",
    "outlook.com": "outlook.office365.com", "hotmail.com": "outlook.office365.com", "live.com": "outlook.office365.com",
    "yahoo.com": "imap.mail.yahoo.com", "icloud.com": "imap.mail.me.com", "zoho.com": "imap.zoho.com",
}
RE_EMAIL = re.compile(r"^[^@\s\"'\\]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")


class ErrorConexion(Exception):
    pass


def servidor_sugerido(correo: str) -> str:
    dominio = correo.rsplit("@", 1)[-1].lower()
    return SERVIDORES_IMAP.get(dominio, f"mail.{dominio}")


def probar(correo: str, clave: str, servidor: str, puerto: int = 993) -> None:
    try:
        with imaplib.IMAP4_SSL(servidor, puerto, ssl_context=ssl.create_default_context(), timeout=30) as m:
            m.login(correo, clave)
            m.select("INBOX", readonly=True)
    except imaplib.IMAP4.error as error:
        mensaje = str(error)
        if "AUTHENTICATIONFAILED" in mensaje or "Invalid credentials" in mensaje:
            raise ErrorConexion("Correo o contraseña incorrectos. En Gmail use una contraseña de aplicación "
                                "(16 letras), no su contraseña normal.") from error
        raise ErrorConexion(f"El servidor rechazó la conexión: {mensaje}") from error
    except OSError as error:
        raise ErrorConexion(f"No se pudo conectar con {servidor}: {error}") from error


def guardar(correo: str, clave: str, servidor: str, raiz: Path = RAIZ, ruta_config: Path = RUTA_CONFIG) -> Buzon:
    """Escribe la contraseña en .env y el buzón en config.toml (o actualiza la contraseña si ya existía)."""
    variable = "MAILSENTRY_PASS_" + re.sub(r"[^A-Z0-9]+", "_", correo.upper()).strip("_")
    env = raiz / ".env"
    lineas = env.read_text(encoding="utf-8").splitlines() if env.exists() else []
    lineas = [l for l in lineas if not l.startswith(variable + "=")] + [f"{variable}={clave}"]
    env.write_text("\n".join(lineas) + "\n", encoding="utf-8")

    texto = ruta_config.read_text(encoding="utf-8") if ruta_config.exists() else ""
    if f'usuario = "{correo}"' not in texto:
        texto += (f'\n[[buzones]]\nnombre = "{correo}"\nconexion = "imap"\nservidor = "{servidor}"\npuerto = 993\n'
                  f'usuario = "{correo}"\npassword_env = "{variable}"\ncarpeta = "INBOX"\ncuarentena = ""\n'
                  'tipo = "entrada"\n')
        ruta_config.write_text(texto, encoding="utf-8")
    import os

    os.environ[variable] = clave  # disponible de inmediato, sin reiniciar
    return Buzon(nombre=correo, usuario=correo, conexion="imap", servidor=servidor, puerto=993, password_env=variable)
