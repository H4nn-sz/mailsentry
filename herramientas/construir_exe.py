"""Construye el programa para Windows: dist/MailSentry/MailSentry.exe (carpeta lista para instalar).

Uso (desde la raíz del proyecto):
    .venv\Scripts\python.exe -m pip install pyinstaller pystray
    .venv\Scripts\python.exe herramientas/construir_exe.py
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

RAIZ = Path(__file__).resolve().parent.parent
SEP = ";" if sys.platform == "win32" else ":"


def main() -> None:
    web = RAIZ / "mailsentry" / "web"
    orden = [
        sys.executable, "-m", "PyInstaller", "--noconfirm", "--clean",
        "--name", "MailSentry", "--windowed", "--onedir",
        "--icon", str(RAIZ / "herramientas" / "mailsentry.ico"),
        "--add-data", f"{web / 'templates'}{SEP}mailsentry/web/templates",
        "--add-data", f"{web / 'static'}{SEP}mailsentry/web/static",
        "--add-data", f"{RAIZ / 'config.example.toml'}{SEP}.",
        "--hidden-import", "main",
        "--hidden-import", "waitress",
        "--hidden-import", "psycopg_binary",
        "--hidden-import", "pystray._win32",
        "--collect-submodules", "mailsentry",
        "--exclude-module", "tkinter",
        "--exclude-module", "matplotlib",
        "--distpath", str(RAIZ / "dist"), "--workpath", str(RAIZ / "build"),
        "--specpath", str(RAIZ / "build"),
        str(RAIZ / "lanzador.py"),
    ]
    sys.exit(subprocess.call(orden, cwd=RAIZ))


if __name__ == "__main__":
    main()
