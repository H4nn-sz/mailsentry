"""Punto de entrada del programa instalado (MailSentry.exe).

Abre el panel en el navegador, deja un ícono junto al reloj de Windows para volver a abrirlo o salir,
y sigue vigilando los buzones mientras el ícono esté ahí. También funciona sin empaquetar:
    python lanzador.py
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
import webbrowser
from pathlib import Path


def _preparar_salida() -> None:
    """Sin consola (modo ventana) stdout/stderr son None: se mandan al archivo de registro."""
    from mailsentry.config import DIR_DATOS

    DIR_DATOS.mkdir(parents=True, exist_ok=True)
    if sys.stdout is None or sys.stderr is None:
        archivo = open(DIR_DATOS / "mailsentry.log", "a", encoding="utf-8", buffering=1)
        sys.stdout = sys.stdout or archivo
        sys.stderr = sys.stderr or archivo


def _puerto_abierto(puerto: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex(("127.0.0.1", puerto)) == 0


def _descargar_geoip() -> None:
    """La base de países por IP no viaja en el instalador (CC BY 4.0, se baja una vez)."""
    try:
        from mailsentry import config as configuracion, geoip

        ruta = configuracion.cargar().ruta_geoip
        if not ruta.exists():
            geoip.actualizar(ruta)
    except Exception:
        pass  # sin internet el panel funciona igual, solo sin la ubicación del atacante


def _acceso_directo() -> None:
    """Primer arranque: deja un acceso directo en el escritorio para volver a abrir MailSentry con un clic."""
    if not getattr(sys, "frozen", False):
        return
    try:
        import subprocess

        from mailsentry.config import DIR_DATOS

        marca = DIR_DATOS / ".acceso_directo"
        if marca.exists():
            return
        marca.write_text("1", encoding="utf-8")
        exe = sys.executable.replace("'", "''")
        orden = (
            "$s=New-Object -ComObject WScript.Shell;"
            "$l=$s.CreateShortcut([IO.Path]::Combine([Environment]::GetFolderPath('Desktop'),'MailSentry.lnk'));"
            f"$l.TargetPath='{exe}';$l.WorkingDirectory=[IO.Path]::GetDirectoryName('{exe}');"
            "$l.Description='MailSentry - detector de phishing';$l.Save()"
        )
        subprocess.run(["powershell", "-NoProfile", "-WindowStyle", "Hidden", "-Command", orden],
                       creationflags=0x08000000, timeout=30)
    except Exception:
        pass


def _imagen_icono():
    from PIL import Image

    for base in (Path(getattr(sys, "_MEIPASS", Path(__file__).parent)), Path(__file__).parent):
        ruta = base / "mailsentry" / "web" / "static" / "img" / "icono.png"
        if ruta.exists():
            return Image.open(ruta)
    return Image.new("RGBA", (64, 64), (229, 103, 43, 255))


def _servir(puerto: int) -> None:
    sys.argv = ["mailsentry", "iniciar", "--sin-navegador"]
    import main

    main.main()


def principal() -> None:
    _preparar_salida()
    from mailsentry import __version__
    from mailsentry.config import cargar

    puerto = cargar().puerto
    url = f"http://127.0.0.1:{puerto}"
    if _puerto_abierto(puerto):  # ya hay un MailSentry abierto: solo mostrarlo
        webbrowser.open(url)
        return

    threading.Thread(target=_servir, args=(puerto,), daemon=True).start()
    threading.Thread(target=_descargar_geoip, daemon=True).start()
    threading.Thread(target=_acceso_directo, daemon=True).start()
    for _ in range(120):
        if _puerto_abierto(puerto):
            break
        time.sleep(0.25)
    webbrowser.open(url)

    try:
        import pystray

        def abrir(icono=None, item=None):
            webbrowser.open(url)

        def salir(icono, item):
            icono.stop()

        menu = pystray.Menu(
            pystray.MenuItem("Abrir MailSentry", abrir, default=True),
            pystray.MenuItem("Salir (deja de vigilar el correo)", salir),
        )
        pystray.Icon("MailSentry", _imagen_icono(), f"MailSentry {__version__} · vigilando su correo", menu).run()
    except Exception:
        while True:  # sin bandeja del sistema: queda vivo hasta que se cierre el proceso
            time.sleep(3600)
    os._exit(0)


if __name__ == "__main__":
    principal()
