"""Autenticación, roles, protección CSRF y límite de intentos de acceso."""

from __future__ import annotations

import hmac
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, current_app, g, redirect, request, session, url_for

from ..config import Config

ROLES = {"lector": 0, "analista": 1, "admin": 2}
NOMBRES_ROL = {"lector": "Lector", "analista": "Analista", "admin": "Administrador"}


def cfg() -> Config:
    """Configuración vigente: config.toml + lo configurado desde el panel (una lectura por petición)."""
    if "cfg" not in g:
        from .. import db

        base = current_app.extensions["mailsentry"]
        with db.sesion() as s:
            g.cfg = base.con_ajustes(db.leer_ajustes(s))
    return g.cfg


def token_csrf() -> str:
    if "_csrf" not in session:
        session["_csrf"] = secrets.token_urlsafe(32)
    return session["_csrf"]


def verificar_csrf() -> None:
    enviado = request.form.get("_csrf") or request.headers.get("X-CSRF-Token") or ""
    esperado = session.get("_csrf", "")
    if not esperado or not hmac.compare_digest(enviado, esperado):
        abort(400, "Token de seguridad inválido. Recargue la página e intente de nuevo.")


def tiene_rol(minimo: str) -> bool:
    usuario = g.get("usuario")
    return bool(usuario) and ROLES.get(usuario.rol, -1) >= ROLES[minimo]


def requiere_rol(minimo: str = "lector"):
    def decorador(vista):
        @wraps(vista)
        def envoltura(*args, **kwargs):
            if not g.get("usuario"):
                return redirect(url_for("auth.login", siguiente=request.full_path))
            if not tiene_rol(minimo):
                abort(403)
            return vista(*args, **kwargs)

        return envoltura

    return decorador


class LimitadorIntentos:
    """Bloquea temporalmente una IP tras varios intentos de acceso fallidos."""

    def __init__(self, maximo: int = 5, ventana: int = 300) -> None:
        self.maximo, self.ventana = maximo, ventana
        self._fallos: dict[str, deque] = defaultdict(deque)

    def _limpiar(self, clave: str) -> deque:
        fallos = self._fallos[clave]
        while fallos and time.time() - fallos[0] > self.ventana:
            fallos.popleft()
        return fallos

    def bloqueado(self, clave: str) -> bool:
        return len(self._limpiar(clave)) >= self.maximo

    def fallo(self, clave: str) -> None:
        self._limpiar(clave).append(time.time())

    def exito(self, clave: str) -> None:
        self._fallos.pop(clave, None)


limitador = LimitadorIntentos()
