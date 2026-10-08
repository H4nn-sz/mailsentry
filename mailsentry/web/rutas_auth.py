"""Inicio de sesión y creación del primer administrador."""

from __future__ import annotations

from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from sqlalchemy import func, select
from werkzeug.security import check_password_hash, generate_password_hash

from .. import db
from ..db import Usuario, registrar_evento
from ..util import ahora
from .seguridad import limitador

bp = Blueprint("auth", __name__)
LARGO_MINIMO = 10


def validar_password(password: str, confirmacion: str) -> str | None:
    if len(password) < LARGO_MINIMO:
        return f"La contraseña debe tener al menos {LARGO_MINIMO} caracteres."
    if password != confirmacion:
        return "Las contraseñas no coinciden."
    return None


def _destino_seguro(siguiente: str | None) -> str:
    if siguiente and siguiente.startswith("/") and not siguiente.startswith("//"):
        return siguiente
    return url_for("panel.inicio")


@bp.route("/ingresar", methods=["GET", "POST"])
def login():
    with db.sesion() as s:
        if not s.scalar(select(func.count(Usuario.id))):
            return redirect(url_for("auth.configuracion_inicial"))
    if request.method == "POST":
        ip = request.remote_addr or "?"
        if limitador.bloqueado(ip):
            flash("Demasiados intentos fallidos. Espere 5 minutos.", "error")
            return render_template("login.html"), 429
        nombre = request.form.get("usuario", "").strip().lower()
        password = request.form.get("password", "")
        with db.sesion() as s:
            usuario = s.scalar(select(Usuario).where(Usuario.usuario == nombre))
            if usuario and usuario.activo and check_password_hash(usuario.password_hash, password):
                limitador.exito(ip)
                usuario.ultimo_acceso = ahora()
                registrar_evento(s, usuario.usuario, "inicio_sesion", f"IP {ip}")
                s.commit()
                session.clear()
                session["uid"] = usuario.id
                session.permanent = True
                return redirect(_destino_seguro(request.args.get("siguiente")))
            limitador.fallo(ip)
            registrar_evento(s, nombre or "?", "inicio_sesion_fallido", f"IP {ip}")
            s.commit()
        flash("Usuario o contraseña incorrectos.", "error")
    return render_template("login.html")


@bp.post("/salir")
def salir():
    session.clear()
    return redirect(url_for("auth.login"))


@bp.route("/configuracion-inicial", methods=["GET", "POST"])
def configuracion_inicial():
    with db.sesion() as s:
        if s.scalar(select(func.count(Usuario.id))):
            return redirect(url_for("auth.login"))
        if request.method == "POST":
            nombre = request.form.get("usuario", "").strip().lower()
            password = request.form.get("password", "")
            error = validar_password(password, request.form.get("confirmacion", ""))
            if not nombre or not nombre.replace(".", "").replace("_", "").isalnum():
                error = "El usuario solo puede tener letras, números, puntos o guiones bajos."
            if error:
                flash(error, "error")
            else:
                usuario = Usuario(usuario=nombre, nombre=request.form.get("nombre", "").strip(), rol="admin",
                                  password_hash=generate_password_hash(password))
                s.add(usuario)
                registrar_evento(s, nombre, "usuario_creado", "Administrador inicial")
                s.commit()
                session.clear()
                session["uid"] = usuario.id
                flash("Administrador creado. ¡Bienvenido a MailSentry!", "ok")
                return redirect(url_for("panel.bienvenida"))
    return render_template("setup.html")
