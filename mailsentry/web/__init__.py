"""Aplicación web (panel de MailSentry)."""

from __future__ import annotations

from datetime import timedelta

from flask import Flask, g, redirect, render_template, request, session, url_for
from sqlalchemy import func, select

from .. import __version__, db, paises
from ..config import Config
from ..db import Usuario
from ..deteccion.modelos import CATEGORIAS, ESTADOS, NIVELES, VEREDICTOS
from ..util import a_local, desarmar_texto, desarmar_url, zona
from .seguridad import NOMBRES_ROL, cfg, tiene_rol, token_csrf, verificar_csrf

RUTAS_PUBLICAS = {"auth.login", "auth.configuracion_inicial", "static"}


def crear_app(config: Config) -> Flask:
    db.inicializar(config.db_url)
    app = Flask(__name__)
    app.config.update(
        SECRET_KEY=config.secret_key,
        MAX_CONTENT_LENGTH=40 * 1024 * 1024,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        PERMANENT_SESSION_LIFETIME=timedelta(hours=10),
        JSON_AS_ASCII=False,
    )
    app.extensions["mailsentry"] = config
    tz = zona(config.zona_horaria)

    from .rutas_api import bp as bp_api
    from .rutas_auth import bp as bp_auth
    from .rutas_panel import bp as bp_panel

    app.register_blueprint(bp_auth)
    app.register_blueprint(bp_panel)
    app.register_blueprint(bp_api)

    @app.before_request
    def _antes():
        g.usuario = None
        uid = session.get("uid")
        if uid:
            with db.sesion() as s:
                usuario = s.get(Usuario, uid)
                if usuario and usuario.activo:
                    g.usuario = usuario
                else:
                    session.clear()
        if request.blueprint == "api":
            return None
        if request.method == "POST":
            verificar_csrf()
        if request.endpoint not in RUTAS_PUBLICAS and not g.usuario:
            with db.sesion() as s:
                sin_usuarios = not s.scalar(select(func.count(Usuario.id)))
            if sin_usuarios:
                return redirect(url_for("auth.configuracion_inicial"))
            return redirect(url_for("auth.login", siguiente=request.full_path))
        return None

    @app.after_request
    def _cabeceras(respuesta):
        respuesta.headers.setdefault("X-Content-Type-Options", "nosniff")
        respuesta.headers.setdefault("X-Frame-Options", "DENY")
        respuesta.headers.setdefault("Referrer-Policy", "same-origin")
        respuesta.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'",
        )
        return respuesta

    @app.context_processor
    def _contexto():
        return {
            "usuario_actual": g.get("usuario"),
            "csrf": token_csrf,
            "tiene_rol": tiene_rol,
            "empresa": cfg().empresa_nombre,
            "buzones_vigilados": sum(1 for b in config.buzones if b.activo),
            "version": __version__,
            "CATEGORIAS": CATEGORIAS,
            "VEREDICTOS": VEREDICTOS,
            "NIVELES": NIVELES,
            "ESTADOS": ESTADOS,
            "NOMBRES_ROL": NOMBRES_ROL,
        }

    @app.template_filter("fecha")
    def _fecha(dt, formato="%d/%m/%Y %H:%M"):
        local = a_local(dt, tz)
        return local.strftime(formato) if local else "—"

    @app.template_filter("desarmar")
    def _desarmar(url):
        return desarmar_url(url)

    @app.template_filter("desarmar_texto")
    def _desarmar_texto(texto):
        return desarmar_texto(texto)

    @app.template_filter("pais")
    def _pais(codigo):
        return paises.nombre(codigo)

    @app.template_filter("region")
    def _region(codigo):
        return paises.region(codigo)

    @app.template_filter("miles")
    def _miles(n):
        return f"{int(n or 0):,}".replace(",", " ")

    @app.template_filter("tamano")
    def _tamano(n):
        n = int(n or 0)
        return f"{n / 1048576:.1f} MB" if n >= 1048576 else f"{n / 1024:.0f} KB" if n >= 1024 else f"{n} B"

    @app.errorhandler(403)
    def _prohibido(_e):
        return render_template("error.html", codigo=403, mensaje="No tiene permisos para esta acción."), 403

    @app.errorhandler(404)
    def _no_encontrado(_e):
        return render_template("error.html", codigo=404, mensaje="La página no existe."), 404

    @app.errorhandler(400)
    def _solicitud(e):
        return render_template("error.html", codigo=400, mensaje=getattr(e, "description", "Solicitud inválida")), 400

    @app.errorhandler(413)
    def _grande(_e):
        return render_template("error.html", codigo=413, mensaje="El archivo supera el límite de 40 MB."), 413

    return app
