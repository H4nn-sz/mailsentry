"""API REST para integrar MailSentry con otros sistemas (pasarelas de correo, SIEM, scripts).

Autenticación: cabecera  Authorization: Bearer <token>  (variable de entorno configurada en [api]).
"""

from __future__ import annotations

import base64
import binascii
import hmac

from flask import Blueprint, abort, jsonify, request

from .. import db, estadisticas, servicio
from ..db import Correo
from ..deteccion.modelos import CATEGORIAS
from .seguridad import cfg

bp = Blueprint("api", __name__, url_prefix="/api/v1")


@bp.before_request
def _autenticar():
    token = cfg().api_token
    if not token:
        abort(404)
    enviado = request.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    if not enviado or not hmac.compare_digest(enviado, token):
        abort(401)


@bp.errorhandler(401)
def _no_autorizado(_e):
    return jsonify(error="no autorizado"), 401


@bp.errorhandler(404)
def _no_existe(_e):
    return jsonify(error="no encontrado"), 404


def _correo_json(c: Correo) -> dict:
    return {
        "id": c.id,
        "recibido_en": c.recibido_en.isoformat() + "Z",
        "remitente": c.remitente_email,
        "destinatario": c.destinatario_principal,
        "asunto": c.asunto,
        "veredicto": c.veredicto_efectivo,
        "puntaje": c.puntaje,
        "nivel_riesgo": c.nivel_riesgo,
        "categoria": c.categoria,
        "categoria_txt": CATEGORIAS.get(c.categoria, c.categoria),
        "marca_suplantada": c.marca_suplantada,
        "estado": c.estado,
        "indicadores": [{k: i[k] for k in ("codigo", "titulo", "detalle", "puntos", "severidad")}
                        for i in c.indicadores if i.get("puntos")],
    }


@bp.post("/analizar")
def analizar():
    """Recibe un correo crudo (cuerpo message/rfc822) o JSON {"eml_base64": "...", "buzon": "..."}."""
    if request.is_json:
        datos = request.get_json(silent=True) or {}
        try:
            crudo = base64.b64decode(datos.get("eml_base64", ""), validate=True)
        except (binascii.Error, ValueError):
            return jsonify(error="eml_base64 inválido"), 400
        buzon = datos.get("buzon") or "API"
    else:
        crudo = request.get_data()
        buzon = request.args.get("buzon") or "API"
    if not crudo:
        return jsonify(error="correo vacío"), 400
    p = servicio.procesar(crudo, cfg(), fuente="api", buzon=buzon)
    return jsonify(nuevo=p.nuevo, correo=_correo_json(p.correo)), 201 if p.nuevo else 200


@bp.get("/correos/<int:correo_id>")
def correo(correo_id: int):
    with db.sesion() as s:
        c = s.get(Correo, correo_id) or abort(404)
        return jsonify(_correo_json(c))


@bp.get("/estadisticas")
def estadisticas_api():
    periodo = request.args.get("periodo", "30d")
    with db.sesion() as s:
        return jsonify(estadisticas.calcular(s, cfg(), periodo, request.args.get("buzon") or None))
