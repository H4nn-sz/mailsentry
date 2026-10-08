"""Vistas del panel: tablero, correos, análisis manual, personal, listas, buzones, IA, reporte y usuarios."""

from __future__ import annotations

import csv
import io
import threading
from datetime import timedelta

from flask import Blueprint, Response, abort, flash, g, redirect, render_template, request, session, url_for
from sqlalchemy import and_, delete, func, or_, select
from werkzeug.security import generate_password_hash

from .. import db, estadisticas, servicio
from ..db import Correo, Empleado, Evento, ReglaLista, Usuario, registrar_evento
from ..deteccion import ml
from ..deteccion.datos import CORREO_GRATUITO
from ..deteccion.modelos import CATEGORIAS, ESTADOS, NIVELES
from ..ingesta import imap, vigilante
from ..util import a_local, ahora, desarmar_texto, zona
from .rutas_auth import validar_password
from .seguridad import ROLES, cfg, requiere_rol

bp = Blueprint("panel", __name__)
POR_PAGINA = 50


def _usuario() -> str:
    return g.usuario.usuario if g.get("usuario") else "sistema"


def cfg_es_propio(dominio: str) -> bool:
    return any(dominio == d or dominio.endswith("." + d) for d in cfg().dominios_propios)


# ------------------------------------------------------------------ tablero

@bp.get("/")
@requiere_rol("lector")
def inicio():
    periodo = request.args.get("periodo", "30d")
    if periodo not in estadisticas.PERIODOS:
        periodo = "30d"
    buzon = request.args.get("buzon") or None
    with db.sesion() as s:
        datos = estadisticas.calcular(s, cfg(), periodo, buzon)
        buzones = sorted(b for b in s.scalars(select(Correo.buzon).distinct()) if b)
        hay_correos = bool(s.scalar(select(func.count(Correo.id))))
        sin_directivos = not s.scalar(select(func.count(Empleado.id)).where(Empleado.es_vip.is_(True)))
        pendiente_configurar = not db.leer_ajustes(s).get("configurado") and not cfg().geoip_demo
    # La animación de entrada se muestra una vez por inicio de sesión (o con ?intro=1 para verla de nuevo)
    mostrar_intro = not session.get("intro_vista") or request.args.get("intro") == "1"
    session["intro_vista"] = True
    return render_template("panel.html", datos=datos, periodos=estadisticas.PERIODOS, buzones=buzones,
                           buzon=buzon, hay_correos=hay_correos, sin_directivos=sin_directivos,
                           mostrar_intro=mostrar_intro, pendiente_configurar=pendiente_configurar)


# ------------------------------------------------------------------ asistente de bienvenida

CIUDADES = {  # ubicación de la empresa: destino de los arcos del globo
    "Lima": (-12.046, -77.043), "Arequipa": (-16.409, -71.537), "Trujillo": (-8.112, -79.029),
    "Chiclayo": (-6.771, -79.841), "Piura": (-5.194, -80.632), "Cusco": (-13.532, -71.967),
    "Iquitos": (-3.749, -73.253), "Huancayo": (-12.065, -75.204), "Tacna": (-18.006, -70.246),
    "Ica": (-14.068, -75.729), "Puno": (-15.840, -70.022), "Chimbote": (-9.075, -78.594),
    "Bogotá": (4.711, -74.072), "Quito": (-0.180, -78.467), "Santiago": (-33.449, -70.669),
    "Ciudad de México": (19.433, -99.133), "Buenos Aires": (-34.604, -58.382), "Madrid": (40.417, -3.704),
}


@bp.route("/bienvenida", methods=["GET", "POST"])
@requiere_rol("admin")
def bienvenida():
    paso = request.args.get("paso", 1, type=int)
    with db.sesion() as s:
        ajustes = db.leer_ajustes(s)
        if request.method == "POST":
            if paso == 1:
                nombre = request.form.get("empresa", "").strip()[:150]
                dominios = {d.strip().lower().removeprefix("@") for d in request.form.get("dominios", "").replace(",", "\n").splitlines()}
                dominios = {d for d in dominios if "." in d and " " not in d}
                if not nombre or not dominios:
                    flash("Ingrese el nombre de la empresa y al menos un dominio de correo (ej. miempresa.com.pe).", "error")
                    return redirect(url_for("panel.bienvenida", paso=1))
                db.guardar_ajuste(s, "empresa_nombre", nombre)
                ciudad = request.form.get("ciudad", "Lima")
                db.guardar_ajuste(s, "ciudad", ciudad)
                db.guardar_ajuste(s, "ubicacion", list(CIUDADES.get(ciudad, CIUDADES["Lima"])))
                s.execute(delete(ReglaLista).where(ReglaLista.tipo == "propio"))
                for d in sorted(dominios):
                    s.add(ReglaLista(tipo="propio", valor=d, nota="Asistente de bienvenida", creado_por=_usuario()))
                registrar_evento(s, _usuario(), "asistente_empresa", f"{nombre}: {', '.join(sorted(dominios))}")
                s.commit()
                return redirect(url_for("panel.bienvenida", paso=2))
            if paso == 2:
                nombres, correos, cargos = (request.form.getlist(k) for k in ("nombre", "email", "cargo"))
                agregados = 0
                for nombre, email, cargo in zip(nombres, correos, cargos):
                    nombre, email = nombre.strip(), email.strip().lower()
                    if not nombre or "@" not in email:
                        continue
                    e = s.scalar(select(Empleado).where(Empleado.email == email)) or Empleado(email=email)
                    e.nombre, e.cargo, e.es_vip = nombre[:200], cargo.strip()[:120], True
                    e.departamento = e.departamento if e.departamento not in ("", "Sin asignar") else "Gerencia"
                    s.add(e)
                    agregados += 1
                registrar_evento(s, _usuario(), "asistente_directivos", f"{agregados} directivo(s)")
                s.commit()
                return redirect(url_for("panel.bienvenida", paso=3))
            if paso == 3:
                db.guardar_ajuste(s, "configurado", True)
                s.commit()
                flash("¡Listo! MailSentry ya protege a su empresa. Analice un correo o conecte sus buzones.", "ok")
                return redirect(url_for("panel.inicio"))
        dominios = [r.valor for r in s.scalars(select(ReglaLista).where(ReglaLista.tipo == "propio"))]
        directivos = s.scalars(select(Empleado).where(Empleado.es_vip.is_(True))).all()
    return render_template("bienvenida.html", paso=max(1, min(3, paso)), ajustes=ajustes, ciudades=CIUDADES,
                           dominios=dominios or cfg().dominios_propios, directivos=directivos,
                           buzones=cfg().buzones)


# ------------------------------------------------------------------ correos

def _filtros_correos(args) -> tuple[list, dict]:
    condiciones = []
    valores = {k: (args.get(k) or "").strip() for k in
               ("q", "veredicto", "categoria", "estado", "nivel", "periodo", "destinatario", "dominio",
                "departamento", "marca", "buzon", "pais", "proveedor")}
    sin_etiqueta = Correo.etiqueta.is_(None)
    veredicto = valores["veredicto"]
    if veredicto == "phishing":
        condiciones.append(or_(Correo.etiqueta == "phishing", and_(sin_etiqueta, Correo.veredicto == "phishing")))
    elif veredicto == "sospechoso":
        condiciones.append(and_(sin_etiqueta, Correo.veredicto == "sospechoso"))
    elif veredicto == "legitimo":
        condiciones.append(or_(Correo.etiqueta == "legitimo", and_(sin_etiqueta, Correo.veredicto == "legitimo")))
    elif veredicto == "amenazas":
        condiciones.append(or_(Correo.etiqueta == "phishing",
                               and_(sin_etiqueta, Correo.veredicto.in_(("phishing", "sospechoso")))))
    for campo, columna in (("categoria", Correo.categoria), ("estado", Correo.estado),
                           ("nivel", Correo.nivel_riesgo), ("destinatario", Correo.destinatario_principal),
                           ("dominio", Correo.remitente_dominio), ("marca", Correo.marca_suplantada),
                           ("buzon", Correo.buzon), ("proveedor", Correo.proveedor_origen)):
        if valores[campo]:
            condiciones.append(columna == valores[campo])
    if valores["pais"]:  # el globo solo cuenta envíos directos (sin proveedor intermedio)
        condiciones += [Correo.pais_origen == valores["pais"].upper(), Correo.proveedor_origen.is_(None)]
    if valores["departamento"]:
        emails = select(Empleado.email).where(Empleado.departamento == valores["departamento"])
        condiciones.append(Correo.destinatario_principal.in_(emails))
    if valores["periodo"] in estadisticas.PERIODOS:
        desde, _ = estadisticas.rango(valores["periodo"])
        if desde:
            condiciones.append(Correo.recibido_en > desde)
    if valores["q"]:
        patron = f"%{valores['q']}%"
        condiciones.append(or_(Correo.asunto.ilike(patron), Correo.remitente_email.ilike(patron),
                               Correo.remitente_nombre.ilike(patron), Correo.destinatario_principal.ilike(patron)))
    return condiciones, valores


@bp.get("/correos")
@requiere_rol("lector")
def correos():
    condiciones, filtros = _filtros_correos(request.args)
    pagina = max(1, request.args.get("pagina", 1, type=int))
    with db.sesion() as s:
        total = s.scalar(select(func.count(Correo.id)).where(*condiciones))
        filas = s.scalars(
            select(Correo).where(*condiciones).order_by(Correo.recibido_en.desc())
            .offset((pagina - 1) * POR_PAGINA).limit(POR_PAGINA)
        ).all()
        departamentos = sorted(set(s.scalars(select(Empleado.departamento).distinct())))
        buzones = sorted(b for b in s.scalars(select(Correo.buzon).distinct()) if b)
    paginas = max(1, -(-total // POR_PAGINA))
    consulta = {k: v for k, v in filtros.items() if v}
    return render_template("correos.html", correos=filas, total=total, pagina=pagina, paginas=paginas,
                           filtros=filtros, consulta=consulta, departamentos=departamentos, buzones=buzones,
                           periodos=estadisticas.PERIODOS)


@bp.get("/correos/exportar.csv")
@requiere_rol("lector")
def exportar_csv():
    condiciones, _ = _filtros_correos(request.args)
    tz = zona(cfg().zona_horaria)
    salida = io.StringIO()
    escritor = csv.writer(salida, delimiter=";")
    escritor.writerow(["id", "recibido", "buzon", "remitente", "email_remitente", "dominio", "destinatario", "asunto",
                       "veredicto", "riesgo", "puntaje", "categoria", "marca_suplantada", "estado", "etiqueta"])
    with db.sesion() as s:
        for c in s.scalars(select(Correo).where(*condiciones).order_by(Correo.recibido_en.desc())):
            escritor.writerow([
                c.id, a_local(c.recibido_en, tz).strftime("%Y-%m-%d %H:%M"), c.buzon or "", c.remitente_nombre,
                c.remitente_email, c.remitente_dominio, c.destinatario_principal, c.asunto, c.veredicto_efectivo,
                NIVELES.get(c.nivel_riesgo, ""), c.puntaje, CATEGORIAS.get(c.categoria, ""), c.marca_suplantada or "",
                ESTADOS.get(c.estado, c.estado), c.etiqueta or "",
            ])
    nombre = f"mailsentry-correos-{ahora():%Y%m%d}.csv"
    return Response("﻿" + salida.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": f"attachment; filename={nombre}"})


@bp.get("/correos/<int:correo_id>")
@requiere_rol("lector")
def correo(correo_id: int):
    with db.sesion() as s:
        c = s.get(Correo, correo_id) or abort(404)
        empleado = s.scalar(select(Empleado).where(Empleado.email == c.destinatario_principal))
        mismo_dominio = s.scalar(select(func.count(Correo.id)).where(Correo.remitente_dominio == c.remitente_dominio,
                                                                      Correo.id != c.id))
        reglas = s.scalars(select(ReglaLista).where(
            ReglaLista.valor.in_((c.remitente_email, c.remitente_dominio)))).all()
        tiene_original = s.scalar(select(Correo.original.is_not(None)).where(Correo.id == c.id))
    return render_template("correo.html", c=c, empleado=empleado, mismo_dominio=mismo_dominio, reglas=reglas,
                           cuerpo=desarmar_texto(c.resumen), tiene_original=tiene_original,
                           dominio_compartido=c.remitente_dominio in CORREO_GRATUITO or cfg_es_propio(c.remitente_dominio),
                           umbrales=(cfg().umbral_sospechoso, cfg().umbral_phishing, cfg().umbral_critico))


@bp.post("/correos/<int:correo_id>/revisar")
@requiere_rol("analista")
def revisar(correo_id: int):
    accion = request.form.get("accion", "")
    with db.sesion() as s:
        c = s.get(Correo, correo_id) or abort(404)
        if accion == "confirmar":
            c.etiqueta, c.estado = "phishing", "confirmado"
        elif accion == "falso_positivo":
            c.etiqueta, c.estado = "legitimo", "falso_positivo"
        elif accion == "en_revision":
            c.estado = "en_revision"
        elif accion == "resuelto":
            c.estado = "resuelto"
            if c.etiqueta is None and c.veredicto == "legitimo":
                c.etiqueta = "legitimo"
        elif accion == "reabrir":
            c.etiqueta, c.estado = None, "nuevo"
        elif accion != "notas":
            abort(400)
        if "notas" in request.form:
            c.notas = request.form.get("notas", "")[:5000]
        c.revisado_por, c.revisado_en = _usuario(), ahora()
        registrar_evento(s, _usuario(), f"correo_{accion}", f"#{c.id} {c.asunto[:120]}")
        s.commit()
    flash("Cambios guardados.", "ok")
    return redirect(url_for("panel.correo", correo_id=correo_id))


@bp.post("/correos/<int:correo_id>/lista")
@requiere_rol("analista")
def agregar_a_lista(correo_id: int):
    tipo = request.form.get("tipo")
    alcance = request.form.get("alcance", "email")
    if tipo not in ("permitido", "bloqueado"):
        abort(400)
    with db.sesion() as s:
        c = s.get(Correo, correo_id) or abort(404)
        valor = c.remitente_email if alcance == "email" else c.remitente_dominio
        if not valor:
            abort(400)
        if alcance != "email" and (valor in CORREO_GRATUITO or cfg_es_propio(valor)):
            flash(f"No se puede incluir el dominio completo {valor} (afectaría a todos sus usuarios). "
                  "Use la dirección concreta.", "error")
            return redirect(url_for("panel.correo", correo_id=correo_id))
        s.execute(delete(ReglaLista).where(ReglaLista.valor == valor,
                                           ReglaLista.tipo.in_(("permitido", "bloqueado"))))
        s.add(ReglaLista(tipo=tipo, valor=valor, nota=f"Desde el correo #{c.id}", creado_por=_usuario()))
        registrar_evento(s, _usuario(), f"lista_{tipo}", valor)
        s.commit()
    flash(f"{valor} agregado a la lista de {'confianza' if tipo == 'permitido' else 'bloqueo'}. "
          "Se aplicará a los próximos correos (o use «Reanalizar»).", "ok")
    return redirect(url_for("panel.correo", correo_id=correo_id))


@bp.post("/correos/<int:correo_id>/reanalizar")
@requiere_rol("analista")
def reanalizar(correo_id: int):
    with db.sesion() as s:
        c = s.get(Correo, correo_id) or abort(404)
        resultado = servicio.reanalizar(s, c, cfg())
        if resultado is None:
            flash("Este correo no tiene el original guardado; no se puede reanalizar.", "error")
        else:
            registrar_evento(s, _usuario(), "correo_reanalizado", f"#{c.id}")
            s.commit()
            flash(f"Reanalizado: {resultado.resumen()}", "ok")
    return redirect(url_for("panel.correo", correo_id=correo_id))


@bp.get("/correos/<int:correo_id>/original.eml")
@requiere_rol("admin")
def original(correo_id: int):
    with db.sesion() as s:
        c = s.get(Correo, correo_id) or abort(404)
        datos = c.original_bytes() or abort(404)
        registrar_evento(s, _usuario(), "original_descargado", f"#{c.id}")
        s.commit()
    return Response(datos, mimetype="application/octet-stream",
                    headers={"Content-Disposition": f"attachment; filename=evidencia-correo-{correo_id}.eml"})


# ------------------------------------------------------------------ análisis manual

@bp.route("/analizar", methods=["GET", "POST"])
@requiere_rol("analista")
def analizar():
    resultados = []
    if request.method == "POST":
        crudos = [(a.filename or "correo.eml", a.read()) for a in request.files.getlist("archivos") if a.filename]
        texto = request.form.get("fuente", "").strip()
        if texto:
            crudos.append(("código fuente pegado", texto.replace("\r\n", "\n").encode("utf-8")))
        if not crudos:
            flash("Suba al menos un archivo .eml o pegue el código fuente del correo.", "error")
        for nombre, crudo in crudos:
            if not crudo:
                continue
            p = servicio.procesar(crudo, cfg(), fuente="carga", buzon="Carga manual", alertar=False)
            resultados.append({"archivo": nombre, "correo": p.correo, "nuevo": p.nuevo})
        if resultados:
            with db.sesion() as s:
                registrar_evento(s, _usuario(), "analisis_manual", f"{len(resultados)} correo(s)")
                s.commit()
        if len(resultados) == 1:
            return redirect(url_for("panel.correo", correo_id=resultados[0]["correo"].id))
    return render_template("analizar.html", resultados=resultados)


# ------------------------------------------------------------------ personal

@bp.get("/personal")
@requiere_rol("lector")
def personal():
    desde = ahora() - timedelta(days=90)
    with db.sesion() as s:
        empleados = s.scalars(select(Empleado).order_by(Empleado.departamento, Empleado.nombre)).all()
        conteos = dict(s.execute(
            select(Correo.destinatario_principal, func.count(Correo.id))
            .where(Correo.recibido_en > desde,
                   or_(Correo.etiqueta == "phishing",
                       and_(Correo.etiqueta.is_(None), Correo.veredicto.in_(("phishing", "sospechoso")))))
            .group_by(Correo.destinatario_principal)
        ).all())
    departamentos = sorted({e.departamento for e in empleados})
    return render_template("personal.html", empleados=empleados, conteos=conteos, departamentos=departamentos)


@bp.post("/personal")
@requiere_rol("analista")
def guardar_empleado():
    email = request.form.get("email", "").strip().lower()
    if "@" not in email:
        flash("Ingrese un correo válido.", "error")
        return redirect(url_for("panel.personal"))
    with db.sesion() as s:
        e = s.get(Empleado, request.form.get("id", type=int)) if request.form.get("id") else None
        if e is None:
            e = s.scalar(select(Empleado).where(Empleado.email == email)) or Empleado(email=email)
            s.add(e)
        e.email = email
        e.nombre = request.form.get("nombre", "").strip()[:200]
        e.departamento = request.form.get("departamento", "").strip()[:120] or "Sin asignar"
        e.cargo = request.form.get("cargo", "").strip()[:120]
        e.es_vip = request.form.get("es_vip") == "1"
        registrar_evento(s, _usuario(), "personal_guardado", email)
        s.commit()
    flash(f"Datos de {email} guardados.", "ok")
    return redirect(url_for("panel.personal"))


@bp.post("/personal/<int:empleado_id>/eliminar")
@requiere_rol("analista")
def eliminar_empleado(empleado_id: int):
    with db.sesion() as s:
        e = s.get(Empleado, empleado_id) or abort(404)
        registrar_evento(s, _usuario(), "personal_eliminado", e.email)
        s.delete(e)
        s.commit()
    flash("Registro eliminado.", "ok")
    return redirect(url_for("panel.personal"))


# ------------------------------------------------------------------ listas

@bp.get("/listas")
@requiere_rol("lector")
def listas():
    with db.sesion() as s:
        reglas = s.scalars(select(ReglaLista).order_by(ReglaLista.tipo, ReglaLista.valor)).all()
    return render_template("listas.html", reglas=reglas, dominios_config=cfg().dominios_propios)


@bp.post("/listas")
@requiere_rol("analista")
def agregar_regla():
    tipo = request.form.get("tipo")
    valor = request.form.get("valor", "").strip().lower().removeprefix("http://").removeprefix("https://").strip("/")
    if tipo not in ("propio", "permitido", "bloqueado") or not valor or " " in valor or "." not in valor:
        flash("Ingrese un dominio (empresa.com) o un correo (persona@empresa.com) válido.", "error")
        return redirect(url_for("panel.listas"))
    with db.sesion() as s:
        if s.scalar(select(ReglaLista.id).where(ReglaLista.tipo == tipo, ReglaLista.valor == valor)):
            flash("Ese valor ya está en la lista.", "error")
        else:
            s.add(ReglaLista(tipo=tipo, valor=valor, nota=request.form.get("nota", "")[:300], creado_por=_usuario()))
            registrar_evento(s, _usuario(), f"lista_{tipo}", valor)
            s.commit()
            flash(f"{valor} agregado.", "ok")
    return redirect(url_for("panel.listas"))


@bp.post("/listas/<int:regla_id>/eliminar")
@requiere_rol("analista")
def eliminar_regla(regla_id: int):
    with db.sesion() as s:
        r = s.get(ReglaLista, regla_id) or abort(404)
        registrar_evento(s, _usuario(), f"lista_{r.tipo}_eliminado", r.valor)
        s.delete(r)
        s.commit()
    flash("Eliminado de la lista.", "ok")
    return redirect(url_for("panel.listas"))


# ------------------------------------------------------------------ buzones

@bp.get("/buzones")
@requiere_rol("lector")
def buzones():
    return render_template("buzones.html", buzones=cfg().buzones, estados=imap.estados(),
                           intervalo=cfg().intervalo_buzones)


@bp.post("/buzones/revisar")
@requiere_rol("admin")
def revisar_buzones():
    if not cfg().buzones:
        flash("No hay buzones configurados en config.toml.", "error")
    else:
        threading.Thread(target=vigilante.revisar_todos, args=(cfg(),), daemon=True).start()
        flash("Revisión iniciada en segundo plano. Actualice la página en unos segundos.", "ok")
    return redirect(url_for("panel.buzones"))


# ------------------------------------------------------------------ inteligencia artificial

@bp.get("/modelo")
@requiere_rol("lector")
def modelo():
    with db.sesion() as s:
        conteo = servicio.conteo_etiquetas(s)
        textos, etiquetas = servicio.datos_entrenamiento(s)
    return render_template("modelo.html", disponible=ml.SKLEARN_DISPONIBLE, info=ml.info_modelo(cfg().ruta_modelo),
                           conteo=conteo, minimo=ml.MINIMO_POR_CLASE, muestras=len(textos),
                           positivos=sum(etiquetas), peso=cfg().peso_ml)


@bp.post("/modelo/entrenar")
@requiere_rol("admin")
def entrenar():
    with db.sesion() as s:
        textos, etiquetas = servicio.datos_entrenamiento(s)
    try:
        meta = ml.entrenar(textos, etiquetas, cfg().ruta_modelo)
    except (ValueError, RuntimeError) as error:
        flash(str(error), "error")
        return redirect(url_for("panel.modelo"))
    with db.sesion() as s:
        registrar_evento(s, _usuario(), "modelo_entrenado", f"{meta['muestras']} muestras, F1 {meta['f1']}")
        s.commit()
    flash(f"Modelo entrenado con {meta['muestras']} correos (F1 = {meta['f1']:.0%}).", "ok")
    return redirect(url_for("panel.modelo"))


@bp.post("/modelo/reanalizar")
@requiere_rol("admin")
def reanalizar_todo():
    total = servicio.reanalizar_todo(cfg())
    with db.sesion() as s:
        registrar_evento(s, _usuario(), "reanalisis_total", f"{total} correos")
        s.commit()
    flash(f"Se reanalizaron {total} correos con las reglas, listas y modelo actuales.", "ok")
    return redirect(url_for("panel.modelo"))


# ------------------------------------------------------------------ reporte ejecutivo

@bp.get("/reporte")
@requiere_rol("lector")
def reporte():
    periodo = request.args.get("periodo", "30d")
    if periodo not in estadisticas.PERIODOS:
        periodo = "30d"
    with db.sesion() as s:
        datos = estadisticas.calcular(s, cfg(), periodo)
        recomendaciones = estadisticas.recomendaciones(s, datos)
    return render_template("reporte.html", datos=datos, recomendaciones=recomendaciones,
                           periodos=estadisticas.PERIODOS, generado=a_local(ahora(), zona(cfg().zona_horaria)))


# ------------------------------------------------------------------ usuarios

@bp.get("/usuarios")
@requiere_rol("admin")
def usuarios():
    with db.sesion() as s:
        lista = s.scalars(select(Usuario).order_by(Usuario.usuario)).all()
        eventos = s.scalars(select(Evento).order_by(Evento.fecha.desc()).limit(60)).all()
    return render_template("usuarios.html", usuarios=lista, eventos=eventos, roles=ROLES)


@bp.post("/usuarios")
@requiere_rol("admin")
def crear_usuario():
    nombre = request.form.get("usuario", "").strip().lower()
    rol = request.form.get("rol", "analista")
    error = validar_password(request.form.get("password", ""), request.form.get("confirmacion", ""))
    if not nombre or not nombre.replace(".", "").replace("_", "").isalnum():
        error = "El usuario solo puede tener letras, números, puntos o guiones bajos."
    if rol not in ROLES:
        error = "Rol inválido."
    with db.sesion() as s:
        if not error and s.scalar(select(Usuario.id).where(Usuario.usuario == nombre)):
            error = "Ese usuario ya existe."
        if error:
            flash(error, "error")
        else:
            s.add(Usuario(usuario=nombre, nombre=request.form.get("nombre", "").strip(), rol=rol,
                          password_hash=generate_password_hash(request.form["password"])))
            registrar_evento(s, _usuario(), "usuario_creado", f"{nombre} ({rol})")
            s.commit()
            flash(f"Usuario {nombre} creado.", "ok")
    return redirect(url_for("panel.usuarios"))


@bp.post("/usuarios/<int:usuario_id>")
@requiere_rol("admin")
def editar_usuario(usuario_id: int):
    with db.sesion() as s:
        u = s.get(Usuario, usuario_id) or abort(404)
        accion = request.form.get("accion")
        if u.id == g.usuario.id and accion in ("desactivar", "rol"):
            flash("No puede quitarse permisos ni desactivarse a sí mismo.", "error")
            return redirect(url_for("panel.usuarios"))
        if accion == "desactivar":
            u.activo = False
        elif accion == "activar":
            u.activo = True
        elif accion == "rol" and request.form.get("rol") in ROLES:
            u.rol = request.form["rol"]
        elif accion == "password":
            error = validar_password(request.form.get("password", ""), request.form.get("confirmacion", ""))
            if error:
                flash(error, "error")
                return redirect(url_for("panel.usuarios"))
            u.password_hash = generate_password_hash(request.form["password"])
        else:
            abort(400)
        registrar_evento(s, _usuario(), f"usuario_{accion}", u.usuario)
        s.commit()
    flash("Usuario actualizado.", "ok")
    return redirect(url_for("panel.usuarios"))
