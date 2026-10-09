"""MailSentry · detector de phishing para empresas.

Uso rápido:
    python main.py iniciar            Abre el panel (y vigila los buzones configurados)
    python main.py demo               Crea una empresa de demostración con 90 días de correo
    python main.py iniciar --demo     Abre el panel con los datos de demostración
    python main.py analizar x.eml     Analiza correos desde la terminal
    python main.py --help             Todos los comandos
"""

from __future__ import annotations

import argparse
import getpass
import logging
import os
import random
import secrets
import sys
import threading
import webbrowser
from dataclasses import replace
from datetime import timedelta
from pathlib import Path

from mailsentry import __version__, config as configuracion, db, servicio
from mailsentry.config import DIR_DATOS, Config, _url_sqlite


def configurar_logs(nivel=logging.INFO) -> None:
    DIR_DATOS.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        level=nivel,
        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
        handlers=[logging.StreamHandler(), logging.FileHandler(DIR_DATOS / "mailsentry.log", encoding="utf-8")],
    )
    logging.getLogger("waitress").setLevel(logging.WARNING)


def config_demo(base: Config) -> Config:
    from mailsentry.demo import DOMINIO_DEMO, EMPRESA_DEMO

    return replace(base, empresa_nombre=f"{EMPRESA_DEMO} (DEMO)", dominios_propios=[DOMINIO_DEMO],
                   db_url=_url_sqlite("sqlite:///data/demo.db"), buzones=[], webhook_url="",
                   archivo_modelo="modelo_demo.joblib", archivo_geoip="geoip/demo.csv", geoip_demo=True,
                   ubicacion=(-12.046, -77.043))


def obtener_config(args) -> Config:
    config = configuracion.cargar()
    if getattr(args, "demo", False):
        config = config_demo(config)
        if not Path(config.db_url.removeprefix("sqlite:///")).exists():
            sys.exit("No existe la demostración. Créela primero con:  python main.py demo")
    db.inicializar(config.db_url)
    with db.sesion() as s:
        return config.con_ajustes(db.leer_ajustes(s))


# ------------------------------------------------------------------ comandos

def cmd_iniciar(args) -> None:
    config = obtener_config(args)
    from mailsentry.ingesta import vigilante
    from mailsentry.web import crear_app

    host = args.host or config.host
    puerto = args.puerto or config.puerto
    app = crear_app(config)
    if not args.sin_vigilancia and config.buzones:
        vigilante.iniciar_en_segundo_plano(config)
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{puerto}"
    print(f"\n  MailSentry {__version__} · {config.empresa_nombre}\n  Panel: {url}\n  (Ctrl+C para detener)\n")
    if host in ("0.0.0.0", "::"):
        print("  ATENCIÓN: el panel es visible en la red local. Úselo detrás de HTTPS (ver README).\n")
    if config.abrir_navegador and not args.sin_navegador:
        threading.Timer(1.2, lambda: webbrowser.open(url)).start()
    try:
        from waitress import serve

        serve(app, host=host, port=puerto, threads=8)
    except ImportError:
        app.run(host=host, port=puerto)


def cmd_demo(args) -> None:
    """Empresa ficticia con 90 días de correo, revisión de analistas simulada y modelo de IA entrenado."""
    from mailsentry.db import Correo, Usuario
    from mailsentry.deteccion import ml
    from mailsentry.simulacion import simular
    from werkzeug.security import generate_password_hash

    config = config_demo(configuracion.cargar())
    ruta = Path(config.db_url.removeprefix("sqlite:///"))
    for sufijo in ("", "-wal", "-shm"):
        Path(str(ruta) + sufijo).unlink(missing_ok=True)
    db.inicializar(config.db_url)
    from mailsentry.demo import escribir_geoip_demo

    escribir_geoip_demo(config.ruta_geoip)

    print(f"Generando {args.dias} días de correo para la empresa ficticia...")
    verdad: dict[int, str] = {}
    informe = simular(replace(config, peso_ml=0), dias=args.dias, semilla=args.semilla,
                      al_procesar=lambda m, c: verdad.__setitem__(c.id, m.etiqueta))

    # Simula el trabajo de los analistas: revisan casi todo lo antiguo y parte de lo reciente
    from sqlalchemy import select

    from mailsentry.util import ahora

    r = random.Random(args.semilla)
    limite = ahora() - timedelta(days=7)
    with db.sesion() as s:
        for c in s.scalars(select(Correo)):
            real = verdad.get(c.id)
            amenaza = c.veredicto != "legitimo"
            if real is None or not (amenaza or real == "phishing"):
                continue
            if r.random() > (0.9 if c.recibido_en < limite else 0.35):
                continue
            c.etiqueta = real
            c.estado = ("confirmado" if r.random() < 0.6 else "resuelto") if real == "phishing" else "falso_positivo"
            c.revisado_por, c.revisado_en = "analista.demo", c.recibido_en + timedelta(hours=r.randint(1, 30))
        s.commit()

    print(f"  {informe.total} correos · phishing detectado {informe.vp}/{informe.vp + informe.fn} "
          f"({informe.deteccion:.0%}) · falsos positivos: {informe.fp}")

    if ml.SKLEARN_DISPONIBLE:
        with db.sesion() as s:
            textos, etiquetas = servicio.datos_entrenamiento(s)
        try:
            meta = ml.entrenar(textos, etiquetas, config.ruta_modelo)
            total = servicio.reanalizar_todo(config)
            print(f"  Modelo de IA entrenado con {meta['muestras']} correos (F1 {meta['f1']:.0%}); "
                  f"{total} correos reanalizados con IA.")
        except ValueError as error:
            print(f"  IA no entrenada: {error}")

    password = secrets.token_urlsafe(9)
    with db.sesion() as s:
        s.add(Usuario(usuario="demo", nombre="Usuario de demostración", rol="admin",
                      password_hash=generate_password_hash(password)))
        s.commit()
    credenciales = DIR_DATOS / "demo-credenciales.txt"
    credenciales.write_text(f"usuario: demo\ncontraseña: {password}\n", encoding="utf-8")
    print(f"\nListo. Abra el panel con:  python main.py iniciar --demo\n"
          f"  usuario: demo\n  contraseña: {password}\n  (también guardada en {credenciales})")


def cmd_analizar(args) -> None:
    from mailsentry.deteccion import CATEGORIAS, VEREDICTOS, analizar
    from mailsentry.parser import parsear

    config = obtener_config(args)
    os.system("")  # habilita colores ANSI en la consola de Windows
    colores = {"legitimo": "\033[32m", "sospechoso": "\033[33m", "phishing": "\033[31m"}
    archivos: list[Path] = []
    for ruta in map(Path, args.rutas):
        archivos.extend(sorted(ruta.rglob("*.eml")) if ruta.is_dir() else [ruta])
    if not archivos:
        sys.exit("No se encontraron archivos .eml")
    with db.sesion() as s:
        ctx = servicio.construir_contexto(s, config)
    for archivo in archivos:
        crudo = archivo.read_bytes()
        if args.guardar:
            p = servicio.procesar(crudo, config, fuente="cli", buzon="Terminal", ctx=ctx)
            resultado = p.resultado
            if resultado is None:
                print(f"\n{archivo.name}: ya estaba registrado (correo #{p.correo.id})")
                continue
        else:
            resultado = analizar(parsear(crudo), ctx)
        correo = parsear(crudo)
        color = colores[resultado.veredicto]
        print(f"\n{'─' * 78}\n{archivo.name}\n  De:      {correo.remitente_nombre} <{correo.remitente_email}>\n"
              f"  Asunto:  {correo.asunto}\n  {color}■ {VEREDICTOS[resultado.veredicto].upper()}  "
              f"{resultado.puntaje}/100\033[0m  ·  {CATEGORIAS[resultado.categoria]}"
              + (f"  ·  imita a {resultado.marca}" if resultado.marca else ""))
        for i in resultado.indicadores:
            if i.puntos or args.detalle:
                print(f"   {i.puntos:+4d}  {i.titulo}: {i.detalle[:150]}")


def cmd_vigilar(args) -> None:
    from mailsentry.ingesta import vigilante

    config = obtener_config(args)
    if not config.buzones:
        sys.exit("No hay buzones configurados en config.toml (sección [[buzones]]).")
    if args.una_vez:
        for r in vigilante.revisar_todos(config):
            print(r)
        return
    detener = threading.Event()
    try:
        vigilante.bucle(config, detener)
    except KeyboardInterrupt:
        detener.set()


def cmd_entrenar(args) -> None:
    from mailsentry.deteccion import ml

    config = obtener_config(args)
    with db.sesion() as s:
        textos, etiquetas = servicio.datos_entrenamiento(s)
    try:
        meta = ml.entrenar(textos, etiquetas, config.ruta_modelo)
    except (ValueError, RuntimeError) as error:
        sys.exit(str(error))
    print(f"Modelo entrenado: {meta}")
    if args.reanalizar:
        print(f"{servicio.reanalizar_todo(config)} correos reanalizados.")


def cmd_reanalizar(args) -> None:
    config = obtener_config(args)
    print(f"{servicio.reanalizar_todo(config)} correos reanalizados.")


def cmd_crear_usuario(args) -> None:
    from sqlalchemy import select
    from werkzeug.security import generate_password_hash

    from mailsentry.db import Usuario
    from mailsentry.web.rutas_auth import validar_password

    obtener_config(args)
    password = getpass.getpass("Contraseña: ")
    error = validar_password(password, getpass.getpass("Repetir contraseña: "))
    if error:
        sys.exit(error)
    with db.sesion() as s:
        usuario = s.scalar(select(Usuario).where(Usuario.usuario == args.usuario.lower()))
        if usuario:
            usuario.password_hash, usuario.rol, usuario.activo = generate_password_hash(password), args.rol, True
            print(f"Usuario {args.usuario} actualizado.")
        else:
            s.add(Usuario(usuario=args.usuario.lower(), rol=args.rol, password_hash=generate_password_hash(password)))
            print(f"Usuario {args.usuario} creado con rol {args.rol}.")
        s.commit()


def cmd_actualizar_feeds(args) -> None:
    from mailsentry.deteccion.inteligencia import actualizar_feeds

    config = configuracion.cargar()
    if not config.feeds:
        sys.exit("No hay feeds configurados en config.toml ([inteligencia] feeds).")
    for url, resultado in actualizar_feeds(config.feeds).items():
        print(f"{url}: {resultado}")


def cmd_actualizar_geoip(args) -> None:
    from mailsentry import geoip

    config = configuracion.cargar()
    print("Descargando la base de países por IP de DB-IP (CC BY 4.0, unos 5 MB)...")
    try:
        info = geoip.actualizar(config.ruta_geoip)
    except RuntimeError as error:
        sys.exit(str(error))
    print(f"Listo: {info['rangos']:,} rangos de IP en {info['archivo']} ({info['tamano_kb']:,} KB)\n"
          f"Fuente: {info['url']}  ·  {geoip.ATRIBUCION}\n"
          "Para ubicar los correos ya guardados ejecute:  python main.py reanalizar")


def cmd_agregar_buzon(args) -> None:
    """Asistente en la terminal para conectar un buzón IMAP sin editar archivos."""
    from mailsentry.conexion_buzones import RE_EMAIL, ErrorConexion, guardar, probar, servidor_sugerido

    print("Conectar un buzón a MailSentry (solo lectura: no marca, mueve ni borra correos)
")
    correo = input("Correo a vigilar: ").strip().lower()
    if not RE_EMAIL.match(correo):
        sys.exit("Correo inválido.")
    sugerido = servidor_sugerido(correo)
    servidor = sugerido if sugerido.startswith("imap.") or sugerido.startswith("outlook.") else (
        input(f"Servidor IMAP [{sugerido}]: ").strip() or sugerido)
    if servidor == "imap.gmail.com":
        print("
Use una CONTRASEÑA DE APLICACIÓN de Google (16 letras), no su contraseña normal:
"
              "  https://myaccount.google.com/apppasswords  (requiere la verificación en 2 pasos)
")
    clave = getpass.getpass("Contraseña de aplicación (no se mostrará): ").replace(" ", "")
    print(f"Probando conexión con {servidor}...")
    try:
        probar(correo, clave, servidor)
    except ErrorConexion as error:
        sys.exit(str(error))
    configuracion.cargar()  # crea config.toml si no existe
    guardar(correo, clave, servidor)
    print("Conexión correcta. Buzón guardado; MailSentry lo revisará cada vez que esté abierto.
"
          "La contraseña quedó guardada solo en el archivo .env de esta PC.")


def cmd_verificar_bd(args) -> None:
    from mailsentry.migracion import verificar

    config = configuracion.cargar()
    try:
        info = verificar(config.db_url)
    except Exception as error:
        sys.exit(f"No se pudo conectar a {configuracion.describir_url_bd(config.db_url)}:\n  {error}")
    print(f"Conectado a {info['url']}\n  {info['version']} · latencia {info['latencia_ms']} ms")
    for tabla, total in info["tablas"].items():
        print(f"  {tabla:16} {total:>6} registros")


def cmd_copiar_datos(args) -> None:
    """Copia la base local (SQLite) a la configurada en MAILSENTRY_DB_URL (p. ej. Supabase)."""
    from mailsentry.migracion import copiar

    config = configuracion.cargar()
    origen = _url_sqlite("sqlite:///data/demo.db" if args.demo else "sqlite:///data/mailsentry.db")
    if config.db_url.startswith("sqlite"):
        sys.exit("Defina primero MAILSENTRY_DB_URL en el archivo .env con la conexión de Supabase.")
    if not Path(origen.removeprefix("sqlite:///")).exists():
        sys.exit(f"No existe la base de origen {origen}")
    print(f"Copiando {origen}\n     → {configuracion.describir_url_bd(config.db_url)}")
    try:
        copiados = copiar(origen, config.db_url, forzar=args.forzar)
    except RuntimeError as error:
        sys.exit(str(error))
    print(f"Listo: {sum(copiados.values())} registros copiados.")


def cmd_simular(args) -> None:
    """Mide la detección sobre una empresa ficticia (no toca sus datos reales)."""
    import tempfile

    from mailsentry.simulacion import simular

    with tempfile.TemporaryDirectory() as tmp:
        config = Config(db_url=f"sqlite:///{Path(tmp, 'sim.db').as_posix()}", peso_ml=0, secret_key="x")
        inf = simular(config, dias=args.dias, semilla=args.semilla)
        db._motor.dispose()
    print(f"Correos: {inf.total} · phishing detectado {inf.vp}/{inf.vp + inf.fn} ({inf.deteccion:.1%}) · "
          f"falsos positivos {inf.fp} · legítimos a revisión {inf.dudosos}")
    for nombre, c in sorted(inf.por_plantilla.items()):
        print(f"  {nombre:42} phishing {c['phishing']:>3}  sospechoso {c['sospechoso']:>3}  legítimo {c['legitimo']:>3}")


def main() -> None:
    # Algunas consolas de Windows no usan UTF-8 y fallan al imprimir tildes o flechas
    for flujo in (sys.stdout, sys.stderr):
        if hasattr(flujo, "reconfigure"):
            flujo.reconfigure(encoding="utf-8", errors="replace")
    parser = argparse.ArgumentParser(prog="mailsentry", description="MailSentry · detector de phishing para empresas")
    parser.add_argument("--version", action="version", version=f"MailSentry {__version__}")
    sub = parser.add_subparsers(dest="comando", required=True, metavar="comando")

    p = sub.add_parser("iniciar", help="abre el panel web y vigila los buzones")
    p.add_argument("--demo", action="store_true", help="usar los datos de demostración")
    p.add_argument("--host")
    p.add_argument("--puerto", type=int)
    p.add_argument("--sin-navegador", action="store_true")
    p.add_argument("--sin-vigilancia", action="store_true", help="no revisar buzones automáticamente")
    p.set_defaults(func=cmd_iniciar)

    p = sub.add_parser("demo", help="crea una empresa ficticia con correo y ataques simulados")
    p.add_argument("--dias", type=int, default=90)
    p.add_argument("--semilla", type=int, default=7)
    p.set_defaults(func=cmd_demo)

    p = sub.add_parser("analizar", help="analiza archivos .eml (o carpetas) desde la terminal")
    p.add_argument("rutas", nargs="+")
    p.add_argument("--guardar", action="store_true", help="registrar el resultado en el panel")
    p.add_argument("--detalle", action="store_true", help="mostrar también las señales informativas")
    p.add_argument("--demo", action="store_true")
    p.set_defaults(func=cmd_analizar)

    p = sub.add_parser("vigilar", help="vigila los buzones sin abrir el panel")
    p.add_argument("--una-vez", action="store_true")
    p.set_defaults(func=cmd_vigilar)

    p = sub.add_parser("entrenar", help="entrena el modelo de IA con los correos revisados")
    p.add_argument("--reanalizar", action="store_true")
    p.add_argument("--demo", action="store_true")
    p.set_defaults(func=cmd_entrenar)

    p = sub.add_parser("reanalizar", help="vuelve a analizar todos los correos guardados")
    p.add_argument("--demo", action="store_true")
    p.set_defaults(func=cmd_reanalizar)

    p = sub.add_parser("crear-usuario", help="crea o restablece un usuario del panel")
    p.add_argument("usuario")
    p.add_argument("--rol", choices=("admin", "analista", "lector"), default="admin")
    p.set_defaults(func=cmd_crear_usuario)

    p = sub.add_parser("actualizar-feeds", help="descarga las listas públicas de phishing configuradas")
    p.set_defaults(func=cmd_actualizar_feeds)

    p = sub.add_parser("actualizar-geoip", help="descarga la base de países por IP (rastreo del origen)")
    p.set_defaults(func=cmd_actualizar_geoip)

    p = sub.add_parser("agregar-buzon", help="conecta un buzón (Gmail, Outlook, hosting) respondiendo preguntas")
    p.set_defaults(func=cmd_agregar_buzon)

    p = sub.add_parser("verificar-bd", help="prueba la conexión con la base de datos (p. ej. Supabase)")
    p.set_defaults(func=cmd_verificar_bd)

    p = sub.add_parser("copiar-datos", help="copia la base local SQLite a la de MAILSENTRY_DB_URL")
    p.add_argument("--demo", action="store_true", help="copiar la base de demostración")
    p.add_argument("--forzar", action="store_true", help="vaciar el destino si ya tiene datos")
    p.set_defaults(func=cmd_copiar_datos)

    p = sub.add_parser("simular", help="mide la detección sobre una empresa ficticia")
    p.add_argument("--dias", type=int, default=90)
    p.add_argument("--semilla", type=int, default=7)
    p.set_defaults(func=cmd_simular)

    args = parser.parse_args()
    configurar_logs(logging.WARNING if args.comando in ("analizar", "demo", "simular") else logging.INFO)
    args.func(args)


if __name__ == "__main__":
    main()
