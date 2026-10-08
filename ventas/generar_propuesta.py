"""Genera la propuesta comercial de MailSentry para una empresa (HTML listo para imprimir como PDF).

Uso:
    python ventas/generar_propuesta.py "Comercial Ejemplo S.A.C." --contacto "Ana Torres" --buzones 12
    python ventas/generar_propuesta.py "Empresa X" --plan diagnostico
    python ventas/generar_propuesta.py "Empresa Y" --plan empresa --buzones 80 --dominios empresay.com.pe empresay.com

El archivo queda en ventas/propuestas/. Ábralo en Chrome y use Imprimir → Guardar como PDF.
"""

from __future__ import annotations

import argparse
import base64
import re
import sys
import tomllib
import unicodedata
from datetime import date, timedelta
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

CARPETA = Path(__file__).resolve().parent
RAIZ = CARPETA.parent
PLANES = {
    "diagnostico": "Diagnóstico",
    "continua": "Protección continua",
    "empresa": "Empresa",
}
MESES = ("enero", "febrero", "marzo", "abril", "mayo", "junio", "julio", "agosto", "septiembre", "octubre",
         "noviembre", "diciembre")


def cargar_datos() -> dict:
    ruta = CARPETA / "propuesta.toml"
    if not ruta.exists():
        ruta = CARPETA / "propuesta.example.toml"
        print("Aviso: usando ventas/propuesta.example.toml (cópielo como propuesta.toml y complete sus datos).")
    return tomllib.loads(ruta.read_text(encoding="utf-8"))


def slug(texto: str) -> str:
    texto = unicodedata.normalize("NFKD", texto).encode("ascii", "ignore").decode()
    return re.sub(r"[^A-Za-z0-9]+", "-", texto).strip("-")[:60] or "empresa"


def fecha_larga(d: date) -> str:
    return f"{d.day} de {MESES[d.month - 1]} de {d.year}"


def dinero(valor: float, moneda: str) -> str:
    return f"{moneda} {valor:,.2f}"


def calcular(plan: str, buzones: int, precios: dict) -> dict:
    datos = precios.get(plan, {})
    if plan == "diagnostico":
        unico = float(datos.get("pago_unico", 0))
        return {"filas": [("Diagnóstico de correo y reporte de amenazas", "Pago único", unico)],
                "unico": unico, "mensual": 0.0}
    instalacion = float(datos.get("instalacion", 0))
    mensual = max(float(datos.get("minimo_mes", 0)), buzones * float(datos.get("por_buzon_mes", 0)))
    return {
        "filas": [
            ("Implementación, configuración y capacitación", "Pago único", instalacion),
            (f"Servicio MailSentry · {buzones} buzón(es)", "Mensual", mensual),
        ],
        "unico": instalacion, "mensual": mensual,
    }


def main() -> None:
    # Algunas consolas de Windows no usan UTF-8 y fallan al imprimir tildes o flechas
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    p = argparse.ArgumentParser(description="Genera una propuesta comercial de MailSentry")
    p.add_argument("empresa", help="razón social o nombre de la empresa cliente")
    p.add_argument("--contacto", default="", help="persona a quien va dirigida")
    p.add_argument("--cargo-contacto", default="")
    p.add_argument("--plan", choices=PLANES, default="continua")
    p.add_argument("--buzones", type=int, default=10, help="número de buzones a proteger")
    p.add_argument("--dominios", nargs="*", default=[], help="dominios de correo del cliente")
    p.add_argument("--numero", default="", help="número de propuesta (por defecto, según la fecha)")
    args = p.parse_args()

    datos = cargar_datos()
    precios = datos.get("precios", {})
    moneda = precios.get("moneda", "S/")
    hoy = date.today()
    calculo = calcular(args.plan, args.buzones, precios)
    sin_precios = calculo["unico"] == 0 and calculo["mensual"] == 0

    entorno = Environment(loader=FileSystemLoader(CARPETA), autoescape=select_autoescape(["html"]))
    entorno.filters["dinero"] = lambda v: dinero(v, moneda)
    logo = base64.b64encode((RAIZ / "mailsentry" / "web" / "static" / "img" / "logo.svg").read_bytes()).decode()
    html = entorno.get_template("plantilla_propuesta.html").render(
        empresa=args.empresa, contacto=args.contacto, cargo_contacto=args.cargo_contacto,
        plan=args.plan, plan_nombre=PLANES[args.plan], buzones=args.buzones, dominios=args.dominios,
        numero=args.numero or f"MS-{hoy:%Y%m%d}-{slug(args.empresa)[:6].upper()}",
        fecha=fecha_larga(hoy), vence=fecha_larga(hoy + timedelta(days=int(precios.get("validez_dias", 30)))),
        proveedor=datos.get("proveedor", {}), precios=precios, calculo=calculo, moneda=moneda,
        sin_precios=sin_precios, logo=f"data:image/svg+xml;base64,{logo}",
    )
    salida = CARPETA / "propuestas" / f"Propuesta-MailSentry-{slug(args.empresa)}.html"
    salida.parent.mkdir(exist_ok=True)
    salida.write_text(html, encoding="utf-8")
    print(f"Propuesta generada: {salida}")
    if sin_precios:
        print("Aviso: los precios están en 0. Complete [precios] en ventas/propuesta.toml.")
    print("Ábrala en Chrome y use Imprimir → Guardar como PDF.")


if __name__ == "__main__":
    sys.exit(main())
