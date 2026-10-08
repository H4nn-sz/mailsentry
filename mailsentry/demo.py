"""Simulación: una empresa ficticia que recibe correo normal mezclado con ataques reales.

Los correos se construyen como .eml auténticos (cabeceras, autenticación, HTML,
adjuntos) y pasan por el mismo motor que el correo de producción. Ningún correo
se envía: todo es local. Los dominios de los atacantes son inventados y los
adjuntos "maliciosos" son inofensivos (solo imitan la forma del archivo).
"""

from __future__ import annotations

import io
import ipaddress
import random
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid
from typing import Callable

EMPRESA_DEMO = "Textiles del Sur S.A.C."
DOMINIO_DEMO = "textilesdelsur.example"
MX = "mx1.textilesdelsur.example"
LIMA = timezone(timedelta(hours=-5))

# (usuario, nombre, departamento, cargo, es_vip)
EMPLEADOS = [
    ("carlos.mendoza", "Carlos Mendoza", "Gerencia", "Gerente General", True),
    ("lucia.paredes", "Lucía Paredes", "Finanzas", "Jefa de Finanzas", True),
    ("jorge.salas", "Jorge Salas", "Finanzas", "Contador", False),
    ("andrea.rios", "Andrea Ríos", "Ventas", "Ejecutiva de Ventas", False),
    ("miguel.torres", "Miguel Torres", "Ventas", "Jefe de Ventas", False),
    ("sofia.vargas", "Sofía Vargas", "Ventas", "Asistente Comercial", False),
    ("rosa.quispe", "Rosa Quispe", "Logística", "Coordinadora de Logística", False),
    ("patricia.flores", "Patricia Flores", "Recursos Humanos", "Analista de RR. HH.", False),
    ("diego.huaman", "Diego Huamán", "TI", "Soporte TI", False),
    ("fernando.castillo", "Fernando Castillo", "Compras", "Jefe de Compras", False),
]
BUZON_POR_AREA = {"Gerencia": "Gerencia", "Finanzas": "Finanzas", "Ventas": "Ventas"}


def email_de(usuario: str) -> str:
    return f"{usuario}@{DOMINIO_DEMO}"


def nombre_de(usuario: str) -> str:
    return next(e[1] for e in EMPLEADOS if e[0] == usuario)


def area_de(email: str) -> str:
    usuario = email.split("@")[0]
    return next((e[2] for e in EMPLEADOS if e[0] == usuario), "Sin asignar")


@dataclass
class Muestra:
    plantilla: str
    etiqueta: str  # verdad: phishing | legitimo
    de_nombre: str
    de_email: str
    para: list[str]
    asunto: str
    texto: str
    html: str = ""
    adjuntos: list[tuple[str, bytes, str]] = field(default_factory=list)
    auth: tuple[str, str, str] | None = ("pass", "pass", "pass")  # spf, dkim, dmarc
    responder_a: str = ""
    respuesta: bool = False
    origen: str = ""  # país del servidor de envío ("" = correo interno)
    servidor: str = ""  # nombre del servidor de envío (por defecto mail.<dominio>)


# ------------------------------------------------------------ adjuntos de imitación (inofensivos)

INOFENSIVO = b"// Archivo de demostracion de MailSentry. No contiene codigo.\n"


def _pdf(nota: str = "documento") -> bytes:
    return f"%PDF-1.4\n1 0 obj << /Type /Catalog >> endobj\n% {nota}\ntrailer << /Root 1 0 R >>\n%%EOF\n".encode()


def _zip(archivos: dict[str, bytes], cifrado: bool = False) -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as z:
        for nombre, datos in archivos.items():
            z.writestr(nombre, datos)
    datos = bytearray(buffer.getvalue())
    if cifrado:  # solo activa el bit "cifrado" en las cabeceras; el contenido sigue siendo texto
        for firma, desplazamiento in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
            i = datos.find(firma)
            while i != -1:
                datos[i + desplazamiento] |= 0x1
                i = datos.find(firma, i + 4)
    return bytes(datos)


def _html_falso_login(marca: str) -> bytes:
    return (f"<html><body><h3>{marca}</h3><form action='https://captura-datos.web.app/r'>"
            "<input name='u'><input type='password' name='p'><button>Ingresar</button></form>"
            "</body></html>").encode()


# ------------------------------------------------------------ ataques

def a_bcp(r: random.Random, para: str) -> Muestra:
    dominio = r.choice(["viabcp-seguridad.xyz", "bcp-validacion.online", "viabcp-pe.com"])
    destino = f"https://{dominio}/bcp/login.php?id={r.randint(1000, 9999)}"
    asunto = r.choice(["Su Clave de Internet ha sido bloqueada", "Aviso importante: actividad inusual en su cuenta",
                       "BCP: confirme su identidad para evitar el bloqueo"])
    cuerpo = ("Estimado cliente: detectamos un intento de acceso no reconocido a su Banca por Internet. "
              "Por su seguridad, su clave de internet será bloqueada en las próximas 24 horas. "
              "Para evitar el bloqueo, valide su cuenta ingresando aquí:")
    html = (f"<p>{cuerpo}</p><p><a href='{destino}'>https://www.viabcp.com/validacion</a></p>"
            "<p>Atentamente,<br>Banco de Crédito del Perú</p>")
    return Muestra("Phishing bancario (BCP)", "phishing", "BCP - Banca por Internet", f"alertas@{dominio}", [para],
                   asunto, f"{cuerpo} {destino}", html, auth=("pass", "none", "none"))


def a_interbank(r: random.Random, para: str) -> Muestra:
    ip = f"185.{r.randint(10, 250)}.{r.randint(1, 250)}.{r.randint(1, 250)}"
    texto = ("Estimado cliente, hemos detectado un consumo no reconocido con su tarjeta. Si no lo reconoce, "
             f"confirme su identidad de inmediato en http://{ip}/interbank/acceso/ para bloquear la operación.")
    return Muestra("Phishing bancario (Interbank)", "phishing", "Interbank", "seguridad@interbank-pe.com", [para],
                   "Consumo no reconocido - acción requerida", texto, auth=("pass", "pass", "none"))


def a_yape(r: random.Random, para: str) -> Muestra:
    destino = "https://yape-validacion.click/verificar"
    html = ("<p>Hola, por disposición de la SBS debes confirmar tu identidad para seguir usando tu Yape. "
            f"Si no lo haces hoy mismo tu cuenta será desactivada.</p><a href='{destino}'>Validar mi Yape</a>")
    return Muestra("Suplantación de Yape", "phishing", "Yape", "soporte@yape-validacion.click", [para],
                   "Yape: confirma tu identidad", "Confirma tu identidad para seguir usando Yape " + destino, html,
                   auth=("pass", "pass", "pass"))


def a_microsoft(r: random.Random, para: str) -> Muestra:
    destino = f"https://office365-mail-verify.web.app/owa/login?u={para}"
    html = ("<p>Su buzón está lleno (98% de su cuota de almacenamiento). Los mensajes entrantes quedarán "
            "retenidos. Inicie sesión para ampliar su espacio sin costo.</p>"
            f"<p><a href='{destino}'>https://outlook.office.com/mail</a></p><p>Equipo de Microsoft 365</p>")
    return Muestra("Robo de credenciales (Microsoft 365)", "phishing", "Microsoft 365",
                   "no-reply@micros0ft-office.com", [para], "Su buzón está lleno - acción requerida",
                   "Su buzón está lleno. Inicie sesión: " + destino, html, auth=("pass", "none", "none"))


def a_docusign(r: random.Random, para: str) -> Muestra:
    destino = "https://docs-review-2026.netlify.app/sign"
    html = ("<p>Lucía Paredes le envió un documento para revisar y firmar: <b>Planilla_Octubre.pdf</b></p>"
            f"<p><a href='{destino}'>REVISAR DOCUMENTO</a></p><p>Para ver el documento debe iniciar sesión "
            "con su correo corporativo.</p>")
    return Muestra("Documento compartido falso (DocuSign)", "phishing", "DocuSign vía Lucía Paredes",
                   "dse@docusign-envelope.net", [para], "Lucía Paredes le envió un documento para firmar",
                   "Documento pendiente de firma " + destino, html)


def a_ceo(r: random.Random, para: str) -> Muestra:
    destinatario = r.choice(["lucia.paredes", "jorge.salas"])
    monto = r.choice(["S/ 18,500.00", "US$ 7,900.00", "S/ 24,300.00"])
    texto = (f"{nombre_de(destinatario).split()[0]}, estoy en una reunión con el directorio y no puedo atender "
             f"llamadas. Necesito que realices hoy mismo una transferencia de {monto} a un proveedor nuevo. "
             "Es un tema confidencial, no lo comentes por ahora. Te paso los datos de la cuenta: "
             "Cta. Cte. 191-2345678-0-12, CCI 00219100234567801255. Confírmame cuando esté hecho.\n\n"
             "Enviado desde mi iPhone")
    return Muestra("Fraude del CEO", "phishing", "Carlos Mendoza", "carlos.mendoza.gerencia@gmail.com",
                   [email_de(destinatario)], r.choice(["Pago urgente", "Transferencia pendiente", "Urgente"]), texto)


def a_ceo_regalo(r: random.Random, para: str) -> Muestra:
    texto = ("¿Estás disponible? Necesito un favor urgente: compra 5 tarjetas de regalo de Google Play de S/ 200 "
             "para unos clientes, luego te reembolso. No puedo hablar ahora, respóndeme solo por correo.")
    return Muestra("Fraude del CEO (tarjetas de regalo)", "phishing", "Carlos Mendoza",
                   f"gerencia@{DOMINIO_DEMO}", [para], "¿Estás disponible?", texto,
                   auth=("fail", "none", "fail"), responder_a="c.mendoza.ofi@outlook.com")


def a_dominio_propio(r: random.Random, para: str) -> Muestra:
    falso = r.choice(["textilesdeisur.example", "textilesdelsur-pe.example", "textiles-delsur.example"])
    texto = ("Jorge, por favor procesa hoy el pago de la factura adjunta del proveedor; vence hoy y no quiero "
             "multas. La cuenta está en el PDF. Gracias.\n\nLucía Paredes\nJefa de Finanzas")
    return Muestra("Dominio parecido al de la empresa", "phishing", "Lucía Paredes", f"lucia.paredes@{falso}",
                   [email_de("jorge.salas")], "Pago de factura pendiente", texto,
                   adjuntos=[("Factura_E001-4521.pdf", _pdf("factura"), "application/pdf")])


def a_proveedor(r: random.Random, para: str) -> Muestra:
    falso = r.choice(["hiladosperuanos-pe.com", "hiladosperuano.com.pe"])
    texto = ("Estimados, por medio de la presente les informamos que hemos cambiado de banco. A partir de la fecha "
             "los pagos de las facturas pendientes deben realizarse a nuestra nueva cuenta bancaria: Interbank "
             "Cta. Cte. 200-3004567891, CCI 003-200-003004567891-35. Agradeceremos realizar el pago de la factura "
             "vencida F001-2231 a la brevedad.\n\nArea de Cobranzas - Hilados Peruanos S.A.")
    return Muestra("Fraude de proveedor (cambio de cuenta)", "phishing", "Hilados Peruanos - Cobranzas",
                   f"cobranzas@{falso}", [email_de("fernando.castillo"), email_de("jorge.salas")],
                   "RE: Facturas pendientes de pago", texto, responder_a="hiladosperuanos.pagos@outlook.com")


def a_factura_malware(r: random.Random, para: str) -> Muestra:
    numero = f"F001-000{r.randint(10000, 99999)}"
    variante = r.randrange(5)
    if variante == 0:
        adjunto = (f"Factura_{numero}.pdf.exe", b"MZ\x90\x00" + INOFENSIVO, "application/octet-stream")
    elif variante == 1:
        adjunto = (f"Factura_{numero}.zip", _zip({f"Factura_{numero}.js": INOFENSIVO}), "application/zip")
    elif variante == 2:
        adjunto = (f"Detalle_{numero}.xlsm", _zip({"[Content_Types].xml": b"<Types/>", "xl/vbaProject.bin": INOFENSIVO}),
                   "application/vnd.ms-excel.sheet.macroEnabled.12")
    elif variante == 3:
        adjunto = (f"Factura_{numero}.iso", b"\x00" * 64 + INOFENSIVO, "application/octet-stream")
    else:
        adjunto = (f"Factura_{numero}.html", _html_falso_login("SUNAT - Comprobantes"), "text/html")
    texto = ("Estimado cliente, adjuntamos su comprobante electrónico. Tiene un pago pendiente: revise el detalle "
             "en el archivo adjunto y realice el pago hoy mismo para evitar recargos.")
    return Muestra("Factura falsa con malware", "phishing", "Facturación Electrónica",
                   "comprobantes@fe-comprobantes.top", [para], f"Factura Electrónica {numero}", texto,
                   adjuntos=[adjunto], auth=("softfail", "none", "none"))


def a_sunat(r: random.Random, para: str) -> Muestra:
    expediente = f"0230-{r.randint(100000, 999999)}"
    if r.random() < 0.5:
        destino = "https://sunat-buzon-electronico.firebaseapp.com/expediente"
        html = (f"<p>Se le notifica la resolución de ejecución coactiva del expediente {expediente}. "
                "De no regularizar en 48 horas se procederá al embargo de sus cuentas.</p>"
                f"<p><a href='{destino}'>Descargar expediente</a></p>")
        return Muestra("Suplantación de SUNAT (enlace)", "phishing", "SUNAT - Notificaciones",
                       "notificaciones@sunat-pe.online", [para], f"Valor de cobranza coactiva N° {expediente}",
                       "Notificación de cobranza coactiva " + destino, html, auth=("pass", "pass", "none"))
    texto = (f"Se le notifica la resolución de ejecución coactiva del expediente {expediente}. Descargue el "
             "archivo adjunto (contraseña: 2026) para ver el detalle de la deuda y evitar el embargo.")
    return Muestra("Suplantación de SUNAT (adjunto)", "phishing", "SUNAT", "notifica@sunat-gob.com", [para],
                   f"Notificación de embargo - Exp. {expediente}", texto,
                   adjuntos=[(f"Expediente_{expediente}.zip", _zip({"Expediente.pdf.js": INOFENSIVO}, cifrado=True),
                              "application/zip")], auth=("pass", "none", "none"))


def a_courier(r: random.Random, para: str) -> Muestra:
    marca, dominio = r.choice([("Olva Courier", "olva-tracking.click"), ("DHL Express", "dhl-entregas.shop"),
                               ("Serpost", "serpost-envios.xyz")])
    destino = f"https://bit.ly/{r.choice(['3xKp9Qa', '4tRw2Lm', '2vNh8Zc'])}"
    html = (f"<p>Su paquete no pudo ser entregado por falta de pago de la tarifa de envío (S/ 4.90).</p>"
            f"<p>Realice el pago en las próximas 24 horas o será devuelto: <a href='{destino}'>{destino}</a></p>")
    return Muestra(f"Paquete falso ({marca})", "phishing", marca, f"envios@{dominio}", [para],
                   "Su paquete está retenido", "Pague la tarifa de envío: " + destino, html)


def a_sextorsion(r: random.Random, para: str) -> Muestra:
    texto = ("Hackeé tu dispositivo y tengo acceso a tu cámara web. Grabé un video íntimo tuyo mientras "
             "visitabas sitios para adultos. Si no transfieres US$ 1,200 en bitcoin a esta billetera en 48 horas, "
             "enviaré el video a todos tus contactos. BTC: bc1q9h7garjr0yr6lq2w8x5n4k3p0jvzt9xv2t6c8m")
    return Muestra("Sextorsión", "phishing", "Anónimo", f"x{r.randint(1000, 9999)}@proton.me", [para],
                   "Tengo acceso a tu dispositivo", texto)


def a_premio(r: random.Random, para: str) -> Muestra:
    html = ("<p>¡Felicidades! Ha sido seleccionado ganador del sorteo aniversario. Reclame su premio de "
            "S/ 5,000 completando el formulario con los datos de su tarjeta para el depósito.</p>"
            "<a href='https://premios-aniversario.win/reclamar'>Reclamar premio</a>")
    return Muestra("Premio falso", "phishing", "Sorteo Aniversario", "premios@sorteo-nacional.win", [para],
                   "¡Usted ha ganado S/ 5,000!", "Reclame su premio https://premios-aniversario.win/reclamar", html)


# ------------------------------------------------------------ correo legítimo

def l_interno(r: random.Random, para: str) -> Muestra:
    autor = r.choice([e for e in EMPLEADOS if email_de(e[0]) != para])
    asunto, texto = r.choice([
        ("Reunión de coordinación semanal", "Hola equipo, la reunión de coordinación será el jueves a las 10 am en la sala 2."),
        ("Reporte de ventas de septiembre", "Adjunto el reporte de ventas del mes. Crecimos 8% respecto a agosto."),
        ("Solicitud de vacaciones", "Solicito vacaciones del 14 al 18 del próximo mes. Quedo atenta a su aprobación."),
        ("Inventario de almacén", "Ya está actualizado el inventario de hilos y telas al cierre de la semana."),
        ("Capacitación de seguridad", "Recuerden la capacitación sobre seguridad de la información este viernes."),
        ("Programación de despachos", "Los despachos a Arequipa salen el lunes. Confirmen pedidos pendientes."),
    ])
    adjuntos = [("Reporte.pdf", _pdf("reporte"), "application/pdf")] if "Reporte" in asunto else []
    return Muestra("Correo interno", "legitimo", autor[1], email_de(autor[0]), [para], asunto,
                   f"{texto}\n\nSaludos,\n{autor[1]}\n{autor[3]}", adjuntos=adjuntos, respuesta=r.random() < 0.3)


def l_proveedor(r: random.Random, para: str) -> Muestra:
    numero = r.randint(1000, 9999)
    asunto, texto, adjuntos = r.choice([
        (f"Cotización N° 2026-{numero}", "Estimado Fernando, adjuntamos la cotización solicitada de hilo de algodón "
         "peinado. Validez: 15 días. Quedamos atentos.", [(f"Cotizacion_{numero}.pdf", _pdf("cotizacion"), "application/pdf")]),
        (f"Factura electrónica F001-{numero}", "Adjuntamos la factura electrónica por el pedido entregado. El pago "
         "se realiza según las condiciones de crédito acordadas (30 días).",
         [(f"F001-{numero}.pdf", _pdf("factura"), "application/pdf"), (f"F001-{numero}.xml", b"<Invoice/>", "text/xml")]),
    ])
    return Muestra("Proveedor habitual", "legitimo", "Hilados Peruanos S.A.", "ventas@hiladosperuanos.com.pe",
                   [email_de("fernando.castillo")], asunto, texto + "\n\nArea Comercial - Hilados Peruanos S.A.",
                   adjuntos=adjuntos)


def l_cliente(r: random.Random, para: str) -> Muestra:
    oc = r.randint(300, 999)
    return Muestra("Cliente", "legitimo", "Confecciones Lima - Compras", "compras@confeccioneslima.com.pe",
                   [email_de(r.choice(["andrea.rios", "miguel.torres", "sofia.vargas"]))], f"Orden de compra OC-{oc}",
                   f"Buenos días, enviamos la orden de compra OC-{oc} por 1,200 metros de tela jersey. "
                   "Por favor confirmar fecha de entrega.", adjuntos=[(f"OC-{oc}.pdf", _pdf("oc"), "application/pdf")])


def l_banco(r: random.Random, para: str) -> Muestra:
    html = ("<p>Hola, te confirmamos que realizaste una transferencia a terceros desde tu Banca por Internet.</p>"
            "<p>Revisa el detalle en <a href='https://www.viabcp.com'>www.viabcp.com</a></p>")
    return Muestra("Notificación real del banco", "legitimo", "BCP", "notificaciones@notificacionesbcp.com.pe",
                   [email_de("lucia.paredes")], "Constancia de transferencia a terceros",
                   "Constancia de transferencia a terceros.", html)


def l_sunat(r: random.Random, para: str) -> Muestra:
    return Muestra("Notificación real de SUNAT", "legitimo", "SUNAT", "noreply@sunat.gob.pe",
                   [email_de("jorge.salas")], "Constancia de presentación - Declaración mensual",
                   "Se ha registrado la presentación de su declaración mensual (Formulario Virtual 621) del "
                   "periodo anterior. Puede consultar la constancia en SUNAT Operaciones en Línea.")


def l_microsoft(r: random.Random, para: str) -> Muestra:
    html = ("<p>Detectamos un nuevo inicio de sesión en su cuenta de Microsoft desde Windows, Lima.</p>"
            "<p>Si fue usted, puede ignorar este mensaje. Si no, <a href='https://account.microsoft.com/security'>"
            "revise la actividad reciente</a>.</p>")
    return Muestra("Alerta real de Microsoft", "legitimo", "Microsoft",
                   "account-security-noreply@accountprotection.microsoft.com", [para],
                   "Nuevo inicio de sesión en su cuenta", "Nuevo inicio de sesión detectado.", html)


def l_courier(r: random.Random, para: str) -> Muestra:
    return Muestra("Courier real", "legitimo", "Olva Courier", "notificaciones@olvacourier.com",
                   [email_de("rosa.quispe")], "Su envío fue entregado",
                   "Su envío con guía 8812345 fue entregado en Arequipa. Gracias por confiar en Olva Courier.")


def l_newsletter(r: random.Random, para: str) -> Muestra:
    html = ("<p>Novedades del sector textil: exportaciones crecieron 12% en el tercer trimestre.</p>"
            "<p><a href='https://www.linkedin.com/news/textil'>Leer más</a></p>")
    return Muestra("Boletín (LinkedIn)", "legitimo", "LinkedIn News", "news@linkedin.com", [para],
                   "Lo más leído de la semana", "Novedades del sector textil.", html)


def l_marketing(r: random.Random, para: str) -> Muestra:
    """Publicidad agresiva pero no maliciosa: caso límite real."""
    html = ("<p>¡ÚLTIMO DÍA! 40% de descuento en máquinas de coser industriales. La oferta termina hoy.</p>"
            "<a href='https://bit.ly/oferta-maquinas'>Ver ofertas</a>")
    return Muestra("Publicidad agresiva", "legitimo", "Ofertas Industriales", "promo@maquinas-ofertas.shop", [para],
                   "¡Último día de ofertas!", "Ofertas en máquinas de coser https://bit.ly/oferta-maquinas", html)


ATAQUES: list[tuple[Callable, float]] = [
    (a_bcp, 3), (a_interbank, 1.5), (a_yape, 1.5), (a_microsoft, 3), (a_docusign, 1.5), (a_ceo, 2), (a_ceo_regalo, 1),
    (a_dominio_propio, 1.5), (a_proveedor, 1.5), (a_factura_malware, 3), (a_sunat, 2.5), (a_courier, 2),
    (a_sextorsion, 1), (a_premio, 1),
]
LEGITIMOS: list[tuple[Callable, float]] = [
    (l_interno, 10), (l_proveedor, 3), (l_cliente, 3), (l_banco, 2), (l_sunat, 1.5), (l_microsoft, 1.5),
    (l_courier, 1.5), (l_newsletter, 2), (l_marketing, 1),
]


# País de los servidores de envío de cada plantilla (pesos). Las legítimas internas no tienen salto externo.
ORIGENES: dict[Callable, dict[str, float]] = {
    a_bcp: {"PE": 3, "BR": 2, "US": 2, "NL": 1.5, "RU": 1}, a_interbank: {"CO": 2, "PE": 2, "US": 1},
    a_yape: {"PE": 4, "BR": 3, "MX": 3}, a_microsoft: {"NG": 2.5, "RU": 2.5, "US": 2, "NL": 1.5, "IN": 1.5},
    a_docusign: {"US": 4, "DE": 3, "SG": 3}, a_ceo: {"US": 1}, a_ceo_regalo: {"RU": 4, "UA": 3, "RO": 3},
    a_dominio_propio: {"NG": 4, "US": 3, "ZA": 3}, a_proveedor: {"NG": 5, "GB": 2.5, "ES": 2.5},
    a_factura_malware: {"RU": 3, "UA": 2, "CN": 2, "VN": 1.5, "TR": 1.5}, a_sunat: {"PE": 4, "CO": 3, "MX": 3},
    a_courier: {"CN": 4, "HK": 3, "VN": 3}, a_sextorsion: {"VN": 3, "IN": 3, "ID": 4}, a_premio: {"NG": 5, "CN": 5},
    l_proveedor: {"PE": 1}, l_cliente: {"PE": 1}, l_banco: {"PE": 1}, l_sunat: {"PE": 1}, l_microsoft: {"US": 1},
    l_courier: {"PE": 1}, l_newsletter: {"US": 1}, l_marketing: {"US": 1},
}
SERVIDORES = {  # envíos a través de grandes proveedores: la IP es del proveedor, no del remitente
    a_ceo: "mail-sor-f41.google.com", l_microsoft: "mail-dm6nam10on2085.outbound.protection.outlook.com",
    a_ceo_regalo: "vps28471.alquiler-vps.example",  # falsifica el dominio propio desde un servidor alquilado
    l_newsletter: "mailb-ae.linkedin.com", l_marketing: "o1.ptr4512.sendgrid.net",
}

# Mapa ficticio país -> bloque /28 dentro de los rangos reservados para documentación (RFC 5737).
# No corresponde a ninguna red real; solo lo usa la demostración.
PAISES_DEMO = ["PE", "US", "BR", "NL", "RU", "NG", "CN", "CO", "MX", "DE", "UA", "IN", "VN", "ID", "TR", "RO",
               "GB", "ES", "SG", "HK", "ZA", "AR", "CL", "FR", "KR"]
REDES_DEMO = ("192.0.2.0", "198.51.100.0", "203.0.113.0")


def _bloque(pais: str) -> int:
    i = PAISES_DEMO.index(pais)
    return int(ipaddress.ip_address(REDES_DEMO[i // 16])) + (i % 16) * 16


def ip_demo(pais: str, r: random.Random) -> str:
    return str(ipaddress.ip_address(_bloque(pais) + r.randint(1, 14)))


def escribir_geoip_demo(ruta) -> None:
    ruta.parent.mkdir(parents=True, exist_ok=True)
    lineas = ["# Geolocalización FICTICIA para la demostración (rangos RFC 5737 de documentación)"]
    for pais in PAISES_DEMO:
        inicio = _bloque(pais)
        lineas.append(f"{ipaddress.ip_address(inicio)},{ipaddress.ip_address(inicio + 15)},{pais}")
    ruta.write_text("\n".join(lineas) + "\n", encoding="utf-8")


def construir_eml(m: Muestra, fecha: datetime, r: random.Random | None = None) -> bytes:
    """Arma un .eml como lo entregaría el servidor de correo de la empresa."""
    r = r or random.Random(0)
    dominio = m.de_email.rsplit("@", 1)[1]
    msg = EmailMessage()
    msg["Return-Path"] = f"<{m.de_email}>"
    # Salto interno (IP privada): del filtro de entrada al buzón. El rastreo debe ignorarlo.
    msg["Received"] = f"from {MX} ([10.0.0.5]) by buzones.{DOMINIO_DEMO} with LMTP; {format_datetime(fecha)}"
    if m.origen:
        servidor = m.servidor or f"mail.{dominio}"
        msg["Received"] = (f"from {servidor} ({servidor} [{ip_demo(m.origen, r)}]) by {MX} "
                           f"with ESMTPS; {format_datetime(fecha)}")
    else:
        msg["Received"] = f"from mail.{DOMINIO_DEMO} ([10.0.0.12]) by {MX} with ESMTPS; {format_datetime(fecha)}"
    if m.auth:
        spf, dkim, dmarc = m.auth
        msg["Authentication-Results"] = (f"{MX}; spf={spf} smtp.mailfrom={dominio}; dkim={dkim} header.d={dominio}; "
                                         f"dmarc={dmarc} header.from={dominio}")
    usuario, host = m.de_email.split("@")
    msg["From"] = Address(display_name=m.de_nombre, username=usuario, domain=host)
    msg["To"] = ", ".join(m.para)
    msg["Subject"] = ("RE: " + m.asunto) if m.respuesta else m.asunto
    msg["Date"] = format_datetime(fecha)
    msg["Message-ID"] = make_msgid(domain=dominio)
    if m.responder_a:
        msg["Reply-To"] = m.responder_a
    if m.respuesta:
        previo = make_msgid(domain=DOMINIO_DEMO)
        msg["In-Reply-To"] = previo
        msg["References"] = previo
    msg.set_content(m.texto)
    if m.html:
        msg.add_alternative(m.html, subtype="html")
    for nombre, datos, mime in m.adjuntos:
        principal, sub = mime.split("/", 1)
        msg.add_attachment(datos, maintype=principal, subtype=sub, filename=nombre)
    return msg.as_bytes()


def generar(dias: int = 90, semilla: int = 7) -> list[tuple[Muestra, datetime, bytes]]:
    """Genera el correo de 'dias' días: tráfico normal + ataques con campañas que se intensifican."""
    r = random.Random(semilla)
    hoy = datetime.now(LIMA).replace(hour=0, minute=0, second=0, microsecond=0)
    personal = [email_de(e[0]) for e in EMPLEADOS]
    campanas = {r.randrange(dias) for _ in range(4)}
    resultado = []
    for d in range(dias, -1, -1):
        dia = hoy - timedelta(days=d)
        laborable = dia.weekday() < 5
        n_legit = r.randint(3, 7) if laborable else r.randint(0, 1)
        tendencia = 1 + (dias - d) / dias  # los ataques crecen con el tiempo
        n_ataques = int(r.random() * 2.2 * tendencia) + (r.randint(3, 6) if d in campanas else 0)
        for plantillas, n in ((LEGITIMOS, n_legit), (ATAQUES, n_ataques)):
            for _ in range(n):
                funcion = r.choices([p for p, _ in plantillas], weights=[w for _, w in plantillas])[0]
                muestra = funcion(r, r.choice(personal))
                if funcion in ORIGENES:
                    opciones = ORIGENES[funcion]
                    muestra.origen = r.choices(list(opciones), weights=list(opciones.values()))[0]
                    muestra.servidor = SERVIDORES.get(funcion, "")
                fecha = dia + timedelta(hours=r.randint(7, 20), minutes=r.randint(0, 59))
                resultado.append((muestra, fecha, construir_eml(muestra, fecha, r)))
    resultado.sort(key=lambda x: x[1])
    return resultado
