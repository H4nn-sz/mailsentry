"""Casos de prueba escritos a mano (fuera de las plantillas de la demo) en formato .eml crudo."""

from __future__ import annotations

import base64

from mailsentry.demo import _zip
from mailsentry.deteccion import Contexto, Persona

D = "textilesdelsur.example"
AR_OK = "Authentication-Results: mx1; spf=pass smtp.mailfrom={d}; dkim=pass header.d={d}; dmarc=pass header.from={d}\n"


def contexto() -> Contexto:
    return Contexto(
        dominios_propios={D},
        vips=[Persona("Carlos Mendoza", f"carlos.mendoza@{D}", "Gerente General"),
              Persona("Lucía Paredes", f"lucia.paredes@{D}", "Jefa de Finanzas")],
        empleados=[Persona("Jorge Salas", f"jorge.salas@{D}")],
        dominios_conocidos={"hiladosperuanos.com.pe", "confeccioneslima.com.pe", "notificacionesbcp.com.pe",
                            "camaralima.org.pe"},
    )


def eml(de: str, para: str, asunto: str, cuerpo: str, ctype: str = "text/plain; charset=utf-8",
        cte: str = "8bit", auth: bool = True) -> bytes:
    d = de.split("@")[-1].rstrip(">")
    cabecera = AR_OK.format(d=d) if auth else ""
    return (f"{cabecera}From: {de}\nTo: {para}\nSubject: {asunto}\nDate: Wed, 07 Oct 2026 10:00:00 -0500\n"
            f"Message-ID: <x{abs(hash(asunto))}@{d}>\nMIME-Version: 1.0\nContent-Type: {ctype}\n"
            f"Content-Transfer-Encoding: {cte}\n\n{cuerpo}\n").encode("utf-8")


HTML = "text/html; charset=utf-8"

# (nombre, verdad, crudo, limitación conocida)
ATAQUES = [
    ("BEC corto sin palabras clave", eml(
        "Carlos Mendoza <cmendoza.textilesdelsur@gmail.com>", f"lucia.paredes@{D}", "Hola",
        "Hola Lucía, ¿tienes un minuto? Necesito que me ayudes con algo.\nCarlos")),
    ("BEC 'Gerencia General' desde Gmail", eml(
        "Gerencia General <gerencia.tds@gmail.com>", f"jorge.salas@{D}", "Pendiente",
        "Jorge, necesito que realices una transferencia hoy a la cuenta que te indico. Avísame cuando esté.")),
    ("Microsoft en inglés + subdominio engañoso", eml(
        "Microsoft Account Team <no-reply@account-team.ru>", f"diego.huaman@{D}", "Your password expires today",
        '<p>Your password expires today. <a href="https://login-microsoftonline.com-auth.ru/?u=1">Keep current '
        'password</a></p>', HTML)),
    ("Quishing (código QR en imagen)", eml(
        "Seguridad TI <it-security@mfa-renovacion.com>", f"andrea.rios@{D}", "Renovación obligatoria de MFA",
        '<p>Escanee el código QR con su celular para reactivar la autenticación multifactor de su cuenta.</p>'
        '<img src="cid:qr123">', HTML)),
    ("RR. HH. falso con Google Forms", eml(
        "Recursos Humanos <rrhh.textilesdelsur@gmail.com>", f"rosa.quispe@{D}", "Actualización de datos de planilla",
        "Estimado colaborador, actualice sus datos de planilla antes del viernes: https://forms.gle/Zx81kQp")),
    ("Nombre visible con email de SUNAT", eml(
        '"notificaciones@sunat.gob.pe" <aviso@mail-sender.net>', f"jorge.salas@{D}", "Notificación electrónica",
        "Tiene una notificación pendiente en su buzón electrónico. Ingrese aquí: https://buzon-sol.net/ingresar")),
    ("Homógrafo cirílico en enlace", eml(
        "Banca BCP <info@promos-banca.com>", f"lucia.paredes@{D}", "Actualización de seguridad",
        '<p>Ingrese a <a href="https://www.vi\u0430bcp.com/login">www.viabcp.com</a> para actualizar.</p>', HTML)),
    ("Mensaje de voz con adjunto .htm", (
        f"From: Central Telefónica <voicemail@vm-notify.com>\nTo: miguel.torres@{D}\n"
        "Subject: Nuevo mensaje de voz (0:47)\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=XX\n\n"
        "--XX\nContent-Type: text/plain\n\nTiene un nuevo mensaje de voz. Abra el archivo adjunto para escucharlo.\n"
        "--XX\nContent-Type: text/html; name=Mensaje_Voz.htm\nContent-Disposition: attachment; filename=Mensaje_Voz.htm\n"
        "Content-Transfer-Encoding: base64\n\n"
        + base64.b64encode(b"<html><script>window.location='https://evil.example'</script></html>").decode()
        + "\n--XX--\n").encode()),
    ("Secuestro de conversación + zip cifrado", (
        f"From: Confecciones Lima - Compras <compras@confeccioneslima.com.pe>\nTo: andrea.rios@{D}\n"
        "Subject: RE: Pedido de telas\nIn-Reply-To: <abc@confeccioneslima.com.pe>\n"
        "References: <abc@confeccioneslima.com.pe>\nMIME-Version: 1.0\nContent-Type: multipart/mixed; boundary=YY\n\n"
        "--YY\nContent-Type: text/plain; charset=utf-8\n\nPor favor revise el documento adjunto. Clave: 4821\n--YY\n"
        "Content-Type: application/zip; name=Documento.zip\nContent-Disposition: attachment; filename=Documento.zip\n"
        "Content-Transfer-Encoding: base64\n\n"
        + base64.b64encode(_zip({"Documento.pdf": b"x"}, cifrado=True)).decode() + "\n--YY--\n").encode()),
]

# Ataques desde cuentas legítimas comprometidas: todo es auténtico (remitente, firma, plataforma).
# Un motor de reglas no los ve; requieren reputación/antigüedad de dominios o análisis del sitio enlazado.
LIMITACIONES = [
    ("Proveedor hackeado + enlace SharePoint", eml(
        "Hilados Peruanos S.A. <ventas@hiladosperuanos.com.pe>", f"fernando.castillo@{D}", "Orden de pago actualizada",
        "Hola Fernando, te comparto la orden de pago actualizada para tu revisión:\n"
        "https://hiladosperuanos-my.sharepoint.com/:b:/g/personal/ventas/EaB12xYz\nSaludos")),
    ("Proveedor hackeado + dominio recién creado", eml(
        "Hilados Peruanos S.A. <ventas@hiladosperuanos.com.pe>", f"fernando.castillo@{D}", "Documentos del pedido",
        "Buen día, adjunto el enlace con los documentos del pedido de octubre: https://doc-viewer-secure.com/view?id=88213")),
]

LEGITIMOS = [
    ("Google: restablecer contraseña (real)", eml(
        "Google <no-reply@accounts.google.com>", f"sofia.vargas@{D}", "Restablece tu contraseña",
        '<p>Recibimos una solicitud para restablecer la contraseña de tu cuenta. '
        '<a href="https://accounts.google.com/signin/recovery">Restablecer contraseña</a></p>', HTML)),
    ("Boletín con Mailchimp", eml(
        "Cámara de Comercio de Lima <boletin@camaralima.org.pe>", f"carlos.mendoza@{D}", "Boletín semanal",
        '<p>Noticias empresariales.</p><a href="https://camaralima.us12.list-manage.com/track/click?u=1&id=2">'
        'www.camaralima.org.pe</a>', HTML)),
    ("Boletín con rastreador no listado", eml(
        "Revista Textil <news@revistatextil.pe>", f"miguel.torres@{D}", "Edición de octubre",
        '<p>Nueva edición.</p><a href="https://t.sidekickopen90.com/s3t/c/abc">www.revistatextil.pe</a>', HTML)),
    ("Factura legítima que vence hoy", eml(
        "Tintes Andinos <cobranzas@tintesandinos.com.pe>", f"jorge.salas@{D}", "Recordatorio: factura F002-881",
        "Estimados, les recordamos que la factura F002-881 vence hoy. Agradeceremos realizar el pago a la brevedad "
        "a nuestra cuenta BBVA de siempre. Saludos cordiales.")),
    ("Correo interno con aviso de confidencialidad", eml(
        f"Lucía Paredes <lucia.paredes@{D}>", f"jorge.salas@{D}", "Cierre contable",
        "Jorge, por favor prepara el cierre contable de septiembre.\n\nEste mensaje es confidencial y está dirigido "
        "únicamente a su destinatario. Si lo recibió por error, elimínelo.")),
    ("Correo en ISO-8859-1 quoted-printable", eml(
        "Cliente Norte <ventas@clientenorte.com.pe>", f"andrea.rios@{D}", "=?iso-8859-1?Q?Cotizaci=F3n_de_telas?=",
        "Buenos d=EDas, solicitamos cotizaci=F3n de 500 metros de tela.\n", "text/plain; charset=iso-8859-1",
        "quoted-printable")),
    ("Correo malformado", b"Esto no es un correo\x00\xff\xfe valido\n\nsin cabeceras"),
]

# Legítimo, pero debe ir a revisión (no a "legítimo" ni a "phishing"): política de verificación.
A_REVISION = [
    ("Gerente escribe de verdad desde su Gmail", eml(
        "Carlos Mendoza <carlosmendoza.personal@gmail.com>", f"lucia.paredes@{D}", "Propuesta del cliente",
        "Lucía, te reenvío desde mi correo personal la propuesta del cliente. Revísala cuando puedas.")),
]
