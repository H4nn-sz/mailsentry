"""Datos de referencia del motor: marcas, dominios, extensiones y frases.

Las frases están normalizadas (minúsculas y sin tildes) porque el texto del
correo se normaliza igual antes de compararlo. Para adaptar MailSentry a otro
país o sector basta con ampliar estas listas.
"""

from __future__ import annotations

# --------------------------------------------------------------------------
# Dominios
# --------------------------------------------------------------------------

# Sufijos de dos niveles: el dominio registrable de "a.b.com.pe" es "b.com.pe"
SUFIJOS_DOBLES = frozenset({
    "com.pe", "gob.pe", "org.pe", "edu.pe", "net.pe", "nom.pe", "mil.pe", "sld.pe",
    "com.mx", "gob.mx", "org.mx", "edu.mx", "com.ar", "gob.ar", "org.ar", "com.co", "gov.co",
    "org.co", "edu.co", "com.br", "gov.br", "org.br", "com.bo", "gob.bo", "com.ec", "gob.ec",
    "com.uy", "com.py", "com.ve", "gob.ve", "cl.cl", "gob.cl", "com.gt", "com.sv", "com.hn",
    "com.ni", "co.cr", "com.do", "com.pa", "com.es", "co.uk", "org.uk", "ac.uk", "gov.uk",
    "com.au", "net.au", "org.au", "co.jp", "co.in", "com.cn", "com.tr", "co.za", "com.sg",
})

CORREO_GRATUITO = frozenset({
    "gmail.com", "googlemail.com", "hotmail.com", "hotmail.es", "outlook.com", "outlook.es",
    "live.com", "live.com.pe", "msn.com", "yahoo.com", "yahoo.es", "yahoo.com.pe", "ymail.com",
    "icloud.com", "me.com", "aol.com", "protonmail.com", "proton.me", "pm.me", "gmx.com",
    "gmx.net", "mail.com", "yandex.com", "yandex.ru", "zoho.com", "zohomail.com", "tutanota.com",
    "tuta.io", "mail.ru", "inbox.com", "hushmail.com",
})

TLD_SOSPECHOSOS = frozenset({
    "xyz", "top", "click", "link", "work", "gq", "tk", "ml", "cf", "ga", "buzz", "rest", "cam",
    "icu", "monster", "cyou", "sbs", "site", "website", "space", "fun", "online", "zip", "mov",
    "country", "kim", "loan", "win", "bid", "review", "date", "racing", "download", "stream",
    "cfd", "lol", "quest", "bond", "beauty", "hair", "skin", "makeup", "autos", "boats", "yachts",
    "mom", "pics", "support", "help", "live", "life", "shop",
})

ACORTADORES = frozenset({
    "bit.ly", "bitly.com", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "cutt.ly",
    "rebrand.ly", "shorturl.at", "rb.gy", "t.ly", "tiny.cc", "s.id", "shorte.st", "adf.ly",
    "qrco.de", "urlz.fr", "v.gd", "x.co", "short.io", "bl.ink", "soo.gd", "clck.ru", "u.to",
    "tinu.be", "acortar.link", "acortaurl.com",
})

# Plataformas gratuitas muy usadas para alojar páginas de phishing (se compara por sufijo)
HOSTING_ABUSADO = (
    "firebaseapp.com", "web.app", "netlify.app", "vercel.app", "github.io", "pages.dev",
    "workers.dev", "glitch.me", "repl.co", "replit.app", "replit.dev", "herokuapp.com",
    "000webhostapp.com", "weebly.com", "weeblysite.com", "wixsite.com", "wixstudio.io",
    "blogspot.com", "sites.google.com", "forms.gle", "ngrok.io", "ngrok-free.app", "ngrok.app",
    "trycloudflare.com", "azurewebsites.net", "web.core.windows.net", "blob.core.windows.net",
    "storage.googleapis.com", "s3.amazonaws.com", "r2.dev", "ipfs.io", "dweb.link", "w3s.link",
    "jotform.com", "typeform.com", "webflow.io", "framer.app", "framer.website",
    "godaddysites.com", "square.site", "mystrikingly.com", "carrd.co", "notion.site",
    "surge.sh", "onrender.com", "fly.dev", "translate.goog", "mybluehost.me", "yolasite.com",
)

# Reescritores de enlaces legítimos (filtros de seguridad y plataformas de envío masivo).
# No se usan como evidencia de engaño cuando el texto visible apunta a otro dominio.
REDIRECTORES_LEGITIMOS = (
    "safelinks.protection.outlook.com", "urldefense.com", "urldefense.proofpoint.com",
    "linkprotect.cudasvc.com", "list-manage.com", "mailchimp.com", "mcsv.net", "sendgrid.net",
    "mandrillapp.com", "hubspotlinks.com", "hs-sites.com", "mailgun.org", "sparkpostmail.com",
    "rs6.net", "exacttarget.com", "mktomail.com", "mkt.com", "brevo.com", "sendibt2.com",
    "sendinblue.com", "awstrack.me", "doppler.com", "fromdoppler.com", "google.com",
)

# --------------------------------------------------------------------------
# Marcas suplantadas con frecuencia (Perú + globales)
#   patrones: cómo aparece la marca en el texto normalizado
#   dominios: dominios legítimos de la marca (se aceptan sus subdominios)
#   solo_remitente: la marca es una palabra común; solo se busca en el nombre del remitente
# --------------------------------------------------------------------------

MARCAS: dict[str, dict] = {
    "BCP": {"patrones": ["bcp", "banco de credito", "viabcp", "banca por internet bcp"],
            "dominios": ["viabcp.com", "bcp.com.pe", "notificacionesbcp.com.pe"]},
    "Interbank": {"patrones": ["interbank"], "dominios": ["interbank.pe", "interbank.com.pe", "netinterbank.com.pe"]},
    "BBVA": {"patrones": ["bbva"], "dominios": ["bbva.pe", "bbva.com", "bbvacontinental.pe"]},
    "Scotiabank": {"patrones": ["scotiabank"], "dominios": ["scotiabank.com.pe", "scotiabank.com"]},
    "Banco de la Nación": {"patrones": ["banco de la nacion"], "dominios": ["bn.com.pe"]},
    "Mibanco": {"patrones": ["mibanco"], "dominios": ["mibanco.com.pe"]},
    "BanBif": {"patrones": ["banbif"], "dominios": ["banbif.com.pe"]},
    "Yape": {"patrones": ["yape"], "dominios": ["yape.com.pe", "viabcp.com"]},
    "Plin": {"patrones": ["plin"], "dominios": ["interbank.pe", "bbva.pe", "scotiabank.com.pe"], "solo_remitente": True},
    "SUNAT": {"patrones": ["sunat", "superintendencia nacional de aduanas"], "dominios": ["sunat.gob.pe"]},
    "SUNARP": {"patrones": ["sunarp"], "dominios": ["sunarp.gob.pe"]},
    "RENIEC": {"patrones": ["reniec"], "dominios": ["reniec.gob.pe"]},
    "Poder Judicial": {"patrones": ["poder judicial"], "dominios": ["pj.gob.pe"]},
    "Serpost": {"patrones": ["serpost"], "dominios": ["serpost.com.pe"]},
    "Olva Courier": {"patrones": ["olva courier", "olva"], "dominios": ["olvacourier.com"]},
    "DHL": {"patrones": ["dhl"], "dominios": ["dhl.com", "dhl.pe"]},
    "FedEx": {"patrones": ["fedex"], "dominios": ["fedex.com"]},
    "Microsoft 365": {"patrones": ["microsoft", "office 365", "microsoft 365", "outlook web", "onedrive",
                                   "sharepoint", "microsoft teams"],
                      "dominios": ["microsoft.com", "office.com", "office365.com", "outlook.com", "outlook.es",
                                   "live.com", "hotmail.com", "hotmail.es", "microsoftonline.com",
                                   "sharepoint.com", "microsoft365.com", "onedrive.com", "1drv.ms", "msn.com",
                                   "azure.com", "windows.com"]},
    "Google": {"patrones": ["google", "gmail", "google workspace", "google drive"],
               "dominios": ["google.com", "gmail.com", "googlemail.com", "google.com.pe", "youtube.com"]},
    "Apple": {"patrones": ["apple", "icloud", "apple id"], "dominios": ["apple.com", "icloud.com", "me.com"]},
    "PayPal": {"patrones": ["paypal"], "dominios": ["paypal.com"]},
    "Amazon": {"patrones": ["amazon", "aws"], "dominios": ["amazon.com", "amazon.es", "amazon.com.mx", "aws.amazon.com"]},
    "Netflix": {"patrones": ["netflix"], "dominios": ["netflix.com"]},
    "Mercado Libre": {"patrones": ["mercado libre", "mercadolibre", "mercado pago", "mercadopago"],
                      "dominios": ["mercadolibre.com.pe", "mercadolibre.com", "mercadopago.com", "mercadopago.com.pe"]},
    "Meta / Facebook": {"patrones": ["facebook", "meta business", "instagram", "whatsapp"],
                        "dominios": ["facebook.com", "facebookmail.com", "meta.com", "instagram.com", "whatsapp.com"]},
    "LinkedIn": {"patrones": ["linkedin"], "dominios": ["linkedin.com", "licdn.com"]},
    "DocuSign": {"patrones": ["docusign"], "dominios": ["docusign.com", "docusign.net"]},
    "Adobe": {"patrones": ["adobe sign", "adobe acrobat", "adobe document cloud"], "dominios": ["adobe.com", "adobesign.com"]},
    "Dropbox": {"patrones": ["dropbox"], "dominios": ["dropbox.com", "dropboxmail.com"]},
    "WeTransfer": {"patrones": ["wetransfer"], "dominios": ["wetransfer.com", "we.tl"]},
    "Zoom": {"patrones": ["zoom meeting", "reunion de zoom", "zoom video"], "dominios": ["zoom.us", "zoom.com"]},
    "Claro": {"patrones": ["claro"], "dominios": ["claro.com.pe"], "solo_remitente": True},
    "Movistar": {"patrones": ["movistar", "telefonica"], "dominios": ["movistar.com.pe", "movistar.pe", "telefonica.com"]},
    "Entel": {"patrones": ["entel"], "dominios": ["entel.pe"], "solo_remitente": True},
    "Falabella": {"patrones": ["falabella", "cmr"], "dominios": ["falabella.com.pe", "falabella.com", "bancofalabella.pe"]},
    "Ripley": {"patrones": ["ripley"], "dominios": ["ripley.com.pe", "bancoripley.com.pe"]},
}

# --------------------------------------------------------------------------
# Adjuntos
# --------------------------------------------------------------------------

EXT_EJECUTABLES = frozenset({
    "exe", "scr", "com", "pif", "bat", "cmd", "msi", "msp", "js", "jse", "vbs", "vbe", "wsf", "wsh",
    "ps1", "psm1", "hta", "cpl", "jar", "lnk", "reg", "dll", "sys", "gadget", "application",
    "appx", "msix", "appref-ms", "url", "scf", "chm", "inf", "sct", "xll", "iqy", "slk", "one",
})
EXT_IMAGEN_DISCO = frozenset({"iso", "img", "vhd", "vhdx"})
EXT_MACROS = frozenset({"docm", "dotm", "xlsm", "xltm", "xlam", "pptm", "potm", "ppam", "ppsm", "sldm"})
EXT_OFFICE_ANTIGUO = frozenset({"doc", "xls", "ppt", "dot", "xlt"})
EXT_COMPRIMIDOS = frozenset({"zip", "rar", "7z", "gz", "tar", "cab", "ace", "arj", "xz", "bz2", "tgz", "z"})
EXT_HTML = frozenset({"html", "htm", "shtml", "xhtml", "svg", "mht", "mhtml"})
EXT_DOCUMENTO = frozenset({"pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "jpg", "jpeg", "png", "txt", "csv", "rtf", "odt"})

# --------------------------------------------------------------------------
# Frases (texto normalizado). Cada grupo suma puntos según cuántas frases distintas aparezcan:
#   puntos = min(maximo, base + extra * (coincidencias - 1))
# --------------------------------------------------------------------------

GRUPOS_FRASES: dict[str, dict] = {
    "KW_URGENCIA": {
        "titulo": "Lenguaje de urgencia o presión",
        "base": 8, "extra": 4, "maximo": 18, "severidad": "media",
        "categorias": {"credenciales": 0.4, "bec": 0.3, "fraude_pagos": 0.3},
        "frases": [
            "urgente", "inmediatamente", "de inmediato", "en las proximas 24 horas", "24 horas", "48 horas",
            "ultimo aviso", "aviso final", "accion requerida", "requiere su atencion", "requiere accion",
            "cuenta suspendida", "sera suspendida", "sera bloqueada", "cuenta bloqueada", "ha sido bloqueada",
            "sera desactivada", "sera eliminada", "evite la suspension", "evitar el bloqueo", "hoy mismo",
            "lo antes posible", "a la brevedad", "plazo vence", "vence hoy", "expirara", "caducara",
            "perdera el acceso", "inmediata", "urgent", "immediately", "action required", "account suspended",
            "final notice", "within 24 hours", "verify now", "will be closed", "asap",
        ],
    },
    "KW_CREDENCIALES": {
        "titulo": "Solicita credenciales o datos personales",
        "base": 12, "extra": 5, "maximo": 25, "severidad": "alta",
        "categorias": {"credenciales": 1.0},
        "frases": [
            "verifique su cuenta", "verificar su cuenta", "verifica tu cuenta", "valide su cuenta", "validar su cuenta",
            "valida tu cuenta", "confirme su identidad", "confirma tu identidad", "confirmar su identidad",
            "actualice sus datos", "actualiza tus datos", "actualizar sus datos", "actualizar su informacion",
            "ingrese su contrasena", "ingresa tu contrasena", "su contrasena", "tu contrasena", "contrasena expira",
            "contrasena caduca", "iniciar sesion", "inicie sesion", "restablecer su contrasena", "clave de internet",
            "clave de acceso", "clave secreta", "clave token", "clave dinamica", "codigo de verificacion",
            "numero de tarjeta", "cvv", "datos de su tarjeta", "datos de tu tarjeta", "reactivar su cuenta",
            "desbloquear su cuenta", "desbloquea tu cuenta", "buzon esta lleno", "buzon de correo lleno",
            "cuota de almacenamiento", "espacio de almacenamiento", "mensajes retenidos", "correos pendientes de entrega",
            "verify your account", "confirm your identity", "update your information", "update your payment",
            "reset your password", "your password", "mailbox is full", "storage quota", "sign in to",
            "reactivar la autenticacion", "autenticacion multifactor", "doble factor de autenticacion",
            "renovar su mfa", "renovacion de mfa", "re-authenticate", "multi-factor authentication",
        ],
    },
    "KW_QR": {
        "titulo": "Pide escanear un código QR (quishing)",
        "base": 15, "extra": 5, "maximo": 20, "severidad": "alta",
        "categorias": {"credenciales": 1.0},
        "frases": [
            "escanee el codigo qr", "escanea el codigo qr", "escanear el codigo qr", "escanee el qr",
            "escanea el qr", "codigo qr adjunto", "scan the qr code", "scan the qr", "qr code below",
        ],
    },
    "KW_FINANZAS": {
        "titulo": "Solicitud de pago o transferencia",
        "base": 8, "extra": 4, "maximo": 18, "severidad": "media",
        "categorias": {"fraude_pagos": 0.7, "bec": 0.3},
        "frases": [
            "transferencia", "transferencia bancaria", "realizar un pago", "realice el pago", "pago urgente",
            "factura pendiente", "factura vencida", "facturas vencidas", "pago pendiente", "orden de pago",
            "comprobante de pago", "deposito", "abono", "cuenta corriente", "numero de cuenta", "cci",
            "cuenta interbancaria", "swift", "iban", "wire transfer", "payment", "invoice", "bank details",
            "remesa", "liquidacion", "adelanto", "tarifa de envio", "pago de aduanas", "arancel",
        ],
    },
    "KW_BEC": {
        "titulo": "Patrón de fraude del CEO / cambio de cuenta bancaria",
        "base": 16, "extra": 6, "maximo": 30, "severidad": "alta",
        "categorias": {"bec": 0.6, "fraude_pagos": 0.4},
        "frases": [
            "cambio de cuenta", "nueva cuenta bancaria", "nuevos datos bancarios", "actualizamos nuestros datos bancarios",
            "hemos cambiado de banco", "cambiamos de banco", "cambio de banco", "nuestra nueva cuenta",
            "estoy en una reunion", "estoy en reunion", "no puedo atender llamadas", "no puedo hablar ahora",
            "necesito que me hagas un favor", "eres discreto", "eres discreta", "tema confidencial",
            "asunto confidencial", "no lo comentes", "no comentes con nadie", "mantenlo en reserva",
            "solo por este medio", "solo por correo", "tarjetas de regalo", "gift card", "gift cards",
            "keep this confidential", "change of bank details", "updated bank details",
        ],
    },
    "KW_CONTACTO_INICIAL": {
        "titulo": "Primer contacto típico de fraude del CEO",
        "base": 5, "extra": 3, "maximo": 10, "severidad": "baja",
        "categorias": {"bec": 1.0},
        "frases": [
            "estas disponible", "estas en la oficina", "necesito un favor", "tienes un minuto",
            "are you available", "quick favor", "are you at your desk",
        ],
    },
    "KW_PREMIO": {
        "titulo": "Promesa de premio, herencia o dinero fácil",
        "base": 12, "extra": 6, "maximo": 25, "severidad": "alta",
        "categorias": {"estafa": 1.0},
        "frases": [
            "ganador", "ha ganado", "has ganado", "ha sido seleccionado", "has sido seleccionado", "premio",
            "sorteo", "loteria", "herencia", "millones de dolares", "beneficiario", "reclame su premio",
            "reclama tu premio", "inversion garantizada", "ganancias garantizadas", "duplica tu dinero",
            "criptomonedas", "you have won", "lottery", "inheritance", "bono especial", "reembolso pendiente",
        ],
    },
    "KW_EXTORSION": {
        "titulo": "Amenaza o extorsión",
        "base": 12, "extra": 12, "maximo": 40, "severidad": "alta",
        "categorias": {"extorsion": 1.0},
        "frases": [
            "bitcoin", "btc", "billetera", "monedero", "wallet", "webcam", "camara web", "video intimo",
            "contenido para adultos", "sitios para adultos", "pornografia", "hackee tu", "hackeado tu",
            "tengo acceso a tu", "tengo acceso a su", "tus contactos", "sus contactos", "grabe un video",
            "te grabe", "i recorded", "your device was hacked", "malware en tu dispositivo",
        ],
    },
    "KW_AMENAZA_LEGAL": {
        "titulo": "Intimidación legal o tributaria",
        "base": 8, "extra": 4, "maximo": 16, "severidad": "media",
        "categorias": {"malware": 0.4, "suplantacion_marca": 0.4, "credenciales": 0.2},
        "frases": [
            "cobranza coactiva", "deuda coactiva", "embargo", "orden judicial", "notificacion judicial",
            "demanda judicial", "demanda en su contra", "citacion", "multa", "infraccion", "sancion",
            "papeleta", "resolucion de ejecucion", "valor de cobranza", "orden de captura", "proceso judicial",
        ],
    },
    "KW_SALUDO_GENERICO": {
        "titulo": "Saludo genérico (no le conoce por su nombre)",
        "base": 4, "extra": 0, "maximo": 4, "severidad": "baja",
        "categorias": {"credenciales": 0.5, "suplantacion_marca": 0.5},
        "frases": [
            "estimado cliente", "estimada cliente", "estimado usuario", "estimada usuaria", "querido cliente",
            "estimado(a) cliente", "estimado titular", "apreciado cliente", "dear customer", "dear user",
            "dear valued customer", "hola usuario", "estimado afiliado",
        ],
    },
}

# Palabras de cargo/área: si el nombre visible las usa y el envío viene de un correo gratuito,
# es una suplantación frecuente ("Gerencia General <gerencia.pe2026@gmail.com>").
PALABRAS_CORPORATIVAS = (
    "gerente", "gerencia", "director", "directora", "soporte", "seguridad", "banco", "facturacion",
    "cobranza", "cobranzas", "tesoreria", "contabilidad", "recursos humanos", "rrhh", "administracion",
    "notificacion", "notificaciones", "servicio al cliente", "atencion al cliente", "help desk",
    "mesa de ayuda", "it support", "sistemas", "proveedores", "pagos", "finanzas", "legal",
)

# Palabras en rutas de URL típicas de páginas de captura de credenciales
RUTAS_SOSPECHOSAS = (
    "login", "signin", "sign-in", "logon", "verify", "verificar", "validar", "secure", "seguridad",
    "account", "cuenta", "update", "actualizar", "confirm", "banking", "webscr", "wp-admin",
    "wp-includes", "wp-content", "auth", "session", "token", "unlock", "desbloqueo", "recovery",
)
