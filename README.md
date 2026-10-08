# MailSentry · Detector de phishing para empresas

**Página del producto:** https://h4nn-sz.github.io/mailsentry/

Programa en Python que vigila los correos de la empresa, detecta phishing con un motor de
5 capas más un modelo de IA que aprende de sus correcciones, y muestra todo en un panel web:
cuántos ataques se recibieron, de qué tipo, a quién atacaron, qué marcas imitaron y qué hacer.

Pensado para una MYPE peruana (bancos, SUNAT, Yape, couriers locales, fraude del CEO), con una
arquitectura que escala a una empresa grande (PostgreSQL, Microsoft 365, API, roles, auditoría).

---

## Inicio rápido (Windows)

1. Instale Python 3.11 o superior (marque *Add Python to PATH*).
2. Doble clic en **`Iniciar MailSentry.bat`**. La primera vez prepara todo solo (1–2 minutos).
3. Se abre el navegador: cree el usuario administrador.

### Probar con la demostración

```bash
python main.py demo
```

```bash
python main.py iniciar --demo
```

Crea una empresa ficticia (*Textiles del Sur S.A.C.*) con 90 días de correo: tráfico normal
mezclado con 14 tipos de ataque reales (BCP, Interbank, Yape, SUNAT, Microsoft 365, DocuSign,
fraude del CEO, cambio de cuenta de proveedor, facturas con malware, paquetes retenidos,
sextorsión...). El usuario y la contraseña se muestran en consola y quedan en
`data/demo-credenciales.txt`. La demo usa su propia base (`data/demo.db`), separada de sus datos reales.

## Conectar los buzones de la empresa

Edite `config.toml` (se crea solo al primer arranque) y ponga las contraseñas en `.env`
(copie `.env.example`). Nunca escriba contraseñas en `config.toml`.

| Correo de la empresa | Conexión | Qué necesita |
|---|---|---|
| Gmail / Google Workspace | `imap` | Contraseña de aplicación (requiere verificación en 2 pasos) |
| Hosting con cPanel, Zoho, Yahoo | `imap` | Servidor `mail.sudominio.com` y contraseña del buzón |
| Microsoft 365 / Exchange Online | `graph` | App registrada en Entra ID con permiso de aplicación `Mail.Read` |

MailSentry lee los correos **sin marcarlos como leídos** y no modifica nada, salvo que configure
una carpeta `cuarentena` (entonces mueve ahí el phishing).

**Buzón de reportes:** cree `reportes@suempresa` con `tipo = "reportes"`. El personal reenvía ahí
los correos dudosos *como adjunto* y MailSentry analiza el correo original, no el reenvío.

### Asistente de bienvenida

En una instalación nueva, después de crear el administrador, MailSentry abre un asistente de 3 pasos:
nombre de la empresa, dominios y ciudad, directivos y conexión del correo. Todo queda guardado en la
base de datos, así que no hay que editar archivos para empezar.

### Primeros pasos recomendados

1. **Personal → marque a sus directivos** (gerente, jefe de finanzas) con nombre y apellido tal como
   firman. Así se detecta cuando alguien externo usa su nombre (fraude del CEO). MailSentry también
   aprende solo los nombres del personal a partir de los correos internos auténticos.
2. **Listas → dominios propios**: agregue todos los dominios de la empresa.
3. Revise las amenazas: **Confirmar phishing** / **Es legítimo**. Eso entrena la IA.

## Qué detecta

| Capa | Ejemplos |
|---|---|
| Autenticación | SPF, DKIM y DMARC fallidos; falsificación del dominio propio |
| Remitente | Dominios que imitan al suyo, a una marca o a un proveedor habitual (`textilesdeisur`, `micros0ft-office`, `viabcp-seguridad`, letras cirílicas); nombre de un directivo desde Gmail; "Responder a" desviado; cargo corporativo desde correo gratuito |
| Enlaces | Texto que muestra un dominio y lleva a otro; IPs; acortadores; hosting gratuito (`web.app`, `netlify.app`...); marca dentro de un dominio ajeno; listas públicas de phishing; desenvuelve Safe Links |
| Contenido | Urgencia, pedido de credenciales, cambio de cuenta bancaria, premios, extorsión, intimidación tributaria/judicial, códigos QR (quishing), formularios y scripts incrustados, falsas respuestas (`RE:` sin conversación) |
| Adjuntos | Ejecutables, doble extensión (`factura.pdf.exe`), macros, `.iso`, HTML/SVG de captura, PDF con JavaScript, ZIP cifrado con la clave en el mismo correo, programas disfrazados (cabecera MZ) |
| IA | Clasificador de texto entrenado con los correos que confirman sus analistas |
| Inteligencia (opcional) | VirusTotal y feeds de phishing (`python main.py actualizar-feeds`) |

Cada correo recibe un puntaje 0–100, un veredicto (legítimo / sospechoso / phishing), un nivel de
riesgo, una categoría y la **explicación de cada señal**. Una señal crítica nunca puede ser
"suavizada" por la IA.

## Rastreo del origen (globo del panel)

MailSentry toma la IP del servidor que **entregó** el correo al servidor de la empresa (cabeceras
`Received-SPF`, `Authentication-Results` o el primer `Received` con IP pública). Esa línea la escribe
su propio servidor, así que el atacante no puede falsificarla. Con esa IP obtiene el país y la región,
sin consultar servicios externos, usando la base gratuita de DB-IP:

```bash
python main.py actualizar-geoip
```

Descarga unos 5 MB (licencia CC BY 4.0) y se recomienda repetirlo una vez al mes. Luego ejecute
`python main.py reanalizar` para ubicar los correos ya guardados.

**Qué indica y qué no:**
- Indica el país del **servidor de envío**. Si el atacante usa una VPN o un servidor alquilado en otro
  país, se verá ese país.
- Si el correo llegó por **Gmail, Outlook, SendGrid u otro gran proveedor**, la IP es del proveedor y
  no dice nada del atacante. Esos correos se cuentan aparte ("vía Gmail…") y no se dibujan en el globo.
- Más precisión (ciudad, proveedor de internet o ASN, IP del cliente que algunos webmails declaran)
  es el siguiente paso planificado.

En la demostración, las ubicaciones son **ficticias**: se usan rangos de IP reservados para
documentación (RFC 5737), para no atribuir ataques a redes reales.

## Evaluación (resultados reales, con sus límites)

Se ejecutan con `python -m unittest discover -s tests -t .` (17 pruebas) y `python main.py simular`.

- **Simulación de empresa (90 días, 469 correos):** 132/132 ataques detectados y 0 legítimos
  marcados como phishing. **Advertencia:** los ataques simulados y las reglas los escribió el mismo
  autor, así que esta cifra prueba que todo el sistema funciona de punta a punta, no que detecte el
  100 % del phishing real.
- **Casos difíciles escritos aparte (19 correos .eml crudos):** 16 correctos; el directivo que escribe
  de verdad desde su Gmail queda como *sospechoso* (a verificar por teléfono, que es la política
  deseada) y **2 no se detectan**.
- **Límite conocido — cuentas de proveedores hackeadas:** si el correo real de un proveedor es
  robado y envía un enlace a SharePoint o a un dominio recién creado, todo es auténtico (remitente,
  firmas, plataforma) y un motor de reglas no lo ve. Mitigación: capacitación, verificación
  telefónica de pagos y, a futuro, antigüedad de dominios y análisis del sitio enlazado.
- **La IA en la demo marca F1 = 100 %:** es engañoso, porque los correos sintéticos se repiten
  por plantillas. Su valor real aparece con correos reales revisados por sus analistas.

## Comandos

```bash
python main.py iniciar               # panel + vigilancia de buzones
python main.py analizar correo.eml   # análisis en la terminal (o una carpeta completa)
python main.py vigilar --una-vez     # revisa los buzones sin abrir el panel
python main.py entrenar --reanalizar # entrena la IA y reanaliza todo
python main.py crear-usuario ana --rol analista
python main.py actualizar-feeds      # descarga listas públicas de phishing
python main.py actualizar-geoip      # descarga la base de países por IP (rastreo del origen)
python main.py simular --dias 120    # mide la detección en una empresa ficticia
```

**API REST** (defina `MAILSENTRY_API_TOKEN` en `.env`): `POST /api/v1/analizar` (correo crudo),
`GET /api/v1/correos/<id>`, `GET /api/v1/estadisticas?periodo=30d`, con
`Authorization: Bearer <token>`.

## Material de venta

- **Página de venta** en [`sitio/`](sitio/index.html): web estática, sin dependencias y con el globo en vivo.
  Se puede publicar en GitHub Pages o en cualquier hosting. Antes de publicarla, busque `PERSONALIZAR` y
  complete su nombre, correo y WhatsApp.
- **Propuesta comercial** en [`ventas/`](ventas): copie `propuesta.example.toml` como `propuesta.toml`,
  complete sus datos y precios, y genere una propuesta por cliente:

```bash
python ventas/generar_propuesta.py "Comercial Ejemplo S.A.C." --contacto "Ana Torres" --buzones 12
```

  Se crea un HTML en `ventas/propuestas/`. Ábralo en Chrome y use Imprimir → Guardar como PDF.
  Los planes disponibles son `diagnostico`, `continua` y `empresa`.

## Seguridad del propio programa

- Usuarios con roles (lector, analista, administrador), contraseñas con hash, bloqueo tras 5
  intentos fallidos, protección CSRF y bitácora de auditoría.
- El HTML de los correos nunca se muestra: solo texto plano con los enlaces desactivados (`hxxps://`).
- Por defecto el panel solo es accesible desde la misma PC (`127.0.0.1`). Para abrirlo a la red use
  `host = "0.0.0.0"` **detrás de un proxy con HTTPS** (Caddy, IIS o Nginx).

## Hoja de ruta hacia empresa mediana/grande

| Ya incluido | Siguiente paso |
|---|---|
| PostgreSQL con solo cambiar `url` | Docker y despliegue en servidor |
| Microsoft 365 vía Graph, IMAP | API de Gmail / Google Workspace |
| Roles, auditoría, API REST | Inicio de sesión con Entra ID / Google (SSO) |
| Buzón de reportes del personal | Botón "Reportar phishing" para Outlook |
| VirusTotal, feeds | Antigüedad de dominios (RDAP), lectura de códigos QR, análisis del sitio enlazado |
| Webhook a Teams/Slack | Envío a SIEM, multiempresa |

## Licencia

Código visible como portafolio; **todos los derechos reservados**. No se permite usarlo, copiarlo ni
ofrecerlo como servicio sin autorización escrita. Ver [LICENSE](LICENSE).

## Estructura

```
mailsentry/
  parser.py          lectura segura de .eml
  deteccion/         motor: autenticacion, remitente, enlaces, contenido, adjuntos, ml, inteligencia
  servicio.py        analiza + guarda + alerta (lo usan todas las entradas)
  ingesta/           IMAP, Microsoft Graph y vigilancia periódica
  origen.py          rastreo de la IP del servidor de envío
  geoip.py, paises.py  país y región por IP (base DB-IP local)
  estadisticas.py    datos del panel, reporte y recomendaciones
  web/               panel Flask; globo y gráficos sin dependencias externas (funciona sin internet)
herramientas/        generar_tierra.py: puntos del globo a partir de Natural Earth (dominio público)
  demo.py            empresa y ataques simulados
tests/               pruebas automáticas
```
