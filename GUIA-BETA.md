# MailSentry · Guía para probadores (beta)

Gracias por probar MailSentry. Te toma unos 10 minutos y funciona en **Windows 10 u 11**.
MailSentry revisa tu correo **en tu propia PC**: tus correos no se envían a nadie.

## 1. Instala Python (una sola vez)
1. Entra a https://www.python.org/downloads/ y descarga la versión más reciente.
2. Al instalar, **marca la casilla "Add python.exe to PATH"** y pulsa *Install Now*.

## 2. Descarga MailSentry
1. Entra a https://github.com/H4nn-sz/mailsentry → botón verde **Code** → **Download ZIP**.
2. Descomprime el ZIP en una carpeta corta, por ejemplo `C:\MailSentry` o tu carpeta *Descargas*.
   (Evita carpetas muy profundas: Windows no acepta rutas demasiado largas.)

## 3. Ábrelo
1. Doble clic en **`Iniciar MailSentry.bat`**.
2. La primera vez tarda 1–2 minutos preparando todo. Luego se abre el navegador solo.
3. Crea tu usuario y contraseña de administrador.
4. Completa el asistente de 3 pasos:
   - **Nombre:** tu nombre o el de tu empresa.
   - **Dominios:** si usas un Gmail personal, **déjalo vacío**. Solo se ponen dominios propios de una empresa (ej. `miempresa.com.pe`).
   - **Directivos:** opcional.

Para cerrarlo, cierra la ventana negra. Para volver a usarlo, otra vez doble clic en `Iniciar MailSentry.bat`.

## 4. Conecta tu Gmail
1. Activa la **verificación en dos pasos**: https://myaccount.google.com/signinoptions/twosv
2. Crea una **contraseña de aplicación** (nombre: `MailSentry`): https://myaccount.google.com/apppasswords
   Google te muestra 16 letras.
3. **Cierra MailSentry** y haz doble clic en **`Conectar mi correo.bat`**.
4. Escribe tu correo y pega la contraseña de aplicación (no se verá mientras escribes, es normal).
5. Debe decir **"Conexión correcta"**. Vuelve a abrir `Iniciar MailSentry.bat`.

En unos minutos verás en el panel los correos de los últimos 30 días ya analizados.

**Tu correo está seguro:** MailSentry solo **lee**; no marca correos como leídos, no los mueve ni los borra.
La contraseña de aplicación queda solo en tu PC (archivo `.env`) y puedes revocarla cuando quieras
en la misma página de Google donde la creaste.

## 5. Qué me ayuda que me cuentes
- ¿Marcó como peligroso algún correo que era normal? (falso positivo) → en el correo, pulsa **"Es legítimo"**.
- ¿Te llegó algún correo sospechoso que no detectó? Cuéntame de qué trataba.
- ¿Algo fue confuso o dio error? Una captura de pantalla ayuda mucho.

Contacto: giancarlogarcia09011@gmail.com

---
*MailSentry es software en prueba. Uso autorizado solo para la beta, según la licencia del repositorio.*
