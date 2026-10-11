# MailSentry · Guía de instalación (beta)

Detector de phishing para tu correo. Revisa tu bandeja en **solo lectura**: no marca como leído, no mueve ni borra nada.

## 1. Instalar

1. Haz doble clic en **`Instalar-MailSentry-1.0.0.exe`**.
2. Si Windows muestra «Windows protegió su PC» (el programa aún no está firmado digitalmente):
   pulsa **Más información → Ejecutar de todos modos**.
3. Pulsa **Siguiente** hasta terminar. No pide permisos de administrador y puede tardar un par de minutos.
4. Deja marcada la opción **Abrir MailSentry ahora**.

> Se instala en tu usuario y deja un acceso directo en el escritorio. Para quitarlo:
> *Configuración de Windows → Aplicaciones → MailSentry → Desinstalar*.

## 2. Primer uso

1. Se abre MailSentry en su propia ventana. Crea tu **usuario y contraseña** (solo sirven en tu PC).
2. En el asistente escribe tu nombre y ciudad. Si usas Gmail, deja el campo de dominios **vacío**.
3. Junto al reloj de Windows queda un ícono de MailSentry: clic derecho → **Abrir** o **Salir**.

## 3. Conectar tu Gmail

Gmail no deja entrar con la contraseña normal: necesitas una **contraseña de aplicación** (16 letras).

1. Activa la verificación en dos pasos de tu cuenta de Google: <https://myaccount.google.com/signinoptions/twosv>
2. Crea una contraseña de aplicación con el nombre «MailSentry»: <https://myaccount.google.com/apppasswords>
3. Google te mostrará **16 letras**. Cópialas.
4. En MailSentry ve a **Buzones**, escribe tu Gmail, pega las 16 letras y pulsa **Probar y conectar**.
5. En 1 o 2 minutos verás tus correos analizados en el **Panel**. Después revisa cada 2 minutos mientras
   MailSentry esté abierto (el ícono junto al reloj).

La contraseña queda guardada solo en tu PC. Puedes revocarla cuando quieras en la misma página de Google.

## 4. Qué te muestra

- **Panel**: cuántos correos son phishing, de qué país vienen y qué tipo de ataque son.
- **Correos**: cada correo con el motivo por el que se marcó, capa por capa.
- **Analizar**: pega un correo sospechoso y MailSentry te dice qué opina.

## Si algo falla

- *«Correo o contraseña incorrectos»*: usaste tu contraseña normal; usa la de aplicación (paso 3).
- *No abre nada*: busca el ícono junto al reloj → **Abrir**.
- Cuéntale a quien te lo pasó qué mensaje viste; los registros están en
  `%LOCALAPPDATA%\MailSentry\data\mailsentry.log`.
