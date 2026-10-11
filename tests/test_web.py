"""Pruebas del panel web y la API con el cliente de pruebas de Flask."""

from __future__ import annotations

import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mailsentry import db  # noqa: E402
from mailsentry.config import Config  # noqa: E402
from mailsentry.web import crear_app  # noqa: E402
from tests import casos  # noqa: E402

CLAVE_PRUEBA = "clave-de-prueba-1234"


class TestWeb(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        os.environ["MAILSENTRY_TOKEN_PRUEBA"] = "token-prueba-123456"
        cls.config = Config(db_url=f"sqlite:///{Path(cls.tmp.name, 'web.db').as_posix()}", secret_key="x" * 32,
                            dominios_propios=[casos.D], peso_ml=0, api_token_env="MAILSENTRY_TOKEN_PRUEBA")
        cls.app = crear_app(cls.config)
        cls.app.config["TESTING"] = True

    @classmethod
    def tearDownClass(cls):
        db._motor.dispose()
        cls.tmp.cleanup()

    def _csrf(self, cliente, ruta):
        html = cliente.get(ruta).get_data(as_text=True)
        return re.search(r'name="_csrf" value="([^"]+)"', html).group(1)

    def test_flujo_completo(self):
        c = self.app.test_client()
        # 1. Sin usuarios: obliga a crear el administrador
        r = c.get("/")
        self.assertIn("/configuracion-inicial", r.headers["Location"])
        token = self._csrf(c, "/configuracion-inicial")
        r = c.post("/configuracion-inicial", data={"_csrf": token, "usuario": "admin", "nombre": "Admin",
                                                   "password": CLAVE_PRUEBA, "confirmacion": CLAVE_PRUEBA})
        self.assertEqual(r.status_code, 302)
        self.assertIn("/bienvenida", r.headers["Location"])

        # 1b. Asistente: empresa, dominios y ciudad; se omiten directivos; termina
        token = self._csrf(c, "/bienvenida?paso=1")
        r = c.post("/bienvenida?paso=1", data={"_csrf": token, "empresa": "Prueba S.A.C.",
                                               "dominios": casos.D, "ciudad": "Arequipa"})
        self.assertIn("paso=2", r.headers["Location"])
        # Un dominio gratuito (gmail.com) nunca debe quedar como "propio": haría parecer interno a todo Gmail
        c.post("/bienvenida?paso=1", data={"_csrf": token, "empresa": "Prueba S.A.C.",
                                           "dominios": f"{casos.D}\ngmail.com", "ciudad": "Arequipa"})
        from mailsentry.db import ReglaLista
        with db.sesion() as s:
            propios = {r.valor for r in s.query(ReglaLista).filter_by(tipo="propio")}
        self.assertEqual(propios, {casos.D})
        # Importación masiva desde el asistente (texto pegado de Excel)
        r = c.post("/personal/importar", data={"_csrf": token, "volver": "bienvenida",
                                               "texto": f"Carlos Mendoza\tcarlos.mendoza@{casos.D}\tGerente General\tGerencia\tsí\n"
                                                        f"Rosa Quispe\trosa.quispe@{casos.D}\tCoordinadora\tLogística\tno"})
        self.assertIn("paso=2", r.headers["Location"])
        self.assertIn("1 directivo", c.get("/bienvenida?paso=2").get_data(as_text=True))
        c.post("/bienvenida?paso=2", data={"_csrf": token, "nombre": "", "email": "", "cargo": ""})
        c.post("/bienvenida?paso=3", data={"_csrf": token})
        self.assertNotIn("Falta la configuración inicial", c.get("/").get_data(as_text=True))
        self.assertIn("Prueba S.A.C.", c.get("/reporte").get_data(as_text=True))

        # 2. Instalación nueva: panel vacío y aviso de registrar directivos
        inicio = c.get("/").get_data(as_text=True)
        self.assertIn("Aún no hay correos", inicio)
        self.assertNotIn("Registre a sus directivos", inicio)  # el asistente ya importó a un directivo

        # 3. Llega un correo interno auténtico: MailSentry aprende "Carlos Mendoza <carlos.mendoza@...>"
        interno = casos.eml(f"Carlos Mendoza <carlos.mendoza@{casos.D}>", f"lucia.paredes@{casos.D}",
                            "Reunión del lunes", "Lucía, confirmemos la reunión del lunes a las 9.")
        token = self._csrf(c, "/analizar")
        c.post("/analizar", data={"_csrf": token, "fuente": interno.decode("utf-8")})

        # ... y el fraude del CEO desde Gmail ya se detecta sin configurar nada a mano
        token = self._csrf(c, "/analizar")
        r = c.post("/analizar", data={"_csrf": token, "fuente": casos.ATAQUES[0][1].decode("utf-8")})
        self.assertEqual(r.status_code, 302)
        detalle = c.get(r.headers["Location"]).get_data(as_text=True)
        # Carlos fue importado como directivo en el asistente: se detecta como suplantación de directivo
        self.assertIn("Usa el nombre de un directivo", detalle)
        self.assertNotIn("Legítimo</span> <span", detalle)

        # 3. Panel, listado, exportación y reporte con datos
        for ruta in ("/", "/correos", "/correos?veredicto=amenazas", "/reporte", "/personal", "/listas",
                     "/buzones", "/modelo", "/usuarios"):
            self.assertEqual(c.get(ruta).status_code, 200, ruta)
        csv = c.get("/correos/exportar.csv")
        self.assertEqual(csv.mimetype, "text/csv")
        self.assertIn("Hola", csv.get_data(as_text=True))

        # 4. Sin token CSRF se rechaza cualquier cambio
        self.assertEqual(c.post("/listas", data={"tipo": "bloqueado", "valor": "malo.com"}).status_code, 400)

        # 5. Un lector no puede revisar correos
        token = self._csrf(c, "/usuarios")
        c.post("/usuarios", data={"_csrf": token, "usuario": "lector1", "rol": "lector",
                                  "password": CLAVE_PRUEBA, "confirmacion": CLAVE_PRUEBA})
        lector = self.app.test_client()
        token = self._csrf(lector, "/ingresar")
        lector.post("/ingresar", data={"_csrf": token, "usuario": "lector1", "password": CLAVE_PRUEBA})
        self.assertEqual(lector.get("/").status_code, 200)
        self.assertEqual(lector.get("/analizar").status_code, 403)

    def test_zz_conectar_buzon_desde_el_panel(self):  # al final: necesita un administrador
        from unittest import mock

        from mailsentry import conexion_buzones as cb

        c = self.app.test_client()
        from mailsentry.db import Usuario
        with db.sesion() as bd:
            admin = bd.query(Usuario).filter_by(rol="admin").first()
            if admin is None:
                admin = Usuario(usuario="admin_buzones", rol="admin", password_hash="x")
                bd.add(admin)
                bd.commit()
            uid = admin.id
        with c.session_transaction() as s:
            s["uid"] = uid
        token = self._csrf(c, "/buzones")
        tmp = Path(self.tmp.name)
        guardar_original = cb.guardar
        guardar_tmp = lambda correo, clave, servidor: guardar_original(correo, clave, servidor, raiz=tmp,  # noqa: E731
                                                                 ruta_config=tmp / "config.toml")
        # Contraseña incorrecta: mensaje claro y no se guarda nada
        with mock.patch.object(cb, "probar", side_effect=cb.ErrorConexion("Correo o contraseña incorrectos.")):
            r = c.post("/buzones/conectar", data={"_csrf": token, "correo": "prueba@gmail.com", "clave": "x"},
                       follow_redirects=True)
        self.assertIn("incorrectos", r.get_data(as_text=True))
        self.assertFalse((tmp / ".env").exists())
        # Conexión correcta: se guarda la contraseña en .env y el buzón aparece en la lista
        with mock.patch.object(cb, "probar"), mock.patch.object(cb, "guardar", side_effect=guardar_tmp), \
                mock.patch("mailsentry.ingesta.vigilante.iniciar_en_segundo_plano"):
            r = c.post("/buzones/conectar", data={"_csrf": token, "correo": "prueba@gmail.com",
                                                  "clave": "abcd efgh ijkl mnop"}, follow_redirects=True)
        html = r.get_data(as_text=True)
        self.assertIn("prueba@gmail.com conectado", html)
        self.assertIn("imap.gmail.com", html)
        self.assertIn("MAILSENTRY_PASS_PRUEBA_GMAIL_COM=abcdefghijklmnop", (tmp / ".env").read_text(encoding="utf-8"))
        self.assertIn('password_env = "MAILSENTRY_PASS_PRUEBA_GMAIL_COM"', (tmp / "config.toml").read_text(encoding="utf-8"))
        self.app.extensions["mailsentry"].buzones.clear()

    def test_zz_alertas_n8n_desde_el_panel(self):
        from tests.test_alertas import _Receptor

        c = self.app.test_client()
        from mailsentry.db import Usuario
        with db.sesion() as bd:
            uid = bd.query(Usuario).filter_by(rol="admin").first().id
        with c.session_transaction() as s:
            s["uid"] = uid
        token = self._csrf(c, "/buzones")
        # Una dirección sin https se rechaza; una local de n8n se acepta y se puede probar
        r = c.post("/alertas/guardar", data={"_csrf": token, "webhook_url": "ftp://x", "nivel": "alto"}, follow_redirects=True)
        self.assertIn("https://", r.get_data(as_text=True))
        with _Receptor() as n8n:
            c.post("/alertas/guardar", data={"_csrf": token, "webhook_url": n8n.url, "nivel": "critico"})
            html = c.get("/buzones").get_data(as_text=True)
            self.assertIn(n8n.url, html)
            r = c.post("/alertas/probar", data={"_csrf": token}, follow_redirects=True)
            self.assertIn("Prueba enviada", r.get_data(as_text=True))
        self.assertEqual(n8n.recibidos[0]["evento"], "prueba")
        c.post("/alertas/guardar", data={"_csrf": token, "webhook_url": "", "nivel": "alto"})

    def test_zz_base_de_datos_desde_el_panel(self):
        from unittest import mock

        from mailsentry import config as configuracion
        from mailsentry import migracion
        from mailsentry.db import Usuario

        c = self.app.test_client()
        with db.sesion() as bd:
            uid = bd.query(Usuario).filter_by(rol="admin").first().id
        with c.session_transaction() as s:
            s["uid"] = uid
        token = self._csrf(c, "/buzones")
        tmp = Path(self.tmp.name) / "bd"
        tmp.mkdir(exist_ok=True)
        uri = "postgresql://postgres.abc:[YOUR-PASSWORD]@aws-0-sa-east-1.pooler.supabase.com:5432/postgres"
        info = {"url": "x", "version": "PostgreSQL 17", "latencia_ms": 40, "tablas": {"correos": 0, "usuarios": 0}}
        with mock.patch.object(configuracion, "RAIZ", tmp):
            # Sin contraseña: pide la contraseña y no guarda nada
            r = c.post("/basedatos/conectar", data={"_csrf": token, "uri": uri}, follow_redirects=True)
            self.assertIn("contraseña", r.get_data(as_text=True))
            self.assertFalse((tmp / ".env").exists())
            # Con contraseña y base vacía: prueba, copia y guarda en .env
            with mock.patch.object(migracion, "verificar", return_value=info),                     mock.patch.object(migracion, "copiar", return_value={"correos": 3}) as copiar:
                r = c.post("/basedatos/conectar", data={"_csrf": token, "uri": uri, "clave": "secreta123", "copiar": "1"},
                           follow_redirects=True)
            html = r.get_data(as_text=True)
            self.assertIn("Base de datos conectada", html)
            self.assertNotIn("secreta123", html)
            copiar.assert_called_once()
            env = (tmp / ".env").read_text(encoding="utf-8")
            self.assertIn("MAILSENTRY_DB_URL=postgresql+psycopg://postgres.abc:secreta123@", env)
            self.assertIn("sslmode=require", env)

    def test_login_incorrecto_y_api(self):
        c = self.app.test_client()
        token = self._csrf(c, "/ingresar") if c.get("/ingresar").status_code == 200 else None
        if token:
            r = c.post("/ingresar", data={"_csrf": token, "usuario": "nadie", "password": "x"})
            self.assertIn("incorrectos", r.get_data(as_text=True))
        api = self.app.test_client()
        self.assertEqual(api.get("/api/v1/estadisticas").status_code, 401)
        cab = {"Authorization": "Bearer token-prueba-123456"}
        r = api.post("/api/v1/analizar", data=casos.ATAQUES[2][1], headers=cab)
        self.assertIn(r.status_code, (200, 201))
        self.assertNotEqual(r.get_json()["correo"]["veredicto"], "legitimo")
        self.assertEqual(api.get("/api/v1/estadisticas?periodo=7d", headers=cab).status_code, 200)


if __name__ == "__main__":
    unittest.main()
