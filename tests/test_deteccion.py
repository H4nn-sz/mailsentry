"""Pruebas del motor de detección. Ejecutar con:  python -m unittest discover tests"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mailsentry.deteccion import analizar  # noqa: E402
from mailsentry.deteccion.dominios import (  # noqa: E402
    dominio_registrable,
    marca_en_subdominio_o_ruta,
    parecido_a_marca,
    tecnica_parecido,
)
from mailsentry.parser import parsear  # noqa: E402
from tests import casos  # noqa: E402


class TestDominios(unittest.TestCase):
    def test_dominio_registrable(self):
        self.assertEqual(dominio_registrable("mail.sunat.gob.pe"), "sunat.gob.pe")
        self.assertEqual(dominio_registrable("www.viabcp.com"), "viabcp.com")
        self.assertEqual(dominio_registrable("a.b.c.ejemplo.com.pe"), "ejemplo.com.pe")

    def test_parecidos(self):
        protegido = "textilesdelsur.com.pe"
        for falso in ("textilesdeisur.com.pe", "textilesdelsur.com", "textiles-delsur.com.pe",
                      "textilesdelsur-pe.com", "textllesdelsur.com.pe"):
            self.assertIsNotNone(tecnica_parecido(falso, protegido), falso)
        for legitimo in ("textilesdelsur.com.pe", "mail.textilesdelsur.com.pe", "hiladosperuanos.com.pe"):
            self.assertIsNone(tecnica_parecido(legitimo, protegido), legitimo)

    def test_marcas(self):
        self.assertEqual(parecido_a_marca("viabcp-seguridad.xyz")[0], "BCP")
        self.assertEqual(parecido_a_marca("micros0ft-office.com")[0], "Microsoft 365")
        self.assertEqual(parecido_a_marca("gmai1.com")[0], "Google")
        self.assertEqual(parecido_a_marca("paypa1.com")[0], "PayPal")
        self.assertIsNone(parecido_a_marca("viabcp.com"))
        self.assertIsNone(parecido_a_marca("notificacionesbcp.com.pe"))
        # Palabras comunes a una letra de una marca no son imitaciones (falso positivo encontrado en pruebas)
        self.assertIsNone(parecido_a_marca("mail-sender.net"))
        self.assertIsNone(parecido_a_marca("mail.com"))
        self.assertEqual(marca_en_subdominio_o_ruta("https://viabcp.com.seguro-web.xyz/a"), "BCP")


class TestCasos(unittest.TestCase):
    def setUp(self):
        self.ctx = casos.contexto()

    def _veredicto(self, crudo: bytes) -> str:
        return analizar(parsear(crudo), self.ctx).veredicto

    def test_ataques_detectados(self):
        for nombre, crudo in casos.ATAQUES:
            with self.subTest(nombre):
                self.assertNotEqual(self._veredicto(crudo), "legitimo")

    def test_legitimos_no_marcados(self):
        for nombre, crudo in casos.LEGITIMOS:
            with self.subTest(nombre):
                self.assertEqual(self._veredicto(crudo), "legitimo")

    def test_casos_a_revision(self):
        for nombre, crudo in casos.A_REVISION:
            with self.subTest(nombre):
                self.assertEqual(self._veredicto(crudo), "sospechoso")

    @unittest.expectedFailure
    def test_limitacion_cuentas_comprometidas(self):
        """Límite conocido: proveedor real hackeado que envía un enlace. Documentado en el README."""
        for _, crudo in casos.LIMITACIONES:
            self.assertNotEqual(self._veredicto(crudo), "legitimo")


class TestSimulacion(unittest.TestCase):
    """Empresa ficticia durante 60 días: detección y falsos positivos sobre el motor completo."""

    def test_simulacion(self):
        import tempfile

        from mailsentry import db
        from mailsentry.config import Config
        from mailsentry.simulacion import simular

        with tempfile.TemporaryDirectory() as tmp:
            config = Config(db_url=f"sqlite:///{Path(tmp, 'sim.db').as_posix()}", peso_ml=0, secret_key="x")
            informe = simular(config, dias=60, semilla=11)
            db._motor.dispose()  # libera el archivo para poder borrarlo en Windows
        self.assertGreater(informe.total, 200)
        self.assertGreaterEqual(informe.deteccion, 0.95)
        self.assertEqual(informe.fp, 0)


if __name__ == "__main__":
    unittest.main()
