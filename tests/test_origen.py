"""Pruebas del rastreo de origen (cabeceras) y de la geolocalización por IP."""

from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mailsentry import geoip, origen, paises  # noqa: E402
from mailsentry.parser import parsear  # noqa: E402

CUERPO = "Subject: x\nMIME-Version: 1.0\nContent-Type: text/plain\n\nhola\n"


def correo(cabeceras: str, de: str = "Alguien <a@ejemplo-externo.com>") -> object:
    return parsear(f"{cabeceras}From: {de}\nTo: b@empresa.pe\n{CUERPO}".encode())


class TestOrigen(unittest.TestCase):
    def test_gmail_por_received_spf(self):
        c = correo(
            "Received: by 2002:a05:6a10:1234 with SMTP id x; Wed, 7 Oct 2026 10:00:00 -0700\n"
            "Received: from mail-sor-f41.google.com (mail-sor-f41.google.com. [209.85.220.41])\n"
            "        by mx.google.com with SMTPS id y; Wed, 7 Oct 2026 10:00:00 -0700\n"
            "Received-SPF: pass (google.com: domain of jefe@gmail.com designates 209.85.220.41 as permitted sender) "
            "client-ip=209.85.220.41;\n", de="Jefe <jefe@gmail.com>")
        o = origen.determinar(c)
        self.assertEqual(o.ip, "209.85.220.41")
        self.assertEqual(o.metodo, "spf")
        self.assertEqual(o.proveedor, "Google (Gmail)")

    def test_microsoft_sender_ip(self):
        c = correo(
            "Authentication-Results: spf=pass (sender IP is 40.107.22.85) smtp.mailfrom=proveedor.com; dkim=pass\n"
            "Received: from EUR05-AM6-obe.outbound.protection.outlook.com (mail-am6eur05on2085.outbound."
            "protection.outlook.com [40.107.22.85]) by BN8NAM12FT010.mail.protection.outlook.com; Wed, 7 Oct 2026\n")
        o = origen.determinar(c)
        self.assertEqual((o.ip, o.metodo, o.proveedor), ("40.107.22.85", "autenticacion", "Microsoft (Outlook)"))

    def test_salta_saltos_internos(self):
        c = correo(
            "Received: from filtro.empresa.pe ([10.0.0.5]) by buzon.empresa.pe with LMTP; Wed, 7 Oct 2026\n"
            "Received: from vps123.hosting-barato.ru (vps123.hosting-barato.ru [45.33.32.156]) by mx.empresa.pe; "
            "Wed, 7 Oct 2026\n"
            "Received: from [192.168.1.20] (unknown [8.8.8.8]) by vps123.hosting-barato.ru; Wed, 7 Oct 2026\n")
        o = origen.determinar(c)
        self.assertEqual(o.ip, "45.33.32.156")  # el salto registrado por el servidor de la empresa
        self.assertEqual(o.servidor, "vps123.hosting-barato.ru")
        self.assertIsNone(o.proveedor)

    def test_sin_cabeceras(self):
        o = origen.determinar(correo(""))
        self.assertIsNone(o.ip)

    def test_documentacion_solo_en_demo(self):
        c = correo("Received: from mail.x.com (mail.x.com [203.0.113.7]) by mx.empresa.pe; Wed, 7 Oct 2026\n")
        self.assertIsNone(origen.determinar(c).ip)
        self.assertEqual(origen.determinar(c, permitir_documentacion=True).ip, "203.0.113.7")


class TestGeoIP(unittest.TestCase):
    def test_busqueda_v4_v6(self):
        filas = [("45.33.0.0", "45.33.255.255", "US"), ("1.0.0.0", "1.0.0.255", "AU"),
                 ("190.0.0.0", "190.0.255.255", "PE"), ("2a02:6b8::", "2a02:6b8:ffff:ffff:ffff:ffff:ffff:ffff", "RU")]
        v4, v6 = geoip.convertir(filas)
        with tempfile.TemporaryDirectory() as tmp:
            ruta = Path(tmp, "ip-pais.bin")
            geoip.guardar(ruta, v4, v6)
            base = geoip.cargar(ruta)
            self.assertEqual(base.rangos, 4)
            self.assertEqual(base.pais("45.33.32.156"), "US")
            self.assertEqual(base.pais("190.0.0.0"), "PE")  # límite inferior
            self.assertEqual(base.pais("190.0.255.255"), "PE")  # límite superior
            self.assertIsNone(base.pais("190.1.0.0"))
            self.assertEqual(base.pais("2a02:6b8::1"), "RU")
            self.assertIsNone(base.pais("no-es-ip"))

    def test_paises(self):
        self.assertEqual(paises.nombre("pe"), "Perú")
        self.assertEqual(paises.region("NG"), "África")
        self.assertEqual(paises.region("XX"), "Otras")
        self.assertIsNotNone(paises.coordenadas("RU"))


if __name__ == "__main__":
    unittest.main()
