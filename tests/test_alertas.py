"""Alertas por webhook: el cuerpo trae los datos separados para n8n y el texto para Teams/Slack."""

from __future__ import annotations

import json
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from types import SimpleNamespace

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mailsentry import alertas  # noqa: E402
from mailsentry.config import Config  # noqa: E402


class _Receptor:
    """Servidor local que hace de n8n: guarda lo que recibe."""

    def __enter__(self):
        recibidos = self.recibidos = []

        class Manejador(BaseHTTPRequestHandler):
            def do_POST(self):
                recibidos.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
                self.send_response(200)
                self.end_headers()

            def log_message(self, *args):
                pass

        self.servidor = HTTPServer(("127.0.0.1", 0), Manejador)
        threading.Thread(target=self.servidor.serve_forever, daemon=True).start()
        self.url = f"http://127.0.0.1:{self.servidor.server_port}/webhook/mailsentry"
        return self

    def __exit__(self, *args):
        self.servidor.shutdown()


class TestAlertas(unittest.TestCase):
    def test_phishing_llega_con_campos_separados(self):
        correo = SimpleNamespace(id=7, nivel_riesgo="critico", puntaje=92, categoria="bec",
                                 remitente_nombre="Carlos Mendoza", remitente_email="carlos@gmail.com",
                                 destinatario_principal="finanzas@empresa.pe", asunto="Transferencia urgente",
                                 buzon="Finanzas")
        with _Receptor() as n8n:
            alertas.notificar(correo, Config(empresa_nombre="Textiles", webhook_url=n8n.url, alerta_nivel_minimo="alto"))
            for _ in range(50):
                if n8n.recibidos:
                    break
                time.sleep(0.1)
        self.assertEqual(len(n8n.recibidos), 1)
        r = n8n.recibidos[0]
        self.assertEqual((r["evento"], r["nivel"], r["puntaje"], r["correo_id"]), ("phishing_detectado", "critico", 92, 7))
        self.assertEqual(r["remitente_email"], "carlos@gmail.com")
        self.assertIn("Transferencia urgente", r["text"])  # el texto para Teams/Slack sigue ahí

    def test_bajo_el_nivel_minimo_no_avisa(self):
        correo = SimpleNamespace(id=1, nivel_riesgo="medio", puntaje=40, categoria="otro")
        with _Receptor() as n8n:
            alertas.notificar(correo, Config(webhook_url=n8n.url, alerta_nivel_minimo="alto"))
            time.sleep(0.4)
        self.assertEqual(n8n.recibidos, [])

    def test_prueba_de_conexion(self):
        self.assertFalse(alertas.enviar_prueba(Config())[0])
        with _Receptor() as n8n:
            ok, _ = alertas.enviar_prueba(Config(webhook_url=n8n.url))
        self.assertTrue(ok)
        self.assertEqual(n8n.recibidos[0]["evento"], "prueba")
        self.assertFalse(alertas.enviar_prueba(Config(webhook_url="http://127.0.0.1:9/x"))[0])


if __name__ == "__main__":
    unittest.main()
