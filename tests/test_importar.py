"""Pruebas de la importación masiva de personal."""

from __future__ import annotations

import io
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mailsentry.importar import leer  # noqa: E402


class TestImportar(unittest.TestCase):
    def test_excel_con_titulos_y_columnas_desordenadas(self):
        from openpyxl import Workbook

        libro = Workbook()
        hoja = libro.active
        hoja.append(["Correo electrónico", "Nombre y apellido", "Área", "¿Directivo?", "Puesto"])
        hoja.append(["ANA.TORRES@empresa.pe", "Ana Torres", "Gerencia", "Sí", "Gerente General"])
        hoja.append(["luis@empresa.pe", "Luis Pérez", "Finanzas", "no", "Contador"])
        hoja.append([None, None, None, None, None])
        buffer = io.BytesIO()
        libro.save(buffer)
        r = leer("personal.xlsx", buffer.getvalue())
        self.assertEqual([p.email for p in r.personas], ["ana.torres@empresa.pe", "luis@empresa.pe"])
        self.assertTrue(r.personas[0].es_vip)
        self.assertFalse(r.personas[1].es_vip)
        self.assertEqual(r.personas[0].cargo, "Gerente General")
        self.assertEqual(r.personas[1].departamento, "Finanzas")

    def test_csv_de_excel_en_windows(self):
        # Excel en español guarda CSV con ";" y codificación latin-1
        datos = "nombre;correo;cargo;area;directivo\nJosé Núñez;jose@empresa.pe;Jefe;Ventas;x\n".encode("latin-1")
        r = leer("lista.csv", datos)
        self.assertEqual(r.personas[0].nombre, "José Núñez")
        self.assertTrue(r.personas[0].es_vip)

    def test_texto_pegado_sin_titulos_y_errores(self):
        texto = ("Ana Torres\tana@empresa.pe\tGerente\tGerencia\tsí\n"
                 "Sin Correo\t\tAsistente\tVentas\tno\n"
                 "Ana Repetida\tana@empresa.pe\t\t\t\n"
                 "Rosa Quispe\trosa@empresa.pe\tCoordinadora\tLogística\t\n")
        r = leer(texto=texto)
        self.assertEqual([p.email for p in r.personas], ["ana@empresa.pe", "rosa@empresa.pe"])
        self.assertEqual(len(r.omitidas), 2)

    def test_vacio(self):
        self.assertEqual(leer(texto="   \n").personas, [])


if __name__ == "__main__":
    unittest.main()
