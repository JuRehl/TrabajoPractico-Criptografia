"""Prueba funcional de la interfaz web (Streamlit AppTest, sin navegador).
Se omite si Streamlit no está instalado (requirements-web.txt es opcional)."""
import os
import unittest
from pathlib import Path
from unittest import mock

from tests.helpers import TmpDirCase

try:
    from streamlit.testing.v1 import AppTest
except ImportError:  # pragma: no cover
    AppTest = None

APP = str(Path(__file__).resolve().parent.parent / "app.py")
ROOT_PASS, SEC_PASS, PASSWORD = "raiz-frase-larga-77", "secre-frase-larga-88", "clave-del-estudiante-99"


@unittest.skipIf(AppTest is None, "Streamlit no instalado")
class WebTests(TmpDirCase):
    def setUp(self):
        super().setUp()
        env = mock.patch.dict(os.environ, {"PLANCIPHER_DATA": str(self.dir)})
        env.start()
        self.addCleanup(env.stop)
        self.at = AppTest.from_file(APP, default_timeout=120).run()

    def fill(self, **values):
        inputs = {t.label: t for t in self.at.text_input}
        for label, value in values.items():
            inputs[label].input(value)

    def click(self, label):
        next(b for b in self.at.button if b.label == label).click().run()
        self.assertEqual([e.value for e in self.at.error], [], label)

    def test_full_web_flow(self):
        self.fill(**{"Passphrase de la AC raíz (mín. 12 caracteres)": ROOT_PASS,
                     "Repite la passphrase de la AC raíz": ROOT_PASS,
                     "Passphrase de la secretaría (mín. 12, distinta)": SEC_PASS,
                     "Repite la passphrase de la secretaría": SEC_PASS})
        self.click("Inicializar PKI y secretaría")
        self.assertIn("PKI creada", self.at.success[0].value)

        self.fill(**{"Usuario nuevo": "alice", "Contraseña (mín. 12 caracteres)": PASSWORD,
                     "Repite la contraseña": PASSWORD})
        self.click("Registrarse")

        self.fill(**{"Passphrase de la secretaría": SEC_PASS})
        self.click("Desbloquear")
        self.assertIn("cadena y CRL verificadas", " ".join(c.value for c in self.at.caption))
        self.click("Emitir certificado")
        self.at.number_input[0].set_value(8.5)
        self.click("Emitir (cifrada y firmada)")
        self.assertIn("emitida para alice", self.at.success[0].value)

        self.fill(Usuario="alice", **{"Contraseña": PASSWORD})
        self.click("Entrar")
        self.fill(Actividad="Clase de Cripto")
        self.click("Añadir (se cifra con AES-256-GCM)")

        tables = [t.value for t in self.at.table]
        planning, notes, pending = tables[0], tables[1], tables[2]
        self.assertEqual(list(planning["Actividad"]), ["Clase de Cripto"])
        self.assertEqual((notes["Asignatura"][0], notes["Nota"][0]), ("CRIPTO", 8.5))
        self.assertNotIn("CRIPTO", list(pending["Código"]))

    def test_password_recovery_button(self):
        self.fill(**{"Usuario nuevo": "alice", "Contraseña (mín. 12 caracteres)": PASSWORD,
                     "Repite la contraseña": PASSWORD})
        self.click("Registrarse")
        code = self.at.success[0].value.split("`")[1]
        new = "otra-clave-del-estudiante-77"
        self.fill(**{"Usuario a recuperar": "alice", "Código de recuperación": code,
                     "Contraseña nueva (mín. 12 caracteres)": new, "Repite la contraseña nueva": new})
        self.click("Recuperar contraseña")
        self.assertIn("Contraseña cambiada", self.at.success[0].value)
        self.fill(Usuario="alice", **{"Contraseña": new})
        next(b for b in self.at.button if b.label == "Entrar").click().run()  # sin PKI, Notas avisa: es esperado
        self.assertIn("Sesión de **alice**", " ".join(c.value for c in self.at.caption))

    def test_mismatched_passphrases_show_error(self):
        self.fill(**{"Passphrase de la AC raíz (mín. 12 caracteres)": ROOT_PASS,
                     "Repite la passphrase de la AC raíz": "otra-cosa-distinta",
                     "Passphrase de la secretaría (mín. 12, distinta)": SEC_PASS,
                     "Repite la passphrase de la secretaría": SEC_PASS})
        next(b for b in self.at.button if b.label == "Inicializar PKI y secretaría").click().run()
        self.assertIn("no coinciden", self.at.error[0].value)
        self.assertFalse((self.dir / "pki").exists())


if __name__ == "__main__":
    unittest.main()
