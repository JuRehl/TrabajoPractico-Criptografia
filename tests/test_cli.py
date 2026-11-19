"""Prueba de extremo a extremo de la CLI con parámetros scrypt REALES (más lenta)."""
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

from tests.helpers import TmpDirCase

ROOT = Path(__file__).resolve().parent.parent
SEC_PASS = "frase-secreta-larga-1"
ROOT_PASS = "frase-ac-raiz-larga-2"
PASSWORD = "clave-del-estudiante-99"


class CliTests(TmpDirCase):
    def run_cli(self, *args, password=PASSWORD, debug=False, **extra_env):
        env = {**os.environ, "PYTHONPATH": str(ROOT), "PYTHONIOENCODING": "utf-8", "PLANCIPHER_DATA": str(self.dir),
               "PLANCIPHER_SECRETARIA_PASS": SEC_PASS, "PLANCIPHER_ROOT_PASS": ROOT_PASS, "PLANCIPHER_PASSWORD": password,
               **extra_env}
        cmd = [sys.executable, "-m", "plancipher"] + (["--debug"] if debug else []) + list(args)
        return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, encoding="utf-8", timeout=120)

    def test_full_flow_and_fail_secure(self):
        self.assertEqual(self.run_cli("init-secretaria").returncode, 0)
        self.assertEqual(self.run_cli("register", "alice").returncode, 0)
        self.assertEqual(self.run_cli("enroll", "alice").returncode, 0)
        r = self.run_cli("issue-grade", "alice", "--subject", "CRIPTO", "--grade", "8", "--term", "2026-1C")
        self.assertEqual(r.returncode, 0, r.stderr)

        r = self.run_cli("grades", "alice", debug=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("CRIPTO", r.stdout)
        self.assertIn("firma verificada", r.stdout)
        for secret in (PASSWORD, SEC_PASS, ROOT_PASS):  # nunca aparecen secretos, ni siquiera con --debug
            self.assertNotIn(secret, r.stdout + r.stderr)

        self.assertEqual(self.run_cli("grades", "alice", password="contrasena-equivocada-1").returncode, 1)

        self.rewrite_json("secretaria/records.json", lambda d: d[0]["header"].update(seq=7))
        r = self.run_cli("grades", "alice")
        self.assertEqual(r.returncode, 3)
        self.assertIn("RECHAZADO", r.stderr)
        self.assertNotIn("CRIPTO", r.stdout)

        r = self.run_cli("revoke-secretaria")
        self.assertEqual(r.returncode, 0, r.stderr)
        r = self.run_cli("pending", "alice")  # el certificado revocado invalida todo lo firmado
        self.assertEqual(r.returncode, 3)
        self.assertIn("REVOCADO", r.stderr)


    def test_planning_pending_and_controlled_errors(self):
        r = self.run_cli("grades", "alice")  # sin secretaría: error controlado, no traza
        self.assertEqual(r.returncode, 1)
        self.assertNotIn("Traceback", r.stderr)
        self.assertIn("--version", self.run_cli("--help").stdout)
        self.assertIn("1.0.0", self.run_cli("--version").stdout)

        r = self.run_cli("init-secretaria")
        self.assertIn("AC raíz", r.stdout)
        fp = r.stdout.split("ancla de confianza):")[1].split()[0]
        self.assertEqual(self.run_cli("register", "alice").returncode, 0)
        self.assertEqual(self.run_cli("register", "alice").returncode, 1)  # duplicado

        self.assertEqual(self.run_cli("add-planning", "alice", "--date", "2026-11-11", "--time", "12:00",
                                      "--text", "Redes").returncode, 0)
        self.assertEqual(self.run_cli("add-planning", "alice", "--date", "2026-11-10", "--time", "09:00",
                                      "--text", "Cripto").returncode, 0)
        self.assertEqual(self.run_cli("add-planning", "alice", "--date", "10/11/2026", "--time", "09:00",
                                      "--text", "x").returncode, 1)
        r = self.run_cli("planning", "alice")
        self.assertEqual(r.stdout.splitlines(), ["2026-11-10 09:00  Cripto", "2026-11-11 12:00  Redes"])

        self.assertEqual(self.run_cli("issue-grade", "alice", "--subject", "cripto", "--grade", "7",
                                      "--term", "2026-1C").returncode, 1)  # aún sin matrícula firmada
        self.assertEqual(self.run_cli("enroll", "alice").returncode, 0)
        r = self.run_cli("issue-grade", "alice", "--subject", "cripto", "--grade", "7", "--term", "2026-1C")
        self.assertEqual(r.returncode, 0, r.stderr)  # el código de asignatura se pasa a mayúsculas
        r = self.run_cli("--trust-fingerprint", fp, "pending", "alice")
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertNotIn("CRIPTO", r.stdout)
        self.assertIn("sin cursar", r.stdout)
        self.assertEqual(self.run_cli("--trust-fingerprint", "00" * 32, "pending", "alice").returncode, 3)
    def test_password_recovery_keeps_planning(self):
        r = self.run_cli("register", "alice")
        code = r.stdout.split("no se volverá a mostrar):")[1].split()[0]
        self.assertRegex(code, r"^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$")
        self.assertEqual(self.run_cli("add-planning", "alice", "--date", "2026-11-20", "--time", "09:00",
                                      "--text", "Clase de Cripto").returncode, 0)
        new = "otra-clave-del-estudiante-77"
        r = self.run_cli("recover-password", "alice", PLANCIPHER_RECOVERY_CODE="AAAA-" + code[5:],
                         PLANCIPHER_NEW_PASSWORD=new)
        self.assertEqual(r.returncode, 1)  # código incorrecto: error controlado, mensaje genérico
        self.assertIn("código de recuperación incorrectos", r.stderr)
        r = self.run_cli("recover-password", "alice", PLANCIPHER_RECOVERY_CODE=code, PLANCIPHER_NEW_PASSWORD=new)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertIn("Código de recuperación nuevo", r.stdout)
        self.assertEqual(self.run_cli("planning", "alice").returncode, 1)  # contraseña antigua
        r = self.run_cli("planning", "alice", password=new)
        self.assertEqual((r.returncode, r.stdout.strip()), (0, "2026-11-20 09:00  Clase de Cripto"))


if __name__ == "__main__":
    unittest.main()
