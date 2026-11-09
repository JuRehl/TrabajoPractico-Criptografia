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
PASSWORD = "clave-del-estudiante-99"


class CliTests(TmpDirCase):
    def run_cli(self, *args, password=PASSWORD, debug=False):
        env = {**os.environ, "PYTHONPATH": str(ROOT), "PLANCIPHER_DATA": str(self.dir),
               "PLANCIPHER_SECRETARIA_PASS": SEC_PASS, "PLANCIPHER_PASSWORD": password}
        cmd = [sys.executable, "-m", "plancipher"] + (["--debug"] if debug else []) + list(args)
        return subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True, timeout=120)

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
        for secret in (PASSWORD, SEC_PASS):  # nunca aparecen secretos, ni siquiera con --debug
            self.assertNotIn(secret, r.stdout + r.stderr)

        self.assertEqual(self.run_cli("grades", "alice", password="contrasena-equivocada-1").returncode, 1)

        path = self.dir / "records.json"
        data = json.loads(path.read_text())
        data[0]["header"]["seq"] = 7
        path.write_text(json.dumps(data))
        r = self.run_cli("grades", "alice")
        self.assertEqual(r.returncode, 3)
        self.assertIn("RECHAZADO", r.stderr)
        self.assertNotIn("CRIPTO", r.stdout)


if __name__ == "__main__":
    unittest.main()
