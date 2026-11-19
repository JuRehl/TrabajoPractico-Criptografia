"""Utilidades compartidas: parámetros scrypt rápidos SOLO para tests."""
import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from plancipher.academic import AcademicService
from plancipher.auth import UserService
from plancipher.crypto.kdf import KdfParams
from plancipher.planning import PlanningService
from plancipher.secretaria import Secretaria, TrustAnchor
from plancipher.storage import JsonStore

FAST = KdfParams(n=2**10, r=8, p=1)  # los valores reales (2^17) están en KdfParams por defecto
PASS_A = "contrasena-de-prueba-A1"
PASS_B = "contrasena-de-prueba-B2"
SEC_PASS = "passphrase-secretaria-123"
ROOT_PASS = "passphrase-ac-raiz-456"
PLAN = {"degree": "Test", "subjects": [
    {"code": "CRIPTO", "name": "Criptografia", "credits": 6},
    {"code": "REDES", "name": "Redes", "credits": 6},
    {"code": "BBDD", "name": "Bases de datos", "credits": 6}]}


class FakeClock:
    def __init__(self):
        self.t = 1_000_000.0

    def __call__(self):
        return self.t


class TmpDirCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dir = Path(self._tmp.name)

    def _bypass(self, path):
        """El atacante se salta los permisos del sistema (solo lectura) de la zona de la secretaría."""
        for d in (path.parent, path.parent.parent):
            if d.exists():
                os.chmod(d, stat.S_IRWXU)
        if path.exists():
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def rewrite_json(self, name, fn):
        """Aplica `fn` al JSON de un fichero de datos (simula un atacante con acceso a disco
        que además se salta la protección de solo lectura)."""
        path = self.dir / name
        self._bypass(path)
        data = json.loads(path.read_text())
        fn(data)
        path.write_text(json.dumps(data))

    def force_write(self, name, content):
        path = self.dir / name
        self._bypass(path)
        (path.write_bytes if isinstance(content, bytes) else path.write_text)(content)

    def force_delete(self, name):
        path = self.dir / name
        self._bypass(path)
        path.unlink()


class SystemCase(TmpDirCase):
    """Sistema completo: secretaría, plan publicado, alice y bob matriculados."""

    def setUp(self):
        super().setUp()
        self.clock = FakeClock()
        self.users = UserService(JsonStore(self.dir / "users.json"), FAST, clock=self.clock)
        Secretaria.init(self.dir, SEC_PASS, FAST, root_passphrase=ROOT_PASS)
        self.sec = Secretaria.unlock(self.dir, SEC_PASS)
        self.anchor = TrustAnchor.load(self.dir)
        self.acad = AcademicService(self.dir, self.users)
        self.planning = PlanningService(JsonStore(self.dir / "planning.json"))
        self.acad.publish_plan(self.sec, PLAN)
        for name, pw in (("alice", PASS_A), ("bob", PASS_B)):
            self.users.register(name, pw)
            self.acad.enroll(self.sec, name)
        self.alice = self.users.login("alice", PASS_A)
        self.bob = self.users.login("bob", PASS_B)
