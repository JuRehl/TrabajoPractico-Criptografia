"""Utilidades compartidas: parámetros scrypt rápidos SOLO para tests."""
import json
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

    def rewrite_json(self, name, fn):
        """Aplica `fn` al JSON de un fichero de datos (simula un atacante con acceso a disco)."""
        path = self.dir / name
        data = json.loads(path.read_text())
        fn(data)
        path.write_text(json.dumps(data))


class SystemCase(TmpDirCase):
    """Sistema completo: secretaría, plan publicado, alice y bob matriculados."""

    def setUp(self):
        super().setUp()
        self.clock = FakeClock()
        self.users = UserService(JsonStore(self.dir / "users.json"), FAST, clock=self.clock)
        Secretaria.init(self.dir, SEC_PASS, FAST)
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
