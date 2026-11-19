"""Separación de accesos: lo que escribe la secretaría (o la AC raíz) no lo puede borrar
ni sobrescribir el estudiante. Se emula con permisos de solo lectura del sistema."""
import hashlib
import os
import unittest

from plancipher.secretaria import Secretaria
from plancipher.storage import JsonStore, is_protected
from tests.helpers import PASS_A, ROOT_PASS, SystemCase, TmpDirCase

SECRETARIA_ZONE = ("pki/root_cert.pem", "pki/root_key.json", "pki/crl.pem",
                   "secretaria/cert.pem", "secretaria/signing_key.json",
                   "secretaria/plan.json", "secretaria/records.json", "secretaria/matriculas.json")
STUDENT_ZONE = ("users.json", "planning.json")

IS_ROOT = hasattr(os, "geteuid") and os.geteuid() == 0  # root ignora los permisos en Linux


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class StoreTests(TmpDirCase):
    def test_protected_store_is_read_only_but_its_owner_can_update_it(self):
        store = JsonStore(self.dir / "zona" / "x.json", protect=True)
        store.save({"v": 1})
        self.assertTrue(is_protected(store.path))
        store.save({"v": 2})  # la secretaría sí puede volver a escribir
        self.assertEqual(store.load(None), {"v": 2})
        self.assertTrue(is_protected(store.path))

    def test_normal_store_stays_writable(self):
        store = JsonStore(self.dir / "x.json")
        store.save({"v": 1})
        self.assertFalse(is_protected(store.path))


class AccessSeparationTests(SystemCase):
    def setUp(self):
        super().setUp()
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 8.5, "2026-1C")
        self.planning.add(self.alice, "2026-11-20", "09:00", "Clase de Cripto")

    def test_every_secretaria_file_is_read_only_and_student_files_are_not(self):
        for rel in SECRETARIA_ZONE:
            self.assertTrue(is_protected(self.dir / rel), rel)
        for rel in STUDENT_ZONE:
            self.assertFalse(is_protected(self.dir / rel), rel)

    @unittest.skipIf(IS_ROOT, "root ignora los permisos")
    def test_student_cannot_delete_secretaria_files(self):
        for rel in SECRETARIA_ZONE:
            with self.assertRaises(PermissionError, msg=rel):
                os.remove(self.dir / rel)
            self.assertTrue((self.dir / rel).exists(), rel)

    @unittest.skipIf(IS_ROOT, "root ignora los permisos")
    def test_student_cannot_overwrite_secretaria_files(self):
        for rel in ("secretaria/records.json", "secretaria/plan.json", "secretaria/matriculas.json"):
            with self.assertRaises(PermissionError, msg=rel):
                with open(self.dir / rel, "w") as fh:
                    fh.write("[]")

    def test_student_operations_never_touch_the_secretaria_zone(self):
        before = {rel: digest(self.dir / rel) for rel in SECRETARIA_ZONE}
        session = self.users.login("alice", PASS_A)
        self.planning.add(session, "2026-11-21", "10:00", "Tutoría")
        self.acad.read_grades(session, self.anchor)
        self.acad.load_plan(self.anchor)
        self.users.register("dave", "clave-del-cuarto-44")
        self.users.login("dave", "clave-del-cuarto-44")
        self.assertEqual({rel: digest(self.dir / rel) for rel in SECRETARIA_ZONE}, before)

    def test_secretaria_can_still_write_and_files_stay_protected(self):
        self.acad.issue_grade(self.sec, "alice", "REDES", 6.0, "2026-1C")
        self.acad.enroll(self.sec, "bob")
        Secretaria.revoke(self.dir, ROOT_PASS)  # la raíz reescribe la CRL protegida
        for rel in SECRETARIA_ZONE:
            self.assertTrue(is_protected(self.dir / rel), rel)


if __name__ == "__main__":
    unittest.main()
