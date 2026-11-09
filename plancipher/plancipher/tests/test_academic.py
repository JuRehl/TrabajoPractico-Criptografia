import copy
import json
import tempfile
import unittest
from pathlib import Path

from plancipher.academic import pending_subjects
from plancipher.crypto.encoding import b64d, b64e
from plancipher.errors import (AuthenticationError, IntegrityError, ReplayError, ValidationError)
from plancipher.secretaria import Secretaria, TrustAnchor
from tests.helpers import FAST, PASS_A, SEC_PASS, SystemCase, TmpDirCase


def flip_b64(text: str, index: int = 20) -> str:
    raw = bytearray(b64d(text))
    raw[index] ^= 0x01
    return b64e(bytes(raw))


class GradeTests(SystemCase):
    def test_issue_and_read_roundtrip(self):
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 8.46, "2026-1C")
        view = self.acad.read_grades(self.alice, self.anchor)
        self.assertEqual([(g["subject"], g["grade"]) for g in view.grades], [("CRIPTO", 8.5)])
        self.assertEqual(view.rejected, [])

    def test_grades_are_encrypted_on_disk(self):
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 9.0, "2026-1C")
        raw = (self.dir / "records.json").read_text()
        self.assertNotIn("CRIPTO", raw)
        self.assertNotIn("9.0", raw)

    def test_student_cannot_read_other_students_grades(self):
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 9.0, "2026-1C")
        self.assertEqual(self.acad.read_grades(self.bob, self.anchor).grades, [])

    def test_latest_grade_wins_and_pending_list(self):
        self.acad.issue_grade(self.sec, "alice", "REDES", 3.0, "2026-1C")
        self.acad.issue_grade(self.sec, "alice", "REDES", 6.0, "2026-2C")  # recuperación
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 4.5, "2026-1C")
        view = self.acad.read_grades(self.alice, self.anchor)
        pend = {p["code"]: p["state"] for p in pending_subjects(self.acad.load_plan(self.anchor), view.grades)}
        self.assertEqual(pend, {"CRIPTO": "suspensa", "BBDD": "sin cursar"})

    # --- negativas: manipulación de registros ---------------------------
    def _issue_and_mutate(self, mutate):
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 9.0, "2026-1C")
        self.rewrite_json("records.json", lambda d: mutate(d[0]))
        return self.acad.read_grades(self.alice, self.anchor)

    def test_modified_ciphertext_rejected(self):
        view = self._issue_and_mutate(lambda r: r.update(ct=flip_b64(r["ct"])))
        self.assertEqual(view.grades, [])
        self.assertEqual(len(view.rejected), 1)

    def test_modified_signature_rejected(self):
        view = self._issue_and_mutate(lambda r: r.update(signature=flip_b64(r["signature"], 10)))
        self.assertEqual((view.grades, len(view.rejected)), ([], 1))

    def test_modified_sealed_key_rejected(self):
        view = self._issue_and_mutate(lambda r: r.update(sealed_cek=flip_b64(r["sealed_cek"], 40)))
        self.assertEqual((view.grades, len(view.rejected)), ([], 1))

    def test_modified_header_seq_rejected(self):
        view = self._issue_and_mutate(lambda r: r["header"].update(seq=99))
        self.assertEqual((view.grades, len(view.rejected)), ([], 1))

    def test_record_relabelled_for_another_student_rejected(self):
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 9.0, "2026-1C")
        self.rewrite_json("records.json", lambda d: d[0]["header"].update(student="bob"))
        view = self.acad.read_grades(self.bob, self.anchor)
        self.assertEqual((view.grades, len(view.rejected)), ([], 1))

    def test_record_forged_by_a_different_secretaria_rejected(self):
        with tempfile.TemporaryDirectory() as other_dir:
            Secretaria.init(Path(other_dir), SEC_PASS, FAST)
            rogue = Secretaria.unlock(Path(other_dir), SEC_PASS)
            rogue_acad = type(self.acad)(Path(other_dir), self.users)
            rogue_acad.publish_plan(rogue, {"degree": "x", "subjects": [{"code": "CRIPTO", "name": "x", "credits": 6}]})
            rogue_acad.enroll(rogue, "alice")  # misma clave pública del estudiante
            rogue_acad.issue_grade(rogue, "alice", "CRIPTO", 10.0, "2026-1C")
            forged = json.loads((Path(other_dir) / "records.json").read_text())
        (self.dir / "records.json").write_text(json.dumps(forged))
        view = self.acad.read_grades(self.alice, self.anchor)  # el ancla es la secretaría REAL
        self.assertEqual((view.grades, len(view.rejected)), ([], 1))

    def test_duplicate_id_in_file_is_rejected(self):
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 9.0, "2026-1C")
        self.rewrite_json("records.json", lambda d: d.append(copy.deepcopy(d[0])))
        view = self.acad.read_grades(self.alice, self.anchor)
        self.assertEqual(len(view.grades), 1)
        self.assertEqual(len(view.rejected), 1)

    # --- negativas: repetición / rollback -------------------------------
    def test_add_same_record_twice_is_replay(self):
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 9.0, "2026-1C")
        record = json.loads((self.dir / "records.json").read_text())[0]
        with self.assertRaises(ReplayError):
            self.acad.add_record(record, self.anchor)

    def test_old_record_reinserted_cannot_roll_back_the_grade(self):
        self.acad.issue_grade(self.sec, "alice", "REDES", 3.0, "2026-1C")
        self.acad.issue_grade(self.sec, "alice", "REDES", 7.0, "2026-2C")
        # Un atacante con acceso a disco reordena los registros para que el antiguo quede el último.
        self.rewrite_json("records.json", lambda d: d.reverse())
        grades = self.acad.read_grades(self.alice, self.anchor).grades
        self.assertEqual([(g["subject"], g["grade"]) for g in grades], [("REDES", 7.0)])

    def test_validly_signed_record_with_lower_seq_rejected_on_add(self):
        self.acad.issue_grade(self.sec, "alice", "REDES", 3.0, "2026-1C")
        self.acad.issue_grade(self.sec, "alice", "REDES", 7.0, "2026-2C")
        records = json.loads((self.dir / "records.json").read_text())
        old = copy.deepcopy(records[0])
        old["header"]["id"] = "e" * 32  # id nuevo, seq=1 < 2 ya aceptado
        body = {k: old[k] for k in ("header", "sealed_cek", "ct")}
        old["signature"] = self.sec.sign("record", body)  # firma legítima: solo falla la regla de seq
        with self.assertRaises(ReplayError):
            self.acad.add_record(old, self.anchor)

    def test_old_record_with_stale_signature_rejected_on_add(self):
        self.acad.issue_grade(self.sec, "alice", "REDES", 3.0, "2026-1C")
        old = json.loads((self.dir / "records.json").read_text())[0]
        old["header"]["id"] = "e" * 32  # cambiar el id sin re-firmar invalida la firma
        with self.assertRaises(IntegrityError):
            self.acad.add_record(old, self.anchor)

    # --- matrícula y validación ----------------------------------------
    def test_cannot_issue_to_unenrolled_student(self):
        self.users.register("carol", "clave-valida-de-prueba-3")
        with self.assertRaises(ValidationError):
            self.acad.issue_grade(self.sec, "carol", "CRIPTO", 5.0, "2026-1C")

    def test_substituted_public_key_is_detected(self):
        """Un atacante cambia la clave pública de alice en users.json para recibir sus notas."""
        self.rewrite_json("users.json", lambda d: d["alice"].update(pub=d["bob"]["pub"]))
        with self.assertRaises(IntegrityError):
            self.acad.issue_grade(self.sec, "alice", "CRIPTO", 9.0, "2026-1C")

    def test_invalid_grade_subject_and_term(self):
        for subject, grade, term in (("CRIPTO", 11, "2026-1C"), ("CRIPTO", -1, "2026-1C"), ("CRIPTO", True, "2026-1C"),
                                     ("NOEXISTE", 5, "2026-1C"), ("CRIPTO", 5, "enero")):
            with self.assertRaises(ValidationError, msg=(subject, grade, term)):
                self.acad.issue_grade(self.sec, "alice", subject, grade, term)

    # --- plan firmado ---------------------------------------------------
    def test_plan_signature_checked(self):
        self.assertEqual(len(self.acad.load_plan(self.anchor)["subjects"]), 3)
        self.rewrite_json("plan.json", lambda d: d["plan"]["subjects"][0].update(credits=1))
        with self.assertRaises(IntegrityError):
            self.acad.load_plan(self.anchor)


class SecretariaTests(TmpDirCase):
    def test_init_unlock_and_wrong_passphrase(self):
        fp = Secretaria.init(self.dir, SEC_PASS, FAST)
        Secretaria.unlock(self.dir, SEC_PASS, expected_fingerprint=fp)
        with self.assertRaises(AuthenticationError):
            Secretaria.unlock(self.dir, "passphrase-incorrecta-1")

    def test_double_init_and_weak_passphrase(self):
        with self.assertRaises(ValidationError):
            Secretaria.init(self.dir, "corta", FAST)
        Secretaria.init(self.dir, SEC_PASS, FAST)
        with self.assertRaises(ValidationError):
            Secretaria.init(self.dir, SEC_PASS, FAST)

    def test_wrong_pinned_fingerprint(self):
        Secretaria.init(self.dir, SEC_PASS, FAST)
        with self.assertRaises(IntegrityError):
            TrustAnchor.load(self.dir, expected_fingerprint="00" * 32)

    def test_tampered_key_file(self):
        Secretaria.init(self.dir, SEC_PASS, FAST)
        self.rewrite_json("secretaria/signing_key.json", lambda d: d.update(blob=flip_b64(d["blob"], 15)))
        with self.assertRaises(AuthenticationError):
            Secretaria.unlock(self.dir, SEC_PASS)

    def test_certificate_swapped_for_another_one(self):
        Secretaria.init(self.dir, SEC_PASS, FAST)
        with tempfile.TemporaryDirectory() as other:
            Secretaria.init(Path(other), SEC_PASS, FAST)
            other_cert = (Path(other) / "secretaria" / "cert.pem").read_bytes()
        (self.dir / "secretaria" / "cert.pem").write_bytes(other_cert)
        with self.assertRaises(IntegrityError):  # la clave descifrada no corresponde al certificado
            Secretaria.unlock(self.dir, SEC_PASS)

    def test_missing_secretaria(self):
        with self.assertRaises(ValidationError):
            TrustAnchor.load(self.dir)


if __name__ == "__main__":
    unittest.main()
