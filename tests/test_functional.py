"""Pruebas FUNCIONALES (casos de uso correctos): persistencia entre ejecuciones,
valores límite, reglas de negocio y flujos completos. Las pruebas de ataques y
manipulaciones están en test_academic, test_auth, test_planning y test_crypto."""
import json
import unicodedata
import unittest

from plancipher.academic import AcademicService, pending_subjects, validate_plan
from plancipher.auth import UserService
from plancipher.crypto.kdf import KdfParams
from plancipher.errors import IntegrityError, ValidationError
from plancipher.planning import MAX_TEXT, PlanningService
from plancipher.secretaria import Secretaria, TrustAnchor
from plancipher.storage import JsonStore
from tests.helpers import FAST, PASS_A, PASS_B, PLAN, SEC_PASS, SystemCase, TmpDirCase


# --- Almacenamiento ------------------------------------------------------------
class StorageTests(TmpDirCase):
    def test_roundtrip_default_and_overwrite(self):
        store = JsonStore(self.dir / "sub" / "dir" / "x.json")  # crea directorios intermedios
        self.assertEqual(store.load({"vacio": True}), {"vacio": True})
        store.save({"a": 1, "ñ": "ü"})
        self.assertEqual(JsonStore(store.path).load(None), {"a": 1, "ñ": "ü"})
        store.save([1, 2, 3])
        self.assertEqual(store.load(None), [1, 2, 3])

    def test_atomic_write_leaves_no_temporary_files(self):
        store = JsonStore(self.dir / "x.json")
        for i in range(5):
            store.save({"i": i})
        self.assertEqual([p.name for p in self.dir.iterdir()], ["x.json"])

    def test_corrupt_file_raises_validation_error(self):
        (self.dir / "x.json").write_text("{no es json", encoding="utf-8")
        with self.assertRaises(ValidationError):
            JsonStore(self.dir / "x.json").load({})


# --- Usuarios ------------------------------------------------------------------
class UserFunctionalTests(TmpDirCase):
    def setUp(self):
        super().setUp()
        self.store = JsonStore(self.dir / "users.json")
        self.users = UserService(self.store, FAST)

    def test_users_persist_across_service_instances(self):
        self.users.register("alice", PASS_A)
        self.users.register("bob", PASS_B)
        fresh = UserService(JsonStore(self.dir / "users.json"), FAST)  # "otra ejecución del programa"
        self.assertEqual(fresh.usernames(), ["alice", "bob"])
        self.assertEqual(fresh.login("bob", PASS_B).username, "bob")

    def test_session_keys_match_stored_public_key_and_are_stable(self):
        self.users.register("alice", PASS_A)
        s1, s2 = self.users.login("alice", PASS_A), self.users.login("alice", PASS_A)
        self.assertEqual(s1.kek, s2.kek)  # la KEK se re-deriva igual en cada login
        from plancipher.crypto import hybrid
        from plancipher.crypto.encoding import b64e
        self.assertEqual(b64e(hybrid.public_to_bytes(s1.public_key)), self.users.get("alice")["pub"])

    def test_each_user_keeps_its_own_kdf_params(self):
        """Los parámetros scrypt se guardan por usuario: cambiar el valor por defecto
        no rompe el login de cuentas antiguas."""
        self.users.register("alice", PASS_A)
        stronger = UserService(self.store, KdfParams(n=2**11, r=8, p=1))
        stronger.register("bob", PASS_B)
        self.assertEqual(self.users.get("alice")["kdf"]["n"], 2**10)
        self.assertEqual(self.users.get("bob")["kdf"]["n"], 2**11)
        self.assertEqual(stronger.login("alice", PASS_A).username, "alice")
        self.assertEqual(self.users.login("bob", PASS_B).username, "bob")

    def test_unicode_password_normalized(self):
        """La misma contraseña con tilde compuesta (NFC) o descompuesta (NFD) es la misma."""
        password = "canción-del-verano-77"
        self.users.register("alice", unicodedata.normalize("NFC", password))
        self.users.login("alice", unicodedata.normalize("NFD", password))

    def test_new_user_starts_unenrolled_and_unlocked(self):
        self.users.register("alice", PASS_A)
        rec = self.users.get("alice")
        self.assertEqual((rec["failed"], rec["locked_until"]), (0, 0))
        self.assertNotIn("cert", rec)  # el certificado vive en la zona de la secretaría
        self.assertIsNone(self.users.get("nadie"))

    def test_valid_username_edge_cases(self):
        for name in ("abc", "a" * 32, "ana.garcia", "user_01", "x-y-z"):
            self.users.register(name, PASS_A)
        self.assertEqual(len(self.users.usernames()), 5)
        for bad in ("ab", "a" * 33, "Alice", "_ana", "ana garcia"):
            with self.assertRaises(ValidationError, msg=bad):
                self.users.register(bad, PASS_A)


# --- Planning ------------------------------------------------------------------
class PlanningFunctionalTests(SystemCase):
    def test_persists_across_logins_and_instances(self):
        self.planning.add(self.alice, "2026-11-10", "09:00", "Clase de Cripto")
        again = self.users.login("alice", PASS_A)  # nueva sesión: misma KEK re-derivada
        fresh = PlanningService(JsonStore(self.dir / "planning.json"))
        entries, rejected = fresh.list(again)
        self.assertEqual(([e["text"] for e in entries], rejected), (["Clase de Cripto"], []))

    def test_sorted_by_day_then_time(self):
        for day, start, text in (("2026-11-11", "08:00", "c"), ("2026-11-10", "18:30", "b"),
                                 ("2026-11-10", "09:00", "a"), ("2027-01-01", "00:00", "d")):
            self.planning.add(self.alice, day, start, text)
        entries, _ = self.planning.list(self.alice)
        self.assertEqual([e["text"] for e in entries], ["a", "b", "c", "d"])

    def test_boundary_values_accepted(self):
        self.planning.add(self.alice, "2026-02-28", "00:00", "x")
        self.planning.add(self.alice, "2028-02-29", "23:59", "y" * MAX_TEXT)  # año bisiesto, texto máximo
        self.assertEqual(len(self.planning.list(self.alice)[0]), 2)
        for day, start, text in (("2026-02-29", "09:00", "x"), ("2026-11-10", "24:00", "x"),
                                 ("2026-11-10", "9:00", "x"), ("2026-11-10", "09:00", "y" * (MAX_TEXT + 1))):
            with self.assertRaises(ValidationError, msg=(day, start)):
                self.planning.add(self.alice, day, start, text)

    def test_text_is_trimmed_and_unicode_preserved(self):
        self.planning.add(self.alice, "2026-11-10", "09:00", "  Tutoría con Ñúñez 📚  ")
        self.assertEqual(self.planning.list(self.alice)[0][0]["text"], "Tutoría con Ñúñez 📚")

    def test_same_text_gives_different_ids_and_ciphertexts(self):
        ids = {self.planning.add(self.alice, "2026-11-10", "09:00", "Igual") for _ in range(3)}
        self.assertEqual(len(ids), 3)
        raw = json.loads((self.dir / "planning.json").read_text())
        self.assertEqual(len({r["data"] for r in raw}), 3)        # nonce y CEK aleatorios
        self.assertEqual(len({r["wrapped_cek"] for r in raw}), 3)
        self.assertEqual(len(self.planning.list(self.alice)[0]), 3)

    def test_users_entries_interleaved_on_disk(self):
        self.planning.add(self.alice, "2026-11-10", "09:00", "A1")
        self.planning.add(self.bob, "2026-11-10", "10:00", "B1")
        self.planning.add(self.alice, "2026-11-11", "09:00", "A2")
        self.assertEqual([e["text"] for e in self.planning.list(self.alice)[0]], ["A1", "A2"])
        self.assertEqual([e["text"] for e in self.planning.list(self.bob)[0]], ["B1"])


# --- Plan de estudios ----------------------------------------------------------
class PlanFunctionalTests(SystemCase):
    def test_validate_plan_normalizes_and_drops_extra_fields(self):
        plan = {"degree": "G", "extra": 1, "subjects": [{"code": "ABC", "name": "n", "credits": 6, "x": "y"}]}
        self.assertEqual(validate_plan(plan), {"degree": "G", "subjects": [{"code": "ABC", "name": "n", "credits": 6}]})

    def test_validate_plan_limits(self):
        ok = lambda **kw: {"degree": "G", "subjects": [{"code": "ABC", "name": "n", "credits": 6} | kw]}
        for good in (ok(code="A" * 12), ok(code="X99"), ok(credits=1), ok(credits=30), ok(name="n" * 80)):
            validate_plan(good)
        dup = {"degree": "G", "subjects": [{"code": "ABC", "name": "n", "credits": 6}] * 2}
        for bad in (ok(code="AB"), ok(code="abc"), ok(code="A" * 13), ok(credits=0), ok(credits=31),
                    ok(credits=6.0), ok(name=""), ok(name="n" * 81), dup, {"degree": "G", "subjects": []}, {}):
            with self.assertRaises(ValidationError, msg=bad):
                validate_plan(bad)

    def test_republish_replaces_plan_and_adds_metadata(self):
        loaded = self.acad.load_plan(self.anchor)
        self.assertEqual((loaded["v"], [s["code"] for s in loaded["subjects"]]), (1, ["CRIPTO", "REDES", "BBDD"]))
        self.assertIn("issued_at", loaded)
        self.acad.publish_plan(self.sec, {"degree": "Nuevo", "subjects": [{"code": "SISOP", "name": "Sistemas operativos", "credits": 6}]})
        self.assertEqual(self.acad.load_plan(self.anchor)["degree"], "Nuevo")
        with self.assertRaises(ValidationError):  # CRIPTO ya no existe en el plan vigente
            self.acad.issue_grade(self.sec, "alice", "CRIPTO", 7.0, "2026-1C")

    def test_plan_not_published_yet(self):
        self.force_delete("secretaria/plan.json")
        with self.assertRaises(ValidationError):
            self.acad.load_plan(self.anchor)


# --- Notas y pendientes --------------------------------------------------------
class GradeFunctionalTests(SystemCase):
    def grades(self, session=None):
        return self.acad.read_grades(session or self.alice, self.anchor).grades

    def test_grade_boundaries_rounding_and_terms(self):
        for subject, grade, term in (("CRIPTO", 0, "2026-1C"), ("REDES", 10, "2026-2C"), ("BBDD", 6.75, "2027-1C")):
            self.acad.issue_grade(self.sec, "alice", subject, grade, term)
        got = {g["subject"]: (g["grade"], g["term"]) for g in self.grades()}
        self.assertEqual(got, {"CRIPTO": (0.0, "2026-1C"), "REDES": (10.0, "2026-2C"), "BBDD": (6.8, "2027-1C")})
        for bad in (10.01, -0.01, "8", None):
            with self.assertRaises(ValidationError, msg=bad):
                self.acad.issue_grade(self.sec, "alice", "CRIPTO", bad, "2026-1C")

    def test_seq_is_independent_per_student(self):
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 5.0, "2026-1C")
        self.acad.issue_grade(self.sec, "alice", "REDES", 5.0, "2026-1C")
        self.acad.issue_grade(self.sec, "bob", "CRIPTO", 5.0, "2026-1C")
        seqs = [(r["header"]["student"], r["header"]["seq"]) for r in json.loads((self.dir / "secretaria" / "records.json").read_text())]
        self.assertEqual(seqs, [("alice", 1), ("alice", 2), ("bob", 1)])

    def test_grades_sorted_by_subject_with_issue_date(self):
        for subject in ("REDES", "BBDD", "CRIPTO"):
            self.acad.issue_grade(self.sec, "alice", subject, 7.0, "2026-1C")
        grades = self.grades()
        self.assertEqual([g["subject"] for g in grades], ["BBDD", "CRIPTO", "REDES"])
        self.assertTrue(all(g["issued_at"] and g["student"] == "alice" for g in grades))

    def test_latest_grade_wins_even_if_lower(self):
        """Una revisión puede bajar la nota: manda la última emitida, no la mayor."""
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 9.0, "2026-1C")
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 4.0, "2026-1C")
        self.assertEqual([g["grade"] for g in self.grades()], [4.0])

    def test_grades_survive_relogin_and_reload_from_disk(self):
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 8.0, "2026-1C")
        users = UserService(JsonStore(self.dir / "users.json"), FAST)
        session = users.login("alice", PASS_A)
        acad = AcademicService(self.dir, users)
        view = acad.read_grades(session, TrustAnchor.load(self.dir))
        self.assertEqual(([g["grade"] for g in view.grades], view.rejected), ([8.0], []))

    def test_enrollment_issues_x509_certificate(self):
        from cryptography import x509
        from cryptography.x509.oid import NameOID
        from plancipher.crypto import hybrid
        from plancipher.crypto.encoding import b64d
        rec = self.users.get("alice")
        pem = json.loads((self.dir / "secretaria" / "matriculas.json").read_text())["alice"]
        cert = x509.load_pem_x509_certificate(pem.encode())
        self.assertEqual(cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value, "alice")
        self.assertEqual(cert.issuer, self.anchor.cert.subject)  # emitido por la secretaría
        self.assertEqual(hybrid.public_to_bytes(cert.public_key()), b64d(rec["pub"]))

    def test_reenrollment_is_idempotent(self):
        self.acad.enroll(self.sec, "alice")
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 6.0, "2026-1C")
        self.assertEqual(len(self.grades()), 1)

    def test_enroll_or_issue_for_unknown_student(self):
        with self.assertRaises(ValidationError):
            self.acad.enroll(self.sec, "nadie")
        with self.assertRaises(ValidationError):
            self.acad.issue_grade(self.sec, "nadie", "CRIPTO", 5.0, "2026-1C")

    def test_end_to_end_course_progress(self):
        """Un curso completo: al principio todo pendiente, al final nada."""
        plan = self.acad.load_plan(self.anchor)
        self.assertEqual([p["state"] for p in pending_subjects(plan, self.grades())], ["sin cursar"] * 3)
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 4.0, "2026-1C")
        self.acad.issue_grade(self.sec, "alice", "REDES", 7.0, "2026-1C")
        self.assertEqual({p["code"]: p["state"] for p in pending_subjects(plan, self.grades())},
                         {"CRIPTO": "suspensa", "BBDD": "sin cursar"})
        self.acad.issue_grade(self.sec, "alice", "CRIPTO", 5.0, "2026-2C")
        self.acad.issue_grade(self.sec, "alice", "BBDD", 9.5, "2026-2C")
        self.assertEqual(pending_subjects(plan, self.grades()), [])
        self.assertEqual(len(pending_subjects(plan, self.grades(self.bob))), 3)  # bob no ha cursado nada


class PendingSubjectsTests(unittest.TestCase):
    """pending_subjects es una función pura: se prueba sin criptografía."""

    def test_pass_mark_and_plan_order(self):
        grades = [{"subject": "REDES", "grade": 5.0}, {"subject": "CRIPTO", "grade": 4.9}]
        out = pending_subjects(PLAN, grades)
        self.assertEqual([(p["code"], p["state"], p["grade"]) for p in out],
                         [("CRIPTO", "suspensa", 4.9), ("BBDD", "sin cursar", None)])
        self.assertEqual(out[0]["credits"], 6)  # conserva los datos del plan

    def test_grades_outside_plan_are_ignored(self):
        all_passed = [{"subject": c, "grade": 10.0} for c in ("CRIPTO", "REDES", "BBDD", "OTRA")]
        self.assertEqual(pending_subjects(PLAN, all_passed), [])


# --- Secretaría / PKI ----------------------------------------------------------
class SecretariaFunctionalTests(SystemCase):
    def test_sign_and_verify_with_domain_separation(self):
        sig = self.sec.sign("plan", {"x": 1})
        self.anchor.verify("plan", {"x": 1}, sig)
        with self.assertRaises(IntegrityError):  # la misma firma no vale en otro dominio
            self.anchor.verify("record", {"x": 1}, sig)

    def test_unlock_from_disk_with_pinned_root(self):
        fp = self.anchor.fingerprint
        sec = Secretaria.unlock(self.dir, SEC_PASS, expected_fingerprint=fp)
        self.assertEqual(sec.anchor.secretaria_fingerprint, self.anchor.secretaria_fingerprint)
        self.acad.issue_grade(sec, "alice", "CRIPTO", 7.0, "2026-1C")
        self.assertEqual(len(self.acad.read_grades(self.alice, TrustAnchor.load(self.dir, fp)).grades), 1)

    def test_pki_files_and_chain(self):
        for rel in ("pki/root_cert.pem", "pki/root_key.json", "pki/crl.pem",
                    "secretaria/cert.pem", "secretaria/signing_key.json"):
            self.assertTrue((self.dir / rel).is_file(), rel)
        self.assertEqual(self.anchor.cert.issuer, self.anchor.root.subject)
        self.assertEqual(len(self.anchor.crl), 0)  # CRL inicial vacía
        for rel in ("pki/root_key.json", "secretaria/signing_key.json"):  # claves privadas nunca en claro
            self.assertNotIn("PRIVATE KEY", (self.dir / rel).read_text())


if __name__ == "__main__":
    unittest.main()
