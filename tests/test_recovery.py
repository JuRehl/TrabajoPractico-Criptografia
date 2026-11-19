"""Recuperación de contraseña con código de recuperación: funcionamiento y fallo seguro."""
import re
import unittest

from plancipher.auth import GENERIC_RECOVERY_ERROR, MAX_FAILED, UserService
from plancipher.crypto import hybrid
from plancipher.errors import AuthenticationError, LockedError, ValidationError
from plancipher.storage import JsonStore
from tests.helpers import FAST, PASS_A, PASS_B, FakeClock, SystemCase, TmpDirCase

NEW_PASS = "contrasena-nueva-segura-7"
CODE_RE = re.compile(r"^[A-Z2-7]{4}(-[A-Z2-7]{4}){7}$")  # 160 bits en base32, 8 grupos


class RecoveryTests(TmpDirCase):
    def setUp(self):
        super().setUp()
        self.clock = FakeClock()
        self.users = UserService(JsonStore(self.dir / "users.json"), FAST, clock=self.clock)
        self.code = self.users.register("alice", PASS_A)

    def test_register_returns_a_random_code_not_stored_in_clear(self):
        self.assertRegex(self.code, CODE_RE)
        other = self.users.register("bob", PASS_B)
        self.assertNotEqual(self.code, other)
        raw = (self.dir / "users.json").read_text()
        self.assertNotIn(self.code, raw)
        self.assertNotIn(self.code.replace("-", ""), raw)

    def test_recover_sets_new_password_and_keeps_keys(self):
        before = self.users.login("alice", PASS_A)
        session, new_code = self.users.recover("alice", self.code, NEW_PASS)
        self.assertEqual(hybrid.public_to_bytes(session.public_key), hybrid.public_to_bytes(before.public_key))
        self.assertNotEqual(session.kek, before.kek)  # KEK nueva
        self.assertEqual(self.users.login("alice", NEW_PASS).kek, session.kek)
        with self.assertRaises(AuthenticationError):
            self.users.login("alice", PASS_A)  # la contraseña antigua ya no vale
        self.assertRegex(new_code, CODE_RE)
        self.assertNotEqual(new_code, self.code)

    def test_code_is_single_use_and_the_new_one_works(self):
        _, new_code = self.users.recover("alice", self.code, NEW_PASS)
        with self.assertRaises(AuthenticationError):
            self.users.recover("alice", self.code, "otra-contrasena-larga-8")
        self.users.recover("alice", new_code, "otra-contrasena-larga-8")
        self.users.login("alice", "otra-contrasena-larga-8")

    def test_code_format_is_forgiving(self):
        sloppy = " " + self.code.lower().replace("-", " ") + " "
        self.users.recover("alice", sloppy, NEW_PASS)
        self.users.login("alice", NEW_PASS)

    def test_wrong_malformed_or_unknown_all_look_identical(self):
        wrong = "AAAA-" + self.code[5:] if not self.code.startswith("AAAA") else "BBBB-" + self.code[5:]
        for user, code in (("alice", wrong), ("alice", ""), ("alice", "no-es-un-codigo"), ("alice", None),
                           ("alice", self.code[:-4]), ("nadie", self.code), (None, self.code)):
            with self.assertRaises(AuthenticationError, msg=(user, code)) as ctx:
                self.users.recover(user, code, NEW_PASS)
            self.assertEqual(str(ctx.exception), GENERIC_RECOVERY_ERROR)
        self.users.login("alice", PASS_A)  # nada ha cambiado

    def test_new_password_must_follow_policy(self):
        for weak in ("corta", "Password12345678", "alice-es-mi-clave-123"):
            with self.assertRaises(ValidationError, msg=weak):
                self.users.recover("alice", self.code, weak)
        self.users.login("alice", PASS_A)

    def test_recovery_unlocks_a_locked_account(self):
        for _ in range(MAX_FAILED):
            with self.assertRaises(AuthenticationError):
                self.users.login("alice", "contrasena-incorrecta-1")
        with self.assertRaises(LockedError):
            self.users.login("alice", PASS_A)
        self.users.recover("alice", self.code, NEW_PASS)
        self.users.login("alice", NEW_PASS)

    def test_tampered_recovery_data_rejected(self):
        self.rewrite_json("users.json", lambda d: d["alice"]["recovery"].update(
            enc_kek=d["bob"]["recovery"]["enc_kek"] if "bob" in d else d["alice"]["recovery"]["enc_kek"][:-6] + "AAAAAA"))
        with self.assertRaises(AuthenticationError):
            self.users.recover("alice", self.code, NEW_PASS)

    def test_recovery_copy_is_bound_to_the_username(self):
        """Copiar la copia de recuperación de bob en alice no sirve: la AAD lleva el usuario."""
        bob_code = self.users.register("bob", PASS_B)
        self.rewrite_json("users.json", lambda d: d["alice"].update(recovery=d["bob"]["recovery"]))
        with self.assertRaises(AuthenticationError):
            self.users.recover("alice", bob_code, NEW_PASS)

    def test_account_without_recovery_data(self):
        self.rewrite_json("users.json", lambda d: d["alice"].pop("recovery"))
        with self.assertRaises(AuthenticationError):
            self.users.recover("alice", self.code, NEW_PASS)


class RecoveryKeepsDataTests(SystemCase):
    """Tras recuperar la contraseña se conservan el planning y las notas."""

    def setUp(self):
        super().setUp()
        # SystemCase registra a alice sin guardar el código: se vuelve a crear con código conocido
        self.code = self.users.register("carol", "clave-de-la-tercera-9")
        self.acad.enroll(self.sec, "carol")
        self.carol = self.users.login("carol", "clave-de-la-tercera-9")

    def test_planning_survives_and_other_users_untouched(self):
        self.planning.add(self.carol, "2026-11-20", "09:00", "Clase de Cripto")
        self.planning.add(self.carol, "2026-11-21", "10:00", "Tutoría")
        self.planning.add(self.alice, "2026-11-20", "12:00", "De alice")
        session, _ = self.users.recover("carol", self.code, NEW_PASS, rekey=self.planning.rekey)
        self.assertEqual([e["text"] for e in self.planning.list(session)[0]], ["Clase de Cripto", "Tutoría"])
        self.assertEqual(self.planning.list(session)[1], [])
        self.assertEqual([e["text"] for e in self.planning.list(self.alice)[0]], ["De alice"])

    def test_without_rekey_the_planning_would_be_lost(self):
        """Muestra por qué hace falta re-envolver: con la KEK nueva las CEK antiguas no abren."""
        self.planning.add(self.carol, "2026-11-20", "09:00", "Clase de Cripto")
        session, _ = self.users.recover("carol", self.code, NEW_PASS)  # sin rekey
        entries, rejected = self.planning.list(session)
        self.assertEqual((entries, len(rejected)), ([], 1))

    def test_grades_survive_recovery(self):
        self.acad.issue_grade(self.sec, "carol", "CRIPTO", 7.5, "2026-1C")
        session, _ = self.users.recover("carol", self.code, NEW_PASS, rekey=self.planning.rekey)
        view = self.acad.read_grades(session, self.anchor)
        self.assertEqual(([g["grade"] for g in view.grades], view.rejected), ([7.5], []))
        self.acad.issue_grade(self.sec, "carol", "REDES", 6.0, "2026-1C")  # el certificado sigue valiendo
        self.assertEqual(len(self.acad.read_grades(session, self.anchor).grades), 2)


if __name__ == "__main__":
    unittest.main()
