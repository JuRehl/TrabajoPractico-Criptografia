import unittest

from plancipher.auth import LOCK_BASE_SECONDS, MAX_FAILED, UserService
from plancipher.errors import AuthenticationError, IntegrityError, LockedError, ValidationError
from plancipher.storage import JsonStore
from tests.helpers import FAST, PASS_A, FakeClock, TmpDirCase


class AuthTests(TmpDirCase):
    def setUp(self):
        super().setUp()
        self.clock = FakeClock()
        self.users = UserService(JsonStore(self.dir / "users.json"), FAST, clock=self.clock)
        self.users.register("alice", PASS_A)

    def test_register_and_login(self):
        s = self.users.login("alice", PASS_A)
        self.assertEqual(s.username, "alice")
        self.assertEqual(len(s.kek), 32)

    def test_password_is_not_stored_in_clear(self):
        raw = (self.dir / "users.json").read_text()
        self.assertNotIn(PASS_A, raw)
        self.assertNotIn("\"kek\"", raw)

    def test_wrong_password_and_unknown_user_look_identical(self):
        with self.assertRaises(AuthenticationError) as e1:
            self.users.login("alice", "contrasena-incorrecta-1")
        with self.assertRaises(AuthenticationError) as e2:
            self.users.login("nadie", "contrasena-incorrecta-1")
        self.assertEqual(str(e1.exception), str(e2.exception))

    def test_reserved_and_invalid_usernames(self):
        for name in ("secretaria", "admin", "ab", "Alice", "../etc", "a b c", "x" * 40):
            with self.assertRaises(ValidationError, msg=name):
                self.users.register(name, "contrasena-valida-123")

    def test_weak_passwords_rejected(self):
        for pw in ("corta", "aaaaaaaaaaaaaaaa", "xxbobxxcontrasena"):
            with self.assertRaises(ValidationError, msg=pw):
                self.users.register("bob", pw)

    def test_duplicate_user(self):
        with self.assertRaises(ValidationError):
            self.users.register("alice", "otra-contrasena-123")

    def test_lockout_after_repeated_failures_then_expires(self):
        for _ in range(MAX_FAILED):
            with self.assertRaises(AuthenticationError):
                self.users.login("alice", "contrasena-incorrecta-1")
        with self.assertRaises(LockedError):  # ni siquiera la contraseña correcta funciona
            self.users.login("alice", PASS_A)
        self.clock.t += LOCK_BASE_SECONDS + 1
        self.assertEqual(self.users.login("alice", PASS_A).username, "alice")

    def test_success_resets_failure_counter(self):
        for _ in range(MAX_FAILED - 1):
            with self.assertRaises(AuthenticationError):
                self.users.login("alice", "contrasena-incorrecta-1")
        self.users.login("alice", PASS_A)
        with self.assertRaises(AuthenticationError):  # no bloquea: el contador volvió a 0
            self.users.login("alice", "contrasena-incorrecta-1")
        self.assertEqual(self.users.get("alice")["failed"], 1)

    def test_tampered_verifier_or_private_key_blob(self):
        self.rewrite_json("users.json", lambda d: d["alice"].update(verifier="AAAA" + d["alice"]["verifier"][4:]))
        with self.assertRaises(AuthenticationError):
            self.users.login("alice", PASS_A)

    def test_tampered_encrypted_private_key(self):
        self.rewrite_json("users.json", lambda d: d["alice"].update(enc_priv=d["alice"]["enc_priv"][:-4] + "AAAA"))
        with self.assertRaises(IntegrityError):
            self.users.login("alice", PASS_A)

    def test_private_key_blob_is_bound_to_username(self):
        self.users.register("carol", "clave-valida-de-prueba-3")
        def swap(d):
            d["carol"]["enc_priv"] = d["alice"]["enc_priv"]
        self.rewrite_json("users.json", swap)
        with self.assertRaises((AuthenticationError, IntegrityError)):
            self.users.login("carol", "clave-valida-de-prueba-3")

    def test_corrupted_users_file_fails_safely(self):
        (self.dir / "users.json").write_text("{no es json")
        with self.assertRaises(ValidationError):
            self.users.login("alice", PASS_A)


if __name__ == "__main__":
    unittest.main()
