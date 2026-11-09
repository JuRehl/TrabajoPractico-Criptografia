import unittest

from plancipher.errors import ValidationError
from tests.helpers import SystemCase


class PlanningTests(SystemCase):
    def test_roundtrip_and_sorting(self):
        self.planning.add(self.alice, "2026-11-11", "10:00", "Redes")
        self.planning.add(self.alice, "2026-11-10", "09:00", "Cripto")
        entries, rejected = self.planning.list(self.alice)
        self.assertEqual([e["text"] for e in entries], ["Cripto", "Redes"])
        self.assertEqual(rejected, [])

    def test_ciphertext_does_not_leak_plaintext(self):
        self.planning.add(self.alice, "2026-11-10", "09:00", "Examen secreto de Cripto")
        raw = (self.dir / "planning.json").read_text()
        self.assertNotIn("Examen", raw)
        self.assertNotIn("Cripto", raw)

    def test_users_only_see_their_own_entries(self):
        self.planning.add(self.alice, "2026-11-10", "09:00", "Solo para Alice")
        self.assertEqual(self.planning.list(self.bob), ([], []))

    def test_tampered_entry_is_rejected(self):
        self.planning.add(self.alice, "2026-11-10", "09:00", "Cripto")
        self.rewrite_json("planning.json", lambda d: d[0].update(data=d[0]["data"][:-4] + "AAAA"))
        self.assertEqual(self.planning.list(self.alice)[0], [])
        self.assertEqual(len(self.planning.list(self.alice)[1]), 1)

    def test_entry_reassigned_to_another_owner_is_rejected(self):
        self.planning.add(self.alice, "2026-11-10", "09:00", "Cripto")
        self.rewrite_json("planning.json", lambda d: d[0].update(owner="bob"))
        entries, rejected = self.planning.list(self.bob)
        self.assertEqual(entries, [])
        self.assertEqual(len(rejected), 1)

    def test_entry_with_swapped_id_is_rejected(self):
        self.planning.add(self.alice, "2026-11-10", "09:00", "Cripto")
        self.rewrite_json("planning.json", lambda d: d[0].update(id="f" * 32))
        self.assertEqual(self.planning.list(self.alice)[0], [])

    def test_input_validation(self):
        for day, start, text in (("2026-13-40", "09:00", "x"), ("2026-11-10", "25:00", "x"),
                                 ("2026-11-10", "09:00", ""), ("2026-11-10", "09:00", "a\x00b"),
                                 ("2026-11-10", "09:00", "x" * 500)):
            with self.assertRaises(ValidationError):
                self.planning.add(self.alice, day, start, text)


if __name__ == "__main__":
    unittest.main()
