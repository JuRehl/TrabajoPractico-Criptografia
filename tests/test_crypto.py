import datetime as dt
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID

from plancipher.crypto import aead, certs, hybrid, kdf, keystore, signing
from plancipher.crypto.encoding import b64d, canonical
from plancipher.errors import AuthenticationError, IntegrityError, ValidationError
from tests.helpers import FAST


def flip(blob: bytes, index: int) -> bytes:
    b = bytearray(blob)
    b[index] ^= 0x01
    return bytes(b)


class AeadTests(unittest.TestCase):
    def setUp(self):
        self.key = aead.new_key()
        self.blob = aead.encrypt(self.key, b"hola mundo", b"aad")

    def test_roundtrip(self):
        self.assertEqual(aead.decrypt(self.key, self.blob, b"aad"), b"hola mundo")

    def test_tamper_every_region_is_rejected(self):
        # nonce (inicio), ciphertext (medio) y tag (final)
        for idx in (0, aead.NONCE_LEN + 1, len(self.blob) - 1):
            with self.assertRaises(IntegrityError):
                aead.decrypt(self.key, flip(self.blob, idx), b"aad")

    def test_wrong_aad_wrong_key_truncated(self):
        with self.assertRaises(IntegrityError):
            aead.decrypt(self.key, self.blob, b"otro")
        with self.assertRaises(IntegrityError):
            aead.decrypt(aead.new_key(), self.blob, b"aad")
        with self.assertRaises(IntegrityError):
            aead.decrypt(self.key, self.blob[:10], b"aad")

    def test_nonce_never_repeats(self):
        nonces = {aead.encrypt(self.key, b"x", b"")[: aead.NONCE_LEN] for _ in range(2000)}
        self.assertEqual(len(nonces), 2000)

    def test_rejects_short_key(self):
        with self.assertRaises(ValueError):
            aead.encrypt(b"corta", b"x", b"")


class HybridTests(unittest.TestCase):
    def setUp(self):
        self.priv, self.pub = hybrid.generate_keypair()
        self.sealed = hybrid.seal(self.pub, b"clave-contenido", b"aad")

    def test_roundtrip_and_fresh_ephemeral_each_time(self):
        self.assertEqual(hybrid.open_sealed(self.priv, self.sealed, b"aad"), b"clave-contenido")
        self.assertNotEqual(self.sealed, hybrid.seal(self.pub, b"clave-contenido", b"aad"))

    def test_wrong_recipient_tamper_and_aad(self):
        other, _ = hybrid.generate_keypair()
        for bad in (lambda: hybrid.open_sealed(other, self.sealed, b"aad"),
                    lambda: hybrid.open_sealed(self.priv, self.sealed, b"otro"),
                    lambda: hybrid.open_sealed(self.priv, flip(self.sealed, 40), b"aad"),
                    lambda: hybrid.open_sealed(self.priv, flip(self.sealed, 3), b"aad"),
                    lambda: hybrid.open_sealed(self.priv, b"corto", b"aad")):
            with self.assertRaises(IntegrityError):
                bad()

    def test_low_order_ephemeral_key_rejected(self):
        zero_point = b"\x00" * 32 + self.sealed[32:]
        with self.assertRaises(IntegrityError):
            hybrid.open_sealed(self.priv, zero_point, b"aad")

    def test_bad_public_key_length(self):
        with self.assertRaises(ValidationError):
            hybrid.public_from_bytes(b"123")


class SigningTests(unittest.TestCase):
    def setUp(self):
        self.key = signing.generate_signing_key()
        self.sig = signing.sign(self.key, b"mensaje")

    def test_valid_signature(self):
        signing.verify(self.key.public_key(), self.sig, b"mensaje")  # no lanza

    def test_modified_message_signature_or_key_rejected(self):
        pub = self.key.public_key()
        with self.assertRaises(IntegrityError):
            signing.verify(pub, self.sig, b"mensaje!")
        with self.assertRaises(IntegrityError):
            signing.verify(pub, flip(self.sig, 10), b"mensaje")
        with self.assertRaises(IntegrityError):
            signing.verify(pub, b"basura", b"mensaje")
        with self.assertRaises(IntegrityError):
            signing.verify(signing.generate_signing_key().public_key(), self.sig, b"mensaje")

    def test_private_key_der_roundtrip(self):
        k2 = signing.private_from_der(signing.private_to_der(self.key))
        signing.verify(self.key.public_key(), signing.sign(k2, b"x"), b"x")


class KdfTests(unittest.TestCase):
    def test_deterministic_and_salt_dependent(self):
        s = kdf.new_salt()
        self.assertEqual(kdf.derive_subkeys("pw-largo-123", s, FAST), kdf.derive_subkeys("pw-largo-123", s, FAST))
        self.assertNotEqual(kdf.derive_subkeys("pw-largo-123", s, FAST), kdf.derive_subkeys("pw-largo-123", kdf.new_salt(), FAST))

    def test_verifier_and_kek_are_independent(self):
        verifier, kek = kdf.derive_subkeys("pw-largo-123", kdf.new_salt(), FAST)
        self.assertNotEqual(verifier, kek)

    def test_unicode_normalization(self):
        s = kdf.new_salt()
        self.assertEqual(kdf.derive_master("caf\u00e9-secreto", s, FAST), kdf.derive_master("cafe\u0301-secreto", s, FAST))

    def test_salts_are_random(self):
        self.assertEqual(len({kdf.new_salt() for _ in range(500)}), 500)


class KeystoreTests(unittest.TestCase):
    def test_roundtrip_wrong_passphrase_and_tamper(self):
        rec = keystore.protect("frase-larga-123", b"secreto", FAST, b"aad")
        self.assertEqual(keystore.unprotect("frase-larga-123", rec, b"aad"), b"secreto")
        with self.assertRaises(AuthenticationError):
            keystore.unprotect("otra-frase-123", rec, b"aad")
        with self.assertRaises(AuthenticationError):
            keystore.unprotect("frase-larga-123", rec, b"otro-aad")
        bad = dict(rec, blob=rec["blob"][:-6] + "AAAAAA")
        with self.assertRaises(AuthenticationError):
            keystore.unprotect("frase-larga-123", bad, b"aad")


class CertTests(unittest.TestCase):
    def setUp(self):
        self.key = signing.generate_signing_key()
        self.cert = certs.create_self_signed(self.key, "Test")
        self.pem = certs.to_pem(self.cert)

    def test_load_and_fingerprint_pin(self):
        fp = certs.fingerprint(self.cert)
        certs.load_trusted(self.pem, fp)
        certs.load_trusted(self.pem, fp.upper())
        with self.assertRaises(IntegrityError):
            certs.load_trusted(self.pem, "00" * 32)

    def test_expired_certificate_rejected(self):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "viejo")])
        now = dt.datetime.now(dt.timezone.utc)
        old = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
               .serial_number(1).not_valid_before(now - dt.timedelta(days=10)).not_valid_after(now - dt.timedelta(days=1))
               .sign(self.key, hashes.SHA256()))
        with self.assertRaises(IntegrityError):
            certs.load_trusted(certs.to_pem(old))

    def test_not_self_signed_rejected(self):
        # Certificado cuyo emisor es otro (firmado por otra clave) no es un ancla autofirmada válida.
        other = signing.generate_signing_key()
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])
        now = dt.datetime.now(dt.timezone.utc)
        forged = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(self.key.public_key())
                  .serial_number(2).not_valid_before(now).not_valid_after(now + dt.timedelta(days=1))
                  .sign(other, hashes.SHA256()))
        with self.assertRaises(IntegrityError):
            certs.load_trusted(certs.to_pem(forged))

    def test_garbage_rejected(self):
        with self.assertRaises(IntegrityError):
            certs.load_trusted(b"no es un certificado")


class EncodingTests(unittest.TestCase):
    def test_strict_base64(self):
        for bad in ("!!!", "abc", 5):
            with self.assertRaises(ValidationError):
                b64d(bad)

    def test_canonical_is_deterministic_and_domain_separated(self):
        self.assertEqual(canonical("a", {"x": 1, "y": 2}), canonical("a", {"y": 2, "x": 1}))
        self.assertNotEqual(canonical("a", {"x": 1}), canonical("b", {"x": 1}))


if __name__ == "__main__":
    unittest.main()
