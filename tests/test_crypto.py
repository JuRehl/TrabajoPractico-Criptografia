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

    def test_params_roundtrip_through_dict(self):
        for params in (kdf.KdfParams(), FAST):
            self.assertEqual(kdf.KdfParams.from_dict(params.to_dict()), params)

    def test_tampered_params_rejected_cleanly(self):
        """Parámetros leídos de disco: inválidos o desorbitados -> IntegrityError, sin ejecutar scrypt."""
        good = kdf.KdfParams().to_dict()
        for bad in (dict(good, n=3), dict(good, n=0), dict(good, n=-2**17), dict(good, n=2**30),
                    dict(good, n=2**8), dict(good, r=0), dict(good, r=10**6), dict(good, p=0),
                    dict(good, p=100), dict(good, n=2**20, r=16),  # 2 GiB de memoria
                    dict(good, n="131072"), dict(good, n=131072.0), dict(good, n=True),
                    {"r": 8, "p": 1}, None, "texto"):
            with self.assertRaises(IntegrityError, msg=bad):
                kdf.KdfParams.from_dict(bad)


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
    """PKI de dos niveles: AC raíz -> AC subordinada (secretaría) + CRL."""

    def setUp(self):
        self.root_key = signing.generate_signing_key()
        self.root = certs.create_root(self.root_key)
        self.sub_key = signing.generate_signing_key()
        self.sub = certs.issue_subordinate(self.root_key, self.root, self.sub_key.public_key())
        self.crl = certs.create_crl(self.root_key, self.root)

    def _builder(self, key, *, issuer_name=None, days=1, start_days=0):
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "x")])
        now = dt.datetime.now(dt.timezone.utc)
        return (x509.CertificateBuilder().subject_name(name).issuer_name(issuer_name or name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - dt.timedelta(days=start_days, minutes=1))
                .not_valid_after(now + dt.timedelta(days=days)))

    @staticmethod
    def _ext(b, *, ca=True, path_length=1, digital_signature=False, key_cert_sign=True, crl_sign=True):
        return b.add_extension(x509.BasicConstraints(ca=ca, path_length=path_length), critical=True).add_extension(
            x509.KeyUsage(digital_signature=digital_signature, key_cert_sign=key_cert_sign, crl_sign=crl_sign,
                          content_commitment=False, key_encipherment=False, data_encipherment=False,
                          key_agreement=False, encipher_only=False, decipher_only=False), critical=True)

    def _sub(self, **ext):
        """Subordinada emitida por la raíz con extensiones a medida."""
        b = self._builder(self.sub_key, issuer_name=self.root.subject)
        opts = dict(path_length=0, digital_signature=True) | ext
        return certs.to_pem(self._ext(b, **opts).sign(self.root_key, hashes.SHA256()))

    def verify(self, sub_pem=None, crl=None):
        return certs.verify_subordinate(sub_pem or certs.to_pem(self.sub), self.root, crl or self.crl)

    # --- AC raíz ---------------------------------------------------------
    def test_root_load_and_fingerprint_pin(self):
        pem, fp = certs.to_pem(self.root), certs.fingerprint(self.root)
        certs.load_root(pem, fp)
        certs.load_root(pem, fp.upper())
        with self.assertRaises(IntegrityError):
            certs.load_root(pem, "00" * 32)
        with self.assertRaises(IntegrityError):  # la huella de la subordinada no sirve como ancla
            certs.load_root(pem, certs.fingerprint(self.sub))

    def test_root_must_be_self_signed_ca(self):
        other = signing.generate_signing_key()
        forged = self._ext(self._builder(self.root_key)).sign(other, hashes.SHA256())
        expired = self._ext(self._builder(self.root_key, days=-1, start_days=10)).sign(self.root_key, hashes.SHA256())
        for bad in (forged, expired):
            with self.assertRaises(IntegrityError):
                certs.load_root(certs.to_pem(bad))
        with self.assertRaises(IntegrityError):  # la subordinada no es autofirmada: no puede ser raíz
            certs.load_root(certs.to_pem(self.sub))
        with self.assertRaises(IntegrityError):
            certs.load_root(b"no es un certificado")

    def test_root_usage_is_checked(self):
        def root(**ext):
            return certs.to_pem(self._ext(self._builder(self.root_key), **ext).sign(self.root_key, hashes.SHA256()))
        certs.load_root(root())
        no_ext = certs.to_pem(self._builder(self.root_key).sign(self.root_key, hashes.SHA256()))
        for bad in (no_ext, root(ca=False, path_length=None), root(path_length=0),
                    root(key_cert_sign=False), root(crl_sign=False)):
            with self.assertRaises(IntegrityError):
                certs.load_root(bad)

    # --- cadena subordinada -> raíz ---------------------------------------
    def test_valid_chain(self):
        cert = self.verify()
        self.assertEqual(cert.issuer, self.root.subject)
        self.assertLessEqual(cert.not_valid_after_utc, self.root.not_valid_after_utc)

    def test_subordinate_signed_by_other_root_rejected(self):
        other_key = signing.generate_signing_key()
        other_root = certs.create_root(other_key)  # mismo nombre "PlanCipher AC Raiz", distinta clave
        fake = certs.issue_subordinate(other_key, other_root, self.sub_key.public_key())
        with self.assertRaises(IntegrityError):
            self.verify(certs.to_pem(fake))

    def test_self_signed_secretaria_rejected(self):
        """El modelo antiguo (secretaría autofirmada) ya no es aceptado: debe colgar de la raíz."""
        b = self._ext(self._builder(self.sub_key), path_length=0, digital_signature=True)
        with self.assertRaises(IntegrityError):
            self.verify(certs.to_pem(b.sign(self.sub_key, hashes.SHA256())))

    def test_subordinate_usage_is_checked(self):
        self.verify(self._sub())
        for bad in (self._sub(ca=False, path_length=None), self._sub(path_length=1),
                    self._sub(digital_signature=False)):
            with self.assertRaises(IntegrityError):
                self.verify(bad)

    def test_expired_subordinate_rejected(self):
        b = self._ext(self._builder(self.sub_key, issuer_name=self.root.subject, days=-1, start_days=10),
                      path_length=0, digital_signature=True)
        with self.assertRaises(IntegrityError):
            self.verify(certs.to_pem(b.sign(self.root_key, hashes.SHA256())))

    def test_subordinate_outliving_root_rejected(self):
        b = self._ext(self._builder(self.sub_key, issuer_name=self.root.subject, days=ROOT_PLUS),
                      path_length=0, digital_signature=True)
        with self.assertRaises(IntegrityError):
            self.verify(certs.to_pem(b.sign(self.root_key, hashes.SHA256())))

    # --- CRL --------------------------------------------------------------
    def test_revoked_subordinate_rejected(self):
        crl = certs.create_crl(self.root_key, self.root, [self.sub.serial_number])
        crl = certs.load_crl(certs.to_pem(crl), self.root)
        with self.assertRaises(IntegrityError):
            self.verify(crl=crl)
        self.verify(crl=certs.load_crl(certs.to_pem(certs.create_crl(self.root_key, self.root, [12345])), self.root))

    def test_crl_must_be_signed_by_root_and_fresh(self):
        other_key = signing.generate_signing_key()
        forged = certs.create_crl(other_key, certs.create_root(other_key))  # emisor con mismo nombre
        now = dt.datetime.now(dt.timezone.utc)
        expired = (x509.CertificateRevocationListBuilder().issuer_name(self.root.subject)
                   .last_update(now - dt.timedelta(days=10)).next_update(now - dt.timedelta(days=1))
                   .sign(self.root_key, hashes.SHA256()))
        for bad in (certs.to_pem(forged), certs.to_pem(expired), b"no es una CRL"):
            with self.assertRaises(IntegrityError):
                certs.load_crl(bad, self.root)


    # --- certificados de estudiante (entidad final) -------------------------
    def _student_pem(self, *, username="alice", key=None, issuer_key=None, issuer=None, ca=False,
                     key_agreement=True, digital_signature=False, days=1, start_days=0):
        pub = key or hybrid.generate_keypair()[1]
        issuer = issuer or self.sub
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, username)])
        now = dt.datetime.now(dt.timezone.utc)
        b = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer.subject).public_key(pub)
             .serial_number(x509.random_serial_number())
             .not_valid_before(now - dt.timedelta(days=start_days, minutes=1)).not_valid_after(now + dt.timedelta(days=days))
             .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
             .add_extension(x509.KeyUsage(digital_signature=digital_signature, key_cert_sign=False, crl_sign=False,
                                          content_commitment=False, key_encipherment=False, data_encipherment=False,
                                          key_agreement=key_agreement, encipher_only=False, decipher_only=False),
                            critical=True))
        return certs.to_pem(b.sign(issuer_key or self.sub_key, hashes.SHA256()))

    def test_student_certificate_roundtrip(self):
        _, pub = hybrid.generate_keypair()
        cert = certs.issue_student(self.sub_key, self.sub, pub, "alice")
        got = certs.verify_student(certs.to_pem(cert), self.sub, "alice")
        self.assertEqual(hybrid.public_to_bytes(got), hybrid.public_to_bytes(pub))
        self.assertEqual(cert.issuer, self.sub.subject)
        self.assertLessEqual(cert.not_valid_after_utc, self.sub.not_valid_after_utc)
        self.assertFalse(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
        certs.verify_student(self._student_pem(), self.sub, "alice")  # el constructor del test también es válido

    def test_student_certificate_bound_to_username(self):
        with self.assertRaises(IntegrityError):
            certs.verify_student(self._student_pem(username="bob"), self.sub, "alice")

    def test_student_certificate_must_come_from_secretaria(self):
        other_key = signing.generate_signing_key()
        other_sub = certs.issue_subordinate(self.root_key, self.root, other_key.public_key())  # mismo nombre
        for bad in (self._student_pem(issuer=self.root, issuer_key=self.root_key),   # la raíz no emite estudiantes
                    self._student_pem(issuer_key=other_key),                         # firma de otra clave
                    self._student_pem(issuer=other_sub, issuer_key=other_key)):
            with self.assertRaises(IntegrityError):
                certs.verify_student(bad, self.sub, "alice")

    def test_student_certificate_usage_validity_and_key_type(self):
        ec_pub = signing.generate_signing_key().public_key()
        for bad in (self._student_pem(ca=True), self._student_pem(key_agreement=False),
                    self._student_pem(digital_signature=True), self._student_pem(days=-1, start_days=10),
                    self._student_pem(key=ec_pub), b"no es un certificado"):
            with self.assertRaises(IntegrityError):
                certs.verify_student(bad, self.sub, "alice")


ROOT_PLUS = certs.ROOT_DAYS + 30


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
