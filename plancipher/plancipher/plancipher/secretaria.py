"""Secretaría: emisora de firmas (matrículas, plan de estudios, notas).

La clave privada de firma ECDSA P-256 se guarda cifrada con una passphrase
(scrypt + AES-256-GCM). El certificado autofirmado es el ancla de confianza que
usan los estudiantes para verificar todo lo que la secretaría firma.
"""
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from .crypto import certs, keystore, signing
from .crypto.encoding import b64d, b64e, canonical
from .crypto.kdf import KdfParams
from .errors import AuthenticationError, IntegrityError, ValidationError
from .storage import JsonStore, ensure_dir

log = logging.getLogger("plancipher.secretaria")

KEY_AAD = b"plancipher/v1/secretaria-signing-key"
MIN_PASSPHRASE = 12


class TrustAnchor:
    """Lado público: verifica firmas de la secretaría con su certificado."""

    def __init__(self, cert):
        self.cert = cert
        self.public_key: ec.EllipticCurvePublicKey = cert.public_key()

    @classmethod
    def load(cls, data_dir: Path, expected_fingerprint: str | None = None) -> "TrustAnchor":
        pem_path = Path(data_dir) / "secretaria" / "cert.pem"
        try:
            pem = pem_path.read_bytes()
        except FileNotFoundError as exc:
            raise ValidationError("No existe la secretaría: ejecuta 'init-secretaria' primero") from exc
        cert = certs.load_trusted(pem, expected_fingerprint)
        log.debug("Ancla de confianza cargada, huella SHA-256 %s", certs.fingerprint(cert))
        return cls(cert)

    @property
    def fingerprint(self) -> str:
        return certs.fingerprint(self.cert)

    def verify(self, domain: str, obj, signature_b64: str) -> None:
        """Verifica la firma sobre la serialización canónica de `obj` (IntegrityError si falla)."""
        signing.verify(self.public_key, b64d(signature_b64), canonical(domain, obj))


class Secretaria:
    """Lado privado: requiere la passphrase para firmar."""

    def __init__(self, signing_key: ec.EllipticCurvePrivateKey, anchor: TrustAnchor):
        self._key = signing_key
        self.anchor = anchor

    @staticmethod
    def init(data_dir: Path, passphrase: str, params: KdfParams = KdfParams()) -> str:
        if len(passphrase) < MIN_PASSPHRASE:
            raise ValidationError(f"La passphrase debe tener al menos {MIN_PASSPHRASE} caracteres")
        sdir = ensure_dir(Path(data_dir) / "secretaria")
        key_store = JsonStore(sdir / "signing_key.json")
        if key_store.path.exists():
            raise ValidationError("La secretaría ya está inicializada")
        key = signing.generate_signing_key()
        key_store.save(keystore.protect(passphrase, signing.private_to_der(key), params, KEY_AAD))
        cert = certs.create_self_signed(key, "PlanCipher Secretaria")
        (sdir / "cert.pem").write_bytes(certs.to_pem(cert))
        return certs.fingerprint(cert)

    @classmethod
    def unlock(cls, data_dir: Path, passphrase: str, expected_fingerprint: str | None = None) -> "Secretaria":
        anchor = TrustAnchor.load(data_dir, expected_fingerprint)
        record = JsonStore(Path(data_dir) / "secretaria" / "signing_key.json").load(None)
        if record is None:
            raise ValidationError("Falta la clave de firma de la secretaría")
        try:
            der = keystore.unprotect(passphrase, record, KEY_AAD)
        except (KeyError, ValueError, TypeError) as exc:
            raise ValidationError("Fichero de clave de la secretaría malformado") from exc
        key = signing.private_from_der(der)
        # La clave descifrada debe corresponder al certificado de confianza.
        if key.public_key().public_numbers() != anchor.public_key.public_numbers():
            raise IntegrityError("La clave de firma no corresponde al certificado")
        return cls(key, anchor)

    def sign(self, domain: str, obj) -> str:
        return b64e(signing.sign(self._key, canonical(domain, obj)))
