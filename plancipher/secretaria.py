"""PKI y secretaría: AC raíz (ancla de confianza) -> AC subordinada (secretaría).

* La AC raíz tiene su propia clave ECDSA P-256 protegida con OTRA passphrase
  (scrypt + AES-256-GCM). Solo se usa para emitir el certificado de la secretaría
  y la CRL; en un despliegue real estaría offline.
* La secretaría (AC subordinada) firma matrículas, plan de estudios y notas. Su clave
  privada también se guarda cifrada con su propia passphrase.
* Los estudiantes solo confían en la AC raíz: validan la cadena secretaría -> raíz y la
  CRL antes de aceptar cualquier firma.

Ficheros:  pki/root_cert.pem, pki/root_key.json, pki/crl.pem,
           secretaria/cert.pem, secretaria/signing_key.json
"""
import logging
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric import ec

from .crypto import certs, keystore, signing
from .crypto.encoding import b64d, b64e, canonical
from .crypto.kdf import KdfParams
from .errors import IntegrityError, ValidationError
from .password_policy import is_common_password
from .storage import JsonStore, ensure_dir

log = logging.getLogger("plancipher.secretaria")

KEY_AAD = b"plancipher/v1/secretaria-signing-key"
ROOT_KEY_AAD = b"plancipher/v1/root-ca-key"
MIN_PASSPHRASE = 12


def _paths(data_dir: Path) -> dict[str, Path]:
    d = Path(data_dir)
    return {"root_cert": d / "pki" / "root_cert.pem", "root_key": d / "pki" / "root_key.json",
            "crl": d / "pki" / "crl.pem", "sub_cert": d / "secretaria" / "cert.pem",
            "sub_key": d / "secretaria" / "signing_key.json"}


def _check_passphrase(passphrase: str, what: str) -> None:
    if len(passphrase) < MIN_PASSPHRASE:
        raise ValidationError(f"La passphrase de la {what} debe tener al menos {MIN_PASSPHRASE} caracteres")
    if is_common_password(passphrase):
        raise ValidationError(f"La passphrase de la {what} es demasiado común (aparece en listas de diccionario)")


def _unlock_key(path: Path, passphrase: str, aad: bytes, what: str) -> ec.EllipticCurvePrivateKey:
    record = JsonStore(path).load(None)
    if record is None:
        raise ValidationError(f"Falta la clave privada de la {what}")
    try:
        der = keystore.unprotect(passphrase, record, aad)
    except (KeyError, ValueError, TypeError) as exc:
        raise ValidationError(f"Fichero de clave de la {what} malformado") from exc
    return signing.private_from_der(der)


def _same_key(priv: ec.EllipticCurvePrivateKey, cert) -> bool:
    return priv.public_key().public_numbers() == cert.public_key().public_numbers()


class TrustAnchor:
    """Lado público: valida la cadena secretaría -> AC raíz y verifica firmas de la secretaría."""

    def __init__(self, root, cert, crl):
        self.root = root
        self.cert = cert                # certificado de la AC subordinada (secretaría)
        self.crl = crl
        self.public_key: ec.EllipticCurvePublicKey = cert.public_key()

    @classmethod
    def load(cls, data_dir: Path, expected_fingerprint: str | None = None) -> "TrustAnchor":
        p = _paths(data_dir)
        try:
            root_pem, crl_pem, sub_pem = (p["root_cert"].read_bytes(), p["crl"].read_bytes(),
                                          p["sub_cert"].read_bytes())
        except FileNotFoundError as exc:
            raise ValidationError("No existe la PKI de la secretaría: ejecuta 'init-secretaria' primero") from exc
        root = certs.load_root(root_pem, expected_fingerprint)
        crl = certs.load_crl(crl_pem, root)
        cert = certs.verify_subordinate(sub_pem, root, crl)
        log.debug("Cadena X.509 verificada: secretaría (serie %x) -> AC raíz (huella SHA-256 %s); CRL con %d revocados",
                  cert.serial_number, certs.fingerprint(root), len(crl))
        return cls(root, cert, crl)

    @property
    def fingerprint(self) -> str:
        """Huella de la AC raíz: es lo que se fija (pinning) con --trust-fingerprint."""
        return certs.fingerprint(self.root)

    @property
    def secretaria_fingerprint(self) -> str:
        return certs.fingerprint(self.cert)

    def verify_student(self, username: str, pem: str):
        """Valida la cadena estudiante -> secretaría (-> raíz, ya validada) y devuelve su clave X25519."""
        if not isinstance(pem, str):
            raise IntegrityError("Certificado del estudiante malformado")
        return certs.verify_student(pem.encode("ascii", "replace"), self.cert, username)

    def verify(self, domain: str, obj, signature_b64: str) -> None:
        """Verifica la firma sobre la serialización canónica de `obj`"""
        signing.verify(self.public_key, b64d(signature_b64), canonical(domain, obj))


class Secretaria:
    """Lado privado: requiere la passphrase de la secretaría para firmar."""

    def __init__(self, signing_key: ec.EllipticCurvePrivateKey, anchor: TrustAnchor):
        self._key = signing_key
        self.anchor = anchor

    @staticmethod
    def init(data_dir: Path, passphrase: str, params: KdfParams = KdfParams(), *, root_passphrase: str) -> str:
        """Crea la AC raíz, la AC subordinada (secretaría) y una CRL vacía.
        Devuelve la huella SHA-256 de la AC raíz."""
        _check_passphrase(passphrase, "secretaría")
        _check_passphrase(root_passphrase, "AC raíz")
        if passphrase == root_passphrase:
            raise ValidationError("La passphrase de la AC raíz debe ser distinta de la de la secretaría")
        p = _paths(data_dir)
        if p["sub_key"].exists() or p["root_key"].exists():
            raise ValidationError("La secretaría ya está inicializada")
        ensure_dir(p["root_cert"].parent)
        ensure_dir(p["sub_cert"].parent)

        root_key = signing.generate_signing_key()
        root = certs.create_root(root_key)
        JsonStore(p["root_key"]).save(keystore.protect(root_passphrase, signing.private_to_der(root_key),
                                                       params, ROOT_KEY_AAD))
        p["root_cert"].write_bytes(certs.to_pem(root))

        key = signing.generate_signing_key()
        JsonStore(p["sub_key"]).save(keystore.protect(passphrase, signing.private_to_der(key), params, KEY_AAD))
        p["sub_cert"].write_bytes(certs.to_pem(certs.issue_subordinate(root_key, root, key.public_key())))
        p["crl"].write_bytes(certs.to_pem(certs.create_crl(root_key, root)))
        log.debug("PKI creada: AC raíz + AC subordinada (secretaría) + CRL vacía")
        return certs.fingerprint(root)

    @staticmethod
    def revoke(data_dir: Path, root_passphrase: str) -> int:
        """[AC raíz] Revoca el certificado actual de la secretaría publicando una CRL nueva.
        Devuelve el número de serie revocado."""
        p = _paths(data_dir)
        root = certs.load_root(p["root_cert"].read_bytes())
        root_key = _unlock_key(p["root_key"], root_passphrase, ROOT_KEY_AAD, "AC raíz")
        if not _same_key(root_key, root):
            raise IntegrityError("La clave de la AC raíz no corresponde a su certificado")
        crl = certs.load_crl(p["crl"].read_bytes(), root)
        serial = certs.verify_subordinate(p["sub_cert"].read_bytes(), root, crl).serial_number
        revoked = [r.serial_number for r in crl] + [serial]
        p["crl"].write_bytes(certs.to_pem(certs.create_crl(root_key, root, revoked)))
        return serial

    @classmethod
    def unlock(cls, data_dir: Path, passphrase: str, expected_fingerprint: str | None = None) -> "Secretaria":
        anchor = TrustAnchor.load(data_dir, expected_fingerprint)
        key = _unlock_key(_paths(data_dir)["sub_key"], passphrase, KEY_AAD, "secretaría")
        # Confirmación de que la clave descifrada corresponde al certificado de la cadena
        if not _same_key(key, anchor.cert):
            raise IntegrityError("La clave de firma no corresponde al certificado")
        return cls(key, anchor)

    def certify_student(self, username: str, student_pub) -> str:
        """Emite el certificado X.509 (PEM) que liga `username` con su clave pública X25519."""
        cert = certs.issue_student(self._key, self.anchor.cert, student_pub, username)
        log.debug("Certificado X.509 de estudiante emitido para '%s' (serie %x, X25519 255 bits)",
                  username, cert.serial_number)
        return certs.to_pem(cert).decode("ascii")

    def sign(self, domain: str, obj) -> str:
        return b64e(signing.sign(self._key, canonical(domain, obj)))
