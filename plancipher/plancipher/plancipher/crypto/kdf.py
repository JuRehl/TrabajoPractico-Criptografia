"""Derivación de claves a partir de contraseñas: scrypt + HKDF-SHA256.

Una única ejecución de scrypt produce una clave maestra; HKDF con etiquetas
distintas separa (a) el verificador de autenticación, que se guarda, y (b) la
KEK que protege las claves del usuario, que NUNCA se guarda.
"""
import hmac
import logging
import os
import unicodedata
from dataclasses import asdict, dataclass

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

log = logging.getLogger("plancipher.crypto.kdf")

SALT_LEN = 16  # 128 bits aleatorios por usuario


@dataclass(frozen=True)
class KdfParams:
    """Parámetros de scrypt (n=2^17, r=8, p=1: recomendación OWASP, ~128 MiB)."""

    n: int = 2**17
    r: int = 8
    p: int = 1

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "KdfParams":
        return cls(n=int(d["n"]), r=int(d["r"]), p=int(d["p"]))


def new_salt() -> bytes:
    return os.urandom(SALT_LEN)


def _normalize(password: str) -> bytes:
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def derive_master(password: str, salt: bytes, params: KdfParams) -> bytes:
    log.debug("scrypt: n=%d r=%d p=%d salt=%d bytes -> 256 bits", params.n, params.r, params.p, len(salt))
    return Scrypt(salt=salt, length=32, n=params.n, r=params.r, p=params.p).derive(_normalize(password))


def _hkdf(master: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(master)


def derive_subkeys(password: str, salt: bytes, params: KdfParams) -> tuple[bytes, bytes]:
    """Devuelve (verificador_de_login, KEK)."""
    master = derive_master(password, salt, params)
    return _hkdf(master, b"plancipher/v1/auth"), _hkdf(master, b"plancipher/v1/kek")


def constant_time_equal(a: bytes, b: bytes) -> bool:
    return hmac.compare_digest(a, b)
