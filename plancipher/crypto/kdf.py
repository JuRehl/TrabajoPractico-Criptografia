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

from ..errors import IntegrityError

log = logging.getLogger("plancipher.crypto.kdf")

SALT_LEN = 16  # 128 bits aleatorios por usuario

# Límites para parámetros LEÍDOS DE DISCO. Un fichero manipulado podría pedir valores
# inválidos (error no controlado) o enormes (memoria/CPU sin límite: DoS).
MIN_N = 2**10              # suelo usado en los tests; el valor real por defecto es 2^17
MAX_N = 2**20
MAX_R = 16
MAX_P = 4
MAX_MEMORY = 256 * 2**20   # scrypt usa ~128·r·n bytes; el valor por defecto usa 128 MiB


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
        """Lee parámetros guardados y los RECHAZA (IntegrityError) si están fuera de rango."""
        try:
            n, r, p = d["n"], d["r"], d["p"]
        except (KeyError, TypeError) as exc:
            raise IntegrityError("Parámetros de scrypt ausentes o malformados") from exc
        # Enteros estrictos: ni bool, ni float, ni texto ("131072" o 131072.5 no se aceptan).
        if not all(isinstance(v, int) and not isinstance(v, bool) for v in (n, r, p)):
            raise IntegrityError("Parámetros de scrypt con tipo inválido")
        if not (MIN_N <= n <= MAX_N and n & (n - 1) == 0):
            raise IntegrityError("Parámetro n de scrypt fuera de rango o no potencia de 2")
        if not (1 <= r <= MAX_R and 1 <= p <= MAX_P and 128 * r * n <= MAX_MEMORY):
            raise IntegrityError("Parámetros r/p de scrypt fuera de rango")
        return cls(n=n, r=r, p=p)


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
