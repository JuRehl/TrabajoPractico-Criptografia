"""Cifrado autenticado AES-256-GCM con AAD.

Formato: nonce(12) || ciphertext || tag(16). El nonce es aleatorio de 96 bits
(os.urandom) y se genera en cada cifrado. Cada registro usa su propia clave de
contenido, y la KEK cifra muy pocos mensajes, por lo que la probabilidad de
colisión de nonce es despreciable (límite NIST: 2^32 cifrados por clave).
"""
import logging
import os

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from ..errors import IntegrityError

log = logging.getLogger("plancipher.crypto.aead")

KEY_LEN = 32
NONCE_LEN = 12
TAG_LEN = 16


def new_key() -> bytes:
    return os.urandom(KEY_LEN)


def encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """Genera un nonce aleatorio de 12 bytes (96 bits) distinto en cada cifrado
    (AES-256-GCM, tag de 16 bytes)."""
    if len(key) != KEY_LEN:
        raise ValueError("La clave AES-256 debe tener 32 bytes")
    nonce = os.urandom(NONCE_LEN)
    ct = AESGCM(key).encrypt(nonce, plaintext, aad)
    log.debug("AES-256-GCM cifrar: clave=256 bits nonce=96 bits aad=%dB ct=%dB", len(aad), len(ct))
    return nonce + ct


def decrypt(key: bytes, blob: bytes, aad: bytes) -> bytes:
    """Descifra y verifica el tag: cualquier modificación (nonce, ct, tag o AAD) -> IntegrityError."""
    if len(key) != KEY_LEN:
        raise ValueError("La clave AES-256 debe tener 32 bytes")
    if len(blob) < NONCE_LEN + TAG_LEN:
        raise IntegrityError("Cifrado demasiado corto")
    nonce, ct = blob[:NONCE_LEN], blob[NONCE_LEN:]
    try:
        pt = AESGCM(key).decrypt(nonce, ct, aad)
    except InvalidTag as exc:
        log.warning("AES-256-GCM (clave=256 bits): tag de autenticación de 128 bits INVÁLIDO -> datos rechazados")
        raise IntegrityError("Tag de autenticación inválido (datos manipulados o clave incorrecta)") from exc
    log.debug("AES-256-GCM descifrar: clave=256 bits nonce=96 bits tag=128 bits verificado OK (pt=%dB)", len(pt))
    return pt
