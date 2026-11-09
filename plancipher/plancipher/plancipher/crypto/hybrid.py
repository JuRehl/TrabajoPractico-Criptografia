"""Cifrado híbrido tipo ECIES: X25519 efímero + HKDF-SHA256 + AES-256-GCM.

Permite a la secretaría entregar una clave de contenido a un estudiante usando
solo su clave pública. El remitente genera un par X25519 efímero por mensaje,
por lo que la clave simétrica derivada es siempre distinta.
"""
import logging

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..errors import IntegrityError, ValidationError
from . import aead

log = logging.getLogger("plancipher.crypto.hybrid")

PUB_LEN = 32


def generate_keypair() -> tuple[X25519PrivateKey, X25519PublicKey]:
    priv = X25519PrivateKey.generate()
    log.debug("X25519: par de claves generado (255 bits)")
    return priv, priv.public_key()


def private_to_bytes(priv: X25519PrivateKey) -> bytes:
    return priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def private_from_bytes(raw: bytes) -> X25519PrivateKey:
    return X25519PrivateKey.from_private_bytes(raw)


def public_to_bytes(pub: X25519PublicKey) -> bytes:
    return pub.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def public_from_bytes(raw: bytes) -> X25519PublicKey:
    if len(raw) != PUB_LEN:
        raise ValidationError("Clave pública X25519 con longitud inválida")
    return X25519PublicKey.from_public_bytes(raw)


def _derive(shared: bytes, eph_pub: bytes, recipient_pub: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(), length=32, salt=eph_pub + recipient_pub, info=b"plancipher/v1/seal"
    ).derive(shared)


def seal(recipient: X25519PublicKey, plaintext: bytes, aad: bytes) -> bytes:
    eph = X25519PrivateKey.generate()
    eph_pub = public_to_bytes(eph.public_key())
    key = _derive(eph.exchange(recipient), eph_pub, public_to_bytes(recipient))
    log.debug("ECIES(X25519+HKDF-SHA256+AES-256-GCM): sellado para destinatario")
    return eph_pub + aead.encrypt(key, plaintext, aad)


def open_sealed(priv: X25519PrivateKey, blob: bytes, aad: bytes) -> bytes:
    if len(blob) < PUB_LEN + aead.NONCE_LEN + aead.TAG_LEN:
        raise IntegrityError("Sobre cifrado demasiado corto")
    eph_pub, body = blob[:PUB_LEN], blob[PUB_LEN:]
    try:
        shared = priv.exchange(X25519PublicKey.from_public_bytes(eph_pub))
    except ValueError as exc:  # punto de orden bajo -> secreto compartido nulo
        raise IntegrityError("Clave efímera inválida") from exc
    key = _derive(shared, eph_pub, public_to_bytes(priv.public_key()))
    return aead.decrypt(key, body, aad)
