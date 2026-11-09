"""Protección de secretos con passphrase: scrypt -> AES-256-GCM.

Se usa para la clave privada de firma de la secretaría. El fichero guardado
contiene solo sal, parámetros y el cifrado autenticado; nunca la clave en claro.
"""
import logging

from ..errors import AuthenticationError, IntegrityError
from . import aead, kdf
from .encoding import b64d, b64e

log = logging.getLogger("plancipher.crypto.keystore")


def protect(passphrase: str, secret: bytes, params: kdf.KdfParams, aad: bytes) -> dict:
    salt = kdf.new_salt()
    key = kdf.derive_master(passphrase, salt, params)
    return {"kdf": "scrypt", **params.to_dict(), "salt": b64e(salt), "blob": b64e(aead.encrypt(key, secret, aad))}


def unprotect(passphrase: str, record: dict, aad: bytes) -> bytes:
    params = kdf.KdfParams.from_dict(record)
    key = kdf.derive_master(passphrase, b64d(record["salt"]), params)
    try:
        return aead.decrypt(key, b64d(record["blob"]), aad)
    except IntegrityError as exc:
        raise AuthenticationError("Passphrase incorrecta o fichero de clave manipulado") from exc
