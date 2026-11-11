"""Firma digital ECDSA con la curva P-256 (secp256r1) y SHA-256."""
import logging

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..errors import IntegrityError, ValidationError

log = logging.getLogger("plancipher.crypto.signing")


def generate_signing_key() -> ec.EllipticCurvePrivateKey:
    log.debug("ECDSA: generando clave privada P-256 (256 bits)")
    return ec.generate_private_key(ec.SECP256R1())


def sign(priv: ec.EllipticCurvePrivateKey, data: bytes) -> bytes:
    sig = priv.sign(data, ec.ECDSA(hashes.SHA256()))
    log.debug("ECDSA-P256-SHA256: firma generada (%d bytes DER)", len(sig))
    return sig


def verify(pub: ec.EllipticCurvePublicKey, signature: bytes, data: bytes) -> None:
    """Lanza IntegrityError si la firma no es válida; no devuelve nada si es válida."""
    try:
        pub.verify(signature, data, ec.ECDSA(hashes.SHA256()))
    except (InvalidSignature, ValueError) as exc:
        log.warning("ECDSA-P256-SHA256: firma INVÁLIDA -> datos rechazados")
        raise IntegrityError("Firma digital inválida") from exc
    log.debug("ECDSA-P256-SHA256: firma verificada OK")


def private_to_der(priv: ec.EllipticCurvePrivateKey) -> bytes:
    return priv.private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
    )


def private_from_der(der: bytes) -> ec.EllipticCurvePrivateKey:
    key = serialization.load_der_private_key(der, password=None)
    if not isinstance(key, ec.EllipticCurvePrivateKey) or not isinstance(key.curve, ec.SECP256R1):
        raise ValidationError("La clave de firma no es ECDSA P-256")
    return key
