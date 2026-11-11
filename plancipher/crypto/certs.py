"""Certificado X.509 autofirmado de la secretaría (ancla de confianza)."""
import datetime as dt

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from ..errors import IntegrityError


def create_self_signed(priv: ec.EllipticCurvePrivateKey, common_name: str, days: int = 730) -> x509.Certificate:
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = dt.datetime.now(dt.timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(priv.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_cert_sign=True, crl_sign=False, content_commitment=False,
                key_encipherment=False, data_encipherment=False, key_agreement=False,
                encipher_only=False, decipher_only=False,
            ),
            critical=True,
        )
        .sign(priv, hashes.SHA256())
    )


def to_pem(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def load_trusted(pem: bytes, expected_fingerprint: str | None = None) -> x509.Certificate:
    """Carga el ancla de confianza validando fechas, autofirma, tipo de clave y huella."""
    try:
        cert = x509.load_pem_x509_certificate(pem)
        now = dt.datetime.now(dt.timezone.utc)
        if not (cert.not_valid_before_utc <= now <= cert.not_valid_after_utc):
            raise IntegrityError("Certificado de la secretaría fuera de su periodo de validez")
        cert.verify_directly_issued_by(cert)
    except (ValueError, InvalidSignature, TypeError) as exc:
        raise IntegrityError("Certificado de la secretaría inválido") from exc
    pub = cert.public_key()
    if not (isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1)):
        raise IntegrityError("El certificado no contiene una clave ECDSA P-256")
    if expected_fingerprint and fingerprint(cert) != expected_fingerprint.lower().replace(":", ""):
        raise IntegrityError("La huella del certificado no coincide con la esperada")
    return cert
