"""PKI de dos niveles con X.509: AC raíz -> AC subordinada (secretaría).

* AC raíz: certificado autofirmado (CA, pathLen=1, keyCertSign + cRLSign). Es la única
  ancla de confianza; su clave solo se usa para emitir el certificado de la subordinada
  y la CRL. Su huella SHA-256 es la que se fija con --trust-fingerprint.
* AC subordinada (secretaría): certificado emitido por la raíz (CA, pathLen=0,
  digitalSignature + keyCertSign + cRLSign). Su clave firma matrículas, plan y notas.
* CRL firmada por la raíz: permite revocar el certificado de la subordinada.
* Estudiantes (entidad final): la secretaría emite un certificado X.509 que liga el
  nombre de usuario (CN) con su clave pública X25519 (CA=false, solo keyAgreement).
"""
import datetime as dt

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey
from cryptography.x509.oid import NameOID

from ..errors import IntegrityError

ROOT_DAYS = 3650
SUB_DAYS = 730
STUDENT_DAYS = 365
CRL_DAYS = 365


def _name(common_name: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "PlanCipher"),
                      x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _key_usage(*, digital_signature: bool, key_cert_sign: bool, crl_sign: bool) -> x509.KeyUsage:
    return x509.KeyUsage(digital_signature=digital_signature, key_cert_sign=key_cert_sign, crl_sign=crl_sign,
                         content_commitment=False, key_encipherment=False, data_encipherment=False,
                         key_agreement=False, encipher_only=False, decipher_only=False)


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def create_root(priv: ec.EllipticCurvePrivateKey, common_name: str = "PlanCipher AC Raiz",
                days: int = ROOT_DAYS) -> x509.Certificate:
    """Certificado autofirmado de la AC raíz (10 años). Solo firma certificados y CRL."""
    name, now, pub = _name(common_name), _now(), priv.public_key()
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name).public_key(pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(_key_usage(digital_signature=False, key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(pub), critical=False)
        .sign(priv, hashes.SHA256())
    )


def issue_subordinate(root_priv: ec.EllipticCurvePrivateKey, root_cert: x509.Certificate,
                      sub_pub: ec.EllipticCurvePublicKey, common_name: str = "PlanCipher Secretaria",
                      days: int = SUB_DAYS) -> x509.Certificate:
    """La AC raíz emite el certificado de la AC subordinada (2 años, sin superar a la raíz)."""
    now = _now()
    not_after = min(now + dt.timedelta(days=days), root_cert.not_valid_after_utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(common_name)).issuer_name(root_cert.subject).public_key(sub_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(_key_usage(digital_signature=True, key_cert_sign=True, crl_sign=True), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(sub_pub), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(root_cert.public_key()), critical=False)
        .sign(root_priv, hashes.SHA256())
    )


def issue_student(sub_priv: ec.EllipticCurvePrivateKey, sub_cert: x509.Certificate,
                  student_pub: X25519PublicKey, username: str, days: int = STUDENT_DAYS) -> x509.Certificate:
    """La secretaría (AC subordinada) certifica la clave X25519 de un estudiante (1 año)."""
    now = _now()
    not_after = min(now + dt.timedelta(days=days), sub_cert.not_valid_after_utc)
    return (
        x509.CertificateBuilder()
        .subject_name(_name(username)).issuer_name(sub_cert.subject).public_key(student_pub)
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, key_cert_sign=False, crl_sign=False,
                                     content_commitment=False, key_encipherment=False, data_encipherment=False,
                                     key_agreement=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(student_pub), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(sub_cert.public_key()), critical=False)
        .sign(sub_priv, hashes.SHA256())
    )


def create_crl(root_priv: ec.EllipticCurvePrivateKey, root_cert: x509.Certificate,
               revoked_serials: list[int] = (), days: int = CRL_DAYS) -> x509.CertificateRevocationList:
    """CRL firmada por la AC raíz con los números de serie revocados."""
    now = _now()
    builder = (x509.CertificateRevocationListBuilder().issuer_name(root_cert.subject)
               .last_update(now - dt.timedelta(minutes=1)).next_update(now + dt.timedelta(days=days)))
    for serial in revoked_serials:
        builder = builder.add_revoked_certificate(
            x509.RevokedCertificateBuilder().serial_number(serial).revocation_date(now).build())
    return builder.sign(root_priv, hashes.SHA256())


def to_pem(obj: x509.Certificate | x509.CertificateRevocationList) -> bytes:
    return obj.public_bytes(serialization.Encoding.PEM)


def fingerprint(cert: x509.Certificate) -> str:
    return cert.fingerprint(hashes.SHA256()).hex()


def _parse_cert(pem: bytes, what: str) -> x509.Certificate:
    try:
        return x509.load_pem_x509_certificate(pem)
    except (ValueError, TypeError) as exc:
        raise IntegrityError(f"Certificado de la {what} inválido") from exc


def _check_validity(cert: x509.Certificate, what: str) -> None:
    if not (cert.not_valid_before_utc <= _now() <= cert.not_valid_after_utc):
        raise IntegrityError(f"Certificado de la {what} fuera de su periodo de validez")


def _check_p256(cert: x509.Certificate, what: str) -> None:
    pub = cert.public_key()
    if not (isinstance(pub, ec.EllipticCurvePublicKey) and isinstance(pub.curve, ec.SECP256R1)):
        raise IntegrityError(f"El certificado de la {what} no contiene una clave ECDSA P-256")


def _extensions(cert: x509.Certificate, what: str) -> tuple[x509.BasicConstraints, x509.KeyUsage]:
    try:
        return (cert.extensions.get_extension_for_class(x509.BasicConstraints).value,
                cert.extensions.get_extension_for_class(x509.KeyUsage).value)
    except x509.ExtensionNotFound as exc:
        raise IntegrityError(f"Al certificado de la {what} le faltan basicConstraints o keyUsage") from exc


def _verify_issued_by(cert: x509.Certificate, issuer: x509.Certificate, what: str) -> None:
    try:
        cert.verify_directly_issued_by(issuer)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise IntegrityError(f"El certificado de la {what} no está firmado por la AC raíz") from exc


def load_root(pem: bytes, expected_fingerprint: str | None = None) -> x509.Certificate:
    """Carga y valida el ancla de confianza (AC raíz)."""
    what = "AC raíz"
    cert = _parse_cert(pem, what)
    _check_validity(cert, what)
    if cert.issuer != cert.subject:
        raise IntegrityError("La AC raíz debe ser autofirmada")
    try:
        cert.verify_directly_issued_by(cert)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise IntegrityError("La autofirma de la AC raíz no es válida") from exc
    bc, ku = _extensions(cert, what)
    if not bc.ca:
        raise IntegrityError("La AC raíz no es una autoridad (basicConstraints: CA=false)")
    if bc.path_length is not None and bc.path_length < 1:
        raise IntegrityError("La AC raíz no puede emitir autoridades subordinadas (pathLen=0)")
    if not (ku.key_cert_sign and ku.crl_sign):
        raise IntegrityError("keyUsage de la AC raíz no permite firmar certificados y CRL")
    _check_p256(cert, what)
    if expected_fingerprint and fingerprint(cert) != expected_fingerprint.lower().replace(":", ""):
        raise IntegrityError("La huella de la AC raíz no coincide con la esperada")
    return cert


def load_crl(pem: bytes, root: x509.Certificate) -> x509.CertificateRevocationList:
    """Carga la CRL y comprueba que la firmó la AC raíz y que está vigente."""
    try:
        crl = x509.load_pem_x509_crl(pem)
    except (ValueError, TypeError) as exc:
        raise IntegrityError("CRL inválida") from exc
    if crl.issuer != root.subject or not crl.is_signature_valid(root.public_key()):
        raise IntegrityError("La CRL no está firmada por la AC raíz")
    if crl.next_update_utc is None or _now() > crl.next_update_utc:
        raise IntegrityError("La CRL ha caducado: la AC raíz debe emitir una nueva")
    return crl


def verify_subordinate(pem: bytes, root: x509.Certificate,
                       crl: x509.CertificateRevocationList) -> x509.Certificate:
    """Valida la cadena AC subordinada -> AC raíz y su estado de revocación."""
    what = "secretaría"
    cert = _parse_cert(pem, what)
    if cert.issuer != root.subject:
        raise IntegrityError("El emisor del certificado de la secretaría no es la AC raíz")
    _verify_issued_by(cert, root, what)
    _check_validity(cert, what)
    if cert.not_valid_after_utc > root.not_valid_after_utc:
        raise IntegrityError("El certificado de la secretaría caduca después que la AC raíz")
    bc, ku = _extensions(cert, what)
    if not bc.ca or bc.path_length != 0:
        raise IntegrityError("La secretaría debe ser AC subordinada con pathLen=0")
    if not ku.digital_signature:
        raise IntegrityError("keyUsage de la secretaría no permite firmar datos")
    _check_p256(cert, what)
    if crl.get_revoked_certificate_by_serial_number(cert.serial_number) is not None:
        raise IntegrityError("El certificado de la secretaría está REVOCADO (CRL de la AC raíz)")
    return cert


def verify_student(pem: bytes, sub_cert: x509.Certificate, username: str) -> X25519PublicKey:
    """Valida el certificado de un estudiante emitido por la secretaría y devuelve su clave X25519."""
    what = "estudiante"
    cert = _parse_cert(pem, what)
    if cert.issuer != sub_cert.subject:
        raise IntegrityError("El certificado del estudiante no lo emitió la secretaría")
    try:
        cert.verify_directly_issued_by(sub_cert)
    except (ValueError, TypeError, InvalidSignature) as exc:
        raise IntegrityError("La firma del certificado del estudiante no es de la secretaría") from exc
    _check_validity(cert, what)
    bc, ku = _extensions(cert, what)
    if bc.ca or not ku.key_agreement or ku.digital_signature or ku.key_cert_sign:
        raise IntegrityError("El certificado del estudiante debe ser de entidad final y solo keyAgreement")
    names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if len(names) != 1 or names[0].value != username:
        raise IntegrityError("El certificado pertenece a otro estudiante")
    pub = cert.public_key()
    if not isinstance(pub, X25519PublicKey):
        raise IntegrityError("El certificado del estudiante no contiene una clave X25519")
    return pub
