"""Registro y autenticación de usuarios (algo que se sabe: contraseña).

Almacenamiento: scrypt(contraseña, sal) -> HKDF -> {verificador, KEK}. Solo se
guarda el verificador; la KEK se recalcula en cada login y protege la clave
privada X25519 del usuario. Un atacante con el fichero de usuarios debe pagar
el coste de scrypt por cada intento y no obtiene la KEK.
"""
import logging
import re
import time
from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .crypto import aead, hybrid, kdf
from .crypto.encoding import b64d, b64e
from .errors import AuthenticationError, IntegrityError, LockedError, ValidationError
from .storage import JsonStore

log = logging.getLogger("plancipher.auth")

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")
RESERVED = {"secretaria", "admin", "root", "system"}  # el rol de secretaría no se obtiene por nombre
MIN_PASSWORD = 12
MAX_FAILED = 5
LOCK_BASE_SECONDS = 30
LOCK_MAX_SECONDS = 900
GENERIC_LOGIN_ERROR = "Usuario o contraseña incorrectos"


def _key_aad(username: str) -> bytes:
    return b"plancipher/v1/userkey|" + username.encode()


@dataclass
class Session:
    """Material desbloqueado durante UN comando. No se persiste."""

    username: str
    kek: bytes
    private_key: X25519PrivateKey
    public_key: X25519PublicKey


def validate_username(username: str) -> str:
    if not isinstance(username, str) or not USERNAME_RE.fullmatch(username):
        raise ValidationError("Usuario inválido: 3-32 caracteres [a-z0-9_.-], sin empezar por símbolo")
    return username


def validate_password(username: str, password: str) -> None:
    if len(password) < MIN_PASSWORD:
        raise ValidationError(f"La contraseña debe tener al menos {MIN_PASSWORD} caracteres")
    if username.lower() in password.lower():
        raise ValidationError("La contraseña no puede contener el nombre de usuario")
    if len(set(password)) < 5:
        raise ValidationError("La contraseña es demasiado repetitiva")


class UserService:
    def __init__(self, store: JsonStore, params: kdf.KdfParams = kdf.KdfParams(), clock=time.time):
        self.store = store
        self.params = params
        self.clock = clock

    # --- acceso a datos -------------------------------------------------
    def _all(self) -> dict:
        data = self.store.load({})
        if not isinstance(data, dict):
            raise ValidationError("Fichero de usuarios con formato inválido")
        return data

    def get(self, username: str) -> dict | None:
        return self._all().get(username)

    # --- registro -------------------------------------------------------
    def register(self, username: str, password: str) -> None:
        validate_username(username)
        if username in RESERVED:
            raise ValidationError("Nombre de usuario reservado")
        validate_password(username, password)
        users = self._all()
        if username in users:
            raise ValidationError("El usuario ya existe")
        salt = kdf.new_salt()
        verifier, kek = kdf.derive_subkeys(password, salt, self.params)
        priv, pub = hybrid.generate_keypair()
        users[username] = {
            "kdf": self.params.to_dict(),
            "salt": b64e(salt),
            "verifier": b64e(verifier),
            "pub": b64e(hybrid.public_to_bytes(pub)),
            "enc_priv": b64e(aead.encrypt(kek, hybrid.private_to_bytes(priv), _key_aad(username))),
            "failed": 0,
            "locked_until": 0,
            "enrollment": None,
        }
        self.store.save(users)
        log.info("Usuario '%s' registrado (scrypt n=%d, X25519)", username, self.params.n)

    # --- login ----------------------------------------------------------
    def login(self, username: str, password: str) -> Session:
        users = self._all()
        rec = users.get(username) if isinstance(username, str) else None
        if rec is None:
            # Coste equivalente al de un usuario real: no revela si el usuario existe por tiempo.
            kdf.derive_subkeys(password, b"\x00" * kdf.SALT_LEN, self.params)
            raise AuthenticationError(GENERIC_LOGIN_ERROR)

        now = self.clock()
        if rec["locked_until"] > now:
            raise LockedError(f"Cuenta bloqueada temporalmente. Reintenta en {int(rec['locked_until'] - now) + 1} s")

        params = kdf.KdfParams.from_dict(rec["kdf"])
        verifier, kek = kdf.derive_subkeys(password, b64d(rec["salt"]), params)
        if not kdf.constant_time_equal(verifier, b64d(rec["verifier"])):
            rec["failed"] += 1
            if rec["failed"] >= MAX_FAILED:
                delay = min(LOCK_MAX_SECONDS, LOCK_BASE_SECONDS * 2 ** (rec["failed"] - MAX_FAILED))
                rec["locked_until"] = now + delay
                log.warning("Usuario '%s' bloqueado %d s tras %d fallos", username, delay, rec["failed"])
            self.store.save(users)
            raise AuthenticationError(GENERIC_LOGIN_ERROR)

        try:
            priv = hybrid.private_from_bytes(aead.decrypt(kek, b64d(rec["enc_priv"]), _key_aad(username)))
        except IntegrityError as exc:
            raise IntegrityError("La clave privada del usuario está manipulada") from exc
        if rec["failed"] or rec["locked_until"]:
            rec["failed"], rec["locked_until"] = 0, 0
            self.store.save(users)
        log.info("Login correcto de '%s'", username)
        return Session(username, kek, priv, priv.public_key())

    # --- matrícula firmada ---------------------------------------------
    def set_enrollment(self, username: str, signature_b64: str) -> None:
        users = self._all()
        if username not in users:
            raise ValidationError("Usuario inexistente")
        users[username]["enrollment"] = signature_b64
        self.store.save(users)
