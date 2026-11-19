"""Registro y autenticación de usuarios (algo que se sabe: contraseña).

Almacenamiento: scrypt(contraseña, sal) -> HKDF -> {verificador, KEK}. Solo se
guarda el verificador; la KEK se recalcula en cada login y protege la clave
privada X25519 del usuario.

Recuperación: al registrarse se genera un código de recuperación aleatorio (160 bits)
que se muestra una sola vez. Con él se guarda una segunda copia de la KEK cifrada
(HKDF(código) -> AES-256-GCM). Si el usuario olvida la contraseña, el código descifra
la KEK antigua, se fija una contraseña nueva, se vuelven a cifrar la clave privada y el
planning con la KEK nueva y se emite un código nuevo (el anterior deja de valer).
"""
import base64
import binascii
import logging
import os
import re
import time
from dataclasses import dataclass
from typing import Callable

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey

from .crypto import aead, hybrid, kdf
from .crypto.encoding import b64d, b64e
from .errors import AuthenticationError, IntegrityError, LockedError, ValidationError
from .password_policy import is_common_password
from .storage import JsonStore

log = logging.getLogger("plancipher.auth")

USERNAME_RE = re.compile(r"^[a-z0-9][a-z0-9_.-]{2,31}$")
RESERVED = {"secretaria", "admin", "root", "system"}  
MIN_PASSWORD = 12
MAX_FAILED = 5
LOCK_BASE_SECONDS = 30
LOCK_MAX_SECONDS = 900
GENERIC_LOGIN_ERROR = "Usuario o contraseña incorrectos"
GENERIC_RECOVERY_ERROR = "Usuario o código de recuperación incorrectos"
RECOVERY_BYTES = 20  # 160 bits -> 32 caracteres base32 (8 grupos de 4)


def _key_aad(username: str) -> bytes:
    return b"plancipher/v1/userkey|" + username.encode()


def _recovery_aad(username: str) -> bytes:
    return b"plancipher/v1/recovery|" + username.encode()


def _format_code(raw: bytes) -> str:
    text = base64.b32encode(raw).decode("ascii")
    return "-".join(text[i:i + 4] for i in range(0, len(text), 4))


def _parse_code(code: str) -> bytes:
    """Acepta el código con o sin guiones/espacios y en minúsculas."""
    if not isinstance(code, str):
        raise AuthenticationError(GENERIC_RECOVERY_ERROR)
    text = code.upper().replace("-", "").replace(" ", "")
    try:
        raw = base64.b32decode(text)
    except (binascii.Error, ValueError) as exc:
        raise AuthenticationError(GENERIC_RECOVERY_ERROR) from exc
    if len(raw) != RECOVERY_BYTES:
        raise AuthenticationError(GENERIC_RECOVERY_ERROR)
    return raw


def _new_recovery(username: str, kek: bytes) -> tuple[str, dict]:
    """Genera un código de recuperación y la copia de la KEK cifrada con él."""
    raw, salt = os.urandom(RECOVERY_BYTES), kdf.new_salt()
    key = kdf.derive_recovery_key(raw, salt)
    record = {"salt": b64e(salt), "enc_kek": b64e(aead.encrypt(key, kek, _recovery_aad(username)))}
    return _format_code(raw), record


@dataclass
class Session:

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
    if is_common_password(password):
        raise ValidationError("La contraseña es demasiado común (aparece en listas de diccionario)")


class UserService:
    def __init__(self, store: JsonStore, params: kdf.KdfParams = kdf.KdfParams(), clock=time.time):
        self.store = store
        self.params = params
        self.clock = clock

    # Acceso a datos 
    def _all(self) -> dict:
        data = self.store.load({})
        if not isinstance(data, dict):
            raise ValidationError("Fichero de usuarios con formato inválido")
        return data

    def get(self, username: str) -> dict | None:
        return self._all().get(username)

    def usernames(self) -> list[str]:
        return sorted(self._all())

    # Registro
    def register(self, username: str, password: str) -> str:
        """Registra al usuario y devuelve su código de recuperación (mostrarlo UNA vez)."""
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
        }
        code, users[username]["recovery"] = _new_recovery(username, kek)
        self.store.save(users)
        log.info("Usuario '%s' registrado (scrypt n=%d, X25519, código de recuperación de %d bits)",
                 username, self.params.n, RECOVERY_BYTES * 8)
        return code

    # Login
    def login(self, username: str, password: str) -> Session:
        users = self._all()
        rec = users.get(username) if isinstance(username, str) else None
        if rec is None:
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

    # Recuperación de contraseña
    def recover(self, username: str, code: str, new_password: str,
                rekey: Callable[[str, bytes, bytes], None] = lambda user, old, new: None) -> tuple[Session, str]:
        """Fija una contraseña nueva usando el código de recuperación.

        `rekey(usuario, kek_antigua, kek_nueva)` vuelve a envolver los datos cifrados con
        la KEK (el planning). Se llama ANTES de guardar el usuario. Devuelve la sesión
        nueva y el código de recuperación nuevo; el anterior deja de valer."""
        if not isinstance(username, str):
            raise AuthenticationError(GENERIC_RECOVERY_ERROR)
        validate_password(username, new_password)
        raw = _parse_code(code)
        users = self._all()
        rec = users.get(username)
        if rec is None or not isinstance(rec.get("recovery"), dict):
            raise AuthenticationError(GENERIC_RECOVERY_ERROR)  # mismo mensaje: no revela si existe
        try:
            key = kdf.derive_recovery_key(raw, b64d(rec["recovery"]["salt"]))
            old_kek = aead.decrypt(key, b64d(rec["recovery"]["enc_kek"]), _recovery_aad(username))
        except IntegrityError as exc:
            log.warning("Recuperación fallida para '%s': código incorrecto o datos manipulados", username)
            raise AuthenticationError(GENERIC_RECOVERY_ERROR) from exc
        except (KeyError, TypeError) as exc:
            raise ValidationError("Datos de recuperación malformados") from exc
        try:
            priv = hybrid.private_from_bytes(aead.decrypt(old_kek, b64d(rec["enc_priv"]), _key_aad(username)))
        except IntegrityError as exc:
            raise IntegrityError("La clave privada del usuario está manipulada") from exc

        salt = kdf.new_salt()
        verifier, kek = kdf.derive_subkeys(new_password, salt, self.params)
        new_code, recovery = _new_recovery(username, kek)
        rekey(username, old_kek, kek)
        rec.update({
            "kdf": self.params.to_dict(),
            "salt": b64e(salt),
            "verifier": b64e(verifier),
            "enc_priv": b64e(aead.encrypt(kek, hybrid.private_to_bytes(priv), _key_aad(username))),
            "recovery": recovery,
            "failed": 0,
            "locked_until": 0,
        })
        self.store.save(users)
        log.info("Contraseña de '%s' recuperada: KEK nueva y código de recuperación renovado", username)
        return Session(username, kek, priv, priv.public_key()), new_code
