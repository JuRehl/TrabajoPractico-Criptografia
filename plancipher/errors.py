"""Excepciones propias. La CLI las traduce a mensajes y códigos de salida."""


class PlanCipherError(Exception):
    """Base de todos los errores controlados de la aplicación."""


class ValidationError(PlanCipherError):
    """Entrada del usuario o fichero con formato inválido."""


class AuthenticationError(PlanCipherError):
    """Credenciales incorrectas (contraseña, usuario o passphrase)."""


class LockedError(AuthenticationError):
    """Cuenta bloqueada temporalmente por demasiados intentos fallidos."""


class IntegrityError(PlanCipherError):
    """Tag AEAD, firma o certificado inválidos: los datos se RECHAZAN."""


class ReplayError(PlanCipherError):
    """Registro repetido o anterior a uno ya aceptado."""
