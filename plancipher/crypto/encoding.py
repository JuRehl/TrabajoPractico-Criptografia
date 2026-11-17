"""Codificación base64 estricta y serialización canónica para firmar."""
import base64
import binascii
import json

from ..errors import ValidationError


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(text: str) -> bytes:
    """Decodifica base64 de forma estricta"""
    if not isinstance(text, str):
        raise ValidationError("Campo base64 con tipo inválido")
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (binascii.Error, UnicodeEncodeError) as exc:
        raise ValidationError("Campo base64 corrupto") from exc


def canonical(domain: str, obj) -> bytes:
    """Impedimiento para reutilizar firma"""
    body = json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return f"plancipher/v1/{domain}\x00".encode("ascii") + body.encode("ascii")
