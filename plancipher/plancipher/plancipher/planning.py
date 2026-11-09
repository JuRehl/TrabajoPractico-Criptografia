"""Planning personal del estudiante, cifrado de extremo a extremo.

Cada entrada usa una clave de contenido (CEK) aleatoria de 256 bits que se cifra
(AES-256-GCM) con la KEK del usuario. El id y el propietario viajan como AAD, de
modo que copiar una entrada a otro usuario o a otro id invalida su tag.
"""
import datetime as dt
import json
import logging
import os
import re

from .auth import Session
from .crypto import aead
from .crypto.encoding import b64d, b64e
from .errors import IntegrityError, ValidationError
from .storage import JsonStore

log = logging.getLogger("plancipher.planning")

TIME_RE = re.compile(r"^([01]\d|2[0-3]):[0-5]\d$")
MAX_TEXT = 200


def _aad(kind: str, owner: str, entry_id: str) -> bytes:
    return f"plancipher/v1/{kind}|{owner}|{entry_id}".encode()


def _clean_text(text: str) -> str:
    text = text.strip()
    if not text or len(text) > MAX_TEXT or any(ord(c) < 32 for c in text):
        raise ValidationError(f"El texto debe tener 1-{MAX_TEXT} caracteres sin caracteres de control")
    return text


class PlanningService:
    def __init__(self, store: JsonStore):
        self.store = store

    def add(self, session: Session, day: str, start: str, text: str) -> str:
        try:
            dt.date.fromisoformat(day)
        except ValueError as exc:
            raise ValidationError("Fecha inválida: usa AAAA-MM-DD") from exc
        if not TIME_RE.fullmatch(start):
            raise ValidationError("Hora inválida: usa HH:MM")
        entry = {"day": day, "start": start, "text": _clean_text(text)}

        entry_id = os.urandom(16).hex()
        cek = aead.new_key()
        record = {
            "id": entry_id,
            "owner": session.username,
            "wrapped_cek": b64e(aead.encrypt(session.kek, cek, _aad("wrap", session.username, entry_id))),
            "data": b64e(aead.encrypt(cek, json.dumps(entry).encode(), _aad("planning", session.username, entry_id))),
        }
        records = self.store.load([])
        records.append(record)
        self.store.save(records)
        return entry_id

    def list(self, session: Session) -> tuple[list[dict], list[str]]:
        """Devuelve (entradas válidas ordenadas, ids rechazados por fallo de integridad)."""
        entries, rejected = [], []
        for rec in self.store.load([]):
            if not isinstance(rec, dict) or rec.get("owner") != session.username:
                continue
            rid = str(rec.get("id", "?"))
            try:
                cek = aead.decrypt(session.kek, b64d(rec["wrapped_cek"]), _aad("wrap", session.username, rid))
                data = aead.decrypt(cek, b64d(rec["data"]), _aad("planning", session.username, rid))
                entry = json.loads(data)
                entries.append({"id": rid, **entry})
            except (IntegrityError, ValidationError, KeyError, TypeError, ValueError) as exc:
                log.warning("Entrada de planning %s RECHAZADA: %s", rid[:8], exc)
                rejected.append(rid)
        entries.sort(key=lambda e: (e["day"], e["start"]))
        return entries, rejected
