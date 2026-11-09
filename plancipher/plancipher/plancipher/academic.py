"""Expediente académico: matrícula, plan de estudios y notas.

* Matrícula: la secretaría firma (usuario, clave pública X25519). Así sabe que
  cifra para la clave auténtica del estudiante y no para una sustituida.
* Plan de estudios: público, firmado por la secretaría (integridad/autenticidad).
* Notas: cifradas con una CEK que se entrega al estudiante con ECIES y firmadas
  (ECDSA P-256) sobre todo el sobre (cabecera + clave sellada + cifrado).
"""
import datetime as dt
import json
import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path

from .auth import Session, UserService
from .crypto import aead, hybrid
from .crypto.encoding import b64d, b64e, canonical
from .errors import IntegrityError, ReplayError, ValidationError
from .secretaria import Secretaria, TrustAnchor
from .storage import JsonStore

log = logging.getLogger("plancipher.academic")

CODE_RE = re.compile(r"^[A-Z0-9]{3,12}$")
TERM_RE = re.compile(r"^\d{4}-[12]C$")
PASS_MARK = 5.0


def validate_plan(plan) -> dict:
    try:
        subjects = plan["subjects"]
        if not isinstance(plan["degree"], str) or not subjects or len(subjects) > 100:
            raise ValueError
        seen = set()
        for s in subjects:
            if not CODE_RE.fullmatch(s["code"]) or s["code"] in seen:
                raise ValueError
            seen.add(s["code"])
            if not (isinstance(s["name"], str) and 0 < len(s["name"]) <= 80):
                raise ValueError
            if not (isinstance(s["credits"], int) and 1 <= s["credits"] <= 30):
                raise ValueError
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError("Plan de estudios con formato inválido") from exc
    return {"degree": plan["degree"], "subjects": [
        {"code": s["code"], "name": s["name"], "credits": s["credits"]} for s in subjects]}


@dataclass
class GradesView:
    grades: list = field(default_factory=list)    # nota vigente por asignatura
    rejected: list = field(default_factory=list)  # (id, motivo) de registros rechazados


class AcademicService:
    def __init__(self, data_dir: Path, users: UserService):
        self.users = users
        self.records = JsonStore(Path(data_dir) / "records.json")
        self.plan_store = JsonStore(Path(data_dir) / "plan.json")

    # --- matrícula ------------------------------------------------------
    def enroll(self, sec: Secretaria, username: str) -> None:
        rec = self.users.get(username)
        if rec is None:
            raise ValidationError("Usuario inexistente")
        self.users.set_enrollment(username, sec.sign("enroll", {"username": username, "pub": rec["pub"]}))

    def _verified_public_key(self, anchor: TrustAnchor, username: str):
        rec = self.users.get(username)
        if rec is None:
            raise ValidationError("Usuario inexistente")
        if not rec.get("enrollment"):
            raise ValidationError("El estudiante no está matriculado (la secretaría debe firmar su matrícula)")
        anchor.verify("enroll", {"username": username, "pub": rec["pub"]}, rec["enrollment"])
        return hybrid.public_from_bytes(b64d(rec["pub"]))

    # --- plan de estudios ----------------------------------------------
    def publish_plan(self, sec: Secretaria, plan: dict) -> None:
        plan = validate_plan(plan)
        plan.update({"v": 1, "issued_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")})
        self.plan_store.save({"plan": plan, "signature": sec.sign("plan", plan)})

    def load_plan(self, anchor: TrustAnchor) -> dict:
        doc = self.plan_store.load(None)
        if doc is None:
            raise ValidationError("La secretaría aún no ha publicado el plan de estudios")
        try:
            anchor.verify("plan", doc["plan"], doc["signature"])
        except (KeyError, TypeError) as exc:
            raise ValidationError("Plan de estudios malformado") from exc
        return doc["plan"]

    # --- notas: emisión (secretaría) -----------------------------------
    def issue_grade(self, sec: Secretaria, student: str, subject: str, grade: float, term: str) -> str:
        plan = self.load_plan(sec.anchor)
        if subject not in {s["code"] for s in plan["subjects"]}:
            raise ValidationError("La asignatura no existe en el plan de estudios")
        if isinstance(grade, bool) or not isinstance(grade, (int, float)) or not 0 <= grade <= 10:
            raise ValidationError("La nota debe estar entre 0 y 10")
        if not TERM_RE.fullmatch(term):
            raise ValidationError("Convocatoria inválida: usa AAAA-1C o AAAA-2C")
        pub = self._verified_public_key(sec.anchor, student)

        seq = max((r["header"]["seq"] for r in self._load_records() if r["header"]["student"] == student), default=0) + 1
        header = {"v": 1, "id": os.urandom(16).hex(), "student": student, "seq": seq,
                  "issued_at": dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")}
        payload = {"student": student, "seq": seq, "subject": subject, "grade": round(float(grade), 1), "term": term}

        aad = canonical("record-aad", header)
        cek = aead.new_key()
        body = {
            "header": header,
            "sealed_cek": b64e(hybrid.seal(pub, cek, aad)),
            "ct": b64e(aead.encrypt(cek, json.dumps(payload).encode(), aad)),
        }
        self.add_record({**body, "signature": sec.sign("record", body)}, sec.anchor)
        return header["id"]

    def _load_records(self) -> list:
        data = self.records.load([])
        if not isinstance(data, list):
            raise ValidationError("Fichero de notas con formato inválido")
        return data

    def add_record(self, record: dict, anchor: TrustAnchor) -> None:
        """Alta de un registro: firma válida + id único + seq estrictamente creciente por estudiante."""
        try:
            anchor.verify("record", {k: record[k] for k in ("header", "sealed_cek", "ct")}, record["signature"])
            header = record["header"]
            student, seq, rid = header["student"], header["seq"], header["id"]
        except (KeyError, TypeError) as exc:
            raise ValidationError("Registro malformado") from exc
        existing = self._load_records()
        if any(r["header"]["id"] == rid for r in existing):
            raise ReplayError("Registro repetido (mismo id)")
        if any(r["header"]["student"] == student and r["header"]["seq"] >= seq for r in existing):
            raise ReplayError("Registro anterior o igual a uno ya aceptado (repetición/rollback)")
        existing.append(record)
        self.records.save(existing)

    # --- notas: lectura (estudiante) -----------------------------------
    def read_grades(self, session: Session, anchor: TrustAnchor) -> GradesView:
        view, latest, seen_ids = GradesView(), {}, set()
        for rec in self._load_records():
            try:
                if rec["header"]["student"] != session.username:
                    continue
                rid = rec["header"]["id"]
            except (KeyError, TypeError):
                continue
            try:
                if rid in seen_ids:
                    raise ReplayError("id duplicado")
                seen_ids.add(rid)
                anchor.verify("record", {k: rec[k] for k in ("header", "sealed_cek", "ct")}, rec["signature"])
                aad = canonical("record-aad", rec["header"])
                cek = hybrid.open_sealed(session.private_key, b64d(rec["sealed_cek"]), aad)
                payload = json.loads(aead.decrypt(cek, b64d(rec["ct"]), aad))
                if payload["student"] != session.username or payload["seq"] != rec["header"]["seq"]:
                    raise IntegrityError("Contenido incoherente con la cabecera firmada")
                cur = latest.get(payload["subject"])
                if cur is None or payload["seq"] > cur["seq"]:
                    latest[payload["subject"]] = {**payload, "issued_at": rec["header"]["issued_at"]}
            except (IntegrityError, ReplayError, ValidationError, KeyError, TypeError, ValueError) as exc:
                log.warning("Nota %s RECHAZADA: %s", str(rid)[:8], exc)
                view.rejected.append((str(rid), str(exc)))
        view.grades = sorted(latest.values(), key=lambda g: g["subject"])
        return view


def pending_subjects(plan: dict, grades: list) -> list[dict]:
    """Asignaturas del plan sin aprobar (nota vigente < 5 o sin cursar)."""
    by_code = {g["subject"]: g for g in grades}
    out = []
    for s in plan["subjects"]:
        g = by_code.get(s["code"])
        if g is None:
            out.append({**s, "state": "sin cursar", "grade": None})
        elif g["grade"] < PASS_MARK:
            out.append({**s, "state": "suspensa", "grade": g["grade"]})
    return out
