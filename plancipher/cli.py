"""Interfaz de línea de comandos. Solo entrada/salida: la lógica vive en los servicios.

Secretos: se piden con getpass (sin eco) o, para scripts/demos, se leen de las
variables PLANCIPHER_PASSWORD y PLANCIPHER_SECRETARIA_PASS. Nunca se imprimen.
Códigos de salida: 0 OK, 1 error controlado, 3 datos rechazados por integridad.
"""
import argparse
import getpass
import json
import logging
import os
import sys
from pathlib import Path

from . import __version__
from .academic import AcademicService, pending_subjects
from .auth import UserService
from .errors import IntegrityError, PlanCipherError, ReplayError
from .planning import PlanningService
from .secretaria import Secretaria, TrustAnchor
from .storage import JsonStore, ensure_dir

SAMPLE_PLAN = Path(__file__).with_name("sample_plan.json")


def _secret(prompt: str, env: str, confirm: bool = False) -> str:
    if os.environ.get(env):
        return os.environ[env]
    value = getpass.getpass(prompt)
    if confirm and getpass.getpass("Repite: ") != value:
        raise PlanCipherError("Las contraseñas no coinciden")
    return value


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="plancipher", description="PlanCipher: planning y notas cifrados")
    p.add_argument("--data-dir", default=os.environ.get("PLANCIPHER_DATA", "data"), help="directorio de datos")
    p.add_argument("--trust-fingerprint", default=os.environ.get("PLANCIPHER_TRUST_FP"),
                   help="huella SHA-256 esperada del certificado de la secretaría")
    p.add_argument("--debug", action="store_true", help="log de depuración (algoritmos, longitudes; nunca secretos)")
    p.add_argument("--version", action="version", version=__version__)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init-secretaria", help="crea la clave de firma y el certificado de la secretaría")
    s.add_argument("--plan", type=Path, default=SAMPLE_PLAN, help="JSON del plan de estudios a publicar")
    s = sub.add_parser("enroll", help="[secretaría] firma la matrícula de un estudiante")
    s.add_argument("user")
    s = sub.add_parser("issue-grade", help="[secretaría] emite una nota cifrada y firmada")
    s.add_argument("student")
    s.add_argument("--subject", required=True)
    s.add_argument("--grade", type=float, required=True)
    s.add_argument("--term", required=True, help="p. ej. 2026-1C")

    s = sub.add_parser("register", help="registra un estudiante")
    s.add_argument("user")
    s = sub.add_parser("add-planning", help="añade una entrada cifrada al planning")
    s.add_argument("user")
    s.add_argument("--date", required=True, help="AAAA-MM-DD")
    s.add_argument("--time", required=True, help="HH:MM")
    s.add_argument("--text", required=True)
    for name, help_ in (("planning", "muestra el planning"), ("grades", "muestra notas verificadas"),
                        ("pending", "muestra asignaturas pendientes")):
        s = sub.add_parser(name, help=help_)
        s.add_argument("user")
    return p


def _users(data: Path) -> UserService:
    return UserService(JsonStore(data / "users.json"))


def _print_rejected(view_rejected) -> None:
    for rid, reason in view_rejected:
        print(f"  RECHAZADO {rid[:8]}: {reason}", file=sys.stderr)


def run(args) -> int:
    data = ensure_dir(Path(args.data_dir))
    fp = args.trust_fingerprint

    if args.cmd == "init-secretaria":
        plan = json.loads(args.plan.read_text(encoding="utf-8"))
        passphrase = _secret("Passphrase de la secretaría: ", "PLANCIPHER_SECRETARIA_PASS", confirm=True)
        fingerprint = Secretaria.init(data, passphrase)
        sec = Secretaria.unlock(data, passphrase)
        AcademicService(data, _users(data)).publish_plan(sec, plan)
        print(f"Secretaría creada. Huella SHA-256 del certificado:\n  {fingerprint}")
        print("Plan de estudios publicado y firmado.")

    elif args.cmd in ("enroll", "issue-grade"):
        sec = Secretaria.unlock(data, _secret("Passphrase de la secretaría: ", "PLANCIPHER_SECRETARIA_PASS"), fp)
        acad = AcademicService(data, _users(data))
        if args.cmd == "enroll":
            acad.enroll(sec, args.user)
            print(f"Matrícula de '{args.user}' firmada.")
        else:
            rid = acad.issue_grade(sec, args.student, args.subject.upper(), args.grade, args.term)
            print(f"Nota emitida (id {rid[:8]}): cifrada para '{args.student}' y firmada.")

    elif args.cmd == "register":
        _users(data).register(args.user, _secret("Contraseña: ", "PLANCIPHER_PASSWORD", confirm=True))
        print(f"Usuario '{args.user}' registrado. Pide a la secretaría que firme tu matrícula.")

    else:  # comandos del estudiante: requieren login
        users = _users(data)
        session = users.login(args.user, _secret("Contraseña: ", "PLANCIPHER_PASSWORD"))
        if args.cmd == "add-planning":
            PlanningService(JsonStore(data / "planning.json")).add(session, args.date, args.time, args.text)
            print("Entrada añadida (cifrada con AES-256-GCM).")
        elif args.cmd == "planning":
            entries, rejected = PlanningService(JsonStore(data / "planning.json")).list(session)
            for e in entries:
                print(f"{e['day']} {e['start']}  {e['text']}")
            if not entries:
                print("(planning vacío)")
            _print_rejected([(r, "tag de autenticación inválido") for r in rejected])
            return 3 if rejected else 0
        else:
            anchor = TrustAnchor.load(data, fp)
            acad = AcademicService(data, users)
            view = acad.read_grades(session, anchor)
            if args.cmd == "grades":
                for g in view.grades:
                    print(f"{g['subject']:<8} {g['grade']:>4.1f}  {g['term']}  [firma verificada]")
                if not view.grades:
                    print("(sin notas)")
            else:
                for s in pending_subjects(acad.load_plan(anchor), view.grades):
                    extra = f" (nota {s['grade']})" if s["grade"] is not None else ""
                    print(f"{s['code']:<8} {s['name']}  - {s['state']}{extra}")
            _print_rejected(view.rejected)
            return 3 if view.rejected else 0
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.debug else logging.ERROR,
                        format="[%(levelname)s] %(name)s: %(message)s", stream=sys.stderr)
    try:
        return run(args)
    except (IntegrityError, ReplayError) as exc:
        print(f"RECHAZADO: {exc}", file=sys.stderr)
        return 3
    except PlanCipherError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"Error de E/S: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    sys.exit(main())
