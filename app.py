"""Interfaz web LOCAL (Streamlit) sobre los mismos servicios que la CLI.

Ejecutar:  streamlit run app.py --server.address 127.0.0.1
La criptografía no cambia: aquí solo hay entrada/salida. Las sesiones viven en la
memoria del servidor (st.session_state) y se descartan al cerrar sesión.
"""
import datetime as dt
import json
import os
from pathlib import Path

import streamlit as st

from plancipher.academic import AcademicService, pending_subjects
from plancipher.auth import UserService
from plancipher.cli import SAMPLE_PLAN
from plancipher.errors import IntegrityError, PlanCipherError, ReplayError
from plancipher.planning import PlanningService
from plancipher.secretaria import Secretaria, TrustAnchor
from plancipher.storage import JsonStore, ensure_dir

DATA = ensure_dir(Path(os.environ.get("PLANCIPHER_DATA", "data")))
FP = os.environ.get("PLANCIPHER_TRUST_FP") or None

st.set_page_config(page_title="PlanCipher", page_icon="🔐")
users = UserService(JsonStore(DATA / "users.json"))
planning = PlanningService(JsonStore(DATA / "planning.json"))
acad = AcademicService(DATA, users)


def show_error(exc: Exception) -> None:
    """Los fallos de integridad se muestran como RECHAZADO; el resto, como error normal."""
    if isinstance(exc, (IntegrityError, ReplayError)):
        st.error(f"RECHAZADO: {exc}")
    else:
        st.error(str(exc))


def student_view(session) -> None:
    head, out = st.columns([4, 1])
    head.caption(f"Sesión de **{session.username}**")
    if out.button("Cerrar sesión"):
        st.session_state.pop("student", None)
        st.rerun()

    tab_plan, tab_notes, tab_pending = st.tabs(["Planning", "Notas", "Pendientes"])

    with tab_plan:
        with st.form("add_planning", clear_on_submit=True):
            day = st.date_input("Fecha", value=dt.date.today())
            start = st.time_input("Hora", value=dt.time(9, 0))
            text = st.text_input("Actividad", max_chars=200)
            if st.form_submit_button("Añadir (se cifra con AES-256-GCM)"):
                try:
                    planning.add(session, day.isoformat(), start.strftime("%H:%M"), text)
                    st.success("Entrada añadida")
                except PlanCipherError as exc:
                    show_error(exc)
        entries, rejected = planning.list(session)
        if entries:
            st.table([{"Fecha": e["day"], "Hora": e["start"], "Actividad": e["text"]} for e in entries])
        else:
            st.info("Planning vacío")
        for rid in rejected:
            st.error(f"RECHAZADO {rid[:8]}: tag de autenticación inválido")

    with tab_notes:
        try:
            view = acad.read_grades(session, TrustAnchor.load(DATA, FP))
        except PlanCipherError as exc:
            show_error(exc)
        else:
            if view.grades:
                st.table([{"Asignatura": g["subject"], "Nota": g["grade"], "Convocatoria": g["term"],
                           "Estado": "✅ firma verificada"} for g in view.grades])
            else:
                st.info("Sin notas")
            for rid, reason in view.rejected:
                st.error(f"RECHAZADO {rid[:8]}: {reason}")

    with tab_pending:
        try:
            anchor = TrustAnchor.load(DATA, FP)
            grades = acad.read_grades(session, anchor).grades
            pend = pending_subjects(acad.load_plan(anchor), grades)
        except PlanCipherError as exc:
            show_error(exc)
        else:
            if pend:
                st.table([{"Código": p["code"], "Asignatura": p["name"], "Créditos": p["credits"],
                           "Estado": p["state"], "Nota": p["grade"] if p["grade"] is not None else "-"}
                          for p in pend])
            else:
                st.success("No te queda ninguna asignatura pendiente")


def student_tab() -> None:
    session = st.session_state.get("student")
    if session is not None:
        student_view(session)
        return
    tab_login, tab_register = st.tabs(["Entrar", "Registrarse"])
    with tab_login, st.form("login"):
        user = st.text_input("Usuario")
        password = st.text_input("Contraseña", type="password")
        if st.form_submit_button("Entrar"):
            try:
                st.session_state["student"] = users.login(user.strip(), password)
            except PlanCipherError as exc:
                show_error(exc)
            else:
                st.rerun()
    with tab_register, st.form("register"):
        user = st.text_input("Usuario nuevo")
        password = st.text_input("Contraseña (mín. 12 caracteres)", type="password")
        again = st.text_input("Repite la contraseña", type="password")
        if st.form_submit_button("Registrarse"):
            if password != again:
                st.error("Las contraseñas no coinciden")
            else:
                try:
                    users.register(user.strip(), password)
                    st.success("Registrado. Pide a la secretaría que firme tu matrícula.")
                except PlanCipherError as exc:
                    show_error(exc)


def secretaria_tab() -> None:
    if not (DATA / "secretaria" / "cert.pem").exists():
        st.info("La secretaría aún no está inicializada.")
        with st.form("init_sec"):
            passphrase = st.text_input("Passphrase (mín. 12 caracteres)", type="password")
            again = st.text_input("Repite la passphrase", type="password")
            if st.form_submit_button("Inicializar secretaría"):
                if passphrase != again:
                    st.error("Las passphrases no coinciden")
                else:
                    try:
                        fingerprint = Secretaria.init(DATA, passphrase)
                        sec = Secretaria.unlock(DATA, passphrase)
                        acad.publish_plan(sec, json.loads(SAMPLE_PLAN.read_text(encoding="utf-8")))
                        st.success("Secretaría creada y plan publicado y firmado.")
                        st.code(fingerprint, language=None)
                    except PlanCipherError as exc:
                        show_error(exc)
        return

    sec = st.session_state.get("sec")
    if sec is None:
        with st.form("unlock_sec"):
            passphrase = st.text_input("Passphrase de la secretaría", type="password")
            if st.form_submit_button("Desbloquear"):
                try:
                    st.session_state["sec"] = Secretaria.unlock(DATA, passphrase, FP)
                except PlanCipherError as exc:
                    show_error(exc)
                else:
                    st.rerun()
        return

    head, out = st.columns([4, 1])
    head.caption(f"Huella SHA-256 del certificado: `{sec.anchor.fingerprint}`")
    if out.button("Bloquear"):
        st.session_state.pop("sec", None)
        st.rerun()

    names = users.usernames()
    if not names:
        st.info("No hay estudiantes registrados.")
        return

    st.subheader("Firmar matrícula")
    with st.form("enroll"):
        student = st.selectbox("Estudiante", names, key="enroll_student")
        if st.form_submit_button("Firmar matrícula"):
            try:
                acad.enroll(sec, student)
                st.success(f"Matrícula de {student} firmada")
            except PlanCipherError as exc:
                show_error(exc)

    st.subheader("Emitir nota")
    try:
        codes = [s["code"] for s in acad.load_plan(sec.anchor)["subjects"]]
    except PlanCipherError as exc:
        show_error(exc)
        return
    with st.form("issue"):
        student = st.selectbox("Estudiante", names, key="issue_student")
        subject = st.selectbox("Asignatura", codes)
        grade = st.number_input("Nota", min_value=0.0, max_value=10.0, value=5.0, step=0.1)
        term = st.text_input("Convocatoria", value=f"{dt.date.today().year}-1C")
        if st.form_submit_button("Emitir (cifrada y firmada)"):
            try:
                acad.issue_grade(sec, student, subject, float(grade), term.strip())
                st.success("Nota emitida: cifrada para el estudiante y firmada")
            except PlanCipherError as exc:
                show_error(exc)


st.title("🔐 PlanCipher")
st.caption("Planning, notas y asignaturas pendientes, cifrados y firmados. Demo local.")
tab_student, tab_secretaria = st.tabs(["Estudiante", "Secretaría"])
with tab_student:
    student_tab()
with tab_secretaria:
    secretaria_tab()
