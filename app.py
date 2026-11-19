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

# Estética institucional (colores base en .streamlit/config.toml). Solo presentación.
UC3M_BLUE = "#000E78"
st.markdown(f"""
<style>
  .block-container {{ padding-top: 2.2rem; }}
  .pc-header {{
    background: {UC3M_BLUE}; color: #fff; padding: 1.6rem 1.8rem 1.4rem;
    border-bottom: 5px solid #5B7BD5; margin-bottom: 1.4rem;
  }}
  .pc-header .pc-kicker {{ font-size: .78rem; letter-spacing: .14em; text-transform: uppercase; opacity: .8; }}
  .pc-header h1 {{ color: #fff; margin: .2rem 0 .3rem; padding: 0; font-size: 2.1rem; }}
  .pc-header p {{ margin: 0; opacity: .9; font-size: .95rem; }}
  [data-testid="stTable"] th {{ background: {UC3M_BLUE}; color: #fff; font-weight: 600; }}
  [data-testid="stForm"] {{ border-left: 4px solid {UC3M_BLUE}; }}
  h2, h3 {{ color: {UC3M_BLUE}; }}
  .pc-footer {{ margin-top: 2.5rem; padding-top: .8rem; border-top: 1px solid #D3D9E6;
               font-size: .8rem; color: #5A6078; }}
</style>
""", unsafe_allow_html=True)
users = UserService(JsonStore(DATA / "users.json"))
planning = PlanningService(JsonStore(DATA / "planning.json"))
acad = AcademicService(DATA, users)


def show_error(exc: Exception) -> None:
    """Los fallos de integridad se muestran como RECHAZADO; el resto, como error normal."""
    if isinstance(exc, (IntegrityError, ReplayError)):
        st.error(f"RECHAZADO: {exc}")
    else:
        st.error(str(exc))


def done(message: str) -> None:
    """Tras un cambio, vuelve a ejecutar el script entero para que TODAS las pestañas
    se dibujen con los datos nuevos (Streamlit pinta en orden: la pestaña Estudiante
    se dibuja antes que la de Secretaría). El mensaje se muestra en la siguiente ejecución."""
    st.session_state["flash"] = message
    st.rerun()


def student_view(session) -> None:
    head, out = st.columns([4, 1])
    head.caption(f"Sesión de **{session.username}**")
    if out.button("Cerrar sesión"):
        st.session_state.pop("student", None)
        st.rerun()

    tab_plan, tab_notes, tab_pending = st.tabs(["Planning", "Notas", "Pendientes"], key="student_tab",
                                               on_change="rerun")

    with tab_plan:
        with st.form("add_planning", clear_on_submit=True):
            day = st.date_input("Fecha", value=dt.date.today())
            start = st.time_input("Hora", value=dt.time(9, 0))
            text = st.text_input("Actividad", max_chars=200)
            if st.form_submit_button("Añadir (se cifra con AES-256-GCM)", type="primary"):
                try:
                    planning.add(session, day.isoformat(), start.strftime("%H:%M"), text)
                except PlanCipherError as exc:
                    show_error(exc)
                else:
                    done("Entrada añadida")
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
    tab_login, tab_register, tab_recover = st.tabs(["Entrar", "Registrarse", "¿Olvidaste la contraseña?"])
    with tab_login, st.form("login"):
        user = st.text_input("Usuario")
        password = st.text_input("Contraseña", type="password")
        if st.form_submit_button("Entrar", type="primary"):
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
        if st.form_submit_button("Registrarse", type="primary"):
            if password != again:
                st.error("Las contraseñas no coinciden")
            else:
                try:
                    code = users.register(user.strip(), password)
                except PlanCipherError as exc:
                    show_error(exc)
                else:
                    done("Registrado. Pide a la secretaría que emita tu certificado de matrícula.  \n"
                         f"**Código de recuperación** (guárdalo, no se volverá a mostrar): `{code}`")
    with tab_recover, st.form("recover", clear_on_submit=True):
        st.caption("Usa el código de recuperación que se te mostró al registrarte. Tu planning y tus "
                   "notas se conservan: solo cambia la contraseña (y se genera un código nuevo).")
        user = st.text_input("Usuario a recuperar", key="recover_user")
        code = st.text_input("Código de recuperación", type="password")
        password = st.text_input("Contraseña nueva (mín. 12 caracteres)", type="password")
        again = st.text_input("Repite la contraseña nueva", type="password")
        if st.form_submit_button("Recuperar contraseña", type="primary"):
            if password != again:
                st.error("Las contraseñas no coinciden")
            else:
                try:
                    _, new_code = users.recover(user.strip(), code, password, rekey=planning.rekey)
                except PlanCipherError as exc:
                    show_error(exc)
                else:
                    done("Contraseña cambiada; ya puedes entrar con la nueva. El código anterior ya no vale.  \n"
                         f"**Código de recuperación nuevo** (guárdalo): `{new_code}`")


def secretaria_tab() -> None:
    if not (DATA / "pki" / "root_cert.pem").exists():
        st.info("La secretaría aún no está inicializada. Se creará una PKI de dos niveles: "
                "AC raíz → AC subordinada (secretaría) + CRL.")
        with st.form("init_sec"):
            root_pass = st.text_input("Passphrase de la AC raíz (mín. 12 caracteres)", type="password")
            root_again = st.text_input("Repite la passphrase de la AC raíz", type="password")
            passphrase = st.text_input("Passphrase de la secretaría (mín. 12, distinta)", type="password")
            again = st.text_input("Repite la passphrase de la secretaría", type="password")
            if st.form_submit_button("Inicializar PKI y secretaría", type="primary"):
                if passphrase != again or root_pass != root_again:
                    st.error("Las passphrases no coinciden")
                else:
                    try:
                        fingerprint = Secretaria.init(DATA, passphrase, root_passphrase=root_pass)
                        sec = Secretaria.unlock(DATA, passphrase)
                        acad.publish_plan(sec, json.loads(SAMPLE_PLAN.read_text(encoding="utf-8")))
                    except PlanCipherError as exc:
                        show_error(exc)
                    else:
                        done("PKI creada y plan publicado y firmado. "
                             f"Huella SHA-256 de la AC raíz: `{fingerprint}`")
        return

    sec = st.session_state.get("sec")
    if sec is None:
        with st.form("unlock_sec"):
            passphrase = st.text_input("Passphrase de la secretaría", type="password")
            if st.form_submit_button("Desbloquear", type="primary"):
                try:
                    st.session_state["sec"] = Secretaria.unlock(DATA, passphrase, FP)
                except PlanCipherError as exc:
                    show_error(exc)
                else:
                    st.rerun()
        return

    head, out = st.columns([4, 1])
    head.caption(f"AC raíz `{sec.anchor.fingerprint[:16]}…` → secretaría "
                 f"`{sec.anchor.secretaria_fingerprint[:16]}…` (cadena y CRL verificadas)")
    if out.button("Bloquear"):
        st.session_state.pop("sec", None)
        st.rerun()

    names = users.usernames()
    if not names:
        st.info("No hay estudiantes registrados.")
        return

    st.subheader("Matrícula (certificado X.509)")
    with st.form("enroll"):
        student = st.selectbox("Estudiante", names, key="enroll_student")
        if st.form_submit_button("Emitir certificado", type="primary"):
            try:
                acad.enroll(sec, student)
            except PlanCipherError as exc:
                show_error(exc)
            else:
                done(f"Certificado X.509 de {student} emitido: ya puede recibir notas")

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
        if st.form_submit_button("Emitir (cifrada y firmada)", type="primary"):
            try:
                acad.issue_grade(sec, student, subject, float(grade), term.strip())
            except PlanCipherError as exc:
                show_error(exc)
            else:
                done(f"Nota de {subject} emitida para {student}: cifrada y firmada")


st.markdown("""
<div class="pc-header">
  <div class="pc-kicker">Criptografía y Seguridad Informática · Práctica final</div>
  <h1>PlanCipher</h1>
  <p>Planning, notas y asignaturas pendientes, cifrados y firmados. Demo local.</p>
</div>
""", unsafe_allow_html=True)
if flash := st.session_state.pop("flash", None):
    st.success(flash)
# Con `key`, la pestaña activa se conserva tras st.rerun(); al cambiar de pestaña se vuelve a ejecutar.
tab_student, tab_secretaria = st.tabs(["Estudiante", "Secretaría"], key="main_tab", on_change="rerun")
with tab_student:
    student_tab()
with tab_secretaria:
    secretaria_tab()
st.markdown('<div class="pc-footer">PlanCipher · AES-256-GCM · X25519 · ECDSA P-256 · scrypt</div>',
            unsafe_allow_html=True)
