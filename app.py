# app.py
import os, json
import streamlit as st
from pathlib import Path

from auth_mfa import (
    AuthManager, S3UserStore, SheetSeeder, hash_password  # <- NUEVOS
)

st.set_page_config(page_title="InsurApp Login", layout="centered")

# =========================
# 1) Email: usa st.secrets
# =========================
def send_email_smtp(*, to: str, subject: str, html: str):
    import smtplib
    from email.message import EmailMessage

    host   = st.secrets["smtp"]["host"]
    port   = int(st.secrets["smtp"]["port"])
    user   = st.secrets["smtp"]["user"]
    pwd    = st.secrets["smtp"]["password"]
    sender = st.secrets["smtp"]["from"]

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"]    = sender
    msg["To"]      = to
    msg.set_content("Para ver este mensaje usa un cliente compatible con HTML.")
    msg.add_alternative(html, subtype="html")

    with smtplib.SMTP(host, port) as s:
        s.starttls()
        if user and pwd:
            s.login(user, pwd)
        s.send_message(msg)

# ====================================================
# 2) Seeder desde tu Google Sheet (lee de st.secrets)
# ====================================================
# Asegúrate que en secrets tengas el bloque [gcp_service_account] y el sheet_key correcto.
creds_dict = dict(st.secrets["gcp_service_account"])
seeder = SheetSeeder(
    sheet_key="13hY8la9Xke5-wu3vmdB-tNKtY5D6ud4FZrJG2_HtKd8",   # <--- tu sheet
    creds_dict=creds_dict,
    worksheet_name="aseguradosatlantida",                                   # o la que uses
    email_col="CORREO ELECTRÓNICO",
    cedula_col="CÉDULA",                                         # ajusta al nombre exacto de tu columna
    name_col="NOMBRE COMPLETO",
    role_default="cliente"
)

# ======================================
# 3) Store S3 (fuente de verdad de auth)
# ======================================
s3_store = S3UserStore(
    bucket=st.secrets["aws"]["bucket_name"],                     # p. ej. "insurapp-uploader"
    prefix="auth/users",                                         # ruta dentro del bucket
    aws_region=st.secrets["aws"]["region"],                      # "us-east-1"
    seeder=seeder
)

auth = AuthManager(s3_store, issuer_name="InsurApp")

# =========================================================
# 4) Manejar link de reseteo (ANTES del login normal/MFA)
# =========================================================
# En Streamlit recientes: st.query_params; en antiguos: st.experimental_get_query_params()
try:
    params = st.query_params
    reset_token = params.get("reset")
    reset_user  = params.get("u")
except Exception:
    params = st.experimental_get_query_params()
    reset_token = params.get("reset", [None])
    reset_token = reset_token[0] if isinstance(reset_token, list) else reset_token
    reset_user  = params.get("u", [None])
    reset_user  = reset_user[0] if isinstance(reset_user, list) else reset_user

if reset_token and reset_user:
    st.markdown("## Restablecer contraseña")
    new1 = st.text_input("Nueva contraseña", type="password")
    new2 = st.text_input("Confirmar nueva contraseña", type="password")

    if st.button("Guardar nueva contraseña"):
        if new1 and new2 and new1 == new2:
            if auth.verify_reset_token(reset_user, reset_token):
                if auth.finalize_password_reset(reset_user, new1):
                    st.success("✅ Contraseña actualizada. Ya puedes iniciar sesión.")
                    # Limpiar query params y volver al login
                    try:
                        st.query_params.clear()
                    except Exception:
                        st.experimental_set_query_params()
                    st.stop()
                else:
                    st.error("No se pudo actualizar la contraseña.")
            else:
                st.error("El enlace es inválido o expiró.")
        else:
            st.warning("Las contraseñas no coinciden.")
    st.stop()  # No renderices el login normal si estás en el flujo de reset

# ======================================
# 5) Login normal + MFA (S3 como backend)
# ======================================
user = auth.login(key_prefix="insurapp", debug=False)

# ==================================================
# 6) ¿Olvidaste tu contraseña? (si aún no está logueado)
# ==================================================
if not user:
    with st.expander("¿Olvidaste tu contraseña?"):
        username_fp = st.text_input("Ingresa tu usuario (correo) para enviarte el enlace")
        if st.button("Enviar enlace de restablecimiento"):
            base_url = st.secrets["app"]["base_url"]  # e.g. "https://tu-app.onrender.com"
            ok = auth.request_password_reset(username_fp, base_url, send_email_smtp)
            if ok:
                st.success("Te enviamos un correo con el enlace para restablecer tu contraseña (revisa SPAM).")
            else:
                st.error("No encontramos un email para ese usuario o el usuario no existe.")
    st.stop()

# =========================
# 7) Contenido protegido
# =========================
st.success(f"¡Bienvenido, {user.display_name}! (rol: {user.role})")
if st.button("Cerrar sesión"):
    for k in list(st.session_state.keys()):
        if k.startswith("insurapp"):
            st.session_state.pop(k)
    st.rerun()

