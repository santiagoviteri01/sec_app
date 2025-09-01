# app.py
import os, json
import streamlit as st
from pathlib import Path

from auth_mfa import (
    AuthManager, S3UserStore, SheetSeeder, hash_password  # <- NUEVOS
)

st.set_page_config(page_title="InsurApp Login", layout="centered")
# --- Diagnóstico S3 (antes de S3UserStore) ---
# Pégalo en tu app antes de crear S3UserStore
import streamlit as st, boto3
from botocore.exceptions import ClientError
from auth_mfa import S3UserStore
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
s3_store = S3UserStore(
    bucket=st.secrets["aws"]["bucket_name"],     # "insurapp-uploader"
    prefix="auth/users",                         # carpeta dentro del bucket
    aws_region=st.secrets["aws"]["region"],      # debe coincidir con la región REAL del bucket
    seeder=seeder,
)
auth = AuthManager(s3_store, issuer_name="InsurApp")
# Asegura credenciales desde st.secrets
# credenciales desde secrets
boto3.setup_default_session(
    aws_access_key_id=st.secrets["aws"]["access_key_id"],
    aws_secret_access_key=st.secrets["aws"]["secret_access_key"],
    region_name=st.secrets["aws"]["region"],
)

BUCKET = st.secrets["aws"]["bucket_name"]
REGION = st.secrets["aws"]["region"]
PREFIX = "auth/users"

s3 = boto3.client("s3", region_name=REGION)

# 0) NO uses ACL si el bucket tiene ACL deshabilitadas
try:
    s3.put_object(Bucket=BUCKET, Key=f"{PREFIX}/.healthcheck", Body=b"")  # sin ACL
    st.success("S3 OK: escritura en prefijo auth/users/")
except botocore.exceptions.ClientError as e:
    code = e.response.get("Error", {}).get("Code")
    st.error(f"PutObject falló en s3://{BUCKET}/{PREFIX}/  ({code}). "
             "Si es AccessDenied, revisa la policy; si es NoSuchBucket, revisa el nombre.")
    st.stop()

# 1) Simula el read del store para un usuario de prueba
test_username = "alguien@tu-dominio.com"  # pon un correo real que tengas en tu Sheet
key = f"{PREFIX}/{test_username}.json"
try:
    _ = s3.get_object(Bucket=BUCKET, Key=key)
    st.info(f"Encontrado {key} (usuario ya existe en S3).")
except botocore.exceptions.ClientError as e:
    code = e.response.get("Error", {}).get("Code")
    if code in ("NoSuchKey", "404"):
        st.info(f"No existe {key} (esto es normal si nunca se sembró; el seeder lo creará on-demand).")
    elif code in ("NoSuchBucket", "PermanentRedirect"):
        st.error(f"{code}: bucket/región incorrectos. Asegúrate que [aws].bucket_name y [aws].region son los del bucket de AUTH.")
        st.stop()
    elif code == "AccessDenied":
        st.error("AccessDenied leyendo el usuario. Agrega permisos s3:GetObject en arn:aws:s3:::<bucket>/auth/users/*")
        st.stop()
    else:
        st.error(f"get_object error inesperado: {code}")
        st.stop()

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

# ======================================
# 3) Store S3 (fuente de verdad de auth)
# ======================================


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
user = auth.login(key_prefix="insurapp-auth-prod-abc123", debug=False)

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

