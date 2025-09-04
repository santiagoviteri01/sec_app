# app.py
import json
import streamlit as st
from auth_mfa import AuthManager, S3UserStore, CombinedSeeder ,SheetSeeder
import boto3, botocore
from botocore.exceptions import ClientError

st.set_page_config(page_title="InsurApp Login", layout="centered")

# ========= 0) Validaciones básicas =========
required = ["access_key_id","secret_access_key","bucket_name","region"]
missing = [k for k in required if not st.secrets.get("aws", {}).get(k)]
if missing:
    st.error(f"Faltan secrets AWS: {', '.join(missing)} en [aws].")
    st.stop()

if "gcp_service_account" not in st.secrets:
    st.error("Falta [gcp_service_account] en secrets para leer el Google Sheet.")
    st.stop()

# ========= 1) Configurar boto3 primero (antes del store) =========
boto3.setup_default_session(
    aws_access_key_id=st.secrets["aws"]["access_key_id"],
    aws_secret_access_key=st.secrets["aws"]["secret_access_key"],
    region_name=st.secrets["aws"]["region"],
)

BUCKET = st.secrets["aws"]["bucket_name"]
REGION = st.secrets["aws"]["region"]
PREFIX = "auth/users"
s3 = boto3.client("s3", region_name=REGION)

# ========= 2) Diagnóstico mínimo (sin ListBuckets) =========
# Escritura en el prefijo (no usar ACL si el bucket tiene ACL deshabilitadas)
try:
    s3.put_object(Bucket=BUCKET, Key=f"{PREFIX}/.healthcheck", Body=b"")
    st.info("S3 OK: escritura en prefijo auth/users/")
except botocore.exceptions.ClientError as e:
    code = e.response.get("Error", {}).get("Code")
    st.error(f"PutObject falló en s3://{BUCKET}/{PREFIX}/  ({code}). "
             "Si es AccessDenied, revisa la policy; si es NoSuchBucket, revisa nombre/región.")
    st.stop()

# ========= 3) Seeder desde Google Sheets =========
creds_dict = dict(st.secrets["gcp_service_account"])
clientes_seeder = SheetSeeder(
    sheet_key="13hY8la9Xke5-wu3vmdB-tNKtY5D6ud4FZrJG2_HtKd8",
    creds_dict=creds_dict,
    worksheet_name="aseguradosatlantida",
    email_col="CORREO ELECTRÓNICO",
    cedula_col="NÚMERO IDENTIFICACIÓN",
    name_col="NOMBRE COMPLETO",
    role_default="cliente",
)
admins_seeder = SheetSeeder(
    sheet_key="13hY8la9Xke5-wu3vmdB-tNKtY5D6ud4FZrJG2_HtKd8",
    creds_dict=dict(creds_dict),
    worksheet_name="admins",
    email_col="CORREO ELECTRÓNICO",
    cedula_col="NÚMERO IDENTIFICACIÓN",  # o la que tengas
    name_col="NOMBRE COMPLETO",
    role_default="admin",
)

seeder = CombinedSeeder(clientes_seeder, admins_seeder)
# ========= 4) Store S3 (fuente de verdad) =========
s3_store = S3UserStore(
    bucket=BUCKET,
    prefix=PREFIX,
    aws_region=REGION,
    seeder=seeder,
)
auth = AuthManager(s3_store, issuer_name="InsurApp")

# ========= 5) Envío de email (reset) =========
def send_email_smtp(*, to: str, subject: str, html: str):
    import smtplib
    from email.message import EmailMessage
    host = st.secrets["smtp"]["host"]
    port = int(st.secrets["smtp"]["port"])
    user = st.secrets["smtp"]["user"]
    pwd  = st.secrets["smtp"]["password"]
    sender = st.secrets["smtp"]["from"]

    msg = EmailMessage()
    msg["Subject"] = subject; msg["From"] = sender; msg["To"] = to
    msg.set_content("Para ver este mensaje usa un cliente compatible con HTML.")
    msg.add_alternative(html, subtype="html")
    with smtplib.SMTP(host, port) as s:
        s.starttls()
        if user and pwd: s.login(user, pwd)
        s.send_message(msg)

# ========= 6) Flujo de reseteo por link (antes del login) =========
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
    st.stop()

# ========= 7) Login + MFA =========
user = auth.login(key_prefix="insurapp-uploader", debug=False)  # <- prefijo corto; NO es el bucket

# ========= 8) ¿Olvidaste tu contraseña? =========
if not user:
    with st.expander("¿Olvidaste tu contraseña?"):
        username_fp = st.text_input("Ingresa tu usuario (correo) para enviarte el enlace")
        if st.button("Enviar enlace de restablecimiento"):
            base_url = "https://secapp.streamlit.app/"
            ok = auth.request_password_reset(username_fp, base_url, send_email_smtp)
            if ok:
                st.success("Te enviamos un correo con el enlace para restablecer tu contraseña (revisa SPAM).")
            else:
                st.error("No encontramos un email para ese usuario o el usuario no existe.")
    st.stop()

# ========= 9) Contenido protegido =========
st.success(f"¡Bienvenido, {user.display_name}! (rol: {user.role})")
if st.button("Cerrar sesión"):
    for k in list(st.session_state.keys()):
        if k.startswith("insurapp"):
            st.session_state.pop(k)
    st.rerun()

