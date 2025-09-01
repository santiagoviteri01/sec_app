# app.py
import os
import streamlit as st
from auth_mfa import AuthManager, DictUserStore, SheetUserStore, hash_password

st.set_page_config(page_title="Demo Auth MFA", layout="centered")

def send_email_smtp(*, to: str, subject: str, html: str):
    import smtplib
    from email.message import EmailMessage

    host = os.getenv("SMTP_HOST")
    port = int(os.getenv("SMTP_PORT", "587"))
    user = os.getenv("SMTP_USER")
    pwd  = os.getenv("SMTP_PASS")
    sender = os.getenv("SMTP_FROM", user)

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = to
    msg.set_content("Para ver este mensaje usa un cliente compatible con HTML.")
    msg.add_alternative(html, subtype="html")

    with smtplib.SMTP(host, port) as s:
        s.starttls()
        if user and pwd:
            s.login(user, pwd)
        s.send_message(msg)

@st.cache_resource
def get_store():
    return DictUserStore({
        "demo": {
            "display_name": "Usuario Demo",
            "role": "admin",
            "password_hash": hash_password("demo123"),
            # "mfa_secret": None  # se autogenera y se persiste en session_state
            "email": os.getenv("SMTP_TEST_TO", "demo@example.com"),  # <-- asegúrate de tener email
        }
    })

store = get_store()
auth = AuthManager(store, issuer_name="InsurApp-Demo")

# ---------- 1) Manejar link de reseteo ANTES del login ----------
params = st.query_params  # en versiones antiguas: st.experimental_get_query_params()
reset_token = params.get("reset")
reset_user  = params.get("u")

if reset_token and reset_user:
    st.markdown("## Restablecer contraseña")
    new1 = st.text_input("Nueva contraseña", type="password")
    new2 = st.text_input("Confirmar nueva contraseña", type="password")

    if st.button("Guardar nueva contraseña"):
        if new1 and new1 == new2:
            if auth.verify_reset_token(reset_user, reset_token):
                ok = auth.finalize_password_reset(reset_user, new1)
                if ok:
                    st.success("✅ Contraseña actualizada. Ya puedes iniciar sesión.")
                    # Limpiar query params y volver al login
                    try:
                        st.query_params.clear()
                    except Exception:
                        st.experimental_set_query_params()  # fallback versiones antiguas
                    st.stop()
                else:
                    st.error("No se pudo actualizar la contraseña.")
            else:
                st.error("El enlace es inválido o expiró.")
        else:
            st.warning("Las contraseñas no coinciden.")
    st.stop()  # no renders el login normal si estás en el flujo de reset

# ---------- 2) Login normal + MFA ----------
user = auth.login(key_prefix="demoapp", debug=True)

# ---------- 3) Si aún no está logueado, mostrar 'Olvidé mi contraseña' ----------
if not user:
    with st.expander("¿Olvidaste tu contraseña?"):
        username_fp = st.text_input("Ingresa tu usuario para enviarte el enlace")
        if st.button("Enviar enlace de restablecimiento"):
            base_url = os.getenv("APP_BASE_URL", "http://localhost:8501")
            ok = auth.request_password_reset(username_fp, base_url, send_email_smtp)
            if ok:
                st.success("Te enviamos un correo con el enlace para restablecer tu contraseña (revisa SPAM).")
            else:
                st.error("No encontramos un email para ese usuario o el usuario no existe.")
    st.stop()

# ---------- 4) Contenido protegido ----------
st.success(f"¡Bienvenido, {user.display_name}! (rol: {user.role})")
if st.button("Cerrar sesión"):
    for k in list(st.session_state.keys()):
        if k.startswith("demoapp"):
            st.session_state.pop(k)
    st.rerun()


