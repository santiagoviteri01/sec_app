import streamlit as st
from auth_mfa import AuthManager, DictUserStore, hash_password

st.set_page_config(page_title="Demo Auth MFA", layout="centered")

# --- Usuarios en memoria para pruebas ---
USUARIOS = {
    "demo": {
        "display_name": "Usuario Demo",
        "role": "admin",
        # Para demo: hasheamos en runtime. En producción pega un hash fijo.
        "password_hash": hash_password("demo123"),
        # "mfa_secret": None  # se autogenera al primer login
    }
}

store = DictUserStore(USUARIOS)
auth = AuthManager(store, issuer_name="InsurApp-Demo")

# --- Login + MFA ---
user = auth.login(key_prefix="demoapp")
if not user:
    st.stop()

# --- Contenido protegido ---
st.success(f"¡Bienvenido, {user.display_name}! (rol: {user.role})")
st.write("Esta es la zona protegida de tu app de pruebas ✅")

# --- Logout simple ---
if st.button("Cerrar sesión"):
    for k in list(st.session_state.keys()):
        if k.startswith("demoapp"):
            st.session_state.pop(k)
    st.experimental_rerun()
