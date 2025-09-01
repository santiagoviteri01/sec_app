# app.py
import streamlit as st
from auth_mfa import AuthManager, DictUserStore, hash_password

st.set_page_config(page_title="Demo Auth MFA", layout="centered")

@st.cache_resource
def get_store():
    return DictUserStore({
        "demo": {
            "display_name": "Usuario Demo",
            "role": "admin",
            "password_hash": hash_password("demo123"),
            # "mfa_secret": None  # se autogenera y se persiste en session_state
        }
    })

store = get_store()
auth = AuthManager(store, issuer_name="InsurApp-Demo")

user = auth.login(key_prefix="demoapp", debug=True)  # debug=True muestra el TOTP del servidor
if not user:
    st.stop()

st.success(f"¡Bienvenido, {user.display_name}! (rol: {user.role})")
if st.button("Cerrar sesión"):
    for k in list(st.session_state.keys()):
        if k.startswith("demoapp"):
            st.session_state.pop(k)
    st.rerun()

