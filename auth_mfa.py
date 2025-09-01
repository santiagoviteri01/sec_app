# auth_mfa.py
from __future__ import annotations
import io
import time
import base64
from dataclasses import dataclass
from typing import Optional, Dict

import streamlit as st
import pyotp
import qrcode
from passlib.context import CryptContext

# === Opcional (backend en Google Sheets) ===
try:
    import gspread
    from google.oauth2.service_account import Credentials
except Exception:
    gspread = None
    Credentials = None

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


# ---------- Modelo ----------
@dataclass
class User:
    username: str
    display_name: str
    role: str
    password_hash: str
    mfa_secret: Optional[str] = None
    email: Optional[str] = None


# ---------- UserStore base ----------
class BaseUserStore:
    def get_user(self, username: str) -> Optional[User]:
        raise NotImplementedError

    def update_user(self, username: str, **fields) -> None:
        raise NotImplementedError


# ---------- Backend 1: Google Sheets ----------
class SheetUserStore(BaseUserStore):
    """
    Espera una hoja 'usuarios' (o la que indiques) con columnas:
    username | display_name | role | password_hash | mfa_secret | email
    """
    def __init__(self, sheet_key: str, creds_dict: dict, worksheet_name: str = "usuarios"):
        if gspread is None or Credentials is None:
            raise RuntimeError("gspread y google.oauth2.service_account son requeridos para SheetUserStore.")
        creds = Credentials.from_service_account_info(creds_dict, scopes=[
            "https://www.googleapis.com/auth/spreadsheets"
        ])
        self.gc = gspread.authorize(creds)
        self.sh = self.gc.open_by_key(sheet_key)
        self.ws = self.sh.worksheet(worksheet_name)
        self._header = [h.strip() for h in self.ws.row_values(1)]
        self._idx = {name: i for i, name in enumerate(self._header)}

    def _row_to_user(self, row: list[str]) -> Optional[User]:
        row = row + [""] * max(0, len(self._header) - len(row))
        d = {h: row[i] if i < len(row) else "" for i, h in enumerate(self._header)}
        if not d.get("username"):
            return None
        return User(
            username=d.get("username", "").strip(),
            display_name=d.get("display_name", "").strip() or d.get("username", ""),
            role=d.get("role", "viewer").strip() or "viewer",
            password_hash=d.get("password_hash", "").strip(),
            mfa_secret=(d.get("mfa_secret") or "").strip() or None,
            email=(d.get("email") or "").strip() or None,
        )

    @st.cache_data(ttl=60, show_spinner=False)
    def _dump_all(self):
        return self.ws.get_all_values()

    def get_user(self, username: str) -> Optional[User]:
        data = self._dump_all()
        if not data or len(data) < 2:
            return None
        for i in range(1, len(data)):
            row = data[i]
            user = self._row_to_user(row)
            if user and user.username == username:
                return user
        return None

    def update_user(self, username: str, **fields) -> None:
        data = self.ws.get_all_values()
        for i in range(1, len(data)):
            row = data[i]
            if len(row) <= self._idx["username"]:
                continue
            if row[self._idx["username"]].strip() == username:
                for k, v in fields.items():
                    if k in self._idx:
                        col = self._idx[k] + 1
                        self.ws.update_cell(i + 1, col, v if v is not None else "")
                st.cache_data.clear()
                return
        # Crear si no existe
        new_row = [""] * len(self._header)
        if "username" not in fields:
            fields["username"] = username
        for k, v in fields.items():
            if k in self._idx:
                new_row[self._idx[k]] = v if v is not None else ""
        self.ws.append_row(new_row)
        st.cache_data.clear()


# ---------- Backend 2: En memoria (útil para pruebas / migración) ----------
class DictUserStore(BaseUserStore):
    """
    users_dict: { "user": {"password_hash": "...", "display_name": "...", "role": "...", "mfa_secret": "...", "email": "..."} }
    """
    def __init__(self, users_dict: Dict[str, Dict]):
        self.users = users_dict

    def get_user(self, username: str) -> Optional[User]:
        d = self.users.get(username)
        if not d:
            return None
        return User(
            username=username,
            display_name=d.get("display_name") or username,
            role=d.get("role", "viewer"),
            password_hash=d.get("password_hash", ""),
            mfa_secret=d.get("mfa_secret"),
            email=d.get("email"),
        )

    def update_user(self, username: str, **fields) -> None:
        d = self.users.get(username, {})
        d.update(fields)
        self.users[username] = d


# ---------- Utilidades de seguridad ----------
def hash_password(plain: str) -> str:
    return pwd_context.hash(plain)

def verify_password(plain: str, hashed: str) -> bool:
    if not hashed:
        return False
    try:
        return pwd_context.verify(plain, hashed)
    except Exception:
        return False


# ---------- Manager principal ----------
class AuthManager:
    def __init__(self, store: BaseUserStore, issuer_name: str = "InsurApp"):
        self.store = store
        self.issuer_name = issuer_name

    # -- TOTP helpers --
    def _ensure_mfa_secret(self, user: User) -> str:
        """
        Parche para demos: si usas DictUserStore, persistimos en session_state para que
        el secreto no cambie en cada rerun de Streamlit.
        """
        ss_key = f"mfa_secret_{user.username}"

        if isinstance(self.store, DictUserStore):
            # ¿Ya guardado en sesión?
            if ss_key in st.session_state:
                if not user.mfa_secret:
                    self.store.update_user(user.username, mfa_secret=st.session_state[ss_key])
                return st.session_state[ss_key]

        if user.mfa_secret:
            if isinstance(self.store, DictUserStore):
                st.session_state[ss_key] = user.mfa_secret
            return user.mfa_secret

        secret = pyotp.random_base32()
        self.store.update_user(user.username, mfa_secret=secret)
        if isinstance(self.store, DictUserStore):
            st.session_state[ss_key] = secret
        user.mfa_secret = secret
        return secret

    def provisioning_uri(self, user: User) -> str:
        secret = self._ensure_mfa_secret(user)
        return pyotp.totp.TOTP(secret).provisioning_uri(
            name=user.username,
            issuer_name=self.issuer_name
        )

    def qr_png_base64(self, uri: str) -> str:
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return base64.b64encode(buf.getvalue()).decode()

    def _render_debug_totp(self, secret: str) -> None:
        with st.expander("Debug TOTP (solo desarrollo)"):
            st.write("Este valor DEBE coincidir con tu app Authenticator (no lo dejes en producción).")
            st.code(pyotp.TOTP(secret).now())
            # Barra de tiempo aproximada al próximo tick
            # (solo visual; TOTP estándar = 30s por paso)
            epoch = int(time.time())
            st.progress((epoch % 30) / 30)

    # -- Flujo UI en Streamlit --
    def login(self, key_prefix: str = "auth", debug: bool = False) -> Optional[User]:
        """
        Retorna el User autenticado o None. Maneja:
        1) Usuario/Contraseña (bcrypt)
        2) MFA TOTP (con tolerancia de ventana)
        Persiste en st.session_state[key_prefix + "_user"]
        """
        sess_user_key = f"{key_prefix}_user"
        step_key = f"{key_prefix}_step"
        u_key = f"{key_prefix}_username"
        p_key = f"{key_prefix}_password"

        # Ya autenticado
        if sess_user_key in st.session_state and st.session_state[sess_user_key]:
            return st.session_state[sess_user_key]

        st.markdown("### Iniciar sesión")
        username = st.text_input("Usuario", key=u_key)
        password = st.text_input("Contraseña", type="password", key=p_key)

        # Paso 1: credenciales
        if st.button("Ingresar"):
            user = self.store.get_user((username or "").strip()) if username else None
            if not user or not verify_password(password, user.password_hash):
                st.error("❌ Usuario o contraseña incorrectos.")
                return None
            st.session_state[step_key] = "mfa"
            st.session_state[sess_user_key] = None
            st.session_state[f"{key_prefix}_pending_username"] = user.username
            st.rerun()

        # Paso 2: MFA
        if st.session_state.get(step_key) == "mfa":
            pending_username = st.session_state.get(f"{key_prefix}_pending_username")
            user = self.store.get_user(pending_username) if pending_username else None
            if not user:
                st.error("Sesión inválida, vuelve a iniciar sesión.")
                st.session_state.pop(step_key, None)
                return None

            secret = self._ensure_mfa_secret(user)
            uri = self.provisioning_uri(user)
            qr = self.qr_png_base64(uri)

            with st.expander("Configurar MFA (solo si aún no lo hiciste)"):
                st.markdown("Escanea este QR con Google Authenticator / Authy:")
                st.image(f"data:image/png;base64,{qr}")
                st.code(f"Clave secreta (backup): {secret}")

            if debug:
                self._render_debug_totp(secret)

            otp = st.text_input("Código de 6 dígitos (MFA)", max_chars=6)
            if st.button("Verificar MFA"):
                otp = (otp or "").strip().replace(" ", "")
                totp = pyotp.TOTP(secret)
                # valid_window=2 => acepta el paso actual y ±1 paso extra (~30-60s de tolerancia)
                if totp.verify(otp, valid_window=2):
                    st.success("✅ Autenticación correcta.")
                    st.session_state[sess_user_key] = user
                    st.session_state.pop(step_key, None)
                    for k in (u_key, p_key, f"{key_prefix}_pending_username"):
                        st.session_state.pop(k, None)
                    time.sleep(0.2)
                    st.rerun()
                else:
                    st.error("❌ Código MFA inválido. Revisa hora del servidor y del teléfono, y vuelve a intentar.")
        return None

    def _now_utc(self) -> datetime:
        return datetime.now(timezone.utc)

    def _hash_token(self, token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def _constant_time_equal(self, a: str, b: str) -> bool:
        return hmac.compare_digest(a or "", b or "")

    def request_password_reset(self, username: str, app_base_url: str, send_email_func) -> bool:
        user = self.store.get_user((username or "").strip())
        if not user or not user.email:
            return False

        # Generar token y persistir hash + expiry (1 hora)
        token = secrets.token_urlsafe(32)
        token_hash = self._hash_token(token)
        expiry = (self._now_utc() + timedelta(hours=1)).isoformat()

        # Guardar en el store
        self.store.update_user(
            user.username,
            reset_token_hash=token_hash,
            reset_token_expiry=expiry,
            reset_requested_at=self._now_utc().isoformat(),
        )

        # Construir link de reseteo
        reset_link = f"{app_base_url}?reset={token}&u={user.username}"

        # Enviar email
        subject = "Restablecer contraseña - InsurApp"
        
        display = escape(user.display_name or user.username)
        reset_link = f"{app_base_url}?reset={token}&u={user.username}"
        
        html = dedent(f'''\
        <p>Hola {display},</p>
        <p>Recibimos una solicitud para restablecer tu contraseña.</p>
        <p>Haz clic en el siguiente enlace para continuar (válido 1 hora):<br>
        <a href="{reset_link}">{reset_link}</a></p>
        <p>Si tú no solicitaste este cambio, ignora este mensaje.</p>
        <p>— InsurApp</p>
        ''')
        
        send_email_func(to=user.email, subject=subject, html=html)
        return True

    def verify_reset_token(self, username: str, token: str) -> bool:
        """Valida hash y expiración del token."""
        user = self.store.get_user((username or "").strip())
        if not user:
            return False
        # Cargar campos desde store (pueden estar en dict o sheet)
        # Nota: accedemos a través de store.get_user y suponemos que update_user guarda los campos.
        # Para SheetUserStore, asegúrate de tener las columnas.
        # Obtenemos el usuario de nuevo por si el store no expone directamente los nuevos campos
        # (en DictUserStore sí estarán, en SheetUserStore también si las columnas existen).
        # Recupero valores "a mano" según backend:
        reset_hash = getattr(user, "reset_token_hash", None)
        reset_exp = getattr(user, "reset_token_expiry", None)

        # Si el modelo User no tiene esos atributos, intenta leerlos directamente (DictUserStore)
        # Añadimos una lectura directa del store si fuera necesario:
        if reset_hash is None or reset_exp is None:
            if isinstance(self.store, DictUserStore):
                d = self.store.users.get(username, {})
                reset_hash = d.get("reset_token_hash")
                reset_exp = d.get("reset_token_expiry")
            elif isinstance(self.store, SheetUserStore):
                # Relee crudo desde la Sheet
                # (re-usa API pública: get_user ya mapea columnas conocidas,
                # si deseas, puedes extender User para incluir estos campos)
                pass

        if not reset_hash or not reset_exp:
            return False

        # Validar expiración
        try:
            exp_dt = datetime.fromisoformat(reset_exp)
        except Exception:
            return False
        if self._now_utc() > exp_dt:
            return False

        # Validar hash
        return self._constant_time_equal(reset_hash, self._hash_token(token))

    def finalize_password_reset(self, username: str, new_password: str) -> bool:
        """
        Setea nueva contraseña y limpia token. Devuelve True si ok.
        """
        user = self.store.get_user((username or "").strip())
        if not user:
            return False

        new_hash = hash_password(new_password)
        # Limpiamos los campos de token
        self.store.update_user(
            user.username,
            password_hash=new_hash,
            reset_token_hash="",
            reset_token_expiry="",
            reset_requested_at="",
        )
        return True

    def verify_reset_token(self, username: str, token: str) -> bool:
        """Valida hash y expiración del token."""
        user = self.store.get_user((username or "").strip())
        if not user:
            return False
        # Cargar campos desde store (pueden estar en dict o sheet)
        # Nota: accedemos a través de store.get_user y suponemos que update_user guarda los campos.
        # Para SheetUserStore, asegúrate de tener las columnas.
        # Obtenemos el usuario de nuevo por si el store no expone directamente los nuevos campos
        # (en DictUserStore sí estarán, en SheetUserStore también si las columnas existen).
        # Recupero valores "a mano" según backend:
        reset_hash = getattr(user, "reset_token_hash", None)
        reset_exp = getattr(user, "reset_token_expiry", None)

        # Si el modelo User no tiene esos atributos, intenta leerlos directamente (DictUserStore)
        # Añadimos una lectura directa del store si fuera necesario:
        if reset_hash is None or reset_exp is None:
            if isinstance(self.store, DictUserStore):
                d = self.store.users.get(username, {})
                reset_hash = d.get("reset_token_hash")
                reset_exp = d.get("reset_token_expiry")
            elif isinstance(self.store, SheetUserStore):
                # Relee crudo desde la Sheet
                # (re-usa API pública: get_user ya mapea columnas conocidas,
                # si deseas, puedes extender User para incluir estos campos)
                pass

        if not reset_hash or not reset_exp:
            return False

        # Validar expiración
        try:
            exp_dt = datetime.fromisoformat(reset_exp)
        except Exception:
            return False
        if self._now_utc() > exp_dt:
            return False

        # Validar hash
        return self._constant_time_equal(reset_hash, self._hash_token(token))

    def finalize_password_reset(self, username: str, new_password: str) -> bool:
        """
        Setea nueva contraseña y limpia token. Devuelve True si ok.
        """
        user = self.store.get_user((username or "").strip())
        if not user:
            return False

        new_hash = hash_password(new_password)
        # Limpiamos los campos de token
        self.store.update_user(
            user.username,
            password_hash=new_hash,
            reset_token_hash="",
            reset_token_expiry="",
            reset_requested_at="",
        )
        return True

