# auth_mfa.py
from __future__ import annotations
import io, time, base64, json, hashlib, hmac, secrets
from dataclasses import dataclass
from typing import Optional, Dict
from datetime import datetime, timedelta, timezone
from html import escape
from textwrap import dedent

import streamlit as st
import pyotp
import qrcode

# ⬇️ IMPORT CLAVE
try:
    from passlib.context import CryptContext
except Exception as e:
    raise RuntimeError(
        "Falta la dependencia 'passlib'. Agrega 'passlib[bcrypt]' a requirements.txt y vuelve a desplegar."
    ) from e

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
        # meta de reset (opcionales)
    reset_token_hash: Optional[str] = None
    reset_token_expiry: Optional[str] = None
    reset_requested_at: Optional[str] = None


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
            user = self.store.get_user((username or "").strip().lower()) if username else None
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
        uname = (username or "").strip().lower()
        user = self.store.get_user(uname)
        if not user:
            return False

        reset_hash = getattr(user, "reset_token_hash", None)
        reset_exp  = getattr(user, "reset_token_expiry", None)

        # Si no vino en el modelo User, intenta leer crudo desde el store (S3)
        if (not reset_hash or not reset_exp) and hasattr(self.store, "get_reset_meta"):
            reset_hash, reset_exp = self.store.get_reset_meta(uname)

        if not reset_hash or not reset_exp:
            return False

        try:
            exp_dt = datetime.fromisoformat(reset_exp)
        except Exception:
            return False
        if self._now_utc() > exp_dt:
            return False

        return self._constant_time_equal(reset_hash, self._hash_token(token))

    def finalize_password_reset(self, username: str, new_password: str) -> bool:
        uname = (username or "").strip().lower()
        user = self.store.get_user(uname)
        if not user:
            return False

        new_hash = hash_password(new_password)
        self.store.update_user(
            user.username,
            password_hash=new_hash,
            reset_token_hash="",
            reset_token_expiry="",
            reset_requested_at="",
        )
        return True

import json
import boto3
from botocore.exceptions import ClientError

# ---------- Seeder desde Google Sheets (para poblar S3 si falta) ----------
class SheetSeeder:
    """
    Busca un usuario por email en Google Sheets y devuelve un dict con
    campos mínimos para crear al usuario en S3.
    """
    def __init__(self, *, sheet_key: str, creds_dict: dict, worksheet_name: str = "usuarios",
                 email_col="CORREO ELECTRÓNICO", cedula_col="CÉDULA",
                 name_col="NOMBRE COMPLETO", role_default="cliente"):
        # Import local para evitar NameError si el módulo no existe o el orden de import falló
        try:
            import gspread  # type: ignore
            from google.oauth2.service_account import Credentials  # type: ignore
        except Exception as e:
            raise RuntimeError(
                "Faltan dependencias para Google Sheets. "
                "Instala 'gspread' y 'google-auth' en requirements.txt."
            ) from e

        scopes = ["https://www.googleapis.com/auth/spreadsheets"]
        creds = Credentials.from_service_account_info(creds_dict, scopes=scopes)
        self.gc = gspread.authorize(creds)
        self.sh = self.gc.open_by_key(sheet_key)
        self.ws = self.sh.worksheet(worksheet_name)

        self.headers = [h.strip() for h in self.ws.row_values(1)]
        self.idx = {name: i for i, name in enumerate(self.headers)}
        self.email_col = email_col
        self.cedula_col = cedula_col
        self.name_col = name_col
        self.role_default = role_default

    @st.cache_data(ttl=60, show_spinner=False)
    def _dump_all(self):
        return self.ws.get_all_values()

    def find_user(self, email: str) -> Optional[Dict]:
        data = self._dump_all()
        if not data or len(data) < 2:
            return None
        target = (email or "").strip().lower()
        for i in range(1, len(data)):
            row = data[i] + [""] * max(0, len(self.headers) - len(data[i]))
            try:
                email_val = row[self.idx[self.email_col]].strip().lower()
            except KeyError:
                # columna mal nombrada
                return None
            if email_val == target:
                cedula = row[self.idx.get(self.cedula_col, -1)].strip() if self.cedula_col in self.idx else ""
                nombre = row[self.idx.get(self.name_col, -1)].strip() if self.name_col in self.idx else target
                return {
                    "username": email_val,
                    "display_name": nombre or target,
                    "role": self.role_default,
                    "email": email_val,
                    "cedula": cedula,
                }
        return None


# ---------- Store en S3 ----------
class S3UserStore(BaseUserStore):
    """
    Guarda cada usuario como un JSON en:
      s3://{bucket}/{prefix}/{username}.json

    Campos JSON esperados:
      username, display_name, role, email, password_hash, mfa_secret,
      reset_token_hash, reset_token_expiry, reset_requested_at, created_at, updated_at

    Si no encuentra el usuario, intenta sembrarlo con SheetSeeder
    (password inicial = hash(cedula)).
    """
    def __init__(self, *, bucket: str, prefix: str = "auth/users",
                 aws_region: Optional[str] = None,
                 aws_access_key_id: Optional[str] = None,
                 aws_secret_access_key: Optional[str] = None,
                 aws_session_token: Optional[str] = None,
                 seeder: Optional[SheetSeeder] = None):
        self.bucket = bucket
        self.prefix = prefix.strip("/")
        self.seeder = seeder

        self.s3 = boto3.client(
            "s3",
            region_name=aws_region,
            aws_access_key_id=aws_access_key_id,
            aws_secret_access_key=aws_secret_access_key,
            aws_session_token=aws_session_token,
        )

    def _key(self, username: str) -> str:
        uname = (username or "").strip().lower()
        return f"{self.prefix}/{uname}.json"

    def _load_json(self, key: str) -> Optional[Dict]:
        try:
            obj = self.s3.get_object(Bucket=self.bucket, Key=key)
            return json.loads(obj["Body"].read().decode("utf-8"))
        except ClientError as e:
            code = e.response.get("Error", {}).get("Code", "Unknown")
            # Normal: usuario aún no existe en S3
            if code in ("NoSuchKey", "404"):
                return None
    
            # Diagnóstico visible en la UI
            import streamlit as st
            if code == "AccessDenied":
                st.error(f"S3 AccessDenied al leer s3://{self.bucket}/{key}. "
                         f"Revisa la policy del usuario IAM: debe permitir "
                         f"s3:GetObject en arn:aws:s3:::{self.bucket}/{self.prefix}/*")
            elif code in ("PermanentRedirect", "AuthorizationHeaderMalformed"):
                st.error("❗ Región incorrecta: el bucket está en otra región distinta a la configurada. "
                         "Ajusta [aws].region en secrets a la región REAL del bucket.")
            elif code == "NoSuchBucket":
                st.error(f"❗ NoSuchBucket: el bucket '{self.bucket}' no existe (o el nombre está mal).")
            else:
                st.error(f"S3 get_object falló ({code}) para s3://{self.bucket}/{key}")
            raise

    def _save_json(self, key: str, data: Dict) -> None:
        data = dict(data)
        # timestamps
        now_iso = datetime.utcnow().isoformat() + "Z"
        if "created_at" not in data or not data["created_at"]:
            data["created_at"] = now_iso
        data["updated_at"] = now_iso
        self.s3.put_object(
            Bucket=self.bucket,
            Key=key,
            Body=json.dumps(data, ensure_ascii=False).encode("utf-8"),
            ContentType="application/json",
        )

    def get_user(self, username: str) -> Optional[User]:
        if not username:
            return None
        uname = (username or "").strip().lower()
        key = self._key(uname)
        data = self._load_json(key)

        # Si no está en S3 y hay seeder => sembrar
        if data is None and self.seeder:
            seed = self.seeder.find_user(uname)
            if seed and seed.get("cedula"):
                pwd_hash = hash_password(seed["cedula"])
                data = {
                    "username": seed["username"],
                    "display_name": seed["display_name"],
                    "role": seed["role"],
                    "email": seed["email"],
                    "password_hash": pwd_hash,
                    "mfa_secret": "",
                    "reset_token_hash": "",
                    "reset_token_expiry": "",
                    "reset_requested_at": "",
                }
                self._save_json(key, data)

        if not data:
            return None

        return User(
            username=data.get("username", uname),
            display_name=data.get("display_name") or uname,
            role=data.get("role", "viewer"),
            password_hash=data.get("password_hash", ""),
            mfa_secret=data.get("mfa_secret") or None,
            email=data.get("email") or None,
            reset_token_hash=data.get("reset_token_hash") or None,
            reset_token_expiry=data.get("reset_token_expiry") or None,
            reset_requested_at=data.get("reset_requested_at") or None,
        )
    def get_reset_meta(self, username: str) -> tuple[Optional[str], Optional[str]]:
        uname = (username or "").strip().lower()
        data = self._load_json(self._key(uname)) or {}
        return data.get("reset_token_hash"), data.get("reset_token_expiry")
    def update_user(self, username: str, **fields) -> None:
        if not username:
            return
        key = self._key(username)
        data = self._load_json(key) or {"username": username}
        # merge
        for k, v in fields.items():
            data[k] = v
        self._save_json(key, data)
