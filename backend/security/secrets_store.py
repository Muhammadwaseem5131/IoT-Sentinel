import os
import stat

from cryptography.fernet import Fernet, InvalidToken

KEY_PATH = os.getenv(
    "SECRETS_ENCRYPTION_KEY_PATH",
    os.path.join(os.path.dirname(__file__), "..", ".secrets.key"),
)


def _get_or_create_key() -> bytes:
    if os.path.exists(KEY_PATH):
        with open(KEY_PATH, "rb") as f:
            return f.read().strip()
    key = Fernet.generate_key()
    with open(KEY_PATH, "wb") as f:
        f.write(key)
    if os.name != "nt":
        os.chmod(KEY_PATH, stat.S_IRUSR | stat.S_IWUSR)
    return key


_fernet = Fernet(_get_or_create_key())


def encrypt_secret(plaintext: str) -> bytes:
    return _fernet.encrypt(plaintext.encode("utf-8"))


def decrypt_secret(blob: bytes) -> str:
    try:
        return _fernet.decrypt(blob).decode("utf-8")
    except InvalidToken:
        return ""


def mask_key(secret: str) -> str:
    if not secret:
        return ""
    if len(secret) <= 8:
        return "*" * len(secret)
    return f"{secret[:3]}...{secret[-4:]}"
