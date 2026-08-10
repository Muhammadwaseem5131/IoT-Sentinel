from datetime import datetime

from db import models
from security import secrets_store

ALLOWED_PROVIDERS = {"claude", "openai", "gemini", "groq", "ollama"}


def get_ai_provider() -> dict:
    """Returns the active provider plus a masked version of its key."""
    with models.db_cursor() as cur:
        cur.execute("SELECT value_encrypted FROM settings WHERE key = 'ai_provider'")
        row = cur.fetchone()
        provider = row["value_encrypted"].decode("utf-8") if row and row["value_encrypted"] else ""

    if not provider:
        return {"provider": None, "key_masked": ""}

    with models.db_cursor() as cur:
        cur.execute("SELECT value_encrypted FROM settings WHERE key = ?", (f"key_{provider}",))
        key_row = cur.fetchone()
    masked = ""
    if key_row and key_row["value_encrypted"]:
        decrypted = secrets_store.decrypt_secret(bytes(key_row["value_encrypted"]))
        masked = secrets_store.mask_key(decrypted)
    return {"provider": provider, "key_masked": masked}


def set_ai_provider(provider: str, api_key: str = None):
    if provider not in ALLOWED_PROVIDERS:
        raise ValueError(f"Unsupported provider: {provider}")
    now = datetime.utcnow().isoformat(timespec="seconds")
    with models.db_cursor() as cur:
        cur.execute(
            "INSERT INTO settings (key, value_encrypted, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_encrypted = excluded.value_encrypted, "
            "updated_at = excluded.updated_at",
            ("ai_provider", provider.encode("utf-8"), now),
        )
        if api_key:
            encrypted = secrets_store.encrypt_secret(api_key)
            cur.execute(
                "INSERT INTO settings (key, value_encrypted, updated_at) VALUES (?, ?, ?) "
                "ON CONFLICT(key) DO UPDATE SET value_encrypted = excluded.value_encrypted, "
                "updated_at = excluded.updated_at",
                (f"key_{provider}", encrypted, now),
            )


def get_provider_key(provider: str) -> str:
    with models.db_cursor() as cur:
        cur.execute("SELECT value_encrypted FROM settings WHERE key = ?", (f"key_{provider}",))
        row = cur.fetchone()
    if not row or not row["value_encrypted"]:
        return ""
    return secrets_store.decrypt_secret(bytes(row["value_encrypted"]))


def delete_provider(provider: str):
    now = datetime.utcnow().isoformat(timespec="seconds")
    with models.db_cursor() as cur:
        cur.execute("DELETE FROM settings WHERE key = ?", (f"key_{provider}",))
        cur.execute(
            "INSERT INTO settings (key, value_encrypted, updated_at) VALUES (?, ?, ?) "
            "ON CONFLICT(key) DO UPDATE SET value_encrypted = excluded.value_encrypted, "
            "updated_at = excluded.updated_at",
            ("ai_provider", b"", now),
        )
