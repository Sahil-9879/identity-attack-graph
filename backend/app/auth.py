"""User account authentication.

Two modes coexist:
  * User accounts (DB-backed)  — the normal path. Every user has their own
    email / username / password. Sessions carry the user id.
  * IAG_PASSWORD env var       — optional shared-password fallback for
    emergency access. Only active if explicitly set.

If neither users exist nor IAG_PASSWORD is set, the app runs open (dev mode).
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
from typing import Optional

from fastapi import HTTPException, Request, status

from . import store


# ---------------------------------------------------------------- config

def shared_password_enabled() -> bool:
    return bool(os.environ.get("IAG_PASSWORD", "").strip())


def is_enabled() -> bool:
    """Auth is enforced when users exist OR a shared password is set."""
    if shared_password_enabled():
        return True
    try:
        return store.count_users() > 0
    except Exception:
        return False


def get_secret_key() -> str:
    key = os.environ.get("IAG_SECRET_KEY", "").strip()
    if key:
        return key
    return secrets.token_urlsafe(48)


# ---------------------------------------------------------------- hashing

_PBKDF2_ROUNDS = 100_000


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                            salt, _PBKDF2_ROUNDS)
    return base64.b64encode(salt + h).decode("ascii")


def verify_password(password: str, stored: str) -> bool:
    try:
        raw = base64.b64decode(stored.encode("ascii"))
        if len(raw) < 17:
            return False
        salt, expected = raw[:16], raw[16:]
        h = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"),
                                salt, _PBKDF2_ROUNDS)
        return hmac.compare_digest(h, expected)
    except Exception:
        return False


# ---------------------------------------------------------------- register / login

class AuthError(Exception):
    def __init__(self, message: str, code: str = "auth_error"):
        super().__init__(message)
        self.message = message
        self.code = code


def register_user(email: str, username: str, password: str) -> dict:
    email = (email or "").strip().lower()
    username = (username or "").strip()
    if not email or "@" not in email:
        raise AuthError("A valid email is required.", "invalid_email")
    if not username or len(username) < 3:
        raise AuthError("Username must be at least 3 characters.", "invalid_username")
    if len(password or "") < 8:
        raise AuthError("Password must be at least 8 characters.", "weak_password")

    if store.get_user_by_email(email):
        raise AuthError("That email is already registered.", "email_taken")
    if store.get_user_by_username(username):
        raise AuthError("That username is already taken.", "username_taken")

    user_id = store.create_user(email, username, hash_password(password))
    user = store.get_user_by_id(user_id)
    return user


def authenticate(identifier: str, password: str) -> Optional[dict]:
    """Look up a user by email OR username and verify the password."""
    identifier = (identifier or "").strip()
    if not identifier or not password:
        return None

    user = store.get_user_by_email(identifier) or \
           store.get_user_by_username(identifier)
    if not user:
        return None
    if not verify_password(password, user["password_hash"]):
        return None

    store.update_last_login(user["id"])
    return user


def authenticate_shared(password: str) -> Optional[dict]:
    """Legacy: check the shared IAG_PASSWORD env var."""
    if not shared_password_enabled():
        return None
    expected = os.environ["IAG_PASSWORD"]
    if secrets.compare_digest(password or "", expected):
        return {"id": None, "username": os.environ.get("IAG_USER", "admin"),
                "email": None, "shared": True}
    return None


# ---------------------------------------------------------------- session helpers

def login_session(request: Request, user: dict) -> None:
    """Write the user's identity into the signed session cookie."""
    request.session["user_id"] = user.get("id")
    request.session["username"] = user.get("username")
    request.session["email"] = user.get("email")


def logout_session(request: Request) -> None:
    request.session.clear()


def current_user(request: Request) -> Optional[dict]:
    if not is_enabled():
        return {"id": None, "username": "anonymous", "email": None,
                "shared": False, "anonymous": True}
    uid = request.session.get("user_id")
    if uid is None and request.session.get("username"):
        # Shared-password login (no user id)
        return {"id": None, "username": request.session["username"],
                "email": None, "shared": True}
    if uid is None:
        return None
    user = store.get_user_by_id(uid)
    return user


def current_user_id(request: Request) -> Optional[int]:
    user = current_user(request)
    return user["id"] if user else None


def require_user(request: Request) -> dict:
    """FastAPI dependency — 401 if not logged in. No-op when auth disabled."""
    if not is_enabled():
        return {"id": None, "username": "anonymous", "shared": False,
                "anonymous": True}
    user = current_user(request)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return user
