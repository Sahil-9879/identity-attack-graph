"""Simple session-based auth gate.

Credentials come from environment variables:
    IAG_USER       (default: "admin")
    IAG_PASSWORD   (required to enable auth)
    IAG_SECRET_KEY (used to sign cookies; random per-process if unset)

If IAG_PASSWORD is unset, auth is DISABLED — all endpoints are open.
This keeps local development friction-free while giving production a
one-variable switch.
"""
from __future__ import annotations

import os
import secrets

from fastapi import HTTPException, Request, status


def is_enabled() -> bool:
    return bool(os.environ.get("IAG_PASSWORD", "").strip())


def get_user() -> str:
    return os.environ.get("IAG_USER", "admin").strip() or "admin"


def get_password() -> str:
    return os.environ.get("IAG_PASSWORD", "")


def get_secret_key() -> str:
    key = os.environ.get("IAG_SECRET_KEY", "").strip()
    if key:
        return key
    # No secret set: generate one for this process.  Sessions won't survive
    # a restart, but the app keeps working.
    return secrets.token_urlsafe(48)


def check_credentials(username: str, password: str) -> bool:
    """Constant-time compare of submitted credentials."""
    if not is_enabled():
        return True
    u_ok = secrets.compare_digest(username or "", get_user())
    p_ok = secrets.compare_digest(password or "", get_password())
    return u_ok and p_ok


def require_user(request: Request):
    """FastAPI dependency — raises 401 if the caller isn't logged in.

    When auth is disabled (no IAG_PASSWORD), this is a no-op so the app
    remains fully usable out of the box.
    """
    if not is_enabled():
        return "anonymous"
    user = request.session.get("user")
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
        )
    return user


def current_user(request: Request) -> str | None:
    """Return the logged-in user, or None."""
    if not is_enabled():
        return "anonymous"
    return request.session.get("user")
