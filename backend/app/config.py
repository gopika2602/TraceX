"""Environment-backed settings for the TraceX API."""

from __future__ import annotations

import os
import secrets


def _csv(name: str, default: str) -> list[str]:
    return [item.strip() for item in os.getenv(name, default).split(",") if item.strip()]


APP_ENV = os.getenv("APP_ENV", "development").strip().lower()
MONGODB_URI = os.getenv("MONGODB_URI", "mongodb://127.0.0.1:27017")
MONGODB_DATABASE = os.getenv("MONGODB_DATABASE", "tracex")
JWT_TTL_MINUTES = max(5, int(os.getenv("JWT_TTL_MINUTES", "240")))
SESSION_COOKIE_NAME = os.getenv("SESSION_COOKIE_NAME", "tracex_session")
SESSION_COOKIE_SAMESITE = os.getenv("SESSION_COOKIE_SAMESITE", "lax").lower()
SESSION_COOKIE_SECURE = os.getenv("SESSION_COOKIE_SECURE", "").lower() in {"1", "true", "yes"} or APP_ENV in {"prod", "production"}
CORS_ORIGINS = _csv("CORS_ORIGINS", "http://localhost:5173,http://127.0.0.1:5173")
BOOTSTRAP_ADMIN_EMAILS = {email.lower() for email in _csv("TRACEX_BOOTSTRAP_ADMIN_EMAILS", "")}

_ephemeral_development_secret = secrets.token_urlsafe(48)


def jwt_secret() -> str:
    secret = os.getenv("JWT_SECRET_KEY", "").strip()
    if secret:
        if len(secret) < 32:
            raise RuntimeError("JWT_SECRET_KEY must be at least 32 characters.")
        return secret
    if APP_ENV in {"prod", "production"}:
        raise RuntimeError("JWT_SECRET_KEY is required when APP_ENV is production.")
    return _ephemeral_development_secret
