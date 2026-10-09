"""Password hashing and signed session tokens."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from uuid import uuid4

from jose import JWTError, jwt
from passlib.context import CryptContext

from .config import JWT_TTL_MINUTES, jwt_secret

ALGORITHM = "HS256"
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def hash_password(password: str) -> str:
    return password_context.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return password_context.verify(password, password_hash)
    except (ValueError, TypeError):
        return False


def issue_session(database, user_id: str) -> tuple[str, datetime]:
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=JWT_TTL_MINUTES)
    session_id = uuid4().hex
    token = jwt.encode(
        {"sub": user_id, "jti": session_id, "iat": now, "exp": expires_at},
        jwt_secret(),
        algorithm=ALGORITHM,
    )
    database.sessions.insert_one({"_id": session_id, "user_id": user_id, "created_at": now, "expires_at": expires_at, "revoked_at": None})
    return token, expires_at


def decode_token(token: str, *, verify_exp: bool = True) -> dict:
    return jwt.decode(token, jwt_secret(), algorithms=[ALGORITHM], options={"verify_exp": verify_exp})


__all__ = ["JWTError", "decode_token", "hash_password", "issue_session", "verify_password"]
