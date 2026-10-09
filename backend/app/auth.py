"""Authentication dependencies shared by protected API routes."""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import ExpiredSignatureError, JWTError

from .config import SESSION_COOKIE_NAME
from .db import get_database
from .security import decode_token

_bearer = HTTPBearer(auto_error=False)


def _unauthorized(code: str) -> HTTPException:
    return HTTPException(status_code=401, detail={"code": code})


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(_bearer),
    database=Depends(get_database),
) -> dict:
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if not token and credentials is not None:
        token = credentials.credentials
    if not token:
        raise _unauthorized("NO_SESSION")
    try:
        claims = decode_token(token)
    except ExpiredSignatureError as exc:
        raise _unauthorized("SESSION_EXPIRED") from exc
    except JWTError as exc:
        raise _unauthorized("NO_SESSION") from exc

    session_id = claims.get("jti")
    user_id = claims.get("sub")
    if not session_id or not user_id:
        raise _unauthorized("NO_SESSION")
    session = database.sessions.find_one({"_id": session_id, "user_id": user_id, "revoked_at": None})
    if not session:
        raise _unauthorized("NO_SESSION")
    user = database.users.find_one({"_id": user_id})
    if not user:
        raise _unauthorized("NO_SESSION")

    expires_at = session.get("expires_at")
    if expires_at and expires_at <= datetime.now(timezone.utc):
        raise _unauthorized("SESSION_EXPIRED")
    return {
        "id": user["_id"],
        "email": user["email"],
        "display_name": user.get("display_name"),
        "role": user.get("role", "analyst"),
        "permissions": user.get("permissions", []),
        "_session_id": session_id,
        "_expires_at": expires_at,
    }


def require_admin(user: dict = Depends(get_current_user)) -> dict:
    if user.get("role") != "admin":
        raise HTTPException(status_code=403, detail={"code": "FORBIDDEN", "message": "An admin role is required."})
    return user
