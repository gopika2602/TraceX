"""Login, registration and HttpOnly cookie session routes."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pymongo.errors import DuplicateKeyError

from ..auth import get_current_user
from ..config import BOOTSTRAP_ADMIN_EMAILS, JWT_TTL_MINUTES, SESSION_COOKIE_NAME, SESSION_COOKIE_SAMESITE, SESSION_COOKIE_SECURE
from ..db import get_database
from ..models import AuthSession, Credentials, Registration
from ..security import JWTError, decode_token, hash_password, issue_session, verify_password

router = APIRouter(prefix="/auth", tags=["authentication"])


def _permissions(role: str) -> list[str]:
    if role == "admin":
        return ["case:read", "remediation:apply", "case:contain", "dataset:manage"]
    return ["case:read"]


def _public_session(user: dict, expires_at: datetime) -> dict:
    return {
        "user": {
            "id": user["_id"],
            "email": user["email"],
            "display_name": user.get("display_name"),
            "role": user.get("role", "analyst"),
            "permissions": user.get("permissions", []),
        },
        "expires_at": expires_at.astimezone(timezone.utc).isoformat().replace("+00:00", "Z"),
    }


def _set_session_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=token,
        httponly=True,
        secure=SESSION_COOKIE_SECURE,
        samesite=SESSION_COOKIE_SAMESITE,
        max_age=JWT_TTL_MINUTES * 60,
        path="/",
    )


def _start_session(database, user: dict, response: Response) -> dict:
    token, expires_at = issue_session(database, user["_id"])
    _set_session_cookie(response, token)
    return _public_session(user, expires_at)


@router.post("/register", response_model=AuthSession, status_code=status.HTTP_201_CREATED)
def register(payload: Registration, response: Response, database=Depends(get_database)):
    now = datetime.now(timezone.utc)
    role = "admin" if payload.email in BOOTSTRAP_ADMIN_EMAILS else "analyst"
    user = {
        "_id": uuid4().hex,
        "email": payload.email,
        "display_name": payload.display_name,
        "password_hash": hash_password(payload.password),
        "role": role,
        "permissions": _permissions(role),
        "created_at": now,
    }
    try:
        database.users.insert_one(user)
    except DuplicateKeyError as exc:
        raise HTTPException(status_code=409, detail="An account with this email already exists.") from exc
    return _start_session(database, user, response)


@router.post("/login", response_model=AuthSession)
def login(payload: Credentials, response: Response, database=Depends(get_database)):
    user = database.users.find_one({"email": payload.email})
    if not user or not verify_password(payload.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail={"code": "INVALID_CREDENTIALS"})
    return _start_session(database, user, response)


@router.get("/session", response_model=AuthSession)
def session(current_user: dict = Depends(get_current_user)):
    return _public_session(
        {key: current_user.get(key) for key in ("id", "email", "display_name", "role", "permissions")} | {"_id": current_user["id"]},
        current_user["_expires_at"],
    )


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(request: Request, response: Response, database=Depends(get_database)):
    token = request.cookies.get(SESSION_COOKIE_NAME)
    if token:
        try:
            claims = decode_token(token, verify_exp=False)
            session_id = claims.get("jti")
            if session_id:
                database.sessions.update_one({"_id": session_id, "revoked_at": None}, {"$set": {"revoked_at": datetime.now(timezone.utc)}})
        except JWTError:
            pass
    response.delete_cookie(SESSION_COOKIE_NAME, path="/", secure=SESSION_COOKIE_SECURE, httponly=True, samesite=SESSION_COOKIE_SAMESITE)
    response.status_code = status.HTTP_204_NO_CONTENT
    return response
