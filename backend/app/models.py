"""Request and response schemas aligned with the existing frontend contract."""

from __future__ import annotations

import re

from pydantic import BaseModel, Field, field_validator


class Credentials(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=8, max_length=128)

    @field_validator("email")
    @classmethod
    def normalize_email(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", normalized):
            raise ValueError("Enter a valid email address.")
        return normalized


class Registration(Credentials):
    display_name: str = Field(min_length=1, max_length=100)

    @field_validator("display_name")
    @classmethod
    def normalize_display_name(cls, value: str) -> str:
        return value.strip()


class CaseCreate(BaseModel):
    dataset_id: str | None = Field(default=None, min_length=1, max_length=100)


class SessionUser(BaseModel):
    id: str
    email: str
    display_name: str | None = None
    role: str
    permissions: list[str] = Field(default_factory=list)


class AuthSession(BaseModel):
    user: SessionUser
    expires_at: str
