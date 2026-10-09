"""Request and response schemas aligned with the existing frontend contract."""

from __future__ import annotations

import re
from datetime import datetime

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


class IntakeEvidence(BaseModel):
    evidence_type: str = Field(min_length=1, max_length=100)
    timestamp: datetime
    source: str | None = Field(default=None, max_length=500)
    source_ip: str | None = Field(default=None, max_length=100)
    destination_ip: str | None = Field(default=None, max_length=100)
    device_id: str | None = Field(default=None, max_length=200)
    identity: str | None = Field(default=None, max_length=320)
    session_id: str | None = Field(default=None, max_length=200)
    token_id: str | None = Field(default=None, max_length=200)
    user_agent: str | None = Field(default=None, max_length=1000)
    process: str | None = Field(default=None, max_length=500)
    authentication: str | None = Field(default=None, max_length=500)
    network_connection: str | None = Field(default=None, max_length=500)
    api_service: str | None = Field(default=None, max_length=300)
    description: str | None = Field(default=None, max_length=4000)
    investigator_notes: str | None = Field(default=None, max_length=4000)


class CaseIntake(BaseModel):
    case_id: str | None = Field(default=None, max_length=100)
    case_name: str = Field(min_length=1, max_length=200)
    organization: str | None = Field(default=None, max_length=200)
    incident_at: datetime | None = None
    description: str | None = Field(default=None, max_length=4000)
    investigator_name: str | None = Field(default=None, max_length=200)
    investigator_notes: str | None = Field(default=None, max_length=8000)
    evidence: list[IntakeEvidence] = Field(min_length=1, max_length=10000)

    @field_validator("case_id")
    @classmethod
    def normalize_case_id(cls, value: str | None) -> str | None:
        return value.strip() if value and value.strip() else None

    @field_validator("case_name")
    @classmethod
    def normalize_case_name(cls, value: str) -> str:
        return value.strip()


class InvestigatorNotes(BaseModel):
    notes: str = Field(max_length=8000)


class SessionUser(BaseModel):
    id: str
    email: str
    display_name: str | None = None
    role: str
    permissions: list[str] = Field(default_factory=list)


class AuthSession(BaseModel):
    user: SessionUser
    expires_at: str
