"""Tests for the first-admin startup bootstrap."""

from __future__ import annotations

from datetime import datetime, timezone

import mongomock

from backend.app.bootstrap import bootstrap_admin
from backend.app.security import hash_password, verify_password


def test_bootstrap_creates_admin_with_normal_password_hash_when_users_empty():
    database = mongomock.MongoClient(tz_aware=True).tracex

    created = bootstrap_admin(database, email="  FIRST.ADMIN@example.test ", password="Strong-bootstrap-password")

    user = database.users.find_one({"email": "first.admin@example.test"})
    assert created is True
    assert database.users.count_documents({}) == 1
    assert user["role"] == "admin"
    assert user["permissions"] == ["case:read", "remediation:apply", "case:contain", "dataset:manage"]
    assert user["created_at"].tzinfo is not None
    assert user["password_hash"] != "Strong-bootstrap-password"
    assert verify_password("Strong-bootstrap-password", user["password_hash"])


def test_bootstrap_does_not_duplicate_or_change_existing_user_password():
    database = mongomock.MongoClient(tz_aware=True).tracex
    original_hash = hash_password("Original-user-password")
    database.users.insert_one({
        "_id": "existing-user",
        "email": "admin@example.test",
        "display_name": "Existing account",
        "password_hash": original_hash,
        "role": "analyst",
        "permissions": ["case:read"],
        "created_at": datetime.now(timezone.utc),
    })

    created = bootstrap_admin(database, email="admin@example.test", password="New-bootstrap-password")

    user = database.users.find_one({"_id": "existing-user"})
    assert created is False
    assert database.users.count_documents({}) == 1
    assert user["password_hash"] == original_hash
    assert verify_password("Original-user-password", user["password_hash"])
    assert not verify_password("New-bootstrap-password", user["password_hash"])


def test_bootstrap_does_nothing_when_any_user_exists():
    database = mongomock.MongoClient(tz_aware=True).tracex
    database.users.insert_one({"_id": "investigator", "email": "investigator@example.test"})

    assert bootstrap_admin(database, email="admin@example.test", password="Strong-bootstrap-password") is False
    assert database.users.count_documents({}) == 1


def test_bootstrap_does_nothing_when_either_setting_is_missing():
    database = mongomock.MongoClient(tz_aware=True).tracex

    assert bootstrap_admin(database, email="admin@example.test", password=None) is False
    assert bootstrap_admin(database, email=None, password="Strong-bootstrap-password") is False
    assert database.users.count_documents({}) == 0
