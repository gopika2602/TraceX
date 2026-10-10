"""One-time, environment-configured first-admin bootstrap."""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import uuid4

from pymongo.errors import DuplicateKeyError

from .security import hash_password


def bootstrap_admin(database, *, email: str | None, password: str | None) -> bool:
    """Create the initial admin only when both credentials exist and users is empty.

    Returns True only when this call inserted the account. Credentials are never
    logged or included in exceptions raised by this helper.
    """
    normalized_email = (email or "").strip().lower()
    if not normalized_email or not password or not password.strip():
        return False
    if database.users.find_one({}, {"_id": 1}) is not None:
        return False

    user = {
        "_id": uuid4().hex,
        "email": normalized_email,
        "display_name": normalized_email.partition("@")[0],
        "password_hash": hash_password(password),
        "role": "admin",
        "permissions": ["case:read", "remediation:apply", "case:contain", "dataset:manage"],
        "created_at": datetime.now(timezone.utc),
    }
    try:
        database.users.insert_one(user)
    except DuplicateKeyError:
        # Another startup may have inserted this account after the empty check.
        return False
    return True
