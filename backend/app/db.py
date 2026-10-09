"""MongoDB connection and index management."""

from __future__ import annotations

from functools import lru_cache
from threading import Lock

from fastapi import HTTPException
from pymongo import ASCENDING, MongoClient
from pymongo.errors import PyMongoError

from .config import MONGODB_DATABASE, MONGODB_URI

_indexed_databases: set[str] = set()
_index_lock = Lock()


@lru_cache(maxsize=1)
def get_client() -> MongoClient:
    return MongoClient(MONGODB_URI, serverSelectionTimeoutMS=4000, connectTimeoutMS=4000, tz_aware=True, appname="TraceX")


def get_database():
    try:
        database = get_client()[MONGODB_DATABASE]
        if MONGODB_DATABASE not in _indexed_databases:
            with _index_lock:
                if MONGODB_DATABASE not in _indexed_databases:
                    ensure_indexes(database)
                    _indexed_databases.add(MONGODB_DATABASE)
        return database
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="MongoDB is unavailable.") from exc


def ensure_indexes(database) -> None:
    database.users.create_index([("email", ASCENDING)], unique=True)
    database.sessions.create_index([("expires_at", ASCENDING)], expireAfterSeconds=0)
    database.datasets.create_index([("created_at", ASCENDING)])
    database.events.create_index([("dataset_id", ASCENDING), ("event_index", ASCENDING)])
    database.environments.create_index([("dataset_id", ASCENDING), ("version", ASCENDING)], unique=True)
    database.cases.create_index([("created_at", ASCENDING)])
    database.analyses.create_index([("case_id", ASCENDING)], unique=True)
    database.evidence.create_index([("case_id", ASCENDING), ("record.timestamp", ASCENDING)])


def close_client() -> None:
    client = get_client()
    client.close()
    get_client.cache_clear()
    _indexed_databases.clear()
