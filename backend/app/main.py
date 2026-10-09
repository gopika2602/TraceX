"""FastAPI application entry point for the TraceX API."""

from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi import Depends, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pymongo.errors import PyMongoError

from .config import CORS_ORIGINS
from .db import close_client, get_database
from .routers import auth_routes, cases, datasets


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    close_client()


app = FastAPI(
    title="TraceX API",
    description="AI-Powered Attack Path and Root-Cause Investigator",
    version="1.0.0",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type"],
)
app.include_router(auth_routes.router)
app.include_router(datasets.router)
app.include_router(cases.router)


@app.get("/health", tags=["health"])
def health():
    return {"status": "ok", "service": "TraceX API"}


@app.get("/health/ready", tags=["health"])
def readiness(database=Depends(get_database)):
    try:
        database.command("ping")
    except PyMongoError as exc:
        raise HTTPException(status_code=503, detail="MongoDB readiness check failed.") from exc
    return {"status": "ready", "service": "TraceX API", "database": "connected", "engine": "loaded"}
