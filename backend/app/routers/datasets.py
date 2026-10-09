"""Dataset upload and deterministic demo loading routes."""

from __future__ import annotations

import json
from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from ..auth import get_current_user
from ..data import MAX_DATASET_BYTES, persist_dataset, read_events, validate_environment, validate_events
from ..db import get_database

router = APIRouter(tags=["datasets"])
REPOSITORY_ROOT = Path(__file__).resolve().parents[3]


async def _read_json_upload(upload: UploadFile, label: str):
    raw = await upload.read(MAX_DATASET_BYTES + 1)
    if len(raw) > MAX_DATASET_BYTES:
        raise HTTPException(status_code=413, detail=f"{label} file must be 10 MB or smaller.")
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise HTTPException(status_code=422, detail=f"{label} file must contain valid UTF-8 JSON.") from exc


@router.post("/datasets", status_code=201)
async def upload_dataset(
    events_file: UploadFile = File(..., description="JSON list of normalized security events"),
    environment_file: UploadFile = File(..., description="JSON environment graph with nodes and edges"),
    current_user: dict = Depends(get_current_user),
    database=Depends(get_database),
):
    events = validate_events(await _read_json_upload(events_file, "Events"))
    environment = validate_environment(await _read_json_upload(environment_file, "Environment"))
    return persist_dataset(database, events, environment, name=events_file.filename or "uploaded-dataset", owner_id=current_user["id"])


@router.post("/datasets/load-demo", status_code=201)
def load_demo(current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    events_path = REPOSITORY_ROOT / "scenarios" / "events.json"
    environment_path = REPOSITORY_ROOT / "scenarios" / "environment.json"
    if not events_path.is_file() or not environment_path.is_file():
        raise HTTPException(status_code=503, detail="Nimbus demo data is missing. Run scenarios/generate_nimbus.py first.")
    try:
        events = validate_events(json.loads(events_path.read_text(encoding="utf-8")))
        environment = validate_environment(json.loads(environment_path.read_text(encoding="utf-8")))
    except json.JSONDecodeError as exc:
        raise HTTPException(status_code=500, detail="Nimbus demo JSON is invalid.") from exc
    return persist_dataset(database, events, environment, name="Nimbus deterministic demo", owner_id=current_user["id"], dataset_id="demo-nimbus", synthetic=True)


@router.get("/datasets/{dataset_id}/events")
def dataset_events(dataset_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    if not database.datasets.find_one({"_id": dataset_id}):
        raise HTTPException(status_code=404, detail="Dataset not found.")
    return read_events(database, dataset_id)


@router.get("/environments/{dataset_id}")
def dataset_environment(dataset_id: str, current_user: dict = Depends(get_current_user), database=Depends(get_database)):
    environment = database.environments.find_one({"dataset_id": dataset_id, "version": 1})
    if not environment:
        raise HTTPException(status_code=404, detail="Environment not found.")
    return {"dataset_id": dataset_id, "version": 1, **environment["data"]}
