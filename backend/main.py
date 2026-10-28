"""FastAPI REST and WebSocket interface for deterministic incident investigations."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from . import db
from .ai_investigator import VerifiableAIInvestigator
from .config import get_settings
from .fix_protocol import parse_fix_message
from .models import (
    Direction,
    IncidentFixture,
    OMSRecord,
    TelemetryEvent,
    WireEvent,
)
from .multimodal_intake import analyze_blotter_screenshot, transcribe_voice_squawk
from .reconstructor import FixReconstructor
from .simulator import all_incidents
from .tcp_harness import LocalFIXExchangeHarness

settings = get_settings()
app = FastAPI(title="TradeOps Sentinel API", version="0.2.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "OPTIONS"],
    allow_headers=["*"],
)


class RawFIXIngestRequest(BaseModel):
    raw_fix_lines: list[str] = Field(min_length=1)
    incident_id: str | None = None
    direction: Direction = Direction.INBOUND
    directions: list[Direction] | None = None
    oms_snapshot: list[dict[str, Any]] = Field(default_factory=list)
    source_layer: str = "CUSTOM_FIX_LOG"


class WebSocketHub:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()

    async def connect(self, websocket: WebSocket) -> None:
        await websocket.accept()
        self._clients.add(websocket)

    def disconnect(self, websocket: WebSocket) -> None:
        self._clients.discard(websocket)

    async def broadcast(self, payload: dict[str, Any]) -> None:
        encoded = json.loads(json.dumps(payload, default=_json_value))
        stale: list[WebSocket] = []
        for client in tuple(self._clients):
            try:
                await client.send_json(encoded)
            except (RuntimeError, WebSocketDisconnect):
                stale.append(client)
        for client in stale:
            self.disconnect(client)


hub = WebSocketHub()


def _json_value(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json")
    raise TypeError(f"Not JSON serializable: {type(value).__name__}")


def _db_path() -> str:
    # Resolve on each request so pytest/env overrides take effect after import.
    return get_settings().sqlite_db_path


def _report_summary(report: Any) -> dict[str, Any]:
    return {
        "incident_id": report.incident_id,
        "title": report.title,
        "primary_failure_category": report.primary_failure_category,
        "severity": report.severity,
        "total_exposure_dollars": str(report.total_exposure_dollars),
        "safe_to_resend": report.safe_to_resend,
        "subway_map_status": [node.model_dump(mode="json") for node in report.subway_map_status],
    }


@app.get("/api/health")
async def health() -> dict[str, Any]:
    path = _db_path()
    db.init_db(path)
    return {"status": "ok", "db_path": path, "engine_version": "0.2.0"}


@app.post("/api/incidents/seed")
async def seed_incidents() -> dict[str, Any]:
    reports = db.seed_all_incidents(_db_path())
    return {"seeded": len(reports), "incidents": [_report_summary(report) for report in reports]}


@app.get("/api/incidents")
async def incidents() -> list[dict[str, Any]]:
    return db.list_incidents(_db_path())


@app.get("/api/incidents/{incident_id}")
async def incident_detail(incident_id: str) -> dict[str, Any]:
    path = _db_path()
    report = db.get_deterministic_report(path, incident_id)
    if report is None:
        raise HTTPException(status_code=404, detail=f"Incident {incident_id!r} not found")
    return {
        "report": report.model_dump(mode="json"),
        "telemetry_events": db.get_incident_events(path, incident_id),
        "oms_orders": db.get_oms_orders(path, incident_id),
        "sql_recon_breaks": [item.model_dump(mode="json") for item in db.run_sql_reconciliation(path, incident_id)],
        "ai_diagnosis": (db.get_ai_diagnosis(path, incident_id).model_dump(mode="json")
                 if db.get_ai_diagnosis(path, incident_id) else None),
    }


@app.post("/api/incidents/{incident_id}/simulate-tcp")
async def simulate_tcp(incident_id: str) -> dict[str, Any]:
    try:
        harness = LocalFIXExchangeHarness(_db_path())
        result = await harness.run(incident_id)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except (ValueError, RuntimeError, OSError, TimeoutError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    for event in result.captured_events:
        await hub.broadcast({"type": "telemetry_event", "incident_id": incident_id, "event": event.model_dump(mode="json")})
    await hub.broadcast({"type": "investigation_update", "incident_id": incident_id, "report": result.report.model_dump(mode="json")})
    return {
        "report": result.report.model_dump(mode="json"),
        "socket_metadata": result.socket_metadata,
        "transmitted_frames": result.transmitted_frames,
        "received_frames": result.received_frames,
        "captured_events": len(result.captured_events),
    }


@app.post("/api/ingest/raw-fix")
async def ingest_raw_fix(request: RawFIXIngestRequest) -> dict[str, Any]:
    if request.directions is not None and len(request.directions) != len(request.raw_fix_lines):
        raise HTTPException(status_code=422, detail="directions must have the same number of entries as raw_fix_lines")
    incident_id = request.incident_id or f"CUSTOM-{uuid.uuid4().hex[:12].upper()}"
    now = datetime.now(timezone.utc)
    wires: list[WireEvent] = []
    parsed_messages = []
    try:
        for index, raw in enumerate(request.raw_fix_lines):
            parsed = parse_fix_message(raw)
            parsed_messages.append(parsed)
            direction = request.directions[index] if request.directions is not None else request.direction
            wires.append(WireEvent(
                event_id=f"{incident_id.lower()}-fix-{index + 1}",
                timestamp=now,
                source_layer=request.source_layer,
                provenance=f"User-supplied raw FIX log line {index + 1}; not independently verified against an exchange.",
                direction=direction,
                wire=raw,
                sender_comp_id=parsed.sender_comp_id or "CUSTOM_SENDER",
                target_comp_id=parsed.target_comp_id or "CUSTOM_TARGET",
            ))
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail=f"Invalid FIX input: {exc}") from exc

    oms_records: list[OMSRecord] = []
    for index, item in enumerate(request.oms_snapshot):
        try:
            oms_records.append(OMSRecord(
                order_id=str(item["cl_ord_id"]),
                status=str(item.get("oms_status", "unknown")),
                filled_qty=Decimal(str(item.get("filled_qty", "0"))),
                event_id=str(item.get("event_id", f"{incident_id.lower()}-oms-{index + 1}")),
                timestamp=datetime.fromisoformat(str(item.get("updated_at", now.isoformat()))),
                source_layer=str(item.get("source_layer", "OMS_SQL")),
                provenance="User-supplied OMS snapshot; provenance is caller-provided.",
            ))
        except (KeyError, ValueError, ArithmeticError) as exc:
            raise HTTPException(status_code=422, detail=f"Invalid OMS snapshot at index {index}: {exc}") from exc

    reconstructor = FixReconstructor()
    results = tuple(
        reconstructor.process(parsed, direction=wire.direction, event_id=wire.event_id)
        for parsed, wire in zip(parsed_messages, wires)
    )
    fixture = IncidentFixture(
        incident_id=incident_id,
        title="CUSTOM_FIX_INGEST",
        description="Deterministic reconstruction of caller-provided FIX lines; external exchange state may remain unknown.",
        events=tuple(wires),
        oms_records=tuple(oms_records),
    )
    report = db.persist_custom_incident(_db_path(), fixture, reconstructor, results)
    await hub.broadcast({"type": "investigation_update", "incident_id": incident_id, "report": report.model_dump(mode="json")})
    return {"report": report.model_dump(mode="json")}


@app.post("/api/incidents/{incident_id}/investigate")
async def investigate_incident(incident_id: str) -> dict[str, Any]:
    investigator = VerifiableAIInvestigator(_db_path())
    try:
        diagnosis = await investigator.investigate(incident_id)
        db.persist_ai_diagnosis(_db_path(), incident_id, diagnosis)
    except KeyError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    await hub.broadcast({
        "type": "ai_diagnosis",
        "incident_id": incident_id,
        "diagnosis": diagnosis.model_dump(mode="json"),
    })
    return diagnosis.model_dump(mode="json")


async def _intake_payload(request: Request, *, modality: str) -> bytes | str:
    content_type = request.headers.get("content-type", "")
    if "multipart/form-data" in content_type or "application/x-www-form-urlencoded" in content_type:
        form = await request.form()
        text_key = "transcript" if modality == "VOICE_SQUAWK" else "caption"
        if form.get(text_key):
            return str(form[text_key])
        upload_key = "audio" if modality == "VOICE_SQUAWK" else "image"
        upload = form.get(upload_key)
        if upload is not None and hasattr(upload, "read"):
            return await upload.read()
        raise HTTPException(status_code=422, detail=f"Provide a {text_key} or {upload_key} upload")
    try:
        payload = await request.json()
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=422, detail="Provide JSON transcript/caption or multipart file upload") from exc
    if not isinstance(payload, dict):
        raise HTTPException(status_code=422, detail="Intake request must be a JSON object")
    key = "transcript" if modality == "VOICE_SQUAWK" else "caption"
    if not isinstance(payload.get(key), str):
        raise HTTPException(status_code=422, detail=f"JSON {key} must be a string")
    return payload[key]


@app.post("/api/intake/voice-squawk")
async def intake_voice_squawk(request: Request) -> dict[str, Any]:
    payload = await _intake_payload(request, modality="VOICE_SQUAWK")
    result = transcribe_voice_squawk(payload, _db_path())
    matched_report = db.get_deterministic_report(_db_path(), result.matched_incident_id) if result.matched_incident_id else None
    return {
        "intake": result.model_dump(mode="json"),
        "matched_report": matched_report.model_dump(mode="json") if matched_report else None,
    }


@app.post("/api/intake/blotter-screenshot")
async def intake_blotter_screenshot(request: Request) -> dict[str, Any]:
    payload = await _intake_payload(request, modality="BLOTTER_SCREENSHOT")
    result = analyze_blotter_screenshot(payload, _db_path())
    matched_report = db.get_deterministic_report(_db_path(), result.matched_incident_id) if result.matched_incident_id else None
    return {
        "intake": result.model_dump(mode="json"),
        "matched_report": matched_report.model_dump(mode="json") if matched_report else None,
    }


@app.websocket("/ws/stream")
async def stream(websocket: WebSocket) -> None:
    await hub.connect(websocket)
    try:
        while True:
            # Keep connection alive and allow clients to send harmless ping/control JSON.
            await websocket.receive_text()
    except WebSocketDisconnect:
        hub.disconnect(websocket)
