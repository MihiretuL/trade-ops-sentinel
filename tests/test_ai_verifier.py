from __future__ import annotations

import asyncio
import json
from decimal import Decimal

import httpx
import pytest
from fastapi.testclient import TestClient

from backend import db
from backend.ai_investigator import (
    AgentToolkit,
    VerifiableAIInvestigator,
    generate_artifacts,
    synthesize_from_deterministic_report,
    verify_and_sanitize_ai_diagnosis,
)
from backend.fix_protocol import build_fix_message
from backend.main import app
from backend.models import (
    EvidenceCitation,
    HypothesisRanking,
    ReadOnlyRemediationArtifact,
    VerifiedAIDiagnosis,
)
from backend.multimodal_intake import (
    analyze_blotter_screenshot,
    generate_muse_code_remediation,
    transcribe_voice_squawk,
)
from backend.simulator import all_incidents, get_incident


@pytest.fixture
def seeded_db(tmp_path, monkeypatch):
    path = str(tmp_path / "ai-verifier.sqlite3")
    monkeypatch.setenv("SQLITE_DB_PATH", path)
    db.seed_all_incidents(path)
    return path


@pytest.mark.parametrize("incident_id", [f"INC-{number}" for number in range(101, 106)])
def test_all_agent_tools_return_persisted_deterministic_evidence(seeded_db, incident_id):
    toolkit = AgentToolkit(seeded_db)
    results = toolkit.run_all(incident_id)
    assert list(results) == ["inspect_fix_session", "trace_order_chain", "check_network_telemetry", "reconcile_oms_sql"]
    known = {event["event_id"] for event in db.get_incident_events(seeded_db, incident_id)}
    for result in results.values():
        assert result["incident_id"] == incident_id
        assert set(result.get("event_ids", result.get("evidence_event_ids", []))) <= known
    if incident_id == "INC-101":
        findings = results["inspect_fix_session"]["findings"]
        assert any(item["msg_type"] == "2" and item["resend_begin_seq_no"] == "105" for item in findings)
        assert any(item["msg_type"] == "4" and item["gap_fill_flag"] == "Y" for item in findings)
    if incident_id == "INC-102":
        transitions = results["trace_order_chain"]["transitions"]
        assert any(item["msg_type"] == "9" and item["cancel_reject_reason"] == "TooLateToCancel" for item in transitions)
        assert results["trace_order_chain"]["decimal_exposure_dollars"] == "112750.00"
    if incident_id == "INC-103":
        assert any(item["event_type"] == "gateway_timeout" for item in results["check_network_telemetry"]["events"])
    if incident_id == "INC-104":
        assert any(item["msg_type"] == "3" and item["ref_tag_id"] == "44" for item in results["inspect_fix_session"]["findings"])
    if incident_id == "INC-105":
        assert results["reconcile_oms_sql"]["break_count"] == 1


def test_inspect_tools_are_deterministic(seeded_db):
    toolkit = AgentToolkit(seeded_db)
    assert toolkit.run_all("INC-105") == toolkit.run_all("INC-105")


def test_fallback_investigator_executes_all_tools_and_persists_schema(seeded_db, monkeypatch):
    monkeypatch.delenv("BASETEN_API_KEY", raising=False)
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    monkeypatch.delenv("META_API_KEY", raising=False)
    diagnosis = asyncio.run(VerifiableAIInvestigator(seeded_db).investigate("INC-105"))
    assert diagnosis.model_used == "deterministic-fallback-verifier"
    assert diagnosis.tool_calls_executed == [
        "inspect_fix_session", "trace_order_chain", "check_network_telemetry", "reconcile_oms_sql"
    ]
    assert diagnosis.verification_passed
    assert diagnosis.proven_claims
    actual_ids = {event["event_id"] for event in db.get_incident_events(seeded_db, "INC-105")}
    assert all(citation.event_id in actual_ids for citation in diagnosis.proven_claims)
    db.persist_ai_diagnosis(seeded_db, "INC-105", diagnosis)
    assert db.get_ai_diagnosis(seeded_db, "INC-105") == diagnosis


def _diagnosis_payload(report, event_id: str) -> dict:
    return {
        "incident_id": report.incident_id,
        "model_used": "mock-untrusted-model",
        "tool_calls_executed": ["inspect_fix_session"],
        "executive_summary": "Untrusted summary",
        "proven_claims": [{"event_id": event_id, "fix_tags": ["11"], "claim": "Untrusted claim"}],
        "ranked_hypotheses": [{
            "hypothesis": "Untrusted hypothesis", "confidence": "HIGH",
            "supporting_event_ids": [event_id], "ruled_out_alternatives": [],
        }],
        "explicit_unknowns": [],
        "trader_squawk_update": "Order state unknown.",
        "engineering_escalation_summary": "Inspect evidence.",
        "remediation_artifacts": [{
            "title": "Unsafe artifact", "target_system": "OMS_SQL", "artifact_type": "SQL_PATCH",
            "code_or_command": "UPDATE oms_orders SET filled_qty='0';",
            "requires_human_approval": False, "safety_warning": "No warning",
        }],
        "safe_to_resend": True,
        "verification_passed": False,
        "verification_warnings": [],
    }


def test_verifier_strips_fabricated_event_citations(seeded_db):
    report = db.get_deterministic_report(seeded_db, "INC-102")
    events = db.get_incident_events(seeded_db, "INC-102")
    raw = _diagnosis_payload(report, "EVT-FAKE-999")
    sanitized = verify_and_sanitize_ai_diagnosis(raw, report, events)
    assert sanitized.proven_claims == []
    assert sanitized.ranked_hypotheses == []
    assert any("EVT-FAKE-999" in warning for warning in sanitized.verification_warnings)
    assert not sanitized.verification_passed


def test_adversarial_unknown_timeout_safety_override_and_unknown_restoration(seeded_db):
    report = db.get_deterministic_report(seeded_db, "INC-103")
    events = db.get_incident_events(seeded_db, "INC-103")
    raw = _diagnosis_payload(report, "e103-new")
    raw["incident_id"] = "INC-103"
    raw["explicit_unknowns"] = []
    raw["safe_to_resend"] = True
    sanitized = verify_and_sanitize_ai_diagnosis(raw, report, events)
    assert sanitized.safe_to_resend is False
    assert report.unknowns[0] in sanitized.explicit_unknowns
    assert any("CRITICAL SAFETY OVERRIDE" in warning for warning in sanitized.verification_warnings)
    assert any("unknown restored" in warning for warning in sanitized.verification_warnings)
    assert all(artifact.requires_human_approval for artifact in sanitized.remediation_artifacts)


def test_schema_failure_uses_deterministic_fallback(seeded_db):
    report = db.get_deterministic_report(seeded_db, "INC-102")
    result = verify_and_sanitize_ai_diagnosis({"safe_to_resend": True}, report, db.get_incident_events(seeded_db, "INC-102"))
    assert result.model_used == "deterministic-fallback-verifier"
    assert result.incident_id == "INC-102"
    assert not result.safe_to_resend
    assert any("schema/JSON rejected" in warning for warning in result.verification_warnings)


@pytest.mark.parametrize(
    "incident_id,expected_target,expected_type,marker",
    [
        ("INC-101", "FIX_SESSION", "PYTHON_DIAGNOSTIC", "123=Y"),
        ("INC-102", "EXCHANGE_DESK", "RUNBOOK_STEPS", "ExecID"),
        ("INC-103", "FIX_SESSION", "FIX_MESSAGE", "35=H"),
        ("INC-105", "OMS_SQL", "SQL_PATCH", "drop_copy_executions"),
    ],
)
def test_muse_code_artifacts_match_scenario_and_require_human_approval(
    seeded_db, incident_id, expected_target, expected_type, marker
):
    report = db.get_deterministic_report(seeded_db, incident_id)
    artifacts = generate_muse_code_remediation(report)
    assert artifacts
    assert artifacts[0].target_system == expected_target
    assert artifacts[0].artifact_type == expected_type
    assert marker in artifacts[0].code_or_command
    assert all(artifact.requires_human_approval for artifact in artifacts)
    assert all("read-only" in artifact.safety_warning.lower() for artifact in artifacts)


def test_transcribe_voice_extracts_identifiers_symbols_and_matches_incident(seeded_db):
    result = transcribe_voice_squawk(
        "WEX_DMA reports ORD-9040 in NVDA timed out; exchange receipt is unknown.", seeded_db
    )
    assert result.modality == "VOICE_SQUAWK"
    assert result.model_used == "Muse Voice Transcribe"
    assert result.extracted_cl_ord_ids == ["ORD-9040"]
    assert result.extracted_symbols == ["NVDA"]
    assert result.matched_incident_id == "INC-103"


def test_vision_caption_extracts_order_and_symbol(seeded_db):
    result = analyze_blotter_screenshot(b"", seeded_db)  # byte payload falls back to empty visible OCR text
    assert result.modality == "BLOTTER_SCREENSHOT"
    caption = analyze_blotter_screenshot("Blotter: ORD-5510 MSFT filled 500 shares", seeded_db)
    assert caption.extracted_cl_ord_ids == ["ORD-5510"]
    assert caption.extracted_symbols == ["MSFT"]
    assert caption.matched_incident_id == "INC-105"


def test_api_investigate_route_returns_persists_and_broadcasts(seeded_db, monkeypatch):
    monkeypatch.delenv("BASETEN_API_KEY", raising=False)
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    monkeypatch.delenv("META_API_KEY", raising=False)
    with TestClient(app) as client:
        client.post("/api/incidents/seed")
        with client.websocket_connect("/ws/stream") as websocket:
            response = client.post("/api/incidents/INC-103/investigate")
            assert response.status_code == 200, response.text
            diagnosis = response.json()
            assert diagnosis["incident_id"] == "INC-103"
            assert diagnosis["verification_passed"]
            assert diagnosis["safe_to_resend"] is False
            assert db.get_ai_diagnosis(seeded_db, "INC-103").incident_id == "INC-103"
            message = websocket.receive_json()
            assert message["type"] == "ai_diagnosis"
            assert message["diagnosis"]["incident_id"] == "INC-103"
        missing = client.post("/api/incidents/NOT-SEEDED/investigate")
        assert missing.status_code == 404


def test_api_voice_and_blotter_intake_json_end_to_end(seeded_db):
    with TestClient(app) as client:
        client.post("/api/incidents/seed")
        voice = client.post("/api/intake/voice-squawk", json={"transcript": "Trader reports ORD-8821 AAPL filled"})
        assert voice.status_code == 200, voice.text
        assert voice.json()["intake"]["matched_incident_id"] == "INC-102"
        assert voice.json()["matched_report"]["incident_id"] == "INC-102"

        image = client.post(
            "/api/intake/blotter-screenshot",
            json={"caption": "Grafana alert ORD-5510 MSFT SQL database lock"},
        )
        assert image.status_code == 200, image.text
        assert image.json()["intake"]["matched_incident_id"] == "INC-105"
        assert image.json()["matched_report"]["incident_id"] == "INC-105"


def test_api_voice_and_screenshot_multipart_uploads(seeded_db):
    with TestClient(app) as client:
        client.post("/api/incidents/seed")
        voice = client.post(
            "/api/intake/voice-squawk",
            files={"audio": ("voice.wav", b"ORD-9040 NVDA gateway timeout", "audio/wav")},
        )
        assert voice.status_code == 200, voice.text
        assert voice.json()["intake"]["matched_incident_id"] == "INC-103"
        image = client.post(
            "/api/intake/blotter-screenshot",
            files={"image": ("blotter.png", b"ORD-5510 MSFT execution alert", "image/png")},
        )
        assert image.status_code == 200, image.text
        assert image.json()["intake"]["matched_incident_id"] == "INC-105"


def test_api_rejects_missing_multimodal_payload(seeded_db):
    with TestClient(app) as client:
        assert client.post("/api/intake/voice-squawk", json={}).status_code == 422
        assert client.post("/api/intake/blotter-screenshot", json={}).status_code == 422


def test_live_provider_request_uses_mock_httpx_and_is_verified(seeded_db, monkeypatch):
    monkeypatch.setenv("BASETEN_API_KEY", "test-key")
    monkeypatch.setenv("BASETEN_MODEL_ID", "meta-models/muse-spark-open-1026")
    report = db.get_deterministic_report(seeded_db, "INC-102")
    events = db.get_incident_events(seeded_db, "INC-102")
    event_id = events[0]["event_id"]
    response_json = {"choices": [{"message": {"content": json.dumps(_diagnosis_payload(report, event_id))}}]}
    requests = []

    async def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=response_json)

    async def run():
        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
            investigator = VerifiableAIInvestigator(seeded_db, http_client=client)
            result = await investigator.investigate("INC-102")
            return result

    result = asyncio.run(run())
    assert result.model_used == "meta-models/muse-spark-open-1026"
    assert len(requests) == 1
    assert requests[0].url.path.endswith("/chat/completions")
    assert result.safe_to_resend is False
    assert all(artifact.requires_human_approval for artifact in result.remediation_artifacts)
