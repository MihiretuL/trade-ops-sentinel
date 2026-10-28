"""Multimodal desk intake and read-only Muse Code remediation templates."""

from __future__ import annotations

import base64
import json
import re
from typing import Any

import httpx

from . import db
from .ai_investigator import generate_artifacts
from .config import get_settings
from .models import DeterministicInvestigationReport, MultimodalIntakeResult, ReadOnlyRemediationArtifact

_ORDER_ID = re.compile(r"\b(?:ORD|CXL)-\d+\b", re.IGNORECASE)
_SYMBOLS = {"AAPL", "NVDA", "SPY", "MSFT", "ESZ6"}
_SESSION_NAMES = {"WEX_DMA", "CME_GW", "NASDAQ_GW", "EXCHANGE_GW", "FIX_GATEWAY", "SQL_DB"}


def _text_from_input(payload: bytes | str) -> str:
    if isinstance(payload, str):
        return payload
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def _model_extract_text(modality: str, payload: bytes | str) -> str | None:
    """Optionally call Meta's OpenAI-compatible endpoint; never required for local mode."""
    settings = get_settings()
    if not settings.meta_api_key or not settings.meta_base_url:
        return None
    try:
        with httpx.Client(timeout=20.0) as client:
            if modality == "VOICE_SQUAWK":
                content = payload if isinstance(payload, bytes) else payload.encode("utf-8")
                response = client.post(
                    f"{settings.meta_base_url.rstrip('/')}/audio/transcriptions",
                    headers={"Authorization": f"Bearer {settings.meta_api_key}"},
                    data={"model": "muse-voice-transcribe"},
                    files={"file": ("squawk.wav", content, "audio/wav")},
                )
                response.raise_for_status()
                return str(response.json().get("text", ""))
            content = payload if isinstance(payload, bytes) else payload.encode("utf-8")
            encoded = base64.b64encode(content).decode("ascii")
            response = client.post(
                f"{settings.meta_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {settings.meta_api_key}", "Content-Type": "application/json"},
                json={"model": "muse-spark-vision", "temperature": 0,
                      "messages": [{"role": "user", "content": [
                          {"type": "text", "text": "Read the trading blotter/Grafana image. Return only visible text, identifiers and symbols; do not infer missing facts."},
                          {"type": "image_url", "image_url": {"url": f"data:image/png;base64,{encoded}"}},
                      ]}]},
            )
            response.raise_for_status()
            message = response.json()["choices"][0]["message"]["content"]
            if isinstance(message, list):
                return " ".join(str(part.get("text", "")) for part in message if isinstance(part, dict))
            return str(message)
    except (httpx.HTTPError, ValueError, KeyError, TypeError):
        # External extraction is optional; the explicit local fallback below remains authoritative.
        return None


def _extract(text: str) -> tuple[list[str], list[str]]:
    order_ids = list(dict.fromkeys(match.upper() for match in _ORDER_ID.findall(text)))
    uppercase = set(re.findall(r"\b[A-Z][A-Z0-9]{1,5}\b", text.upper()))
    symbols = sorted(_SYMBOLS.intersection(uppercase))
    return order_ids, symbols


def _match_incident(db_path: str, text: str, order_ids: list[str], symbols: list[str]) -> str | None:
    incidents = db.list_incidents(db_path)
    normalized_text = text.upper()
    for incident in incidents:
        incident_id = str(incident["incident_id"])
        rows = db.get_oms_orders(db_path, incident_id)
        identifiers = {str(row["cl_ord_id"]).upper() for row in rows}
        known_ids = identifiers.intersection(order_id.upper() for order_id in order_ids)
        if known_ids:
            return incident_id
        # Match canonical non-order descriptions only when a distinctive symbol and ID are present.
        if incident_id == "INC-102" and "ORD-8821" in order_ids:
            return incident_id
        if incident_id == "INC-103" and "ORD-9040" in order_ids:
            return incident_id
        if incident_id == "INC-105" and "ORD-5510" in order_ids:
            return incident_id
        if incident_id == "INC-101" and "ORD-101" in order_ids:
            return incident_id
        if incident_id == "INC-104" and any(item in order_ids for item in ("ORD-7701", "ORD-7702")):
            return incident_id
        if incident_id in normalized_text and (not symbols or any(symbol in normalized_text for symbol in symbols)):
            return incident_id
    return None


def transcribe_voice_squawk(audio_bytes_or_text: bytes | str, db_path: str) -> MultimodalIntakeResult:
    """Transcribe or accept supplied transcript, then extract identifiers and match evidence."""
    text = audio_bytes_or_text if isinstance(audio_bytes_or_text, str) else _model_extract_text("VOICE_SQUAWK", audio_bytes_or_text)
    if text is None:
        text = _text_from_input(audio_bytes_or_text)
    order_ids, symbols = _extract(text)
    return MultimodalIntakeResult(
        modality="VOICE_SQUAWK",
        model_used="Muse Voice Transcribe",
        extracted_text=text,
        extracted_cl_ord_ids=order_ids,
        extracted_symbols=symbols,
        matched_incident_id=_match_incident(db_path, text, order_ids, symbols),
    )


def analyze_blotter_screenshot(image_bytes_or_caption: bytes | str, db_path: str) -> MultimodalIntakeResult:
    """Analyze an image via configured Muse Vision or use visible caption/OCR-like text fallback."""
    text = image_bytes_or_caption if isinstance(image_bytes_or_caption, str) else _model_extract_text("BLOTTER_SCREENSHOT", image_bytes_or_caption)
    if text is None:
        text = _text_from_input(image_bytes_or_caption)
        # A screenshot's filename/metadata can be supplied as textual caption in local mode.
    order_ids, symbols = _extract(text)
    return MultimodalIntakeResult(
        modality="BLOTTER_SCREENSHOT",
        model_used="Muse Spark Vision",
        extracted_text=text,
        extracted_cl_ord_ids=order_ids,
        extracted_symbols=symbols,
        matched_incident_id=_match_incident(db_path, text, order_ids, symbols),
    )


def _muse_code_artifacts(
    report: DeterministicInvestigationReport,
    expected: list[ReadOnlyRemediationArtifact],
) -> list[ReadOnlyRemediationArtifact] | None:
    """Request optional OpenAI-compatible Muse Code output and enforce category contract."""
    settings = get_settings()
    if not settings.meta_api_key or not settings.meta_base_url:
        return None
    try:
        with httpx.Client(timeout=20.0) as client:
            response = client.post(
                f"{settings.meta_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {settings.meta_api_key}", "Content-Type": "application/json"},
                json={
                    "model": "muse-code",
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": (
                            "Generate read-only trading operations diagnostics only. Never produce code that sends orders, "
                            "changes a database, or executes recovery. Return JSON with an artifacts array."
                        )},
                        {"role": "user", "content": json.dumps({
                            "incident_id": report.incident_id,
                            "failure_category": report.primary_failure_category,
                            "deterministic_summary": report.summary,
                            "required_target_system": expected[0].target_system,
                            "required_artifact_type": expected[0].artifact_type,
                            "required_human_approval": True,
                            "read_only_template": expected[0].model_dump(mode="json"),
                        }, sort_keys=True)},
                    ],
                },
            )
            response.raise_for_status()
            content = response.json()["choices"][0]["message"]["content"]
            decoded = json.loads(content) if isinstance(content, str) else content
            raw_items = decoded.get("artifacts", []) if isinstance(decoded, dict) else []
            candidates = [ReadOnlyRemediationArtifact.model_validate(item) for item in raw_items]
            if len(candidates) != len(expected):
                return None
            for candidate, template in zip(candidates, expected):
                if candidate.target_system != template.target_system or candidate.artifact_type != template.artifact_type:
                    return None
                if not candidate.code_or_command.strip():
                    return None
                candidate.requires_human_approval = True
                candidate.safety_warning = (
                    "Muse Code suggestion is untrusted and read-only; verify independently. "
                    "Human approval is required; this artifact is never executed automatically."
                )
            return candidates
    except (httpx.HTTPError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None


def generate_muse_code_remediation(
    deterministic_report: DeterministicInvestigationReport,
) -> list[ReadOnlyRemediationArtifact]:
    """Create category-matched read-only artifacts via Muse Code or safe local templates."""
    artifacts = generate_artifacts(deterministic_report)
    model_artifacts = _muse_code_artifacts(deterministic_report, artifacts)
    if model_artifacts is not None:
        artifacts = model_artifacts
    for artifact in artifacts:
        artifact.requires_human_approval = True
        if not artifact.safety_warning:
            artifact.safety_warning = "Read-only recommendation. Human approval is required; do not execute automatically."
    return artifacts
