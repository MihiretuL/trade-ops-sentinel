"""Ground-truth deterministic production-style incident evidence fixtures.

These are local simulations only and do not establish production connectivity
or prove how a real exchange behaves.
"""

from __future__ import annotations

from datetime import datetime, timezone

from .fix_protocol import SOH, build_fix_message
from .models import (
    Direction,
    IncidentFixture,
    OMSRecord,
    SessionSeed,
    TelemetryEvent,
    WireEvent,
)

WEX = "WEX_DMA"
CME = "CME_GW"


def _ts(value: str) -> datetime:
    return datetime.fromisoformat(value).replace(tzinfo=timezone.utc)


def _wire_event(
    event_id: str,
    timestamp: str,
    direction: Direction,
    msg_type: str,
    seq: int,
    sender: str,
    target: str,
    *fields: tuple[int, str],
    poss_dup: bool = False,
    source: str = "FIX_WIRE",
) -> WireEvent:
    header = [(35, msg_type), (34, str(seq)), (49, sender), (56, target)]
    if poss_dup:
        header.append((43, "Y"))
    wire = build_fix_message([*header, *fields], begin_string="FIX.4.4", delimiter=SOH)
    return WireEvent(
        event_id=event_id,
        timestamp=_ts(timestamp),
        source_layer=source,
        provenance=f"Deterministic local fixture {event_id}; simulated evidence, not live exchange telemetry.",
        direction=direction,
        wire=wire,
        sender_comp_id=sender,
        target_comp_id=target,
    )


def _telemetry(
    event_id: str,
    timestamp: str,
    source: str,
    event_type: str,
    *,
    order_id: str | None = None,
    **details: object,
) -> TelemetryEvent:
    return TelemetryEvent(
        event_id=event_id,
        timestamp=_ts(timestamp),
        source_layer=source,
        provenance=f"Deterministic local fixture {event_id}; simulated evidence, not production telemetry.",
        event_type=event_type,
        order_id=order_id,
        details=dict(details),
    )


def all_incidents() -> tuple[IncidentFixture, ...]:
    """Return exactly five stable incidents with deterministic evidence IDs/times."""
    return (
        IncidentFixture(
            incident_id="INC-101",
            title="SEQ_GAP_RESEND",
            description="WEX_DMA outbound sequences 105–107 are missing; CME requests resend and WEX sends a gap fill.",
            sequence_seeds=(SessionSeed(sender_comp_id=WEX, target_comp_id=CME, direction=Direction.OUTBOUND, next_sequence=105),),
            events=(
                _wire_event("e101-order-108", "2026-10-27T09:30:00.000", Direction.OUTBOUND, "D", 108, WEX, CME,
                            (11, "ORD-101"), (55, "AAPL"), (54, "1"), (38, "100"), (40, "2"), (44, "225.50")),
                _wire_event("e101-resend-request", "2026-10-27T09:30:00.001", Direction.INBOUND, "2", 1, CME, WEX,
                            (7, "105"), (16, "0")),
                _wire_event("e101-gap-fill", "2026-10-27T09:30:00.002", Direction.OUTBOUND, "4", 105, WEX, CME,
                            (123, "Y"), (36, "108"), poss_dup=True),
            ),
            expected={"sequence_gap": True, "gap_resolved": True, "resend_range": [105, 0], "order_status": "pending_new"},
        ),
        IncidentFixture(
            incident_id="INC-102",
            title="CANCEL_FILL_RACE",
            description="An AAPL order fills completely; a cancel sent 2ms later is rejected as too late.",
            events=(
                _wire_event("e102-new", "2026-10-27T09:31:00.000", Direction.OUTBOUND, "D", 1, WEX, CME,
                            (11, "ORD-8821"), (55, "AAPL"), (54, "1"), (38, "500"), (40, "2"), (44, "225.50")),
                _wire_event("e102-ack", "2026-10-27T09:31:00.001", Direction.INBOUND, "8", 1, CME, WEX,
                            (11, "ORD-8821"), (37, "EX-8821"), (150, "0"), (39, "0"), (55, "AAPL"),
                            (54, "1"), (38, "500"), (14, "0"), (151, "500"), (6, "0")),
                _wire_event("e102-fill", "2026-10-27T09:31:00.002", Direction.INBOUND, "8", 2, CME, WEX,
                            (11, "ORD-8821"), (37, "EX-8821"), (17, "EXEC-01"), (150, "2"), (39, "2"),
                            (55, "AAPL"), (54, "1"), (38, "500"), (32, "500"), (31, "225.50"),
                            (14, "500"), (151, "0"), (6, "225.50")),
                _wire_event("e102-cancel", "2026-10-27T09:31:00.004", Direction.OUTBOUND, "F", 2, WEX, CME,
                            (11, "CXL-8821"), (41, "ORD-8821"), (55, "AAPL"), (54, "1"), (38, "500")),
                _wire_event("e102-cancel-reject", "2026-10-27T09:31:00.005", Direction.INBOUND, "9", 3, CME, WEX,
                            (11, "CXL-8821"), (41, "ORD-8821"), (37, "EX-8821"), (39, "2"), (102, "0"),
                            (58, "TooLateToCancel")),
            ),
            expected={"status": "filled", "cum_qty": "500", "exposure_dollars": "112750.00", "safe_to_resend": False},
        ),
        IncidentFixture(
            incident_id="INC-103",
            title="IN_FLIGHT_GATEWAY_TIMEOUT",
            description="FIX gateway timeout after transmission leaves exchange receipt and execution unknown.",
            events=(
                _telemetry("e103-risk-pass", "2026-10-27T09:32:00.000", "RISK", "risk_pass", order_id="ORD-9040", decision="pass"),
                _wire_event("e103-new", "2026-10-27T09:32:00.001", Direction.OUTBOUND, "D", 1, WEX, "NASDAQ_GW",
                            (11, "ORD-9040"), (55, "NVDA"), (54, "1"), (38, "1000"), (40, "2"), (44, "138.40"), source="FIX_GATEWAY"),
                _telemetry("e103-timeout", "2026-10-27T09:32:00.501", "FIX_GATEWAY", "gateway_timeout",
                            order_id="ORD-9040", timeout_ms=500, peer="NASDAQ_GW", inbound_execution_reports=0),
            ),
            expected={"is_in_flight_unknown": True, "safe_to_resend": False, "exposure_dollars": "138400.00",
                      "unknown": "Exchange receipt or execution cannot be determined from current telemetry."},
        ),
        IncidentFixture(
            incident_id="INC-104",
            title="PROTOCOL_OR_RISK_REJECT",
            description="A malformed limit order receives a session reject; a distinct order receives an application risk reject.",
            events=(
                _wire_event("e104-order-a", "2026-10-27T09:33:00.000", Direction.OUTBOUND, "D", 1, WEX, CME,
                            (11, "ORD-7701"), (55, "AAPL"), (54, "1"), (38, "10"), (40, "2")),
                _wire_event("e104-session-reject", "2026-10-27T09:33:00.001", Direction.INBOUND, "3", 1, CME, WEX,
                            (45, "1"), (371, "44"), (372, "D"), (373, "1"), (58, "RequiredTagMissing")),
                _wire_event("e104-order-b", "2026-10-27T09:33:00.002", Direction.OUTBOUND, "D", 2, WEX, CME,
                            (11, "ORD-7702"), (55, "AAPL"), (54, "1"), (38, "1000"), (40, "2"), (44, "225.50")),
                _wire_event("e104-app-reject", "2026-10-27T09:33:00.003", Direction.INBOUND, "8", 2, CME, WEX,
                            (11, "ORD-7702"), (37, "EX-7702"), (150, "8"), (39, "8"), (103, "3"),
                            (58, "OrderExceedsLimit")),
            ),
            expected={"ORD-7701": "session_protocol_reject", "ORD-7702": "application_risk_reject"},
        ),
        IncidentFixture(
            incident_id="INC-105",
            title="DROP_COPY_SQL_RECON_BREAK",
            description="Exchange fill evidence conflicts with a stale OMS record after a database lock error.",
            events=(
                _wire_event("e105-new", "2026-10-27T09:34:00.000", Direction.OUTBOUND, "D", 1, WEX, "NASDAQ_GW",
                            (11, "ORD-5510"), (55, "MSFT"), (54, "1"), (38, "500"), (40, "2"), (44, "415.20")),
                _wire_event("e105-fill", "2026-10-27T09:34:00.010", Direction.INBOUND, "8", 1, "NASDAQ_GW", WEX,
                            (11, "ORD-5510"), (37, "EX-5510"), (17, "EXEC-5510"), (55, "MSFT"), (54, "1"),
                            (150, "2"), (39, "2"), (38, "500"), (32, "500"), (31, "415.20"),
                            (14, "500"), (151, "0"), (6, "415.20")),
                _telemetry("e105-db-lock", "2026-10-27T09:34:00.011", "SQL_DB", "database_error",
                            order_id="ORD-5510", error="database is locked", operation="persist_execution"),
            ),
            oms_records=(OMSRecord(order_id="ORD-5510", status="PendingNew", filled_qty="0", event_id="oms-e105-5510",
                                   timestamp=_ts("2026-10-27T09:34:00.012"), source_layer="OMS_SQL",
                                   provenance="Deterministic stale OMS snapshot following simulated database lock."),),
            expected={"exchange_filled_qty": "500", "oms_filled_qty": "0", "exchange_notional": "207600.00"},
        ),
    )


def get_incident(incident_id: str) -> IncidentFixture:
    """Return one stable fixture or raise KeyError for an unknown ID."""
    for incident in all_incidents():
        if incident.incident_id == incident_id:
            return incident
    raise KeyError(f"Unknown incident ID: {incident_id}")
