"""Dynamic red-team scenarios whose fault instructions stay outside blue-team evidence.

This module compiles user language into a local LimitOrderBook exercise, then
persists only observed FIX/telemetry/OMS evidence. The deterministic reconstructor
and AI investigator receive no ChaosFaultSpec, prompt text, or DYN prefix.
All simulated transport faults are local observations; no external hosts are
contacted and generated remediation is never executed.
"""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Awaitable, Callable

import httpx

from . import db
from .config import get_settings
from .fix_protocol import build_fix_message, parse_fix_message
from .models import (
    ChaosFaultSpec,
    Direction,
    IncidentFixture,
    OMSRecord,
    TelemetryEvent,
    WireEvent,
)
from .order_book import FIXFrame, LimitOrderBook, MatchingResult
from .reconstructor import IncidentReconstructor

Broadcast = Callable[[dict[str, Any]], Awaitable[None]]
_SYMBOLS = tuple(LimitOrderBook.MARKET)


def _decimal_string(value: Decimal) -> str:
    return format(value, "f")


def _fallback_compile(prompt: str, book: LimitOrderBook) -> ChaosFaultSpec:
    text = prompt.upper()
    symbol = next((candidate for candidate in _SYMBOLS if re.search(rf"\b{candidate}\b", text)), "NVDA")
    side = "SELL" if re.search(r"\b(SELL|SHORT|OFFER)\b", text) else "BUY"
    quantity_matches = re.findall(r"\b([\d,]+)\s*[- ]?\s*(?:SHARES?|SHR)\b", text)
    quantity = Decimal(quantity_matches[-1].replace(",", "")) if quantity_matches else Decimal("100")

    sequence_count = 0
    if re.search(r"(PACKET|SEQUENCE|RESEND|TCP|OUTBOUND)", text) and re.search(r"(DROP|GAP|RESEND|PACKET)", text):
        match = re.search(r"\b(\d+)\s+(?:OUTBOUND\s+)?(?:TCP\s+)?PACKETS?\b", text)
        sequence_count = int(match.group(1)) if match else 1
        fault_type = "sequence_gap"
    elif re.search(r"(SQL|DATABASE|SQLITE|COMMIT|PHANTOM FILL|DB LOCK)", text):
        fault_type = "sql_lock"
    elif re.search(r"(CANCEL|CXL).*(FILL|RACE)|(FILL|RACE).*(CANCEL|CXL)", text):
        fault_type = "cancel_fill_race"
    elif re.search(r"(TIMEOUT|TIMED OUT|SILENT|NO ACK|UNACKNOWLEDGED)", text):
        fault_type = "gateway_timeout"
    else:
        fault_type = "normal_flow"

    price_match = re.search(r"(?:@|\$|\bAT\s+)\s*\$?\s*(\d{1,7}(?:\.\d{1,6})?)", prompt, re.IGNORECASE)
    timeout_match = re.search(r"\b(\d+)\s*MS\b", text)
    delay_match = re.search(r"\b(\d+(?:\.\d+)?)\s*(MS|MICROSECONDS?|US)\b", text)
    snapshot = book.get_book_snapshot(symbol)
    default_price = snapshot["best_ask"] if side == "BUY" else snapshot["best_bid"]
    limit_price = Decimal(price_match.group(1)) if price_match else Decimal(default_price)
    return ChaosFaultSpec(
        symbol=symbol,
        side=side,
        order_qty=quantity,
        limit_price=limit_price,
        fault_type=fault_type,
        dropped_seq_count=sequence_count,
        timeout_ms=int(timeout_match.group(1)) if timeout_match else 500 if fault_type == "gateway_timeout" else 0,
        induce_sql_lock=fault_type == "sql_lock" or bool(re.search(r"\b(SQL|DATABASE|SQLITE|COMMIT|DB LOCK)\b", text)),
        race_cancel_delay_ms=(
            Decimal(delay_match.group(1)) / (Decimal("1000") if delay_match.group(2).startswith("MICRO") or delay_match.group(2) == "US" else Decimal("1"))
            if delay_match else Decimal("0.001") if fault_type == "cancel_fill_race" and "MICRO" in text else Decimal("0.250") if fault_type == "cancel_fill_race" else Decimal("0")
        ),
    )


async def compile_chaos_prompt(prompt: str, book: LimitOrderBook) -> ChaosFaultSpec:
    """Use configured Meta-compatible model for structured compilation, with local parser fallback."""
    fallback = _fallback_compile(prompt, book)
    settings = get_settings()
    if not settings.meta_api_key or not settings.meta_base_url:
        return fallback
    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            response = await client.post(
                f"{settings.meta_base_url.rstrip('/')}/chat/completions",
                headers={"Authorization": f"Bearer {settings.meta_api_key}", "Content-Type": "application/json"},
                json={
                    "model": settings.baseten_model_id,
                    "temperature": 0,
                    "response_format": {"type": "json_object"},
                    "messages": [
                        {"role": "system", "content": (
                            "Compile the request to ChaosFaultSpec JSON only. Symbols must be one of AAPL,NVDA,MSFT,SPY,TSLA,ESZ6; "
                            "fault_type one of normal_flow,sequence_gap,gateway_timeout,sql_lock,cancel_fill_race. "
                            "This controls a local simulator only; never request external network actions."
                        )},
                        {"role": "user", "content": json.dumps({"prompt": prompt, "fallback": fallback.model_dump(mode="json")})},
                    ],
                },
            )
            response.raise_for_status()
            payload = response.json()["choices"][0]["message"]["content"]
            raw = json.loads(payload) if isinstance(payload, str) else payload
            spec = ChaosFaultSpec.model_validate(raw)
            if spec.order_qty <= 0 or spec.limit_price <= 0 or spec.dropped_seq_count < 0 or spec.timeout_ms < 0:
                return fallback
            return spec.model_copy(update={
                "induce_sql_lock": spec.induce_sql_lock or spec.fault_type == "sql_lock",
            })
    except (httpx.HTTPError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return fallback


def _canonicalize_frames(frames: list[FIXFrame], *, dropped_seq_count: int = 0) -> list[tuple[Direction, str]]:
    """Give each isolated incident a coherent session sequence, preserving configured gaps."""
    next_seq = {"outbound": 1, "inbound": 1}
    result: list[tuple[Direction, str]] = []
    outbound_first = True
    for frame in frames:
        message = parse_fix_message(frame.raw_fix)
        direction = Direction(frame.direction)
        seq_key = frame.direction
        if frame.direction == "outbound" and outbound_first:
            next_seq[seq_key] += dropped_seq_count
            outbound_first = False
        sequence = next_seq[seq_key]
        next_seq[seq_key] += 1
        pairs = [(field.tag, field.value) for field in message.fields if field.tag != 34]
        # Insert sequence number immediately after MsgType; the builder enforces MsgType at body head.
        fields = []
        inserted = False
        for tag, value in pairs:
            fields.append((tag, value))
            if tag == 35 and not inserted:
                fields.append((34, str(sequence)))
                inserted = True
        if not inserted:
            raise ValueError("Order-book FIX frame is missing MsgType(35)")
        wire = build_fix_message(fields, begin_string="FIX.4.2")
        result.append((direction, wire))
    return result


def _wire_event(event_id: str, timestamp: datetime, direction: Direction, wire: str) -> WireEvent:
    message = parse_fix_message(wire)
    return WireEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_layer="FIX_ORDER_ROUTER" if direction == Direction.OUTBOUND else "EXCHANGE_GW",
        provenance="Observed FIX 4.2 frame from the local order-book digital twin; no live exchange connection.",
        direction=direction,
        wire=wire,
        sender_comp_id=message.sender_comp_id or "WEX_DMA",
        target_comp_id=message.target_comp_id or "EXCHANGE_GW",
    )


def _telemetry(
    event_id: str,
    timestamp: datetime,
    source: str,
    event_type: str,
    *,
    order_id: str | None = None,
    details: dict[str, Any],
) -> TelemetryEvent:
    return TelemetryEvent(
        event_id=event_id,
        timestamp=timestamp,
        source_layer=source,
        provenance="Observed local digital-twin telemetry; prompt specification is not included in evidence.",
        event_type=event_type,
        order_id=order_id,
        details=details,
    )


async def inject_natural_language_chaos(
    prompt: str,
    db_path: str,
    *,
    order_book: LimitOrderBook,
    broadcast: Broadcast | None = None,
) -> dict[str, Any]:
    """Compile an instruction, exercise the LOB, persist evidence, then invoke a blind investigator.

    The returned object includes the red-team spec for the caller. The spec and
    original prompt are deliberately excluded from incident storage and from
    both blue-team services; they receive only FIX frames, telemetry and SQL rows.
    """
    if not prompt.strip():
        raise ValueError("Chaos prompt must not be empty")
    spec = await compile_chaos_prompt(prompt, order_book)
    incident_id = f"DYN-{uuid.uuid4().hex[:8].upper()}"
    prefix = uuid.uuid4().hex[:10]
    result: MatchingResult = order_book.match_new_order(
        spec.symbol, spec.side, spec.order_qty, spec.limit_price,
        msg_seq_num=1,
    )
    frames = _canonicalize_frames(
        result.frames,
        dropped_seq_count=spec.dropped_seq_count if spec.fault_type == "sequence_gap" else 0,
    )

    # An injected gateway timeout deliberately hides exchange responses even though
    # the isolated digital-twin book executed. This models ambiguous in-flight exposure.
    if spec.fault_type == "gateway_timeout":
        frames = [(direction, wire) for direction, wire in frames if direction == Direction.OUTBOUND]

    now = datetime.now(timezone.utc)
    events: list[WireEvent | TelemetryEvent] = []
    frame_event_by_wire: dict[str, str] = {}
    for index, (direction, wire) in enumerate(frames):
        event_id = f"evt-{prefix}-{index + 1:03d}"
        timestamp = now + timedelta(microseconds=index * 100)
        event = _wire_event(event_id, timestamp, direction, wire)
        events.append(event)
        frame_event_by_wire[wire] = event_id

    order_id = result.cl_ord_id
    next_time = now + timedelta(microseconds=(len(events) + 1) * 100)
    if spec.fault_type == "sequence_gap":
        next_inbound_seq = 1 + sum(direction == Direction.INBOUND for direction, _ in frames)
        gap_wire = build_fix_message(
            [(35, "2"), (34, str(next_inbound_seq)), (49, "EXCHANGE_GW"), (56, "WEX_DMA"),
             (7, "1"), (16, str(spec.dropped_seq_count))],
            begin_string="FIX.4.2",
        )
        gap_event = _wire_event(
            f"evt-{prefix}-resend", next_time + timedelta(microseconds=50),
            Direction.INBOUND, gap_wire,
        )
        events.append(gap_event)
        network_event = _telemetry(
            f"evt-{prefix}-net", next_time, "NETWORK", "network_packet_drop", order_id=order_id,
            details={"dropped_packets": spec.dropped_seq_count, "direction": "outbound", "session": "WEX_DMA->EXCHANGE_GW"},
        )
        events.append(network_event)
    if spec.fault_type == "gateway_timeout":
        events.append(_telemetry(
            f"evt-{prefix}-timeout", next_time, "FIX_GATEWAY", "gateway_timeout", order_id=order_id,
            details={"timeout_ms": spec.timeout_ms, "peer": "EXCHANGE_GW", "inbound_execution_reports": 0},
        ))
    elif spec.fault_type == "sql_lock" or spec.induce_sql_lock:
        events.append(_telemetry(
            f"evt-{prefix}-sql", next_time, "SQL_DB", "database_error", order_id=order_id,
            details={"error": "database is locked", "operation": "persist_execution", "table": "oms_orders"},
        ))
    elif spec.fault_type == "cancel_fill_race" and result.leaves_qty == 0:
        cancel_result = order_book.cancel_order(order_id)
        cancel_frames = _canonicalize_frames(cancel_result.frames)
        base_index = len(events)
        for offset, (direction, wire) in enumerate(cancel_frames):
            events.append(_wire_event(f"evt-{prefix}-cancel-{offset + 1}", next_time + timedelta(microseconds=(offset + 1) * 100), direction, wire))

    filled_qty = result.cum_qty
    # A simulated DB lock keeps OMS stale; all other observed cases persist the current order state.
    if spec.fault_type == "sql_lock" or spec.induce_sql_lock:
        oms_status, oms_filled = "PendingNew", Decimal("0")
    elif spec.fault_type == "gateway_timeout":
        oms_status, oms_filled = "PendingNew", Decimal("0")
    else:
        oms_status = "filled" if result.leaves_qty == 0 and filled_qty > 0 else "partially_filled" if filled_qty else "new"
        oms_filled = filled_qty
    oms_event_id = f"evt-{prefix}-oms"
    record = OMSRecord(
        order_id=order_id,
        status=oms_status,
        filled_qty=oms_filled,
        event_id=oms_event_id,
        timestamp=next_time + timedelta(microseconds=100),
        source_layer="OMS_SQL",
        provenance="Observed local OMS snapshot for this order; no ChaosFaultSpec or prompt stored.",
    )
    fixture = IncidentFixture(
        incident_id=incident_id,
        title="Dynamic market execution evidence",
        description="A newly generated order-book event was reconstructed from captured FIX, telemetry, and SQL evidence.",
        events=tuple(events),
        oms_records=(record,),
    )

    # The blue-team reconstructor sees only the persisted fixture evidence.
    reconstructor = IncidentReconstructor()
    results = reconstructor.process_incident(fixture)
    report = db.persist_custom_incident(db_path, fixture, reconstructor, results)
    from .ai_investigator import VerifiableAIInvestigator

    diagnosis = await VerifiableAIInvestigator(db_path).investigate(incident_id)
    db.persist_ai_diagnosis(db_path, incident_id, diagnosis)

    response = {
        "incident_id": incident_id,
        "fault_spec": spec.model_dump(mode="json"),
        "report": report.model_dump(mode="json"),
        "diagnosis": diagnosis.model_dump(mode="json"),
        "events": [event.model_dump(mode="json") for event in events],
        "book_snapshot": order_book.get_book_snapshot(spec.symbol),
        "order_result": {
            "cl_ord_id": order_id,
            "cum_qty": _decimal_string(filled_qty),
            "leaves_qty": _decimal_string(result.leaves_qty),
            "average_price": _decimal_string(result.average_price),
            "status": result.status,
            "book_executed_notional": _decimal_string(result.notional),
        },
    }
    if broadcast:
        for event in events:
            await broadcast({"type": "telemetry_event", "incident_id": incident_id, "event": event.model_dump(mode="json")})
        await broadcast({"type": "market_book", "incident_id": incident_id, "book": response["book_snapshot"]})
        await broadcast({"type": "investigation_update", "incident_id": incident_id, "report": report.model_dump(mode="json")})
        await broadcast({"type": "ai_diagnosis", "incident_id": incident_id, "diagnosis": diagnosis.model_dump(mode="json")})
    return response


async def step_live_market(
    db_path: str,
    *,
    order_book: LimitOrderBook,
    batch_size: int = 5,
    broadcast: Broadcast | None = None,
) -> dict[str, Any]:
    """Generate ordinary deterministic market flow, persist fills, and publish book snapshots."""
    if batch_size < 1 or batch_size > 100:
        raise ValueError("batch_size must be between 1 and 100")
    trades: list[dict[str, Any]] = []
    snapshots: list[dict[str, Any]] = []
    symbols = list(LimitOrderBook.MARKET)
    for index in range(batch_size):
        symbol = symbols[index % len(symbols)]
        side = "BUY" if index % 2 == 0 else "SELL"
        snapshot = order_book.get_book_snapshot(symbol)
        price = Decimal(snapshot["best_ask"] if side == "BUY" else snapshot["best_bid"])
        quantity = Decimal(10 + (index % 4) * 5)
        result = order_book.match_new_order(symbol, side, quantity, price, msg_seq_num=1)
        wire_events = []
        now = datetime.now(timezone.utc)
        for frame_index, frame in enumerate(result.frames):
            parsed = parse_fix_message(frame.raw_fix)
            wire_events.append(_wire_event(
                f"mkt-{uuid.uuid4().hex[:10]}-{frame_index}", now + timedelta(microseconds=frame_index * 100),
                Direction(frame.direction), frame.raw_fix,
            ))
        oms = OMSRecord(
            order_id=result.cl_ord_id,
            status="filled" if result.leaves_qty == 0 else "new",
            filled_qty=result.cum_qty,
            event_id=f"mkt-oms-{uuid.uuid4().hex[:10]}",
            timestamp=now + timedelta(microseconds=500),
            source_layer="OMS_SQL",
            provenance="Normal order-flow market tick persisted by the local digital twin.",
        )
        incident_id = f"MKT-{uuid.uuid4().hex[:8].upper()}"
        incident = IncidentFixture(
            incident_id=incident_id,
            title="Live market order-flow tick",
            description="Normal deterministic order flow matched against the local in-memory limit order book.",
            events=tuple(wire_events),
            oms_records=(oms,),
        )
        reconstructor = IncidentReconstructor()
        recon_results = reconstructor.process_incident(incident)
        report = db.persist_custom_incident(db_path, incident, reconstructor, recon_results)
        trades.append({
            "incident_id": incident_id,
            "cl_ord_id": result.cl_ord_id,
            "symbol": symbol,
            "side": side,
            "quantity": _decimal_string(result.cum_qty),
            "price": _decimal_string(result.average_price),
            "notional": _decimal_string(result.notional),
            "report": report.model_dump(mode="json"),
            "events": [event.model_dump(mode="json") for event in wire_events],
        })
        snapshots.append(order_book.get_book_snapshot(symbol))
    if broadcast:
        for trade in trades:
            for event in trade["events"]:
                await broadcast({"type": "telemetry_event", "incident_id": trade["incident_id"], "event": event})
            await broadcast({"type": "investigation_update", "incident_id": trade["incident_id"], "report": trade["report"]})
        await broadcast({"type": "market_books", "books": snapshots})
    return {"trades": trades, "books": snapshots, "batch_size": batch_size}
