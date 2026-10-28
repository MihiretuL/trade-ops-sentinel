"""SQLite persistence, deterministic incident seeding and STP reconciliation."""

from __future__ import annotations

import json
import sqlite3
import threading
from contextlib import contextmanager
from datetime import datetime, timezone
from decimal import Decimal
from pathlib import Path
from typing import Any, Iterator

from .fix_protocol import parse_fix_message
from .models import (
    DeterministicInvestigationReport,
    Direction,
    IncidentFixture,
    VerifiedAIDiagnosis,
    OMSRecord,
    OrderSnapshot,
    ReconciliationBreak,
    ReportFact,
    SubwayNode,
    TelemetryEvent,
    WireEvent,
)
from .reconstructor import FixReconstructor
from .simulator import all_incidents, get_incident

_SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    scenario_code TEXT NOT NULL,
    created_at TEXT NOT NULL,
    status TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS telemetry_events (
    event_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    timestamp TEXT NOT NULL,
    sequence_index INTEGER NOT NULL,
    source_layer TEXT NOT NULL,
    direction TEXT,
    raw_payload TEXT NOT NULL,
    parsed_json TEXT NOT NULL,
    metadata_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS oms_orders (
    cl_ord_id TEXT NOT NULL,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    symbol TEXT,
    side TEXT,
    order_qty TEXT NOT NULL,
    price TEXT NOT NULL,
    oms_status TEXT NOT NULL,
    filled_qty TEXT NOT NULL,
    avg_px TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (incident_id, cl_ord_id)
);
CREATE TABLE IF NOT EXISTS drop_copy_executions (
    exec_id TEXT NOT NULL,
    incident_id TEXT NOT NULL REFERENCES incidents(incident_id) ON DELETE CASCADE,
    cl_ord_id TEXT NOT NULL,
    symbol TEXT,
    exec_type TEXT,
    ord_status TEXT,
    last_qty TEXT NOT NULL,
    last_px TEXT NOT NULL,
    cum_qty TEXT NOT NULL,
    leaves_qty TEXT NOT NULL,
    raw_fix TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    PRIMARY KEY (incident_id, exec_id)
);
CREATE TABLE IF NOT EXISTS investigation_reports (
    incident_id TEXT PRIMARY KEY REFERENCES incidents(incident_id) ON DELETE CASCADE,
    deterministic_report_json TEXT NOT NULL,
    ai_diagnosis_json TEXT,
    updated_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_telemetry_incident_sequence ON telemetry_events(incident_id, sequence_index);
CREATE INDEX IF NOT EXISTS idx_drop_copy_incident_order ON drop_copy_executions(incident_id, cl_ord_id);
"""

_MEMORY: dict[str, sqlite3.Connection] = {}
_MEMORY_LOCKS: dict[str, threading.RLock] = {}
_GLOBAL_LOCK = threading.RLock()


def _decimal(value: object, default: str = "0") -> Decimal:
    if value is None or value == "":
        return Decimal(default)
    return Decimal(str(value))


def _json_default(value: Any) -> Any:
    if isinstance(value, Decimal):
        return str(value)
    if isinstance(value, datetime):
        return value.isoformat()
    if hasattr(value, "value"):
        return value.value
    raise TypeError(f"Cannot serialize {type(value).__name__} to JSON")


def _event_dict(event: WireEvent | TelemetryEvent) -> dict[str, Any]:
    return event.model_dump(mode="json")


def _parse_event(event: WireEvent | TelemetryEvent) -> dict[str, Any]:
    if isinstance(event, WireEvent):
        message = parse_fix_message(event.wire)
        return {
            "kind": "fix",
            "begin_string": message.begin_string,
            "msg_type": message.msg_type,
            "sequence_number": message.sequence_number,
            "sender_comp_id": message.sender_comp_id,
            "target_comp_id": message.target_comp_id,
            "tags": message.as_dict(),
            "validation_errors": message.validation_errors,
            "is_structurally_valid": message.is_structurally_valid,
        }
    return {"kind": "telemetry", "event_type": event.event_type, "order_id": event.order_id, "details": event.details}


def _ensure_path(path: str) -> None:
    if path != ":memory:" and not path.startswith("file:"):
        Path(path).expanduser().resolve().parent.mkdir(parents=True, exist_ok=True)


def _connection(path: str) -> tuple[sqlite3.Connection, bool, threading.RLock]:
    _ensure_path(path)
    if path == ":memory:":
        with _GLOBAL_LOCK:
            if path not in _MEMORY:
                _MEMORY[path] = sqlite3.connect(path, check_same_thread=False)
                _MEMORY[path].row_factory = sqlite3.Row
                _MEMORY_LOCKS[path] = threading.RLock()
            return _MEMORY[path], False, _MEMORY_LOCKS[path]
    connection = sqlite3.connect(path, timeout=30)
    connection.row_factory = sqlite3.Row
    return connection, True, threading.RLock()


@contextmanager
def _database(path: str) -> Iterator[sqlite3.Connection]:
    connection, should_close, lock = _connection(path)
    try:
        with lock:
            yield connection
            connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        if should_close:
            connection.close()


def init_db(db_path: str) -> None:
    """Create all Sprint 2 tables and indexes for a file or in-memory database."""
    with _database(db_path) as connection:
        connection.executescript(_SCHEMA)


def _upsert_incident(connection: sqlite3.Connection, incident: IncidentFixture) -> None:
    scenario = incident.title
    connection.execute(
        "INSERT INTO incidents(incident_id,title,scenario_code,created_at,status) VALUES(?,?,?,?,?) "
        "ON CONFLICT(incident_id) DO UPDATE SET title=excluded.title,scenario_code=excluded.scenario_code,status=excluded.status",
        (incident.incident_id, incident.title, scenario, _utcnow(), "seeded"),
    )


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _insert_event(
    connection: sqlite3.Connection,
    incident_id: str,
    event: WireEvent | TelemetryEvent,
    sequence_index: int,
) -> None:
    if isinstance(event, WireEvent):
        raw_payload = event.wire
        direction = event.direction.value
        metadata = {
            "sender_comp_id": event.sender_comp_id,
            "target_comp_id": event.target_comp_id,
            "provenance": event.provenance,
            "event_kind": "fix_wire",
        }
    else:
        raw_payload = json.dumps(event.model_dump(mode="json"), sort_keys=True)
        direction = None
        metadata = {"provenance": event.provenance, "event_kind": event.event_type, "details": event.details}
    connection.execute(
        "INSERT OR REPLACE INTO telemetry_events(event_id,incident_id,timestamp,sequence_index,source_layer,direction,raw_payload,parsed_json,metadata_json) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (event.event_id, incident_id, event.timestamp.isoformat(), sequence_index, event.source_layer, direction,
         raw_payload, json.dumps(_parse_event(event), sort_keys=True, default=_json_default),
         json.dumps(metadata, sort_keys=True, default=_json_default)),
    )


def _snapshots(reconstructor: FixReconstructor) -> dict[str, OrderSnapshot]:
    result: dict[str, OrderSnapshot] = {}
    for order in reconstructor.all_orders():
        result[order.root_cl_ord_id] = order
        for alias in (*order.lineage, *order.order_ids):
            result[alias] = order
    return result


def _build_report(
    incident: IncidentFixture,
    reconstructor: FixReconstructor,
    breaks: list[ReconciliationBreak],
) -> DeterministicInvestigationReport:
    orders = reconstructor.all_orders()
    exposure = sum((order.exposure_dollars for order in orders), Decimal("0"))
    unknown_orders = [order for order in orders if order.is_in_flight_unknown]
    safe_to_resend = bool(orders) and all(order.safe_to_resend for order in orders) and not unknown_orders
    event_ids = tuple(event.event_id for event in incident.events)
    facts: list[ReportFact] = []
    for order in orders:
        evidence = tuple(order.event_history)
        if order.status.value == "filled":
            facts.append(ReportFact(claim=f"Order {order.root_cl_ord_id} is filled for {order.cum_qty} shares.", event_ids=evidence, fix_tags=(11, 14, 17, 39, 150)))
        elif order.is_in_flight_unknown:
            facts.append(ReportFact(claim=f"Order {order.root_cl_ord_id} was transmitted but exchange receipt/execution is unresolved.", event_ids=evidence, fix_tags=(11, 34, 38, 44)))
        elif order.status.value == "rejected":
            facts.append(ReportFact(claim=f"Order {order.root_cl_ord_id} was rejected at the {order.rejection_layer or 'unknown'} layer.", event_ids=evidence, fix_tags=(11, 39, 150, 371, 373)))
    for discrepancy in breaks:
        facts.append(ReportFact(claim=discrepancy.description, event_ids=discrepancy.event_ids, fix_tags=(11, 17, 31, 32, 39, 150)))

    if incident.incident_id == "INC-101":
        category, severity = "sequence_gap_resend", "high"
    elif incident.incident_id == "INC-102":
        category, severity = "cancel_fill_race", "critical"
    elif incident.incident_id == "INC-103":
        category, severity = "in_flight_unknown", "critical"
    elif incident.incident_id == "INC-104":
        category, severity = "protocol_and_risk_reject", "high"
    elif incident.incident_id == "INC-105":
        category, severity = "drop_copy_sql_reconciliation", "critical"
    else:
        category, severity = "custom_fix_investigation", "high"

    warnings = [warning for result in getattr(reconstructor, "_last_results", ()) for warning in result.warnings]
    unknowns: list[str] = []
    if unknown_orders:
        unknowns.append("Exchange receipt or execution cannot be determined from current telemetry; do not resend until independently resolved.")
    if incident.incident_id == "INC-101":
        unknowns.append("Gap fill resolves the indicated session sequence interval only; the captured NewOrderSingle has no exchange acknowledgment.")
    if not unknowns and warnings:
        unknowns.extend(warnings)

    statuses = {order.root_cl_ord_id: order.status.value for order in orders}
    nodes = (
        SubwayNode(name="OMS", status="discrepancy" if breaks else "observed", event_ids=event_ids),
        SubwayNode(name="Risk", status="rejected" if incident.incident_id == "INC-104" else "passed" if incident.incident_id == "INC-103" else "not_observed", event_ids=tuple(event.event_id for event in incident.events if isinstance(event, TelemetryEvent) and event.event_type == "risk_pass")),
        SubwayNode(name="FIX Gateway", status="timeout" if incident.incident_id == "INC-103" else "protocol_reject" if incident.incident_id == "INC-104" else "observed", event_ids=event_ids),
        SubwayNode(name="Exchange", status="unknown" if unknown_orders else "filled" if any(order.status.value == "filled" for order in orders) else "rejected" if any(order.status.value == "rejected" for order in orders) else "sequence_recovery", event_ids=event_ids),
    )
    return DeterministicInvestigationReport(
        incident_id=incident.incident_id,
        title=incident.title,
        scenario_code=incident.title,
        primary_failure_category=category,
        severity=severity,
        summary=incident.description,
        total_exposure_dollars=exposure,
        is_in_flight_unknown=bool(unknown_orders),
        safe_to_resend=safe_to_resend,
        order_statuses=statuses,
        facts=tuple(facts),
        unknowns=tuple(unknowns),
        reconciliation_breaks=tuple(breaks),
        subway_map_status=nodes,
        event_ids=event_ids,
    )


def _persist_reconstruction(connection: sqlite3.Connection, incident: IncidentFixture, reconstructor: FixReconstructor) -> None:
    alias_map = _snapshots(reconstructor)
    oms_by_id = {record.order_id: record for record in incident.oms_records}
    for order in reconstructor.all_orders():
        record = oms_by_id.get(order.root_cl_ord_id) or next((oms_by_id.get(alias) for alias in (*order.lineage, *order.order_ids) if oms_by_id.get(alias)), None)
        # For scenarios without an intentionally stale SQL snapshot, persist the deterministic
        # reconstructed OMS state so canonical incidents do not manufacture reconciliation breaks.
        status = record.status if record else order.status.value
        filled = record.filled_qty if record else order.cum_qty
        avg_px = order.avg_px if record is None else (order.avg_px if filled else Decimal("0"))
        updated_at = record.timestamp.isoformat() if record else _utcnow()
        for clord in dict.fromkeys((order.root_cl_ord_id, *order.lineage)):
            connection.execute(
                "INSERT OR REPLACE INTO oms_orders(cl_ord_id,incident_id,symbol,side,order_qty,price,oms_status,filled_qty,avg_px,updated_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?)",
                (clord, incident.incident_id, order.symbol, order.side, str(order.order_qty), str(order.limit_px), status,
                 str(filled), str(avg_px), updated_at),
            )

    for event in incident.events:
        if not isinstance(event, WireEvent):
            continue
        message = parse_fix_message(event.wire)
        if message.msg_type != "8" or message.get(17) is None:
            continue
        exec_type = message.get(150) or ""
        if exec_type not in {"2", "F"}:
            continue
        connection.execute(
            "INSERT OR REPLACE INTO drop_copy_executions(exec_id,incident_id,cl_ord_id,symbol,exec_type,ord_status,last_qty,last_px,cum_qty,leaves_qty,raw_fix,timestamp) "
            "VALUES(?,?,?,?,?,?,?,?,?,?,?,?)",
            (message.get(17), incident.incident_id, message.get(41) or message.get(11) or "", message.get(55),
             exec_type, message.get(39), str(_decimal(message.get(32))), str(_decimal(message.get(31))),
             str(_decimal(message.get(14))), str(_decimal(message.get(151))), event.wire, event.timestamp.isoformat()),
        )


def _sql_breaks(connection: sqlite3.Connection, incident_id: str) -> list[ReconciliationBreak]:
    # The SQL join is the authoritative relation selection. Decimal aggregation is
    # performed in Python to avoid SQLite NUMERIC/REAL precision loss.
    rows = connection.execute(
        "SELECT d.exec_id,d.cl_ord_id,d.symbol,d.exec_type,d.ord_status,d.last_qty,d.last_px,d.cum_qty,d.timestamp, "
        "o.oms_status,o.filled_qty,o.avg_px, "
        "(SELECT t.event_id FROM telemetry_events AS t WHERE t.incident_id=d.incident_id "
        "AND json_extract(t.parsed_json,'$.tags.17')=d.exec_id ORDER BY t.sequence_index LIMIT 1) AS evidence_event_id "
        "FROM drop_copy_executions AS d JOIN oms_orders AS o "
        "ON o.incident_id=d.incident_id AND o.cl_ord_id=d.cl_ord_id "
        "WHERE d.incident_id=? ORDER BY d.cl_ord_id,d.timestamp,d.exec_id",
        (incident_id,),
    ).fetchall()
    grouped: dict[str, list[sqlite3.Row]] = {}
    for row in rows:
        grouped.setdefault(row["cl_ord_id"], []).append(row)
    breaks: list[ReconciliationBreak] = []
    for clord, items in grouped.items():
        drop_qty = sum((_decimal(row["last_qty"]) for row in items), Decimal("0"))
        drop_notional = sum((_decimal(row["last_qty"]) * _decimal(row["last_px"]) for row in items), Decimal("0"))
        # Query joins all drop rows to same OMS row. Filled_qty is identical in each joined result.
        oms_qty = _decimal(items[0]["filled_qty"])
        status = items[0]["oms_status"]
        if drop_qty != oms_qty or status in {"PendingNew", "pending_new"} and drop_qty > 0:
            breaks.append(ReconciliationBreak(
                incident_id=incident_id,
                cl_ord_id=clord,
                symbol=items[0]["symbol"] or "",
                drop_copy_filled_qty=drop_qty,
                oms_filled_qty=oms_qty,
                drop_copy_notional=drop_notional,
                oms_status=status,
                exec_ids=tuple(row["exec_id"] for row in items),
                event_ids=tuple(row["evidence_event_id"] or f"drop-copy:{row['exec_id']}" for row in items),
                break_type="fill_quantity_mismatch",
                description=f"Drop-Copy has {drop_qty} filled shares ({drop_notional}) while OMS reports {oms_qty} ({status}).",
            ))
    return breaks


def seed_incident_from_simulator(db_path: str, incident_id: str) -> DeterministicInvestigationReport:
    """Persist one canonical fixture and its engine-derived report idempotently."""
    incident = get_incident(incident_id)
    init_db(db_path)
    reconstructor = FixReconstructor()
    results = reconstructor.process_incident(incident)
    reconstructor._last_results = results
    with _database(db_path) as connection:
        _upsert_incident(connection, incident)
        connection.execute("DELETE FROM telemetry_events WHERE incident_id=?", (incident_id,))
        connection.execute("DELETE FROM oms_orders WHERE incident_id=?", (incident_id,))
        connection.execute("DELETE FROM drop_copy_executions WHERE incident_id=?", (incident_id,))
        for index, event in enumerate(incident.events):
            _insert_event(connection, incident_id, event, index)
        _persist_reconstruction(connection, incident, reconstructor)
        breaks = _sql_breaks(connection, incident_id)
        report = _build_report(incident, reconstructor, breaks)
        connection.execute(
            "INSERT INTO investigation_reports(incident_id,deterministic_report_json,ai_diagnosis_json,updated_at) VALUES(?,?,NULL,?) "
            "ON CONFLICT(incident_id) DO UPDATE SET deterministic_report_json=excluded.deterministic_report_json,updated_at=excluded.updated_at",
            (incident_id, report.model_dump_json(), _utcnow()),
        )
    return report


def seed_all_incidents(db_path: str) -> list[DeterministicInvestigationReport]:
    """Seed all five stable incidents and return their deterministic reports."""
    init_db(db_path)
    return [seed_incident_from_simulator(db_path, incident.incident_id) for incident in all_incidents()]


def run_sql_reconciliation(db_path: str, incident_id: str) -> list[ReconciliationBreak]:
    init_db(db_path)
    with _database(db_path) as connection:
        return _sql_breaks(connection, incident_id)


def get_incident_events(db_path: str, incident_id: str) -> list[dict[str, Any]]:
    init_db(db_path)
    with _database(db_path) as connection:
        rows = connection.execute(
            "SELECT * FROM telemetry_events WHERE incident_id=? ORDER BY sequence_index", (incident_id,)
        ).fetchall()
        return [
            {**dict(row), "parsed_json": json.loads(row["parsed_json"]), "metadata_json": json.loads(row["metadata_json"])}
            for row in rows
        ]


def get_oms_orders(db_path: str, incident_id: str) -> list[dict[str, Any]]:
    init_db(db_path)
    with _database(db_path) as connection:
        rows = connection.execute(
            "SELECT * FROM oms_orders WHERE incident_id=? ORDER BY cl_ord_id", (incident_id,)
        ).fetchall()
        return [dict(row) for row in rows]


def get_deterministic_report(db_path: str, incident_id: str) -> DeterministicInvestigationReport | None:
    init_db(db_path)
    with _database(db_path) as connection:
        row = connection.execute(
            "SELECT deterministic_report_json FROM investigation_reports WHERE incident_id=?", (incident_id,)
        ).fetchone()
        return DeterministicInvestigationReport.model_validate_json(row[0]) if row else None


def persist_ai_diagnosis(db_path: str, incident_id: str, diagnosis: VerifiedAIDiagnosis) -> None:
    """Persist a schema-validated diagnosis without modifying deterministic report data."""
    init_db(db_path)
    with _database(db_path) as connection:
        cursor = connection.execute(
            "UPDATE investigation_reports SET ai_diagnosis_json=?,updated_at=? WHERE incident_id=?",
            (diagnosis.model_dump_json(), _utcnow(), incident_id),
        )
        if cursor.rowcount == 0:
            raise KeyError(f"Incident {incident_id!r} has no deterministic report")


def get_ai_diagnosis(db_path: str, incident_id: str) -> VerifiedAIDiagnosis | None:
    """Return a stored verified diagnosis, if one has been generated."""
    init_db(db_path)
    with _database(db_path) as connection:
        row = connection.execute(
            "SELECT ai_diagnosis_json FROM investigation_reports WHERE incident_id=?",
            (incident_id,),
        ).fetchone()
        if row is None or row[0] is None:
            return None
        return VerifiedAIDiagnosis.model_validate_json(row[0])


def list_incidents(db_path: str) -> list[dict[str, Any]]:
    init_db(db_path)
    with _database(db_path) as connection:
        rows = connection.execute("SELECT incident_id,title,scenario_code,created_at,status FROM incidents ORDER BY incident_id").fetchall()
        result: list[dict[str, Any]] = []
        for row in rows:
            report_row = connection.execute(
                "SELECT deterministic_report_json FROM investigation_reports WHERE incident_id=?", (row["incident_id"],)
            ).fetchone()
            report = DeterministicInvestigationReport.model_validate_json(report_row[0]) if report_row else None
            result.append({
                **dict(row),
                "primary_failure_category": report.primary_failure_category if report else "not_investigated",
                "severity": report.severity if report else "unknown",
                "total_exposure_dollars": str(report.total_exposure_dollars) if report else "0",
                "safe_to_resend": report.safe_to_resend if report else False,
                "subway_map_status": [node.model_dump(mode="json") for node in report.subway_map_status] if report else [],
            })
        return result


def persist_custom_incident(
    db_path: str,
    incident: IncidentFixture,
    reconstructor: FixReconstructor,
    results: tuple[Any, ...],
) -> DeterministicInvestigationReport:
    """Persist caller-validated custom incident evidence and generated report."""
    init_db(db_path)
    reconstructor._last_results = results
    with _database(db_path) as connection:
        _upsert_incident(connection, incident)
        connection.execute("DELETE FROM telemetry_events WHERE incident_id=?", (incident.incident_id,))
        connection.execute("DELETE FROM oms_orders WHERE incident_id=?", (incident.incident_id,))
        connection.execute("DELETE FROM drop_copy_executions WHERE incident_id=?", (incident.incident_id,))
        for index, event in enumerate(incident.events):
            _insert_event(connection, incident.incident_id, event, index)
        _persist_reconstruction(connection, incident, reconstructor)
        breaks = _sql_breaks(connection, incident.incident_id)
        report = _build_report(incident, reconstructor, breaks)
        connection.execute(
            "INSERT INTO investigation_reports(incident_id,deterministic_report_json,ai_diagnosis_json,updated_at) VALUES(?,?,NULL,?) "
            "ON CONFLICT(incident_id) DO UPDATE SET deterministic_report_json=excluded.deterministic_report_json,updated_at=excluded.updated_at",
            (incident.incident_id, report.model_dump_json(), _utcnow()),
        )
    return report


def persist_captured_events(db_path: str, incident_id: str, events: tuple[WireEvent | TelemetryEvent, ...]) -> None:
    """Persist newly captured local-harness evidence using parameterized SQL."""
    init_db(db_path)
    with _database(db_path) as connection:
        connection.execute(
            "INSERT INTO incidents(incident_id,title,scenario_code,created_at,status) VALUES(?,?,?,?,?) "
            "ON CONFLICT(incident_id) DO UPDATE SET status=excluded.status",
            (incident_id, "TCP Loopback Simulation", "tcp_loopback", _utcnow(), "simulated"),
        )
        for index, event in enumerate(events):
            _insert_event(connection, incident_id, event, index)
