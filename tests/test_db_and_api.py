from __future__ import annotations

import asyncio
import json
import sqlite3
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from backend import db
from backend.main import app
from backend.models import Direction
from backend.simulator import all_incidents, get_incident
from backend.tcp_harness import LocalFIXExchangeHarness


@pytest.fixture
def database_path(tmp_path, monkeypatch):
    path = tmp_path / "tradeops-test.sqlite3"
    monkeypatch.setenv("SQLITE_DB_PATH", str(path))
    monkeypatch.setenv("TCP_HARNESS_HOST", "127.0.0.1")
    monkeypatch.setenv("TCP_HARNESS_PORT", "0")
    db.init_db(str(path))
    return str(path)


def test_schema_creation_and_exact_decimal_round_trip(database_path):
    connection = sqlite3.connect(database_path)
    tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    assert {"incidents", "telemetry_events", "oms_orders", "drop_copy_executions", "investigation_reports"} <= tables
    connection.execute(
        "INSERT INTO incidents VALUES(?,?,?,?,?)",
        ("DECIMAL", "exact", "test", "2026-10-27T00:00:00+00:00", "test"),
    )
    exact = "12345678901234567890.12345678901234567890"
    connection.execute(
        "INSERT INTO oms_orders VALUES(?,?,?,?,?,?,?,?,?,?)",
        ("O-1", "DECIMAL", "MSFT", "1", "1", exact, "filled", "0.00000000000000000001", exact, "now"),
    )
    connection.commit()
    stored = connection.execute("SELECT price,filled_qty,avg_px FROM oms_orders WHERE cl_ord_id=?", ("O-1",)).fetchone()
    connection.close()
    assert tuple(Decimal(value) for value in stored) == (
        Decimal(exact), Decimal("0.00000000000000000001"), Decimal(exact)
    )


def test_seed_all_incidents_persists_events_orders_execs_and_reports(database_path):
    reports = db.seed_all_incidents(database_path)
    assert len(reports) == 5
    assert {item["incident_id"] for item in db.list_incidents(database_path)} == {
        f"INC-{number}" for number in range(101, 106)
    }
    for incident in all_incidents():
        events = db.get_incident_events(database_path, incident.incident_id)
        orders = db.get_oms_orders(database_path, incident.incident_id)
        report = db.get_deterministic_report(database_path, incident.incident_id)
        assert len(events) == len(incident.events)
        assert orders
        assert report is not None
        assert report.event_ids
    with sqlite3.connect(database_path) as connection:
        count = connection.execute("SELECT COUNT(*) FROM drop_copy_executions").fetchone()[0]
    assert count == 2  # INC-102 and INC-105 each have a canonical fill.


def test_seed_idempotency_does_not_duplicate_rows(database_path):
    db.seed_all_incidents(database_path)
    db.seed_all_incidents(database_path)
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("SELECT COUNT(*) FROM incidents").fetchone()[0] == 5
        assert connection.execute("SELECT COUNT(*) FROM telemetry_events").fetchone()[0] == sum(
            len(incident.events) for incident in all_incidents()
        )
        assert connection.execute("SELECT COUNT(*) FROM drop_copy_executions").fetchone()[0] == 2


def test_incident_105_sql_join_reports_exact_msft_stp_break(database_path):
    db.seed_all_incidents(database_path)
    breaks = db.run_sql_reconciliation(database_path, "INC-105")
    assert len(breaks) == 1
    item = breaks[0]
    assert item.cl_ord_id == "ORD-5510"
    assert item.symbol == "MSFT"
    assert item.drop_copy_filled_qty == Decimal("500")
    assert item.oms_filled_qty == Decimal("0")
    assert item.drop_copy_notional == Decimal("207600.00")
    assert item.exec_ids == ("EXEC-5510",)


@pytest.mark.parametrize("incident_id", [f"INC-{number}" for number in range(101, 105)])
def test_canonical_incidents_101_to_104_have_no_sql_false_positive(database_path, incident_id):
    db.seed_all_incidents(database_path)
    assert db.run_sql_reconciliation(database_path, incident_id) == []


def test_sql_reconciliation_uses_parameterized_incident_id(database_path):
    db.seed_all_incidents(database_path)
    assert db.run_sql_reconciliation(database_path, "INC-105' OR 1=1 --") == []


def test_run_sql_reconciliation_reads_persisted_join_rows(database_path):
    db.seed_all_incidents(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "UPDATE oms_orders SET filled_qty=?,oms_status=? WHERE incident_id=? AND cl_ord_id=?",
            ("499", "PartiallyFilled", "INC-102", "ORD-8821"),
        )
    breaks = db.run_sql_reconciliation(database_path, "INC-102")
    assert len(breaks) == 1
    assert breaks[0].drop_copy_filled_qty == Decimal("500")
    assert breaks[0].oms_filled_qty == Decimal("499")


@pytest.mark.parametrize("incident_id", [f"INC-{number}" for number in range(101, 106)])
def test_tcp_harness_transfers_valid_soh_fix_over_ephemeral_loopback(database_path, incident_id):
    result = asyncio.run(LocalFIXExchangeHarness(database_path, host="127.0.0.1", port=0).run(incident_id))
    assert result.host == "127.0.0.1"
    assert result.port > 0
    assert result.transmitted_frames + result.received_frames == sum(
        1 for event in get_incident(incident_id).events if hasattr(event, "wire")
    )
    assert result.socket_metadata["digital_twin"] is True
    assert result.socket_metadata["external_exchange_connection"] is False
    assert result.socket_metadata["wire_encoding"] == "ASCII"
    fix_events = [event for event in result.captured_events if hasattr(event, "wire")]
    assert fix_events
    assert all("\x01" in event.wire for event in fix_events)
    assert all(event.wire.startswith("8=FIX.4.2\x01") for event in fix_events)
    assert all(event.event_id.startswith("tcp:") for event in fix_events)
    assert result.report.incident_id == incident_id
    assert result.report.source == "deterministic_local_engine"
    assert db.get_deterministic_report(database_path, incident_id) == result.report


def test_tcp_harness_refuses_non_loopback_bind(database_path):
    with pytest.raises(ValueError, match="loopback"):
        LocalFIXExchangeHarness(database_path, host="0.0.0.0", port=0)


def test_api_health_seed_list_detail_and_not_found(database_path, monkeypatch):
    with TestClient(app) as client:
        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"
        assert health.json()["db_path"] == database_path
        seeded = client.post("/api/incidents/seed")
        assert seeded.status_code == 200
        assert seeded.json()["seeded"] == 5
        listing = client.get("/api/incidents")
        assert listing.status_code == 200 and len(listing.json()) == 5
        assert all("primary_failure_category" in row for row in listing.json())
        detail = client.get("/api/incidents/INC-105")
        assert detail.status_code == 200
        assert detail.json()["report"]["incident_id"] == "INC-105"
        assert len(detail.json()["sql_recon_breaks"]) == 1
        assert detail.json()["sql_recon_breaks"][0]["drop_copy_notional"] == "207600.00"
        missing = client.get("/api/incidents/INC-MISSING")
        assert missing.status_code == 404


def test_api_simulate_tcp_persists_and_returns_updated_report(database_path):
    with TestClient(app) as client:
        client.post("/api/incidents/seed")
        response = client.post("/api/incidents/INC-102/simulate-tcp")
        assert response.status_code == 200, response.text
        payload = response.json()
        assert payload["report"]["incident_id"] == "INC-102"
        assert payload["socket_metadata"]["digital_twin"] is True
        events = client.get("/api/incidents/INC-102").json()["telemetry_events"]
        assert any(row["event_id"].startswith("tcp:") for row in events)


def test_api_raw_fix_ingest_pipe_and_oms_snapshot(database_path):
    from backend.fix_protocol import build_fix_message

    pipe_wire = build_fix_message(
        [(35, "D"), (34, "1"), (49, "DESK"), (56, "EX"), (11, "CUSTOM-1"), (55, "MSFT"), (54, "1"), (38, "3"), (40, "2"), (44, "10.25")],
        delimiter="|",
    )
    request = {
        "incident_id": "CUSTOM-RAW-1",
        "raw_fix_lines": [pipe_wire],
        "direction": "outbound",
        "oms_snapshot": [{"cl_ord_id": "CUSTOM-1", "oms_status": "PendingNew", "filled_qty": "0.000"}],
    }
    with TestClient(app) as client:
        response = client.post("/api/ingest/raw-fix", json=request)
        assert response.status_code == 200, response.text
        report = response.json()["report"]
        assert report["incident_id"] == "CUSTOM-RAW-1"
        assert report["is_in_flight_unknown"] is True
        detail = client.get("/api/incidents/CUSTOM-RAW-1")
        assert detail.status_code == 200
        assert detail.json()["telemetry_events"][0]["raw_payload"] == pipe_wire


def test_api_raw_fix_ingest_rejects_bad_wire_and_direction_count(database_path):
    with TestClient(app) as client:
        invalid = client.post("/api/ingest/raw-fix", json={"raw_fix_lines": ["not FIX"]})
        assert invalid.status_code == 422
        from backend.fix_protocol import build_fix_message

        wire = build_fix_message([(35, "0"), (34, "1")])
        mismatch = client.post("/api/ingest/raw-fix", json={"raw_fix_lines": [wire], "directions": []})
        assert mismatch.status_code == 422


def test_websocket_broadcasts_tcp_events_and_reconstruction(database_path):
    with TestClient(app) as client:
        client.post("/api/incidents/seed")
        with client.websocket_connect("/ws/stream") as websocket:
            response = client.post("/api/incidents/INC-101/simulate-tcp")
            assert response.status_code == 200
            first = websocket.receive_json()
            assert first["type"] == "telemetry_event"
            assert first["incident_id"] == "INC-101"
            assert first["event"]["event_id"].startswith("tcp:")
            messages = [first]
            while len(messages) < response.json()["captured_events"] + 1:
                messages.append(websocket.receive_json())
            assert any(item["type"] == "investigation_update" for item in messages)
