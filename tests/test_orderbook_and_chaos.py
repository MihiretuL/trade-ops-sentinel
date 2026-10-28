from __future__ import annotations

import asyncio
from decimal import Decimal

import pytest
from fastapi.testclient import TestClient

from backend import db
from backend.ai_investigator import AgentToolkit
from backend.fix_protocol import FIX_TAGS, parse_fix_message
from backend.main import app
from backend.order_book import LimitOrderBook


@pytest.fixture
def isolated(tmp_path, monkeypatch):
    path = str(tmp_path / "chaos-test.sqlite3")
    monkeypatch.setenv("SQLITE_DB_PATH", path)
    monkeypatch.delenv("META_API_KEY", raising=False)
    monkeypatch.delenv("BASETEN_API_KEY", raising=False)
    monkeypatch.delenv("FIREWORKS_API_KEY", raising=False)
    return path


def test_seeded_orderbook_has_five_decimal_levels_each_side_for_all_symbols():
    book = LimitOrderBook()
    assert {item["symbol"] for item in book.get_all_snapshots()} == {"AAPL", "NVDA", "MSFT", "SPY", "TSLA", "ESZ6"}
    for snapshot in book.get_all_snapshots():
        assert len(snapshot["bids"]) == 5
        assert len(snapshot["asks"]) == 5
        assert Decimal(snapshot["best_bid"]) < Decimal(snapshot["best_ask"])
        assert Decimal(snapshot["spread"]) > 0


def test_matching_emits_valid_fix42_new_ack_partial_and_full_reports_with_decimal_avgpx():
    book = LimitOrderBook()
    result = book.match_new_order("AAPL", "BUY", 800, "225.52")
    assert result.status == "2"
    assert result.cum_qty == Decimal("800")
    assert result.leaves_qty == 0
    expected_notional = Decimal("500") * Decimal("225.51") + Decimal("300") * Decimal("225.52")
    assert result.average_price == expected_notional / Decimal("800")
    messages = [parse_fix_message(frame.raw_fix) for frame in result.frames]
    assert all(message.begin_string == "FIX.4.2" for message in messages)
    assert [message.msg_type for message in messages] == ["D", "8", "8", "8"]
    assert messages[1].get(39) == "0" and messages[1].get(150) == "0"
    assert messages[2].get(39) == "1" and messages[2].get(150) == "1"
    assert messages[3].get(39) == "2" and messages[3].get(150) == "2"
    assert Decimal(messages[-1].get(6)) == result.average_price
    assert Decimal(messages[-1].get(14)) == Decimal("800")
    assert Decimal(messages[-1].get(151)) == Decimal("0")
    assert result.notional == expected_notional


def test_partial_fill_leaves_remainder_resting_and_snapshot_updates():
    book = LimitOrderBook()
    result = book.match_new_order("NVDA", "BUY", 700, "138.45")
    assert result.cum_qty == Decimal("500")
    assert result.leaves_qty == Decimal("200")
    assert result.status == "1"
    snapshot = book.get_book_snapshot("NVDA")
    assert snapshot["last_trade_price"] == "138.45"
    assert any(level["price"] == "138.45" and level["quantity"] == "200" for level in snapshot["bids"])


def test_price_time_priority_consumes_best_price_then_fifo_at_same_level():
    book = LimitOrderBook(initialize_liquidity=False)
    # Sell orders join at the mid; the first maker must be consumed first.
    first = book.match_new_order("AAPL", "SELL", 3, "225.50")
    second = book.match_new_order("AAPL", "SELL", 5, "225.50")
    assert first.leaves_qty == Decimal("3") and second.leaves_qty == Decimal("5")
    buy = book.match_new_order("AAPL", "BUY", 6, "225.50")
    assert buy.cum_qty == Decimal("6")
    assert [(fill["maker_cl_ord_id"], fill["quantity"]) for fill in buy.fills] == [
        (first.cl_ord_id, Decimal("3")), (second.cl_ord_id, Decimal("3"))
    ]
    assert book.get_order(first.cl_ord_id).leaves_qty == Decimal("0")
    assert book.get_order(second.cl_ord_id).leaves_qty == Decimal("2")


def test_risk_collar_reject_has_authentic_fix_fields_and_no_execution():
    book = LimitOrderBook()
    result = book.match_new_order("MSFT", "BUY", 10, "500.00")
    assert result.rejected
    assert result.status == "8" and result.exec_type == "8"
    assert result.cum_qty == 0
    report = parse_fix_message(result.frames[-1].raw_fix)
    assert report.msg_type == "8"
    assert report.get(39) == "8" and report.get(150) == "8" and report.get(103) == "3"
    assert all(parse_fix_message(frame.raw_fix).is_structurally_valid for frame in result.frames)


def test_cancel_resting_order_and_cancel_after_fill_race():
    book = LimitOrderBook(initialize_liquidity=False)
    resting = book.match_new_order("SPY", "BUY", 100, "580.00")
    assert resting.leaves_qty == 100
    canceled = book.cancel_order(resting.cl_ord_id)
    canceled_report = parse_fix_message(canceled.frames[-1].raw_fix)
    assert canceled_report.get(39) == "4" and canceled_report.get(150) == "4"
    assert not any(level["price"] == "580.00" for level in book.get_book_snapshot("SPY")["bids"])

    book.match_new_order("SPY", "SELL", 10, "580.10")
    filled = book.match_new_order("SPY", "BUY", 10, "580.11")
    assert filled.leaves_qty == 0
    too_late = book.cancel_order(filled.cl_ord_id)
    reject = parse_fix_message(too_late.frames[-1].raw_fix)
    assert reject.msg_type == "9"
    assert reject.get(102) == "0" and reject.get(58) == "TooLateToCancel"
    assert parse_fix_message(too_late.frames[-1].raw_fix).is_structurally_valid


def test_replace_loses_priority_and_generates_new_order_chain():
    book = LimitOrderBook(initialize_liquidity=False)
    original = book.match_new_order("TSLA", "SELL", 20, "245.00")
    replaced = book.replace_order(original.cl_ord_id, new_quantity=30, new_limit_price="245.00")
    assert replaced.cl_ord_id != original.cl_ord_id
    request = parse_fix_message(replaced.frames[0].raw_fix)
    assert request.msg_type == "G"
    assert request.get(41) == original.cl_ord_id
    assert request.get(11) == replaced.cl_ord_id


def test_fix_tag_dictionary_includes_avgpx_and_requested_institutional_tags():
    assert FIX_TAGS[6] == "AvgPx"
    for tag, name in {
        12: "Commission", 13: "CommType", 15: "Currency", 18: "ExecInst", 20: "ExecTransType",
        21: "HandlInst", 30: "LastMkt", 43: "PossDupFlag", 47: "Rule80A", 50: "SenderSubID",
        57: "TargetSubID", 59: "TimeInForce", 63: "SettlmntTyp", 97: "PossResend",
        98: "EncryptMethod", 108: "HeartBtInt", 112: "TestReqID", 141: "ResetSeqNumFlag",
        167: "SecurityType", 207: "SecurityExchange",
    }.items():
        assert FIX_TAGS[tag] == name


def test_dynamic_chaos_sql_lock_is_new_incident_blindly_diagnosed_from_evidence(isolated):
    prompt = "Fill a large MSFT order, then drop the SQLite OMS commit to cause a phantom fill"
    with TestClient(app) as client:
        response = client.post("/api/chaos/inject-prompt", json={"prompt": prompt})
    assert response.status_code == 200, response.text
    result = response.json()
    assert result["incident_id"].startswith("DYN-")
    assert result["fault_spec"]["fault_type"] == "sql_lock"
    assert result["fault_spec"]["symbol"] == "MSFT"
    assert result["order_result"]["cl_ord_id"].startswith("ORD-")
    assert result["order_result"]["cum_qty"] != "0"
    assert result["report"]["primary_failure_category"] == "drop_copy_sql_reconciliation"
    assert result["report"]["reconciliation_breaks"]
    assert result["diagnosis"]["verification_passed"]
    assert any("oms_orders" in result["diagnosis"]["engineering_escalation_summary"] for _ in [0])
    assert "$" in result["diagnosis"]["trader_squawk_update"]
    assert "Category=" not in result["diagnosis"]["engineering_escalation_summary"]
    stored = db.get_incident_events(isolated, result["incident_id"])
    assert stored
    assert all("fault_type" not in event["metadata_json"] for event in stored)
    assert all(citation["event_id"] in {event["event_id"] for event in stored} for citation in result["diagnosis"]["proven_claims"])


def test_dynamic_chaos_sequence_gap_and_timeout_are_evidence_classified(isolated):
    with TestClient(app) as client:
        gap = client.post("/api/chaos/inject-prompt", json={"prompt": "Drop 3 outbound TCP packets on AAPL during an order burst"})
        timeout = client.post("/api/chaos/inject-prompt", json={"prompt": "Send a 1,000-share NVDA buy order and wait for a silent gateway timeout"})
    assert gap.status_code == 200, gap.text
    assert timeout.status_code == 200, timeout.text
    gap_result, timeout_result = gap.json(), timeout.json()
    assert gap_result["fault_spec"]["dropped_seq_count"] == 3
    assert gap_result["report"]["primary_failure_category"] == "sequence_gap_resend"
    assert timeout_result["report"]["primary_failure_category"] == "in_flight_unknown"
    assert timeout_result["report"]["safe_to_resend"] is False
    assert timeout_result["diagnosis"]["safe_to_resend"] is False
    assert timeout_result["report"]["unknowns"]


def test_live_market_tick_and_orderbook_api_publish_matched_flow(isolated):
    with TestClient(app) as client:
        before = client.get("/api/orderbook")
        tick = client.post("/api/market/tick", json={"batch_size": 3})
        after = client.get("/api/orderbook")
    assert before.status_code == after.status_code == tick.status_code == 200
    assert len(before.json()["symbols"]) == 6
    assert len(tick.json()["trades"]) == 3
    assert all(trade["cl_ord_id"].startswith("ORD-") for trade in tick.json()["trades"])
    assert any(book["last_trade_price"] is not None for book in after.json()["symbols"])
    for trade in tick.json()["trades"]:
        assert db.get_deterministic_report(isolated, trade["incident_id"]) is not None


def test_dynamic_event_citations_are_distinct_and_event_specific(isolated):
    with TestClient(app) as client:
        response = client.post("/api/chaos/inject-prompt", json={"prompt": "Run a 50-share NVDA buy through the book"})
    assert response.status_code == 200, response.text
    diagnosis = response.json()["diagnosis"]
    claims = diagnosis["proven_claims"]
    assert len(claims) == len({claim["event_id"] for claim in claims})
    assert len(claims) == len({claim["claim"] for claim in claims})
    assert any("NewOrderSingle (35=D)" in claim["claim"] for claim in claims)
    assert any("ExecutionReport (35=8" in claim["claim"] for claim in claims)
