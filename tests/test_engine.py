from decimal import Decimal

import pytest

from backend.fix_protocol import FixParseError, build_fix_message, parse_fix_message
from backend.models import Direction, TelemetryEvent
from backend.reconstructor import FixReconstructor
from backend.simulator import all_incidents, get_incident


def _wire_in_order(body: list[tuple[int, str]]) -> str:
    """Construct checksum-correct wire for negative tag-order/structure tests."""
    soh = b"\x01"
    body_bytes = b"".join(f"{tag}={value}".encode() + soh for tag, value in body)
    prefix = b"8=FIX.4.4" + soh + f"9={len(body_bytes)}".encode() + soh + body_bytes
    checksum = sum(prefix) % 256
    return (prefix + f"10={checksum:03d}".encode() + soh).decode()


def _run(incident_id: str) -> tuple[FixReconstructor, tuple]:
    reconstructor = FixReconstructor()
    results = reconstructor.process_incident(get_incident(incident_id))
    return reconstructor, results


def test_fix_round_trip_soh_pipe_and_preserve_original_fixture_text():
    pairs = [(34, "7"), (11, "ORDER-1"), (55, "AAPL"), (35, "D"), (38, "12")]
    for delimiter in ("\x01", "|"):
        wire = build_fix_message(pairs, delimiter=delimiter)
        parsed = parse_fix_message(wire)
        assert parsed.begin_string == "FIX.4.4"
        assert parsed.msg_type == "D"
        assert parsed.get(11) == "ORDER-1"
        assert parsed.sequence_number == 7
        assert parsed.delimiter == delimiter
        assert parsed.raw_wire == wire
        assert parsed.is_structurally_valid
        assert parsed.validation_errors == []
        assert wire.split(delimiter)[:4] == ["8=FIX.4.4", wire.split(delimiter)[1], "35=D", "34=7"]


def test_fix_42_body_length_and_checksum_use_encoded_bytes():
    wire = build_fix_message([(35, "0"), (34, "1"), (58, "café")], begin_string="FIX.4.2")
    parsed = parse_fix_message(wire.encode("utf-8"))
    parts = wire.encode("utf-8").split(b"\x01")
    assert parsed.begin_string == "FIX.4.2"
    assert parsed.get(58) == "café"
    assert int(parts[1].split(b"=", 1)[1]) == len(b"\x01".join(parts[2:-2]) + b"\x01")
    checksum_start = wire.encode().rfind(b"10=")
    assert int(parts[-2].split(b"=", 1)[1]) == sum(wire.encode()[:checksum_start]) % 256


def test_pipe_fixture_checksum_uses_normalized_soh_and_keeps_raw():
    wire = build_fix_message([(35, "0"), (34, "1")], delimiter="|")
    parsed = parse_fix_message(wire)
    checksum_start = wire.encode().rfind(b"10=")
    normalized_prefix = wire.encode()[:checksum_start].replace(b"|", b"\x01")
    assert int(wire.split("10=")[1][:3]) == sum(normalized_prefix) % 256
    assert parsed.raw_wire == wire and parsed.delimiter == "|"


def test_builder_rejects_missing_reserved_duplicate_and_ambiguous_tags():
    with pytest.raises(ValueError, match="MsgType"):
        build_fix_message([(34, "1")])
    with pytest.raises(ValueError, match="generated framing"):
        build_fix_message([(35, "0"), (8, "FIX.4.4")])
    with pytest.raises(ValueError, match="Duplicate FIX tag"):
        build_fix_message([(35, "0"), (34, "1"), (34, "2")])


@pytest.mark.parametrize(
    "mutation,expected",
    [
        ("checksum", "CheckSum"),
        ("length", "BodyLength"),
        ("duplicate", "Duplicate FIX tag"),
        ("missing", "Missing required structural tag 35"),
        ("order", "MsgType(35) must be third"),
    ],
)
def test_parser_returns_structured_validation_errors(mutation, expected):
    original = build_fix_message([(35, "0"), (34, "1"), (58, "hello")])
    if mutation == "checksum":
        index = original.rfind("10=") + 3
        invalid = original[:index] + "999" + original[index + 3 :]
    elif mutation == "length":
        parts = original.split("\x01")
        parts[1] = "9=999"
        invalid = "\x01".join(parts)
    elif mutation == "duplicate":
        invalid = _wire_in_order([(35, "0"), (34, "1"), (58, "hello"), (58, "world")])
    elif mutation == "missing":
        invalid = _wire_in_order([(34, "1"), (58, "hello")])
    else:
        invalid = _wire_in_order([(34, "1"), (35, "0"), (58, "hello")])
    with pytest.raises(FixParseError) as error:
        parse_fix_message(invalid)
    assert any(expected in item for item in error.value.validation_errors)
    assert error.value.is_structurally_valid is False
    assert any(expected in item for item in error.value.validation_errors)
    inspectable = parse_fix_message(invalid, validate=False)
    assert inspectable.is_structurally_valid is False
    assert inspectable.validation_errors


def test_invalid_checksum_validation_has_precise_error_list():
    wire = build_fix_message([(35, "0"), (34, "1")])
    index = wire.rfind("10=") + 3
    parsed = parse_fix_message(wire[:index] + "000" + wire[index + 3 :], validate=False)
    assert parsed.validation_errors[0].startswith("CheckSum(10) mismatch")


def test_malformed_framing_syntax_fails_with_structured_value_error():
    with pytest.raises(FixParseError, match="must end") as error:
        parse_fix_message("8=FIX.4.4|9=1|35=0|10=000")
    assert error.value.validation_errors
    assert error.value.is_structurally_valid is False


def test_session_sequence_gap_resend_and_gapfill_resolution():
    reconstructor, results = _run("INC-101")
    first, resend, gapfill = [result.session_observation for result in results]
    assert first.sequence_gap
    assert first.expected_sequence_number == 105
    assert resend.resend_range == (105, 0)
    assert gapfill.reset_mode == "gap_fill"
    assert gapfill.gap_resolved
    order = reconstructor.get_order("ORD-101")
    assert order is not None and order.is_in_flight_unknown
    assert order.status.value == "pending_new"  # Gap resolution is not an order acknowledgment.


def test_gapfill_y_resolves_but_reset_mode_n_does_not_claim_gapfill():
    reconstructor = FixReconstructor()
    reconstructor.set_expected_sequence("A", "B", Direction.INBOUND, 5)
    gap = build_fix_message([(35, "0"), (34, "8"), (49, "A"), (56, "B")])
    assert reconstructor.process(gap, direction=Direction.INBOUND).session_observation.sequence_gap
    gapfill = build_fix_message([(35, "4"), (34, "5"), (49, "A"), (56, "B"), (123, "Y"), (36, "9"), (43, "Y")])
    result = reconstructor.process(gapfill, direction=Direction.INBOUND)
    assert result.session_observation.reset_mode == "gap_fill"
    assert result.session_observation.gap_resolved

    other = FixReconstructor()
    other.set_expected_sequence("A", "B", Direction.INBOUND, 5)
    other.process(gap, direction=Direction.INBOUND)
    reset = build_fix_message([(35, "4"), (34, "9"), (49, "A"), (56, "B"), (123, "N"), (36, "10")])
    reset_result = other.process(reset, direction=Direction.INBOUND)
    assert reset_result.session_observation.reset_mode == "reset"
    assert not reset_result.session_observation.gap_resolved
    assert other._open_gaps[(("A", "B"), Direction.INBOUND)] == [(5, 7)]


def test_directional_session_keys_are_sender_target_pairs():
    reconstructor = FixReconstructor()
    inbound_a = build_fix_message([(35, "0"), (34, "1"), (49, "EX1"), (56, "DESK")])
    inbound_b = build_fix_message([(35, "0"), (34, "3"), (49, "EX2"), (56, "DESK")])
    first = reconstructor.process(inbound_a, direction=Direction.INBOUND)
    second = reconstructor.process(inbound_b, direction=Direction.INBOUND)
    assert first.session_observation.session_key == ("EX1", "DESK")
    assert second.session_observation.session_key == ("EX2", "DESK")
    assert second.session_observation.sequence_gap


def test_cancel_fill_race_keeps_filled_authoritative_and_cancel_attempt_separate():
    reconstructor, results = _run("INC-102")
    order = reconstructor.get_order("ORD-8821")
    assert order is not None
    assert order.status.value == "filled"
    assert order.cum_qty == Decimal("500")
    assert order.exposure_dollars == Decimal("112750.00")
    assert order.safe_to_resend is False
    assert order.cancel_rejections == ("e102-cancel-reject",)
    assert "e102-fill" in order.event_history and "e102-cancel-reject" in order.event_history
    assert any("authoritative OrdStatus is unchanged" in warning for warning in results[-1].warnings)
    assert order.status.value != "canceled"


def test_duplicate_exec_and_possdup_are_idempotent_by_session_execid():
    reconstructor = FixReconstructor()
    new = build_fix_message([(35, "D"), (34, "1"), (49, "D"), (56, "X"), (11, "O"), (38, "10"), (44, "2")])
    fill_fields = [(11, "O"), (17, "E1"), (150, "F"), (39, "1"), (38, "10"), (32, "2"), (31, "2"), (14, "2"), (151, "8")]
    fill = build_fix_message([(35, "8"), (34, "1"), (49, "X"), (56, "D"), *fill_fields])
    replay = build_fix_message([(35, "8"), (34, "2"), (49, "X"), (56, "D"), (43, "Y"), *fill_fields])
    assert reconstructor.process(new, direction=Direction.OUTBOUND).order
    once = reconstructor.process(fill, direction=Direction.INBOUND)
    twice = reconstructor.process(replay, direction=Direction.INBOUND)
    assert once.order.cum_qty == Decimal("2")
    assert twice.session_observation.poss_dup and twice.session_observation.duplicate_exec_id
    assert not twice.applied_as_business_event
    assert twice.order.cum_qty == Decimal("2")
    assert twice.order.notional == Decimal("4")


def test_possdup_with_new_execid_is_evidence_not_blanket_discard():
    reconstructor = FixReconstructor()
    new = build_fix_message([(35, "D"), (34, "1"), (49, "D"), (56, "X"), (11, "O"), (38, "10"), (44, "2")])
    reconstructor.process(new, direction=Direction.OUTBOUND)
    ack = build_fix_message([(35, "8"), (34, "1"), (49, "X"), (56, "D"), (11, "O"), (17, "E1"), (150, "F"), (39, "1"), (38, "10"), (32, "2"), (31, "2"), (14, "2"), (151, "8"), (43, "Y")])
    result = reconstructor.process(ack, direction=Direction.INBOUND)
    assert result.session_observation.poss_dup
    assert not result.session_observation.duplicate_exec_id
    assert result.applied_as_business_event
    assert result.order.cum_qty == Decimal("2")


def test_late_execution_report_cannot_regress_cumulative_fill_or_status():
    reconstructor = FixReconstructor()
    base = [(49, "D"), (56, "X")]
    reconstructor.process(build_fix_message([(35, "D"), (34, "1"), *base, (11, "LATE"), (38, "10"), (44, "5")]), direction=Direction.OUTBOUND)
    current = build_fix_message([(35, "8"), (34, "1"), (49, "X"), (56, "D"), (11, "LATE"), (17, "E20"), (150, "F"), (39, "1"), (38, "10"), (32, "5"), (31, "5"), (14, "5"), (151, "5")])
    late = build_fix_message([(35, "8"), (34, "2"), (49, "X"), (56, "D"), (11, "LATE"), (17, "E10"), (150, "F"), (39, "1"), (38, "10"), (32, "2"), (31, "5"), (14, "2"), (151, "8")])
    reconstructor.process(current, direction=Direction.INBOUND)
    result = reconstructor.process(late, direction=Direction.INBOUND, event_id="late-report")
    assert result.order.cum_qty == Decimal("5")
    assert result.order.status.value == "partially_filled"
    assert "late-report" in result.order.event_history
    assert any("financial state preserved" in warning for warning in result.warnings)


def test_gateway_timeout_keeps_unknown_and_never_advises_resend():
    reconstructor, results = _run("INC-103")
    order = reconstructor.get_order("ORD-9040")
    assert order is not None
    assert order.is_in_flight_unknown
    assert order.safe_to_resend is False
    assert order.exposure_dollars == Decimal("138400.00")
    assert order.status.value != "rejected"
    assert any("cannot be determined" in warning for warning in results[-1].warnings)
    assert not any(event.msg_type == "8" for event in [
        # Simulator timeline contains no inbound ExecutionReport in this incident.
        parsed for parsed in (parse_fix_message(item.wire) for item in get_incident("INC-103").events if hasattr(item, "wire"))
    ])


def test_session_protocol_reject_and_application_risk_reject_are_distinct():
    reconstructor, _ = _run("INC-104")
    protocol_order = reconstructor.get_order("ORD-7701")
    risk_order = reconstructor.get_order("ORD-7702")
    assert protocol_order.status.value == "rejected"
    assert protocol_order.rejection_layer == "session"
    assert "RequiredTagMissing" in protocol_order.rejection_reason
    assert risk_order.status.value == "rejected"
    assert risk_order.rejection_layer == "application"
    assert "OrderExceedsLimit" in risk_order.rejection_reason


def test_drop_copy_to_oms_reconciliation_detects_fill_and_notional_break():
    reconstructor, _ = _run("INC-105")
    discrepancies = reconstructor.reconcile_oms_records()
    assert len(discrepancies) == 1
    discrepancy = discrepancies[0]
    assert discrepancy.exchange_filled_qty == Decimal("500")
    assert discrepancy.oms_filled_qty == Decimal("0")
    assert discrepancy.exchange_notional == Decimal("207600.00")
    assert set(discrepancy.event_ids) >= {"e105-fill", "oms-e105-5510"}


def test_all_five_incidents_have_stable_provenance_timestamps_and_valid_wires():
    first, second = all_incidents(), all_incidents()
    assert len(first) == 5
    assert [incident.incident_id for incident in first] == [f"INC-{number}" for number in range(101, 106)]
    assert [incident.model_dump(mode="json") for incident in first] == [
        incident.model_dump(mode="json") for incident in second
    ]
    for incident in first:
        event_ids = [event.event_id for event in incident.events]
        assert len(event_ids) == len(set(event_ids))
        for event in incident.events:
            assert event.timestamp.tzinfo is not None
            assert event.source_layer and event.provenance
            if hasattr(event, "wire"):
                parsed = parse_fix_message(event.wire)
                assert parsed.is_structurally_valid
                assert parsed.raw_wire == event.wire
                assert parsed.sender_comp_id == event.sender_comp_id
                assert parsed.target_comp_id == event.target_comp_id


@pytest.mark.parametrize("incident_id", [f"INC-{number}" for number in range(101, 106)])
def test_all_incident_events_are_processed_by_engine_not_hardcoded_report(incident_id):
    incident = get_incident(incident_id)
    reconstructor = FixReconstructor()
    results = reconstructor.process_incident(incident)
    assert len(results) == len(incident.events)
    assert all(result.event_id == event.event_id for result, event in zip(results, incident.events))
    assert any(snapshot.event_history for snapshot in reconstructor.all_orders())


def test_every_incident_asserts_required_non_conclusions():
    recon, _ = _run("INC-102")
    assert recon.get_order("ORD-8821").status.value != "canceled"
    recon, _ = _run("INC-103")
    assert recon.get_order("ORD-9040").status.value != "rejected"
    assert recon.get_order("ORD-9040").is_in_flight_unknown
    recon, _ = _run("INC-101")
    assert recon.get_order("ORD-101").status.value != "new"  # Gap fill is not business acknowledgment.


def test_unknown_incident_raises_key_error():
    with pytest.raises(KeyError, match="Unknown incident ID"):
        get_incident("INC-999")
