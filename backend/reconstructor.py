"""Evidence-preserving FIX session and order reconstruction."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation

from .fix_protocol import parse_fix_message
from .models import (
    Direction,
    FixMessage,
    IncidentFixture,
    OMSRecord,
    OrderSnapshot,
    OrderStatus,
    ReconciliationDiscrepancy,
    ReconstructionResult,
    SessionObservation,
    TelemetryEvent,
    WireEvent,
)

_ORD_STATUS = {
    "0": OrderStatus.NEW,
    "1": OrderStatus.PARTIALLY_FILLED,
    "2": OrderStatus.FILLED,
    "4": OrderStatus.CANCELED,
    "5": OrderStatus.NEW,
    "6": OrderStatus.PENDING_CANCEL,
    "8": OrderStatus.REJECTED,
    "C": OrderStatus.EXPIRED,
    "E": OrderStatus.PENDING_REPLACE,
}
_EXEC_TYPE = {"0": OrderStatus.NEW, "1": OrderStatus.PARTIALLY_FILLED, "2": OrderStatus.FILLED, "4": OrderStatus.CANCELED, "5": OrderStatus.NEW, "8": OrderStatus.REJECTED}
_TERMINAL = {OrderStatus.FILLED, OrderStatus.CANCELED, OrderStatus.REJECTED, OrderStatus.EXPIRED}


def _decimal(value: str | None, default: Decimal = Decimal("0")) -> Decimal:
    if value is None or value == "":
        return default
    try:
        result = Decimal(value)
    except InvalidOperation as exc:
        raise ValueError(f"Invalid FIX decimal {value!r}") from exc
    if not result.is_finite():
        raise ValueError(f"FIX decimal must be finite, got {value!r}")
    return result


@dataclass
class _Order:
    root_id: str
    current_id: str
    lineage: list[str]
    order_ids: list[str] = field(default_factory=list)
    symbol: str | None = None
    side: str | None = None
    order_qty: Decimal = Decimal("0")
    cum_qty: Decimal = Decimal("0")
    leaves_qty: Decimal = Decimal("0")
    limit_px: Decimal = Decimal("0")
    avg_px: Decimal = Decimal("0")
    notional: Decimal = Decimal("0")
    status: OrderStatus = OrderStatus.PENDING_NEW
    is_in_flight_unknown: bool = True
    safe_to_resend: bool = False
    rejection_layer: str | None = None
    rejection_reason: str | None = None
    last_exec_id: str | None = None
    pending_target_id: str | None = None
    event_history: list[str] = field(default_factory=list)
    cancel_rejections: list[str] = field(default_factory=list)

    @property
    def exposure(self) -> Decimal:
        # Known executions plus remaining order at its limit; in-flight orders
        # retain full notional exposure even when no exchange response exists.
        return self.notional + self.leaves_qty * self.limit_px

    @property
    def quantity_math_valid(self) -> bool:
        if self.status in {OrderStatus.CANCELED, OrderStatus.REJECTED, OrderStatus.EXPIRED}:
            return self.cum_qty <= self.order_qty
        return self.cum_qty + self.leaves_qty == self.order_qty

    def snapshot(self) -> OrderSnapshot:
        return OrderSnapshot(
            order_id=self.root_id,
            root_cl_ord_id=self.root_id,
            current_cl_ord_id=self.current_id,
            order_ids=tuple(self.order_ids),
            lineage=tuple(self.lineage),
            symbol=self.symbol,
            side=self.side,
            order_qty=self.order_qty,
            cum_qty=self.cum_qty,
            leaves_qty=self.leaves_qty,
            limit_px=self.limit_px,
            avg_px=self.avg_px,
            notional=self.notional,
            exposure_dollars=self.exposure,
            status=self.status,
            is_in_flight_unknown=self.is_in_flight_unknown,
            exchange_exposure_unknown=self.is_in_flight_unknown,
            safe_to_resend=self.safe_to_resend if not self.is_in_flight_unknown else False,
            rejection_layer=self.rejection_layer,
            rejection_reason=self.rejection_reason,
            last_exec_id=self.last_exec_id,
            event_history=tuple(self.event_history),
            cancel_rejections=tuple(self.cancel_rejections),
            quantity_math_valid=self.quantity_math_valid,
        )


class FixReconstructor:
    """Reconstruct sessions, order state and OMS/drop-copy reconciliation.

    A forward sequence jump records an unresolved inclusive missing range and
    advances the observed high-water mark to received+1. A SequenceReset with
    123=Y closes only its specified gap-fill interval; 123=N or absent is a
    Reset mode and changes the expected sequence but does not assert gap-fill.
    """

    def __init__(self) -> None:
        self._expected: dict[tuple[tuple[str, str], Direction], int] = {}
        self._seen_sequences: dict[tuple[tuple[str, str], Direction], set[int]] = {}
        self._open_gaps: dict[tuple[tuple[str, str], Direction], list[tuple[int, int]]] = {}
        self._orders: dict[str, _Order] = {}
        self._clord_to_root: dict[str, str] = {}
        self._orderid_to_root: dict[str, str] = {}
        self._seen_exec_ids: set[tuple[tuple[str, str], str]] = set()
        self._outbound_clord_by_sequence: dict[tuple[tuple[str, str], int], str] = {}
        self._oms_records: dict[str, OMSRecord] = {}
        self._drop_copy_qty: dict[str, Decimal] = {}
        self._drop_copy_notional: dict[str, Decimal] = {}
        self._evidence: dict[str, object] = {}

    def process(
        self,
        message: FixMessage | str | bytes,
        *,
        direction: Direction,
        session_id: str = "default",
        event_id: str | None = None,
    ) -> ReconstructionResult:
        if not isinstance(message, FixMessage):
            message = parse_fix_message(message)
        msg_type = message.msg_type
        sender, target = message.sender_comp_id, message.target_comp_id
        if sender is None or target is None:
            # Compatibility for synthetic callers; production fixtures always carry 49/56.
            sender, target = (session_id, "peer") if direction == Direction.OUTBOUND else ("peer", session_id)
        session_key = (sender, target)
        seq_key = (session_key, direction)
        sequence = message.sequence_number
        expected_before = self._expected.get(seq_key, 1)
        poss_dup = message.get(43) == "Y"
        seen = self._seen_sequences.setdefault(seq_key, set())
        retransmission = poss_dup or (sequence is not None and sequence in seen)
        sequence_gap = False
        gap_resolved = False
        warnings: list[str] = []
        resend_range: tuple[int, int] | None = None
        reset_mode: str | None = None
        new_sequence_number: int | None = None

        if sequence is None:
            warnings.append("MsgSeqNum(34) missing; session sequence cannot be verified")
        else:
            if sequence > expected_before:
                sequence_gap = True
                self._open_gaps.setdefault(seq_key, []).append((expected_before, sequence - 1))
                warnings.append(f"Sequence gap: expected {expected_before}, received {sequence}; missing outcome is unknown")
                self._expected[seq_key] = sequence + 1
            elif sequence == expected_before:
                self._expected[seq_key] = sequence + 1
            elif sequence < expected_before and sequence not in seen:
                warnings.append(f"Late/out-of-order sequence {sequence}; current expected sequence is {expected_before}")
            if not retransmission:
                seen.add(sequence)

        exec_id = message.get(17) if msg_type == "8" else None
        duplicate_exec = bool(exec_id and (session_key, exec_id) in self._seen_exec_ids)

        if msg_type == "2":
            begin, end = message.get(7), message.get(16)
            resend_range = (int(begin or "0"), int(end or "0"))
            warnings.append(f"ResendRequest received for sequence range {resend_range[0]}..{resend_range[1] or 'infinity'}")
        elif msg_type == "4":
            new_sequence_number = int(message.get(36) or "0")
            gapfill = message.get(123) == "Y"
            reset_mode = "gap_fill" if gapfill else "reset"
            if new_sequence_number <= 0:
                warnings.append("SequenceReset NewSeqNo(36) must be positive")
            elif gapfill:
                remaining: list[tuple[int, int]] = []
                filled_start = sequence if sequence is not None else new_sequence_number
                filled_end = new_sequence_number - 1
                for start, end in self._open_gaps.get(seq_key, []):
                    if filled_start > end or filled_end < start:
                        remaining.append((start, end))
                    else:
                        gap_resolved = True
                        if start < filled_start:
                            remaining.append((start, filled_start - 1))
                        if filled_end < end:
                            remaining.append((filled_end + 1, end))
                self._open_gaps[seq_key] = remaining
                old_expected = self._expected.get(seq_key, 1)
                self._expected[seq_key] = max(old_expected, new_sequence_number)
                if not gap_resolved:
                    warnings.append("GapFill SequenceReset did not match a recorded open sequence gap")
            else:
                # Reset mode changes expected sequence, but is not evidence that missing
                # application messages were gap-filled or that their business effects are known.
                self._expected[seq_key] = new_sequence_number

        observation = SessionObservation(
            event_id=event_id,
            session_key=session_key,
            direction=direction,
            msg_type=msg_type,
            sequence_number=sequence,
            expected_sequence_number=expected_before,
            sequence_gap=sequence_gap,
            gap_resolved=gap_resolved,
            retransmission=retransmission,
            poss_dup=poss_dup,
            duplicate_exec_id=duplicate_exec,
            exec_id=exec_id,
            resend_range=resend_range,
            reset_mode=reset_mode,
            new_sequence_number=new_sequence_number,
        )

        self._evidence[event_id or f"fix:{session_key}:{sequence}"] = message
        order, applied = self._apply_order_message(
            message, session_key, event_id, retransmission, duplicate_exec, warnings
        )
        if order is not None and not order.quantity_math_valid:
            warnings.append(
                f"Quantity invariant failed: CumQty({order.cum_qty}) + LeavesQty({order.leaves_qty}) "
                f"!= OrderQty({order.order_qty})"
            )
        return ReconstructionResult(
            event_id=event_id,
            session_observation=observation,
            order=order.snapshot() if order else None,
            warnings=tuple(warnings),
            applied_as_business_event=applied,
        )

    def process_event(self, event: WireEvent | TelemetryEvent) -> ReconstructionResult:
        """Ingest one simulator evidence event through deterministic logic."""
        self._evidence[event.event_id] = event
        if isinstance(event, WireEvent):
            parsed = parse_fix_message(event.wire)
            # Fixture metadata and on-wire comp IDs must agree; do not silently repair.
            if parsed.sender_comp_id != event.sender_comp_id or parsed.target_comp_id != event.target_comp_id:
                raise ValueError(f"Event {event.event_id} session metadata does not match FIX tags 49/56")
            return self.process(parsed, direction=event.direction, event_id=event.event_id)

        if event.event_type == "gateway_timeout":
            order = self._resolve(event.order_id)
            if order:
                order.is_in_flight_unknown = True
                order.safe_to_resend = False
                order.event_history.append(event.event_id)
        elif event.event_type == "drop_copy_fill":
            order_id = event.order_id or str(event.details.get("order_id", ""))
            qty = Decimal(str(event.details.get("filled_qty", "0")))
            notional = Decimal(str(event.details.get("notional", "0")))
            self._drop_copy_qty[order_id] = self._drop_copy_qty.get(order_id, Decimal("0")) + qty
            self._drop_copy_notional[order_id] = self._drop_copy_notional.get(order_id, Decimal("0")) + notional
            order = self._resolve(order_id)
            if order:
                order.is_in_flight_unknown = False
                order.event_history.append(event.event_id)
        else:
            order = self._resolve(event.order_id)
            if order:
                order.event_history.append(event.event_id)
        return ReconstructionResult(
            event_id=event.event_id,
            order=order.snapshot() if order else None,
            warnings=("Exchange receipt or execution cannot be determined from current telemetry; a gateway timeout does not establish non-receipt or rejection.",)
            if event.event_type == "gateway_timeout" else (),
            applied_as_business_event=event.event_type == "drop_copy_fill",
        )

    def process_incident(self, incident: IncidentFixture) -> tuple[ReconstructionResult, ...]:
        for seed in incident.sequence_seeds:
            self.set_expected_sequence(
                seed.sender_comp_id, seed.target_comp_id, seed.direction, seed.next_sequence
            )
        results = tuple(self.process_event(event) for event in incident.events)
        for record in incident.oms_records:
            self._oms_records[record.order_id] = record
        return results

    def set_expected_sequence(
        self, sender_comp_id: str, target_comp_id: str, direction: Direction, next_sequence: int
    ) -> None:
        """Seed a session from established Logon/recovery evidence in a fixture."""
        if next_sequence < 1:
            raise ValueError("Expected FIX sequence must be positive")
        self._expected[((sender_comp_id, target_comp_id), direction)] = next_sequence

    def get_order(self, identifier: str) -> OrderSnapshot | None:
        order = self._resolve(identifier)
        return order.snapshot() if order else None

    def all_orders(self) -> tuple[OrderSnapshot, ...]:
        return tuple(order.snapshot() for order in self._orders.values())

    def reconcile_oms_records(self, records: tuple[OMSRecord, ...] | None = None) -> tuple[ReconciliationDiscrepancy, ...]:
        """Compare reconstructed executions with declared OMS records using Decimals."""
        selected = records if records is not None else tuple(self._oms_records.values())
        discrepancies: list[ReconciliationDiscrepancy] = []
        for record in selected:
            order = self._resolve(record.order_id)
            exchange_qty = order.cum_qty if order else self._drop_copy_qty.get(record.order_id, Decimal("0"))
            exchange_notional = order.notional if order else self._drop_copy_notional.get(record.order_id, Decimal("0"))
            if exchange_qty != record.filled_qty:
                evidence_ids = tuple(order.event_history) if order else ()
                discrepancies.append(ReconciliationDiscrepancy(
                    order_id=record.order_id,
                    exchange_filled_qty=exchange_qty,
                    oms_filled_qty=record.filled_qty,
                    exchange_notional=exchange_notional,
                    oms_status=record.status,
                    event_ids=(*evidence_ids, record.event_id),
                    description=f"OMS fill quantity {record.filled_qty} differs from exchange evidence {exchange_qty}",
                ))
        for order_id, drop_qty in self._drop_copy_qty.items():
            record = next((item for item in selected if item.order_id == order_id), None)
            if record and record.filled_qty != drop_qty:
                # Avoid duplicates where a FIX order also exists for same id.
                if not any(item.order_id == order_id for item in discrepancies):
                    discrepancies.append(ReconciliationDiscrepancy(
                        order_id=order_id,
                        exchange_filled_qty=drop_qty,
                        oms_filled_qty=record.filled_qty,
                        exchange_notional=self._drop_copy_notional.get(order_id, Decimal("0")),
                        oms_status=record.status,
                        event_ids=(record.event_id,),
                        description="Drop-Copy and OMS fill quantities differ",
                    ))
        return tuple(discrepancies)

    def _apply_order_message(
        self,
        message: FixMessage,
        session_key: tuple[str, str],
        event_id: str | None,
        retransmission: bool,
        duplicate_exec: bool,
        warnings: list[str],
    ) -> tuple[_Order | None, bool]:
        msg_type = message.msg_type
        clord = message.get(11)
        orig = message.get(41)
        order_id = message.get(37)
        order = self._resolve(clord) or self._resolve(orig) or self._resolve(order_id)

        if msg_type == "3":  # Session Reject, not an order-level rejection.
            ref_seq = message.get(45)
            outbound_session = (session_key[1], session_key[0])
            referenced = self._outbound_clord_by_sequence.get((outbound_session, int(ref_seq))) if ref_seq and ref_seq.isdigit() else None
            order = self._resolve(referenced)
            warnings.append(f"Session-layer Reject(35=3): RefTagID={message.get(371)}, RefMsgType={message.get(372)}, reason={message.get(373)}")
            if order:
                order.status = OrderStatus.REJECTED
                order.is_in_flight_unknown = False
                order.leaves_qty = Decimal("0")
                order.rejection_layer = "session"
                order.rejection_reason = message.get(58) or message.get(373)
                if event_id:
                    order.event_history.append(event_id)
            return order, False

        if msg_type == "D":
            if not clord:
                warnings.append("NewOrderSingle missing ClOrdID(11); order cannot be correlated")
                return None, False
            if retransmission:
                warnings.append("NewOrderSingle retransmission recorded; duplicate request not applied")
                return self._resolve(clord), False
            order = self._resolve(clord)
            if order is None:
                order = _Order(root_id=clord, current_id=clord, lineage=[clord])
                self._orders[clord] = order
            order.symbol = message.get(55, order.symbol)
            order.side = message.get(54, order.side)
            order.order_qty = _decimal(message.get(38), order.order_qty)
            order.limit_px = _decimal(message.get(44), order.limit_px)
            order.leaves_qty = max(order.order_qty - order.cum_qty, Decimal("0"))
            order.status = OrderStatus.PENDING_NEW
            order.is_in_flight_unknown = True
            self._clord_to_root[clord] = order.root_id
            if message.sequence_number is not None:
                self._outbound_clord_by_sequence[(session_key, message.sequence_number)] = clord
            if event_id:
                order.event_history.append(event_id)
            if message.get(40) == "2" and message.get(44) is None:
                warnings.append("Limit order omits required Price(44); session protocol rejection expected")
            return order, True

        if msg_type in {"F", "G"}:
            if order is None:
                warnings.append(f"Cancel/replace request cannot resolve order {orig or clord!r}")
                return None, False
            if retransmission:
                warnings.append("Cancel/replace retransmission recorded; request state not applied twice")
                return order, False
            if clord and clord not in order.lineage:
                order.lineage.append(clord)
                self._clord_to_root[clord] = order.root_id
            if msg_type == "F":
                if order.status not in _TERMINAL:
                    order.status = OrderStatus.PENDING_CANCEL
            else:
                order.pending_target_id = clord
                order.status = OrderStatus.PENDING_REPLACE
                order.order_qty = _decimal(message.get(38), order.order_qty)
                order.limit_px = _decimal(message.get(44), order.limit_px)
                order.leaves_qty = max(order.order_qty - order.cum_qty, Decimal("0"))
            if event_id:
                order.event_history.append(event_id)
            return order, True

        if msg_type == "9":  # CancelReject is attempt evidence, never execution state.
            if order is None:
                warnings.append(f"OrderCancelReject cannot resolve order {orig or clord!r}")
                return None, False
            if event_id:
                order.cancel_rejections.append(event_id)
                order.event_history.append(event_id)
            warnings.append("OrderCancelReject records the cancel attempt; authoritative OrdStatus is unchanged")
            return order, False

        if msg_type != "8":
            return None, False
        if order is None:
            warnings.append(f"ExecutionReport cannot resolve order ClOrdID(11)={clord!r}")
            return None, False
        if duplicate_exec:
            warnings.append(f"Duplicate ExecID(17) {message.get(17)!r} ignored for execution accounting")
            if event_id:
                order.event_history.append(event_id)
            return order, False
        exec_id = message.get(17)
        if exec_id:
            self._seen_exec_ids.add((session_key, exec_id))
            order.last_exec_id = exec_id
        if event_id:
            order.event_history.append(event_id)

        new_cum = _decimal(message.get(14), order.cum_qty)
        stale = new_cum < order.cum_qty
        if stale:
            warnings.append(f"Late ExecutionReport has CumQty {new_cum} below authoritative {order.cum_qty}; financial state preserved")
        else:
            order.symbol = message.get(55, order.symbol)
            order.side = message.get(54, order.side)
            order.order_qty = _decimal(message.get(38), order.order_qty)
            order.order_ids = list(dict.fromkeys([*order.order_ids, *([order_id] if order_id else [])]))
            if order_id:
                self._orderid_to_root[order_id] = order.root_id
            order.cum_qty = new_cum
            order.leaves_qty = _decimal(message.get(151), max(order.order_qty - order.cum_qty, Decimal("0")))
            avg_text, last_px, last_qty = message.get(6), message.get(31), message.get(32)
            if avg_text is not None:
                order.avg_px = _decimal(avg_text)
                order.notional = order.cum_qty * order.avg_px
            elif last_px is not None and last_qty is not None:
                # FIX's cumulative quantity is authoritative; compute total notional
                # incrementally only when this execution is not stale/replayed.
                order.notional += _decimal(last_px) * _decimal(last_qty)
                if order.cum_qty:
                    order.avg_px = order.notional / order.cum_qty
            status = _ORD_STATUS.get(message.get(39) or "") or _EXEC_TYPE.get(message.get(150) or "")
            if status is not None and not (order.status in _TERMINAL and status not in _TERMINAL):
                order.status = status
            if status == OrderStatus.REJECTED:
                order.rejection_layer = "application"
                order.rejection_reason = message.get(58) or message.get(103)
                order.leaves_qty = Decimal("0")
            if clord:
                if clord not in order.lineage:
                    order.lineage.append(clord)
                self._clord_to_root[clord] = order.root_id
                if message.get(150) == "5" or order.pending_target_id == clord:
                    order.current_id = clord
                    order.pending_target_id = None
            order.is_in_flight_unknown = False
        return order, not stale

    def _resolve(self, identifier: str | None) -> _Order | None:
        if not identifier:
            return None
        root = self._clord_to_root.get(identifier, self._orderid_to_root.get(identifier, identifier))
        return self._orders.get(root)



# Public task terminology; both names refer to the same deterministic engine.
IncidentReconstructor = FixReconstructor
