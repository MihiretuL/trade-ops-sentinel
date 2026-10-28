"""Typed evidence, FIX, session, order and incident domain models."""

from __future__ import annotations

from datetime import datetime
from decimal import Decimal
from enum import StrEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


class Direction(StrEnum):
    INBOUND = "inbound"
    OUTBOUND = "outbound"


class OrderStatus(StrEnum):
    PENDING_NEW = "pending_new"
    NEW = "new"
    PARTIALLY_FILLED = "partially_filled"
    FILLED = "filled"
    PENDING_CANCEL = "pending_cancel"
    PENDING_REPLACE = "pending_replace"
    CANCELED = "canceled"
    REJECTED = "rejected"
    EXPIRED = "expired"
    UNKNOWN = "unknown"


class FixField(BaseModel):
    model_config = ConfigDict(frozen=True)
    tag: int
    value: str


class FixMessage(BaseModel):
    model_config = ConfigDict(frozen=True)
    begin_string: str
    fields: tuple[FixField, ...]
    raw_wire: str
    delimiter: str
    validation_errors: list[str] = Field(default_factory=list)
    is_structurally_valid: bool = True

    def get(self, tag: int, default: str | None = None) -> str | None:
        """Return the first body-field value for a tag."""
        return next((field.value for field in self.fields if field.tag == tag), default)

    def get_all(self, tag: int) -> tuple[str, ...]:
        return tuple(field.value for field in self.fields if field.tag == tag)

    @property
    def msg_type(self) -> str | None:
        return self.get(35)

    @property
    def sequence_number(self) -> int | None:
        value = self.get(34)
        return int(value) if value is not None else None

    @property
    def sender_comp_id(self) -> str | None:
        return self.get(49)

    @property
    def target_comp_id(self) -> str | None:
        return self.get(56)

    def as_dict(self, *, last_value_wins: bool = True) -> dict[int, str | list[str]]:
        result: dict[int, Any] = {}
        for field in self.fields:
            if field.tag not in result:
                result[field.tag] = field.value
            elif last_value_wins:
                result[field.tag] = field.value
            else:
                current = result[field.tag]
                if not isinstance(current, list):
                    current = [current]
                    result[field.tag] = current
                current.append(field.value)
        return result


class EvidenceEvent(BaseModel):
    model_config = ConfigDict(frozen=True)
    event_id: str
    timestamp: datetime
    source_layer: str
    provenance: str


class WireEvent(EvidenceEvent):
    direction: Direction
    wire: str
    sender_comp_id: str
    target_comp_id: str


class TelemetryEvent(EvidenceEvent):
    event_type: Literal["gateway_timeout", "risk_pass", "database_error", "drop_copy_fill", "fix_wire_capture"]
    order_id: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    direction: Direction | None = None
    raw_payload: str | None = None


class OMSRecord(BaseModel):
    order_id: str
    status: str
    filled_qty: Decimal
    event_id: str
    timestamp: datetime
    source_layer: str = "OMS_SQL"
    provenance: str


class SessionSeed(BaseModel):
    sender_comp_id: str
    target_comp_id: str
    direction: Direction
    next_sequence: int


class IncidentFixture(BaseModel):
    incident_id: str
    title: str
    description: str
    events: tuple[WireEvent | TelemetryEvent, ...]
    expected: dict[str, Any] = Field(default_factory=dict)
    oms_records: tuple[OMSRecord, ...] = ()
    sequence_seeds: tuple[SessionSeed, ...] = ()


class SessionObservation(BaseModel):
    event_id: str | None = None
    session_key: tuple[str, str]
    direction: Direction
    msg_type: str | None
    sequence_number: int | None
    expected_sequence_number: int | None
    sequence_gap: bool = False
    gap_resolved: bool = False
    retransmission: bool = False
    poss_dup: bool = False
    duplicate_exec_id: bool = False
    exec_id: str | None = None
    resend_range: tuple[int, int] | None = None
    reset_mode: str | None = None
    new_sequence_number: int | None = None


class OrderSnapshot(BaseModel):
    order_id: str
    root_cl_ord_id: str
    current_cl_ord_id: str
    order_ids: tuple[str, ...] = ()
    lineage: tuple[str, ...]
    symbol: str | None = None
    side: str | None = None
    order_qty: Decimal = Decimal("0")
    cum_qty: Decimal = Decimal("0")
    leaves_qty: Decimal = Decimal("0")
    limit_px: Decimal = Decimal("0")
    avg_px: Decimal = Decimal("0")
    notional: Decimal = Decimal("0")
    exposure_dollars: Decimal = Decimal("0")
    status: OrderStatus = OrderStatus.UNKNOWN
    is_in_flight_unknown: bool = True
    exchange_exposure_unknown: bool = True
    safe_to_resend: bool = False
    rejection_layer: str | None = None
    rejection_reason: str | None = None
    last_exec_id: str | None = None
    event_history: tuple[str, ...] = ()
    cancel_rejections: tuple[str, ...] = ()
    quantity_math_valid: bool = True


class ReconstructionResult(BaseModel):
    event_id: str | None = None
    session_observation: SessionObservation | None = None
    order: OrderSnapshot | None = None
    warnings: tuple[str, ...] = Field(default_factory=tuple)
    applied_as_business_event: bool = False


class ReconciliationDiscrepancy(BaseModel):
    order_id: str
    exchange_filled_qty: Decimal
    oms_filled_qty: Decimal
    exchange_notional: Decimal
    oms_status: str
    event_ids: tuple[str, ...]
    description: str


class ReconciliationBreak(BaseModel):
    incident_id: str
    cl_ord_id: str
    symbol: str
    drop_copy_filled_qty: Decimal
    oms_filled_qty: Decimal
    drop_copy_notional: Decimal
    oms_status: str
    exec_ids: tuple[str, ...]
    event_ids: tuple[str, ...]
    break_type: str
    description: str


class ReportFact(BaseModel):
    claim: str
    event_ids: tuple[str, ...]
    fix_tags: tuple[int, ...] = ()


class SubwayNode(BaseModel):
    name: str
    status: str
    event_ids: tuple[str, ...] = ()


class DeterministicInvestigationReport(BaseModel):
    incident_id: str
    title: str
    scenario_code: str
    primary_failure_category: str
    severity: str
    summary: str
    total_exposure_dollars: Decimal
    is_in_flight_unknown: bool
    safe_to_resend: bool
    order_statuses: dict[str, str]
    facts: tuple[ReportFact, ...]
    unknowns: tuple[str, ...]
    reconciliation_breaks: tuple[ReconciliationBreak, ...]
    subway_map_status: tuple[SubwayNode, ...]
    event_ids: tuple[str, ...]
    source: str = "deterministic_local_engine"
