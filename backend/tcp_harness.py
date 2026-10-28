"""Controlled local TCP loopback digital twin for FIX incident scenarios.

This harness binds only the configured local interface and exchanges fixture
traffic between an asyncio initiator and acceptor. It is not a live external
exchange connection and cannot prove external market connectivity or behavior.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from . import db
from .config import get_settings
from .fix_protocol import SOH, build_fix_message, parse_fix_message
from .models import (
    DeterministicInvestigationReport,
    Direction,
    IncidentFixture,
    TelemetryEvent,
    WireEvent,
)
from .reconstructor import FixReconstructor
from .simulator import get_incident


async def _read_fix_frame(reader: asyncio.StreamReader) -> bytes:
    """Read delimiter-framed FIX fields until a CheckSum(10) field is complete."""
    collected: list[bytes] = []
    while True:
        field = await reader.readuntil(SOH.encode("ascii"))
        collected.append(field)
        content = field[:-1]
        if content.startswith(b"10="):
            if len(content) != 6 or not content[3:].isdigit():
                raise ValueError(f"Invalid CheckSum field in TCP frame: {content!r}")
            return b"".join(collected)


@dataclass(frozen=True)
class HarnessResult:
    incident_id: str
    host: str
    port: int
    transmitted_frames: int
    received_frames: int
    captured_events: tuple[WireEvent | TelemetryEvent, ...]
    report: DeterministicInvestigationReport
    socket_metadata: dict[str, Any]


class LocalFIXExchangeHarness:
    """Run scenario traffic over a real local asyncio TCP socket pair.

    Supported scenarios are the five deterministic fixtures. `port=0` asks the
    OS to bind an ephemeral port. Socket metadata and capture timestamps describe
    this local digital twin only; no external socket is opened.
    """

    def __init__(
        self,
        db_path: str | None = None,
        *,
        host: str | None = None,
        port: int | None = None,
    ) -> None:
        settings = get_settings()
        self.db_path = db_path or settings.sqlite_db_path
        self.host = host or settings.tcp_harness_host
        self.port = settings.tcp_harness_port if port is None else port
        if self.host not in {"127.0.0.1", "localhost", "::1"}:
            raise ValueError("The local FIX digital twin may bind only to a loopback host")
        if not 0 <= self.port <= 65535:
            raise ValueError("TCP harness port must be between 0 and 65535")

    async def run(self, incident_id: str) -> HarnessResult:
        fixture = get_incident(incident_id)
        acceptor_frames: asyncio.Queue[bytes] = asyncio.Queue()
        initiator_writes: asyncio.Queue[bytes | None] = asyncio.Queue()
        server_errors: asyncio.Queue[BaseException] = asyncio.Queue()
        server_connections: list[tuple[Any, Any]] = []
        server_sender_task: asyncio.Task[None] | None = None

        async def acceptor(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            nonlocal server_sender_task
            """Exchange frames with the test initiator entirely over loopback."""
            server_connections.append((writer.get_extra_info("peername"), writer.get_extra_info("sockname")))

            async def sender() -> None:
                while True:
                    frame = await initiator_writes.get()
                    if frame is None:
                        break
                    writer.write(frame)
                    await writer.drain()

            server_sender_task = asyncio.create_task(sender())
            try:
                while True:
                    frame = await _read_fix_frame(reader)
                    parse_fix_message(frame)
                    await acceptor_frames.put(frame)
            except (asyncio.IncompleteReadError, ConnectionResetError):
                return
            except BaseException as exc:
                await server_errors.put(exc)
            finally:
                if server_sender_task is not None:
                    server_sender_task.cancel()
                    await asyncio.gather(server_sender_task, return_exceptions=True)
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(acceptor, self.host, self.port)
        sock = server.sockets[0]
        bound_host, bound_port = sock.getsockname()[:2]
        reader, writer = await asyncio.open_connection(bound_host, bound_port)
        captured: list[WireEvent | TelemetryEvent] = []
        sent_count = 0
        received_count = 0
        try:
            for index, event in enumerate(fixture.events):
                if isinstance(event, TelemetryEvent):
                    captured.append(event.model_copy(update={
                        "source_layer": f"TCP_LOOPBACK:{event.source_layer}",
                        "provenance": f"{event.provenance} Captured during local controlled TCP loopback run.",
                    }))
                    continue

                # The shared ground-truth fixtures are FIX.4.4; exercise the requested
                # local exchange harness as FIX.4.2 while preserving all ordered fields.
                parsed_fixture = parse_fix_message(event.wire)
                raw = build_fix_message(parsed_fixture.fields, begin_string="FIX.4.2").encode("ascii")
                parse_fix_message(raw)
                if event.direction == Direction.OUTBOUND:
                    writer.write(raw)
                    await writer.drain()
                    received = await asyncio.wait_for(acceptor_frames.get(), timeout=3.0)
                    received_count += 1
                    if received != raw:
                        raise RuntimeError("Local acceptor received wire bytes different from initiator transmission")
                    captured.append(self._captured_wire(event, received, index, "initiator_to_acceptor"))
                else:
                    await initiator_writes.put(raw)
                    received = await asyncio.wait_for(_read_fix_frame(reader), timeout=3.0)
                    sent_count += 1
                    if received != raw:
                        raise RuntimeError("Local initiator received wire bytes different from acceptor transmission")
                    captured.append(self._captured_wire(event, received, index, "acceptor_to_initiator"))

            if not acceptor_frames.empty():
                raise RuntimeError("Unexpected unconsumed local acceptor frames")
        finally:
            await initiator_writes.put(None)
            writer.close()
            await writer.wait_closed()
            server.close()
            await server.wait_closed()

        if not server_errors.empty():
            raise RuntimeError("Local FIX acceptor failed") from server_errors.get_nowait()

        captured_fixture = fixture.model_copy(update={"events": tuple(captured)})
        reconstructor = FixReconstructor()
        results = reconstructor.process_incident(captured_fixture)
        report = db.persist_custom_incident(self.db_path, captured_fixture, reconstructor, results)
        peer = server_connections[0] if server_connections else (None, None)
        metadata = {
            "digital_twin": True,
            "external_exchange_connection": False,
            "local_bind_host": str(bound_host),
            "local_bind_port": int(bound_port),
            "acceptor_peer": peer[0],
            "acceptor_socket": peer[1],
            "wire_encoding": "ASCII",
            "delimiter": "SOH (0x01)",
            "captured_at": datetime.now(timezone.utc).isoformat(),
        }
        return HarnessResult(
            incident_id=incident_id,
            host=str(bound_host),
            port=int(bound_port),
            transmitted_frames=sent_count,
            received_frames=received_count,
            captured_events=tuple(captured),
            report=report,
            socket_metadata=metadata,
        )

    @staticmethod
    def _captured_wire(event: WireEvent, raw: bytes, index: int, route: str) -> WireEvent:
        parsed = parse_fix_message(raw)
        return event.model_copy(update={
            "event_id": f"tcp:{event.event_id}:{index}",
            "timestamp": datetime.now(timezone.utc),
            "source_layer": "TCP_LOOPBACK",
            "provenance": f"Captured {route} on local loopback; fixture evidence {event.event_id}; not a live exchange feed.",
            "wire": raw.decode("ascii"),
            "sender_comp_id": parsed.sender_comp_id or event.sender_comp_id,
            "target_comp_id": parsed.target_comp_id or event.target_comp_id,
        })
