# TradeOps Sentinel — Project Blueprint & Precision Rules

## 1. Project Identity & Problem Statement

- **Project Name:** TradeOps Sentinel (`trade-ops-sentinel`)
- **Hackathon Track:** Indie Developer ($400K Pool) — *Build for Your World* & *Push the Frontier*
- **Target Bonus Prizes:**
  1. **Best Build on Meta Open Weight Models ($10K):** Uses `meta-models/muse-spark-open-1026` on Baseten / Fireworks.
  2. **Best Agentic Use-Case ($5K):** Autonomous, verifiable multi-step tool-calling diagnostic agent.
  3. **Most Viral Project ($20K):** Live “Chaos-to-Resolution” trading desk terminal demo.
- **Core Problem Solved:** When an order fails, stalls, or disappears mid-flight on an electronic trading desk, a Trading Operations Engineer has seconds to correlate disconnected telemetry across (1) raw FIX 4.2/4.4 wire packets, (2) Linux/TCP socket health, (3) pre-trade Risk controls, and (4) internal OMS SQL databases vs. Exchange Drop-Copies. Naive chatbots hallucinate root causes or advise retrying an unacknowledged order—risking catastrophic double-fills. TradeOps Sentinel deterministically reconstructs the incident state machine, verifies evidence, explicitly flags unknown exchange exposure, and generates separate outputs for Traders (position safety) and Engineers (protocol/SQL remediation).

## 2. Complete Tech Stack & Architecture

| Layer | Technology | Role in `trade-ops-sentinel` |
| :--- | :--- | :--- |
| **Backend API & Streaming** | **Python 3.11+ & FastAPI (`uvicorn`, `websockets`)** | REST endpoints + live WebSocket feed for real-time FIX wire streaming, fault injection, and agent execution. |
| **Protocol & State Engine** | **Custom FIX 4.2/4.4 Engine (`fix_protocol.py`, `reconstructor.py`)** | Parses SOH (`\x01`) and pipe (`|`) FIX fixtures, validates `BodyLength (9)` & modulo-256 `CheckSum (10)`, tracks directional `MsgSeqNum (34)`, deduplicates `ExecID (17)` / `PossDupFlag (43)`, and chains `ClOrdID (11)` <- `OrigClOrdID (41)` using `Decimal` arithmetic. |
| **Live Exchange Harness** | **Python `asyncio` TCP Loopback (`tcp_harness.py`)** | Runs a local FIX Initiator (Desk OMS) <-> FIX Acceptor (Exchange Gateway) over TCP with a Chaos Fault Injector using realistic tickers (`AAPL`, `NVDA`, `SPY`, `MSFT`, `ESZ6`). |
| **Database & Reconciliation** | **SQLite (`sqlite3` / `oms.db`)** | Stores `oms_orders`, `fix_wire_events`, `network_telemetry`, and `drop_copy_fills` to detect SQL vs. Exchange Straight-Through Processing (STP) breaks. |
| **Open-Weight Reasoning Agent** | **`Muse Spark Open` (`meta-models/muse-spark-open-1026`) via Baseten & Fireworks AI** | Runs the verifiable multi-turn tool-calling investigator (`inspect_fix_session`, `trace_order_chain`, `check_network_socket`, `reconcile_oms_sql`) with strict Pydantic citation enforcement. |
| **Multimodal & Code AI** | **Meta Model API (`Muse Voice Transcribe`, `Muse Spark` Vision, `Muse Code`)** | 1. `Muse Voice Transcribe`: Transcribes spoken trader squawk box audio reports into structured incident queries.<br>2. `Muse Spark` Vision: Extracts `ClOrdID`s, symbols, and error states from uploaded trader blotter / Grafana screenshots.<br>3. `Muse Code`: Generates read-only recommended Python/SQL/FIX recovery scripts for the diagnosed incident. |
| **Frontend Dashboard** | **Next.js 14+ (App Router, TypeScript), Tailwind CSS, Lucide Icons** | Dark-mode institutional trading ops terminal featuring a Plain-English Dollar Exposure Banner, 4-Node Visual Subway Map (`OMS -> Risk -> FIX Gateway -> Exchange`), Live FIX Wire Decoder, Chaos Control Bar, and Dual Stakeholder Diagnosis Panel. |
| **Testing & QA** | **`pytest` + `httpx`** | Automated unit and integration tests for FIX checksums, BodyLength, sequence gaps, order chaining, SQL recon breaks, and AI citation validation. |

## 3. Target Repository Directory Structure

```text
trade-ops-sentinel/
├── CLAUDE.md
├── README.md
├── requirements.txt
├── .env.example
├── backend/
│   ├── __init__.py
│   ├── main.py                # Sprint 2: FastAPI app, REST routes, WebSocket live stream
│   ├── config.py              # Sprint 2: Env vars for Meta Model API, Baseten, Fireworks, SQLite
│   ├── fix_protocol.py        # Sprint 1: FIX 4.2/4.4 wire parser, builder, checksum/length validator
│   ├── models.py              # Sprint 1: Pydantic v2 schemas (using Decimal for monetary values)
│   ├── reconstructor.py       # Sprint 1: Deterministic session & order lifecycle state machine
│   ├── simulator.py           # Sprint 1: Generates the 5 deterministic incident fixtures (INC-101..105)
│   ├── db.py                  # Sprint 2: SQLite OMS store, event persistence, and Drop-Copy SQL reconciler
│   ├── tcp_harness.py         # Sprint 2: Asyncio TCP loopback FIX Initiator <-> Acceptor + Fault Injector
│   ├── ai_investigator.py     # Sprint 3: Verifiable tool-calling agent (Baseten muse-spark-open-1026)
│   └── multimodal_intake.py   # Sprint 3: Muse Voice Transcribe + Muse Spark Vision + Muse Code
├── frontend/                  # Sprint 4: Next.js TypeScript + Tailwind CSS institutional dashboard
└── tests/
    ├── test_engine.py         # Sprint 1: Comprehensive positive & negative protocol & state tests
    ├── test_db_and_api.py     # Sprint 2: SQLite reconciliation & FastAPI endpoint tests
    └── test_ai_verifier.py    # Sprint 3: Agent tool-calling & untrusted LLM citation guardrail tests
```

## 4. Implementation Precision & Acceptance Criteria (Mandatory Rules)

### A. FIX Protocol Correctness
- Treat FIX messages as bytes for all protocol length and checksum calculations. `BodyLength (9)` counts bytes from the first byte of the message body (always starting with `35=`) through the delimiter immediately before `10=`. `CheckSum (10)` is the modulo-256 sum of all bytes preceding the checksum field, including the delimiter immediately before `10=`.
- Support both ASCII SOH (`\x01`) and pipe-delimited (`|`) fixtures. Normalize delimiters only for parsing/calculation when explicitly working with pipe-delimited fixtures; preserve the original raw string and original delimiter on the parsed object, and do not claim that pipe-delimited fixtures are literal production wire traffic.
- Validate `BeginString (8)`, `BodyLength (9)`, `CheckSum (10)` formatting (3-digit zero-padded), required structural fields (`8`, `9`, `35`, `10`), tag ordering (`8` first, `9` second, `35` third, `10` last), and malformed or duplicate tags. Return explicit structured validation errors (`validation_errors: list[str]`, `is_structurally_valid: bool`) instead of silently accepting invalid messages or silently repairing corrupted input.
- Ensure `build_fix_message` produces strict tag ordering: `BeginString (8)`, `BodyLength (9)`, `MsgType (35)`, then the remaining body fields in order, with `CheckSum (10)` last. Document that `tag_pairs` must include `(35, msg_type)` and reject ambiguous, missing-`35`, pre-supplied `8`/`9`/`10`, or duplicate-tag input with `ValueError`.

### B. Session State and Sequence Recovery
- Track sequence numbers independently for each FIX session and direction using `(SenderCompID [49], TargetCompID [56])` as the directional session key.
- Model expected inbound sequence numbers, sequence gaps, `ResendRequest (35=2, BeginSeqNo 7, EndSeqNo 16)`, and `SequenceReset (35=4, NewSeqNo 36)`. Do not treat every `SequenceReset (35=4)` as a gap fill: distinguish `123=Y` GapFill mode from `123=N` or absent Reset mode.
- Record retransmissions (`PossDupFlag 43=Y` or already-seen `MsgSeqNum`) and possible duplicate messages separately from new business events. Never apply the same execution twice when a message is replayed.
- Make all sequence recovery assumptions explicit in code and tests. Simulated events must obey the exact same rules.

### C. Order State-Machine Safety
- Maintain a deterministic order-state transition model using `ClOrdID (11)`, `OrigClOrdID (41)`, `OrderID (37)`, `OrdStatus (39)`, `ExecType (150)`, `LastQty (32)`, `LastPx (31)`, `CumQty (14)`, `LeavesQty (151)`, and `ExecID (17)`.
- Distinguish an order's root identity, its cancel/replace requests (`35=F`, `35=G`), its authoritative execution events (`35=8`), and its current reported status. An `OrderCancelReject (35=9)` is NOT an execution report and must never overwrite the order's authoritative execution state (e.g., if `ORD-8821` is `Filled` via `35=8`, a subsequent `35=9` records the rejected cancel attempt while keeping the order's execution state as `Filled`).
- Deduplicate executions using `(session_key, ExecID [17])`. Validate quantity math (`CumQty + LeavesQty == OrderQty` for active/filled orders unless canceled/rejected) and preserve event history when messages arrive late or out of order.
- An unresolved order (`is_in_flight_unknown=True`) must NEVER be marked `safe_to_resend=True` merely because a timeout occurred or an acknowledgment is absent. Require an explicit, evidence-backed resolution path (`OrderStatusRequest 35=H` or verified Drop-Copy check).
- Use Python's `decimal.Decimal` for all prices (`Price 44`, `LastPx 31`, `AvgPx 6`), quantities, notional calculations, and `exposure_dollars`.

### D. Evidence and AI Boundaries
- Every event must have a stable `event_id`, explicit deterministic `timestamp`, `source_layer`, and provenance. Every proven fact in a report must reference one or more actual `event_id`s and, where applicable, the exact FIX tags supporting the claim.
- Deterministic logic—not the LLM—must establish protocol validity, order state, sequence gaps, and SQL reconciliation discrepancies.
- Treat model output as untrusted input. Validate it against Pydantic schemas, verify that cited `event_id`s exist in the incident, reject fabricated evidence references, and retain explicit unknowns.
- Do not allow model-generated code or recovery actions to execute automatically. Recovery suggestions must be read-only recommendations.
- Never claim that the local simulator proves real exchange behavior or production connectivity.

### E. Simulator and Test Quality
- Each incident fixture (`INC-101` through `INC-105`) must contain a coherent timeline with valid FIX messages, correct message directions, session sequence numbers, explicit deterministic timestamps (no `time.sleep` or wall-clock drift), order identifiers, and consistent database records except where the scenario intentionally introduces a failure.
- Include unit tests in `tests/test_engine.py` for: corrupted checksums, incorrect `BodyLength`, missing required tags, duplicate tags, wrong tag ordering, sequence gaps, `GapFillFlag=Y` vs `GapFillFlag=N` sequence resets, duplicate `ExecID` / `PossDupFlag=Y` execution reports, out-of-order/late messages, cancel/fill races (`INC-102`), unresolved gateway timeouts (`INC-103`), session vs application rejects (`INC-104`), and SQL reconciliation discrepancies (`INC-105`).
- Verify both positive and negative behavior: for each incident, assert not only what the engine detects, but also what it must NOT conclude (e.g., `INC-103` must NOT conclude the exchange rejected or did not receive the order; `INC-102` must NOT mark the order as Canceled).
- No placeholder implementations, fabricated test results, silent exception swallowing, or hardcoded reports that bypass the actual reconstruction engine.

## 5. The 5 Production Incident Scenarios (Sprint 1 Ground Truth)

1. **`INC-101` (`SEQ_GAP_RESEND`)**: TCP micro-outage drops outbound `MsgSeqNum 34=105..107` on `WEX_DMA -> CME_GW`. When `34=108` (`NewOrderSingle 35=D`) arrives, `CME_GW` sends `ResendRequest (35=2, 7=105, 16=0)`. `WEX_DMA` responds with `SequenceReset-GapFill (35=4, 123=Y, 36=108)` for admin messages and resolves the gap.
2. **`INC-102` (`CANCEL_FILL_RACE`)**: Trader sends `NewOrderSingle (35=D, 11=ORD-8821, 55=AAPL, 54=1, 38=500, 44=225.50)`. Exchange acknowledges (`35=8, 150=0, 39=0`) and then fills all 500 shares (`35=8, 17=EXEC-01, 150=2, 39=2, 32=500, 31=225.50, 14=500, 151=0`). 2ms later, trader's `OrderCancelRequest (35=F, 11=CXL-8821, 41=ORD-8821)` hits the exchange, which replies with `OrderCancelReject (35=9, 11=CXL-8821, 41=ORD-8821, 39=2, 102=0 TooLateToCancel)`. Engine must preserve `OrdStatus=Filled`, calculate `Decimal("112750.00")` exposure, and set `safe_to_resend=False`.
3. **`INC-103` (`IN_FLIGHT_GATEWAY_TIMEOUT`)**: `NewOrderSingle (35=D, 11=ORD-9040, 55=NVDA, 54=1, 38=1000, 44=138.40)` passes internal Risk and is transmitted by `FIX_GATEWAY`, followed by a gateway SLA timeout event with zero inbound `35=8` from `NASDAQ_GW`. Engine must set `is_in_flight_unknown=True`, `safe_to_resend=False`, `exposure_dollars=Decimal("138400.00")`, and include an explicit unknown stating that exchange receipt/execution cannot be determined from current telemetry.
4. **`INC-104` (`PROTOCOL_OR_RISK_REJECT`)**: Contains two distinct rejected orders on a newly certified link: Order A rejected at the session layer (`35=3, 45=202, 371=44, 372=D, 373=1 RequiredTagMissing`) because a Limit order (`40=2`) omitted `Price (44)`; Order B rejected at the application layer (`35=8, 11=ORD-7702, 150=8, 39=8, 103=3 OrderExceedsLimit`). Engine must distinguish the session protocol bug from the business risk collar reject.
5. **`INC-105` (`DROP_COPY_SQL_RECON_BREAK`)**: Exchange sends a valid `ExecutionReport Fill (35=8, 11=ORD-5510, 17=EXEC-5510, 55=MSFT, 54=1, 150=2, 39=2, 38=500, 32=500, 31=415.20, 14=500, 151=0)`, but a database lock error event occurs on `SQL_DB` and the internal OMS record remains at `status="PendingNew", filled_qty=Decimal("0")`. Engine must detect the 500-share / `Decimal("207600.00")` STP reconciliation break.

## 6. Sprint 1 Completion Gate

Before declaring Sprint 1 complete:
1. Inspect the repository structure and existing changes before modifying files. Preserve unrelated work.
2. Create or update `CLAUDE.md` with the complete project context and these implementation rules.
3. Install declared dependencies (`requirements.txt`) into the active project `.venv`/`venv` without modifying global environments.
4. Implement the deterministic foundation (`backend/fix_protocol.py`, `backend/models.py`, `backend/reconstructor.py`, `backend/simulator.py`) and the test suite (`tests/test_engine.py`).
5. Run `pytest -v`, fix any failures, and rerun the suite.
6. Report the actual test count and result, commands executed, files changed, known limitations, and any behavior reserved for Sprint 2+.
7. Never claim all tests pass unless the test command actually completes with 0 failures.
