# TradeOps Sentinel

Deterministic FIX protocol and incident reconstruction core for electronic trading operations. Sprint 1 runs offline: no API credentials, database service, or network connection is required.

## Sprint 1

- FIX 4.2/4.4 parser and builder with SOH/pipe support and byte-accurate BodyLength/CheckSum validation.
- Directional session sequence tracking, duplicate ExecID protection, and Decimal-based order lifecycle reconstruction.
- Five stable demo incidents (`INC-101`–`INC-105`), including sequence gaps, duplicate executions, cancel/replace lineage, and unknown exchange exposure.

## Setup and tests

Install dependencies from `requirements.txt`, then run `pytest -v` from the repository root.

Example fixture loading is available through `backend.simulator.all_incidents()` and `backend.simulator.get_incident("INC-105")`.
