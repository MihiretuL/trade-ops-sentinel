# TradeOps Sentinel

Deterministic FIX protocol and incident reconstruction core for electronic trading operations. Sprint 1 runs offline: no API credentials, database service, or network connection is required.

## Sprint 1

- FIX 4.2/4.4 parser and builder with SOH/pipe support and byte-accurate BodyLength/CheckSum validation.
- Directional session sequence tracking, duplicate ExecID protection, and Decimal-based order lifecycle reconstruction.
- Five stable demo incidents (`INC-101`–`INC-105`), including sequence gaps, duplicate executions, cancel/replace lineage, and unknown exchange exposure.

## Setup and tests

Install dependencies from `requirements.txt`, then run `pytest -v` from the repository root.

Example fixture loading is available through `backend.simulator.all_incidents()` and `backend.simulator.get_incident("INC-105")`.

## Local full-stack demo

1. In a terminal at the repository root, activate the Python environment and run `uvicorn backend.main:app --reload --host 127.0.0.1 --port 8000`.
2. In another terminal, copy `frontend/.env.example` to `frontend/.env.local` if you need to override the defaults. The default API and WebSocket URLs target `127.0.0.1:8000`.
3. From `frontend/`, run `npm install` once and then `npm run dev`. Open `http://localhost:3000`.
4. The dashboard seeds the five canonical incidents on initial load if the SQLite store is empty. Use the chaos controls to simulate a local TCP loopback, and run the verified AI investigation to view grounded claims and read-only recovery suggestions.

Production frontend validation: from `frontend/`, run `npm run typecheck`, `npm run lint`, and `npm run build`.
