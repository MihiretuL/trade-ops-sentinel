"use client";

import { useEffect, useMemo, useState } from "react";
import {
  ArrowDownLeft,
  ArrowUpRight,
  Check,
  ChevronDown,
  ChevronRight,
  CircleAlert,
  Database,
  Radio,
  Waypoints,
} from "lucide-react";
import type {
  DeterministicReport,
  IncidentDetail,
  TelemetryEvent,
} from "@/lib/types";

const tagNames: Record<string, string> = {
  "8": "BeginString",
  "9": "BodyLength",
  "10": "CheckSum",
  "11": "ClOrdID",
  "14": "CumQty",
  "17": "ExecID",
  "31": "LastPx",
  "32": "LastQty",
  "34": "MsgSeqNum",
  "35": "MsgType",
  "37": "OrderID",
  "39": "OrdStatus",
  "40": "OrdType",
  "41": "OrigClOrdID",
  "43": "PossDupFlag",
  "44": "Price",
  "45": "RefSeqNum",
  "49": "SenderCompID",
  "54": "Side",
  "55": "Symbol",
  "56": "TargetCompID",
  "58": "Text",
  "102": "CxlRejReason",
  "103": "OrdRejReason",
  "123": "GapFillFlag",
  "150": "ExecType",
  "151": "LeavesQty",
  "371": "RefTagID",
  "372": "RefMsgType",
  "373": "SessionRejectReason",
  "7": "BeginSeqNo",
  "16": "EndSeqNo",
  "36": "NewSeqNo",
  "6": "AvgPx",
  "12": "Commission",
  "13": "CommType",
  "15": "Currency",
  "18": "ExecInst",
  "20": "ExecTransType",
  "21": "HandlInst",
  "30": "LastMkt",
  "47": "Rule80A",
  "50": "SenderSubID",
  "57": "TargetSubID",
  "59": "TimeInForce",
  "63": "SettlmntTyp",
  "97": "PossResend",
  "98": "EncryptMethod",
  "108": "HeartBtInt",
  "112": "TestReqID",
  "141": "ResetSeqNumFlag",
  "167": "SecurityType",
  "207": "SecurityExchange",
};
const msgTypes: Record<string, string> = {
  "2": "ResendRequest",
  "3": "SessionReject",
  "4": "SequenceReset",
  "8": "ExecutionReport",
  "9": "OrderCancelReject",
  D: "NewOrderSingle",
  F: "OrderCancelRequest",
  G: "OrderCancelReplaceRequest",
};

type Props = {
  detail: IncidentDetail | null;
  report: DeterministicReport | null;
  focusEventId: string | null;
  onFocusEvent: (id: string) => void;
};
const EMPTY_EVENTS: TelemetryEvent[] = [];

export function FixWireStream({
  detail,
  report,
  focusEventId,
  onFocusEvent,
}: Props) {
  const [tab, setTab] = useState<"wire" | "orders" | "recon">("wire");
  const [expanded, setExpanded] = useState<string | null>(focusEventId);
  const events = detail?.telemetry_events ?? EMPTY_EVENTS;
  useEffect(() => {
    if (!focusEventId) return;
    const timer = window.setTimeout(() => {
      setTab("wire");
      setExpanded(focusEventId);
      document
        .getElementById(`event-${focusEventId}`)
        ?.scrollIntoView({ behavior: "smooth", block: "center" });
    }, 40);
    return () => window.clearTimeout(timer);
  }, [focusEventId]);
  const sequenceGaps = useMemo(() => {
    const groups = new Map<string, TelemetryEvent[]>();
    for (const event of events) {
      if (
        event.parsed_json.kind !== "fix" ||
        event.parsed_json.sequence_number === undefined
      )
        continue;
      const key = `${event.parsed_json.sender_comp_id}:${event.parsed_json.target_comp_id}:${event.direction}`;
      groups.set(key, [...(groups.get(key) ?? []), event]);
    }
    return [...groups.values()].flatMap((group) => {
      const sorted = [...group].sort(
        (a, b) => a.sequence_index - b.sequence_index,
      );
      const result: {
        expected: number;
        actual: number;
        from: string;
        to: string;
      }[] = [];
      for (let i = 1; i < sorted.length; i++) {
        const previous = sorted[i - 1].parsed_json.sequence_number ?? 0;
        const actual = sorted[i].parsed_json.sequence_number ?? 0;
        if (actual > previous + 1)
          result.push({
            expected: previous + 1,
            actual,
            from: sorted[i - 1].event_id,
            to: sorted[i].event_id,
          });
      }
      return result;
    });
  }, [events]);

  const renderEvent = (event: TelemetryEvent) => {
    const isFix = event.parsed_json.kind === "fix";
    const isOpen =
      expanded === event.event_id || focusEventId === event.event_id;
    const tags = event.parsed_json.tags ?? {};
    return (
      <article
        id={`event-${event.event_id}`}
        key={event.event_id}
        className={`event-row ${isOpen ? "expanded" : ""} ${focusEventId === event.event_id ? "citation-target" : ""}`}
      >
        <button
          className="event-summary"
          onClick={() => {
            setExpanded(isOpen ? null : event.event_id);
            onFocusEvent(event.event_id);
          }}
        >
          <span className="event-expand">
            {isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </span>
          <span
            className={`direction-icon ${event.direction === "outbound" ? "out" : "in"}`}
          >
            {event.direction === "outbound" ? (
              <ArrowUpRight size={13} />
            ) : event.direction === "inbound" ? (
              <ArrowDownLeft size={13} />
            ) : (
              <Radio size={13} />
            )}
          </span>
          <span className="event-time">
            {new Date(event.timestamp).toLocaleTimeString("en-US", {
              hour12: false,
              fractionalSecondDigits: 3,
            })}
          </span>
          <span className="event-source">{event.source_layer}</span>
          <span className="event-code">
            {isFix
              ? `${msgTypes[event.parsed_json.msg_type ?? ""] ?? "FIX Message"} · ${event.parsed_json.msg_type}`
              : event.parsed_json.event_type?.replaceAll("_", " ")}
          </span>
          <span className="event-id">{event.event_id}</span>
        </button>
        {isOpen && (
          <div className="event-detail">
            {isFix ? (
              <>
                <div className="wire-line">
                  <span>RAW SOH WIRE</span>
                  <code>{event.raw_payload.replaceAll("\x01", "|")}</code>
                </div>
                <div className="checksum-valid">
                  <Check size={12} /> FIX framing was validated at ingestion ·
                  source delimiter preserved in raw event
                </div>
                <div className="tag-table">
                  <div className="tag-table-head">
                    <span>TAG</span>
                    <span>FIELD</span>
                    <span>VALUE</span>
                  </div>
                  {Object.entries(tags).map(([tag, value]) => (
                    <div key={tag} className="tag-table-row">
                      <b>{tag}</b>
                      <span>
                        {tag === "35"
                          ? `${tagNames[tag]} (${msgTypes[String(value)] ?? value})`
                          : (tagNames[tag] ?? "FIX Field")}
                      </span>
                      <code>{String(value)}</code>
                    </div>
                  ))}
                </div>
              </>
            ) : (
              <pre className="telemetry-detail">
                {JSON.stringify(event.parsed_json, null, 2)}
              </pre>
            )}
          </div>
        )}
      </article>
    );
  };

  return (
    <section className="panel stream-panel">
      <div className="panel-heading compact">
        <div>
          <span className="eyebrow">EVIDENCE WORKBENCH</span>
          <h2>FIX & reconciliation</h2>
        </div>
        <span className="stream-live">
          <i /> LIVE CAPTURE
        </span>
      </div>
      <div className="workbench-tabs">
        <button
          className={tab === "wire" ? "active" : ""}
          onClick={() => setTab("wire")}
        >
          <Radio size={13} /> Wire timeline <span>{events.length}</span>
        </button>
        <button
          className={tab === "orders" ? "active" : ""}
          onClick={() => setTab("orders")}
        >
          <Waypoints size={13} /> Lifecycle / sequence
        </button>
        <button
          className={tab === "recon" ? "active" : ""}
          onClick={() => setTab("recon")}
        >
          <Database size={13} /> OMS vs Drop-Copy{" "}
          <span className={detail?.sql_recon_breaks.length ? "tab-alert" : ""}>
            {detail?.sql_recon_breaks.length ?? 0}
          </span>
        </button>
      </div>
      {tab === "wire" && (
        <div className="event-list">
          {events.length ? (
            events.map(renderEvent)
          ) : (
            <div className="empty-state stream-empty">
              <Radio size={22} />
              Select an incident or inject a TCP scenario to inspect the event
              timeline.
            </div>
          )}
        </div>
      )}
      {tab === "orders" && (
        <div className="lifecycle-view">
          <div className="subsection-title">
            ORDER LIFECYCLE CHAINS{" "}
            <span>
              {Object.keys(report?.order_statuses ?? {}).length} ORDERS
            </span>
          </div>
          {report &&
            Object.entries(report.order_statuses).map(([orderId, status]) => {
              const matching =
                detail?.oms_orders.filter(
                  (order) => order.cl_ord_id === orderId,
                ) ?? [];
              const row = matching[0];
              return (
                <div key={orderId} className="lifecycle-card">
                  <div className="lifecycle-top">
                    <b>{orderId}</b>
                    <span
                      className={`status-tag ${status === "filled" ? "ok" : status === "rejected" ? "fail" : "warn"}`}
                    >
                      {status}
                    </span>
                  </div>
                  <div className="lifecycle-metrics">
                    <span>
                      QTY <b>{row?.order_qty ?? "—"}</b>
                    </span>
                    <span>
                      FILLED <b>{row?.filled_qty ?? "—"}</b>
                    </span>
                    <span>
                      AVG PX <b>{row?.avg_px ?? "—"}</b>
                    </span>
                    <span>
                      CHAIN{" "}
                      <b>
                        {matching.map((item) => item.cl_ord_id).join(" ← ") ||
                          orderId}
                      </b>
                    </span>
                  </div>
                  <div className="chain-evidence">
                    Evidence:{" "}
                    {(
                      report.facts.find((fact) => fact.claim.includes(orderId))
                        ?.event_ids ?? report.event_ids.slice(0, 3)
                    ).map((id) => (
                      <button
                        key={id}
                        onClick={() => {
                          setTab("wire");
                          onFocusEvent(id);
                          setExpanded(id);
                        }}
                      >
                        [{id}]
                      </button>
                    ))}
                  </div>
                </div>
              );
            })}
          <div className="subsection-title gap-title">
            SEQUENCE GAP INSPECTOR <span>{sequenceGaps.length} GAPS</span>
          </div>
          {sequenceGaps.length ? (
            sequenceGaps.map((gap) => (
              <div className="gap-card" key={`${gap.from}-${gap.to}`}>
                <CircleAlert size={15} />
                <div>
                  <b>
                    Expected {gap.expected} · received {gap.actual}
                  </b>
                  <span>
                    Missing MsgSeqNum 34={gap.expected}–{gap.actual - 1}
                  </span>
                </div>
                <button
                  onClick={() => {
                    setTab("wire");
                    onFocusEvent(gap.to);
                    setExpanded(gap.to);
                  }}
                >
                  VIEW EVIDENCE
                </button>
              </div>
            ))
          ) : (
            <div className="no-break">
              No sequence discontinuity inferred from captured ordered events. A
              partial capture may not establish session history.
            </div>
          )}
        </div>
      )}
      {tab === "recon" && (
        <div className="recon-view">
          <div className="subsection-title">
            OMS SQLITE ↔ EXCHANGE DROP-COPY{" "}
            <span>{detail?.sql_recon_breaks.length ?? 0} BREAKS</span>
          </div>
          <div className="recon-grid">
            <div className="table-wrap">
              <div className="recon-table-title">
                OMS ORDERS <span>SQLITE</span>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>CLORDID</th>
                    <th>SYMBOL</th>
                    <th>STATUS</th>
                    <th>FILLED</th>
                    <th>AVG PX</th>
                  </tr>
                </thead>
                <tbody>
                  {detail?.oms_orders.map((order) => (
                    <tr key={order.cl_ord_id}>
                      <td>{order.cl_ord_id}</td>
                      <td>{order.symbol}</td>
                      <td>{order.oms_status}</td>
                      <td>{order.filled_qty}</td>
                      <td>{order.avg_px}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="table-wrap">
              <div className="recon-table-title">
                DROP-COPY EXECUTIONS <span>EXCHANGE EVIDENCE</span>
              </div>
              <table>
                <thead>
                  <tr>
                    <th>EXECID</th>
                    <th>SYMBOL</th>
                    <th>QTY</th>
                    <th>PX</th>
                    <th>NOTIONAL</th>
                  </tr>
                </thead>
                <tbody>
                  {detail?.telemetry_events
                    .filter(
                      (event) =>
                        event.parsed_json.kind === "fix" &&
                        event.parsed_json.msg_type === "8" &&
                        event.parsed_json.tags?.["17"],
                    )
                    .map((event) => {
                      const tags = event.parsed_json.tags ?? {};
                      const notional =
                        Number(tags["32"] ?? 0) * Number(tags["31"] ?? 0);
                      return (
                        <tr
                          key={event.event_id}
                          className={
                            detail.sql_recon_breaks.length
                              ? "recon-row-break"
                              : ""
                          }
                        >
                          <td>{tags["17"]}</td>
                          <td>{tags["55"]}</td>
                          <td>{tags["32"]}</td>
                          <td>{tags["31"]}</td>
                          <td>
                            {new Intl.NumberFormat("en-US", {
                              style: "currency",
                              currency: "USD",
                            }).format(notional)}
                          </td>
                        </tr>
                      );
                    })}
                </tbody>
              </table>
            </div>
          </div>
          {detail?.sql_recon_breaks.map((item) => (
            <div className="recon-break-banner" key={item.cl_ord_id}>
              <CircleAlert size={19} />
              <div>
                <strong>
                  STP RECON BREAK · {item.symbol} · {item.cl_ord_id}
                </strong>
                <span>
                  Exchange recorded {item.drop_copy_filled_qty} shares (
                  {new Intl.NumberFormat("en-US", {
                    style: "currency",
                    currency: "USD",
                  }).format(Number(item.drop_copy_notional))}
                  ) · OMS shows {item.oms_filled_qty} shares / {item.oms_status}
                  .
                </span>
              </div>
              <button
                onClick={() => {
                  setTab("wire");
                  onFocusEvent(item.event_ids[0]);
                  setExpanded(item.event_ids[0]);
                }}
              >
                TRACE FILL
              </button>
            </div>
          ))}
          {!detail?.sql_recon_breaks.length && (
            <div className="no-break">
              No OMS / Drop-Copy quantity mismatch detected in persisted rows.
            </div>
          )}
        </div>
      )}
    </section>
  );
}
