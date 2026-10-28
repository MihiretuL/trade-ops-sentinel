import {
  ArrowRight,
  Database,
  Network,
  RadioTower,
  ShieldCheck,
} from "lucide-react";
import type { DeterministicReport, SubwayNode } from "@/lib/types";

const descriptors = [
  { title: "TRADER DESK / OMS", icon: Database },
  { title: "PRE-TRADE RISK", icon: ShieldCheck },
  { title: "FIX GATEWAY / TCP", icon: Network },
  { title: "EXCHANGE ENGINE", icon: RadioTower },
];

function stateFor(
  node: SubwayNode | undefined,
  report: DeterministicReport,
): { state: string; caption: string } {
  const name = node?.name.toLowerCase() || "";
  if (name.includes("oms"))
    return report.reconciliation_breaks.length
      ? { state: "FAIL", caption: "SQL_DB lock · recon break" }
      : { state: "OK", caption: "Order state reconstructed" };
  if (name.includes("risk"))
    return report.primary_failure_category === "protocol_and_risk_reject"
      ? { state: "FAIL", caption: "OrderExceedsLimit · 103=3" }
      : report.primary_failure_category === "in_flight_unknown"
        ? { state: "OK", caption: "Pre-trade risk pass" }
        : { state: "OK", caption: "No risk block observed" };
  if (name.includes("gateway"))
    return report.primary_failure_category === "sequence_gap_resend"
      ? { state: "WARN", caption: "TCP sequence gap · 105–107" }
      : report.primary_failure_category === "protocol_and_risk_reject"
        ? { state: "FAIL", caption: "Session reject · tag 44 missing" }
        : report.primary_failure_category === "in_flight_unknown"
          ? { state: "WARN", caption: "Gateway SLA timeout" }
          : { state: "OK", caption: "FIX session evidence" };
  if (report.is_in_flight_unknown)
    return { state: "UNKNOWN", caption: "Receipt / execution unknown" };
  if (report.primary_failure_category === "cancel_fill_race")
    return { state: "OK", caption: "Filled · cancel too late" };
  if (report.primary_failure_category === "drop_copy_sql_reconciliation")
    return { state: "OK", caption: "500 MSFT shares filled" };
  if (report.primary_failure_category === "protocol_and_risk_reject")
    return { state: "FAIL", caption: "Application risk reject" };
  return { state: "WARN", caption: "GapFill seen · ack not observed" };
}

export function SubwayPipelineMap({
  report,
}: {
  report: DeterministicReport | null;
}) {
  return (
    <section className="panel pipeline-panel">
      <div className="panel-heading compact">
        <div>
          <span className="eyebrow">ORDER ROUTE</span>
          <h2>Pipeline health</h2>
        </div>
        <span className="pipeline-context">4 CONTROL POINTS</span>
      </div>
      <div className="pipeline-track">
        {descriptors.map((descriptor, index) => {
          const node = report?.subway_map_status.find((item) =>
            item.name
              .toLowerCase()
              .includes(["oms", "risk", "gateway", "exchange"][index]),
          );
          const state = report
            ? stateFor(node, report)
            : { state: "IDLE", caption: "Awaiting incident evidence" };
          const Icon = descriptor.icon;
          return (
            <div key={descriptor.title} className="pipeline-step-wrap">
              <div className={`pipeline-node ${state.state.toLowerCase()}`}>
                <div className="pipeline-node-top">
                  <span className="node-index">0{index + 1}</span>
                  <span className={`node-state ${state.state.toLowerCase()}`}>
                    {state.state}
                  </span>
                </div>
                <div className="pipeline-icon">
                  <Icon size={18} />
                </div>
                <strong>{descriptor.title}</strong>
                <span className="pipeline-caption">{state.caption}</span>
              </div>
              {index < descriptors.length - 1 && (
                <div className="pipeline-connector">
                  <ArrowRight size={14} />
                </div>
              )}
            </div>
          );
        })}
      </div>
    </section>
  );
}
