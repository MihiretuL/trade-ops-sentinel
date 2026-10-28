import {
  AlertOctagon,
  ArrowDownRight,
  ShieldAlert,
  ShieldCheck,
  TrendingUp,
} from "lucide-react";
import type { DeterministicReport } from "@/lib/types";

function money(value: string) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
  }).format(Number(value || 0));
}

export function ImpactBanner({
  report,
}: {
  report: DeterministicReport | null;
}) {
  if (!report)
    return (
      <section className="impact-banner impact-empty">
        <div>
          <span className="eyebrow">POSITION SAFETY</span>
          <h2>Select an incident to reconstruct exposure</h2>
          <p>
            Verified state and retry safety appear here—never inferred from a
            timeout alone.
          </p>
        </div>
        <ShieldCheck size={26} />
      </section>
    );
  const filled = Object.values(report.order_statuses).some(
    (status) => status === "filled",
  );
  const reason = filled
    ? "Order is already filled — duplicate execution risk"
    : report.is_in_flight_unknown
      ? "Exchange state is in-flight unknown — acknowledgment not observed"
      : report.primary_failure_category === "sequence_gap_resend"
        ? "Sequence recovery observed; order acknowledgment remains unknown"
        : "No evidence-backed resolution path authorizes a resend";
  return (
    <section
      className={`impact-banner ${report.safe_to_resend ? "safe" : "unsafe"}`}
    >
      <div className="impact-copy">
        <div className="eyebrow">
          <TrendingUp size={12} /> POSITION SAFETY INTERLOCK{" "}
          <span className="impact-dot" /> {report.severity.toUpperCase()}{" "}
          SEVERITY
        </div>
        <div className="impact-value">
          {money(report.total_exposure_dollars)} <span>EXPOSURE</span>
        </div>
        <p>{report.summary}</p>
      </div>
      <div
        className={`safety-interlock ${report.safe_to_resend ? "safe" : "unsafe"} `}
      >
        <div className="interlock-icon">
          {report.safe_to_resend ? (
            <ShieldCheck size={21} />
          ) : (
            <ShieldAlert size={21} />
          )}
        </div>
        <div>
          <strong>
            {report.safe_to_resend
              ? "SAFE TO RETRY AFTER FIX"
              : "DO NOT RESEND"}
          </strong>
          <span>{reason}</span>
        </div>
        {report.safe_to_resend ? (
          <ArrowDownRight size={17} />
        ) : (
          <AlertOctagon size={17} />
        )}
      </div>
      <div className="impact-orders">
        {Object.entries(report.order_statuses).map(([id, status]) => (
          <div key={id}>
            <span>{id}</span>
            <b
              className={
                status === "filled"
                  ? "text-green"
                  : status === "rejected"
                    ? "text-red"
                    : "text-amber"
              }
            >
              {status.replaceAll("_", " ").toUpperCase()}
            </b>
          </div>
        ))}
      </div>
    </section>
  );
}
