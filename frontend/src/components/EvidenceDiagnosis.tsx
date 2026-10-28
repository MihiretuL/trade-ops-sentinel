"use client";

import { useState } from "react";
import {
  BadgeCheck,
  Bot,
  Check,
  Clipboard,
  ClipboardCheck,
  Copy,
  ExternalLink,
  LockKeyhole,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
} from "lucide-react";
import type { AIDiagnosis, DeterministicReport } from "@/lib/types";

type Props = {
  diagnosis: AIDiagnosis | null;
  report: DeterministicReport | null;
  busy: boolean;
  onInvestigate: () => void;
  onFocusEvent: (id: string) => void;
};
async function copyText(value: string) {
  await navigator.clipboard.writeText(value);
}

export function EvidenceDiagnosis({
  diagnosis,
  report,
  busy,
  onInvestigate,
  onFocusEvent,
}: Props) {
  const [copied, setCopied] = useState<string | null>(null);
  const copy = async (id: string, value: string) => {
    try {
      await copyText(value);
      setCopied(id);
      window.setTimeout(() => setCopied(null), 1500);
    } catch {
      setCopied(null);
    }
  };
  return (
    <section className="panel diagnosis-panel">
      <div className="panel-heading compact">
        <div>
          <span className="eyebrow">VERIFIABLE AI</span>
          <h2>Investigator</h2>
        </div>
        <button
          className="refresh-button"
          disabled={!report || busy}
          onClick={onInvestigate}
          title="Run or refresh investigation"
        >
          {busy ? <span className="spinner" /> : <RefreshCw size={14} />}
        </button>
      </div>
      {!diagnosis && (
        <div className="ai-empty">
          <div className="ai-orb">
            <Bot size={23} />
          </div>
          <h3>Evidence first. Model second.</h3>
          <p>
            Four deterministic inspection tools establish the ground truth
            before the Meta model is allowed to summarize it.
          </p>
          <div className="tool-preview">
            {[
              "inspect_fix_session",
              "trace_order_chain",
              "check_network_telemetry",
              "reconcile_oms_sql",
            ].map((tool) => (
              <span key={tool}>
                <Check size={11} />
                {tool}
              </span>
            ))}
          </div>
          <button
            disabled={!report || busy}
            className="primary-wide"
            onClick={onInvestigate}
          >
            <Sparkles size={14} />
            {busy ? "VERIFYING EVIDENCE…" : "RUN VERIFIED INVESTIGATION"}
          </button>
        </div>
      )}
      {diagnosis && (
        <div className="diagnosis-content">
          <div
            className={`firewall-badge ${diagnosis.verification_passed ? "passed" : "warning"}`}
          >
            <div className="firewall-icon">
              {diagnosis.verification_passed ? (
                <ShieldCheck size={17} />
              ) : (
                <ShieldAlert size={17} />
              )}
            </div>
            <div>
              <strong>
                {diagnosis.verification_passed
                  ? "HALLUCINATION FIREWALL · VERIFIED"
                  : "VERIFICATION WARNINGS"}
              </strong>
              <span>{diagnosis.model_used}</span>
            </div>
            <BadgeCheck size={15} />
          </div>
          <div className="tool-calls">
            <div className="micro-label">DETERMINISTIC TOOLS EXECUTED</div>
            <div className="tool-badges">
              {diagnosis.tool_calls_executed.map((tool) => (
                <span key={tool}>
                  <Check size={10} />
                  {tool}
                </span>
              ))}
            </div>
          </div>
          {diagnosis.verification_warnings.length > 0 && (
            <div className="verification-warning">
              {diagnosis.verification_warnings.map((warning, index) => (
                <p key={`${index}-${warning}`}>{warning}</p>
              ))}
            </div>
          )}
          <div className="diagnosis-summary">
            <div className="micro-label">EXECUTIVE SUMMARY</div>
            <p>{diagnosis.executive_summary}</p>
          </div>
          <div className="stakeholder-card squawk-card">
            <div className="stakeholder-head">
              <span>🎙️ 10-SECOND TRADER SQUAWK</span>
              <button
                aria-label="Copy squawk update"
                onClick={() =>
                  void copy("squawk", diagnosis.trader_squawk_update)
                }
              >
                {copied === "squawk" ? (
                  <ClipboardCheck size={13} />
                ) : (
                  <Copy size={13} />
                )}
              </button>
            </div>
            <p>{diagnosis.trader_squawk_update}</p>
          </div>
          <div className="stakeholder-card engineering-card">
            <div className="stakeholder-head">
              <span>🛠️ ENGINEERING ESCALATION</span>
              <button
                aria-label="Copy engineering summary"
                onClick={() =>
                  void copy(
                    "engineering",
                    diagnosis.engineering_escalation_summary,
                  )
                }
              >
                {copied === "engineering" ? (
                  <ClipboardCheck size={13} />
                ) : (
                  <Copy size={13} />
                )}
              </button>
            </div>
            <p>{diagnosis.engineering_escalation_summary}</p>
          </div>
          <div className="proven-section">
            <div className="section-label">
              <span>PROVEN CLAIMS</span>
              <span>{diagnosis.proven_claims.length}</span>
            </div>
            {diagnosis.proven_claims.length ? (
              diagnosis.proven_claims.map((claim, index) => (
                <div className="claim-card" key={`${claim.event_id}-${index}`}>
                  <p>{claim.claim}</p>
                  <div className="citation-pills">
                    <button
                      className="citation-event"
                      onClick={() => onFocusEvent(claim.event_id)}
                    >
                      <ExternalLink size={10} />[{claim.event_id}]
                    </button>
                    {claim.fix_tags.map((tag) => (
                      <button
                        key={tag}
                        className="citation-tag"
                        onClick={() => onFocusEvent(claim.event_id)}
                      >
                        Tag {tag}
                      </button>
                    ))}
                  </div>
                </div>
              ))
            ) : (
              <div className="no-break">No verified claims returned.</div>
            )}
          </div>
          {diagnosis.ranked_hypotheses.map((hypothesis, index) => (
            <div
              className="hypothesis-card"
              key={`${hypothesis.hypothesis}-${index}`}
            >
              <div>
                <span
                  className={`confidence ${hypothesis.confidence.toLowerCase()}`}
                >
                  {hypothesis.confidence} CONFIDENCE
                </span>
                <p>{hypothesis.hypothesis}</p>
              </div>
              {hypothesis.ruled_out_alternatives.length > 0 && (
                <small>
                  Not established:{" "}
                  {hypothesis.ruled_out_alternatives.join(" · ")}
                </small>
              )}
            </div>
          ))}
          <div className="unknown-box">
            <div className="unknown-title">
              <ShieldAlert size={14} /> EXPLICIT UNKNOWNS · DO NOT INFER
            </div>
            {diagnosis.explicit_unknowns.length ? (
              <ul>
                {diagnosis.explicit_unknowns.map((unknown) => (
                  <li key={unknown}>{unknown}</li>
                ))}
              </ul>
            ) : (
              <p>No unresolved unknowns reported.</p>
            )}
          </div>
          <div className="remediation-section">
            <div className="section-label">
              <span>MUSE CODE · READ-ONLY</span>
              <span>{diagnosis.remediation_artifacts.length}</span>
            </div>
            {diagnosis.remediation_artifacts.map((artifact, index) => (
              <div className="artifact-card" key={`${artifact.title}-${index}`}>
                <div className="artifact-head">
                  <div>
                    <strong>{artifact.title}</strong>
                    <span>
                      {artifact.target_system} · {artifact.artifact_type}
                    </span>
                  </div>
                  <button
                    aria-label="Copy read-only remediation"
                    onClick={() =>
                      void copy(`artifact-${index}`, artifact.code_or_command)
                    }
                  >
                    {copied === `artifact-${index}` ? (
                      <ClipboardCheck size={13} />
                    ) : (
                      <Clipboard size={13} />
                    )}
                  </button>
                </div>
                <div className="read-only-lock">
                  <LockKeyhole size={11} /> READ-ONLY · REQUIRES HUMAN ENGINEER
                  APPROVAL
                </div>
                <pre>{artifact.code_or_command}</pre>
                <p>{artifact.safety_warning}</p>
              </div>
            ))}
          </div>
        </div>
      )}
    </section>
  );
}
