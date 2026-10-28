"use client";

import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  Radio,
  ShieldCheck,
  Wifi,
} from "lucide-react";

const scenarios = [
  { id: "INC-101", label: "SEQ GAP", icon: "01" },
  { id: "INC-102", label: "CANCEL / FILL", icon: "02" },
  { id: "INC-103", label: "SILENT TIMEOUT", icon: "03" },
  { id: "INC-104", label: "CERT / RISK", icon: "04" },
  { id: "INC-105", label: "SQL RECON", icon: "05" },
];

type Props = {
  selectedId: string;
  connected: boolean;
  busy: string | null;
  onSimulate: (id: string) => void;
  onInvestigate: () => void;
};

export function ChaosInjectorBar({
  selectedId,
  connected,
  busy,
  onSimulate,
  onInvestigate,
}: Props) {
  return (
    <header className="top-shell">
      <div className="brand-block">
        <div className="brand-mark">
          <Activity size={19} strokeWidth={2.5} />
        </div>
        <div>
          <div className="brand-title">
            TRADEOPS <span>SENTINEL</span>
          </div>
          <div className="brand-subtitle">
            FIX 4.2 / 4.4 <i /> Deterministic + Verifiable Incident Engine
          </div>
        </div>
      </div>
      <div className="header-meta">
        <div className={`connection-pill ${connected ? "good" : "bad"}`}>
          <span className="pulse-dot" />
          {connected ? "BACKEND LIVE" : "BACKEND OFFLINE"}
        </div>
        <div className="ai-model-pill">
          <BrainCircuit size={14} /> MUSE SPARK OPEN <span>·</span> VOICE{" "}
          <span>·</span> VISION <span>·</span> CODE
        </div>
      </div>
      <div className="injector-row">
        <div className="injector-label">
          <Radio size={14} />
          <span>CHAOS CONTROL</span>
          <small>LOCAL TCP DIGITAL TWIN</small>
        </div>
        <div className="scenario-buttons">
          {scenarios.map((scenario) => (
            <button
              key={scenario.id}
              className={`scenario-button ${selectedId === scenario.id ? "active" : ""}`}
              disabled={!connected || busy !== null}
              onClick={() => onSimulate(scenario.id)}
              title={`Inject ${scenario.id}`}
            >
              <span className="scenario-num">{scenario.icon}</span>
              <span>{scenario.label}</span>
            </button>
          ))}
        </div>
        <button
          className="investigate-button"
          disabled={!connected || busy !== null}
          onClick={onInvestigate}
        >
          {busy === "investigate" ? (
            <span className="spinner" />
          ) : (
            <ShieldCheck size={15} />
          )}
          {busy === "investigate" ? "VERIFYING" : "RUN META AI INVESTIGATION"}
        </button>
      </div>
      {!connected && (
        <div className="backend-hint">
          <AlertTriangle size={13} /> Start the FastAPI backend on
          127.0.0.1:8000 to enable live controls.
        </div>
      )}
      {busy?.startsWith("simulate") && (
        <div className="simulating-ribbon">
          <Wifi size={13} /> Opening loopback FIX session · transmitting
          SOH-framed messages
        </div>
      )}
    </header>
  );
}
