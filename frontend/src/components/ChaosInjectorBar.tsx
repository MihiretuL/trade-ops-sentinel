"use client";

import {
  Activity,
  AlertTriangle,
  BrainCircuit,
  BookOpen,
  Flame,
  Radio,
  Send,
  ShieldCheck,
  Wifi,
} from "lucide-react";
import { useState } from "react";
import type { BookSnapshot } from "@/lib/types";

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
  books: BookSnapshot[];
  marketBusy: boolean;
  chaosBusy: boolean;
  onSimulate: (id: string) => void;
  onInvestigate: () => void;
  onMarket: () => void;
  onChaos: (prompt: string) => void;
};

export function ChaosInjectorBar({
  selectedId,
  connected,
  busy,
  books,
  marketBusy,
  chaosBusy,
  onSimulate,
  onInvestigate,
  onMarket,
  onChaos,
}: Props) {
  const [prompt, setPrompt] = useState("");
  const chaosPresets = [
    "Fill 800-share SPY buy, then race its cancel",
    "Drop 3 outbound packets on AAPL during an order burst",
    "Fill a large MSFT order, then lock the OMS SQL commit",
  ];
  const submitChaos = (value = prompt) => {
    if (!value.trim() || chaosBusy) return;
    onChaos(value.trim());
  };
  const formatPrice = (value: string | null) =>
    value === null
      ? "—"
      : `$${Number(value).toLocaleString("en-US", { minimumFractionDigits: 2, maximumFractionDigits: 2 })}`;
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
      <div className="market-strip">
        <div className="market-strip-title">
          <BookOpen size={13} />
          <span>LIVE LIMIT ORDER BOOK</span>
          <small>PRICE-TIME MATCHING</small>
        </div>
        {books
          .filter((book) =>
            ["AAPL", "NVDA", "MSFT", "SPY", "TSLA"].includes(book.symbol),
          )
          .map((book) => (
            <div className="ticker-cell" key={book.symbol}>
              <b>{book.symbol}</b>
              <span className="ticker-bid">{formatPrice(book.best_bid)}</span>
              <i>/</i>
              <span className="ticker-ask">{formatPrice(book.best_ask)}</span>
              <small>LAST {formatPrice(book.last_trade_price)}</small>
            </div>
          ))}
        <button
          className="market-tick-button"
          disabled={!connected || marketBusy}
          onClick={onMarket}
        >
          {marketBusy ? <span className="spinner" /> : <Activity size={13} />}
          {marketBusy ? "MATCHING…" : "SIMULATE LIVE FLOW"}
        </button>
      </div>
      <div className="redteam-bar">
        <div className="redteam-title">
          <Flame size={14} />
          <span>RED-TEAM META AI CHAOS</span>
          <small>UNSCRIPTED · BLUE TEAM BLIND</small>
        </div>
        <div className="chaos-prompt-wrap">
          <input
            value={prompt}
            onChange={(event) => setPrompt(event.target.value)}
            onKeyDown={(event) => {
              if (event.key === "Enter") submitChaos();
            }}
            placeholder="Describe a market or infrastructure fault…"
            maxLength={4000}
          />
          <button
            disabled={!connected || chaosBusy || !prompt.trim()}
            onClick={() => submitChaos()}
          >
            {chaosBusy ? <span className="spinner" /> : <Send size={13} />}
            {chaosBusy ? "INJECTING" : "LAUNCH ATTACK"}
          </button>
        </div>
        <div className="chaos-preset-chips">
          {chaosPresets.map((item) => (
            <button
              key={item}
              disabled={!connected || chaosBusy}
              onClick={() => {
                setPrompt(item);
                submitChaos(item);
              }}
            >
              {item}
            </button>
          ))}
        </div>
      </div>
    </header>
  );
}
