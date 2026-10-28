"use client";

import { useState } from "react";
import {
  AudioLines,
  FileImage,
  FileText,
  Inbox,
  Mic2,
  Upload,
  X,
} from "lucide-react";
import type { IncidentListItem, IntakeResult } from "@/lib/types";

type Props = {
  incidents: IncidentListItem[];
  selectedId: string;
  loading: boolean;
  intake: (
    kind: "voice" | "vision" | "fix",
    value: string | File,
  ) => Promise<IntakeResult | void>;
  onSelect: (id: string) => void;
};

const presets = [
  {
    title: "NVDA · order timeout",
    text: "Hey Ops, my 1,000-share NVDA order ORD-9040 on NASDAQ is stuck in Pending New—are we dropped?!",
  },
  {
    title: "AAPL · cancel race",
    text: "Did my cancel on AAPL ORD-8821 go through? I saw a full fill just before the cancel.",
  },
];

function money(value: string) {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
  }).format(Number(value || 0));
}
function severityClass(value: string) {
  return value.toLowerCase() === "critical"
    ? "critical"
    : value.toLowerCase() === "high"
      ? "high"
      : "medium";
}

export function IncidentSidebar({
  incidents,
  selectedId,
  loading,
  intake,
  onSelect,
}: Props) {
  const [tab, setTab] = useState<"voice" | "vision" | "fix">("voice");
  const [text, setText] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [working, setWorking] = useState(false);
  const [lastResult, setLastResult] = useState<IntakeResult | null>(null);
  const [error, setError] = useState("");

  const submit = async (value?: string) => {
    setWorking(true);
    setError("");
    try {
      const input = value ?? file ?? text;
      if (!input) return;
      const result = await intake(tab, input);
      if (result) {
        setLastResult(result);
        if (result.matched_incident_id) onSelect(result.matched_incident_id);
      }
      setText("");
      setFile(null);
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : "Intake failed");
    } finally {
      setWorking(false);
    }
  };

  return (
    <aside className="sidebar panel">
      <div className="panel-heading">
        <div>
          <span className="eyebrow">OPERATIONS</span>
          <h2>Incident queue</h2>
        </div>
        <span className="count-chip">
          {incidents.length.toString().padStart(2, "0")}
        </span>
      </div>
      <div className="incident-list">
        {loading && incidents.length === 0 ? (
          <div className="empty-state">Connecting to incident store…</div>
        ) : (
          incidents.map((incident) => (
            <button
              key={incident.incident_id}
              onClick={() => onSelect(incident.incident_id)}
              className={`incident-card ${selectedId === incident.incident_id ? "selected" : ""}`}
            >
              <div className="incident-card-top">
                <span className="incident-id">{incident.incident_id}</span>
                <span
                  className={`severity ${severityClass(incident.severity)}`}
                >
                  {incident.severity || "monitor"}
                </span>
              </div>
              <div className="incident-title">
                {incident.title.replaceAll("_", " ")}
              </div>
              <div className="incident-card-bottom">
                <span className="failure-category">
                  {incident.primary_failure_category?.replaceAll("_", " ") ||
                    "Awaiting report"}
                </span>
                <span className="incident-exposure">
                  {money(incident.total_exposure_dollars)}
                </span>
              </div>
            </button>
          ))
        )}
        {!loading && incidents.length === 0 && (
          <div className="empty-state">
            No incidents loaded. Seed the canonical scenarios to begin.
          </div>
        )}
      </div>

      <div className="intake-heading">
        <div>
          <span className="eyebrow">EVIDENCE IN</span>
          <h2>Desk intake</h2>
        </div>
        <Inbox size={16} />
      </div>
      <div className="intake-tabs">
        <button
          className={tab === "voice" ? "active" : ""}
          onClick={() => {
            setTab("voice");
            setLastResult(null);
          }}
        >
          <Mic2 size={13} />
          Voice
        </button>
        <button
          className={tab === "vision" ? "active" : ""}
          onClick={() => {
            setTab("vision");
            setLastResult(null);
          }}
        >
          <FileImage size={13} />
          Vision
        </button>
        <button
          className={tab === "fix" ? "active" : ""}
          onClick={() => {
            setTab("fix");
            setLastResult(null);
          }}
        >
          <FileText size={13} />
          Raw FIX
        </button>
      </div>
      {tab === "voice" && (
        <div className="intake-content">
          <div className="micro-label">
            <AudioLines size={13} /> MUSE VOICE TRANSCRIBE
          </div>
          <div className="preset-list">
            {presets.map((preset) => (
              <button
                key={preset.title}
                className="preset-button"
                onClick={() => {
                  setText(preset.text);
                  void submit(preset.text);
                }}
              >
                {preset.title}
                <span>↗</span>
              </button>
            ))}
          </div>
          <textarea
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder="Type a desk squawk or paste a transcript…"
            rows={3}
          />
          <div className="intake-actions">
            <label className="upload-button">
              <Upload size={13} /> Audio
              <input
                type="file"
                accept="audio/*"
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                hidden
              />
            </label>
            <button
              className="mini-submit"
              disabled={working || (!text && !file)}
              onClick={() => void submit()}
            >
              {working ? "TRANSCRIBING…" : "ANALYZE SQUAWK"}
            </button>
          </div>
        </div>
      )}
      {tab === "vision" && (
        <div className="intake-content">
          <div className="micro-label">
            <FileImage size={13} /> MUSE SPARK VISION
          </div>
          <div className="preset-list">
            <button
              className="preset-button"
              onClick={() => {
                setText(
                  "Blotter alert · ORD-5510 · MSFT · 500 filled · OMS PendingNew · SQL database locked",
                );
                void submit(
                  "Blotter alert · ORD-5510 · MSFT · 500 filled · OMS PendingNew · SQL database locked",
                );
              }}
            >
              MSFT · SQL lock alert <span>↗</span>
            </button>
            <button
              className="preset-button"
              onClick={() => {
                setText(
                  "Order blotter · ORD-9040 · NVDA · Pending New · FIX gateway timeout",
                );
                void submit(
                  "Order blotter · ORD-9040 · NVDA · Pending New · FIX gateway timeout",
                );
              }}
            >
              NVDA · gateway timeout <span>↗</span>
            </button>
          </div>
          <textarea
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder="Describe visible blotter or Grafana text…"
            rows={3}
          />
          <div className="intake-actions">
            <label className="upload-button">
              <Upload size={13} /> Screenshot
              <input
                type="file"
                accept="image/*"
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
                hidden
              />
            </label>
            <button
              className="mini-submit"
              disabled={working || (!text && !file)}
              onClick={() => void submit()}
            >
              {working ? "ANALYZING…" : "TRIAGE IMAGE"}
            </button>
          </div>
        </div>
      )}
      {tab === "fix" && (
        <div className="intake-content">
          <div className="micro-label">
            <FileText size={13} /> FIX LOG INGEST
          </div>
          <textarea
            className="fix-input"
            value={text}
            onChange={(event) => setText(event.target.value)}
            placeholder={
              "Paste complete FIX lines (pipe or SOH), one per line…\n8=FIX.4.2|9=...|35=8|...|10=XXX|"
            }
            rows={6}
          />
          <div className="intake-actions">
            <span className="tiny-muted">
              Input is validated; no recovery message is sent.
            </span>
            <button
              className="mini-submit"
              disabled={working || !text.trim()}
              onClick={() => void submit()}
            >
              {working ? "PARSING…" : "INGEST LOG"}
            </button>
          </div>
        </div>
      )}
      {error && (
        <div className="intake-error">
          <X size={12} />
          {error}
        </div>
      )}
      {lastResult && (
        <div className="intake-result">
          <div>
            <span className="result-check">✓</span> {lastResult.model_used}
          </div>
          <p>{lastResult.extracted_text || "No text extracted from upload."}</p>
          <div className="result-tags">
            {lastResult.extracted_cl_ord_ids.map((id) => (
              <span key={id}>{id}</span>
            ))}
            {lastResult.extracted_symbols.map((symbol) => (
              <span key={symbol}>{symbol}</span>
            ))}
          </div>
          {lastResult.matched_incident_id && (
            <button onClick={() => onSelect(lastResult.matched_incident_id!)}>
              OPEN {lastResult.matched_incident_id} →
            </button>
          )}
        </div>
      )}
    </aside>
  );
}
