"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { Activity, AlertTriangle, Clock3, Layers3, Zap } from "lucide-react";
import { ChaosInjectorBar } from "@/components/ChaosInjectorBar";
import { EvidenceDiagnosis } from "@/components/EvidenceDiagnosis";
import { FixWireStream } from "@/components/FixWireStream";
import { ImpactBanner } from "@/components/ImpactBanner";
import { IncidentSidebar } from "@/components/IncidentSidebar";
import { SubwayPipelineMap } from "@/components/SubwayPipelineMap";
import { api, WS_URL } from "@/lib/api";
import type {
  AIDiagnosis,
  DeterministicReport,
  IncidentDetail,
  IncidentListItem,
  IntakeResult,
} from "@/lib/types";

export default function Home() {
  const [incidents, setIncidents] = useState<IncidentListItem[]>([]);
  const [selectedId, setSelectedId] = useState("INC-103");
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [diagnosis, setDiagnosis] = useState<AIDiagnosis | null>(null);
  const [connected, setConnected] = useState(false);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState<string | null>(null);
  const [aiBusy, setAiBusy] = useState(false);
  const [toast, setToast] = useState("");
  const [lastUpdated, setLastUpdated] = useState<Date | null>(null);
  const [focusEventId, setFocusEventId] = useState<string | null>(null);
  const wsRef = useRef<WebSocket | null>(null);

  const notify = useCallback((message: string) => {
    setToast(message);
    window.setTimeout(() => setToast(""), 3500);
  }, []);

  const loadIncidents = useCallback(async () => {
    try {
      let items = await api.incidents();
      if (items.length === 0) {
        await api.seed();
        items = await api.incidents();
      }
      setIncidents(items);
      setConnected(true);
      setLastUpdated(new Date());
      if (!items.some((item) => item.incident_id === selectedId) && items[0])
        setSelectedId(items[0].incident_id);
    } catch (error) {
      setConnected(false);
      notify(
        error instanceof Error
          ? `Backend unavailable: ${error.message}`
          : "Backend unavailable",
      );
    } finally {
      setLoading(false);
    }
  }, [notify, selectedId]);

  const loadDetail = useCallback(
    async (incidentId: string) => {
      try {
        const next = await api.incident(incidentId);
        setDetail(next);
        setDiagnosis(next.ai_diagnosis ?? null);
        setLastUpdated(new Date());
      } catch (error) {
        setDetail(null);
        setDiagnosis(null);
        notify(
          error instanceof Error
            ? error.message
            : "Unable to load incident evidence",
        );
      }
    },
    [notify],
  );

  useEffect(() => {
    const timer = window.setTimeout(() => {
      void loadIncidents();
    }, 0);
    return () => window.clearTimeout(timer);
  }, [loadIncidents]);
  useEffect(() => {
    if (!selectedId) return;
    const timer = window.setTimeout(() => {
      void loadDetail(selectedId);
    }, 0);
    return () => window.clearTimeout(timer);
  }, [selectedId, loadDetail]);

  useEffect(() => {
    let reconnectTimer: number | undefined;
    let disposed = false;
    const connect = () => {
      if (disposed) return;
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;
      ws.onopen = () => setConnected(true);
      ws.onmessage = (event) => {
        try {
          const payload = JSON.parse(event.data) as {
            type: string;
            incident_id: string;
            event?: unknown;
            report?: DeterministicReport;
            diagnosis?: AIDiagnosis;
          };
          if (
            payload.type === "telemetry_event" &&
            payload.incident_id === selectedId
          ) {
            void loadDetail(selectedId);
            setLastUpdated(new Date());
          }
          if (
            payload.type === "investigation_update" &&
            payload.incident_id === selectedId &&
            payload.report
          ) {
            setDetail((current) =>
              current ? { ...current, report: payload.report! } : current,
            );
            void loadIncidents();
          }
          if (
            payload.type === "ai_diagnosis" &&
            payload.incident_id === selectedId &&
            payload.diagnosis
          )
            setDiagnosis(payload.diagnosis);
        } catch {
          /* HTTP detail remains authoritative if a stream packet is malformed. */
        }
      };
      ws.onclose = () => {
        setConnected(false);
        if (!disposed) reconnectTimer = window.setTimeout(connect, 2500);
      };
      ws.onerror = () => ws.close();
    };
    connect();
    return () => {
      disposed = true;
      if (reconnectTimer) window.clearTimeout(reconnectTimer);
      wsRef.current?.close();
    };
  }, [selectedId, loadDetail, loadIncidents]);

  const simulate = async (id: string) => {
    setSelectedId(id);
    setBusy(`simulate:${id}`);
    setDiagnosis(null);
    try {
      const response = await api.simulate(id);
      await loadIncidents();
      await loadDetail(id);
      notify(
        `${id} traversed the local TCP loopback · ${response.captured_events} evidence events captured`,
      );
    } catch (error) {
      notify(error instanceof Error ? error.message : "TCP simulation failed");
    } finally {
      setBusy(null);
    }
  };

  const investigate = async () => {
    if (!selectedId) return;
    setAiBusy(true);
    setBusy("investigate");
    try {
      const result = await api.investigate(selectedId);
      setDiagnosis(result);
      await loadDetail(selectedId);
      notify(
        `Evidence verified · ${result.tool_calls_executed.length} deterministic tools executed`,
      );
    } catch (error) {
      notify(error instanceof Error ? error.message : "Investigation failed");
    } finally {
      setAiBusy(false);
      setBusy(null);
    }
  };

  const intake = async (
    kind: "voice" | "vision" | "fix",
    value: string | File,
  ): Promise<IntakeResult | void> => {
    if (kind === "fix") {
      if (typeof value !== "string") return;
      const response = await api.ingestFix(value);
      const id = response.report.incident_id;
      await loadIncidents();
      setSelectedId(id);
      await loadDetail(id);
      notify(
        `Custom FIX incident ${id} reconstructed from validated wire evidence`,
      );
      return;
    }
    const response =
      kind === "voice"
        ? typeof value === "string"
          ? await api.voice(value)
          : await api.voiceFile(value)
        : typeof value === "string"
          ? await api.screenshot(value)
          : await api.screenshotFile(value);
    if (response.intake.matched_incident_id) {
      setSelectedId(response.intake.matched_incident_id);
      await loadDetail(response.intake.matched_incident_id);
      notify(`Intake matched ${response.intake.matched_incident_id}`);
    } else
      notify(
        "Intake processed · no stored incident matched the extracted identifiers",
      );
    return response.intake;
  };

  const report = detail?.report ?? null;
  const selectedSummary = incidents.find(
    (incident) => incident.incident_id === selectedId,
  );

  return (
    <main className="terminal-root">
      <ChaosInjectorBar
        selectedId={selectedId}
        connected={connected}
        busy={busy}
        onSimulate={(id) => void simulate(id)}
        onInvestigate={() => void investigate()}
      />
      <div className="dashboard-grid">
        <IncidentSidebar
          incidents={incidents}
          selectedId={selectedId}
          loading={loading}
          intake={intake}
          onSelect={setSelectedId}
        />
        <div className="center-column">
          <div className="workspace-heading">
            <div>
              <span className="eyebrow">LIVE INCIDENT WORKSPACE</span>
              <h1>
                {selectedSummary?.title.replaceAll("_", " ") ??
                  "Trading operations overview"}
                <span className="selected-code">{selectedId}</span>
              </h1>
            </div>
            <div className="workspace-state">
              <span>
                <i />{" "}
                {detail ? "DETERMINISTIC STATE BUILT" : "AWAITING EVIDENCE"}
              </span>
              <small>
                <Clock3 size={11} /> UPDATED{" "}
                {lastUpdated?.toLocaleTimeString("en-US", { hour12: false }) ??
                  "--:--:--"}
              </small>
            </div>
          </div>
          <ImpactBanner report={report} />
          <SubwayPipelineMap report={report} />
          <FixWireStream
            detail={detail}
            report={report}
            focusEventId={focusEventId}
            onFocusEvent={(id) => {
              setFocusEventId(id);
              window.setTimeout(
                () =>
                  document
                    .getElementById(`event-${id}`)
                    ?.scrollIntoView({ behavior: "smooth", block: "center" }),
                30,
              );
            }}
          />
          <div className="footer-status">
            <div>
              <Activity size={13} />
              <span>DETERMINISTIC ENGINE</span>
              <b>ACTIVE</b>
            </div>
            <div>
              <Layers3 size={13} />
              <span>LOCAL DIGITAL TWIN</span>
              <b>NO EXTERNAL EXCHANGE CONNECTION</b>
            </div>
            <div>
              <Zap size={13} />
              <span>EVIDENCE EVENTS</span>
              <b>{detail?.telemetry_events.length ?? 0}</b>
            </div>
          </div>
        </div>
        <EvidenceDiagnosis
          diagnosis={diagnosis}
          report={report}
          busy={aiBusy}
          onInvestigate={() => void investigate()}
          onFocusEvent={(id) => {
            setFocusEventId(id);
            window.setTimeout(
              () =>
                document
                  .getElementById(`event-${id}`)
                  ?.scrollIntoView({ behavior: "smooth", block: "center" }),
              30,
            );
          }}
        />
      </div>
      {toast && (
        <div className="toast-message">
          <AlertTriangle size={14} />
          {toast}
        </div>
      )}
    </main>
  );
}
