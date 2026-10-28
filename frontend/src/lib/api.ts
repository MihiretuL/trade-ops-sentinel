import type { AIDiagnosis, BookSnapshot, ChaosResponse, IncidentDetail, IncidentListItem, IntakeResult } from "@/lib/types";

export const API_BASE = (process.env.NEXT_PUBLIC_API_BASE_URL || "http://127.0.0.1:8000").replace(/\/$/, "");
export const WS_URL = process.env.NEXT_PUBLIC_WS_URL || "ws://127.0.0.1:8000/ws/stream";

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(`${API_BASE}${path}`, { ...init, cache: "no-store" });
  if (!response.ok) {
    const detail = await response.text();
    throw new Error(detail || `Request failed (${response.status})`);
  }
  return response.json() as Promise<T>;
}

export const api = {
  health: () => request<{ status: string; db_path: string; engine_version: string }>("/api/health"),
  seed: () => request<{ seeded: number; incidents: unknown[] }>("/api/incidents/seed", { method: "POST" }),
  incidents: () => request<IncidentListItem[]>("/api/incidents"),
  incident: (id: string) => request<IncidentDetail>(`/api/incidents/${encodeURIComponent(id)}`),
  simulate: (id: string) => request<{ report: IncidentDetail["report"]; captured_events: number }>(`/api/incidents/${encodeURIComponent(id)}/simulate-tcp`, { method: "POST" }),
  investigate: (id: string) => request<AIDiagnosis>(`/api/incidents/${encodeURIComponent(id)}/investigate`, { method: "POST" }),
  voice: (transcript: string) => request<{ intake: IntakeResult; matched_report: IncidentDetail["report"] | null }>("/api/intake/voice-squawk", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ transcript }) }),
  voiceFile: (file: File) => { const body = new FormData(); body.append("audio", file); return request<{ intake: IntakeResult; matched_report: IncidentDetail["report"] | null }>("/api/intake/voice-squawk", { method: "POST", body }); },
  screenshot: (caption: string) => request<{ intake: IntakeResult; matched_report: IncidentDetail["report"] | null }>("/api/intake/blotter-screenshot", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ caption }) }),
  screenshotFile: (file: File) => { const body = new FormData(); body.append("image", file); return request<{ intake: IntakeResult; matched_report: IncidentDetail["report"] | null }>("/api/intake/blotter-screenshot", { method: "POST", body }); },
  ingestFix: (raw: string) => request<{ report: IncidentDetail["report"] }>("/api/ingest/raw-fix", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ raw_fix_lines: raw.split(/\r?\n/).map((line) => line.trim()).filter(Boolean), direction: "inbound" }) }),
  orderbook: () => request<{ symbols: BookSnapshot[] }>("/api/orderbook"),
  marketTick: (batchSize = 5) => request<{ trades: unknown[]; books: BookSnapshot[]; batch_size: number }>("/api/market/tick", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ batch_size: batchSize }) }),
  chaosPrompt: (prompt: string) => request<ChaosResponse>("/api/chaos/inject-prompt", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ prompt }) }),
};
