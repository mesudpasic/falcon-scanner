// Thin API client for the FastAPI backend.

export async function createScan(payload) {
  const res = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(formatDetail(err.detail) || "Request failed");
  }
  return res.json();
}

export async function listScans() {
  const res = await fetch("/api/scans");
  if (!res.ok) throw new Error("Failed to list scans");
  return res.json();
}

export async function getScan(scanId) {
  const res = await fetch(`/api/scans/${scanId}`);
  if (!res.ok) throw new Error("Scan not found");
  return res.json();
}

export async function deleteScan(scanId) {
  const res = await fetch(`/api/scans/${scanId}`, { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(formatDetail(err.detail) || "Failed to delete scan");
  }
  return res.json();
}

export async function clearScans() {
  const res = await fetch("/api/scans", { method: "DELETE" });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(formatDetail(err.detail) || "Failed to clear scans");
  }
  return res.json();
}

export async function listTampers() {
  const res = await fetch("/api/tampers");
  if (!res.ok) return { tampers: [] };
  return res.json();
}

export function openScanStream(scanId, onEvent, onClose) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/scans/${scanId}/stream`);
  ws.onmessage = (e) => onEvent(JSON.parse(e.data));
  ws.onclose = () => onClose && onClose();
  return ws;
}

function formatDetail(detail) {
  if (!detail) return "";
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    return detail.map((d) => d.msg || JSON.stringify(d)).join("; ");
  }
  return String(detail);
}
