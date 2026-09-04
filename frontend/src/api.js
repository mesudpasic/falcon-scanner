// Thin API client for the FastAPI backend.

export async function createScan(payload) {
  const res = await fetch("/api/scans", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Request failed");
  }
  return res.json();
}

export function openScanStream(scanId, onEvent, onClose) {
  const proto = location.protocol === "https:" ? "wss" : "ws";
  const ws = new WebSocket(`${proto}://${location.host}/api/scans/${scanId}/stream`);
  ws.onmessage = (e) => onEvent(JSON.parse(e.data));
  ws.onclose = () => onClose && onClose();
  return ws;
}
