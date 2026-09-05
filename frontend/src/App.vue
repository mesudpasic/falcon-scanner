<script setup>
import { computed, onMounted, ref } from "vue";
import ScanForm from "./components/ScanForm.vue";
import ScanResults from "./components/ScanResults.vue";
import DocsPanel from "./components/DocsPanel.vue";
import { clearScans, createScan, deleteScan, getScan, listScans, openScanStream } from "./api";

const error = ref("");
const guideOpen = ref(false);
const history = ref([]);
const selectedId = ref(null);
const sessions = ref({});
const sockets = new Map();

const runningCount = computed(
  () => history.value.filter((s) => s.status === "running" || s.status === "pending").length
);

const current = computed(() => {
  const id = selectedId.value;
  if (!id) {
    return {
      progress: null,
      findings: [],
      log: [],
      status: "",
      extracted: [],
      dumps: [],
      waf: [],
      urls: [],
    };
  }
  return (
    sessions.value[id] || {
      progress: null,
      findings: [],
      log: [],
      status: "",
      extracted: [],
      dumps: [],
      waf: [],
      urls: [],
    }
  );
});

function emptySession(partial = {}) {
  return {
    progress: null,
    findings: [],
    log: [],
    status: "pending",
    extracted: [],
    dumps: [],
    waf: [],
    urls: [],
    ...partial,
  };
}

function upsertHistory(entry) {
  const idx = history.value.findIndex((s) => s.scan_id === entry.scan_id);
  if (idx >= 0) history.value.splice(idx, 1, { ...history.value[idx], ...entry });
  else history.value.unshift(entry);
}

function applyEvent(id, event) {
  const session = sessions.value[id];
  if (!session) return;
  session.log.push(event);
  if (event.type === "progress") session.progress = event;
  else if (event.type === "finding") session.findings.push(event);
  else if (event.type === "extracted-data") session.extracted.push(event);
  else if (event.type === "table-dump") session.dumps.push(event);
  else if (event.type === "waf" && event.detected) session.waf.push(event);
  else if (event.type === "scan_started" && event.urls) session.urls = event.urls;
  else if (event.type === "error") error.value = event.message;
  else if (event.type === "done") {
    session.status = event.status;
    upsertHistory({ scan_id: id, status: event.status, findings_count: session.findings.length });
  }
}

function watchScan(scanId) {
  if (sockets.has(scanId)) return;
  const ws = openScanStream(
    scanId,
    (event) => applyEvent(scanId, event),
    () => {
      sockets.delete(scanId);
      const session = sessions.value[scanId];
      if (session && (session.status === "running" || session.status === "pending")) {
        session.status = session.status === "running" ? "finished" : session.status;
      }
    }
  );
  sockets.set(scanId, ws);
}

function hydrateFromApi(data) {
  const id = data.scan_id;
  sessions.value[id] = emptySession({
    status: data.status,
    findings: data.findings || [],
    extracted: data.extracted || [],
    dumps: data.dumps || [],
    log: data.events || [],
    waf: data.waf || [],
    urls: data.urls || (data.url ? [data.url] : []),
    progress: (data.events || []).findLast?.((e) => e.type === "progress")
      || [...(data.events || [])].reverse().find((e) => e.type === "progress")
      || null,
  });
  if (data.status === "running" || data.status === "pending") {
    watchScan(id);
  }
}

async function refreshHistory() {
  try {
    history.value = await listScans();
  } catch {
    /* backend may not be up yet */
  }
}

async function selectScan(id) {
  selectedId.value = id;
  error.value = "";
  if (!sessions.value[id]) {
    try {
      hydrateFromApi(await getScan(id));
    } catch (e) {
      error.value = e.message;
    }
  } else if (
    sessions.value[id].status === "running" ||
    sessions.value[id].status === "pending"
  ) {
    watchScan(id);
  }
}

function forgetScan(id) {
  const ws = sockets.get(id);
  if (ws) {
    try {
      ws.close();
    } catch {
      /* already closed */
    }
    sockets.delete(id);
  }
  delete sessions.value[id];
  history.value = history.value.filter((s) => s.scan_id !== id);
  if (selectedId.value === id) selectedId.value = null;
}

async function removeScan(id) {
  error.value = "";
  try {
    await deleteScan(id);
    forgetScan(id);
  } catch (e) {
    error.value = e.message;
  }
}

async function removeAllScans() {
  error.value = "";
  try {
    await clearScans();
    for (const id of [...sockets.keys()]) forgetScan(id);
    sessions.value = {};
    history.value = [];
    selectedId.value = null;
  } catch (e) {
    error.value = e.message;
  }
}

async function startScan(payload) {
  error.value = "";
  try {
    const { scan_id } = await createScan(payload);
    sessions.value[scan_id] = emptySession({
      status: "running",
      urls: payload.urls || (payload.url ? [payload.url] : []),
    });
    upsertHistory({
      scan_id,
      status: "running",
      url: payload.url || (payload.urls && payload.urls[0]) || "",
      urls: payload.urls || [],
      created_at: new Date().toISOString(),
      findings_count: 0,
    });
    selectedId.value = scan_id;
    watchScan(scan_id);
  } catch (e) {
    error.value = e.message;
  }
}

onMounted(() => {
  refreshHistory();
});
</script>

<template>
  <div class="container-xxl py-4">
    <nav class="navbar navbar-expand-md mb-3 px-0">
      <a class="navbar-brand d-flex align-items-center gap-2 mb-0" href="#">
        <img src="/falcon.png" alt="Falcon Scanner logo" />
        <span class="fw-semibold">Falcon Scanner</span>
      </a>
      <button
        type="button"
        class="btn btn-outline-info btn-sm ms-md-auto mt-3 mt-md-0"
        @click="guideOpen = true"
      >
        Guide &amp; options
      </button>
    </nav>

    <p class="text-secondary mb-2">
      Open-source SQL-injection scanner with a live GUI. It finds injectable
      parameters and shows how far an attacker could reach — from leaked data
      to a full schema dump.
    </p>
    <p class="small text-warning-emphasis mb-4">
      Authorized use only. Test only targets you own or have written permission to test.
    </p>

    <div v-if="error" class="alert alert-danger">{{ error }}</div>

    <div class="d-flex flex-column gap-4">
      <ScanForm
        :running-count="runningCount"
        :history="history"
        :selected-id="selectedId"
        @submit="startScan"
        @select-scan="selectScan"
        @delete-scan="removeScan"
        @clear-history="removeAllScans"
      />
      <ScanResults
        :progress="current.progress"
        :findings="current.findings"
        :log="current.log"
        :status="current.status"
        :scan-id="selectedId"
        :extracted="current.extracted"
        :dumps="current.dumps"
        :waf="current.waf"
        :urls="current.urls"
      />
    </div>

    <footer class="d-flex flex-wrap align-items-center gap-2 mt-5 pt-3 border-top text-secondary small">
      <span>Falcon Scanner <strong>v1.1.0</strong></span>
      <span class="opacity-50">·</span>
      <span>
        Built by
        <a href="https://www.setec.ba" target="_blank" rel="noopener noreferrer">SETEC d.o.o.</a>
        —
        <a href="https://www.setec.ba" target="_blank" rel="noopener noreferrer">www.setec.ba</a>
      </span>
    </footer>

    <DocsPanel :open="guideOpen" @update:open="guideOpen = $event" />
  </div>
</template>
