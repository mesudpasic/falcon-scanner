<script setup>
import { ref } from "vue";
import ScanForm from "./components/ScanForm.vue";
import ScanResults from "./components/ScanResults.vue";
import { createScan, openScanStream } from "./api";

const running = ref(false);
const status = ref("");
const progress = ref(null);
const findings = ref([]);
const log = ref([]);
const error = ref("");
const scanId = ref(null);
const extracted = ref([]);
const dumps = ref([]);

async function startScan(payload) {
  error.value = "";
  findings.value = [];
  log.value = [];
  progress.value = null;
  scanId.value = null;
  extracted.value = [];
  dumps.value = [];
  status.value = "starting";
  running.value = true;

  try {
    const { scan_id } = await createScan(payload);
    scanId.value = scan_id;
    status.value = "running";
    openScanStream(
      scan_id,
      (event) => {
        log.value.push(event);
        if (event.type === "progress") progress.value = event;
        else if (event.type === "finding") findings.value.push(event);
        else if (event.type === "extracted-data") extracted.value.push(event);
        else if (event.type === "table-dump") dumps.value.push(event);
        else if (event.type === "error") error.value = event.message;
        else if (event.type === "done") {
          status.value = event.status;
          running.value = false;
        }
      },
      () => {
        running.value = false;
      }
    );
  } catch (e) {
    error.value = e.message;
    status.value = "error";
    running.value = false;
  }
}
</script>

<template>
  <div class="app">
    <header>
      <div class="brand">
        <img class="logo" src="/falcon.png" alt="Falcon Scanner logo" />
        <h1>Falcon Scanner</h1>
      </div>
      <p class="tagline">
        Falcon Scanner is an open-source penetration-testing tool that
        automatically uncovers and safely exploits SQL injection weaknesses in
        web applications — revealing how far an attacker could reach, from
        leaking sensitive data to fully compromising the database server.
      </p>
      <p class="sub">Authorized use only · test only targets you own or have written permission to test.</p>
    </header>

    <p v-if="error" class="banner">{{ error }}</p>

    <div class="grid">
      <ScanForm :running="running" @submit="startScan" />
      <ScanResults :progress="progress" :findings="findings" :log="log" :status="status" :scan-id="scanId" :extracted="extracted" :dumps="dumps" />
    </div>

    <footer class="site-footer">
      <span>Falcon Scanner <strong>v1.0.0</strong></span>
      <span class="dot">·</span>
      <span>
        Built by
        <a href="https://www.setec.ba" target="_blank" rel="noopener noreferrer">SETEC d.o.o.</a>
        —
        <a href="https://www.setec.ba" target="_blank" rel="noopener noreferrer">www.setec.ba</a>
      </span>
    </footer>
  </div>
</template>

<style>
body {
  margin: 0;
  background: #0d1117;
  color: #e6edf3;
  font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}
.app { width: 100%; max-width: 1440px; margin: 0 auto; padding: 32px clamp(16px, 4vw, 48px); box-sizing: border-box; }
header h1 { margin: 0; font-size: clamp(22px, 3vw, 30px); }
.brand { display: flex; align-items: center; gap: 14px; }
.logo { height: clamp(40px, 6vw, 56px); width: auto; display: block; }
.tagline { color: #c9d1d9; font-size: 15px; line-height: 1.5; margin: 8px 0 4px; max-width: 720px; }
.sub { color: #8b949e; font-size: 13px; margin: 6px 0 20px; }
.banner {
  background: #3d1418;
  border: 1px solid #f85149;
  color: #ffa198;
  padding: 10px 14px;
  border-radius: 8px;
}
.grid { display: grid; grid-template-columns: minmax(320px, 5fr) minmax(0, 7fr); gap: 24px; align-items: start; }
@media (max-width: 900px) { .grid { grid-template-columns: 1fr; } }
.site-footer {
  margin-top: 40px;
  padding-top: 20px;
  border-top: 1px solid #21262d;
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  color: #8b949e;
  font-size: 13px;
}
.site-footer a { color: #58a6ff; text-decoration: none; }
.site-footer a:hover { text-decoration: underline; }
.site-footer .dot { color: #30363d; }
@media (max-width: 500px) { .site-footer .dot { display: none; } }
</style>
