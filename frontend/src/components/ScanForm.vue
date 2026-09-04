<script setup>
import { ref, reactive, computed } from "vue";

const props = defineProps({ running: Boolean });
const emit = defineEmits(["submit"]);

const form = reactive({
  url: "",
  method: "GET",
  paramsText: "",
  allowedHostsText: "",
  rate: 10,
  extractData: true,
  dumpData: true,
  maxDumpTables: "",
  maxDumpRows: "",
  consent: false,
});

const hostFromUrl = computed(() => {
  try {
    return new URL(form.url).hostname;
  } catch {
    return "";
  }
});

function parsePairs(text) {
  const out = {};
  text
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean)
    .forEach((pair) => {
      const idx = pair.indexOf("=");
      if (idx > -1) out[pair.slice(0, idx).trim()] = pair.slice(idx + 1).trim();
    });
  return out;
}

function submit() {
  const toCap = (v) => (v === "" || v == null ? null : Number(v));
  emit("submit", {
    url: form.url,
    method: form.method,
    params: parsePairs(form.paramsText),
    allowed_hosts: form.allowedHostsText.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean),
    consent: form.consent,
    rate_limit_per_sec: Number(form.rate),
    extract_data: form.extractData,
    dump_data: form.dumpData,
    max_dump_tables: toCap(form.maxDumpTables),
    max_dump_rows: toCap(form.maxDumpRows),
  });
}
</script>

<template>
  <form class="card" @submit.prevent="submit">
    <h2>New scan</h2>

    <label>Target URL</label>
    <input v-model="form.url" type="text" placeholder="https://example.com/item.php" />

    <div class="row">
      <div>
        <label>Method</label>
        <select v-model="form.method">
          <option>GET</option>
          <option>POST</option>
        </select>
      </div>
      <div>
        <label>Max requests/sec</label>
        <input v-model.number="form.rate" type="number" min="1" step="1" />
      </div>
    </div>

    <label>Parameters (key=value, one per line)</label>
    <textarea v-model="form.paramsText" rows="3" placeholder="cat=1"></textarea>

    <label>Authorized hosts (allowlist)</label>
    <textarea v-model="form.allowedHostsText" rows="2"></textarea>
    <p v-if="hostFromUrl && !form.allowedHostsText.includes(hostFromUrl)" class="warn">
      Target host <code>{{ hostFromUrl }}</code> is not in your allowlist.
    </p>

    <label class="toggle">
      <input v-model="form.extractData" type="checkbox" />
      Attempt data extraction after confirming an injection (version, user, tables)
    </label>

    <label class="toggle">
      <input v-model="form.dumpData" type="checkbox" :disabled="!form.extractData" />
      Dump full table contents over a UNION channel (whole database)
    </label>

    <div v-if="form.dumpData && form.extractData" class="row">
      <div>
        <label>Max tables</label>
        <input v-model="form.maxDumpTables" type="number" min="1" step="1" placeholder="all" />
      </div>
      <div>
        <label>Max rows / table</label>
        <input v-model="form.maxDumpRows" type="number" min="1" step="1" placeholder="all" />
      </div>
    </div>
    <p v-if="form.dumpData && form.extractData" class="hint">
      Leave blank to extract every table and every row.
    </p>

    <label class="consent">
      <input v-model="form.consent" type="checkbox" />
      I am authorized to test this target and accept responsibility for this scan.
    </label>

    <button type="submit" :disabled="running || !form.consent">
      {{ running ? "Scanning…" : "Start scan" }}
    </button>
  </form>
</template>

<style scoped>
.card {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 10px;
  padding: 20px;
  display: flex;
  flex-direction: column;
  gap: 8px;
}
h2 { margin: 0 0 8px; font-size: 18px; }
label { font-size: 13px; color: #8b949e; margin-top: 6px; }
input[type="text"], input[type="number"], select, textarea {
  background: #0d1117;
  border: 1px solid #30363d;
  border-radius: 6px;
  color: #e6edf3;
  padding: 8px 10px;
  font: inherit;
  width: 100%;
  box-sizing: border-box;
}
.row { display: flex; flex-wrap: wrap; gap: 12px; }
.row > div { flex: 1 1 140px; min-width: 0; }
.consent { display: flex; align-items: flex-start; gap: 8px; color: #e6edf3; margin-top: 12px; }
.consent input { margin-top: 3px; }
.toggle { display: flex; align-items: flex-start; gap: 8px; color: #c9d1d9; font-size: 13px; margin-top: 12px; }
.toggle input { margin-top: 2px; }
.warn { color: #d29922; font-size: 12px; margin: 4px 0 0; }
.hint { color: #8b949e; font-size: 12px; margin: 2px 0 0; }
button {
  margin-top: 14px;
  background: #238636;
  border: none;
  border-radius: 6px;
  color: white;
  padding: 10px;
  font-weight: 600;
  cursor: pointer;
}
button:disabled { background: #30363d; color: #8b949e; cursor: not-allowed; }
code { background: #0d1117; padding: 1px 4px; border-radius: 4px; }
</style>
