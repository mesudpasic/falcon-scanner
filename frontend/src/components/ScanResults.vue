<script setup>
import { ref } from "vue";

defineProps({
  progress: { type: Object, default: null },
  findings: { type: Array, default: () => [] },
  log: { type: Array, default: () => [] },
  status: { type: String, default: "" },
  scanId: { type: String, default: null },
  extracted: { type: Array, default: () => [] },
  dumps: { type: Array, default: () => [] },
});

const dumpFormat = ref("csv");

function dumpUrl(scanId, table) {
  return `/api/scans/${scanId}/dump/${encodeURIComponent(table)}?format=${dumpFormat.value}`;
}

const sevColor = {
  info: "#58a6ff",
  low: "#3fb950",
  medium: "#d29922",
  high: "#f85149",
  critical: "#ff5c8a",
};
</script>

<template>
  <div class="card">
    <div class="head">
      <h2>Results</h2>
      <a
        v-if="scanId && (status === 'finished' || status === 'error')"
        class="download"
        :href="`/api/scans/${scanId}/report`"
        :download="`sqli-report-${scanId}.html`"
      >
        ↓ Download HTML report
      </a>
    </div>

    <div v-if="progress" class="progress">
      <div class="bar">
        <div
          class="fill"
          :style="{ width: (100 * progress.step) / progress.total_steps + '%' }"
        ></div>
      </div>
      <span>{{ progress.step }}/{{ progress.total_steps }} · {{ progress.detector }} → {{ progress.parameter }}</span>
    </div>

    <p v-if="status" class="status" :class="status">Status: {{ status }}</p>

    <div v-if="findings.length" class="findings">
      <div v-for="(f, i) in findings" :key="i" class="finding">
        <span class="sev" :style="{ background: sevColor[f.severity] || '#8b949e' }">
          {{ f.severity }}
        </span>
        <div>
          <strong>{{ f.technique }}</strong> in <code>{{ f.parameter }}</code>
          <span class="conf">confidence {{ f.confidence }}</span>
          <div class="evidence">{{ f.evidence }}</div>
          <div class="payload">{{ f.payload }}</div>
        </div>
      </div>
    </div>
    <p v-else-if="status === 'finished'" class="none">No SQL injection detected.</p>

    <div v-if="extracted.length" class="extracted">
      <h3>Extracted data</h3>
      <div v-for="(x, i) in extracted" :key="i" class="exblock">
        <div class="exhead">
          <code>{{ x.parameter }}</code> · via {{ x.channel }} · {{ x.dbms || "unknown DBMS" }}
        </div>
        <table v-if="x.values && Object.keys(x.values).length" class="exvalues">
          <tbody>
            <tr v-for="(v, k) in x.values" :key="k">
              <td class="exkey">{{ k }}</td>
              <td class="exval">{{ v }}</td>
            </tr>
          </tbody>
        </table>
        <div v-if="x.tables && x.tables.length" class="tables">
          <strong>Tables:</strong>
          <code v-for="(t, ti) in x.tables" :key="ti" class="tbl">{{ t }}</code>
        </div>
      </div>
    </div>

    <div v-if="dumps.length" class="dumps">
      <div class="dumphead">
        <h3>Database dump ({{ dumps.length }} tables)</h3>
        <label class="fmt">
          File type
          <select v-model="dumpFormat">
            <option value="csv">CSV</option>
            <option value="json">JSON</option>
            <option value="html">HTML</option>
          </select>
        </label>
      </div>
      <div v-for="(d, i) in dumps" :key="i" class="dumpblock">
        <div class="dbhead">
          <div>
            <code class="tbl">{{ d.table }}</code>
            <span class="rowcount">
              {{ d.rows.length }}<template v-if="d.truncated"> of {{ d.row_count }}</template> rows
              <template v-if="d.truncated">(capped)</template>
            </span>
          </div>
          <a
            class="download small"
            :href="dumpUrl(scanId, d.table)"
            :download="`${d.table}.${dumpFormat}`"
          >
            ↓ Download {{ dumpFormat.toUpperCase() }}
          </a>
        </div>
        <div class="tablewrap" v-if="d.rows.length">
          <table class="dumptable">
            <thead>
              <tr><th v-for="(c, ci) in d.columns" :key="ci">{{ c }}</th></tr>
            </thead>
            <tbody>
              <tr v-for="(row, ri) in d.rows" :key="ri">
                <td v-for="(cell, ci) in row" :key="ci">{{ cell }}</td>
              </tr>
            </tbody>
          </table>
        </div>
        <p v-else class="none">No rows returned.</p>
      </div>
    </div>

    <details v-if="log.length" class="logbox">
      <summary>Event log ({{ log.length }})</summary>
      <pre>{{ log.map((e) => JSON.stringify(e)).join("\n") }}</pre>
    </details>
  </div>
</template>

<style scoped>
.card {
  background: #161b22;
  border: 1px solid #30363d;
  border-radius: 10px;
  padding: 20px;
}
h2 { margin: 0 0 12px; font-size: 18px; }
.head { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.head h2 { margin: 0 0 12px; }
.download {
  display: inline-block;
  margin-bottom: 12px;
  background: #1f6feb;
  color: #fff;
  text-decoration: none;
  font-size: 13px;
  font-weight: 600;
  padding: 7px 12px;
  border-radius: 6px;
}
.download:hover { background: #388bfd; }
.progress { margin-bottom: 12px; }
.bar { height: 8px; background: #0d1117; border-radius: 4px; overflow: hidden; }
.fill { height: 100%; background: #238636; transition: width 0.2s; }
.progress span { font-size: 12px; color: #8b949e; }
.status { font-size: 13px; }
.status.finished { color: #3fb950; }
.status.error { color: #f85149; }
.finding {
  display: flex;
  gap: 10px;
  padding: 12px;
  border: 1px solid #30363d;
  border-radius: 8px;
  margin-bottom: 8px;
}
.sev {
  align-self: flex-start;
  color: #0d1117;
  font-weight: 700;
  font-size: 11px;
  text-transform: uppercase;
  padding: 2px 8px;
  border-radius: 999px;
}
.conf { color: #8b949e; font-size: 12px; margin-left: 8px; }
.evidence { color: #c9d1d9; font-size: 13px; margin-top: 4px; }
.payload {
  font-family: monospace;
  font-size: 12px;
  color: #d29922;
  margin-top: 4px;
  word-break: break-all;
}
.none { color: #8b949e; }
.extracted { margin-top: 16px; border-top: 1px solid #21262d; padding-top: 14px; }
.extracted h3 { margin: 0 0 10px; font-size: 15px; color: #d2a8ff; }
.exblock { border: 1px solid #30363d; border-radius: 8px; padding: 12px; margin-bottom: 10px; }
.exhead { font-size: 12px; color: #8b949e; margin-bottom: 8px; }
.exvalues { width: 100%; border-collapse: collapse; }
.exvalues td { padding: 5px 10px 5px 0; border-bottom: 1px solid #21262d; vertical-align: top; }
.exkey { color: #8b949e; font-size: 13px; white-space: nowrap; }
.exval { font-family: monospace; font-size: 12px; color: #7ee787; word-break: break-all; }
.tables { margin-top: 8px; font-size: 13px; color: #c9d1d9; }
.tables .tbl { margin: 0 4px 4px 0; display: inline-block; }
.dumps { margin-top: 16px; border-top: 1px solid #21262d; padding-top: 14px; }
.dumphead { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; }
.dumphead h3 { margin: 0 0 10px; font-size: 15px; color: #ffa657; }
.fmt { font-size: 12px; color: #8b949e; display: flex; align-items: center; gap: 6px; }
.fmt select {
  background: #0d1117;
  border: 1px solid #30363d;
  border-radius: 6px;
  color: #e6edf3;
  padding: 5px 8px;
  font: inherit;
}
.dumpblock { border: 1px solid #30363d; border-radius: 8px; padding: 12px; margin-bottom: 10px; }
.dbhead { display: flex; align-items: center; justify-content: space-between; gap: 10px; flex-wrap: wrap; margin-bottom: 10px; }
.dbhead .tbl { font-size: 13px; color: #ffa657; }
.rowcount { color: #8b949e; font-size: 12px; margin-left: 8px; }
.download.small { margin: 0; padding: 5px 10px; font-size: 12px; }
.tablewrap { overflow-x: auto; max-height: 320px; overflow-y: auto; }
.dumptable { border-collapse: collapse; width: 100%; font-size: 12px; }
.dumptable th, .dumptable td {
  border: 1px solid #21262d;
  padding: 5px 8px;
  text-align: left;
  white-space: nowrap;
}
.dumptable th { background: #0d1117; color: #c9d1d9; position: sticky; top: 0; }
.dumptable td { color: #adbac7; font-family: monospace; }
.dumptable tr:nth-child(even) td { background: #12161c; }
code { background: #0d1117; padding: 1px 4px; border-radius: 4px; }
.logbox { margin-top: 12px; }
.logbox summary { cursor: pointer; color: #8b949e; font-size: 13px; }
.logbox pre {
  background: #0d1117;
  padding: 10px;
  border-radius: 6px;
  font-size: 11px;
  overflow-x: auto;
  max-height: 240px;
}
</style>
