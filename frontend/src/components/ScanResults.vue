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
  waf: { type: Array, default: () => [] },
  urls: { type: Array, default: () => [] },
});

const dumpFormat = ref("csv");

function dumpUrl(scanId, table) {
  return `/api/scans/${scanId}/dump/${encodeURIComponent(table)}?format=${dumpFormat.value}`;
}

const sevClass = {
  info: "text-bg-info",
  low: "text-bg-success",
  medium: "text-bg-warning",
  high: "text-bg-danger",
  critical: "text-bg-danger",
};
</script>

<template>
  <div class="card card-falcon">
    <div class="card-body">
      <div class="d-flex align-items-center justify-content-between gap-2 flex-wrap mb-3">
        <h2 class="h5 mb-0">Results</h2>
        <a
          v-if="scanId && (status === 'finished' || status === 'error')"
          class="btn btn-sm btn-primary"
          :href="`/api/scans/${scanId}/report`"
          :download="`sqli-report-${scanId}.html`"
        >
          Download HTML report
        </a>
      </div>

      <div v-if="progress" class="mb-3">
        <div class="progress" role="progressbar" style="height: 8px">
          <div
            class="progress-bar bg-success"
            :style="{ width: (100 * progress.step) / progress.total_steps + '%' }"
          ></div>
        </div>
        <div class="form-help">
          {{ progress.step }}/{{ progress.total_steps }} · {{ progress.detector }} → {{ progress.parameter }}
        </div>
      </div>

      <p v-if="status" class="small mb-2" :class="status === 'error' ? 'text-danger' : status === 'finished' ? 'text-success' : 'text-info'">
        Status: {{ status }}
      </p>
      <p v-if="urls.length > 1" class="small text-secondary">
        {{ urls.length }} targets:
        <code v-for="u in urls" :key="u" class="me-1">{{ u }}</code>
      </p>

      <div v-if="waf.length" class="alert alert-warning py-2 small">
        <div v-for="(w, i) in waf" :key="i">
          WAF: <strong>{{ w.product || "detected" }}</strong>
          <span v-if="w.host"> on {{ w.host }}</span>
          — {{ w.evidence }}
        </div>
      </div>

      <div v-if="findings.length">
        <div v-for="(f, i) in findings" :key="i" class="border rounded-3 p-3 mb-2">
          <div class="d-flex flex-wrap align-items-center gap-2 mb-1">
            <span class="badge rounded-pill" :class="sevClass[f.severity] || 'text-bg-secondary'">
              {{ f.severity }}
            </span>
            <strong>{{ f.technique }}</strong>
            <span class="text-secondary">in</span>
            <code>{{ f.parameter }}</code>
            <span class="small text-secondary">confidence {{ f.confidence }}</span>
          </div>
          <div v-if="f.url" class="small text-secondary text-break">{{ f.url }}</div>
          <div class="small mt-1">{{ f.evidence }}</div>
          <div v-if="f.payload" class="payload-text mt-1">{{ f.payload }}</div>
        </div>
      </div>
      <p v-else-if="status === 'finished'" class="text-secondary mb-0">No SQL injection detected.</p>
      <p v-else-if="!status" class="text-secondary mb-0">
        Start a scan to see live findings here. Open <strong>Guide</strong> if you are new to the options.
      </p>

      <div v-if="extracted.length" class="mt-4 pt-3 border-top">
        <h3 class="h6 text-info-emphasis">Extracted data</h3>
        <div v-for="(x, i) in extracted" :key="i" class="border rounded-3 p-3 mb-2">
          <div class="small text-secondary mb-2">
            <code>{{ x.parameter }}</code> · via {{ x.channel }} · {{ x.dbms || "unknown DBMS" }}
          </div>
          <table v-if="x.values && Object.keys(x.values).length" class="table table-sm table-borderless mb-2">
            <tbody>
              <tr v-for="(v, k) in x.values" :key="k">
                <td class="text-secondary text-nowrap small">{{ k }}</td>
                <td class="font-monospace small text-success text-break">{{ v }}</td>
              </tr>
            </tbody>
          </table>
          <div v-if="x.databases && x.databases.length" class="small mb-1">
            <strong>Databases:</strong>
            <code v-for="(d, di) in x.databases" :key="di" class="ms-1">{{ d }}</code>
          </div>
          <div v-if="x.schemas && x.schemas.length" class="small mb-1">
            <strong>Schemas:</strong>
            <code v-for="(s, si) in x.schemas" :key="si" class="ms-1">{{ s }}</code>
          </div>
          <div v-if="x.tables && x.tables.length" class="small">
            <strong>Tables:</strong>
            <code v-for="(t, ti) in x.tables" :key="ti" class="ms-1">{{ t }}</code>
          </div>
        </div>
      </div>

      <div v-if="dumps.length" class="mt-4 pt-3 border-top">
        <div class="d-flex align-items-center justify-content-between gap-2 flex-wrap mb-2">
          <h3 class="h6 text-warning mb-0">Database dump ({{ dumps.length }} tables)</h3>
          <label class="small text-secondary d-flex align-items-center gap-2 mb-0">
            File type
            <select v-model="dumpFormat" class="form-select form-select-sm" style="width: auto">
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
              <option value="html">HTML</option>
            </select>
          </label>
        </div>
        <div v-for="(d, i) in dumps" :key="i" class="border rounded-3 p-3 mb-2">
          <div class="d-flex align-items-center justify-content-between gap-2 flex-wrap mb-2">
            <div>
              <code class="text-warning">{{ d.table }}</code>
              <span class="small text-secondary ms-2">
                {{ d.rows.length }}<template v-if="d.truncated"> of {{ d.row_count }}</template> rows
                <template v-if="d.truncated">(capped)</template>
              </span>
            </div>
            <a
              class="btn btn-sm btn-outline-primary"
              :href="dumpUrl(scanId, d.table)"
              :download="`${d.table}.${dumpFormat}`"
            >
              Download {{ dumpFormat.toUpperCase() }}
            </a>
          </div>
          <div class="table-responsive" style="max-height: 320px" v-if="d.rows.length">
            <table class="table table-sm table-striped table-hover mb-0">
              <thead class="sticky-top">
                <tr><th v-for="(c, ci) in d.columns" :key="ci">{{ c }}</th></tr>
              </thead>
              <tbody>
                <tr v-for="(row, ri) in d.rows" :key="ri">
                  <td v-for="(cell, ci) in row" :key="ci" class="font-monospace text-nowrap">{{ cell }}</td>
                </tr>
              </tbody>
            </table>
          </div>
          <p v-else class="text-secondary small mb-0">No rows returned.</p>
        </div>
      </div>

      <details v-if="log.length" class="mt-3">
        <summary class="small text-secondary" style="cursor: pointer">Event log ({{ log.length }})</summary>
        <pre class="bg-body-tertiary border rounded-3 p-2 mt-2 small mb-0" style="max-height: 240px; overflow: auto">{{ log.map((e) => JSON.stringify(e)).join("\n") }}</pre>
      </details>
    </div>
  </div>
</template>
