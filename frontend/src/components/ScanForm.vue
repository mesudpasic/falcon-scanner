<script setup>
import { ref, reactive, computed, onMounted } from "vue";
import { listTampers } from "../api";
import HelpTip from "./HelpTip.vue";

const props = defineProps({
  runningCount: { type: Number, default: 0 },
  history: { type: Array, default: () => [] },
  selectedId: { type: String, default: null },
});
const emit = defineEmits(["submit", "select-scan", "delete-scan", "clear-history"]);
const advancedOpen = ref(false);
const tab = ref("new");

function statusBadge(status) {
  if (status === "running" || status === "pending") return "text-bg-info";
  if (status === "finished") return "text-bg-success";
  if (status === "error") return "text-bg-danger";
  return "text-bg-secondary";
}

function openHistoryScan(id) {
  emit("select-scan", id);
}

function confirmDelete(id) {
  if (window.confirm("Remove this scan and its findings, dumps, and report data?")) {
    emit("delete-scan", id);
  }
}

function confirmClear() {
  if (
    window.confirm(
      "Clear all scan history and stored artifacts? This cannot be undone."
    )
  ) {
    emit("clear-history");
  }
}

const form = reactive({
  urlsText: "",
  method: "GET",
  paramsText: "",
  cookiesText: "",
  allowedHostsText: "",
  rate: 10,
  concurrency: 3,
  extractData: true,
  dumpData: true,
  maxDumpTables: "",
  maxDumpRows: "",
  consent: false,
  crawl: false,
  crawlDepth: 2,
  crawlMaxPages: 50,
  detectWaf: true,
  autoTamper: true,
  tampers: [],
  oobCallback: "",
  oobDomain: "",
  oobInteractsh: "",
  oobInteractshToken: "",
  oobPollUrl: "",
  oobPollAuth: "",
  blindEnumerate: true,
});

const tamperOptions = ref([]);

onMounted(async () => {
  try {
    const data = await listTampers();
    tamperOptions.value = data.tampers || [];
  } catch {
    tamperOptions.value = [];
  }
});

const hostsFromUrls = computed(() => {
  const hosts = [];
  for (const line of form.urlsText.split(/[\n,]+/)) {
    const raw = line.trim();
    if (!raw) continue;
    try {
      const host = new URL(raw).hostname;
      if (host && !hosts.includes(host)) hosts.push(host);
    } catch {
      /* ignore unparseable lines while typing */
    }
  }
  return hosts;
});

const missingHosts = computed(() =>
  hostsFromUrls.value.filter((h) => !form.allowedHostsText.includes(h))
);

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

function parseUrls(text) {
  return text
    .split(/[\n,]+/)
    .map((s) => s.trim())
    .filter(Boolean);
}

function submit() {
  const toCap = (v) => (v === "" || v == null ? null : Number(v));
  const urls = parseUrls(form.urlsText);
  emit("submit", {
    url: urls[0] || "",
    urls,
    method: form.method,
    params: parsePairs(form.paramsText),
    cookies: parsePairs(form.cookiesText),
    allowed_hosts: form.allowedHostsText.split(/[\n,]+/).map((s) => s.trim()).filter(Boolean),
    consent: form.consent,
    rate_limit_per_sec: Number(form.rate),
    concurrency: Number(form.concurrency) || 3,
    extract_data: form.extractData,
    dump_data: form.dumpData,
    max_dump_tables: toCap(form.maxDumpTables),
    max_dump_rows: toCap(form.maxDumpRows),
    crawl: form.crawl,
    crawl_depth: Number(form.crawlDepth) || 2,
    crawl_max_pages: Number(form.crawlMaxPages) || 50,
    detect_waf: form.detectWaf,
    auto_tamper: form.autoTamper,
    tampers: [...form.tampers],
    oob_callback: form.oobCallback.trim(),
    oob_domain: form.oobDomain.trim(),
    oob_interactsh: form.oobInteractsh.trim(),
    oob_interactsh_token: form.oobInteractshToken.trim(),
    oob_poll_url: form.oobPollUrl.trim(),
    oob_poll_auth: form.oobPollAuth.trim(),
    blind_enumerate: form.blindEnumerate,
  });
}
</script>

<template>
  <div class="card card-falcon">
    <div class="card-header d-flex align-items-center gap-3 flex-wrap bg-transparent">
      <ul class="nav nav-tabs card-header-tabs border-0">
        <li class="nav-item">
          <button
            type="button"
            class="nav-link"
            :class="{ active: tab === 'new' }"
            @click="tab = 'new'"
          >
            New scan
          </button>
        </li>
        <li class="nav-item">
          <button
            type="button"
            class="nav-link"
            :class="{ active: tab === 'history' }"
            @click="tab = 'history'"
          >
            History
            <span v-if="history.length" class="badge text-bg-secondary ms-1">{{ history.length }}</span>
          </button>
        </li>
      </ul>
    </div>

    <form v-show="tab === 'new'" class="card-body" @submit.prevent="submit">

      <div class="mb-3">
        <label class="form-label">
          Target URLs
          <HelpTip text="One URL per line. They are scanned in parallel. Query-string keys (?cat=1) become parameters automatically." />
        </label>
        <textarea
          v-model="form.urlsText"
          class="form-control"
          rows="3"
          placeholder="http://testphp.vulnweb.com/listproducts.php?cat=1"
        ></textarea>
        <div class="form-help">One endpoint per line.</div>
      </div>

      <div class="d-flex flex-wrap gap-3 mb-3">
        <div>
          <label class="form-label">
            Method
            <HelpTip text="GET puts parameters in the query string. POST sends them as a form body." />
          </label>
          <select v-model="form.method" class="form-select form-control-num">
            <option>GET</option>
            <option>POST</option>
          </select>
        </div>
        <div>
          <label class="form-label">
            Max req/sec
            <HelpTip text="Rate limit for requests to the target. Default 10." />
          </label>
          <input v-model.number="form.rate" class="form-control form-control-num" type="number" min="1" step="1" />
        </div>
        <div>
          <label class="form-label">
            Workers
            <HelpTip text="How many URLs or crawled endpoints to test at once. The rate limit still applies globally." />
          </label>
          <input v-model.number="form.concurrency" class="form-control form-control-num" type="number" min="1" max="20" step="1" />
        </div>
      </div>

      <div class="mb-3">
        <label class="form-label">
          Parameters
          <HelpTip text="Baseline key=value pairs, one per line. The scanner mutates one key at a time. Merged onto every URL." />
        </label>
        <textarea v-model="form.paramsText" class="form-control" rows="2" placeholder="cat=1"></textarea>
      </div>

      <div class="mb-3">
        <label class="form-label">
          Cookies
          <HelpTip text="Session cookies sent with every request (name=value). Use this for authenticated / session-bound pages." />
        </label>
        <textarea v-model="form.cookiesText" class="form-control" rows="2" placeholder="PHPSESSID=abc123"></textarea>
      </div>

      <div class="mb-3">
        <label class="form-label">
          Authorized hosts
          <HelpTip text="Required allowlist. Hostnames or globs (*.example.com). The scan is refused if a target host is missing." />
        </label>
        <textarea v-model="form.allowedHostsText" class="form-control" rows="2" placeholder="testphp.vulnweb.com"></textarea>
        <div v-if="missingHosts.length" class="alert alert-warning py-2 px-3 small mt-2 mb-0">
          Not in your allowlist:
          <code v-for="h in missingHosts" :key="h" class="ms-1">{{ h }}</code>
        </div>
      </div>

      <div class="form-check mb-2">
        <input id="extractData" v-model="form.extractData" class="form-check-input" type="checkbox" />
        <label class="form-check-label" for="extractData">
          Extract data after a confirmed injection
          <HelpTip text="Read version, user, and database, then list schemas and tables." />
        </label>
      </div>
      <div class="form-check mb-2">
        <input id="blindEnumerate" v-model="form.blindEnumerate" class="form-check-input" type="checkbox" :disabled="!form.extractData" />
        <label class="form-check-label" for="blindEnumerate">
          Enumerate catalogs on a blind channel
          <HelpTip text="When only boolean- or time-blind works, reconstruct database/schema/table names character-by-character. Slow, especially time-based." />
        </label>
      </div>
      <div class="form-check mb-3">
        <input id="dumpData" v-model="form.dumpData" class="form-check-input" type="checkbox" :disabled="!form.extractData" />
        <label class="form-check-label" for="dumpData">
          Dump table contents (UNION channel)
          <HelpTip text="Pull rows from enumerated tables. Only works over UNION — too slow on blind channels." />
        </label>
      </div>

      <div v-if="form.dumpData && form.extractData" class="d-flex flex-wrap gap-3 mb-3">
        <div>
          <label class="form-label">
            Max tables
            <HelpTip text="Leave blank to dump every enumerated table." />
          </label>
          <input v-model="form.maxDumpTables" class="form-control form-control-num" type="number" min="1" step="1" placeholder="all" />
        </div>
        <div>
          <label class="form-label">
            Max rows / table
            <HelpTip text="Leave blank to pull every row." />
          </label>
          <input v-model="form.maxDumpRows" class="form-control form-control-num" type="number" min="1" step="1" placeholder="all" />
        </div>
      </div>

      <div class="accordion accordion-flush mb-3">
        <div class="accordion-item bg-transparent">
          <h3 class="accordion-header">
            <button
              class="accordion-button shadow-none"
              :class="{ collapsed: !advancedOpen }"
              type="button"
              :aria-expanded="advancedOpen"
              aria-controls="advancedCollapse"
              @click="advancedOpen = !advancedOpen"
            >
              Discovery, WAF evasion &amp; OOB
            </button>
          </h3>
          <div id="advancedCollapse" class="accordion-collapse collapse" :class="{ show: advancedOpen }">
            <div class="accordion-body px-0 pt-2">
              <div class="form-check mb-2">
                <input id="crawl" v-model="form.crawl" class="form-check-input" type="checkbox" />
                <label class="form-check-label" for="crawl">
                  Crawl for links, forms, and parameters
                  <HelpTip text="Stays in-scope (allowlist). Skips logout and static files." />
                </label>
              </div>
              <div v-if="form.crawl" class="d-flex flex-wrap gap-3 mb-3">
                <div>
                  <label class="form-label">Crawl depth</label>
                  <input v-model.number="form.crawlDepth" class="form-control form-control-num" type="number" min="0" max="6" />
                </div>
                <div>
                  <label class="form-label">Max pages</label>
                  <input v-model.number="form.crawlMaxPages" class="form-control form-control-num" type="number" min="1" max="500" />
                </div>
              </div>

              <div class="form-check mb-2">
                <input id="detectWaf" v-model="form.detectWaf" class="form-check-input" type="checkbox" />
                <label class="form-check-label" for="detectWaf">
                  Fingerprint WAF / IPS first
                  <HelpTip text="Noisy probe plus product signatures (Cloudflare, AWS WAF, ModSecurity, …)." />
                </label>
              </div>
              <div class="form-check mb-3">
                <input id="autoTamper" v-model="form.autoTamper" class="form-check-input" type="checkbox" />
                <label class="form-check-label" for="autoTamper">
                  Auto-enable tampers if a WAF is detected
                  <HelpTip text="Applies a default evasion chain when you have not picked tampers yourself." />
                </label>
              </div>

              <label class="form-label">
                Tamper scripts
                <HelpTip text="Rewrite every injected value so signature-based filters are less likely to match." />
              </label>
              <div class="d-flex flex-wrap gap-2 mb-3">
                <div v-for="name in tamperOptions" :key="name" class="form-check form-check-inline">
                  <input :id="'tamper-' + name" class="form-check-input" type="checkbox" :value="name" v-model="form.tampers" />
                  <label class="form-check-label small" :for="'tamper-' + name">{{ name }}</label>
                </div>
              </div>

              <div class="mb-3">
                <label class="form-label">
                  OOB HTTP callback
                  <HelpTip text="URL the database server can reach. Payloads hit {base}/api/oob/<token> on this scanner." />
                </label>
                <input v-model="form.oobCallback" class="form-control" type="text" placeholder="http://YOUR_PUBLIC_IP:8000" />
              </div>
              <div class="mb-3">
                <label class="form-label">
                  OOB DNS domain
                  <HelpTip text="Collaborator suffix. Probes look up {token}.{domain}." />
                </label>
                <input v-model="form.oobDomain" class="form-control" type="text" placeholder="xyz.oastify.com" />
              </div>
              <div class="mb-3">
                <label class="form-label">
                  Interactsh server
                  <HelpTip text="e.g. oast.pro. Registers, uses that domain for DNS probes, then polls to confirm a hit." />
                </label>
                <input v-model="form.oobInteractsh" class="form-control" type="text" placeholder="oast.pro" />
              </div>
              <div class="mb-3">
                <label class="form-label">Interactsh auth token</label>
                <input v-model="form.oobInteractshToken" class="form-control" type="text" placeholder="optional" />
              </div>
              <div class="mb-3">
                <label class="form-label">
                  Burp / custom poll URL
                  <HelpTip text="After DNS probes, GET this URL. Confirmed if the unique token appears in the body." />
                </label>
                <input
                  v-model="form.oobPollUrl"
                  class="form-control"
                  type="text"
                  placeholder="https://polling.example.com/burpresults?biid=…"
                />
              </div>
              <div class="mb-0">
                <label class="form-label">Poll URL Authorization</label>
                <input v-model="form.oobPollAuth" class="form-control" type="text" placeholder="Bearer …" />
              </div>
            </div>
          </div>
        </div>
      </div>

      <div class="form-check mb-3">
        <input id="consent" v-model="form.consent" class="form-check-input" type="checkbox" />
        <label class="form-check-label" for="consent">
          I am authorized to test this target and accept responsibility for this scan.
        </label>
      </div>

      <button type="submit" class="btn btn-falcon px-4" :disabled="!form.consent">
        {{ props.runningCount > 0 ? "Start another scan" : "Start scan" }}
      </button>
    </form>

    <div v-show="tab === 'history'" class="card-body">
      <p v-if="!history.length" class="text-secondary mb-0">
        No scans yet. Start one from the <strong>New scan</strong> tab.
      </p>
      <template v-else>
        <div class="d-flex justify-content-end mb-3">
          <button type="button" class="btn btn-sm btn-outline-danger" @click="confirmClear">
            Clear all
          </button>
        </div>
        <div class="list-group list-group-flush">
          <div
            v-for="s in history"
            :key="s.scan_id"
            class="list-group-item list-group-item-action hist-item rounded-3 mb-2 border"
            :class="{ active: s.scan_id === selectedId }"
            role="button"
            tabindex="0"
            @click="openHistoryScan(s.scan_id)"
            @keydown.enter="openHistoryScan(s.scan_id)"
          >
            <div class="d-flex justify-content-between align-items-center gap-2">
              <span class="badge" :class="statusBadge(s.status)">{{ s.status }}</span>
              <div class="d-flex align-items-center gap-2">
                <span class="small text-secondary">{{ s.findings_count || 0 }} finding(s)</span>
                <button
                  type="button"
                  class="btn btn-sm btn-outline-danger py-0 px-2"
                  title="Remove this scan and its stored artifacts"
                  @click.stop="confirmDelete(s.scan_id)"
                >
                  Remove
                </button>
              </div>
            </div>
            <div class="small text-break mt-1">{{ s.url }}</div>
            <div class="small text-secondary">{{ s.scan_id }}</div>
          </div>
        </div>
      </template>
    </div>
  </div>
</template>
