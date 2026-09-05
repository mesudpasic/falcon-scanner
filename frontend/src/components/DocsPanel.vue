<script setup>
import { onMounted, onUnmounted, watch } from "vue";

const props = defineProps({
  open: { type: Boolean, default: false },
});
const emit = defineEmits(["update:open"]);

function clearLeftoverOverlays() {
  document.querySelectorAll(".offcanvas-backdrop, .modal-backdrop, .guide-backdrop").forEach((el) => {
    if (!el.closest(".guide-root")) el.remove();
  });
  document.body.classList.remove("modal-open", "offcanvas-open", "guide-open");
  document.body.style.removeProperty("overflow");
  document.body.style.removeProperty("padding-right");
}

function close() {
  emit("update:open", false);
  document.body.classList.remove("guide-open");
  document.body.style.removeProperty("overflow");
  document.body.style.removeProperty("padding-right");
  queueMicrotask(clearLeftoverOverlays);
}

function onKey(event) {
  if (event.key === "Escape" && props.open) close();
}

watch(
  () => props.open,
  (value) => {
    document.body.classList.toggle("guide-open", value);
    if (!value) {
      document.body.style.removeProperty("overflow");
    }
  }
);

onMounted(() => {
  clearLeftoverOverlays();
  document.addEventListener("keydown", onKey);
});
onUnmounted(() => {
  document.removeEventListener("keydown", onKey);
  document.body.classList.remove("guide-open");
  document.body.style.removeProperty("overflow");
});
</script>

<template>
  <Teleport to="body">
    <div v-if="open" class="guide-root">
      <div class="guide-backdrop" @click="close"></div>
      <aside
        id="docsPanel"
        class="guide-panel card card-falcon"
        role="dialog"
        aria-modal="true"
        aria-labelledby="docsPanelLabel"
      >
      <div class="d-flex align-items-center justify-content-between gap-2 px-3 py-3 border-bottom border-secondary-subtle">
        <h2 class="h5 mb-0" id="docsPanelLabel">Guide &amp; options</h2>
        <button type="button" class="btn-close btn-close-white" aria-label="Close" @click="close"></button>
      </div>
      <div class="guide-panel-body docs-section px-3 py-3">
        <p class="text-secondary small mb-3">
          Authorized use only. Only scan hosts you own or have written permission to test.
        </p>

        <h3>5-minute tutorial</h3>
        <ol class="small ps-3">
          <li class="mb-2">
            Paste a URL, one per line. A public practice target is
            <code>http://testphp.vulnweb.com/listproducts.php?cat=1</code>
          </li>
          <li class="mb-2">
            Add the hostname to <strong>Authorized hosts</strong>
            (<code>testphp.vulnweb.com</code>). The scan is refused otherwise.
          </li>
          <li class="mb-2">
            Tick the authorization checkbox. Optional: leave extraction and dump on
            to see what an attacker could read after a confirmed injection.
          </li>
          <li class="mb-2">
            Click <strong>Start scan</strong>. Findings stream live. When it
            finishes, download the HTML report or per-table CSV / JSON.
          </li>
        </ol>
        <div class="alert alert-warning py-2 small mb-0">
          Query-string keys on the URL (<code>?cat=1</code>) become parameters
          automatically. You do not have to re-type them unless you want extra ones.
        </div>

        <h3>What the scanner does</h3>
        <p class="small text-secondary">
          For each parameter it runs detectors (fingerprint, error, boolean, UNION,
          stacked queries, time-based, OOB). After a confirmed injection it tries
          to extract data: UNION first (fast), then boolean-blind, then time-blind.
        </p>

        <h3>Target &amp; session</h3>
        <dl class="small mb-0">
          <dt>Target URLs</dt>
          <dd class="text-secondary">
            One endpoint per line. They are scanned in parallel (see workers below).
          </dd>
          <dt>Method</dt>
          <dd class="text-secondary">
            <code>GET</code> sends parameters in the query string;
            <code>POST</code> sends them as a form body.
          </dd>
          <dt>Parameters</dt>
          <dd class="text-secondary">
            Baseline <code>key=value</code> pairs. The scanner mutates one key at a
            time. Merged onto every URL.
          </dd>
          <dt>Cookies</dt>
          <dd class="text-secondary">
            Session cookies (<code>PHPSESSID=…</code>) sent with every request so
            you can test authenticated pages.
          </dd>
          <dt>Authorized hosts</dt>
          <dd class="text-secondary">
            Allowlist of hostnames (globs like <code>*.example.com</code>). Required.
            Private / loopback addresses are also blocked unless you opt in via the API.
          </dd>
          <dt>Max requests/sec</dt>
          <dd class="text-secondary">
            Rate limit so the target is not flooded. Default 10.
          </dd>
          <dt>Parallel workers</dt>
          <dd class="text-secondary">
            How many URLs / crawled endpoints to test at once. Shared rate limit
            still applies.
          </dd>
        </dl>

        <h3>Extraction</h3>
        <dl class="small mb-0">
          <dt>Attempt data extraction</dt>
          <dd class="text-secondary">
            After an injection is confirmed, read version, user, current database,
            then list schemas / tables.
          </dd>
          <dt>Blind catalog enumeration</dt>
          <dd class="text-secondary">
            When only boolean- or time-blind works, reconstruct database / schema /
            table names character-by-character. Slow (especially time-based).
          </dd>
          <dt>Dump full table contents</dt>
          <dd class="text-secondary">
            UNION channel only. Pulls rows from enumerated tables. Leave max
            tables / rows blank to take everything; set caps to bound request volume.
          </dd>
        </dl>

        <h3>Discovery, WAF evasion &amp; OOB</h3>
        <p class="small text-secondary">
          These options live under the <strong>Discovery, WAF evasion &amp; OOB</strong>
          accordion on the New scan form. Leave them closed for a simple single-URL
          scan. Open them when the app has more pages, a filter is blocking
          payloads, or you need a callback the database can reach.
        </p>

        <h3 class="h6">Discovery</h3>
        <dl class="small mb-0">
          <dt>Crawl for links, forms, and parameters</dt>
          <dd class="text-secondary">
            After the URLs you typed, the crawler fetches each page and collects
            in-scope <code>&lt;a href&gt;</code> links plus form actions and field
            names. Those become extra targets. It never leaves
            <strong>Authorized hosts</strong> (same allowlist as the rest of the
            scan). Logout / sign-out URLs and static files
            (<code>.css</code>, <code>.js</code>, images, fonts, PDFs) are skipped.
            Query-string keys and form inputs become parameters the detectors
            later mutate. Off by default — turn it on when you only have an entry
            URL and want the rest of the app discovered.
          </dd>
          <dt>Crawl depth</dt>
          <dd class="text-secondary">
            How many link hops from a starting URL. <code>0</code> only inspects
            the pages you pasted. Default <code>2</code>. Cap is 6 so a large
            site cannot be walked forever.
          </dd>
          <dt>Max pages</dt>
          <dd class="text-secondary">
            Hard stop on how many HTML pages are fetched. Default <code>50</code>,
            max 500. Each crawled endpoint is then scanned in parallel using
            <strong>Workers</strong>, still under the global rate limit.
          </dd>
        </dl>

        <h3 class="h6">WAF fingerprint &amp; evasion</h3>
        <dl class="small mb-0">
          <dt>Fingerprint WAF / IPS first</dt>
          <dd class="text-secondary">
            Sends a noisy probe (typical SQLi characters) and matches the
            response against product signatures: Cloudflare, AWS WAF, Akamai,
            Imperva, ModSecurity, and others. A hit is shown in Results as a WAF
            banner. It does not bypass the filter by itself — it only tells you
            (and Auto-tamper) that one is there. On by default; turn it off if
            the extra probe is too loud for the engagement.
          </dd>
          <dt>Auto-enable tampers if a WAF is detected</dt>
          <dd class="text-secondary">
            When a WAF is fingerprinted <em>and</em> you have not ticked any
            tamper scripts yourself, apply the default chain
            <code>space2comment</code> → <code>randomcase</code> →
            <code>between</code>. If you pick tampers manually, your list is
            used instead — auto-tamper will not override it. On by default.
          </dd>
          <dt>Tamper scripts</dt>
          <dd class="text-secondary">
            Rewrites every injected value just before the HTTP request, so a
            signature-based filter is less likely to match. Semantics stay the
            same for the database. Scripts run in the order you enable them.
            Unknown names are ignored.
          </dd>
        </dl>
        <ul class="small text-secondary ps-3 mb-3">
          <li class="mb-1">
            <code>space2comment</code> — spaces become <code>/**/</code>
            (MySQL-style empty comments).
          </li>
          <li class="mb-1">
            <code>space2plus</code> — spaces become <code>+</code>.
          </li>
          <li class="mb-1">
            <code>randomcase</code> — randomize keyword case
            (<code>UnIoN SeLeCt</code>); quoted strings are left alone.
          </li>
          <li class="mb-1">
            <code>between</code> — rewrite <code>AND 1=1</code> style tests to
            <code>AND 1 BETWEEN 1 AND 1</code>.
          </li>
          <li class="mb-1">
            <code>equaltolike</code> — replace <code>=</code> with
            <code>LIKE</code>.
          </li>
          <li class="mb-1">
            <code>versionedcomment</code> — wrap keywords in MySQL versioned
            comments (<code>/*!UNION*/</code>).
          </li>
          <li class="mb-1">
            <code>commentbeforeparen</code> — insert <code>/**/</code> next to
            parentheses.
          </li>
          <li class="mb-1">
            <code>apostrophenull</code> — turn <code>'</code> into
            <code>%27</code> so some filters miss the quote.
          </li>
        </ul>

        <h3 class="h6">Out-of-band (OOB)</h3>
        <p class="small text-secondary">
          OOB is used when the page does not change and does not delay, but the
          <em>database server</em> can still make a network call. The scanner
          injects a unique token and waits for that token to come back. HTTP
          hits land in this process; DNS hits need a collaborator you poll.
          Leave these blank unless the DB host can reach your callback or a
          collaborator. The browser never sees the OOB request.
        </p>
        <dl class="small mb-0">
          <dt>OOB HTTP callback</dt>
          <dd class="text-secondary">
            Public base URL of <em>this</em> scanner that the database server
            can open, e.g. <code>http://YOUR_PUBLIC_IP:8000</code> (or the
            Docker-published API). Payloads (Oracle
            <code>UTL_HTTP.REQUEST</code>, MSSQL OLE
            <code>MSXML2.ServerXMLHTTP</code>, PostgreSQL
            <code>dblink_connect</code>, …) request
            <code>{base}/api/oob/&lt;token&gt;</code>. A hit in the inbox
            confirms execution. Your laptop’s <code>localhost</code> only works
            if the database is on the same machine.
          </dd>
          <dt>OOB DNS domain</dt>
          <dd class="text-secondary">
            Collaborator suffix you already control. Probes resolve
            <code>{token}.{domain}</code> via MySQL
            <code>LOAD_FILE('\\\\host\\o')</code>, MSSQL
            <code>xp_dirtree</code>, Oracle <code>UTL_INADDR</code>, and
            similar UNC / DNS tricks. Listing the domain alone does
            <strong>not</strong> confirm a hit — pair it with Interactsh or a
            poll URL below. Without a poller the finding is reported as
            unconfirmed.
          </dd>
          <dt>Interactsh server</dt>
          <dd class="text-secondary">
            Host only, e.g. <code>oast.pro</code> (public ProjectDiscovery
            server) or your own Interactsh instance. The scanner registers,
            uses the issued domain for DNS probes, then polls and decrypts
            interactions. If this is set, you usually do not also need
            <strong>OOB DNS domain</strong> — the registered name is used.
          </dd>
          <dt>Interactsh auth token</dt>
          <dd class="text-secondary">
            Optional <code>Authorization</code> token for a private Interactsh
            server. Leave empty for the public <code>oast.pro</code> pool.
          </dd>
          <dt>Burp / custom poll URL</dt>
          <dd class="text-secondary">
            After each DNS probe the scanner GETs this URL. If the unique
            token appears anywhere in the body, the finding is confirmed.
            Typical use: Burp Collaborator polling
            (<code>https://polling.example.com/burpresults?biid=…</code>) or
            any collaborator API that echoes received DNS names. Use this when
            you are not using Interactsh.
          </dd>
          <dt>Poll URL Authorization</dt>
          <dd class="text-secondary">
            Value sent as the <code>Authorization</code> header on the poll
            request — <code>Bearer …</code> or whatever your collaborator
            expects. Needed for private Burp / custom poll endpoints; unused
            for a public Interactsh server.
          </dd>
        </dl>
        <div class="alert alert-secondary py-2 small mb-0">
          You do not need every OOB field. HTTP callback is enough for HTTP
          OOB. For DNS, pick <strong>either</strong> Interactsh
          <strong>or</strong> a poll URL (plus a domain if the poller does
          not issue one). Combining both pollers is unnecessary.
        </div>

        <h3>Reading results</h3>
        <ul class="small text-secondary ps-3">
          <li class="mb-1"><strong>Findings</strong> — technique, parameter, payload, evidence, confidence.</li>
          <li class="mb-1"><strong>Extracted data</strong> — scalars plus databases / schemas / tables.</li>
          <li class="mb-1"><strong>Dump</strong> — live tables; download CSV, JSON, or HTML per table.</li>
          <li class="mb-1"><strong>History</strong> — persisted in SQLite; click a past scan to reopen it. Remove one scan or <strong>Clear all</strong> to drop stored findings, dumps, and events (the audit log is kept).</li>
        </ul>
      </div>
      <div class="px-3 py-3 border-top border-secondary-subtle">
        <button type="button" class="btn btn-falcon w-100" @click="close">Close</button>
      </div>
      </aside>
    </div>
  </Teleport>
</template>
