// Wires the page together.
import { createResolver, RESOLVERS } from "./dns.js";
import { checkDomain, cleanDomain } from "./check.js";
import { renderSingle, bulkTable, fillBulkRow, copyText } from "./render.js";
import { singleReport, bulkReport, allFixes, sortWorstFirst } from "./report.js";

const MAX_DOMAINS = 50;
const $ = (id) => document.getElementById(id);

const state = { resolver: "cloudflare", running: false };

function resolverChoice() {
  const v = $("resolver").value;
  return RESOLVERS[v] ? v : "cloudflare";
}

function setStatus(text) { $("status").textContent = text; }

function selectors() {
  const s = $("selector").value.trim().toLowerCase();
  return /^[a-z0-9._-]{1,63}$/.test(s) ? [s] : [];
}

async function runSingle(raw, { push = true } = {}) {
  const domain = cleanDomain(raw);
  const results = $("results");
  if (!domain) {
    setStatus("That doesn't look like a domain. Try something like example.com.");
    results.replaceChildren();
    return;
  }
  if (state.running) return;
  state.running = true;
  $("domain").value = domain;
  setStatus(`Checking ${domain}…`);
  results.replaceChildren();
  results.setAttribute("aria-busy", "true");
  try {
    const dns = createResolver({ resolver: resolverChoice() });
    const result = await checkDomain(dns, domain, { selectors: selectors() });
    const report = result.missing || result.error ? null : singleReport(result);
    renderSingle(results, result, report);
    setStatus(result.missing || result.error ? "" : `Checked ${domain} with ${dns.lookups} DNS lookups through ${dns.resolverName}.`);
    if (push) history.replaceState(null, "", `?d=${encodeURIComponent(domain)}`);
    const h = results.querySelector("h2");
    if (h) { h.setAttribute("tabindex", "-1"); h.focus({ preventScroll: false }); }
  } catch {
    setStatus("Something went wrong while checking. Try again.");
  } finally {
    results.removeAttribute("aria-busy");
    state.running = false;
  }
}

async function runBulk(text) {
  const seen = new Set();
  const domains = [];
  const bad = [];
  for (const line of text.split(/[\r\n,;]+/)) {
    if (!line.trim()) continue;
    const d = cleanDomain(line);
    if (!d) { bad.push(line.trim()); continue; }
    if (!seen.has(d)) { seen.add(d); domains.push(d); }
  }
  if (!domains.length) { setStatus("Add at least one domain, one per line."); return; }
  if (domains.length > MAX_DOMAINS) { setStatus(`That's ${domains.length} domains. Check up to ${MAX_DOMAINS} at a time.`); return; }
  if (state.running) return;
  state.running = true;
  history.replaceState(null, "", location.pathname);
  const ui = bulkTable($("results"), domains);
  const dns = createResolver({ resolver: resolverChoice(), concurrency: 4 });
  const results = [];
  let done = 0;
  const skipped = bad.length ? ` Skipped ${bad.length} that didn't look like domains.` : "";
  setStatus(`Checking 0 of ${domains.length}…${skipped}`);
  for (const d of domains) {
    let r;
    try { r = await checkDomain(dns, d, { selectors: selectors() }); }
    catch { r = { domain: d, error: "failed" }; }
    results.push(r);
    fillBulkRow(ui.rows.get(d), r);
    done++;
    setStatus(`Checking ${done} of ${domains.length}…${skipped}`);
  }
  // Worst first.
  for (const r of sortWorstFirst(results)) ui.tbody.append(ui.rows.get(r.domain));
  setStatus(`Checked ${domains.length} domains with ${dns.lookups} DNS lookups through ${dns.resolverName}.${skipped}`);
  const rep = bulkReport(results);
  ui.copyAll.disabled = false;
  ui.copyRep.disabled = false;
  ui.copyAll.addEventListener("click", () => copyText(allFixes(results), ui.copyAll));
  ui.copyRep.addEventListener("click", () => copyText(rep.text, ui.copyRep, rep.html));
  state.running = false;
}

function setMode(bulk) {
  $("single").hidden = bulk;
  $("bulk").hidden = !bulk;
  $("toggle-mode").textContent = bulk ? "Check one domain" : "Check several domains";
  (bulk ? $("domains") : $("domain")).focus();
}

function init() {
  $("single").addEventListener("submit", (e) => { e.preventDefault(); runSingle($("domain").value); });
  $("bulk").addEventListener("submit", (e) => { e.preventDefault(); runBulk($("domains").value); });
  $("toggle-mode").addEventListener("click", () => setMode($("bulk").hidden));
  $("resolver").addEventListener("change", () => { $("resolver-name").textContent = RESOLVERS[resolverChoice()].name; });
  const d = new URLSearchParams(location.search).get("d");
  if (d) runSingle(d, { push: false });
}

init();
