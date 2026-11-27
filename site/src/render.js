// Builds the results on the page. Everything that came from DNS goes in as text,
// never as HTML, so a hostile record can't inject anything.
import { STATUS_LABEL, VERDICT } from "./check.js";
import { LOOKUP_LIMIT } from "./spf.js";

export function el(tag, attrs = {}, ...kids) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k === "text") n.textContent = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else n.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false) continue;
    n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return n;
}

function chip(status) {
  return el("span", { class: `chip s-${status}`, text: STATUS_LABEL[status] || status });
}

export async function copyText(text, button, html) {
  try {
    if (html && typeof ClipboardItem !== "undefined") {
      await navigator.clipboard.write([new ClipboardItem({
        "text/plain": new Blob([text], { type: "text/plain" }),
        "text/html": new Blob([html], { type: "text/html" }),
      })]);
    } else {
      await navigator.clipboard.writeText(text);
    }
    flash(button, "Copied");
  } catch {
    flash(button, "Couldn't copy");
  }
}

function flash(button, word) {
  if (!button) return;
  const was = button.dataset.label || button.textContent;
  button.dataset.label = was;
  button.textContent = word;
  setTimeout(() => { button.textContent = was; }, 1600);
}

function copyButton(value, label = "Copy") {
  const b = el("button", { type: "button", class: "btn-small", text: label });
  b.addEventListener("click", () => copyText(value, b));
  return b;
}

function recordBlock(fix) {
  return el("div", { class: "record" },
    el("dl", { class: "record-meta" },
      el("div", {}, el("dt", { text: "Name" }), el("dd", { class: "mono", text: fix.host })),
      el("div", {}, el("dt", { text: "Type" }), el("dd", { class: "mono", text: fix.type })),
    ),
    el("div", { class: "record-value" },
      el("code", { class: "mono", text: fix.value }),
      copyButton(fix.value),
    ),
  );
}

function fixFor(result, finding) {
  if (!finding) return null;
  if (finding.check === "SPF") return result.fixes.spf || null;
  if (finding.check === "DMARC") return result.fixes.dmarc || null;
  return null;
}

function verdictCard(result) {
  const v = VERDICT[result.verdict];
  const tone = result.verdict.toLowerCase().includes("locked") ? "good" : result.verdict.toLowerCase().includes("open") ? "risk" : "work";
  const top = result.findings.find((f) => f.status !== "info") || null;
  const topFix = fixFor(result, top) || (result.parked ? (result.fixes.spf || result.fixes.dmarc) : null);
  return el("section", { class: `verdict v-${tone}`, "aria-labelledby": "verdict-h" },
    el("p", { class: "verdict-domain mono", text: result.domain }),
    el("h2", { id: "verdict-h", class: "verdict-label", text: v.label }),
    el("p", { class: "verdict-line", text: v.line }),
    result.parked ? el("p", { class: "verdict-note", text: "This domain has no mail servers and no senders, so it's treated as one that doesn't send email." }) : null,
    top ? el("div", { class: "first-fix" },
      el("p", { class: "first-fix-h", text: "Fix this first" }),
      el("p", { class: "first-fix-title", text: top.title }),
      el("p", { class: "first-fix-detail", text: top.detail }),
      topFix ? recordBlock(topFix) : null,
    ) : null,
  );
}

function sendersSection(result) {
  const s = result.spf;
  if (!s.tree || s.records.length !== 1) return null;
  const rows = s.senders;
  const body = rows.length
    ? el("table", { class: "senders" },
        el("thead", {}, el("tr", {}, el("th", { text: "Sender" }), el("th", { text: "Allowed by" }), el("th", { class: "num", text: "Lookups" }), el("th", { text: "Note" }))),
        el("tbody", {}, rows.map((r) => el("tr", { class: `row-${r.status}` },
          el("td", {}, el("strong", { text: r.name }), r.kind ? el("span", { class: "kind", text: r.kind }) : null),
          el("td", { class: "mono", text: r.how }),
          el("td", { class: "num", text: String(r.lookups) }),
          el("td", { text: r.note || "" }),
        ))),
      )
    : el("p", { text: "Your SPF record doesn't allow any server to send email as this domain." });
  const total = s.tree.lookups;
  return el("section", { class: "block", "aria-labelledby": "senders-h" },
    el("h2", { id: "senders-h", class: "block-h", text: "Who can send email as you" }),
    el("p", { class: "block-lede", text: `From your SPF record. It uses ${total} of the ${LOOKUP_LIMIT} lookups receiving servers allow.` }),
    el("div", { class: "table-wrap" }, body),
  );
}

function fixesSection(result) {
  const list = [];
  if (result.fixes.spf) list.push({ title: "SPF record", fix: result.fixes.spf, extra: result.fixes.spf.changes });
  if (result.fixes.dmarc) list.push({ title: `DMARC: ${result.fixes.dmarc.step}`, fix: result.fixes.dmarc, note: result.fixes.dmarc.note });
  if (result.fixes.nullMx) list.push({ title: "Null MX (optional)", fix: result.fixes.nullMx, note: result.fixes.nullMx.note });
  if (!list.length) return null;
  return el("section", { class: "block", "aria-labelledby": "fixes-h" },
    el("h2", { id: "fixes-h", class: "block-h", text: "Records to publish" }),
    el("p", { class: "block-lede", text: "Add or replace these at your DNS provider. Each one replaces the record of the same type at that name." }),
    list.map((item) => el("div", { class: "fix" },
      el("h3", { text: item.title }),
      recordBlock(item.fix),
      item.extra && item.extra.length ? el("ul", { class: "changes" }, item.extra.map((c) => el("li", { text: c }))) : null,
      item.note ? el("p", { class: "fix-note", text: item.note }) : null,
      item.fix.stillOver ? el("p", { class: "fix-note warn", text: `This still needs about ${item.fix.lookupsAfter} lookups. Remove services you no longer use until it's at 10 or fewer.` }) : null,
    )),
  );
}

function findingsSection(result) {
  if (!result.findings.length) return null;
  return el("section", { class: "block", "aria-labelledby": "find-h" },
    el("h2", { id: "find-h", class: "block-h", text: "What needs attention" }),
    el("ul", { class: "findings" }, result.findings.map((f) => el("li", { class: `finding f-${f.status}` },
      chip(f.status === "info" ? "info" : f.status),
      el("div", {},
        el("p", { class: "finding-title", text: f.title }),
        el("p", { class: "finding-detail", text: f.detail }),
      ),
    ))),
  );
}

function checksSection(result) {
  return el("section", { class: "block", "aria-labelledby": "checks-h" },
    el("h2", { id: "checks-h", class: "block-h", text: "Every check" }),
    el("div", { class: "checks" }, result.checks.map((c) => el("div", { class: "check" },
      el("div", { class: "check-top" }, el("h3", { text: c.name }), chip(c.status)),
      el("p", { class: "check-sum", text: c.summary }),
      c.record ? el("details", { class: "raw" }, el("summary", { text: "Show record" }), el("pre", { class: "mono", text: c.record })) : null,
    ))),
  );
}

function actions(result, report) {
  const copyReport = el("button", { type: "button", class: "btn", text: "Copy report" });
  copyReport.addEventListener("click", () => copyText(report.text, copyReport, report.html));
  const link = `${location.origin}${location.pathname}?d=${encodeURIComponent(result.domain)}`;
  return el("div", { class: "actions" }, copyReport, copyButton(link, "Copy link to this check"));
}

export function renderSingle(container, result, report) {
  container.replaceChildren();
  if (result.missing) {
    container.append(el("section", { class: "verdict v-work" },
      el("p", { class: "verdict-domain mono", text: result.domain }),
      el("h2", { class: "verdict-label", text: "This domain doesn't exist" }),
      el("p", { class: "verdict-line", text: "DNS has no record of it. Check the spelling." }),
    ));
    return;
  }
  if (result.error) {
    container.append(el("section", { class: "verdict v-work" },
      el("p", { class: "verdict-domain mono", text: result.domain }),
      el("h2", { class: "verdict-label", text: "Couldn't check this domain" }),
      el("p", { class: "verdict-line", text: "The DNS service didn't answer. Try again, or switch DNS service at the bottom of the page." }),
    ));
    return;
  }
  container.append(
    verdictCard(result),
    sendersSection(result) || "",
    fixesSection(result) || "",
    findingsSection(result) || "",
    checksSection(result),
    actions(result, report),
  );
}

// ---------- Several domains ----------

export function bulkTable(container, domains) {
  container.replaceChildren();
  const tbody = el("tbody");
  const rows = new Map();
  for (const d of domains) {
    const tr = el("tr", {}, el("td", { class: "mono" }, el("a", { href: `?d=${encodeURIComponent(d)}`, text: d })), el("td", { colspan: "5", class: "pending", text: "Waiting" }));
    rows.set(d, tr);
    tbody.append(tr);
  }
  const copyAll = el("button", { type: "button", class: "btn", text: "Copy all fixes", disabled: true });
  const copyRep = el("button", { type: "button", class: "btn", text: "Copy report", disabled: true });
  container.append(el("section", { class: "block", "aria-labelledby": "bulk-h" },
    el("h2", { id: "bulk-h", class: "block-h", text: "Your domains" }),
    el("p", { class: "block-lede", text: "Worst first once they're all in. Domains with no mail servers and no senders are treated as not sending email, and need SPF -all, DMARC reject, and no MX or a null MX to be locked down." }),
    el("div", { class: "table-wrap" }, el("table", { class: "bulk-table" },
      el("thead", {}, el("tr", {}, ["Domain", "Sends email", "Verdict", "SPF", "DMARC", "To add"].map((h) => el("th", { text: h })))),
      tbody,
    )),
    el("div", { class: "actions" }, copyAll, copyRep),
  ));
  return { rows, tbody, copyAll, copyRep };
}

export function fillBulkRow(tr, result) {
  const cells = [];
  if (result.missing || result.error) {
    cells.push(el("td", { colspan: "5", text: result.missing ? "Doesn't exist" : "Couldn't check" }));
  } else {
    const v = VERDICT[result.verdict];
    const tone = result.verdict.toLowerCase().includes("locked") ? "good" : result.verdict.toLowerCase().includes("open") ? "risk" : "work";
    const spf = result.checks.find((c) => c.name === "SPF");
    const dm = result.checks.find((c) => c.name === "DMARC");
    const toAdd = Object.values(result.fixes).filter((f) => !f.optional).map((f) => `${f.type} ${f.host}`).join(", ");
    cells.push(
      el("td", { text: result.sending ? "Yes" : "No" }),
      el("td", {}, el("span", { class: `chip s-${tone}`, text: v.label })),
      el("td", {}, chip(spf.status)),
      el("td", {}, chip(dm.status)),
      el("td", { class: "mono small", text: toAdd || "Nothing" }),
    );
  }
  tr.replaceChildren(tr.firstChild, ...cells);
}
