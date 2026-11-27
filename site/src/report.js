// The Copy report text: a clean table for Docs, Word and email, plus Markdown as plain text.
import { STATUS_LABEL, VERDICT } from "./check.js";

export function htmlEscape(s) {
  return String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
function md(s) {
  return String(s).replace(/[\\`*_[\]<>|]/g, (c) => "\\" + c);
}
// Plain table attributes, not style="", so the page's strict CSP has nothing to object to.
// Docs, Word and email clients all draw these as a bordered table.
const TABLE = 'border="1" cellpadding="6" cellspacing="0"';
const TD = 'align="left" valign="top"';

function htmlTable(head, rows) {
  return `<table ${TABLE}><thead><tr>${head.map((h) => `<th ${TD}>${htmlEscape(h)}</th>`).join("")}</tr></thead><tbody>${rows.map((r) => `<tr>${r.map((c) => `<td ${TD}>${htmlEscape(c)}</td>`).join("")}</tr>`).join("")}</tbody></table>`;
}
function mdTable(head, rows) {
  return [`| ${head.map(md).join(" | ")} |`, `| ${head.map(() => "---").join(" | ")} |`, ...rows.map((r) => `| ${r.map(md).join(" | ")} |`)].join("\n");
}

function fixRows(result) {
  return Object.values(result.fixes).map((f) => [f.type, f.host === "@" ? result.domain : f.name, f.value]);
}

export function singleReport(result, when = new Date()) {
  const v = VERDICT[result.verdict];
  const date = when.toISOString().slice(0, 10);
  const checks = result.checks.map((c) => [c.name, STATUS_LABEL[c.status], c.summary]);
  const senders = result.spf.senders.map((s) => [s.name, s.how, s.note || ""]);
  const findings = result.findings.map((f) => [STATUS_LABEL[f.status], f.title]);
  const fixes = fixRows(result);

  const html = [
    `<p><strong>Email check: ${htmlEscape(result.domain)}</strong><br>${htmlEscape(v.label)}. ${htmlEscape(v.line)}<br>Checked ${date}</p>`,
    findings.length ? `<p><strong>What needs attention</strong></p>${htmlTable(["Status", "Finding"], findings)}` : "",
    senders.length ? `<p><strong>Who can send email as this domain</strong></p>${htmlTable(["Sender", "Allowed by", "Note"], senders)}` : "",
    fixes.length ? `<p><strong>Records to publish</strong></p>${htmlTable(["Type", "Name", "Value"], fixes)}` : "",
    `<p><strong>Every check</strong></p>${htmlTable(["Check", "Status", "Detail"], checks)}`,
    `<p><small>From mailcheck.kimberly-wood.com, using public DNS.</small></p>`,
  ].join("");

  const text = [
    `## Email check: ${md(result.domain)}`,
    "",
    `**${v.label}.** ${v.line}`,
    `Checked ${date}`,
    findings.length ? `\n### What needs attention\n\n${mdTable(["Status", "Finding"], findings)}` : "",
    senders.length ? `\n### Who can send email as this domain\n\n${mdTable(["Sender", "Allowed by", "Note"], senders)}` : "",
    fixes.length ? `\n### Records to publish\n\n${mdTable(["Type", "Name", "Value"], fixes)}` : "",
    `\n### Every check\n\n${mdTable(["Check", "Status", "Detail"], checks)}`,
    "",
    "From mailcheck.kimberly-wood.com, using public DNS.",
  ].filter((x) => x !== "").join("\n");
  return { html, text };
}

const RANK = { open: 0, parkedOpen: 0, partial: 1, parkedPartial: 1, locked: 2, parkedLocked: 2 };

export function sortWorstFirst(results) {
  return [...results].sort((a, b) => {
    const ra = a.missing || a.error ? 3 : RANK[a.verdict];
    const rb = b.missing || b.error ? 3 : RANK[b.verdict];
    return ra - rb || a.domain.localeCompare(b.domain);
  });
}

export function bulkReport(results, when = new Date()) {
  const date = when.toISOString().slice(0, 10);
  const rows = sortWorstFirst(results).map((r) => r.missing ? [r.domain, "", "Doesn't exist", ""] : r.error ? [r.domain, "", "Couldn't check", ""] : [
    r.domain, r.sending ? "Yes" : "No", VERDICT[r.verdict].label, Object.values(r.fixes).filter((f) => !f.optional).map((f) => `${f.type} ${f.host}`).join(", ") || "Nothing",
  ]);
  const head = ["Domain", "Sends email", "Verdict", "To add"];
  return {
    html: `<p><strong>Email check: ${results.length} domains</strong><br>Checked ${date}</p>${htmlTable(head, rows)}<p><small>From mailcheck.kimberly-wood.com, using public DNS.</small></p>`,
    text: `## Email check: ${results.length} domains\n\nChecked ${date}\n\n${mdTable(head, rows)}\n\nFrom mailcheck.kimberly-wood.com, using public DNS.`,
  };
}

// One line per record, ready to hand to whoever runs DNS.
export function allFixes(results) {
  const lines = [];
  for (const r of sortWorstFirst(results)) {
    if (r.missing || r.error) continue;
    for (const f of Object.values(r.fixes).filter((x) => !x.optional)) {
      const name = f.host === "@" ? r.domain : f.name;
      lines.push(`${name}\t${f.type}\t${f.type === "TXT" ? `"${f.value}"` : f.value}`);
    }
  }
  return lines.length ? `# Name\tType\tValue\n${lines.join("\n")}` : "Nothing to add. Every domain is locked down.";
}
