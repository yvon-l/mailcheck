// DMARC: find the policy that applies to a domain and read it.
import { NOERROR, NXDOMAIN } from "./dns.js";

// Enough of the public suffix list to find the organisational domain for
// common two-part endings. Anything else falls back to the last two labels.
const TWO_PART = new Set([
  "co.uk", "org.uk", "ac.uk", "gov.uk", "ltd.uk", "plc.uk", "me.uk", "net.uk",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "org.nz", "net.nz", "co.jp", "ne.jp", "or.jp", "ac.jp",
  "com.br", "net.br", "org.br", "co.za", "org.za", "com.mx", "com.ar",
  "co.in", "net.in", "org.in", "com.sg", "com.hk", "com.tr", "co.il", "com.cn",
  "co.kr", "com.tw", "com.my", "com.ph", "co.id", "com.vn", "com.ua", "com.pl",
]);

export function orgDomain(domain) {
  const labels = domain.split(".");
  if (labels.length <= 2) return domain;
  const lastTwo = labels.slice(-2).join(".");
  if (TWO_PART.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}

export function parseDmarc(record) {
  const tags = {};
  const problems = [];
  const parts = String(record).split(";").map((s) => s.trim()).filter(Boolean);
  parts.forEach((p, i) => {
    const eq = p.indexOf("=");
    if (eq < 1) { problems.push(`"${p}" isn't a valid tag`); return; }
    const k = p.slice(0, eq).trim().toLowerCase();
    const v = p.slice(eq + 1).trim();
    if (i === 0 && (k !== "v" || v.toUpperCase() !== "DMARC1")) problems.push("The record must start with v=DMARC1");
    tags[k] = v;
  });
  const p = (tags.p || "").toLowerCase();
  if (!["none", "quarantine", "reject"].includes(p)) problems.push(tags.p ? `"p=${tags.p}" isn't a valid policy` : "There's no p= policy");
  const pct = tags.pct === undefined ? 100 : Number(tags.pct);
  if (Number.isNaN(pct) || pct < 0 || pct > 100) problems.push(`"pct=${tags.pct}" isn't between 0 and 100`);
  const sp = tags.sp ? tags.sp.toLowerCase() : null;
  return {
    tags, problems,
    policy: ["none", "quarantine", "reject"].includes(p) ? p : null,
    subdomainPolicy: ["none", "quarantine", "reject"].includes(sp) ? sp : null,
    pct: Number.isNaN(pct) ? 100 : pct,
    rua: tags.rua || null,
    ruf: tags.ruf || null,
  };
}

// Returns { found, at, record, parsed, inherited, multiple, error }
export async function getDmarc(dns, domain) {
  async function at(name) {
    const r = await dns.txt(`_dmarc.${name}`);
    const recs = r.values.filter((v) => /^v\s*=\s*DMARC1/i.test(v.trim()));
    return { r, recs };
  }
  let { r, recs } = await at(domain);
  if (r.status !== NOERROR && r.status !== NXDOMAIN) return { found: false, error: r.error || "lookup failed" };
  let where = domain;
  let inherited = false;
  if (recs.length === 0) {
    const org = orgDomain(domain);
    if (org !== domain) {
      ({ r, recs } = await at(org));
      if (recs.length) { where = org; inherited = true; }
    }
  }
  if (recs.length === 0) return { found: false };
  if (recs.length > 1) return { found: true, multiple: true, at: where, record: recs.join(" | "), parsed: null, inherited };
  const parsed = parseDmarc(recs[0]);
  return { found: true, at: where, record: recs[0], parsed, inherited };
}

// The policy that really applies to this domain.
export function effectivePolicy(d) {
  if (!d || !d.found || !d.parsed) return null;
  if (d.inherited && d.parsed.subdomainPolicy) return d.parsed.subdomainPolicy;
  return d.parsed.policy;
}
