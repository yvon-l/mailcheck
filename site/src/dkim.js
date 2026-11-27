// DKIM keys can't be listed, only looked up by selector name, so we try the
// names the common providers use and any the visitor types in.

export const COMMON_SELECTORS = [
  "google", "selector1", "selector2", "protonmail", "protonmail2", "protonmail3",
  "key1", "key2", "key3", "fm1", "fm2", "fm3", "k1", "k2", "s1", "s2",
  "default", "dkim", "mail", "smtp", "sig1", "zmail", "mandrill", "mxvault",
];

export function parseDkim(record) {
  const tags = {};
  for (const part of String(record).split(";")) {
    const eq = part.indexOf("=");
    if (eq < 1) continue;
    tags[part.slice(0, eq).trim().toLowerCase()] = part.slice(eq + 1).replace(/\s+/g, "");
  }
  const keyType = (tags.k || "rsa").toLowerCase();
  const p = tags.p ?? null;
  let bits = null;
  if (p && keyType === "rsa") {
    // The key is a DER SubjectPublicKeyInfo; its length tells us the size closely enough.
    const bytes = Math.floor((p.replace(/=+$/, "").length * 3) / 4);
    bits = bytes < 120 ? 512 : bytes < 200 ? 1024 : bytes < 330 ? 2048 : bytes < 600 ? 4096 : 8192;
  }
  return { tags, keyType, revoked: p === "", bits, valid: p !== null };
}

function looksLikeDkim(txt) {
  return /(^|;)\s*(v=DKIM1|p=)/i.test(txt);
}

// A selector nobody would ever use. If it answers, the domain has a catch-all
// (wildcard) record that answers every selector the same way.
export const PROBE_SELECTOR = "mailcheck-probe-7q2x";

// Returns { keys: [{ selector, record, parsed }], wildcard: { record, parsed } | null }.
// Selectors that only return the catch-all record are left out of keys.
export async function findDkim(dns, domain, extra = []) {
  const names = [...new Set([...extra.map((s) => s.trim().toLowerCase()).filter(Boolean), ...COMMON_SELECTORS])];
  const lookup = async (sel) => {
    const r = await dns.txt(`${sel}._domainkey.${domain}`);
    const rec = r.values.find(looksLikeDkim);
    return rec ? { selector: sel, record: rec, parsed: parseDkim(rec) } : null;
  };
  const [probe, ...results] = await Promise.all([lookup(PROBE_SELECTOR), ...names.map(lookup)]);
  const wildcard = probe ? { record: probe.record, parsed: probe.parsed } : null;
  const keys = results.filter(Boolean).filter((k) => !wildcard || k.record !== wildcard.record);
  return { keys, wildcard };
}
