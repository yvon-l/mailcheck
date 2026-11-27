// Writes the corrected records. Everything here is a rule written in advance:
// the same records in always give the same fix out.
import { matchSuffix, senderFor } from "./vendors.js";
import { LOOKUP_LIMIT } from "./spf.js";

function treeHas(node, pattern) {
  if (!node) return false;
  if (matchSuffix(node.domain, pattern)) return true;
  return node.children.some((c) => treeHas(c, pattern));
}

// Addresses listed in the domain's own records (its record, its own lists, a redirect
// target), not the ones inside a recognised vendor's include.
function treeHasAddresses(node, domain) {
  if (!node) return false;
  if (node.parsed && node.parsed.terms.some((t) => t.mechanism === "ip4" || t.mechanism === "ip6")) return true;
  return node.children
    .filter((c) => !senderFor(c.domain) && (c.via === "redirect" || matchSuffix(c.domain, domain)))
    .some((c) => treeHasAddresses(c, domain));
}

// "missing": the provider's include isn't anywhere in the tree and there are no raw
// addresses that might cover it. "unsure": no include, but the record lists addresses
// directly (a "flattened" SPF), so the provider may well be covered by those.
export function providerSpfState(spfTree, provider) {
  if (!provider || !provider.spf || !spfTree || !spfTree.root.parsed) return "ok";
  if (treeHas({ domain: "", children: spfTree.root.children }, provider.spf)) return "ok";
  return treeHasAddresses(spfTree.root, spfTree.root.domain) ? "unsure" : "missing";
}

export function providerMissingFromSpf(spfTree, provider) {
  return providerSpfState(spfTree, provider) === "missing";
}

// Returns { value, changes: [..], lookupsAfter, stillOver } or null when nothing needs changing.
export function fixSpf({ domain, spf, provider, sending }) {
  // No record at all.
  if (spf.records.length === 0) {
    if (!sending) return { value: "v=spf1 -all", changes: ["Added a record that says nothing sends mail for this domain"], lookupsAfter: 0, stillOver: false };
    if (provider && provider.spf) return { value: `v=spf1 include:${provider.spf} ~all`, changes: [`Added a record that allows ${provider.name}`], lookupsAfter: null, stillOver: false };
    return null; // we can't guess who sends their mail
  }

  const tree = spf.tree;
  const changes = [];
  let terms = [];
  let all = null;
  let redirect = null;

  const sources = spf.records.length > 1 ? spf.records.map((r) => parseRecord(r)) : [tree.root.parsed];
  if (spf.records.length > 1) changes.push("Merged your SPF records into one");

  const dead = new Set(tree.dangling.map((d) => d.domain));
  const empty = new Set((tree.root.children || []).filter((c) => c.state === "none").map((c) => c.domain));
  const seen = new Set();
  let removedLookups = 0;

  for (const parsed of sources) {
    if (!parsed) continue;
    for (const t of parsed.terms) {
      if (t.mechanism === "all") { all = all || t.qualifier; continue; }
      const key = `${t.mechanism}:${t.value}${t.cidr}`;
      if (seen.has(key)) { changes.push(`Removed a duplicate ${t.raw}`); if (t.mechanism !== "ip4" && t.mechanism !== "ip6") removedLookups++; continue; }
      seen.add(key);
      if (t.mechanism === "include" && dead.has(t.value)) { changes.push(`Removed include:${t.value}, which points to a domain that doesn't exist`); removedLookups++; continue; }
      if (t.mechanism === "include" && empty.has(t.value)) { changes.push(`Removed include:${t.value}, which has no SPF record`); removedLookups++; continue; }
      if (t.mechanism === "ptr") { changes.push(`Removed ${t.raw}, which the SPF standard says not to use`); removedLookups++; continue; }
      if ((t.mechanism === "a" || t.mechanism === "mx") && t.value && dead.has(t.value)) { changes.push(`Removed ${t.raw}, which points to a domain that doesn't exist`); removedLookups++; continue; }
      terms.push(t.raw.replace(/^\+/, ""));
    }
    if (parsed.modifiers && parsed.modifiers.redirect && !redirect) redirect = parsed.modifiers.redirect;
  }

  if (redirect && dead.has(redirect.toLowerCase())) {
    changes.push(`Removed redirect=${redirect}, which points to a domain that doesn't exist`);
    redirect = null;
    removedLookups++;
  }

  let added = 0;
  if (sending && provider && provider.spf && !provider.forwardingOnly && providerMissingFromSpf(tree, provider) && !redirect) {
    terms.unshift(`include:${provider.spf}`);
    changes.push(`Added include:${provider.spf}, because ${provider.name} handles your mail`);
    added = 1;
  }

  if (!redirect) {
    if (all === "+") { changes.push("Changed +all to ~all, so other servers are no longer allowed"); all = "~"; }
    else if (all === "?") { changes.push("Changed ?all to ~all, so unlisted servers are treated as suspicious"); all = "~"; }
    else if (!all) { changes.push("Added ~all at the end, so unlisted servers are treated as suspicious"); all = "~"; }
    if (!sending && terms.length === 0 && all !== "-") { changes.push("Changed to -all, because nothing sends mail for this domain"); all = "-"; }
  }

  if (changes.length === 0) return null;
  const value = ["v=spf1", ...terms, redirect ? `redirect=${redirect}` : `${all}all`].join(" ");
  const lookupsAfter = Math.max(0, tree.lookups - removedLookups) + added;
  return { value, changes, lookupsAfter, stillOver: lookupsAfter > LOOKUP_LIMIT };
}

function parseRecord(r) {
  // Local import cycle avoided: a tiny re-parse for merged records.
  const parts = r.trim().split(/\s+/).slice(1);
  const terms = [];
  const modifiers = {};
  for (const raw of parts) {
    const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
    if (mod) { modifiers[mod[1].toLowerCase()] = mod[2]; continue; }
    const m = /^([+?~-]?)([a-z0-9]+)(?::([^/]*))?(\/.*)?$/i.exec(raw);
    if (!m) continue;
    terms.push({ raw, qualifier: m[1] || "+", mechanism: m[2].toLowerCase(), value: m[3] ? m[3].toLowerCase() : "", cidr: m[4] || "" });
  }
  return { terms, modifiers };
}

// The next DMARC record to publish. Returns { value, step, note } or null.
export function fixDmarc({ domain, dmarc, sending }) {
  if (!sending) {
    const p = dmarc.found && dmarc.parsed ? dmarc.parsed.policy : null;
    if (p === "reject" && !dmarc.inherited && dmarc.parsed.pct === 100) return null;
    if (dmarc.inherited && dmarc.parsed && (dmarc.parsed.subdomainPolicy || dmarc.parsed.policy) === "reject") return null;
    return { value: "v=DMARC1; p=reject;", step: "Reject everything", note: "Nothing sends mail for this domain, so it's safe to tell receivers to reject anything that claims to be from it." };
  }

  if (!dmarc.found) {
    return {
      value: `v=DMARC1; p=none; rua=mailto:dmarc-reports@${domain}`,
      step: "Start watching",
      note: `This only collects reports at first. Create the dmarc-reports@${domain} mailbox, or change it to one you already read. After two to four weeks, when the reports show your real senders passing, move to quarantine.`,
    };
  }
  if (dmarc.multiple || !dmarc.parsed || dmarc.parsed.problems.length) {
    const keep = dmarc.parsed && dmarc.parsed.rua ? `; rua=${dmarc.parsed.rua}` : "";
    return { value: `v=DMARC1; p=none${keep};`, step: "Fix the record", note: "Your DMARC record can't be read, so receivers ignore it. Replace it with this one, then tighten it as below." };
  }

  const t = { ...dmarc.parsed.tags };
  const p = dmarc.inherited ? (dmarc.parsed.subdomainPolicy || dmarc.parsed.policy) : dmarc.parsed.policy;
  let step, note;
  if (dmarc.parsed.pct < 100) {
    delete t.pct;
    step = "Apply it to all mail";
    note = `Your policy only applies to ${dmarc.parsed.pct}% of mail. Remove pct so it covers everything.`;
  } else if (p === "none") {
    t.p = "quarantine";
    step = "Move to quarantine";
    note = "Do this once your reports show every real sender passing. Failing mail then goes to spam instead of the inbox.";
  } else if (p === "quarantine") {
    t.p = "reject";
    step = "Move to reject";
    note = "Do this after a few weeks at quarantine with nothing real landing in spam. Failing mail is then refused outright.";
  } else {
    return null;
  }
  if (dmarc.inherited) {
    return { value: `v=DMARC1; p=${t.p || p};`, step, note: `${note} This domain currently borrows its policy from ${dmarc.at}. Publishing its own record at _dmarc.${domain} lets you set it separately.` };
  }
  const order = ["v", "p", "sp", "pct", "rua", "ruf", "adkim", "aspf", "fo", "ri", "rf"];
  const keys = [...order.filter((k) => k in t), ...Object.keys(t).filter((k) => !order.includes(k))];
  const value = keys.map((k) => `${k === "v" ? "v" : k}=${k === "v" ? "DMARC1" : t[k]}`).join("; ") + ";";
  return { value, step, note };
}

export const NULL_MX = "0 .";
