// SPF: parse the record, follow every include, count lookups, and work out
// who is allowed to send as the domain.
import { NXDOMAIN, NOERROR } from "./dns.js";
import { senderFor, matchSuffix } from "./vendors.js";

export const LOOKUP_LIMIT = 10;
export const VOID_LIMIT = 2;
const HARD_STOP = 40; // keep following past 10 so we can show how far over it is, but not forever

const MECHANISMS = new Set(["all", "include", "a", "mx", "ptr", "ip4", "ip6", "exists"]);
const COUNTS_LOOKUP = new Set(["include", "a", "mx", "ptr", "exists"]);

export function isSpf(txt) {
  return /^v=spf1(\s|$)/i.test(String(txt).trim());
}

export function parseSpf(record) {
  const parts = String(record).trim().split(/\s+/).slice(1);
  const terms = [];
  const modifiers = {};
  const problems = [];
  for (const raw of parts) {
    if (!raw) continue;
    const mod = /^([a-z][a-z0-9_.-]*)=(.*)$/i.exec(raw);
    if (mod) {
      const key = mod[1].toLowerCase();
      if (key in modifiers) problems.push(`"${key}=" appears more than once`);
      modifiers[key] = mod[2];
      continue;
    }
    const m = /^([+?~-]?)([a-z0-9]+)(?::([^/]*))?(\/.*)?$/i.exec(raw);
    if (!m || !MECHANISMS.has(m[2].toLowerCase())) {
      problems.push(`"${raw}" isn't valid SPF`);
      continue;
    }
    terms.push({
      raw,
      qualifier: m[1] || "+",
      mechanism: m[2].toLowerCase(),
      value: m[3] ? m[3].toLowerCase().replace(/\.$/, "") : "",
      cidr: m[4] || "",
    });
  }
  const allTerm = terms.find((t) => t.mechanism === "all") || null;
  return { terms, modifiers, problems, all: allTerm ? allTerm.qualifier + "all" : null };
}

// Fetch the SPF record(s) at a name.
export async function getSpf(dns, name) {
  const r = await dns.txt(name);
  const spf = r.values.filter(isSpf);
  return { status: r.status, error: r.error, records: spf };
}

function targetFor(term, domain) {
  return term.value || domain;
}

// Build the include tree. Every node: { domain, via, state, record, parsed, children, lookups }
// state: ok | none | multiple | nxdomain | error | loop | skipped
export async function expandSpf(dns, domain, opts = {}) {
  const ctx = { lookups: 0, voids: 0, dangling: [], seen: new Set(), notes: [] };

  async function visit(name, via, depth) {
    const node = { domain: name, via, state: "ok", record: null, parsed: null, children: [], lookups: 0, extra: [] };
    if (ctx.seen.has(name)) { node.state = "loop"; return node; }
    if (depth > 10 || ctx.lookups > HARD_STOP) { node.state = "skipped"; return node; }
    ctx.seen.add(name);

    const got = await getSpf(dns, name);
    if (got.status === NXDOMAIN) {
      node.state = "nxdomain";
      if (depth > 0) { ctx.voids++; ctx.dangling.push({ domain: name, via }); }
      return node;
    }
    if (got.status !== NOERROR) { node.state = "error"; node.error = got.error || "lookup failed"; return node; }
    if (got.records.length === 0) {
      node.state = "none";
      if (depth > 0) ctx.voids++;
      return node;
    }
    if (got.records.length > 1) { node.state = "multiple"; node.record = got.records.join(" | "); return node; }

    node.record = got.records[0];
    node.parsed = parseSpf(node.record);
    const before = ctx.lookups;

    for (const term of node.parsed.terms) {
      if (!COUNTS_LOOKUP.has(term.mechanism)) continue;
      ctx.lookups++;
      const target = targetFor(term, name);
      if (term.mechanism === "include") {
        const child = await visit(target, "include", depth + 1);
        node.children.push(child);
      } else if (term.mechanism === "a" || term.mechanism === "mx") {
        const r = term.mechanism === "a" ? await dns.query(target, "A") : await dns.query(target, "MX");
        if (r.status === NXDOMAIN) {
          ctx.voids++;
          if (term.value) ctx.dangling.push({ domain: target, via: term.mechanism });
          node.extra.push({ term: term.raw, state: "nxdomain" });
        } else if (r.status === NOERROR && r.answers.length === 0) {
          ctx.voids++;
          node.extra.push({ term: term.raw, state: "empty" });
        }
      }
    }
    const redirect = node.parsed.modifiers.redirect;
    if (redirect && !node.parsed.all) {
      ctx.lookups++;
      const child = await visit(redirect.toLowerCase().replace(/\.$/, ""), "redirect", depth + 1);
      node.children.push(child);
    }
    node.lookups = ctx.lookups - before;
    return node;
  }

  const root = await visit(domain, "root", 0);
  return { root, lookups: ctx.lookups, voids: ctx.voids, dangling: ctx.dangling };
}

function vendorsInTree(node, out = new Set()) {
  for (const c of node.children) {
    const v = senderFor(c.domain);
    if (v) out.add(v.name);
    else vendorsInTree(c, out);
  }
  return out;
}

// The top-level entries of the domain's SPF, turned into "who can send as you".
export function sendersFrom(tree, domain) {
  const root = tree.root;
  if (!root.parsed) return [];
  const rows = [];
  const childFor = (name) => root.children.find((c) => c.domain === name);

  for (const term of root.parsed.terms) {
    if (term.qualifier !== "+" && term.mechanism !== "all") continue;
    switch (term.mechanism) {
      case "include": {
        const child = childFor(term.value);
        const v = senderFor(term.value);
        const own = matchSuffix(term.value, domain);
        let name, note = "", status = "known";
        if (child && child.state === "nxdomain") {
          name = "Domain that doesn't exist"; status = "dangling";
          note = "Anyone who registers this domain can send as you.";
        } else if (child && child.state === "none") {
          name = v ? v.name : "Unknown"; status = "broken";
          note = "This include has no SPF record, so receiving servers treat your SPF as broken.";
        } else if (v) {
          name = v.name;
        } else if (own) {
          const inner = child ? [...vendorsInTree(child)] : [];
          name = "Your own list";
          note = inner.length ? `Covers ${inner.join(", ")}.` : "A list you publish yourself.";
        } else {
          const inner = child ? [...vendorsInTree(child)] : [];
          name = "Unknown sender"; status = "unknown";
          note = inner.length ? `Not a service this page recognises. It covers ${inner.join(", ")}.` : "Not a service this page recognises. Check you still use it.";
        }
        rows.push({ name, how: `include:${term.value}`, lookups: child ? Math.max(1, child.lookups + 1) : 1, status, note, kind: v ? v.kind : "" });
        break;
      }
      case "ip4":
      case "ip6": {
        // One row for all the address ranges, however many there are.
        const range = `${term.mechanism}:${term.value}${term.cidr}`;
        const existing = rows.find((r) => r.status === "address");
        if (existing) {
          existing.ranges.push(range);
          existing.how = `${existing.ranges[0]} and ${existing.ranges.length - 1} more`;
          existing.note = `${existing.ranges.length} address ranges listed directly in the record.`;
        } else {
          rows.push({ name: "Specific servers", how: range, lookups: 0, status: "address", note: "", ranges: [range] });
        }
        break;
      }
      case "a":
        rows.push({ name: term.value ? `Servers at ${term.value}` : "Your website's servers", how: term.raw, lookups: 1, status: "known", note: "Whatever this name points to can send as you." });
        break;
      case "mx":
        rows.push({ name: "Your incoming mail servers", how: term.raw, lookups: 1, status: "known", note: "" });
        break;
      case "exists": {
        // Some services use exists with a macro, like Salesforce's %{i}._spf.mta.salesforce.com.
        const target = term.value.replace(/^.*%\{[^}]*\}\.?/, "");
        const v = target ? senderFor(target) : null;
        if (v) rows.push({ name: v.name, how: term.raw, lookups: 1, status: "known", note: "", kind: v.kind });
        else rows.push({ name: "Custom rule", how: term.raw, lookups: 1, status: "unknown", note: "An advanced rule. Make sure you know who set it up." });
        break;
      }
      case "ptr":
        rows.push({ name: "Reverse DNS rule", how: term.raw, lookups: 1, status: "unknown", note: "\"ptr\" is slow, unreliable, and the SPF standard says not to use it." });
        break;
      case "all":
        if (term.qualifier === "+") rows.push({ name: "Every server on the internet", how: "+all", lookups: 0, status: "dangling", note: "This lets anyone send as you." });
        break;
    }
  }
  const redirect = root.parsed.modifiers.redirect;
  if (redirect && !root.parsed.all) {
    const child = root.children.find((c) => c.via === "redirect");
    const v = senderFor(redirect);
    const dead = child && child.state === "nxdomain";
    if (dead) {
      rows.push({ name: "Domain that doesn't exist", how: `redirect=${redirect}`, lookups: 1, status: "dangling", note: "Anyone who registers this domain can send as you." });
    } else if (child && child.parsed) {
      // Follow it: the senders that matter are the ones in the record it points to.
      const inner = sendersFrom({ root: child }, domain).map((r) => ({ ...r, nested: true }));
      rows.push({
        name: v ? `Managed by ${v.name}` : "Managed elsewhere",
        how: `redirect=${redirect}`, lookups: 1, status: "known", kind: "Your whole SPF record lives here",
        note: inner.length ? "The senders below come from that record." : "That record allows no senders.",
      });
      rows.push(...inner);
    } else {
      rows.push({ name: "Unknown sender", how: `redirect=${redirect}`, lookups: 1, status: "unknown", note: "Your whole SPF policy comes from this record, and it couldn't be read." });
    }
  }
  return rows;
}
