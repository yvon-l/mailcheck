// Runs every check for one domain and turns the answers into plain findings.
import { NXDOMAIN, NOERROR } from "./dns.js";
import { getSpf, expandSpf, sendersFrom, parseSpf, LOOKUP_LIMIT, VOID_LIMIT } from "./spf.js";
import { getDmarc, effectivePolicy, orgDomain } from "./dmarc.js";
import { findDkim } from "./dkim.js";
import { providerForMx } from "./vendors.js";
import { fixSpf, fixDmarc, providerSpfState, NULL_MX } from "./fixes.js";

export const STATUS_LABEL = { good: "Good", work: "Needs work", broken: "Broken", missing: "Missing", risk: "Risk", info: "Not set up", na: "Not needed" };
const SEVERITY = { risk: 0, broken: 1, missing: 2, work: 3, info: 4, good: 5, na: 6 };

export const VERDICT = {
  locked: { label: "Locked down", line: "Nobody else can send email that passes as this domain." },
  partial: { label: "Partly protected", line: "The basics are in place, but there are gaps someone could use." },
  open: { label: "Anyone can send as you", line: "Someone could send email that looks like it came from this domain, and most inboxes would accept it." },
  parkedLocked: { label: "Locked down", line: "This domain doesn't send email, and it's set up so nobody else can either." },
  parkedOpen: { label: "Anyone can send as you", line: "This domain doesn't send email, but nothing stops someone else from using it to." },
  parkedPartial: { label: "Partly protected", line: "This domain doesn't send email, and it's partly locked down." },
};

// The name to type at a DNS provider. For example.com that's "@" (or "_dmarc");
// for mail.example.com it's "mail" (or "_dmarc.mail"), because "@" would mean
// example.com itself.
export function hostFor(domain, prefix = "") {
  const org = orgDomain(domain);
  const sub = domain === org ? "" : domain.slice(0, -(org.length + 1));
  return [prefix, sub].filter(Boolean).join(".") || "@";
}

export function cleanDomain(input) {
  let s = String(input || "").trim().toLowerCase();
  s = s.replace(/^[a-z]+:\/\//, "").replace(/^[^@/]*@/, "").split(/[/?#:\s]/)[0].replace(/\.$/, "");
  if (s.startsWith("www.")) s = s.slice(4);
  if (!/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9-]{2,63}$/.test(s)) return null;
  return s;
}

async function extras(dns, domain) {
  const [sts, tlsrpt, bimi] = await Promise.all([
    dns.txt(`_mta-sts.${domain}`),
    dns.txt(`_smtp._tls.${domain}`),
    dns.txt(`default._bimi.${domain}`),
  ]);
  const pick = (r, re) => r.values.find((v) => re.test(v)) || null;
  return {
    mtasts: pick(sts, /^v=STSv1/i),
    tlsrpt: pick(tlsrpt, /^v=TLSRPTv1/i),
    bimi: pick(bimi, /^v=BIMI1/i),
  };
}

export async function checkDomain(dns, domain, { selectors = [] } = {}) {
  const apex = await dns.query(domain, "A");
  if (apex.status === NXDOMAIN) return { domain, missing: true };
  if (apex.status !== NOERROR) return { domain, error: apex.error || "The DNS service didn't answer." };

  const [spfRaw, dmarc, dkimRes, mxRes, ext] = await Promise.all([
    getSpf(dns, domain),
    getDmarc(dns, domain),
    findDkim(dns, domain, selectors),
    dns.mx(domain),
    extras(dns, domain),
  ]);

  const dkim = dkimRes.keys;
  const dkimWildcard = dkimRes.wildcard;

  // If the core lookups failed, say so rather than guess a verdict.
  if (dmarc.error || spfRaw.status === -1) return { domain, error: dmarc.error || spfRaw.error || "lookup failed" };

  // SPF
  const spf = { records: spfRaw.records, tree: null, senders: [], parsed: null };
  if (spfRaw.records.length === 1) {
    spf.tree = await expandSpf(dns, domain);
    spf.parsed = spf.tree.root.parsed;
    spf.senders = sendersFrom(spf.tree, domain);
  } else if (spfRaw.records.length > 1) {
    spf.tree = await expandSpf(dns, domain);
    spf.parsed = parseSpf(spfRaw.records[0]);
  }

  // MX
  const mxRecords = mxRes.records;
  const nullMx = mxRecords.length === 1 && mxRecords[0].host === "." ;
  const realMx = mxRecords.filter((r) => r.host !== ".");
  const provider = realMx.length ? providerForMx(realMx[0].host) : null;
  const mxChecks = await Promise.all(realMx.map(async (r) => ({ ...r, resolves: await dns.hasAddress(r.host), exists: await dns.exists(r.host) })));
  const deadMx = mxChecks.filter((r) => r.resolves === false && r.exists === false);
  const brokenMx = mxChecks.filter((r) => r.resolves === false && r.exists !== false);

  // Is this a domain that sends email? Revoked DKIM keys (p= with nothing after it)
  // are how you say a domain doesn't sign anything, so they don't count.
  const liveKeys = dkim.filter((k) => !k.parsed.revoked);
  const sending = spf.senders.some((s) => s.how !== "+all") || liveKeys.length > 0 || spfRaw.records.length > 1;
  const parked = !sending && (realMx.length === 0);

  const result = { domain, spf, dmarc, dkim, mx: { records: mxRecords, nullMx, provider, dead: deadMx, broken: brokenMx }, extras: ext, dkimWildcard, sending, parked, findings: [], checks: [] };
  result.fixes = buildFindings(result);
  result.verdict = verdictFor(result);
  return result;
}

function add(r, f) { r.findings.push(f); }

function buildFindings(r) {
  const { domain, spf, dmarc, dkim, dkimWildcard, mx, extras: ext, sending, parked } = r;
  const tree = spf.tree;
  const fixes = {};
  const pol = effectivePolicy(dmarc);
  // With DMARC at reject, receivers already refuse fakes, so SPF gaps on a
  // domain that doesn't send are housekeeping, not a way in.
  const rejects = pol === "reject" && !dmarc.multiple && dmarc.found && !(dmarc.parsed.problems || []).length && dmarc.parsed.pct >= 100;

  // ---- SPF ----
  let spfStatus = "good";
  let spfSummary = "";
  if (spf.records.length === 0) {
    spfStatus = "missing";
    spfSummary = "No SPF record.";
    add(r, {
      check: "SPF", status: sending ? "missing" : rejects ? "work" : "risk", tidy: !sending && rejects,
      title: sending ? "There's no list of servers allowed to send your email" : "Nothing says this domain doesn't send email",
      detail: sending ? "Without SPF, receiving servers can't tell your real mail from a fake." : (rejects ? "Your DMARC policy already makes receivers refuse fakes. An SPF record of -all says the same thing to servers that only check SPF." : "An SPF record of -all tells every receiving server that any mail from this domain is fake."),
    });
  } else if (spf.records.length > 1) {
    spfStatus = "broken";
    spfSummary = `${spf.records.length} SPF records.`;
    add(r, { check: "SPF", status: "broken", title: "There are two SPF records, so receivers ignore both", detail: "A domain can only have one SPF record. With more than one, every receiving server treats SPF as broken." });
  } else {
    const p = spf.parsed;
    const all = p.all;
    if (tree.dangling.length) {
      spfStatus = "risk";
      for (const d of tree.dangling) {
        add(r, { check: "SPF", status: "risk", title: `Your SPF trusts ${d.domain}, which doesn't exist`, detail: `Anyone who registers ${d.domain} could send email that passes as ${domain}. Remove it from your SPF record.` });
      }
    }
    if (all === "+all") {
      spfStatus = "risk";
      add(r, { check: "SPF", status: "risk", title: "Your SPF record allows every server on the internet", detail: "\"+all\" means any server may send as you, which defeats the point of SPF." });
    }
    const brokenIncludes = tree.root.children.filter((c) => c.state === "none");
    for (const b of brokenIncludes) {
      if (spfStatus === "good" || spfStatus === "work") spfStatus = "broken";
      add(r, { check: "SPF", status: "broken", title: `include:${b.domain} has no SPF record`, detail: "Receiving servers treat an include with nothing behind it as an error, so your whole SPF fails." });
    }
    if (tree.lookups > LOOKUP_LIMIT) {
      if (spfStatus !== "risk") spfStatus = "broken";
      add(r, { check: "SPF", status: "broken", title: `Your SPF needs ${tree.lookups} lookups, and the limit is ${LOOKUP_LIMIT}`, detail: "Past 10, receiving servers stop and treat your SPF as broken. Remove services you no longer use, starting with the ones that cost the most." });
    } else if (tree.lookups >= 9) {
      if (spfStatus === "good") spfStatus = "work";
      add(r, {
        check: "SPF", status: "work", tidy: true,
        title: `Your SPF uses ${tree.lookups} of its ${LOOKUP_LIMIT} lookups`,
        detail: tree.lookups >= LOOKUP_LIMIT
          ? "It works today, but adding any service that needs a lookup will break it. Remove any you no longer use."
          : "There's room for one more lookup. Remove any services you no longer use to make room.",
      });
    }
    if (tree.voids > VOID_LIMIT) {
      if (spfStatus === "good" || spfStatus === "work") spfStatus = "broken";
      add(r, { check: "SPF", status: "broken", title: `${tree.voids} parts of your SPF point at nothing`, detail: "Receiving servers allow two at most before they treat SPF as broken." });
    }
    if (all === "?all" || (!all && !p.modifiers.redirect)) {
      if (spfStatus === "good") spfStatus = "work";
      add(r, { check: "SPF", status: "work", title: "Your SPF doesn't say what to do with other servers", detail: "Ending with ?all, or nothing, means mail from servers you didn't list is treated as neutral. End it with ~all or -all." });
    }
    if (p.problems.length) {
      if (spfStatus === "good" || spfStatus === "work") spfStatus = "broken";
      add(r, { check: "SPF", status: "broken", title: "Part of your SPF record isn't valid", detail: p.problems.join(". ") + "." });
    }
    const unknown = spf.senders.filter((s) => s.status === "unknown");
    if (unknown.length) {
      add(r, { check: "SPF", status: "info", title: unknown.length === 1 ? "One sender in your SPF isn't one this page recognises" : `${unknown.length} senders in your SPF aren't ones this page recognises`, detail: "That can be fine, but make sure you know who each one is and that you still use them." });
    }
    const provState = sending && mx.provider && !mx.provider.forwardingOnly ? providerSpfState(tree, mx.provider) : "ok";
    if (provState === "missing") {
      if (spfStatus === "good") spfStatus = "work";
      add(r, { check: "SPF", status: "work", title: `${mx.provider.name} handles your mail, but your SPF doesn't allow it to send`, detail: `Mail you send through ${mx.provider.name} may fail SPF checks.` });
    } else if (provState === "unsure") {
      add(r, { check: "SPF", status: "info", title: `Your SPF lists addresses instead of ${mx.provider.name}'s include`, detail: `That's fine if those addresses cover ${mx.provider.name}, but they go stale when it changes its servers. Its own include, ${mx.provider.spf}, keeps itself up to date.` });
    }

    if (!sending && all !== "-all" && spfStatus === "good") {
      spfStatus = "work";
      add(r, { check: "SPF", status: "work", tidy: rejects, title: "This domain doesn't send email, but its SPF doesn't say so firmly", detail: "Use v=spf1 -all, which tells receivers any mail from it is fake." });
    }
    spfSummary = `${tree.lookups} of ${LOOKUP_LIMIT} lookups, ends in ${all || (p.modifiers.redirect ? "a redirect" : "nothing")}.`;
  }
  const spfFix = fixSpf({ domain, spf, provider: mx.provider, sending });
  if (spfFix && spfStatus !== "good") fixes.spf = { name: domain, host: hostFor(domain), type: "TXT", ...spfFix };
  r.checks.push({ name: "SPF", status: spfStatus, summary: spfSummary, record: spf.records.join("\n") || null });

  // ---- DMARC ----
  let dmStatus = "good";
  let dmSummary = "";
  if (dmarc.error) {
    dmStatus = "info"; dmSummary = "Couldn't look it up.";
  } else if (!dmarc.found) {
    dmStatus = "missing"; dmSummary = "No DMARC record.";
    add(r, { check: "DMARC", status: "risk", title: "Nothing tells inboxes to reject fake email from you", detail: "Without DMARC, mail that fails SPF and DKIM is usually delivered anyway." });
  } else if (dmarc.multiple) {
    dmStatus = "broken"; dmSummary = "More than one DMARC record.";
    add(r, { check: "DMARC", status: "risk", title: "There are two DMARC records, so receivers ignore both", detail: "Keep one record at _dmarc." + domain + "." });
  } else if (dmarc.parsed.problems.length) {
    dmStatus = "broken"; dmSummary = "Record can't be read.";
    add(r, { check: "DMARC", status: "risk", title: "Your DMARC record has a mistake, so receivers ignore it", detail: dmarc.parsed.problems.join(". ") + "." });
  } else {
    dmSummary = `Policy: ${pol}${dmarc.parsed.pct < 100 ? `, ${dmarc.parsed.pct}% of mail` : ""}${dmarc.inherited ? `, from ${dmarc.at}` : ""}.`;
    if (pol === "none") {
      dmStatus = "work";
      add(r, { check: "DMARC", status: "risk", title: "Your DMARC policy only watches, it doesn't block", detail: "p=none collects reports but tells inboxes to deliver fake mail anyway." });
    } else if (dmarc.parsed.pct < 100) {
      dmStatus = "work";
      add(r, { check: "DMARC", status: "work", title: `Your DMARC policy only covers ${dmarc.parsed.pct}% of mail`, detail: "The rest of the fake mail is treated as if you had no policy." });
    } else if (!sending && pol !== "reject") {
      dmStatus = "work";
      add(r, { check: "DMARC", status: "work", title: "This domain doesn't send email, so its DMARC can go all the way to reject", detail: "Quarantine sends fakes to spam. Reject refuses them outright." });
    }
    if (dmarc.parsed.subdomainPolicy === "none" && pol !== "none" && !dmarc.inherited) {
      if (dmStatus === "good") dmStatus = "work";
      add(r, { check: "DMARC", status: "work", title: "Your subdomains aren't protected", detail: "sp=none lets anyone send as any subdomain, like billing." + domain + ". Remove sp=none or set it to match p." });
    }
    if (!dmarc.parsed.rua && sending && dmStatus !== "good") {
      add(r, { check: "DMARC", status: "info", title: "You're not getting DMARC reports", detail: "Reports show who is sending as you, which is how you know it's safe to tighten the policy. They're optional." });
    }
  }
  const dmFix = fixDmarc({ domain, dmarc, sending });
  if (dmFix && dmStatus !== "good") fixes.dmarc = { name: `_dmarc.${domain}`, host: hostFor(domain, "_dmarc"), type: "TXT", ...dmFix };
  r.checks.push({ name: "DMARC", status: dmStatus, summary: dmSummary, record: dmarc.record || null });

  // ---- DKIM ----
  let dkStatus;
  let dkSummary;
  const live = dkim.filter((k) => !k.parsed.revoked);
  const wildRevoked = dkimWildcard && dkimWildcard.parsed.revoked;
  const wildNote = dkimWildcard ? (wildRevoked ? "A catch-all record answers every selector with a revoked key." : "A catch-all record answers every selector with the same key.") : "";
  if (!sending && live.length === 0 && (wildRevoked || dkim.length > 0)) {
    dkStatus = "good";
    dkSummary = `${wildRevoked ? "A catch-all record revokes every key" : `Only revoked keys (${dkim.map((k) => k.selector).join(", ")})`}, which is right for a domain that doesn't send.`;
  } else if (dkim.length === 0) {
    dkStatus = sending ? "info" : "na";
    dkSummary = wildNote || (sending ? "No key found on the common selector names. That doesn't mean there isn't one." : "Not needed for a domain that doesn't send.");
  } else {
    const weak = dkim.filter((k) => k.parsed.keyType === "rsa" && k.parsed.bits && k.parsed.bits < 2048 && !k.parsed.revoked);
    dkStatus = weak.length ? "work" : "good";
    dkSummary = dkim.map((k) => `${k.selector}${k.parsed.revoked ? " (revoked)" : k.parsed.keyType === "ed25519" ? " (Ed25519)" : k.parsed.bits ? ` (${k.parsed.bits}-bit)` : ""}`).join(", ") + (wildNote ? `. ${wildNote}` : "");
    if (weak.length) {
      const names = weak.map((k) => `"${k.selector}"`);
      const list = names.length === 1 ? names[0] : `${names.slice(0, -1).join(", ")} and ${names[names.length - 1]}`;
      add(r, {
        check: "DKIM", status: "work", tidy: true,
        title: weak.length === 1 ? `The DKIM key ${list} is ${weak[0].parsed.bits}-bit` : `${weak.length} DKIM keys are 1024-bit or smaller: ${list}`,
        detail: "Keys under 2048 bits are now considered weak. Ask each provider for a 2048-bit key and switch to it.",
      });
    }
  }
  r.checks.push({ name: "DKIM", status: dkStatus, summary: dkSummary, record: [...dkim.map((k) => `${k.selector}._domainkey: ${k.record}`), ...(dkimWildcard ? [`*._domainkey: ${dkimWildcard.record}`] : [])].join("\n") || null });

  // ---- MX ----
  let mxStatus = "good";
  let mxSummary;
  if (mx.nullMx) mxSummary = "Null MX: this domain doesn't receive email.";
  else if (mx.records.length === 0) { mxStatus = parked ? "good" : "info"; mxSummary = "No MX records, so this domain doesn't receive email."; }
  else mxSummary = mx.records.map((x) => `${x.preference} ${x.host}`).join(", ") + (mx.provider ? ` (${mx.provider.name})` : "");
  for (const d of mx.dead) {
    mxStatus = "risk";
    add(r, { check: "MX", status: "risk", title: `Your MX points to ${d.host}, which doesn't exist`, detail: `If someone registers it, they could receive email sent to ${domain}. Remove that MX record.` });
  }
  for (const d of mx.broken) {
    if (mxStatus === "good") mxStatus = "work";
    add(r, { check: "MX", status: "work", title: `Your mail server ${d.host} has no address`, detail: "Mail can't be delivered to it. Fix it or remove that MX record." });
  }
  r.checks.push({ name: "MX", status: mxStatus, summary: mxSummary, record: mx.records.map((x) => `${x.preference} ${x.host}`).join("\n") || null });

  // ---- Receiving extras ----
  const receives = mx.records.length > 0 && !mx.nullMx;
  r.checks.push({ name: "MTA-STS", status: ext.mtasts ? "good" : receives ? "info" : "na", summary: ext.mtasts ? "Record found. The policy file itself can't be read from a browser." : receives ? "Makes servers sending to you use encryption. Optional." : "Not needed for a domain that doesn't receive email.", record: ext.mtasts });
  r.checks.push({ name: "TLS-RPT", status: ext.tlsrpt ? "good" : receives ? "info" : "na", summary: ext.tlsrpt ? "Record found." : receives ? "Sends you reports when encrypted delivery to you fails. Optional." : "Not needed for a domain that doesn't receive email.", record: ext.tlsrpt });
  r.checks.push({ name: "BIMI", status: ext.bimi ? "good" : sending ? "info" : "na", summary: ext.bimi ? "Record found." : sending ? "Shows your logo in some inboxes. Optional, and it needs DMARC at quarantine or reject first." : "Not needed for a domain that doesn't send email.", record: ext.bimi });

  // ---- Parked lockdown ----
  if (parked) {
    const spfLocked = spf.records.length === 1 && spf.parsed && spf.parsed.all === "-all" && spf.senders.length === 0;
    const dmLocked = pol === "reject";
    const mxLocked = mx.nullMx || mx.records.length === 0;
    r.parkedChecks = { spf: spfLocked, dmarc: dmLocked, mx: mxLocked };
    if (!spfLocked) fixes.spf = { name: domain, host: hostFor(domain), type: "TXT", value: "v=spf1 -all", changes: ["Says nothing sends mail for this domain"] };
    if (!dmLocked) fixes.dmarc = { name: `_dmarc.${domain}`, host: hostFor(domain, "_dmarc"), type: "TXT", value: "v=DMARC1; p=reject;", step: "Reject everything", note: "Nothing sends mail for this domain, so receivers can safely refuse anything that claims to be from it." };
    if (!mx.nullMx && mx.records.length === 0) fixes.nullMx = { name: domain, host: hostFor(domain), type: "MX", value: NULL_MX, optional: true, note: "Optional. Says plainly that this domain receives no email, so senders get an instant bounce instead of retrying." };
  }

  r.findings.sort((a, b) => SEVERITY[a.status] - SEVERITY[b.status]);
  return fixes;
}

function verdictFor(r) {
  const pol = effectivePolicy(r.dmarc);
  const spfCheck = r.checks.find((c) => c.name === "SPF");
  const dmCheck = r.checks.find((c) => c.name === "DMARC");
  const mxCheck = r.checks.find((c) => c.name === "MX");
  const spoofable = !pol || pol === "none" || dmCheck.status === "broken" || spfCheck.status === "risk";
  // A gap is something someone could use. Housekeeping (lookup headroom, older
  // DKIM keys, belt-and-braces records) is listed but doesn't change the verdict.
  const gaps = r.findings.some((f) => ["risk", "broken", "missing"].includes(f.status) || (f.status === "work" && !f.tidy));
  r.tidy = r.findings.filter((f) => f.tidy).length;
  if (r.parked) {
    if (spoofable) return "parkedOpen";
    return gaps || !r.parkedChecks.dmarc ? "parkedPartial" : "parkedLocked";
  }
  if (spoofable) return "open";
  return gaps ? "partial" : "locked";
}
