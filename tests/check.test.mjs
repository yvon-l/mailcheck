import { test } from "node:test";
import assert from "node:assert/strict";
import { fakeResolver, PROVIDERS } from "./fake-dns.mjs";
import { checkDomain, cleanDomain } from "../site/src/check.js";
import { txtValue } from "../site/src/dns.js";
import { parseSpf } from "../site/src/spf.js";
import { parseDmarc, orgDomain } from "../site/src/dmarc.js";
import { parseDkim } from "../site/src/dkim.js";

const KEY2048 = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA" + "A".repeat(348) + "IDAQAB";
const KEY1024 = "MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQ" + "A".repeat(172) + "IDAQAB";

function run(zone, domain, opts) {
  return checkDomain(fakeResolver({ ...PROVIDERS, ...zone }), domain, opts);
}

const finding = (r, word) => r.findings.find((f) => f.title.toLowerCase().includes(word.toLowerCase()));
const check = (r, name) => r.checks.find((c) => c.name === name);

test("cleans what people paste into the box", () => {
  assert.equal(cleanDomain("https://www.Example.com/path?q=1"), "example.com");
  assert.equal(cleanDomain("yvon@example.co.uk"), "example.co.uk");
  assert.equal(cleanDomain("  example.com.  "), "example.com");
  assert.equal(cleanDomain("not a domain"), null);
  assert.equal(cleanDomain("<script>.com"), null);
  assert.equal(cleanDomain(""), null);
});

test("reads quoted and split TXT answers", () => {
  assert.equal(txtValue('"v=spf1 " "include:_spf.google.com ~all"'), "v=spf1 include:_spf.google.com ~all");
  assert.equal(txtValue("v=spf1 -all"), "v=spf1 -all");
  assert.equal(txtValue('"a\\"b"'), 'a"b');
});

test("parses SPF, DMARC and DKIM", () => {
  const s = parseSpf("v=spf1 include:_spf.google.com ip4:1.2.3.0/24 ~all");
  assert.equal(s.all, "~all");
  assert.equal(s.terms.length, 3);
  assert.equal(parseSpf("v=spf1 bogus:x -all").problems.length, 1);
  const d = parseDmarc("v=DMARC1; p=quarantine; pct=50; rua=mailto:x@example.com");
  assert.equal(d.policy, "quarantine");
  assert.equal(d.pct, 50);
  assert.ok(parseDmarc("p=reject; v=DMARC1").problems.length > 0);
  assert.equal(orgDomain("mail.example.co.uk"), "example.co.uk");
  assert.equal(orgDomain("a.b.example.com"), "example.com");
  assert.equal(parseDkim(`v=DKIM1; k=rsa; p=${KEY2048}`).bits, 2048);
  assert.equal(parseDkim(`v=DKIM1; k=rsa; p=${KEY1024}`).bits, 1024);
  assert.equal(parseDkim("v=DKIM1; p=").revoked, true);
});

test("a well set up Google Workspace domain is locked down", async () => {
  const r = await run({
    "good.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com -all"], MX: ["1 aspmx.l.google.com.", "5 alt1.aspmx.l.google.com."] },
    "_dmarc.good.example": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@good.example"] },
    "google._domainkey.good.example": { TXT: [`v=DKIM1; k=rsa; p=${KEY2048}`] },
  }, "good.example");
  assert.equal(r.verdict, "locked");
  assert.equal(r.sending, true);
  assert.equal(r.spf.senders[0].name, "Google Workspace");
  assert.equal(r.spf.tree.lookups, 4);
  assert.equal(check(r, "DKIM").status, "good");
  assert.equal(r.fixes.spf, undefined);
  assert.equal(r.fixes.dmarc, undefined);
});

test("no DMARC means anyone can send as you, and the fix starts at p=none", async () => {
  const r = await run({
    "nodmarc.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com ~all"], MX: ["1 aspmx.l.google.com."] },
  }, "nodmarc.example");
  assert.equal(r.verdict, "open");
  assert.ok(finding(r, "reject fake email"));
  assert.match(r.fixes.dmarc.value, /^v=DMARC1; p=none; rua=mailto:dmarc-reports@nodmarc\.example$/);
});

test("p=none moves to quarantine, quarantine to reject, keeping other tags", async () => {
  const none = await run({
    "a.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com -all"], MX: ["1 aspmx.l.google.com."] },
    "_dmarc.a.example": { TXT: ["v=DMARC1; p=none; rua=mailto:r@a.example; adkim=s"] },
  }, "a.example");
  assert.equal(none.verdict, "open");
  assert.equal(none.fixes.dmarc.value, "v=DMARC1; p=quarantine; rua=mailto:r@a.example; adkim=s;");

  const q = await run({
    "b.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com -all"], MX: ["1 aspmx.l.google.com."] },
    "_dmarc.b.example": { TXT: ["v=DMARC1; p=quarantine; rua=mailto:r@b.example"] },
  }, "b.example");
  assert.equal(q.verdict, "locked");
  assert.equal(q.fixes.dmarc, undefined, "quarantine at 100% is good, so no forced fix");

  const pct = await run({
    "c.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com -all"], MX: ["1 aspmx.l.google.com."] },
    "_dmarc.c.example": { TXT: ["v=DMARC1; p=reject; pct=25"] },
  }, "c.example");
  assert.equal(pct.verdict, "partial");
  assert.equal(pct.fixes.dmarc.value, "v=DMARC1; p=reject;");
});

test("a dangling include is the top risk and the fix removes it", async () => {
  const r = await run({
    "dangle.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com include:spf.gone-vendor.example -all"], MX: ["1 aspmx.l.google.com."] },
    "_dmarc.dangle.example": { TXT: ["v=DMARC1; p=reject"] },
  }, "dangle.example");
  assert.equal(r.verdict, "open");
  assert.equal(r.findings[0].status, "risk");
  assert.match(r.findings[0].title, /spf\.gone-vendor\.example, which doesn't exist/);
  const row = r.spf.senders.find((s) => s.how.includes("gone-vendor"));
  assert.equal(row.status, "dangling");
  assert.equal(r.fixes.spf.value, "v=spf1 include:_spf.google.com -all");
});

test("+all, two SPF records, and too many lookups are caught", async () => {
  const plus = await run({ "plus.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:sendgrid.net +all"] }, "_dmarc.plus.example": { TXT: ["v=DMARC1; p=reject"] } }, "plus.example");
  assert.equal(plus.verdict, "open");
  assert.equal(plus.fixes.spf.value, "v=spf1 include:sendgrid.net ~all");

  const two = await run({ "two.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:sendgrid.net -all", "v=spf1 include:servers.mcsv.net -all"] }, "_dmarc.two.example": { TXT: ["v=DMARC1; p=reject"] } }, "two.example");
  assert.equal(check(two, "SPF").status, "broken");
  assert.equal(two.fixes.spf.value, "v=spf1 include:sendgrid.net include:servers.mcsv.net -all");

  const zone = { "many.example": { A: ["1.1.1.1"], TXT: [] }, "_dmarc.many.example": { TXT: ["v=DMARC1; p=reject"] } };
  const incs = [];
  for (let i = 0; i < 12; i++) { zone[`s${i}.vendor.example`] = { TXT: ["v=spf1 ip4:10.0.0.1 ~all"] }; incs.push(`include:s${i}.vendor.example`); }
  zone["many.example"].TXT = [`v=spf1 ${incs.join(" ")} -all`];
  const many = await run(zone, "many.example");
  assert.equal(many.spf.tree.lookups, 12);
  assert.equal(check(many, "SPF").status, "broken");
  assert.ok(finding(many, "12 lookups"));
});

test("unknown senders and a missing provider include are flagged", async () => {
  const r = await run({
    "mixed.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:sendgrid.net include:mystery.example ~all"], MX: ["1 aspmx.l.google.com."] },
    "mystery.example": { TXT: ["v=spf1 ip4:9.9.9.9 -all"] },
    "_dmarc.mixed.example": { TXT: ["v=DMARC1; p=reject"] },
  }, "mixed.example");
  assert.equal(r.verdict, "partial");
  assert.equal(r.spf.senders.find((s) => s.how === "include:mystery.example").status, "unknown");
  assert.ok(finding(r, "Google Workspace handles your mail"));
  assert.equal(r.fixes.spf.value, "v=spf1 include:_spf.google.com include:sendgrid.net include:mystery.example ~all");
});

test("a parked domain with nothing set gets all three lockdown records", async () => {
  const r = await run({ "parked.example": { A: ["1.1.1.1"] } }, "parked.example");
  assert.equal(r.parked, true);
  assert.equal(r.verdict, "parkedOpen");
  assert.equal(r.fixes.spf.value, "v=spf1 -all");
  assert.equal(r.fixes.dmarc.value, "v=DMARC1; p=reject;");
  assert.equal(r.fixes.nullMx.value, "0 .");
});

test("a fully locked parked domain needs nothing", async () => {
  const r = await run({
    "locked.example": { A: ["1.1.1.1"], TXT: ["v=spf1 -all"], MX: ["0 ."] },
    "_dmarc.locked.example": { TXT: ["v=DMARC1; p=reject"] },
  }, "locked.example");
  assert.equal(r.parked, true);
  assert.equal(r.verdict, "parkedLocked");
  assert.deepEqual(Object.keys(r.fixes), []);
});

test("a subdomain borrows its parent's DMARC policy", async () => {
  const r = await run({
    "news.parent.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:sendgrid.net -all"] },
    "_dmarc.parent.example": { TXT: ["v=DMARC1; p=reject; sp=quarantine"] },
  }, "news.parent.example");
  assert.equal(r.dmarc.inherited, true);
  assert.equal(r.verdict, "locked");
});

test("a dangling MX host is a risk, and weak DKIM keys are flagged", async () => {
  const r = await run({
    "mx.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:spf.migadu.com -all"], MX: ["10 aspmx1.migadu.com.", "20 mx.expired-host.example."] },
    "_dmarc.mx.example": { TXT: ["v=DMARC1; p=reject"] },
    "key1._domainkey.mx.example": { TXT: [`v=DKIM1; k=rsa; p=${KEY1024}`] },
  }, "mx.example");
  assert.equal(check(r, "MX").status, "risk");
  assert.ok(finding(r, "expired-host"));
  assert.equal(check(r, "DKIM").status, "work");
});

test("a domain that doesn't exist says so", async () => {
  const r = await run({}, "nothing-here.example");
  assert.equal(r.missing, true);
});

test("hostile TXT content stays plain text in findings", async () => {
  const r = await run({
    "evil.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:<img src=x onerror=alert(1)> -all"] },
  }, "evil.example");
  // The include target is invalid, so it is reported, but only ever as text.
  assert.ok(r.findings.length > 0);
  for (const f of r.findings) assert.equal(typeof f.title, "string");
});

test("when the DNS service fails, it says so instead of guessing", async () => {
  const r = await run({ "flaky.example": { A: ["1.1.1.1"] }, "_dmarc.flaky.example": "SERVFAIL" }, "flaky.example");
  assert.ok(r.error);
});

test("a redirect is followed and its senders listed, and weak DKIM keys are grouped", async () => {
  const r = await run({
    "redir.example": { A: ["1.1.1.1"], TXT: ["v=spf1 redirect=abc._spf._d.mim.ec"], MX: ["10 aspmx.l.google.com."] },
    "abc._spf._d.mim.ec": { TXT: ["v=spf1 include:_spf.google.com include:sendgrid.net -all"] },
    "_dmarc.redir.example": { TXT: ["v=DMARC1; p=reject"] },
    "s1._domainkey.redir.example": { TXT: [`v=DKIM1; k=rsa; p=${KEY1024}`] },
    "s2._domainkey.redir.example": { TXT: [`v=DKIM1; k=rsa; p=${KEY1024}`] },
  }, "redir.example");
  assert.deepEqual(r.spf.senders.map((s) => s.name), ["Managed by Mimecast", "Google Workspace", "SendGrid"]);
  assert.equal(r.spf.senders.filter((s) => s.status === "unknown").length, 0);
  const dk = r.findings.filter((f) => f.check === "DKIM");
  assert.equal(dk.length, 1);
  assert.match(dk[0].title, /2 DKIM keys .* "s1" and "s2"/);
});

test("IP ranges collapse into one row, and Salesforce's exists rule is recognised", async () => {
  const r = await run({
    "ips.example": { A: ["1.1.1.1"], TXT: ["v=spf1 ip4:10.0.0.0/24 ip4:10.0.1.0/24 ip6:2001:db8::/32 exists:%{i}._spf.mta.salesforce.com -all"] },
    "_dmarc.ips.example": { TXT: ["v=DMARC1; p=reject"] },
  }, "ips.example");
  const addr = r.spf.senders.filter((s) => s.status === "address");
  assert.equal(addr.length, 1);
  assert.equal(addr[0].how, "ip4:10.0.0.0/24 and 2 more");
  const sf = r.spf.senders.find((s) => s.how.startsWith("exists:"));
  assert.equal(sf.name, "Salesforce");
  assert.equal(r.spf.senders.filter((s) => s.status === "unknown").length, 0);
});

test("a flattened SPF isn't accused of leaving out the mail provider", async () => {
  const r = await run({
    "flat.example": { A: ["1.1.1.1"], TXT: ["v=spf1 ip4:74.125.0.0/16 ip4:209.85.128.0/17 -all"], MX: ["1 aspmx.l.google.com."] },
    "_dmarc.flat.example": { TXT: ["v=DMARC1; p=reject"] },
    "google._domainkey.flat.example": { TXT: [`v=DKIM1; k=rsa; p=${KEY2048}`] },
  }, "flat.example");
  assert.equal(r.verdict, "locked");
  assert.equal(r.findings.find((f) => /doesn't allow it to send/.test(f.title)), undefined);
  assert.ok(r.findings.find((f) => f.status === "info" && /lists addresses instead/.test(f.title)));
  assert.equal(r.fixes.spf, undefined);
});

// ---- Found in live testing, November 2026 ----

import { COMMON_SELECTORS, PROBE_SELECTOR } from "../site/src/dkim.js";
import { hostFor } from "../site/src/check.js";

// The fake DNS has no wildcards, so answer every selector (and the probe) by hand.
function wildcardDkim(domain, value) {
  const z = {};
  for (const s of [...COMMON_SELECTORS, PROBE_SELECTOR]) z[`${s}._domainkey.${domain}`] = { TXT: [value] };
  return z;
}

test("a catch-all revoked DKIM record doesn't make a parked domain look like a sender", async () => {
  const r = await run({
    "example.test": { A: ["1.1.1.1"], TXT: ["v=spf1 -all"], MX: ["0 ."] },
    "_dmarc.example.test": { TXT: ["v=DMARC1;p=reject;sp=reject;adkim=s;aspf=s"] },
    ...wildcardDkim("example.test", "v=DKIM1; p="),
  }, "example.test");
  assert.equal(r.sending, false);
  assert.equal(r.parked, true);
  assert.equal(r.verdict, "parkedLocked");
  assert.equal(r.dkim.length, 0, "catch-all answers aren't listed as keys");
  assert.ok(r.dkimWildcard.parsed.revoked);
  assert.equal(check(r, "DKIM").status, "good");
  assert.match(check(r, "DKIM").summary, /catch-all/);
  assert.equal(check(r, "BIMI").status, "na");
});

test("revoked keys on named selectors don't count as sending either", async () => {
  const r = await run({
    "old.example": { A: ["1.1.1.1"], TXT: ["v=spf1 -all"] },
    "_dmarc.old.example": { TXT: ["v=DMARC1; p=reject"] },
    "google._domainkey.old.example": { TXT: ["v=DKIM1; k=rsa; p="] },
  }, "old.example");
  assert.equal(r.sending, false);
  assert.equal(r.verdict, "parkedLocked");
  assert.equal(check(r, "DKIM").status, "good");
});

test("a real key next to a catch-all is still found", async () => {
  const r = await run({
    "mixed-dkim.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com -all"], MX: ["1 aspmx.l.google.com."] },
    "_dmarc.mixed-dkim.example": { TXT: ["v=DMARC1; p=reject"] },
    ...wildcardDkim("mixed-dkim.example", "v=DKIM1; p="),
    "google._domainkey.mixed-dkim.example": { TXT: [`v=DKIM1; k=rsa; p=${KEY2048}`] },
  }, "mixed-dkim.example");
  assert.deepEqual(r.dkim.map((k) => k.selector), ["google"]);
  assert.equal(r.verdict, "locked");
});

test("record names for subdomains never say @", () => {
  assert.equal(hostFor("example.com"), "@");
  assert.equal(hostFor("example.com", "_dmarc"), "_dmarc");
  assert.equal(hostFor("mail.example.com"), "mail");
  assert.equal(hostFor("mail.example.com", "_dmarc"), "_dmarc.mail");
  assert.equal(hostFor("a.b.example.co.uk", "_dmarc"), "_dmarc.a.b");
  assert.equal(hostFor("example.co.uk"), "@");
});

test("a non-sending subdomain under a reject policy is locked, and its fix names the subdomain", async () => {
  const r = await run({
    "tools.parent.example": { A: ["1.1.1.1"] },
    "parent.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com -all"] },
    "_dmarc.parent.example": { TXT: ["v=DMARC1; p=reject"] },
  }, "tools.parent.example");
  assert.equal(r.parked, true);
  assert.equal(r.verdict, "parkedLocked");
  assert.equal(r.fixes.spf.host, "tools");
  assert.equal(r.fixes.spf.value, "v=spf1 -all");
  assert.equal(r.fixes.dmarc, undefined, "the inherited reject policy is already right");
  const f = finding(r, "doesn't send email");
  assert.equal(f.status, "work");
  assert.equal(f.tidy, true);
});

test("a subdomain with no DMARC anywhere gets a _dmarc.sub fix", async () => {
  const r = await run({ "shop.bare.example": { A: ["1.1.1.1"] }, "bare.example": { A: ["1.1.1.1"] } }, "shop.bare.example");
  assert.equal(r.verdict, "parkedOpen");
  assert.equal(r.fixes.dmarc.host, "_dmarc.shop");
  assert.equal(r.fixes.spf.host, "shop");
  assert.equal(r.fixes.nullMx.host, "shop");
});

test("housekeeping doesn't lower the verdict when DMARC rejects", async () => {
  const r = await run({
    "tidy.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com include:mystery.example -all"], MX: ["1 aspmx.l.google.com."] },
    "mystery.example": { TXT: ["v=spf1 ip4:9.9.9.9 -all"] },
    "_dmarc.tidy.example": { TXT: ["v=DMARC1; p=reject; rua=mailto:d@tidy.example"] },
    "selector1._domainkey.tidy.example": { TXT: [`v=DKIM1; k=rsa; p=${KEY1024}`] },
  }, "tidy.example");
  assert.equal(r.verdict, "locked");
  assert.equal(r.tidy, 1, "the 1024-bit key is worth tidying");
  assert.equal(finding(r, "recognises").status, "info", "an unknown sender is a note, not a problem");
});

test("lookup headroom wording matches the count", async () => {
  // 9 lookups: Google (4) + five single includes.
  const singles = ["a", "b", "c", "d", "e"].map((x) => `${x}.inc.example`);
  const zone = {
    "near.example": { A: ["1.1.1.1"], TXT: [`v=spf1 include:_spf.google.com ${singles.map((s) => `include:${s}`).join(" ")} -all`] },
    "_dmarc.near.example": { TXT: ["v=DMARC1; p=reject"] },
  };
  for (const s of singles) zone[s] = { TXT: ["v=spf1 ip4:10.0.0.1 -all"] };
  const r = await run(zone, "near.example");
  assert.equal(r.spf.tree.lookups, 9);
  const f = finding(r, "9 of its 10");
  assert.match(f.detail, /room for one more/);
  assert.equal(f.tidy, true);
  assert.equal(r.verdict, "locked");
});

test("Google's netblocks, Mailchimp's other servers, Pardot and Statuspage are recognised", async () => {
  const r = await run({
    "vendors.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_netblocks.google.com include:spf1.mcsv.net include:aspmx.pardot.com include:stspg-customer.com -all"] },
    "spf1.mcsv.net": { TXT: ["v=spf1 ip4:205.201.128.0/20 -all"] },
    "aspmx.pardot.com": { TXT: ["v=spf1 ip4:136.147.176.0/20 -all"] },
    "stspg-customer.com": { TXT: ["v=spf1 ip4:52.0.0.1 -all"] },
    "_dmarc.vendors.example": { TXT: ["v=DMARC1; p=reject"] },
  }, "vendors.example");
  assert.equal(r.spf.senders.filter((s) => s.status === "unknown").length, 0);
  assert.deepEqual(r.spf.senders.map((s) => s.name).sort(), ["Atlassian Statuspage", "Google Workspace", "Mailchimp", "Salesforce Pardot"]);
});
