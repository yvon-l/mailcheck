// End-to-end: the real page in Chromium, under the real CSP, with DNS answered by a fake zone.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { chromium } from "playwright";
import { startServer } from "./serve.mjs";
import { PROVIDERS } from "./fake-dns.mjs";

const TYPE_NUM = { A: 1, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };
const ZONE = {
  ...PROVIDERS,
  "open.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com include:spf.gone.example ~all"], MX: ["1 aspmx.l.google.com."] },
  "good.example": { A: ["1.1.1.1"], TXT: ["v=spf1 include:_spf.google.com -all"], MX: ["1 aspmx.l.google.com."] },
  "_dmarc.good.example": { TXT: ["v=DMARC1; p=reject"] },
  "parked.example": { A: ["1.1.1.1"] },
  "evil.example": { A: ["1.1.1.1"], TXT: ['v=spf1 include:sendgrid.net -all <img src=x onerror="window.__pwned=1">'] },
  "_dmarc.evil.example": { TXT: ['v=DMARC1; p=reject; rua=mailto:<script>window.__pwned=1</script>'] },
};

let server, browser, base;
const cspErrors = [];
const outside = [];

before(async () => {
  ({ server, url: base } = await startServer());
  browser = await chromium.launch({ channel: "chromium" });
});
after(async () => {
  if (browser) await browser.close();
  if (server) server.close();
});

async function openPage(path = "") {
  const ctx = await browser.newContext({ permissions: ["clipboard-read", "clipboard-write"] });
  const page = await ctx.newPage();
  page.on("console", (m) => { if (/Content Security Policy/i.test(m.text())) cspErrors.push(`${path}: ${m.text()}`); });
  await page.route("**/*", (route) => {
    const u = new URL(route.request().url());
    if (u.origin === new URL(base).origin) return route.continue();
    if (u.hostname === "cloudflare-dns.com" || u.hostname === "dns.google") {
      const name = u.searchParams.get("name").toLowerCase();
      const type = u.searchParams.get("type");
      const e = ZONE[name];
      const body = !e ? { Status: 3 } : { Status: 0, Answer: (e[type] || []).map((v) => ({ name, type: TYPE_NUM[type], data: type === "TXT" ? JSON.stringify(v) : v })) };
      return route.fulfill({ status: 200, contentType: "application/dns-json", headers: { "access-control-allow-origin": "*" }, body: JSON.stringify(body) });
    }
    outside.push(u.href);
    return route.abort();
  });
  await page.goto(base + path);
  return { page, ctx };
}

test("one domain: verdict, senders, fix, and the dangling include first", async () => {
  const { page, ctx } = await openPage();
  await page.fill("#domain", "https://www.Open.Example/");
  await page.click("#single button[type=submit]");
  await page.waitForSelector(".verdict-label");
  assert.equal(await page.textContent(".verdict-label"), "Anyone can send as you");
  assert.match(await page.textContent(".first-fix-title"), /spf\.gone\.example, which doesn't exist/);
  const senders = await page.$$eval(".senders tbody tr", (rows) => rows.map((r) => r.querySelector("strong").textContent));
  assert.deepEqual(senders, ["Google Workspace", "Domain that doesn't exist"]);
  const records = await page.$$eval(".fix .record-value code", (c) => c.map((x) => x.textContent));
  assert.ok(records.includes("v=spf1 include:_spf.google.com ~all"));
  assert.ok(records.some((r) => r.startsWith("v=DMARC1; p=none")));
  assert.match(page.url(), /\?d=open\.example$/);
  await ctx.close();
});

test("copy report puts a clean table on the clipboard", async () => {
  const { page, ctx } = await openPage("?d=good.example");
  await page.waitForSelector(".verdict-label");
  assert.equal(await page.textContent(".verdict-label"), "Locked down");
  await page.click("text=Copy report");
  await page.waitForSelector("text=Copied");
  const text = await page.evaluate(() => navigator.clipboard.readText());
  assert.match(text, /## Email check: good\.example/);
  assert.match(text, /\| SPF \| Good \|/);
  await ctx.close();
});

test("several domains: worst first, and all the fixes in one copy", async () => {
  const { page, ctx } = await openPage();
  await page.click("#toggle-mode");
  await page.fill("#domains", "good.example\nparked.example\nopen.example\nnot a domain");
  await page.click("#bulk button[type=submit]");
  await page.waitForSelector("text=Checked 3 domains");
  const order = await page.$$eval(".bulk-table tbody tr td:first-child", (c) => c.map((x) => x.textContent));
  assert.equal(order[order.length - 1], "good.example");
  assert.match(await page.textContent("#status"), /Skipped 1/);
  await page.click("text=Copy all fixes");
  await page.waitForSelector("text=Copied");
  const text = await page.evaluate(() => navigator.clipboard.readText());
  assert.match(text, /parked\.example\tTXT\t"v=spf1 -all"/);
  assert.match(text, /_dmarc\.parked\.example\tTXT\t"v=DMARC1; p=reject;"/);
  await ctx.close();
});

test("hostile records are shown as text, never run", async () => {
  const { page, ctx } = await openPage("?d=evil.example");
  await page.waitForSelector(".verdict-label");
  await page.click(".check:has-text('DMARC') summary");
  assert.equal(await page.evaluate(() => window.__pwned), undefined);
  assert.match(await page.textContent(".checks"), /<script>/);
  await ctx.close();
});

test("nothing loads from anywhere except the page and the DNS service, and the CSP holds", () => {
  assert.deepEqual(outside, []);
  assert.deepEqual(cspErrors, []);
});
