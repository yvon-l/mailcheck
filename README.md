# mailcheck

Who can send email as your domain, whether that's locked down, and the exact records to fix it.

**Use it:** https://mailcheck.kimberly-wood.com

Most email checkers are there to sell you a DMARC product. I wanted one that just tells you who can send as you and how to lock it down, then gets out of the way. No signup, no "full report", no tracking. It runs in your browser.

## What it does

- **Who can send email as you.** Your SPF record, followed to the end and turned into a plain list of services: Google Workspace, Microsoft 365, SendGrid, Mailchimp and so on. Anything it can't name is flagged so you can ask "who is this?"
- **Dangling records.** An SPF include or MX that points at a domain that no longer exists. Anyone who registers that domain can send mail as you, or receive it. This is the check that matters most, so it's shown first.
- **The fix.** Corrected SPF and DMARC records, written from your actual records and your mail provider, with a Copy button. DMARC moves one step at a time: none, then quarantine, then reject.
- **Several domains at once.** Paste up to 50. Domains that don't send email get checked for full lockdown (`v=spf1 -all`, DMARC `p=reject`, no MX or a null MX), and you can copy every missing record in one go.
- **Copy report.** A clean table that pastes well into Docs, Word or email, with Markdown as plain text.

It also checks DKIM (on the common selector names, or one you type), MX, MTA-STS, TLS-RPT and BIMI.

The result is a verdict in plain words: **Locked down**, **Partly protected** or **Anyone can send as you**. There's no letter grade, because whether someone can spoof your domain is mostly a yes or no question, and optional extras like BIMI shouldn't drag a protected domain down.

## How it works

It's a static page. Your browser asks a public DNS-over-HTTPS service (Cloudflare by default, Google if you pick it) for each record, and all the checking happens on your machine. There's no server of mine involved and no API key.

The advice isn't AI. Every finding and every fix is a rule written in advance in `site/src/`, so the same records always get the same answer, and you can read exactly why it said what it said.

## What it can't do

- **List DKIM keys.** DNS only answers for a selector name you ask about. "Not found" means "not on the names tried", not "missing".
- **Read MTA-STS policy files.** They live on the domain's own web server, which usually won't let another site read them. The page checks the DNS record and says so.
- **Tell you whether mail actually passes.** That needs a real message. DNS can only show what's published.

## What it sends where

The domains you check go to the DNS service you picked, to look up their records. Nothing goes to me. Nothing is stored. No cookies, no analytics. The page's Content Security Policy only allows connections to `cloudflare-dns.com` and `dns.google`.

## Adding a sender

The list of known services is in `site/src/vendors.js`. To add one, open a pull request with the include domain and a link to the vendor's own setup docs.

## Run it locally

```
npm install
npm run serve
```

Then open http://127.0.0.1:8788. There's no build step; `site/` is the whole site.

## Tests

```
npm test
```

Unit tests run every check against a fake DNS zone. Browser tests load the real page in Chromium under the real Content Security Policy and check the results, the copy buttons, the several-domains view, and that hostile records are shown as text and never run. They also run on every push.

## License

MIT. The fonts (Bricolage Grotesque, Instrument Sans, JetBrains Mono) are under the SIL Open Font License; their licenses are in `site/fonts/`.
