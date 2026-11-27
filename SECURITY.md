# Security

mailcheck is a static page. It has no server, no account, no analytics and no cookies. Lookups go from your browser to the public DNS service you pick (Cloudflare or Google), and nowhere else.

## Reporting a problem

Please don't open a public issue for a security or privacy problem. Use GitHub's private reporting instead:

https://github.com/yvon-l/mailcheck/security/advisories/new

Include the domain you checked (if you're happy to share it), your browser, what you did, and what happened.

## What counts

- Anything that sends the domains you check anywhere other than the DNS service you picked
- A DNS record shown as HTML or run as code, instead of plain text
- A fix that would break someone's mail or make a domain easier to spoof
- A verdict that says a domain is safer than its records show

## Supported versions

Only what's live at mailcheck.kimberly-wood.com. Fixes land on `main` and deploy from there.
