// A pretend DNS-over-HTTPS service for tests. Names not in the zone answer NXDOMAIN;
// names in the zone without the asked type answer NOERROR with nothing.
import { createResolver } from "../site/src/dns.js";

const TYPE_NUM = { A: 1, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };

export function fakeFetch(zone, log = []) {
  return async (url) => {
    const u = new URL(url);
    const name = u.searchParams.get("name").toLowerCase();
    const type = u.searchParams.get("type");
    log.push(`${name} ${type}`);
    const entry = zone[name];
    let body;
    if (entry === "SERVFAIL") body = { Status: 2 };
    else if (!entry) body = { Status: 3 };
    else {
      const vals = entry[type] || [];
      body = {
        Status: 0,
        Answer: vals.map((v) => ({ name, type: TYPE_NUM[type], data: type === "TXT" ? `"${v.replace(/"/g, '\\"')}"` : v })),
      };
    }
    return { ok: true, status: 200, json: async () => body };
  };
}

export function fakeResolver(zone, log) {
  return createResolver({ fetchImpl: fakeFetch(zone, log) });
}

// Shared records for real providers, so tests read like real domains.
export const PROVIDERS = {
  "_spf.google.com": { TXT: ["v=spf1 include:_netblocks.google.com include:_netblocks2.google.com include:_netblocks3.google.com ~all"] },
  "_netblocks.google.com": { TXT: ["v=spf1 ip4:35.190.247.0/24 ~all"] },
  "_netblocks2.google.com": { TXT: ["v=spf1 ip6:2001:4860:4000::/36 ~all"] },
  "_netblocks3.google.com": { TXT: ["v=spf1 ip4:172.217.0.0/19 ~all"] },
  "sendgrid.net": { TXT: ["v=spf1 ip4:167.89.0.0/17 ~all"], A: ["1.2.3.4"] },
  "servers.mcsv.net": { TXT: ["v=spf1 ip4:205.201.128.0/20 ~all"] },
  "spf.migadu.com": { TXT: ["v=spf1 ip4:46.23.80.0/22 -all"] },
  "aspmx.l.google.com": { A: ["142.250.1.27"] },
  "alt1.aspmx.l.google.com": { A: ["142.250.1.28"] },
  "aspmx1.migadu.com": { A: ["46.23.81.1"] },
};
