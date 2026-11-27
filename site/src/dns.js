// DNS over HTTPS, straight from the visitor's browser. No server of ours is involved.

export const RESOLVERS = {
  cloudflare: { name: "Cloudflare", url: "https://cloudflare-dns.com/dns-query" },
  google: { name: "Google", url: "https://dns.google/resolve" },
};

const TYPES = { A: 1, CNAME: 5, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };

// DNS response codes we care about.
export const NOERROR = 0;
export const SERVFAIL = 2;
export const NXDOMAIN = 3;

// Turn a TXT answer into its text. Resolvers send it either quoted in pieces
// ("v=spf1 " "include:...") or as one plain string.
export function txtValue(data) {
  const s = String(data).trim();
  if (!s.startsWith('"')) return s;
  let out = "";
  const re = /"((?:[^"\\]|\\.)*)"/g;
  let m;
  while ((m = re.exec(s)) !== null) {
    out += m[1].replace(/\\(\d{3})/g, (_, d) => String.fromCharCode(Number(d))).replace(/\\(.)/g, "$1");
  }
  return out;
}

export function normalizeName(name) {
  return String(name).trim().toLowerCase().replace(/\.$/, "");
}

// A small queue so a list of 50 domains doesn't flood the resolver.
function limiter(max) {
  let active = 0;
  const waiting = [];
  const next = () => {
    if (active >= max || waiting.length === 0) return;
    active++;
    const { fn, resolve, reject } = waiting.shift();
    fn().then(resolve, reject).finally(() => { active--; next(); });
  };
  return (fn) => new Promise((resolve, reject) => { waiting.push({ fn, resolve, reject }); next(); });
}

export function createResolver({ resolver = "cloudflare", fetchImpl = globalThis.fetch, concurrency = 6, timeoutMs = 8000 } = {}) {
  const base = RESOLVERS[resolver] ? RESOLVERS[resolver].url : RESOLVERS.cloudflare.url;
  const cache = new Map();
  const run = limiter(concurrency);
  let count = 0;

  async function fetchOnce(name, type) {
    const url = `${base}?name=${encodeURIComponent(name)}&type=${type}`;
    const ctrl = typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer = ctrl ? setTimeout(() => ctrl.abort(), timeoutMs) : null;
    try {
      const res = await fetchImpl(url, {
        headers: { accept: "application/dns-json" },
        credentials: "omit",
        cache: "no-store",
        referrerPolicy: "no-referrer",
        signal: ctrl ? ctrl.signal : undefined,
      });
      if (!res.ok) throw new Error(`Resolver answered ${res.status}`);
      return await res.json();
    } finally {
      if (timer) clearTimeout(timer);
    }
  }

  // Returns { status, answers: [{ type, data }], error? }. Never throws.
  function query(rawName, type) {
    const name = normalizeName(rawName);
    const key = `${name}|${type}`;
    if (cache.has(key)) return cache.get(key);
    const p = run(async () => {
      count++;
      let json;
      try {
        json = await fetchOnce(name, type);
      } catch {
        try { json = await fetchOnce(name, type); } // one retry
        catch (e) { return { status: -1, answers: [], error: e && e.message ? e.message : "lookup failed" }; }
      }
      const want = TYPES[type];
      const answers = (json.Answer || [])
        .filter((a) => a.type === want)
        .map((a) => ({ type, data: type === "TXT" ? txtValue(a.data) : String(a.data) }));
      return { status: typeof json.Status === "number" ? json.Status : -1, answers };
    });
    cache.set(key, p);
    return p;
  }

  async function txt(name) {
    const r = await query(name, "TXT");
    return { ...r, values: r.answers.map((a) => a.data) };
  }

  async function mx(name) {
    const r = await query(name, "MX");
    const records = r.answers.map((a) => {
      const [pref, ...rest] = a.data.trim().split(/\s+/);
      return { preference: Number(pref), host: normalizeName(rest.join(" ") || ".") || "." };
    }).sort((x, y) => x.preference - y.preference);
    return { ...r, records };
  }

  // Does a name exist at all? NXDOMAIN is the only "no".
  async function exists(name) {
    const r = await query(name, "A");
    if (r.status === NXDOMAIN) return false;
    if (r.status === NOERROR) return true;
    return null; // couldn't tell
  }

  async function hasAddress(name) {
    const [a, aaaa] = await Promise.all([query(name, "A"), query(name, "AAAA")]);
    if (a.answers.length || aaaa.answers.length) return true;
    if (a.status === NXDOMAIN) return false;
    if (a.status === NOERROR && aaaa.status === NOERROR) return false;
    return null;
  }

  return { query, txt, mx, exists, hasAddress, get lookups() { return count; }, resolverName: (RESOLVERS[resolver] || RESOLVERS.cloudflare).name };
}
