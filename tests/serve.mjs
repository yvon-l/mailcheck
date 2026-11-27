// A tiny static server for local testing. It sends the same headers as
// site/_headers, so the tests run under the real Content Security Policy.
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { readFileSync } from "node:fs";
import { join, extname, normalize, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..", "site");
const TYPES = { ".html": "text/html; charset=utf-8", ".css": "text/css", ".js": "text/javascript", ".svg": "image/svg+xml", ".woff2": "font/woff2", ".txt": "text/plain" };

function siteHeaders() {
  const lines = readFileSync(join(ROOT, "_headers"), "utf8").split("\n");
  const out = {};
  let inAll = false;
  for (const line of lines) {
    if (!line.startsWith(" ") && line.trim()) { inAll = line.trim() === "/*"; continue; }
    if (!inAll) continue;
    const m = /^\s+([A-Za-z-]+):\s*(.*)$/.exec(line);
    if (m && m[1] !== "Strict-Transport-Security") out[m[1]] = m[2].replace("upgrade-insecure-requests", "").trim().replace(/;$/, "");
  }
  return out;
}

export function startServer(port = 0) {
  const headers = siteHeaders();
  const server = createServer(async (req, res) => {
    const url = new URL(req.url, "http://localhost");
    let path = normalize(decodeURIComponent(url.pathname)).replace(/^(\.\.[/\\])+/, "");
    if (path.endsWith("/")) path += "index.html";
    const file = join(ROOT, path);
    if (!file.startsWith(ROOT)) { res.writeHead(403); res.end(); return; }
    try {
      const body = await readFile(file);
      res.writeHead(200, { "content-type": TYPES[extname(file)] || "application/octet-stream", ...headers });
      res.end(body);
    } catch {
      res.writeHead(404); res.end("not found");
    }
  });
  return new Promise((resolve) => server.listen(port, "127.0.0.1", () => resolve({ server, url: `http://127.0.0.1:${server.address().port}/` })));
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const { url } = await startServer(Number(process.env.PORT) || 8788);
  console.log(`mailcheck running at ${url}`);
}
