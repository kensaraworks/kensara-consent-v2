// Kensara scanner worker. Runs in its own container, NOT on Vercel.
// Only your Vercel API calls it, with a shared secret. Never expose it without the token.
const http = require("http");
const crypto = require("crypto");
const net = require("net");
const { scan } = require("./lib/scanner");
const { isPrivateIp } = require("./lib/egress-proxy");

const PORT = +(process.env.PORT || 8080);
const TOKEN = process.env.SCANNER_TOKEN || "";
const MAX_CONCURRENT = +(process.env.MAX_CONCURRENT_SCANS || 2);
const MAX_WAITING = 10;
const CACHE_MS = 60 * 60 * 1000;                 // same domain within an hour -> cached result
if (TOKEN.length < 32) { console.error("Set SCANNER_TOKEN to a random value of 32+ characters (openssl rand -hex 32)."); process.exit(1); }

const tokenHash = crypto.createHash("sha256").update(TOKEN).digest();
const authorised = req => {
  const got = crypto.createHash("sha256").update((req.headers.authorization || "").replace(/^Bearer /, "")).digest();
  return crypto.timingSafeEqual(got, tokenHash);
};

// Friendly early validation. The egress proxy is what actually enforces the rules.
function normalise(input) {
  let s = String(input || "").trim();
  if (!s) throw new Error("Enter a website address.");
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(s) && !/^https?:\/\//i.test(s)) throw new Error("Only http and https websites can be scanned.");
  if (!/^https?:\/\//i.test(s)) s = "https://" + s;
  let u; try { u = new URL(s); } catch { throw new Error("That doesn't look like a website address."); }
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("Only http and https websites can be scanned.");
  if (u.port && !["80", "443"].includes(u.port)) throw new Error("Only standard web ports can be scanned.");
  if (u.username || u.password) throw new Error("Remove the username or password from the address.");
  const h = u.hostname.replace(/^\[|\]$/g, "");
  if (/^(localhost|.*\.(local|internal|localhost))$/i.test(h) || (net.isIP(h) && isPrivateIp(h))) throw new Error("This address isn't a public website.");
  u.hash = "";
  return u;
}

const cache = new Map();
let running = 0; const waiting = [];
async function slot(fn) {
  if (running >= MAX_CONCURRENT) {
    if (waiting.length >= MAX_WAITING) throw Object.assign(new Error("The scanner is busy. Try again in a minute."), { status: 503 });
    await new Promise(r => waiting.push(r));
  }
  running++;
  try { return await fn(); } finally { running--; const n = waiting.shift(); if (n) n(); }
}

const send = (res, code, obj) => { res.writeHead(code, { "content-type": "application/json" }); res.end(JSON.stringify(obj)); };

http.createServer((req, res) => {
  if (req.method === "GET" && req.url === "/health") return send(res, 200, { ok: true, running, waiting: waiting.length });
  if (req.method !== "POST" || req.url !== "/scan") return send(res, 404, { error: "Not found" });
  if (!authorised(req)) return send(res, 401, { error: "Unauthorised" });
  let body = "";
  req.on("data", c => { body += c; if (body.length > 4096) req.destroy(); });
  req.on("end", async () => {
    try {
      const url = normalise(JSON.parse(body || "{}").url);
      const key = url.hostname;
      const hit = cache.get(key);
      if (hit && Date.now() - hit.at < CACHE_MS) return send(res, 200, { ...hit.result, cached: true });
      const result = await slot(() => scan(url));
      // Only cache complete scans: a partial (time-limited) result shouldn't be
      // pinned for an hour — let the next attempt try to finish the site.
      if (!result.incomplete) {
        cache.set(key, { at: Date.now(), result });
        if (cache.size > 500) cache.delete(cache.keys().next().value);
      }
      send(res, 200, result);
    } catch (e) {
      send(res, e.status || 400, { error: e.status ? e.message : (e.message || "Scan failed.") });
    }
  });
}).listen(PORT, () => console.log(`scanner worker on :${PORT}`));
