// Local test server: serves public/ and runs api/*.js like Vercel does. No npm install needed.
import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const dir = path.dirname(fileURLToPath(import.meta.url));
try { // load .env.local
  for (const line of fs.readFileSync(path.join(dir, ".env.local"), "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z_][A-Z0-9_]*)=(.*)$/); if (m && !(m[1] in process.env)) process.env[m[1]] = m[2].trim();
  }
} catch {}
const vercel = JSON.parse(fs.readFileSync(path.join(dir, "vercel.json"), "utf8"));
const globalHeaders = vercel.headers[0].headers;
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json", ".png": "image/png", ".svg": "image/svg+xml" };
const PORT = +process.env.PORT || 3000;

http.createServer(async (req, res) => {
  for (const h of globalHeaders) if (h.key !== "Strict-Transport-Security") res.setHeader(h.key, h.value);
  const url = new URL(req.url, "http://localhost");
  const m = url.pathname.match(/^\/api\/([a-z]+)$/);
  if (m) {
    const file = path.join(dir, "api", m[1] + ".js");
    if (!fs.existsSync(file)) { res.statusCode = 404; return res.end(); }
    let raw = ""; for await (const c of req) { raw += c; if (raw.length > 100000) return res.destroy(); }
    try { req.body = raw ? JSON.parse(raw) : {}; } catch { req.body = {}; }
    res.status = c => { res.statusCode = c; return res; };
    res.json = o => { res.setHeader("content-type", "application/json"); res.end(JSON.stringify(o)); return res; };
    const mod = await import(pathToFileURL(file).href);
    return mod.default(req, res);
  }
  let p = path.normalize(path.join(dir, "public", decodeURIComponent(url.pathname)));
  if (!p.startsWith(path.join(dir, "public"))) { res.statusCode = 403; return res.end(); }
  if (fs.existsSync(p) && fs.statSync(p).isDirectory()) p = path.join(p, "index.html");
  if (!fs.existsSync(p)) { res.statusCode = 404; return res.end("Not found"); }
  res.setHeader("content-type", MIME[path.extname(p)] || "application/octet-stream");
  fs.createReadStream(p).pipe(res);
}).listen(PORT, () => console.log(`Kensara demo on http://localhost:${PORT}`));
