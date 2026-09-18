// Visits a website like a first-time visitor who has NOT consented, and records what it sets.
// SECURITY MODEL: Chromium is forced through lib/egress-proxy.js, which is the real SSRF control.
// The in-browser checks below are only extra layers. Run this in an isolated container (see Dockerfile).
const fs = require("fs");
const path = require("path");
const { chromium } = require("playwright");
const { classifyCookie, classifyHost, TAGGING_HINTS } = require("./trackers");
const { createEgressProxy } = require("./egress-proxy");

function getChromiumExecutable() {
  if (process.env.CHROMIUM_PATH && fs.existsSync(process.env.CHROMIUM_PATH)) return process.env.CHROMIUM_PATH;
  const localAppData = process.env.LOCALAPPDATA;
  if (localAppData) {
    const candidates = [
      path.join(localAppData, "ms-playwright", "chromium-1243", "chrome-win64", "chrome.exe"),
      path.join(localAppData, "ms-playwright", "chromium-1194", "chrome-win", "chrome.exe"),
    ];
    for (const c of candidates) if (fs.existsSync(c)) return c;
  }
  return undefined;
}

const MAX_PAGES = 4;
const PAGE_TIMEOUT = 15000;
const SETTLE_MS = 2500;
const SCAN_DEADLINE_MS = +(process.env.SCAN_DEADLINE_MS || 60000); // hard cap for the whole scan

// One egress proxy per process, bound to loopback only.
let proxyPort = null;
function startProxy(opts = {}) {
  if (proxyPort) return Promise.resolve(proxyPort);
  return new Promise((res, rej) => {
    const p = createEgressProxy({ log: m => console.warn("[egress]", m), ...opts });
    p.on("error", rej);
    p.listen(0, "127.0.0.1", () => { proxyPort = p.address().port; res(proxyPort); });
  });
}

function registrable(host) {
  const p = host.split(".");
  const two = p.slice(-2).join(".");
  if (/^(co|org|net|gov|ac|edu|firm|gen|ind|com|nic|res)\.(in|uk|au|nz|jp|za|sg)$/.test(two)) return p.slice(-3).join(".");
  return two; // TODO: replace with the Public Suffix List (npm "tldts") for accuracy
}
function duration(expires) {
  if (!expires || expires < 0) return "Session";
  const days = Math.round((expires * 1000 - Date.now()) / 86400000);
  if (days <= 0) return "Session";
  if (days < 60) return `${days} days`;
  if (days < 730) return `${Math.round(days / 30)} months`;
  return `${Math.round(days / 365)} years`;
}

async function scan(url, { proxyOptions } = {}) {
  const port = await startProxy(proxyOptions);
  const siteDomain = registrable(url.hostname);
  const browser = await chromium.launch({
    executablePath: getChromiumExecutable(),
    proxy: { server: `http://127.0.0.1:${port}` },
    args: [
      "--proxy-bypass-list=<-loopback>",     // Chromium otherwise sends localhost/127.x DIRECTLY, skipping the proxy
      "--disable-quic",                        // no UDP path around the proxy
      "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
      "--disable-dev-shm-usage",
      ...(process.env.SCANNER_NO_SANDBOX === "1" ? ["--no-sandbox"] : []), // only if the container truly can't sandbox
    ],
  });
  let timer;
  const deadline = new Promise((_, rej) => { timer = setTimeout(() => rej(Object.assign(new Error("The scan took too long. Try again or add cookies by hand."), { status: 504 })), SCAN_DEADLINE_MS); });
  try {
    return await Promise.race([deadline, run(browser, url, siteDomain)]);
  } finally {
    clearTimeout(timer);
    await browser.close().catch(() => {});
  }
}

async function run(browser, url, siteDomain) {
  const hosts = new Map(), storageKeys = new Set(), pagesVisited = [], errors = [];
  const context = await browser.newContext({
    locale: "en-IN", timezoneId: "Asia/Kolkata", viewport: { width: 1366, height: 850 },
    serviceWorkers: "block",                   // SW fetches aren't visible to routing
    acceptDownloads: false,
    userAgent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36 KensaraConsentScanner/1.0",
  });
  await context.addInitScript(() => { try { delete window.RTCPeerConnection; delete window.webkitRTCPeerConnection; } catch (e) {} });
  if (context.routeWebSocket) await context.routeWebSocket(/.*/, ws => ws.close()); // scanner never needs WebSockets
  await context.route("**/*", route => {
    const r = route.request();
    let u; try { u = new URL(r.url()); } catch { return route.abort(); }
    if (!/^https?:$/.test(u.protocol)) return route.continue();   // data:, blob: are local
    if (u.port && u.port !== "80" && u.port !== "443") return route.abort();
    if (["media", "font"].includes(r.resourceType())) return route.abort();
    return route.continue();
  });

  const page = await context.newPage();
  page.on("request", r => { try { const u = new URL(r.url()); if (/^https?:$/.test(u.protocol)) hosts.set(u.hostname, (hosts.get(u.hostname) || 0) + 1); } catch {} });

  const queue = [url.href], seen = new Set();
  while (queue.length && pagesVisited.length < MAX_PAGES) {
    const target = queue.shift();
    if (seen.has(target)) continue;
    seen.add(target);
    try {
      const resp = await page.goto(target, { waitUntil: "domcontentloaded", timeout: PAGE_TIMEOUT });
      if (resp && resp.headers()["x-kensara-egress"] === "denied") {
        if (!pagesVisited.length) throw Object.assign(new Error("This address isn't a public website."), { denied: true });
        continue; // a link or redirect pointed somewhere internal: skip it
      }
      await page.waitForLoadState("networkidle", { timeout: 6000 }).catch(() => {});
      await page.mouse.wheel(0, 2500).catch(() => {});
      await page.waitForTimeout(SETTLE_MS);
      pagesVisited.push(page.url());
      const keys = await page.evaluate(() => {
        const out = [];
        try { for (let i = 0; i < localStorage.length; i++) out.push(["localStorage", localStorage.key(i)]); } catch {}
        try { for (let i = 0; i < sessionStorage.length; i++) out.push(["sessionStorage", sessionStorage.key(i)]); } catch {}
        return out;
      }).catch(() => []);
      keys.forEach(k => storageKeys.add(JSON.stringify(k)));
      if (pagesVisited.length === 1) {
        const base = new URL(page.url());
        const links = await page.$$eval("a[href]", as => as.map(a => a.href)).catch(() => []);
        queue.push(...[...new Set(links)].filter(h => { try { const u = new URL(h); return u.hostname === base.hostname && /^https?:$/.test(u.protocol) && !/\.(pdf|jpe?g|png|zip|docx?|xlsx?)$/i.test(u.pathname) && !/logout|signout|wp-admin|cart\/add/i.test(u.pathname); } catch { return false; } })
          .map(h => { const u = new URL(h); u.hash = ""; return u.href; }).filter(h => h !== base.href).slice(0, MAX_PAGES * 3));
      }
    } catch (e) {
      if (e.denied) throw e;
      if (!pagesVisited.length && /ERR_TUNNEL_CONNECTION_FAILED/.test(e.message)) throw new Error("This address isn't a public website.");
      errors.push(`${target}: ${e.message.split("\n")[0]}`);
    }
  }
  if (!pagesVisited.length) throw new Error("The site couldn't be loaded. Check the address and that it's publicly reachable.");

  const cookies = (await context.cookies()).map(c => {
    const cls = classifyCookie(c.name), cdom = c.domain.replace(/^\./, "");
    return { name: c.name, domain: cdom, firstParty: registrable(cdom) === siteDomain, duration: duration(c.expires), vendor: cls.vendor, category: cls.category, purpose: cls.purpose };
  }).sort((a, b) => a.category.localeCompare(b.category) || a.name.localeCompare(b.name));

  const storage = [...storageKeys].map(s => JSON.parse(s)).map(([area, key]) => ({ area, key, ...classifyCookie(key) })); // same patterns as cookies
  const thirdParties = [...hosts.entries()].filter(([h]) => registrable(h) !== siteDomain)
    .map(([host, requests]) => ({ host, requests, ...(classifyHost(host) || { vendor: "Unknown", category: "unclassified" }) }))
    .sort((a, b) => b.requests - a.requests);
  const vendors = [...new Set([...cookies, ...thirdParties, ...storage].filter(x => x.vendor !== "Unknown").map(x => x.vendor))];

  const optional = x => x.category === "functional" || x.category === "analytics" || x.category === "marketing";
  const preCookies = cookies.filter(optional), preStorage = storage.filter(optional), preHosts = thirdParties.filter(h => h.category === "analytics" || h.category === "marketing");
  const unknown = cookies.filter(c => c.category === "unclassified").length + storage.filter(s => s.category === "unclassified").length;

  const findings = [];
  if (preCookies.length || preStorage.length) findings.push({ level: "high", text: `${preCookies.length} cookie(s) and ${preStorage.length} browser-storage item(s) for optional purposes were set before the visitor made any choice. These need consent first.` });
  if (preHosts.length) findings.push({ level: "high", text: `Data was sent to ${preHosts.length} analytics or advertising service(s) (${preHosts.slice(0, 4).map(h => h.vendor).join(", ")}) before any choice. Sending the visitor's IP address and device details is processing even without cookies.` });
  if (unknown) findings.push({ level: "medium", text: `${unknown} item(s) set before consent couldn't be identified. If they aren't essential, they also need consent.` });
  if (url.protocol !== "https:") findings.push({ level: "medium", text: "The site doesn't use HTTPS. Personal data should be protected in transit." });
  if (errors.length) findings.push({ level: "low", text: `${errors.length} page(s) couldn't be loaded during the scan.` });

  return { url: url.href, domain: url.hostname.replace(/^www\./, ""), scannedAt: new Date().toISOString(), pagesVisited, cookies, storage, thirdParties, vendors,
    hints: vendors.filter(v => TAGGING_HINTS[v]).map(v => ({ vendor: v, hint: TAGGING_HINTS[v] })), findings, errors };
}

module.exports = { scan };
