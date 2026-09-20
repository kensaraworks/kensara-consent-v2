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

// All tunable from the environment so the same image can run on a small or a large instance.
const MAX_PAGES = +(process.env.MAX_PAGES || 5);
const PAGE_TIMEOUT = +(process.env.PAGE_TIMEOUT_MS || 15000);
const SETTLE_MS = +(process.env.SETTLE_MS || 2500);
const CONCURRENCY = Math.max(1, +(process.env.SCAN_CONCURRENCY || 3)); // pages visited in parallel (after the homepage)
// Hard cap for the whole scan. Kept below the caller's request timeout so we return
// partial results instead of the caller (e.g. a Vercel function) timing out first.
const SCAN_DEADLINE_MS = +(process.env.SCAN_DEADLINE_MS || 50000);

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
function stripHash(href) { try { const u = new URL(href); u.hash = ""; return u.href; } catch { return href; } }
const clamp = (v, lo, hi) => Math.max(lo, Math.min(hi, v));

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
      "--disable-gpu",
      "--disable-software-rasterizer",
      "--js-flags=--max-old-space-size=256",
      ...(process.env.SCANNER_NO_SANDBOX === "1" ? ["--no-sandbox"] : []), // only if the container truly can't sandbox
    ],
  });
  const deadlineAt = Date.now() + SCAN_DEADLINE_MS;
  let timer;
  // Backstop only: run() self-limits to deadlineAt and returns partial results; this fires
  // only if a page hangs badly beyond that, preserving the original hard-fail as a last resort.
  const backstop = new Promise((_, rej) => {
    timer = setTimeout(
      () => rej(Object.assign(new Error("The scan took too long. Try again or add cookies by hand."), { status: 504 })),
      SCAN_DEADLINE_MS + 8000,
    );
  });
  try {
    return await Promise.race([backstop, run(browser, url, siteDomain, deadlineAt)]);
  } finally {
    clearTimeout(timer);
    await browser.close().catch(() => {});
  }
}

async function run(browser, url, siteDomain, deadlineAt) {
  const hosts = new Map(), storageKeys = new Set(), pagesVisited = [], errors = [];
  let site = {};
  const timeLeft = () => deadlineAt - Date.now();

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
    if (["media", "font", "image", "imageset"].includes(r.resourceType())) return route.abort();
    return route.continue();
  });

  // Record every third-party host contacted. Attached to each page we open, so it works
  // whether pages are visited one at a time or concurrently; cookies stay context-wide.
  const trackPage = page => page.on("request", r => {
    try { const u = new URL(r.url()); if (/^https?:$/.test(u.protocol)) hosts.set(u.hostname, (hosts.get(u.hostname) || 0) + 1); } catch {}
  });

  // Visit one URL in its own tab. Returns discovered same-site links when it's the homepage.
  async function visit(target, isHome) {
    if (timeLeft() < 5000) return { visited: false, links: [] };
    const page = await context.newPage();
    trackPage(page);
    try {
      const gotoBudget = clamp(timeLeft() - 3000, 4000, PAGE_TIMEOUT);
      const resp = await page.goto(target, { waitUntil: "domcontentloaded", timeout: gotoBudget });
      if (resp && resp.headers()["x-kensara-egress"] === "denied") {
        if (isHome) throw Object.assign(new Error("This address isn't a public website."), { denied: true });
        return { visited: false, links: [] };  // a link or redirect pointed somewhere internal: skip it
      }
      await page.waitForLoadState("networkidle", { timeout: clamp(timeLeft() - 2000, 1000, 6000) }).catch(() => {});
      await page.mouse.wheel(0, 2500).catch(() => {});
      await page.waitForTimeout(clamp(timeLeft() - 1500, 400, SETTLE_MS)).catch(() => {});
      pagesVisited.push(page.url());

      const keys = await page.evaluate(() => {
        const out = [];
        try { for (let i = 0; i < localStorage.length; i++) out.push(["localStorage", localStorage.key(i)]); } catch {}
        try { for (let i = 0; i < sessionStorage.length; i++) out.push(["sessionStorage", sessionStorage.key(i)]); } catch {}
        return out;
      }).catch(() => []);
      keys.forEach(k => storageKeys.add(JSON.stringify(k)));

      let links = [];
      if (isHome) {
        const base = new URL(page.url());
        const raw = await page.$$eval("a[href]", as => as.map(a => a.href)).catch(() => []);
        links = [...new Set(raw)].filter(h => { try { const u = new URL(h); return u.hostname === base.hostname && /^https?:$/.test(u.protocol) && !/\.(pdf|jpe?g|png|zip|docx?|xlsx?)$/i.test(u.pathname) && !/logout|signout|wp-admin|cart\/add/i.test(u.pathname); } catch { return false; } })
          .map(stripHash).filter(h => h !== base.href).slice(0, MAX_PAGES * 3);
        // Best-effort details to pre-fill the configurator (organisation name, privacy
        // notice link, contact email/phone). Everything is optional and user-editable.
        site = await page.evaluate(() => {
          const meta = n => { const el = document.querySelector(`meta[property="${n}"],meta[name="${n}"]`); return (el && el.content) || ""; };
          let orgName = meta("og:site_name") || meta("application-name") || "";
          try {
            for (const s of document.querySelectorAll('script[type="application/ld+json"]')) {
              const parsed = JSON.parse(s.textContent);
              const list = Array.isArray(parsed) ? parsed : (parsed && parsed["@graph"]) || [parsed];
              for (const o of list) {
                const types = [].concat((o && o["@type"]) || "").join(" ");
                if (o && o.name && /(Organization|LocalBusiness|Corporation|Store|NGO)/i.test(types)) { orgName = orgName || o.name; }
              }
            }
          } catch (e) {}
          if (!orgName) orgName = (document.title || "").split(/[|–—\-:·]/)[0].trim();
          const links = [...document.querySelectorAll("a[href]")];
          const href = a => a.getAttribute("href") || "";
          const privacy = links.find(a => /privacy|data.?protection|\bpolicy\b/i.test((a.textContent || "") + " " + href(a)));
          const mail = links.find(a => /^mailto:/i.test(href(a)));
          const tel = links.find(a => /^tel:/i.test(href(a)));
          const clean = (s, n) => String(s || "").trim().slice(0, n);
          return {
            orgName: clean(orgName, 150),
            privacyUrl: privacy ? privacy.href : "",
            email: mail ? clean(decodeURIComponent(href(mail).replace(/^mailto:/i, "").split("?")[0]), 200) : "",
            phone: tel ? clean(href(tel).replace(/^tel:/i, "").replace(/[^\d+ ()-]/g, ""), 30) : "",
          };
        }).catch(() => ({}));
      }
      return { visited: true, links };
    } catch (e) {
      if (e.denied) throw e;
      if (isHome && /ERR_TUNNEL_CONNECTION_FAILED/.test(e.message)) throw new Error("This address isn't a public website.");
      errors.push(`${target}: ${e.message.split("\n")[0]}`);
      return { visited: false, links: [] };
    } finally {
      await page.close().catch(() => {});
    }
  }

  // 1) Homepage first: it validates the site and gives us the links to crawl.
  const home = await visit(url.href, true);

  // 2) Remaining pages, visited concurrently to stay within the time budget.
  const seen = new Set([stripHash(url.href)]);
  const queue = [];
  for (const link of (home.links || [])) { if (!seen.has(link)) { seen.add(link); queue.push(link); } }

  let next = 0;
  const worker = async () => {
    while (pagesVisited.length < MAX_PAGES && timeLeft() > 5000) {
      const i = next++;
      if (i >= queue.length) return;
      await visit(queue[i], false);
    }
  };
  const pool = clamp(CONCURRENCY, 1, Math.max(1, queue.length));
  await Promise.all(Array.from({ length: pool }, worker));

  if (!pagesVisited.length) throw new Error("The site couldn't be loaded. Check the address and that it's publicly reachable.");

  // True when we stopped for time with more pages we would have visited.
  const incomplete = timeLeft() <= 5000 && pagesVisited.length < Math.min(MAX_PAGES, 1 + queue.length);

  const cookies = (await context.cookies()).map(c => {
    const cls = classifyCookie(c.name), cdom = c.domain.replace(/^\./, "");
    return { name: c.name, domain: cdom, firstParty: registrable(cdom) === siteDomain, duration: duration(c.expires), vendor: cls.vendor, category: cls.category, purpose: cls.purpose, suggested: cls.suggested || "" };
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
  if (incomplete) findings.push({ level: "low", text: `The scan stopped early to stay within the time limit; results cover ${pagesVisited.length} page(s). Trackers on pages we didn't reach may not be listed.` });

  return { url: url.href, domain: url.hostname.replace(/^www\./, ""), scannedAt: new Date().toISOString(), site, pagesVisited, cookies, storage, thirdParties, vendors,
    hints: vendors.filter(v => TAGGING_HINTS[v]).map(v => ({ vendor: v, hint: TAGGING_HINTS[v] })), findings, errors, incomplete };
}

module.exports = { scan };
