// POST /api/scan  ->  forwards to the isolated scanner worker. The browser never talks to the worker.
import { verifyTurnstile, clientIp, str } from "./_shared.js";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const { SCANNER_URL, SCANNER_TOKEN } = process.env;
  if (!SCANNER_URL || !SCANNER_TOKEN) return res.status(503).json({ error: "Website scanning isn't switched on yet. Try the sample website." });

  const body = req.body || {};
  if (!(await verifyTurnstile(body.turnstileToken, clientIp(req)))) return res.status(403).json({ error: "Please complete the check below the box and try again." });
  const url = str(body.url, 300);
  if (!url) return res.status(400).json({ error: "Enter a website address." });

  try {
    const r = await fetch(SCANNER_URL.replace(/\/$/, "") + "/scan", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${SCANNER_TOKEN}` },
      body: JSON.stringify({ url }),
      signal: AbortSignal.timeout(85000),
    });
    const data = await r.json().catch(() => ({ error: "The scanner sent an unexpected reply." }));
    if (r.status === 401) return res.status(502).json({ error: "The scanner isn't set up correctly. Please try again later." });
    return res.status(r.status).json(data);
  } catch {
    return res.status(504).json({ error: "The scan took too long. Try again in a minute, or try the sample website." });
  }
}
