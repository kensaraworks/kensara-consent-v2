// POST /api/lead  ->  validates a prospect's enquiry and forwards it to your CRM / sheet via LEAD_WEBHOOK_URL.
import { verifyTurnstile, clientIp, str } from "./_shared.js";

const EMAIL = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const NOTICE_VERSION = process.env.LEAD_NOTICE_VERSION || "2026-09";

export default async function handler(req, res) {
  if (req.method !== "POST") return res.status(405).json({ error: "Method not allowed" });
  const b = req.body || {};
  if (!(await verifyTurnstile(b.turnstileToken, clientIp(req)))) return res.status(403).json({ error: "Please complete the check and try again." });

  const lead = {
    name: str(b.name, 100), email: str(b.email, 200).toLowerCase(), company: str(b.company, 150),
    website: str(b.website, 200), phone: str(b.phone, 30), message: str(b.message, 1000),
    interest: str(b.interest, 40),
    marketingConsent: b.marketingConsent === true,
    // Proof for Kensara's own consent: what the person saw and ticked, and when.
    marketingConsentText: b.marketingConsent === true ? str(b.marketingConsentText, 300) : "",
    privacyNoticeVersion: NOTICE_VERSION,
    scanSummary: b.scanSummary && typeof b.scanSummary === "object" ? {
      domain: str(b.scanSummary.domain, 200),
      highFindings: +b.scanSummary.highFindings || 0, mediumFindings: +b.scanSummary.mediumFindings || 0,
      cookies: +b.scanSummary.cookies || 0, trackers: +b.scanSummary.trackers || 0,
    } : null,
    submittedAt: new Date().toISOString(),
  };
  if (!lead.name) return res.status(400).json({ error: "Enter your name." });
  if (!EMAIL.test(lead.email)) return res.status(400).json({ error: "Enter a valid work email." });

  const hook = process.env.LEAD_WEBHOOK_URL;
  if (!hook) {
    if (process.env.VERCEL) return res.status(503).json({ error: "Enquiries aren't switched on yet. Please email us." });
    console.log("[lead] (no LEAD_WEBHOOK_URL set, local only)", JSON.stringify(lead));
    return res.status(200).json({ ok: true });
  }
  try {
    const headers = { "content-type": "application/json" };
    if (process.env.LEAD_WEBHOOK_SECRET) headers["x-kensara-secret"] = process.env.LEAD_WEBHOOK_SECRET;
    const r = await fetch(hook, { method: "POST", headers, body: JSON.stringify(lead), signal: AbortSignal.timeout(10000) });
    if (!r.ok) throw new Error("webhook " + r.status);
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("[lead] delivery failed:", e.message);
    return res.status(502).json({ error: "Couldn't send your details just now. Please email us." });
  }
}
