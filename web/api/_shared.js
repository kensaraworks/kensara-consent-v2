// Helpers shared by the API routes (files starting with "_" are not deployed as routes).
export async function verifyTurnstile(token, ip) {
  const secret = process.env.TURNSTILE_SECRET;
  if (!secret) return true; // bot check switched off (local testing)
  try {
    const body = new URLSearchParams({ secret, response: String(token || "") });
    if (ip) body.set("remoteip", ip);
    const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body, signal: AbortSignal.timeout(8000) });
    return !!(await r.json()).success;
  } catch { return false; }
}
export const clientIp = req => String(req.headers["x-forwarded-for"] || "").split(",")[0].trim();
export const str = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");
