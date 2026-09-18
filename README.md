# Kensara Consent: demo and lead generator (v2)

A prospect enters their website. The scanner lists every cookie and tracker that runs before consent. They fill in
their organisation's details and see **their own banner working live** on a sample website, with trackers visibly
blocked and released. Installing it on their real site, consent proof, all languages, parental consent and
monitoring are shown as locked **Pro** features, and every "unlock" opens a lead form.

```
kensara-consent-v2/
├── web/                     → deploy to Vercel
│   ├── public/
│   │   ├── index.html, app.js, app.css   the generator (scan → details → live demo → lead form)
│   │   ├── consent.js                    the banner script (demo mode here; also the base for Pro)
│   │   ├── demo-site.html, demo/         sample website the banner runs on, with fake trackers
│   │   ├── sample-scan.json              "Try it with a sample website" (works with no scanner)
│   │   └── site-config.js                ← EDIT: your privacy notice, pricing link, Turnstile key
│   ├── api/scan.js                       forwards scans to the scanner worker
│   ├── api/lead.js                       validates leads, sends them to your CRM/sheet
│   ├── vercel.json                       Mumbai region, timeouts, security headers
│   └── dev-server.js                     local testing, no install needed
└── scanner-worker/          → deploy to Railway or a VM (NOT Vercel)
    ├── worker.js, lib/                   hardened scanner behind an egress proxy
    └── Dockerfile
```

Nothing a prospect types into the generator is stored or sent anywhere, except the lead form. The demo can't be
used as a free banner: there is no install code, no config endpoint and no consent logging in this deployment.

---

## What changed from v1

**Fixed and tested** (31 automated browser checks, all passing):

| Gap from the audit | Now |
|---|---|
| Scanner SSRF: WebSockets, DNS rebinding, IPv6 tricks | All traffic forced through an egress proxy that checks the IP it actually connects to. 10 attack routes tested, all blocked |
| Chromium `--no-sandbox` next to the consent database | Scanner is its own non-root container with no database and one secret |
| Returning visitors' consented scripts never ran | Scripts released after the page finishes parsing, plus a watcher for scripts added later. Load order preserved |
| Age question pre-selected, missing from first layer, false `18_or_over` records | Asked on the first layer, nothing pre-selected, "Accept" requires an answer, records `not_declared` / `not_asked` honestly. All optional purposes off for under-18s |
| Fake languages (Tamil showed English) | Only languages with real translations are offered (English, Hindi). The rest are shown as Pro |
| Rule 3: no itemised personal data | First layer lists the personal data per purpose. Organisations can edit it |
| Board complaint link optional | Required, and the rights text always mentions the Board |
| Withdrawal left localStorage behind, logged as "reject" | Clears cookies (all paths) and storage, reloads so running trackers stop, logged as `withdraw` with what was withdrawn |
| "Necessary … legitimate use" claim | Replaced with a plain description. Have a lawyer confirm |
| `reconsentDays: 0` became 365 | 0 now means "never expires" |
| Weak consent ID on http sites | Uses `crypto.getRandomValues` |
| Reject hidden below Accept on phones | Buttons stick to the bottom of the banner, Accept and Reject side by side |
| Scanner missed browser storage and cookieless tracking | Both detected and flagged; unidentified items flagged too |
| Scan could outlast the gateway timeout | 60 s hard limit per scan |
| Generator loaded Google Fonts with no consent | System fonts only; the site sets no cookies and loads no trackers |
| No CSP or HSTS | Strict CSP, HSTS and other headers in `vercel.json`. The demo runs with no CSP violations |
| Tagged scripts broke on sites with a CSP nonce | Nonce carried over |

**Removed by design** (no longer apply, because the demo stores nothing and logs nothing): forged receipts,
CSV injection, receipts dropped by rate limits, IP salt, notice snapshots, consent-log retention, domain
verification, the free-use install snippet, SQLite on Vercel.

**Still to do for the paid product**: see "Pro backend checklist" at the end.

---

## 1. Test it on your computer (15 minutes)

You need Node.js 18 or newer (`node -v`). No `npm install` is needed for the website.

```bash
cd web
npm run dev
```
Open http://localhost:3000 and go through this checklist:

1. Type any website and press **Check my website**. You should see "Website scanning isn't switched on yet". That's correct: no scanner is connected yet.
2. Press **Try it with a sample website**. You should see 3 findings and tables of cookies, storage and services.
3. Press **Continue**. It should refuse until you pick a category for the amber row (`tawk_uuid_0`, choose Functional).
4. Fill in an organisation name, privacy notice link and grievance email. Press **See it working**.
5. On the sample website, the right-hand panel shows all trackers **Blocked** and no cookies.
6. Press **Accept all** without answering the age question. It must ask for your age and nothing may start.
7. Choose "Yes, 18 or older", press **Accept all**. All three turn **Running**, cookies appear and the video loads.
8. Press **Reload page** in the panel. No banner, trackers still **Running** (this was the v1 bug).
9. Click **Privacy choices** (bottom left) → **Reject all**. The page reloads, everything is **Blocked**, the demo cookies and storage are gone.
10. Press **Start over**, choose "No, under 18", press **Accept all**. Everything stays **Blocked**.
11. Switch the banner language to हिन्दी. Only English and Hindi are offered.
12. Click **Your rights and complaints**. The grievance officer and the Board link are shown.
13. Press **Get this on my website**, fill the form, send. The terminal prints the lead (`[lead] … local only`).
14. Narrow the browser to phone width. Accept and Reject stay side by side and fully visible.

**Test with the real scanner (optional).** In a second terminal:
```bash
cd scanner-worker
npm install
npx playwright install chromium
SCANNER_TOKEN=$(openssl rand -hex 32) node worker.js     # copy the token it uses
```
Then in `web/`, create `.env.local`:
```
SCANNER_URL=http://127.0.0.1:8080
SCANNER_TOKEN=<the same token>
```
Restart `npm run dev` and scan a real website, for example your own. Scanning `localhost` or `169.254.169.254`
must fail with "This address isn't a public website."

(On Windows, set the token with `set SCANNER_TOKEN=...` in Command Prompt, or run the worker with Docker as below.)

---

## 2. What to use in production

| Piece | Use | Why | Cost to start |
|---|---|---|---|
| Website + API | **Vercel**, Pro plan | Static pages + two small functions; Mumbai region (`bom1`). Vercel's Hobby plan is meant for non-commercial use, and this is a business lead generator | Pro plan |
| Scanner | **Railway** (simplest) or a **DigitalOcean Bangalore droplet** (most control) | Needs a real container with Chromium; can't run safely on Vercel | ~US$5–12/month |
| Leads | **Google Sheet** via Apps Script (free), or **Zoho CRM / HubSpot** via Zapier or Make | Any service that accepts a JSON webhook works | Free to start |
| Bot protection | **Cloudflare Turnstile** | Free, privacy-friendly, stops bots burning your scans and spamming leads | Free |
| Domain | `consent.kensara.in` | A subdomain keeps it separate from your main site | — |

---

## 3. Deploy the scanner

### Option A: Railway (no servers to manage)
1. Push this folder to a private GitHub repository.
2. In Railway: **New Project → Deploy from GitHub repo**, set **Root Directory** to `scanner-worker`. Railway finds the `Dockerfile`.
3. **Variables**: add `SCANNER_TOKEN` = output of `openssl rand -hex 32`. Keep it; Vercel needs the same value.
4. **Settings → Networking → Generate Domain**. Note the `https://…up.railway.app` address.
5. Pick the region closest to India that Railway offers.
6. Check it: open `https://<your-railway-domain>/health`. You should see `{"ok":true,…}`.
7. Give it at least 1 GB of memory.

If Chromium fails to start with a sandbox error on Railway, add the variable `SCANNER_NO_SANDBOX=1`. The egress proxy still blocks internal addresses, and Railway doesn't expose a private network by default, but keep nothing else in that Railway project.

### Option B: DigitalOcean droplet in Bangalore (more control, India-hosted)
1. Create an Ubuntu droplet (1 vCPU / 2 GB) in **BLR1**. Install Docker: `curl -fsSL https://get.docker.com | sh`.
2. Copy `scanner-worker/` to the server, then:
   ```bash
   cd scanner-worker && docker build -t kensara-scanner .
   docker run -d --restart=always --init --ipc=host -p 127.0.0.1:8080:8080 \
     -e SCANNER_TOKEN="<your token>" --name scanner kensara-scanner
   ```
3. HTTPS with Caddy (simplest): point `scanner.kensara.in` at the droplet, install Caddy, and put this in `/etc/caddy/Caddyfile`:
   ```
   scanner.kensara.in {
     reverse_proxy 127.0.0.1:8080
   }
   ```
   `sudo systemctl reload caddy` issues the certificate automatically.
4. Add the firewall backstop from `scanner-worker/README.md` so the container can't reach private networks even if Chromium is compromised.
5. Allow only ports 22, 80 and 443 in the DigitalOcean cloud firewall.

**Either way:** update Playwright roughly monthly (change the version in both `package.json` and the `Dockerfile`, then redeploy). Chromium security fixes are part of your protection.

---

## 4. Set up lead delivery

**Google Sheet (free):**
1. Create a sheet with a tab named `Leads`. Keep sharing restricted: this is personal data.
2. **Extensions → Apps Script**, paste:
   ```js
   const KEY = "paste-a-long-random-value";
   function doPost(e) {
     if (e.parameter.key !== KEY) throw new Error("forbidden");
     const d = JSON.parse(e.postData.contents);
     SpreadsheetApp.getActiveSpreadsheet().getSheetByName("Leads").appendRow([
       d.submittedAt, d.name, d.email, d.company, d.website, d.phone, d.message, d.interest,
       d.marketingConsent, d.marketingConsentText, d.privacyNoticeVersion,
       d.scanSummary ? JSON.stringify(d.scanSummary) : ""
     ]);
     return ContentService.createTextOutput("ok");
   }
   ```
3. **Deploy → New deployment → Web app**, "Execute as: Me", "Who has access: Anyone". Copy the URL.
4. Your `LEAD_WEBHOOK_URL` is that URL plus `?key=` and the same random value.

**Zapier / Make / HubSpot / Zoho:** create a "Catch webhook" trigger, use its URL as `LEAD_WEBHOOK_URL`, and set
`LEAD_WEBHOOK_SECRET`. It arrives as the `x-kensara-secret` header, so check it in the first step.

Each lead includes whether the person ticked the (unticked-by-default) marketing box, the exact wording they
saw, and your privacy notice version. That is your proof of consent for follow-up marketing.

---

## 5. Deploy the website on Vercel

1. **Cloudflare Turnstile** (dashboard → Turnstile → Add widget, domain `consent.kensara.in`, mode "Managed").
   Put the **site key** in `web/public/site-config.js`, and keep the **secret key** for step 4.
2. Edit the rest of `web/public/site-config.js`: your privacy notice URL, contact email, pricing URL.
3. In Vercel: **Add New → Project**, import the repository, set **Root Directory** to `web`, Framework Preset **Other**. No build command.
4. **Settings → Environment Variables** (Production):

   | Name | Value |
   |---|---|
   | `SCANNER_URL` | `https://<railway-domain>` or `https://scanner.kensara.in` |
   | `SCANNER_TOKEN` | the same token as the worker |
   | `LEAD_WEBHOOK_URL` | from section 4 |
   | `LEAD_WEBHOOK_SECRET` | only for Zapier/Make/HubSpot |
   | `LEAD_NOTICE_VERSION` | e.g. `2026-09`; change it whenever your privacy notice changes |
   | `TURNSTILE_SECRET` | from step 1 |

5. Deploy. Then **Settings → Domains → Add** `consent.kensara.in`, and add the CNAME record Vercel shows at your DNS provider.
6. **Firewall → Rules**: add a rate-limit rule for `/api/scan` (for example 5 requests per 10 minutes per IP) and `/api/lead` (10 per hour). In-memory limits don't work on serverless, so this is where rate limiting lives.
7. Add a "Free DPDP check" link or button on kensara.in pointing to `https://consent.kensara.in`.

**After deploying, repeat the section 1 checklist on the live site**, plus:
- scan your own public website and one well-known site;
- scan `localhost` and `169.254.169.254` and confirm both are refused;
- send a test lead and confirm it lands in your sheet or CRM;
- open the browser console on each page and check there are no red errors.

---

## 6. Before you promote it

- **Legal review** of the banner text in both languages (`T` in `web/public/consent.js`) and the generator's wording. The Hindi was written carefully but should be checked by a fluent reviewer.
- **Kensara's own privacy notice** at the URL in `site-config.js`. It must cover the lead form (what you collect, why, how long you keep leads, withdrawal, grievance contact, the Board) and the scanner (you process the URL, and the scanned site's public pages, and don't store results).
- **Confirm the Board complaint link.** The generator pre-fills MeitY's data protection page. Once you've confirmed the Data Protection Board's official complaint portal address, change the default `value` of `boardUrl` in `web/public/index.html`.
- **Honest marketing copy.** The demo avoids "100% compliant" claims. Keep it that way on kensara.in: overstated compliance claims can count as misleading advertising under the Consumer Protection Act, 2019.
- **Timing:** the DPDP Rules' notice and consent obligations take effect on 13/14 May 2027, unless MeitY's proposal to bring this forward to November 2026 is notified. Check the gazette before quoting a date to prospects.

---

## Pro backend checklist (for the paid product, from the audit)

When you build the paid version (installable banner + consent logs), the backend must include:

1. Postgres in Mumbai (e.g. Supabase `ap-south-1`) with row-level security, pooled connections, and an **append-only** consents table.
2. A `notice_versions` table storing an immutable snapshot of every banner config and text version, referenced by each consent record.
3. Signed, short-lived tokens issued with the banner config, verified on each receipt, so forged receipts are rejected.
4. Rate limiting by site and token (Redis/Upstash), not per IP: many Indian mobile users share one IP.
5. CSV export that neutralises cells starting with `= + - @`.
6. IP pseudonymisation with HMAC and a secret that the server refuses to start without.
7. Domain ownership verification (DNS TXT or a meta tag) before a banner goes live.
8. Retention and deletion for consent logs; an endpoint for a visitor to get their own record by consent ID.
9. A data processing agreement with each client, and your sub-processors (hosting, database) listed.
10. `consent.js` served from versioned, immutable URLs, with an optional Subresource Integrity snippet.

`web/public/consent.js` already supports this live mode (`data-site` + receipts to `/api/consent/:id`), so the Pro backend only needs to provide `/api/embed/:id` and `/api/consent/:id`.
