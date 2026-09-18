# Kensara scanner worker

The website scanner runs as its own small service, **not on Vercel**. Your Vercel site calls it through
`web/api/scan.js`, which holds the shared secret.

```
prospect's browser -> Vercel api/scan.js -> (secret) -> scanner worker -> egress proxy -> internet
```

## How it's protected

| Layer | What it stops |
|---|---|
| Egress proxy (`lib/egress-proxy.js`) | **The real control.** Every Chromium connection (http, https, ws, wss) goes through it. It resolves DNS once, refuses private, loopback, link-local, NAT64, 6to4 and Teredo addresses, allows only ports 80/443, and connects to the exact IP it checked, so DNS rebinding has nothing to exploit. |
| Browser settings (`lib/scanner.js`) | WebSockets closed, service workers blocked, QUIC and WebRTC disabled, non-standard ports aborted, 60 s hard deadline per scan. |
| Container | Throwaway, non-root, no secrets except `SCANNER_TOKEN`, no access to any database. |
| Firewall (you set this up) | Backstop if Chromium itself is ever exploited: the container can't reach private networks or the cloud metadata address. |
| Worker (`worker.js`) | Secret token required (refuses to start without a 32+ char one), max 2 scans at once, queue of 10, 1-hour cache per domain. |
| Vercel route | Optional Cloudflare Turnstile check so bots can't burn your scans. |

## Deploy

See the main README, section "Deploy the scanner".

## Chromium sandbox

The container runs as `pwuser` so Chromium's own sandbox can work. If Chromium fails to launch
("No usable sandbox"), run the container with Playwright's seccomp profile
(see Playwright's Docker docs) rather than disabling the sandbox. `SCANNER_NO_SANDBOX=1` exists only as a
last resort. If you use it, the container and firewall are your only barrier, so keep this worker on its own
machine with nothing else on it.

## Firewall backstop (VM/Docker hosts)

Block the container network from reaching private ranges and the metadata endpoint:

```bash
SUBNET=172.17.0.0/16   # docker network inspect bridge -> Subnet
for NET in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16 100.64.0.0/10; do
  sudo iptables -I DOCKER-USER -s $SUBNET -d $NET -j DROP
done
# keep established replies working
sudo iptables -I DOCKER-USER -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
```
Save the rules (`iptables-persistent`). On AWS, also set the instance metadata to IMDSv2 with a hop limit of 1.
On Railway/Fly/Render there's no internal network by default, but don't attach this service to any private
network that reaches your other services.

## Keep up to date

Update Playwright (and the Docker base tag, which must match `package.json`) monthly. Chromium security
fixes are what protect you from hostile pages.

## Tested

A hostile test page tried 10 ways to reach an internal service: direct loopback, `localhost`, an internal hostname,
IPv4-mapped IPv6, DNS rebinding, a redirect to internal, and three WebSockets. All were blocked, both with every
layer on and with the WebSocket layer switched off (the proxy alone blocks them). Legitimate scanning still works.
