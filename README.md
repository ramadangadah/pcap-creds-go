# PCAP Credential Auditor (Go)

A Go rewrite of the PCAP Credential Auditor, aimed at being as light and fast as
possible. It inspects uploaded `.pcap`/`.pcapng` files and flags cleartext
credentials sent over FTP, POP3, IMAP, HTTP Basic Auth, and SMTP AUTH (Telnet is
best-effort — see the note in `parse.go`). For auditing networks you own or are
authorized to test.

It does **not** capture live traffic — you supply the pcap file.

## Features

- **First-run setup wizard** — on first launch the portal has you create an
  admin account (username + password, stored bcrypt-hashed). No password in env.
- **Real-time TZSP capture** — optionally listens on UDP 37008 for live sniffing
  streams (e.g. from a MikroTik `/tool sniffer`) from one or more devices,
  decodes them, and merges cleartext hits into the list as they arrive.
- **Source control** — accept-all by default (right for a LAN); optionally
  restrict to a subnet via `ALLOWED_SOURCES` (CIDR ranges supported), and
  **block specific IPs or ranges live from the dashboard** (persisted, no restart)
  or via `BLOCKED_SOURCES`. A block always wins over the allowlist.
- **Stats dashboard** — most-repeated IPs (with bars), protocol breakdown, live
  capture status, and running totals across everything you've collected.
- **Deduplication** — identical `username`+`password` results collapse into one
  record with an occurrence count and the union of the IPs, flows, and protocols
  they were seen on.
- **Accumulating findings** — uploads and live streams merge into one persistent,
  deduplicated store.
- **Search + export** — client-side filter on the findings table, plus deduped
  `.txt` / `.csv` export. A "Clear" action wipes stored findings.
- **Tiny footprint** — single static binary, distroless image (~10–12MB), a few
  MB of RAM, no libpcap; uploads are parsed in memory (never written to disk).

## First run

1. Start the app (see below) and open it in a browser.
2. You'll land on the **setup page** — create your admin username and password.
3. From then on you log in with those credentials; uploads and stats accumulate
   on the dashboard.

## Why Go / what changed vs the Python version

The heaviest part of the original wasn't the web framework — it was **scapy**,
which builds a full object graph per packet (slow, RAM-hungry, and the reason it
couldn't run on a small router). This version removes that entirely:

| | Python version | Go version |
|---|---|---|
| pcap parsing | scapy (pure-Python, heavy) | `gopacket/pcapgo` (pure-Go, no libpcap) |
| Runtime | CPython + FastAPI + uvicorn + deps | single static binary |
| Container image | `python:3.12-slim` + deps (~250MB+) | distroless static (~10–12MB) |
| Idle RAM | tens of MB | a few MB |
| Auth | single password via env | admin account created in-portal, bcrypt-hashed |
| State | none (per-session only) | persistent deduplicated findings + stats |
| Temp files | writes upload to `/tmp` during parse | none — parsed in memory |

The extraction logic (port-based protocol detection, per-flow TCP reassembly,
per-protocol regex extractors) is a direct port, so results match the Python
version. `CGO_ENABLED=0` with pure-Go pcap reading yields a fully static binary
small enough to run even on constrained hardware like the hAP ac².

## Local run

```bash
docker compose up --build
```

Open `http://<host>:8000`, complete the setup wizard, then upload a pcap. The
admin account and findings persist in the `pcap_data` Docker volume.

### Run without Docker

```bash
go build -o pcap-creds .
DATA_DIR=./data ./pcap-creds
```

## Configuration (environment variables)

| Var | Default | Purpose |
|---|---|---|
| `DATA_DIR` | `./data` | Where the admin account (`config.json`) and findings (`findings.json`) are stored. Both files are written `0600` — they contain plaintext credentials. |
| `MAX_UPLOAD_MB` | `200` | Upload size cap. |
| `COOKIE_SECURE` | `false` | Set `true` behind HTTPS so the session cookie is TLS-only. The production compose sets this for you. |
| `LIVE_CAPTURE` | `false` | Set `true` to enable the real-time TZSP listener. |
| `LIVE_PORT` | `37008` | UDP port for the TZSP stream (MikroTik's default). |
| `LIVE_BIND` | `0.0.0.0` | Address the listener binds to. |
| `ALLOWED_SOURCES` | (empty) | Comma-separated IPs/CIDRs allowed to stream. **Empty = accept all** (the LAN default). Set e.g. `192.168.1.0/24` to restrict. |
| `BLOCKED_SOURCES` | (empty) | Comma-separated IPs/CIDRs to always drop. Blocks also managed live from the dashboard and persisted in `blocked.json`. A block wins over the allowlist. |
| `PORT` | `8000` | Web UI listen port. |

**Deployment guides:** `LOCAL_DEPLOY.md` for a machine on your own LAN (Oracle
Linux + Docker, no VPN — the common case). `ORACLE_CLOUD_DEPLOY.md` for a public
cloud VM, where live capture must sit behind a VPN with the UDP port bound to the
tunnel.

Sessions are in memory with random IDs. Restarting the process logs users out
(they just sign in again) but the account and findings persist in `DATA_DIR`.

## Deploying to a Linux cloud server (Docker + automatic HTTPS)

`docker-compose.prod.yml` runs the app plus **Caddy** as a reverse proxy that
obtains and renews a Let's Encrypt TLS certificate automatically. The app
container is **not** published to the host — the only way in is through Caddy
over HTTPS, which matters because this tool shows plaintext credentials.

### 1. Provision a VM and install Docker

```bash
curl -fsSL https://get.docker.com | sh
```

### 2. Point DNS at the server

Create a DNS **A record** `creds.example.com` → the VM's public IP. Confirm it
resolves (`dig +short creds.example.com`) before continuing.

### 3. Open the firewall (only 80 + 443)

```bash
sudo ufw allow OpenSSH
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw enable
```

### 4. Upload the project and set the domain

```bash
cd pcap-creds-go
cp .env.example .env
nano .env        # set SITE_ADDRESS and ACME_EMAIL
```

### 5. Bring it up

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Caddy fetches a certificate on the first request (10–20s). Open
`https://creds.example.com` and complete the setup wizard to create your admin
account. If the cert doesn't appear, check
`docker compose -f docker-compose.prod.yml logs -f caddy` — usually DNS not yet
pointing at the box, or port 80 blocked upstream.

## Security notes

This tool stores and displays real credentials in plaintext, and cloud-hosting
it makes it internet-reachable. Harden accordingly:

- **Use a strong admin password** at the setup step.
- **The `/data` volume contains plaintext credentials** (`findings.json`). Keep
  it on a trusted host, and clear findings when you're done with an assessment.
- **Prefer not exposing it to the whole internet.** The strongest option is to
  keep 80/443 closed to the world and reach the box over a **WireGuard /
  Tailscale VPN**.
- **If it must be public, add the second gate** — uncomment the `basicauth`
  block in the `Caddyfile`, and/or restrict by source IP at the cloud firewall.
- **Only upload captures from networks you own or are authorized to assess.**

## Project layout

```
main.go                  HTTP server: setup wizard, login, dashboard, upload, exports
store.go                 persistence: admin account, deduplicated findings, stats
parse.go                 pcap/pcapng reading, flow reassembly, protocol extractors
templates/               setup + login + dashboard pages (embedded into the binary)
static/style.css         stylesheet (embedded into the binary)
Dockerfile               multi-stage: golang build -> distroless static runtime
docker-compose.yml       local dev (with pcap_data volume)
docker-compose.prod.yml  app + Caddy (automatic HTTPS) for cloud
Caddyfile                reverse proxy + TLS config
```

## Extending

- `parse.go` holds protocol detection/extraction; `firstDecoder` handles the
  link-layer types (Ethernet, raw IPv4/IPv6, Linux SLL, loopback).
- `store.go` holds dedup + stats. To keep per-upload history rather than a merged
  view, add a scans table alongside the findings map.
- For a larger dataset, swap the JSON store for pure-Go SQLite
  (`modernc.org/sqlite`) to preserve the CGO-free, static-binary property.
