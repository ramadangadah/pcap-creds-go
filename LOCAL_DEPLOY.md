# Deploying on a local network machine (Oracle Linux + Docker)

This is the setup for running the tool on a box on **your own LAN** — no cloud,
no WireGuard. The collector and your devices are on the same network, so the
mirrored traffic never leaves your LAN, and accept-all is a sensible default. Use
this only for networks and devices you own or are authorized to test.

```
 MikroTik router  ──►  LAN  ──►  Oracle Linux box (Docker)
 /tool sniffer                    UDP 37008 (TZSP)  +  http://<lan-ip>:8000
```

## 1. Install Docker on Oracle Linux

```bash
sudo dnf install -y dnf-utils
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker $USER && newgrp docker
```

## 2. Open the ports in the host firewall (firewalld)

Oracle Linux runs firewalld. Allow the dashboard and the TZSP port on your LAN:

```bash
sudo firewall-cmd --permanent --add-port=8000/tcp     # web dashboard
sudo firewall-cmd --permanent --add-port=37008/udp    # live capture
sudo firewall-cmd --reload
```

(If you want to be stricter, scope these to your LAN with a firewalld rich rule,
e.g. `source address="192.168.1.0/24"`.)

## 3. Run it

```bash
cd pcap-creds-go
docker compose up -d --build
```

That's it — the default `docker-compose.yml` already enables live capture,
accept-all, and a persistent `pcap_data` volume. Find the box's LAN IP with
`ip -4 addr` and open:

```
http://<lan-ip>:8000
```

Complete the **setup wizard** to create your admin account, and you're in.

> The dashboard runs over plain HTTP here, which is fine on a trusted LAN. If you
> want HTTPS, put it behind a reverse proxy or use the cloud compose.

## 4. Point your MikroTik at the box

Stream the sniffer to the Oracle box's **LAN IP** on UDP 37008:

```
/tool/sniffer set streaming-enabled=yes streaming-server=<box-lan-ip> filter-stream=yes
/tool/sniffer start
```

Optionally narrow what you mirror to the cleartext protocols to keep volume down:

```
/tool/sniffer set filter-port=ftp,smtp,http,pop3,imap
```

Within seconds the dashboard's **Live capture** card shows packets, active flows,
and source devices, and any cleartext credentials flow into the deduplicated
findings list. Add more routers/APs by pointing each at the same box.

## 5. Controlling sources (accept-all + blocklist)

- **Default: accept-all.** Every device on the LAN that streams to the box is
  accepted. Good for getting started.
- **Restrict to a range (optional).** Set `ALLOWED_SOURCES` in the compose to a
  subnet, e.g. `192.168.1.0/24`, and only that range is accepted.
- **Block specific sources.** On the dashboard's **Live capture** card, each seen
  device has a **Block** button, and there's a field to block an IP or range by
  hand (e.g. `192.168.1.50` or `192.168.1.0/24`). Blocks persist across restarts
  (`blocked.json` in the data volume) and take effect immediately — no restart.
  Unblock from the same panel. You can also preload blocks via `BLOCKED_SOURCES`.

Precedence: a blocked source is always dropped, even if it's inside
`ALLOWED_SOURCES`.

## Notes

- The `pcap_data` volume holds `findings.json` with plaintext credentials — keep
  the box on a trusted network and use the dashboard's **Clear** button when an
  assessment is done.
- Uploads still work alongside live capture; both feed the same deduplicated list.
- ARM or x86 both fine — the image is `CGO_ENABLED=0` and multi-arch.
