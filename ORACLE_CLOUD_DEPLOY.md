# Deploying to Oracle Cloud (with real-time capture over WireGuard)

This guide stands the tool up on an Oracle Cloud "Always Free" VM and wires a
MikroTik router to stream live traffic to it for real-time credential auditing.

**Read this first — the architecture matters.**
The traffic your router mirrors contains exactly the cleartext credentials this
tool hunts for. Streaming that across the public internet unencrypted would be
the very leak you're auditing against, and an open TZSP collector on a public IP
is a credential sink anyone could feed or abuse. So the router → server link runs
**inside a WireGuard tunnel**, the live UDP port is bound **only to the VPN
address**, and a **source allowlist** restricts who may stream. Only ever point
this at networks and devices you own or are explicitly authorized to test.

```
 MikroTik router  ──►  WireGuard tunnel (encrypted)  ──►  Oracle VM
 /tool sniffer                                            UDP 37008 bound to 10.8.0.1
 (TZSP stream)                                            + web dashboard via HTTPS
```

---

## 1. Create the VM

1. Oracle Cloud console → **Compute → Instances → Create instance**.
2. Image: **Ubuntu 22.04**. Shape: **VM.Standard.A1.Flex** (Ampere/ARM, free
   tier). The app is `CGO_ENABLED=0` and multi-arch, so ARM64 is fine.
3. Add your SSH public key, create, and note the **public IP**.

## 2. Open only what's needed (Oracle security list)

VCN → your subnet → **Security List** → add **Ingress** rules:

| Port | Protocol | Source | Purpose |
|---|---|---|---|
| 22 | TCP | your IP/32 | SSH |
| 80 | TCP | 0.0.0.0/0 | HTTP→HTTPS redirect + ACME |
| 443 | TCP | 0.0.0.0/0 | Web dashboard (HTTPS) |
| 51820 | UDP | 0.0.0.0/0 | WireGuard |

**Do not** open 37008. Live capture never touches the public internet — it only
travels inside the WireGuard tunnel.

Oracle Ubuntu images also ship a host firewall. Allow the same set:

```bash
sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT
sudo iptables -I INPUT -p tcp --dport 443 -j ACCEPT
sudo iptables -I INPUT -p udp --dport 51820 -j ACCEPT
sudo netfilter-persistent save
```

## 3. Install Docker

```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER && newgrp docker
```

## 4. Set up WireGuard on the VM

```bash
sudo apt update && sudo apt install -y wireguard
umask 077
wg genkey | sudo tee /etc/wireguard/server.key | wg pubkey | sudo tee /etc/wireguard/server.pub
```

Create `/etc/wireguard/wg0.conf` (server is `10.8.0.1`, router will be `10.8.0.2`):

```ini
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = <contents of /etc/wireguard/server.key>

[Peer]
# MikroTik router
PublicKey = <ROUTER_WG_PUBLIC_KEY>   # fill in after step 6
AllowedIPs = 10.8.0.2/32
```

Enable it:

```bash
sudo systemctl enable --now wg-quick@wg0
```

## 5. Point DNS at the VM

Create a DNS **A record** `creds.example.com` → the VM's public IP. Verify:

```bash
dig +short creds.example.com
```

## 6. Configure WireGuard on the MikroTik (RouterOS v7)

On the router:

```
/interface/wireguard add name=wg-audit listen-port=51820
/interface/wireguard/print                      # copy the public-key value

/interface/wireguard/peers add interface=wg-audit \
    public-key="<SERVER_WG_PUBLIC_KEY>" \
    endpoint-address=<VM_PUBLIC_IP> endpoint-port=51820 \
    allowed-address=10.8.0.1/32 persistent-keepalive=25s

/ip/address add address=10.8.0.2/24 interface=wg-audit
```

Copy the router's **public key** into the `[Peer]` block from step 4 on the VM,
then `sudo systemctl restart wg-quick@wg0`. Confirm the tunnel:

```bash
sudo wg            # on the VM — you should see a handshake with 10.8.0.2
```

## 7. Deploy the app

```bash
# copy this project folder to the VM (scp -r ./pcap-creds-go ubuntu@<VM_IP>:~)
cd pcap-creds-go
cp .env.example .env
nano .env
```

Set in `.env`:

```
SITE_ADDRESS=creds.example.com
ACME_EMAIL=you@example.com
LIVE_CAPTURE=true
LIVE_PORT=37008
WG_ADDR=10.8.0.1
ALLOWED_SOURCES=10.8.0.2/32          # your router's WireGuard address
```

Bring it up:

```bash
docker compose -f docker-compose.prod.yml up -d --build
```

Open `https://creds.example.com`, complete the **setup wizard** to create your
admin account, and you're in.

## 8. Start streaming from the MikroTik

Point the router's sniffer at the server's **WireGuard** address (not its public
IP), so packets ride the tunnel:

```
/tool/sniffer set streaming-enabled=yes streaming-server=10.8.0.1 \
    filter-stream=yes
/tool/sniffer start
```

Optionally narrow what you mirror with sniffer filters (e.g. only ports
21/25/80/110/143), which keeps volume down and focuses on cleartext protocols.

Within a few seconds the dashboard's **Live capture** card should show packets,
active flows, and source devices ticking up, and any cleartext credentials will
flow into the deduplicated findings list. Add more routers/APs by giving each its
own WireGuard peer IP and adding it to `ALLOWED_SOURCES`.

## 9. Hardening checklist

- [ ] 37008 is **not** in the Oracle security list (verify).
- [ ] `ALLOWED_SOURCES` lists only your devices' WireGuard IPs.
- [ ] Strong admin password set at the setup step.
- [ ] Consider putting the dashboard itself behind the VPN too (restrict 443 to
      `10.8.0.0/24` in the security list) if you don't need it publicly, or add
      the `basicauth` block in the `Caddyfile` as a second gate.
- [ ] Remember `pcap_data/findings.json` holds plaintext credentials — clear it
      when an assessment is done (the dashboard "Clear" button, or delete the
      volume).

## Troubleshooting

- **No handshake in `sudo wg`** → router endpoint/keys wrong, or UDP 51820 not
  open in the Oracle security list.
- **Tunnel up but no packets on the Live card** → sniffer `streaming-server`
  must be `10.8.0.1` (the VPN IP), and `ALLOWED_SOURCES` must include
  `10.8.0.2/32`. Check `docker compose -f docker-compose.prod.yml logs -f app`.
- **Cert not issued** → DNS not pointing at the VM yet, or port 80 closed.
  `docker compose -f docker-compose.prod.yml logs -f caddy`.
