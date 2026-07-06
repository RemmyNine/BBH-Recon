# 01. Operational Security (OpSec) & Infrastructure

Establishing a secure, clean, and stealthy operational baseline is the foundation of any professional reconnaissance framework. This section details infrastructure setups, OpSec precautions, legal guardrails, and tactical deployment strategies.

---

## Table of Contents
- [Infrastructure Setup](#infrastructure-setup)
- [Stealth Redirectors](#stealth-redirectors)
- [Proxy Rotation & Tor](#proxy-rotation--tor)
- [Isolated Browser Environments](#isolated-browser-environments)
- [Legal & Ethical Baseline](#legal--ethical-baseline)

---

## Infrastructure Setup

A fundamental rule of reconnaissance is to never perform active testing from your local environment or home IP address. 

### VPS Selection & Provisioning
- **Dedicated Providers**: Use providers like DigitalOcean, Linode, Hetzner, Vultr, or AWS.
- **Ephemeral VPS Strategy**: Spin up VPS instances dynamically for specific scanning tasks and tear them down immediately after. This avoids IP reputation blocklisting from target networks.
- **Location Alignment**: Match the geographical location of your VPS instances to your target's hosting environment to minimize latency and bypass regional access controls (e.g., Geo-IP blocking).

### DNS Setup for Infrastructure
When running servers that send emails, resolve domains, or host redirectors, ensure proper DNS records are configured to prevent domain/IP reputation drops:
- **rDNS (Reverse DNS)**: Set pointer (PTR) records for your VPS IPs to point back to your registered domain.
- **SPF, DKIM, DMARC**: Configure email auth records on redirectors/mail servers to avoid getting flagged by spam filters.

---

## Stealth Redirectors

Redirectors sit between your scanning tools/attack servers and the target. They mask the true location of your back-end infrastructure and allow you to quickly pivot or change IPs if an operational IP gets banned.

### Nginx Redirector Configuration
Use Nginx as a reverse proxy to filter incoming traffic and only forward legitimate-looking requests to your scanning tools or C2.

```nginx
server {
    listen 443 ssl;
    server_name attack-domain.xyz;

    ssl_certificate /etc/letsencrypt/live/attack-domain.xyz/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/attack-domain.xyz/privkey.pem;

    # Block access to scanning files based on custom headers or User-Agents
    location / {
        proxy_pass http://YOUR_BACKEND_IP:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### CDN-Based Redirectors
Routing traffic through Cloudflare or Fastly hides your VPS backend IP behind the CDN's IP range. This makes it difficult for blue teams to block your scans without blocking the entire CDN.

---

## Proxy Rotation & Tor

For passive OSINT, credential checks, or high-volume API requests, rotate your IPs to circumvent rate limits.

### ProxyChains Setup
ProxyChains forces any TCP connection made by a tool (e.g., Nmap, curl) to flow through a proxy or series of proxies.

1. Install ProxyChains:
   ```bash
   sudo apt install proxychains4 -y
   ```
2. Configure `/etc/proxychains4.conf` to use Tor or a custom proxy list:
   ```text
   # /etc/proxychains4.conf
   dynamic_chain
   proxy_dns
   [ProxyList]
   socks5  127.0.0.1 9050 # Local Tor service
   socks4  192.168.1.50 1080 # Custom proxy
   ```

### AWS API Gateway Rotation (FireProx)
[FireProx](https://github.com/ustayready/fireprox) creates on-the-fly API Gateway endpoints to route HTTP traffic. Every request sent via FireProx utilizes a different AWS IP address, bypassing IP-based rate limiting.

---

## Isolated Browser Environments

To prevent cross-contamination of credentials, cookies, and search history:
- **Dedicated Profiles**: Run Chrome or Firefox with the `--user-data-dir` flag pointing to an isolated directory.
- **Containers**: Use Firefox Multi-Account Containers to separate targets.
- **Recon Extensions**: Equip your recon browser with:
  - **FoxyProxy**: Manage proxy profiles.
  - **Wappalyzer / BuiltWith**: Tech stack discovery.
  - **Cookie-Editor**: Quick session manipulation.
  - **User-Agent Switcher**: Emulate different browser environments.

---

## Legal & Ethical Baseline

1. **Strict Target Boundaries**: Cross-reference every active IP or domain with the target's scope list.
2. **Safe Harbor Coverage**: Verify if the program provides full safe harbor or partial safe harbor.
3. **Audit Trail Logging**: Always log command history with timestamps. If accused of causing a denial of service, you must be able to prove exactly what commands you ran and when.
   ```bash
   # Add to ~/.bashrc or ~/.zshrc for command time-stamping
   export HISTTIMEFORMAT="%Y-%m-%d %H:%M:%S "
   ```
4. **Data Privacy**: Stop scanning immediately and report the finding if you stumble upon:
   - Personally Identifiable Information (PII)
   - Credit card data (PCI-DSS)
   - Healthcare details (HIPAA)
   - Database backups/internal configuration dumps
