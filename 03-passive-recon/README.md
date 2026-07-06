# 03. Passive Reconnaissance & Certificate Transparency

Passive reconnaissance relies on querying external databases, logs, and public archives to discover target assets. This method does not generate direct traffic to the target, bypassing intrusion detection systems (IDS) and firewalls.

---

## Table of Contents
- [Passive Subdomain Enumeration](#passive-subdomain-enumeration)
- [Certificate Transparency (CT) Mining](#certificate-transparency-ct-mining)
- [Passive Archive Mining](#passive-archive-mining)
- [Ad-Network Correlation](#ad-network-correlation)

---

## Passive Subdomain Enumeration

Aggregating subdomain references from third-party lookup tools provides a quick baseline of the target's public footprint.

### Primary Aggregators
- **[Subfinder](https://github.com/projectdiscovery/subfinder)**: The industry-standard tool for passive domain gathering. For best results, configure API keys in `~/.config/subfinder/provider-config.yaml`.
  ```bash
  subfinder -dL targets.txt -all -recursive -silent -o subs_passive.txt
  ```
- **[BBot (Black Lantern Security)](https://github.com/blacklanternsecurity/bbot)**: A highly modular, recursive engine for passive recon.
  ```bash
  bbot -t example.com -f subdomain-enum -o output/
  ```
- **[Amass (OWASP)](https://github.com/owasp-amass/amass)**: Deep passive enum framework. Integrates with config files to query over 50 data sources.
  ```bash
  amass enum -passive -d example.com -config amass_config.ini -o subs_amass.txt
  ```
- **[AssetFinder](https://github.com/tomnomnom/assetfinder)**: A fast, lightweight passive source crawler written in Go.
  ```bash
  assetfinder --subs-only example.com >> subs_passive.txt
  ```

---

## Certificate Transparency (CT) Mining

Certificate Authority authorization models require logging all issued TLS/SSL certificates to public Certificate Transparency logs. This provides a goldmine for identifying subdomains the moment they are generated.

### Querying crt.sh
You can query the crt.sh PostgreSQL database directly to circumvent web timeout issues.

```bash
# Query certificate names directly via standard psql guest access
psql -h crt.sh -U guest certwatch -c "
SELECT ci.NAME_VALUE 
FROM certificate_identity ci 
WHERE ci.NAME_TYPE='dNSName' 
AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.example.com'));" \
| grep -oE '[a-zA-Z0-9._-]+\.example\.com' | sort -u > crtsh_subs.txt
```

### Real-Time Monitoring (CertStream)
Use CertStream to monitor certificate transparency logs in real-time. This is ideal for identifying phishing setups or immediately flagging new dev/staging sites.

```python
import certstream

def callback(message, context):
    if message['message_type'] == "certificate_update":
        for domain in message['data']['leaf_cert']['all_domains']:
            if "example.com" in domain:
                print(f"[FOUND CERT] {domain}")

certstream.listen_for_events(callback)
```

---

## Passive Archive Mining

Public web archives scrape and save snapshots of the web. These snapshots contain historical hostnames and endpoint URL strings.

### Wayback Machine & Common Crawl Mining
- **[GAU (Get All URLs)](https://github.com/lc/gau)**: Fetch URLs from the Wayback Machine, Common Crawl, AlienVault OTX, and URLScan.
  ```bash
  gau --subs example.com | unfurl -u domain | sort -u >> subs_passive.txt
  ```
- **[Waybackurls](https://github.com/tomnomnom/waybackurls)**: Extract URLs that the Wayback Machine has crawled.
  ```bash
  echo "example.com" | waybackurls | unfurl -u domains | sort -u >> subs_passive.txt
  ```

---

## Ad-Network Correlation

Websites under the same corporate umbrella often share third-party tracking codes, AdSense IDs, or Google Tag Manager tokens.

- **Tracking Code Correlation**: Look for analytics identifiers (e.g., `UA-XXXXX`, `G-XXXXXX`, `pub-XXXXXX`) in web source code.
- **[BuiltWith](https://builtwith.com/) & [Udon](https://github.com/dhn/udon)**: Run reverse tracking tag lookup queries to uncover related domains that share the same tracking configurations.
