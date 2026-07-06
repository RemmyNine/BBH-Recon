# 03. Passive Reconnaissance & Certificate Transparency

Passive reconnaissance relies on querying external databases, logs, and public archives to discover target assets. This method does not generate direct traffic to the target, bypassing intrusion detection systems (IDS) and firewalls.

---

## Table of Contents
- [Passive Subdomain Enumeration](#passive-subdomain-enumeration)
- [Certificate Transparency (CT) Mining](#certificate-transparency-ct-mining)
- [Passive Archive Mining](#passive-archive-mining)
- [Ad-Network Correlation](#ad-network-correlation)
- [Search Engine & IoT Indexing (Shodan, Censys, FOFA)](#search-engine--iot-indexing-shodan-censys-fofa)
  - [Shodan Advanced Query Syntax](#shodan-advanced-query-syntax)
  - [Censys Query Language](#censys-query-language)
  - [FOFA Search Engine](#fofa-search-engine)
- [GitHub Dorking & Code Repository Leakage](#github-dorking--code-repository-leakage)
  - [Secret Pattern Matching](#secret-pattern-matching)
  - [GitLab & Bitbucket Surveillance](#gitlab--bitbucket-surveillance)
- [Passive Email Enumeration & Pattern Analysis](#passive-email-enumeration--pattern-analysis)
- [Favicon Hash Matching for Technology Fingerprinting](#favicon-hash-matching-for-technology-fingerprinting)
- [WHOIS History & Reverse WHOIS](#whois-history--reverse-whois)
- [CDN & WAF Passive Detection](#cdn--waf-passive-detection)
- [Third-Party SaaS Footprint Mapping](#third-party-saas-footprint-mapping)
- [Pastebin & Underground Intelligence Monitoring](#pastebin--underground-intelligence-monitoring)

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

---

## Search Engine & IoT Indexing (Shodan, Censys, FOFA)

Specialized search engines continuously scan the entire IPv4 address space and index banner data, TLS certificates, HTTP responses, and service fingerprints. These are passive sources—the target never sees queries.

### Shodan Advanced Query Syntax
[Shodan](https://www.shodan.io/) provides a filtering grammar for surgical searches across banners and metadata.

| Filter | Purpose | Example |
|--------|---------|---------|
| `org:` | Organization name from WHOIS | `org:"Target Corp"` |
| `ssl:` | SSL certificate subject/issuer | `ssl:"*.target.com"` |
| `http.title:` | HTML `<title>` tag content | `http.title:"Target Portal"` |
| `http.favicon.hash:` | Favicon MurmurHash3 fingerprint | `http.favicon.hash:-170843133` |
| `port:` | Specific port filter | `port:3389 org:"Target Corp"` |
| `product:` | Banner software string | `product:"Apache httpd"` |
| `asn:` | Autonomous System Number | `asn:AS15169` |
| `html:` | Raw HTML body search | `html:"password"` |
| `server:` | HTTP Server header | `server:"Microsoft-IIS/10.0"` |
| `vuln:` | Known CVE from Shodan's database | `vuln:"CVE-2021-44228"` |

**Compound Query Examples**:
```bash
# All target IPs exposing RDP and tagged with target org
org:"Target Corporation" port:3389

# TLS certificates matching any target subdomain
ssl.cert.subject.CN:"*.target.com"

# Jupyter Notebooks without authentication
http.title:"Jupyter Notebook" http.component:"jupyter" -http.title:"Login"
```

### Censys Query Language
[Censys](https://search.censys.io/) indexes hosts and certificates separately with a structured query language.

**Host Search Grammar**:
```text
services.port: 443 AND
services.tls.certificates.leaf_data.subject.common_name: "*.target.com"
```

**Certificate Transparency Integration**:
```text
parsed.names: "target.com" AND
parsed.validity_period.not_after: [2024-01-01 TO *]
```

**API Query via CLI**:
```bash
censys search "services.tls.certificates.leaf_data.issuer.organization: 'Target Inc'" \
  --index-type hosts --pages 5
```

### FOFA Search Engine
[FOFA](https://fofa.info/) is a Chinese-origin search engine with a unique query grammar and extensive Chinese infrastructure coverage (often overlooked by Western recon pipelines).
```text
# FOFA query syntax
domain="target.com" && protocol="https"
cert="target.com"
icon_hash="-170843133"
body="Admin Panel"
```

---

## GitHub Dorking & Code Repository Leakage

Public code repositories are a passive goldmine for API keys, internal hostnames, configuration templates, and architecture documentation.

### Secret Pattern Matching
- **[GitLeaks](https://github.com/gitleaks/gitleaks)**: Run scheduled scans against target organization repositories using custom regex rules for AWS keys, GCP service account tokens, JWT secrets, and database connection strings.
  ```bash
  gitleaks detect --source https://github.com/target-org/repo.git -v --redact
  ```
- **[TruffleHog](https://github.com/trufflesecurity/trufflehog)**: Deep scans git history across all branches and commit objects, verifying credential validity via API calls.
  ```bash
  trufflehog github --org target-org --only-verified
  ```
- **Manual Dorking Syntax** (GitHub advanced search):
  ```text
  # API keys hardcoded in config files
  org:target-org filename:.env password
  
  # Internal hostname leakage in Terraform
  org:target-org filename:main.tf "private_ip"
  
  # Pytest/JUnit outputs leaking server paths
  org:target-org path:tests/ extension:xml "hostname"
  
  # Jenkinsfile pipeline credential exposure
  org:target-org filename:Jenkinsfile "credentialsId"
  ```

### GitLab & Bitbucket Surveillance
Organizations running self-hosted GitLab or Bitbucket instances occasionally expose repository data through unauthenticated public registration, misconfigured visibility settings, or archived employee forks.
- **[GitLabWatch](https://github.com/pasientskyhosting/gitlabwatch)**: Monitor a GitLab instance for public repository creation.
- **Bitbucket Public Snippets**: Check `https://bitbucket.org/{username}/` for public snippets with sensitive data sharing from individual developer accounts.
- **Gist Surveillance**: `https://gist.github.com/{username}` for code snippets containing internal URLs, configuration templates, or credentials.

---

## Passive Email Enumeration & Pattern Analysis

Mapping employee email addresses establishes naming conventions (`first.last@target.com`) critical for credential spraying and phishing simulation pre-texting.

- **Sources**:
  - **[Hunter.io](https://hunter.io/)**: Aggregates publicly referenced email addresses and deduces corporate naming patterns.
  - **[Phonebook.cz](https://phonebook.cz/)**: Searches across leaked database dumps for corporate email domains.
  - **[DeHashed](https://dehashed.com/)**: Cross-references email addresses from data breaches.
  - **LinkedIn Sales Navigator**: Export employee lists with job titles, then infer email addresses using pattern deduction (`f.last@`, `firstlast@`, `first_last@`).
- **[CrossLinked](https://github.com/m8r0wn/crosslinked)**: LinkedIn scraping tool that programmatically collects employee names and generates email permutations.
  ```bash
  crosslinked -f "{first}.{last}" target.com --jitter 1
  ```
- **Email Pattern Validation**: Validate inferred addresses through:
  - Microsoft Teams / Skype for Business presence checks (passive).
  - O365 Autodiscover response parsing.
  - OWA `/owa/auth/` status codes.

---

## Favicon Hash Matching for Technology Fingerprinting

Every website's favicon generates a unique MurmurHash3 hash. Search engines index these hashes, enabling identification of all internet hosts running the same technology stack—regardless of domain name.

- **Hash Calculation**:
  ```bash
  # Calculate favicon hash with python
  python3 -c "import mmh3, requests, codecs; \
    fav = requests.get('https://target.com/favicon.ico').content; \
    b64 = codecs.encode(fav, 'base64'); \
    print(mmh3.hash(b64))"
  ```
- **Shodan Query**: `http.favicon.hash:<hash_value>` returns all hosts globally sharing the same favicon.
- **[Favicon-Map](https://github.com/0x6470/favicon-map)**: Pre-computed database mapping known favicon hashes to specific technology stacks (e.g., specific Jenkins versions, phpMyAdmin, Citrix NetScaler, Apache Tomcat, VMware vSphere).

---

## WHOIS History & Reverse WHOIS

Historical WHOIS records reveal organizational structure changes, expired domains eligible for takeover, and personal registrant names hidden by modern WHOIS privacy redactions.

- **[WhoisXML API](https://whois.whoisxmlapi.com/)**: Programmatic access to historical WHOIS databases and reverse WHOIS (find all domains registered by a specific email address or organization name).
- **[DomainTools](https://www.domaintools.com/)**: Industry-standard for historical WHOIS lookups, IP-to-domain correlation, and registrant monitoring.
- **[ViewDNS.info](https://viewdns.info/)**: Free reverse IP lookups, WHOIS history, and DNS record history.
- **Passive Regional Registry Queries**: Query RIR databases (ARIN, RIPE, APNIC) for organization handles (`org:`), which remain static even when domains are dropped—enabling tracking of infrastructure reassignments.

---

## CDN & WAF Passive Detection

Determining whether a target sits behind a Content Delivery Network (CDN) or Web Application Firewall (WAF) is critical for understanding the attack surface: origin IP identification vs. CDN proxy attack.

- **CDN Detection Techniques**:
  - **CNAME Chain Analysis**: Check DNS CNAME records for CDN domains (e.g., `*.cloudfront.net`, `*.akamai.net`, `*.fastly.net`, `*.cdn.cloudflare.net`).
  - **Server Header Inspection**: Passive HTTP response headers often contain CDN-specific signatures: `Server: cloudflare`, `X-Cache: Hit from cloudfront`, `Via: 1.1 varnish`, `x-sucuri-id`.
  - **IP ASN Lookup**: If the resolved IP belongs to AS13335 (Cloudflare), AS16509 (AWS), or AS20940 (Akamai), the target is behind that provider's reverse proxy.
- **Origin IP Discovery**:
  - **Historical DNS Records**: SecurityTrails / DNSDB contain A records that predate CDN onboarding.
  - **SSL Certificate History**: Censys / crt.sh certificates logged before CDN migration reveal the true origin IP in SAN fields.
  - **MX Record Analysis**: Mail servers often bypass CDN proxy, exposing the origin IP space.
- **WAF Fingerprinting**: [wafw00f](https://github.com/EnableSecurity/wafw00f) sends probe requests and analyzes response patterns to identify the specific WAF vendor (Cloudflare, AWS WAF, Imperva, F5 ASM, FortiWeb, Barracuda).

---

## Third-Party SaaS Footprint Mapping

Organizations expose themselves across SaaS platforms, each with potentially overlooked public-facing resources.

- **Document Sharing Platforms**:
  - **Google Drive / Docs**: Search for publicly shared documents containing `site:docs.google.com "target.com"` or `site:drive.google.com "target.com"`.
  - **Notion**: Search `site:notion.so "target.com"` for publicly shared Notion pages containing internal documentation.
  - **Confluence / SharePoint Online**: Accessible intranet portals through cloud tenant instances.
- **Trello / Jira / Asana Boards**: Publicly indexed project management boards through search engine dorking: `site:trello.com "target.com"`, `site:atlassian.net "target.com"`.
- **Customer Support & Ticketing**:
  - Zendesk: `{target}.zendesk.com`
  - Freshdesk: `{target}.freshdesk.com`
  - Intercom Help Center: `site:intercom.help "target.com"`
- **Status Pages**: `status.{target}.com`, `{target}.statuspage.io` — often expose internal infrastructure component names and vendor relationships.

---

## Pastebin & Underground Intelligence Monitoring

Sensitive data—database dumps, credential lists, source code snippets, configuration files—frequently appears on paste sites and underground forums.

- **Automated Monitoring**:
  - **[PasteHunter](https://github.com/kevthehermit/PasteHunter)**: Continuously polls paste sites using YARA rules to match corporate keywords, domain names, or credential patterns.
  - **[PasteMonitor](https://github.com/tehryanx/pastemonitor)**: Keyword-based pastebin monitoring with Slack/Discord alerting.
- **Keyword Patterns to Track**:
  - Corporate domain names and subdomains.
  - Organization-specific API key prefixes (e.g., `AKIA` for AWS, `sk-` for OpenAI, `ghp_` for GitHub tokens).
  - Email address patterns matching employee naming conventions.
  - Database connection string formats: `mysql://`, `postgresql://`, `mongodb+srv://`.
  - Internal hostnames: `*.internal.{target}.com`, `*.corp.{target}.com`.
- **Dark Web Monitoring**: Commercial services ([Recorded Future](https://www.recordedfuture.com/), [Digital Shadows](https://www.digitalshadows.com/)) crawl underground forums for credential dumps, but budget-conscious operators query free indices from [Ahmia](https://ahmia.fi/) and [DarkSearch](https://darksearch.io/).
