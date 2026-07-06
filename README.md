# BBH-Recon

> A **comprehensive, practitioner-grade** reconnaissance framework for bug bounty hunting and red team operations. Covers every phase from initial scope expansion to continuous monitoring, with tooling, one-liners, methodology notes, and operational tradecraft.

---

## Table of Contents

- [Operational Security (OpSec)](#operational-security-opsec)
- [Scope & Target Profiling](#scope--target-profiling)
- [Wide Recon](#wide-recon)
  - [Subdomain Enumeration](#subdomain-enumeration)
  - [DNS Bruteforce & Permutation](#dns-bruteforce--permutation)
  - [Subdomain Takeover](#subdomain-takeover)
  - [IP Space & ASN Discovery](#ip-space--asn-discovery)
  - [Port Scanning & Service Discovery](#port-scanning--service-discovery)
- [Asset Discovery](#asset-discovery)
  - [Corporate Intelligence](#corporate-intelligence)
  - [Cloud Asset Discovery](#cloud-asset-discovery)
  - [GitHub & Code Recon](#github--code-recon)
  - [Certificate Transparency](#certificate-transparency)
- [Content Discovery](#content-discovery)
  - [Directory & File Fuzzing](#directory--file-fuzzing)
  - [Historical Content Analysis](#historical-content-analysis)
  - [API & GraphQL Discovery](#api--graphql-discovery)
  - [JavaScript Analysis](#javascript-analysis)
- [Technology Fingerprinting](#technology-fingerprinting)
- [Parameter Analysis](#parameter-analysis)
- [Authentication Analysis](#authentication-analysis)
- [Network & Protocol Analysis](#network--protocol-analysis)
- [OSINT & Passive Recon](#osint--passive-recon)
- [Mobile Application Recon](#mobile-application-recon)
- [Cloud-Specific Recon](#cloud-specific-recon)
- [Vulnerability Scanning](#vulnerability-scanning)
- [Monitoring & Continuous Recon](#monitoring--continuous-recon)
- [Automation Frameworks](#automation-frameworks)
- [Reporting and Documentation](#reporting-and-documentation)
- [Wordlists & Resources](#wordlists--resources)
- [One-Liner Cheat Sheet](#one-liner-cheat-sheet)

---

## Operational Security (OpSec)

> Before touching a single target asset, establish a clean operational baseline. Getting burned = getting banned.

### Infrastructure Setup
- **Dedicated VPS** — Use a clean VPS per engagement. Never recon from your home IP.
- **Rotating Proxies** — [ProxyChains](https://github.com/haad/proxychains) + residential proxies or Tor for passive recon.
- **Separate Browser Profiles** — Use isolated Firefox/Chromium profiles with no personal accounts.
- **Rate Limiting Awareness** — Most platforms (HackerOne, Bugcrowd) monitor aggressive scanning. Respect the rate limits stated in the program policy.
- **VPN/Tunnel** — Keep a dedicated recon VPN tunnel. Mullvad, ProtonVPN, or self-hosted WireGuard are solid choices.

### Legal & Ethical Baseline
- Always read the **entire scope document** before starting. Out-of-scope hits = instant disqualification.
- Check for **safe harbor clauses** in the program policy.
- Document **timestamps** for every action taken. This is your legal protection.
- Never test **production data** — stop immediately if you encounter PII.

---

## Scope & Target Profiling

> Understand what you're allowed to touch before building your recon pipeline.

### Scope Expansion Logic
- Parse the program's scope for wildcard entries (`*.example.com`) — these are goldmines.
- Identify **acquired companies** and subsidiaries — they often run under different domains but share infrastructure.
- Map **partner integrations** listed in the target's documentation or marketing pages.

### Tools
- [Intigriti](https://app.intigriti.com/) / [HackerOne](https://hackerone.com/) / [Bugcrowd](https://bugcrowd.com/) — Pull scope programmatically.
- [chaos-client](https://github.com/projectdiscovery/chaos-client) — `chaos -key YOUR_KEY -d example.com` pulls all known subdomains from ProjectDiscovery's dataset.
- [bbscope](https://github.com/sw33tLie/bbscope) — Extract in-scope targets from H1/BC/IT automatically.

```bash
# Pull all H1 program scopes
bbscope h1 -t YOUR_H1_TOKEN -o output/scopes.txt
```

---

## Wide Recon

### Subdomain Enumeration

> Passive first, active second. Never skip passive sources — they surface assets that DNS bruteforce misses.

#### Passive Sources
- [Subfinder](https://github.com/projectdiscovery/subfinder) — Best passive aggregator. **Configure API keys** for maximum coverage.
  ```bash
  subfinder -dL targets.txt -all -recursive -silent -o subs_passive.txt
  ```
- [BBot](https://github.com/blacklanternsecurity/bbot) — Modern, module-based alternative with excellent passive coverage.
  ```bash
  bbot -t example.com -f subdomain-enum -o output/
  ```
- [Amass](https://github.com/owasp-amass/amass) — Deep passive + active enumeration. Heavyweight but thorough.
  ```bash
  amass enum -passive -d example.com -config amass_config.ini -o subs_amass.txt
  ```
- [AssetFinder](https://github.com/tomnomnom/assetfinder) — Fast, lightweight passive source aggregator.
  ```bash
  assetfinder --subs-only example.com >> subs_passive.txt
  ```
- [Findomain](https://github.com/Findomain/Findomain) — Multi-source subdomain discovery with monitoring support.
- [crt.sh PostgreSQL](https://github.com/RemmyNine/Methodology/blob/main/crtsh.sh) — Direct DB query for CT logs.
  ```bash
  # Direct psql query
  psql -h crt.sh -U guest certwatch -c "SELECT ci.NAME_VALUE FROM certificate_identity ci WHERE ci.NAME_TYPE='dNSName' AND reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower('%.example.com'));" | grep -oE '[a-zA-Z0-9._-]+\.example\.com' | sort -u
  ```
- [GitHub-Subdomains](https://github.com/gwen001/github-subdomains) — Mine GitHub for exposed subdomains.
- [Shosubgo](https://github.com/incogbyte/shosubgo) — Shodan-based subdomain enumeration.
- [Gau](https://github.com/lc/gau) — Archive URL mining for subdomains.
  ```bash
  gau --subs example.com | unfurl -u domain | sort -u >> subs_passive.txt
  ```
- [Waybackurls](https://github.com/tomnomnom/waybackurls) — Wayback Machine URL mining.
  ```bash
  echo example.com | waybackurls | unfurl -u domains | sort -u >> subs_passive.txt
  ```
- [DNSDumpster](https://dnsdumpster.com/) — Visual DNS map and passive enumeration.
- [Shodan](https://shodan.io/) + [Censys](https://censys.io/) — SSL certificate searches.
  ```
  Shodan: ssl.cert.subject.cn:"*.example.com"
  Censys: parsed.names: example.com
  ```
- [FOFA](https://fofa.info/) — `domain="example.com"` for certificate-based enum.
- [Sublist3r](https://github.com/aboul3la/Sublist3r) — Multi-source passive discovery (Python).
- [AbuseIPDB](https://github.com/atxiii/small-tools-for-hunters/tree/main/abuse-ip) — Reverse IP and domain intel.
- [Udon](https://github.com/dhn/udon) / [BuiltWith](https://builtwith.com/) — Ad network tracking ID correlation.

#### Active Discovery
- **Favicon Hash → Shodan** — Calculate MurmurHash3 of favicon and search in Shodan.
  ```python
  import mmh3, requests, codecs
  response = requests.get('https://example.com/favicon.ico')
  favicon = codecs.encode(response.content, 'base64')
  hash = mmh3.hash(favicon)
  # Shodan query: http.favicon.hash:{hash}
  ```
- **Host Header Fuzzing** — Discover virtual hosts.
  ```bash
  ffuf -w subdomains.txt -u "https://TARGET_IP" -H "Host: FUZZ.example.com" \
    -H "User-Agent: Mozilla/5.0" -mc 200,301,302,403 -o vhost_results.json
  ```
- **PTR Records** — Reverse DNS on all discovered IPs.
  ```bash
  cat ips.txt | xargs -I{} dig +short -x {}
  ```
- **Port 80/443/8080/8443 Scan** — Discover hidden web services on non-standard ports.
- **SSL/TLS SAN Fields** — Extract Subject Alternative Names from certificates on all discovered IPs.
  ```bash
  cat ips.txt | while read ip; do echo | openssl s_client -connect $ip:443 2>/dev/null | openssl x509 -noout -text | grep DNS: | tr ',' '\n' | sed 's/.*DNS://g'; done | sort -u
  ```
- [Altdns](https://github.com/infosec-au/altdns) — Permutation generation from discovered subs.
- [Dnsprobe](https://github.com/projectdiscovery/dnsprobe) — Bulk DNS resolution and validation.

#### Subdomain Resolution & Filtering
```bash
# Resolve and filter live subdomains
cat all_subs.txt | sort -u | httpx -silent -status-code -title -tech-detect -o live_subs.txt

# Extract only live HTTP/HTTPS hosts
cat live_subs.txt | grep -E "^\[200\]|^\[301\]|^\[302\]" | awk '{print $2}' > alive_hosts.txt
```

---

### DNS Bruteforce & Permutation

> Static bruteforce surfaces what passive sources miss. Permutation is non-negotiable — *DO NOT SKIP*.

- [PureDNS](https://github.com/d3mondev/puredns) — High-performance DNS bruteforce with wildcard filtering.
  ```bash
  # Static bruteforce
  puredns bruteforce wordlists/all.txt example.com -r resolvers.txt -o puredns_results.txt

  # Resolve a list
  puredns resolve subs_passive.txt -r resolvers.txt -o resolved.txt
  ```
- [MassDNS](https://github.com/blechschmidt/massdns) — Ultra-fast DNS resolver for bulk lookups.
  ```bash
  massdns -r resolvers.txt -t A -o S -w massdns_out.txt subdomains.txt
  ```
- [Gotator](https://github.com/Josue87/gotator) + [DNSGen](https://github.com/AlephNullSK/dnsgen) — Permutation from resolved subdomains.
  ```bash
  # Gotator permutation
  gotator -sub resolved.txt -perm permutations.txt -depth 1 -numbers 3 -mindup -adv -md | sort -u > permutations_out.txt

  # DNSGen permutation
  cat resolved.txt | dnsgen - | massdns -r resolvers.txt -t A -o S -w massdns_perms.txt
  ```
- **Wordlists for DNS Bruteforce:**
  - [all.txt by JHaddix](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056) — ~84k entries
  - [Assetnote Wordlists](https://wordlists.assetnote.io/) — Best-in-class, algorithm-generated
  - [SecLists/Discovery/DNS](https://github.com/danielmiessler/SecLists/tree/master/Discovery/DNS)

---

### Subdomain Takeover

> Dead DNS records pointing to deprovisioned cloud resources = easy wins.

- [Nuclei](https://github.com/projectdiscovery/nuclei) with takeover templates:
  ```bash
  nuclei -l resolved.txt -t nuclei-templates/takeovers/ -o takeover_results.txt
  ```
- [Subzy](https://github.com/LukaSikic/subzy) — Automated takeover checker.
  ```bash
  subzy run --targets resolved.txt --concurrency 50 --hide_fails
  ```
- [SubOver](https://github.com/Ice3man543/SubOver) — Robust takeover detection.
- [Can-I-Take-Over-XYZ](https://github.com/EdOverflow/can-i-take-over-xyz) — Reference for fingerprints.
- [TakeOver](https://github.com/m4ll0k/takeover) — Additional fingerprint coverage.
- **Manual Verification** — Always manually verify CNAME chains before claiming a takeover.
  ```bash
  dig CNAME subdomain.example.com +short
  # If pointing to *.amazonaws.com, *.azurewebsites.net, *.github.io, etc. — check if claimed
  ```

---

### IP Space & ASN Discovery

> Map the entire network footprint, not just what's in DNS.

- [ASNLookup](https://github.com/yassineaboukir/Asnlookup) — Find all ASNs for an org.
  ```bash
  python3 asnlookup.py -o "Target Corporation"
  ```
- [Amass](https://github.com/OWASP/Amass) — ASN + CIDR enumeration.
  ```bash
  amass intel -org "Target Corporation" -asn
  ```
- [BGPView](https://bgpview.io/) — BGP ASN → CIDR mapping.
- [Hurricane Electric BGP Toolkit](https://bgp.he.net/) — Comprehensive ASN data.
- [ARIN](https://search.arin.net/) / [RIPE](https://apps.db.ripe.net/) / [APNIC](https://www.apnic.net/) — Regional IP registries.
- [ipinfo.io](https://ipinfo.io/) API:
  ```bash
  curl -s "https://ipinfo.io/AS{ASN_NUMBER}" | jq '.prefixes[].prefix'
  ```
- [Metabigor](https://github.com/j3ssie/metabigor) — OSINT & network intelligence tool.
  ```bash
  echo "Target Corp" | metabigor net --org -o cidrs.txt
  ```

---

### Port Scanning & Service Discovery

> Cast a wide net first (Masscan), then do deep dives (Nmap) on interesting hosts.

- [Masscan](https://github.com/robertdavidgraham/masscan) — Full port sweep at scale.
  ```bash
  masscan -p0-65535 --rate 50000 -iL cidrs.txt -oG masscan_all_ports.txt
  ```
- [Nmap](https://nmap.org/) — Service/version detection on Masscan results.
  ```bash
  # Extract live IPs from Masscan
  grep "Host:" masscan_all_ports.txt | awk '{print $2}' | sort -u > live_ips.txt

  # Deep scan interesting IPs
  nmap -sV -sC -O -T4 -iL live_ips.txt -oA nmap_deep
  ```
- [RustScan](https://github.com/RustScan/RustScan) — Extremely fast port scanner, feeds into Nmap.
  ```bash
  rustscan -a live_ips.txt --range 1-65535 -- -sV -sC
  ```
- [Naabu](https://github.com/projectdiscovery/naabu) — Fast port scanner from ProjectDiscovery.
  ```bash
  naabu -list live_ips.txt -top-ports 1000 -o naabu_results.txt
  ```
- [httpx](https://github.com/projectdiscovery/httpx) — Web service discovery on port scan results.
  ```bash
  cat live_ips.txt | naabu -silent | httpx -silent -title -status-code -tech-detect
  ```
- **Key Ports to Always Check:** 21, 22, 23, 25, 80, 110, 143, 389, 443, 445, 587, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9200, 27017

---

## Asset Discovery

### Corporate Intelligence

> The best vulnerabilities often live on forgotten assets. OSINT your target's entire business graph.

- **Company Structure Mapping:**
  - [Crunchbase](https://www.crunchbase.com/) — Subsidiaries, acquisitions, funding history.
  - [PitchBook](https://pitchbook.com/) — M&A activity.
  - [ZoomInfo](https://www.zoominfo.com/) — Corporate structure.
  - [SEC EDGAR](https://www.sec.gov/edgar/search/) — Public company filings. Search 10-K for subsidiary lists.
  - [LinkedIn](https://linkedin.com/) — Org structure, employee tech stack mentions.
  - [OpenCorporates](https://opencorporates.com/) — Global corporate registry.

- **Google Dorks for Asset Discovery:**
  ```
  "acquired by example" site:techcrunch.com OR site:reuters.com
  "© 2024 ExampleCorp. All Rights Reserved." -site:example.com
  inurl:example.com filetype:pdf "confidential"
  site:example.com ext:conf OR ext:config OR ext:env
  site:example.com inurl:"/api/" OR inurl:"/v1/" OR inurl:"/v2/"
  ```
- [GHDB](https://www.exploit-db.com/google-hacking-database) — Google Hacking Database for dork patterns.
- [OSINT Framework](https://osintframework.com/) — Comprehensive OSINT resource tree.

- **Email → Reverse Lookup:**
  - [Hunter.io](https://hunter.io/) — Domain email enumeration.
  - [Clearbit Connect](https://connect.clearbit.com/) — Email to person/company mapping.
  - [TheHarvester](https://github.com/laramies/theHarvester):
    ```bash
    theHarvester -d example.com -b all -l 500 -f harvest_results
    ```

- **Mail Server Recon:**
  - [SecurityTrails](https://securitytrails.com/) — Historical DNS, MX records.
  - [MXToolbox](https://mxtoolbox.com/) — MX, SPF, DMARC analysis.
  - [DMARC Live](https://dmarc.live/info/example.com) — Find related domains via DMARC org domain.

- **Search Engine Intelligence:**
  - Google, Bing, Yandex, [Searx](https://searx.github.io/searx/) — Each indexes different content.
  - [Baidu](https://www.baidu.com/) — For targets with Asia presence.

---

### Cloud Asset Discovery

> Cloud misconfigurations are consistently in the top 5 bug classes by volume.

- **AWS:**
  - [S3Scanner](https://github.com/sa7mon/S3Scanner) — Enumerate and scan S3 buckets.
    ```bash
    s3scanner scan --bucket-file potential_buckets.txt
    ```
  - [AWSBucketDump](https://github.com/jordanpotti/AWSBucketDump) — Enumerate S3 with file download.
  - [DumpsterDiver](https://github.com/securing/DumpsterDiver) — Scan for secrets in S3 content.
  - [Pacu](https://github.com/RhinoSecurityLabs/pacu) — AWS exploitation framework.
  - [CloudMapper](https://github.com/duo-labs/cloudmapper) — Visualize AWS environment.
  - **Naming Patterns:** `company-assets`, `company-backup`, `company-dev`, `company-prod`, `company-logs`

- **GCP:**
  - [GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute) — Enumerate GCS buckets.
  - [GCP-IAM-Privilege-Escalation](https://github.com/RhinoSecurityLabs/GCP-IAM-Privilege-Escalation)

- **Azure:**
  - [MicroBurst](https://github.com/NetSPI/MicroBurst) — Azure recon and enumeration.
  - [BlobHunter](https://github.com/cyberark/BlobHunter) — Azure Blob Storage scanner.
  - [AADInternals](https://github.com/Gerenios/AADInternals) — Azure AD reconnaissance.

- **Multi-Cloud:**
  - [CloudBrute](https://github.com/0xsha/CloudBrute) — Multi-cloud storage bruteforcing.
  - [ScoutSuite](https://github.com/nccgroup/ScoutSuite) — Multi-cloud security auditing.
  - [Prowler](https://github.com/prowler-cloud/prowler) — AWS/Azure/GCP security assessment.

- **Cloud IP Range Lists** — Cross-reference IPs against cloud provider ranges:
  - [AWS IP Ranges](https://ip-ranges.amazonaws.com/ip-ranges.json)
  - [Azure IP Ranges](https://www.microsoft.com/en-us/download/details.aspx?id=56519)
  - [GCP IP Ranges](https://www.gstatic.com/ipranges/cloud.json)

---

### GitHub & Code Recon

> Source code leaks are one of the highest-yield recon activities. Automate this early and run it continuously.

- [TruffleHog](https://github.com/trufflesecurity/trufflehog) — High-signal secret detection across git history.
  ```bash
  trufflehog github --org=TargetOrg --only-verified
  trufflehog git https://github.com/TargetOrg/repo --json
  ```
- [GitRob](https://github.com/michenriksen/gitrob) — Scan GitHub orgs for sensitive files.
- [GitHub-Dorks](https://github.com/techgaun/github-dorks) — Dork patterns for GitHub search.
  ```
  org:TargetOrg password
  org:TargetOrg secret
  org:TargetOrg api_key
  org:TargetOrg "BEGIN RSA PRIVATE KEY"
  org:TargetOrg internal
  org:TargetOrg staging
  org:TargetOrg .env
  org:TargetOrg "aws_access_key"
  org:TargetOrg filename:.npmrc _authToken
  org:TargetOrg filename:wp-config.php
  ```
- [Gitleaks](https://github.com/gitleaks/gitleaks) — Fast secret detection.
  ```bash
  gitleaks detect --source . --report-format json --report-path leaks.json
  ```
- [git-dumper](https://github.com/arthaud/git-dumper) — Dump exposed `.git` directories.
  ```bash
  git-dumper https://example.com/.git/ ./dumped_repo
  ```
- [GitHound](https://github.com/tillson/git-hound) — Regex-based secret scanning.
- [Sourcegraph](https://sourcegraph.com/) — Search across millions of public repositories.
- **Check for exposed `.git` directory:**
  ```bash
  curl -s https://example.com/.git/HEAD | grep -i "ref:"
  ```

---

### Certificate Transparency

- [crt.sh](https://crt.sh/) — The primary CT log aggregator.
- [CertStream](https://certstream.calidog.io/) — Real-time certificate issuance feed. Excellent for monitoring.
  ```python
  import certstream

  def callback(message, context):
      if message['message_type'] == "certificate_update":
          for domain in message['data']['leaf_cert']['all_domains']:
              if "example.com" in domain:
                  print(domain)

  certstream.listen_for_events(callback)
  ```
- [Cert Spotter](https://sslmate.com/certspotter/) — API-based CT monitoring.
- [Facebook CT](https://developers.facebook.com/tools/ct/) — Facebook's certificate transparency tool.

---

## Content Discovery

### Directory & File Fuzzing

> Wordlist quality and recursive fuzzing are what separate average from excellent content discovery.

- [FeroxBuster](https://github.com/epi052/feroxbuster) — Recursive, fast, Rust-based. Best overall.
  ```bash
  feroxbuster -u https://example.com -w wordlists/raft-large-directories.txt \
    -x php,asp,aspx,jsp,html,txt,json,bak,sql,config \
    --auto-tune --smart-filter -o ferox_results.txt
  ```
- [FFuF](https://github.com/ffuf/ffuf) — Swiss army fuzzer. Excellent for custom fuzzing scenarios.
  ```bash
  # Directory fuzzing
  ffuf -u https://example.com/FUZZ -w wordlists/raft-large-directories.txt \
    -mc 200,301,302,403 -o ffuf_dirs.json -of json

  # Extension fuzzing
  ffuf -u https://example.com/indexFUZZ -w extensions.txt -mc 200

  # Virtual host fuzzing
  ffuf -u https://example.com -H "Host: FUZZ.example.com" -w subdomains.txt -mc 200
  ```
- [GoBuster](https://github.com/OJ/gobuster) — Versatile dir/DNS/vhost busting.
  ```bash
  gobuster dir -u https://example.com -w wordlists/common.txt -x php,html,bak
  gobuster dns -d example.com -w wordlists/subdomains.txt
  ```
- [DirSearch](https://github.com/evilsocket/dirsearch) — Web path scanner.
  ```bash
  dirsearch -u https://example.com -e php,html,bak,js,json -x 404
  ```
- [Katana](https://github.com/projectdiscovery/katana) — Active crawler for endpoints, forms, JS links.
  ```bash
  katana -u https://example.com -depth 5 -js-crawl -passive -o katana_results.txt
  ```
- **Backup & Sensitive File Extensions to Always Fuzz:**
  `.bak`, `.old`, `.tmp`, `.swp`, `.1`, `.orig`, `.save`, `.sql`, `.dump`, `.log`, `.cfg`, `.conf`, `.env`, `.pem`, `.key`, `.xml`, `.yaml`, `.yml`, `.json`, `.tar.gz`, `.zip`

---

### Historical Content Analysis

- [Wayback Machine](https://archive.org/web/) — Snapshot browsing for deleted content.
- [Waybackurls](https://github.com/tomnomnom/waybackurls) — Extract all Wayback URLs.
  ```bash
  waybackurls example.com | tee wayback_all.txt
  cat wayback_all.txt | grep -E "\.js$" > wayback_js.txt
  cat wayback_all.txt | grep -E "api|v1|v2|v3|admin|upload" > interesting_paths.txt
  ```
- [GAU (Get All URLs)](https://github.com/lc/gau) — Aggregates Wayback + Common Crawl + OTX + URLScan.
  ```bash
  gau --subs --threads 5 example.com | tee gau_all.txt
  ```
- [CommonCrawl](https://commoncrawl.org/) — Petabyte-scale web crawl data.
- [URLScan.io](https://urlscan.io/) — Search previously scanned URLs for a domain.
  ```bash
  curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1000" | jq -r '.results[].page.url'
  ```
- [OTX AlienVault](https://otx.alienvault.com/) — Threat intel + URL history.
  ```bash
  curl -s "https://otx.alienvault.com/api/v1/indicators/domain/example.com/url_list?limit=500" | jq -r '.url_list[].url'
  ```

---

### API & GraphQL Discovery

> APIs are the highest-density attack surface. Document everything.

- [Kiterunner](https://github.com/assetnote/kiterunner) — API route discovery with real-world wordlists.
  ```bash
  kr scan https://api.example.com -w wordlists/routes-large.kite -o api_results.txt
  kr brute https://api.example.com -w wordlists/api_routes.txt
  ```
- [Arjun](https://github.com/s0md3v/Arjun) — Hidden HTTP parameter discovery.
  ```bash
  arjun -u https://api.example.com/endpoint -m GET,POST
  ```
- **API Discovery via Swagger/OpenAPI:**
  ```
  /swagger.json
  /swagger/v1/swagger.json
  /api-docs
  /openapi.json
  /v1/api-docs
  /.well-known/openapi
  /api/swagger-ui.html
  ```
- [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap) — GraphQL endpoint exploitation and recon.
  ```bash
  python3 graphqlmap.py -u https://example.com/graphql --introspection
  ```
- [InQL](https://github.com/doyensec/inql) — Burp Suite extension for GraphQL analysis.
- [Clairvoyance](https://github.com/nikitastupin/clairvoyance) — Recover GraphQL schema even when introspection is disabled.
- **Common GraphQL Endpoints:**
  ```
  /graphql
  /api/graphql
  /v1/graphql
  /graphiql
  /playground
  ```
- [Postman](https://www.postman.com/) — Check public Postman workspaces for API documentation leaks.
  ```bash
  # Search Postman for target APIs
  # https://www.postman.com/search?q=example.com
  ```
- [APICheck](https://github.com/BBVA/apicheck) — API security testing toolkit.

---

### JavaScript Analysis

> Frontend JS is a treasure trove: API keys, endpoints, auth logic, internal paths.

- [Linkfinder](https://github.com/GerbenJavado/LinkFinder) — Extract endpoints from JS files.
  ```bash
  python3 linkfinder.py -i https://example.com -d -o linkfinder_results.html
  # Process all JS files
  cat wayback_js.txt | xargs -I{} python3 linkfinder.py -i {} -o cli
  ```
- [SecretFinder](https://github.com/m4ll0k/SecretFinder) — Find secrets (keys, tokens) in JS.
  ```bash
  python3 SecretFinder.py -i https://example.com/app.js -o cli
  ```
- [JSParser](https://github.com/nahamsec/JSParser) — Parse JS for URLs/paths.
- [JSScanner](https://github.com/0x240x23elu/JSScanner) — Multi-file JS scanner.
- [Retire.js](https://github.com/RetireJS/retire.js) — Detect vulnerable JS libraries.
- [Subjs](https://github.com/lc/subjs) — Fetch JS files for a domain list.
  ```bash
  cat alive_hosts.txt | subjs | tee all_js_files.txt
  ```
- [Relative-URL-Extractor](https://github.com/jobertabma/relative-url-extractor) — Extract relative paths from minified JS.
- [Webpack Exploit](https://github.com/lzghzr/webpack-explode) — Reconstruct Webpack bundles.
- **Manual Analysis Patterns:**
  ```
  Look for: fetch("/api/", "Authorization: Bearer", "apiKey", "secret", "password", "token"
  Internal hosts: localhost, staging, dev, internal, corp, vpn
  S3 bucket URLs, hardcoded credentials, OAuth client IDs
  ```

---

## Technology Fingerprinting

> Knowing the exact stack lets you narrow your attack hypotheses immediately.

- [Wappalyzer](https://www.wappalyzer.com/) — Browser extension + CLI for tech stack detection.
- [WhatWeb](https://github.com/urbanadventurer/whatweb) — Deep technology fingerprinting.
  ```bash
  whatweb -a 3 https://example.com -v
  cat alive_hosts.txt | whatweb --input-file=- --log-json=whatweb_results.json
  ```
- [httpx](https://github.com/projectdiscovery/httpx) — Fast HTTP toolkit with tech-detect.
  ```bash
  httpx -l alive_hosts.txt -tech-detect -title -status-code -server -content-type \
    -web-server -o httpx_fingerprint.txt
  ```
- [Nuclei](https://github.com/projectdiscovery/nuclei) with tech-detect templates:
  ```bash
  nuclei -l alive_hosts.txt -t nuclei-templates/technologies/ -o tech_fingerprint.txt
  ```
- [Wafw00f](https://github.com/EnableSecurity/wafw00f) — WAF detection.
  ```bash
  wafw00f -a https://example.com -o waf_results.txt
  ```
- [Aquatone](https://github.com/michenriksen/aquatone) — Visual screenshot + fingerprint.
  ```bash
  cat alive_hosts.txt | aquatone -out screenshots/
  ```
- [Eyewitness](https://github.com/FortyNorthSecurity/EyeWitness) — Web screenshot taker with report.

#### CMS-Specific
| CMS | Tool | Command |
|-----|------|---------|
| WordPress | [WPScan](https://github.com/wpscanteam/wpscan) | `wpscan --url https://example.com --enumerate u,p,t,tt --api-token TOKEN` |
| Joomla | [JoomScan](https://github.com/OWASP/joomscan) | `joomscan -u https://example.com` |
| Drupal | [Droopescan](https://github.com/droope/droopescan) | `droopescan scan drupal -u https://example.com` |
| Magento | [Magescan](https://github.com/steverobbins/magescan) | `magescan.phar scan:all https://example.com` |
| SharePoint | [sparty](https://github.com/0xdevalias/sparty) | Manual + Nuclei templates |
| Laravel | [Enlightn](https://github.com/enlightn/enlightn) | Static analysis |

#### Header Analysis
```bash
# Analyze security headers
curl -sI https://example.com | grep -iE "server|x-powered-by|x-frame|x-xss|strict|content-security|x-content"

# Check for information disclosure
curl -sIk https://example.com | grep -i "server:\|x-powered-by:\|x-aspnet\|x-generator"
```

---

## Parameter Analysis

> Parameters are injection points. Find them all — GET, POST, JSON, cookies, headers.

- [Arjun](https://github.com/s0md3v/Arjun) — HTTP parameter discovery.
  ```bash
  arjun -u https://example.com/endpoint -m GET,POST,JSON,XML
  arjun -i alive_hosts.txt -oJ arjun_results.json
  ```
- [ParamSpider](https://github.com/devanshbatham/ParamSpider) — Mine parameters from Wayback.
  ```bash
  python3 paramspider.py -d example.com --level high -o params.txt
  ```
- [X8](https://github.com/jakobdoerr/x8) — Hidden parameter discovery suite.
  ```bash
  x8 -u "https://example.com/api/endpoint" -w wordlists/params.txt
  ```
- [Parameth](https://github.com/maK-/parameth) — GET/POST parameter bruteforcing.
- [GF](https://github.com/tomnomnom/gf) — Pattern grep wrapper for finding injection candidates.
  ```bash
  # Find potential XSS parameters
  cat wayback_all.txt | gf xss | tee xss_candidates.txt

  # Find potential SQLi parameters
  cat wayback_all.txt | gf sqli | tee sqli_candidates.txt

  # Find SSRF parameters
  cat wayback_all.txt | gf ssrf | tee ssrf_candidates.txt

  # Redirect parameters
  cat wayback_all.txt | gf redirect | tee redirect_candidates.txt
  ```
- [GF-Patterns](https://github.com/1ndianl33t/Gf-Patterns) — Extended pattern collection.
- [Param-Miner](https://github.com/PortSwigger/param-miner) — Burp extension for web cache poisoning parameter discovery.
- **Parameter Pollution:**
  ```
  ?param=value&param=value2        # HTTP Parameter Pollution
  ?param[]=value1&param[]=value2   # PHP array notation
  ?param%5B%5D=value               # Encoded array notation
  ```
- **URL Pattern Mining Pipeline:**
  ```bash
  cat gau_all.txt wayback_all.txt | sort -u | \
    grep -E "\?" | \
    uro | \
    gf xss > xss_params.txt
  ```
- [Uro](https://github.com/s0md3v/uro) — Deduplicate URL lists intelligently.

---

## Authentication Analysis

> Auth bugs are consistently critical/high severity. This is always worth deep investigation.

- [JWT_Tool](https://github.com/ticarpi/jwt_tool) — Comprehensive JWT testing suite.
  ```bash
  # Scan for JWT vulnerabilities
  python3 jwt_tool.py TOKEN -t https://example.com/api/endpoint

  # Test for none algorithm attack
  python3 jwt_tool.py TOKEN -X a

  # Test for RS256 to HS256 confusion
  python3 jwt_tool.py TOKEN -X k -pk public.pem
  ```
- [JWT-Cracker](https://github.com/lmammino/jwt-cracker) — HS256 JWT secret brute force.
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) — Multi-protocol credential bruteforcing.
  ```bash
  hydra -L users.txt -P passwords.txt example.com http-post-form "/login:user=^USER^&pass=^PASS^:F=Invalid"
  ```
- [Burp Suite Intruder](https://portswigger.net/burp) — Credential stuffing, password spray.
- [Autorepeater](https://github.com/nccgroup/autorepeater) — Automated privilege escalation testing.
- [OAuth 2.0 Testing](https://oauth.tools/) — OAuth flow analysis and testing.

#### OAuth-Specific Checklist
- [ ] State parameter present and validated?
- [ ] Redirect URI restricted/validated?
- [ ] PKCE implemented for public clients?
- [ ] Token leakage in Referer header?
- [ ] Account linking CSRF possible?
- [ ] Implicit flow in use (deprecated, insecure)?
- [ ] Token scope overly permissive?

#### Session Analysis Checklist
- [ ] Session token entropy (should be ≥128 bits)
- [ ] HTTPOnly and Secure flags on session cookies
- [ ] SameSite cookie attribute (Strict/Lax)
- [ ] Session fixation vulnerability
- [ ] Session invalidation on logout
- [ ] Concurrent session handling

#### Password Reset Flow Analysis
- [ ] Token expiry enforced?
- [ ] Token single-use enforced?
- [ ] Token entropy sufficient?
- [ ] Host header injection in reset emails?
- [ ] Username enumeration via timing/response differences?

---

## Network & Protocol Analysis

> Relevant especially for programs with network-accessible infrastructure in scope.

- [Nmap NSE Scripts](https://nmap.org/nsedoc/) — Thousands of specialized scripts.
  ```bash
  # SMB enumeration
  nmap -p 445 --script smb-enum-shares,smb-enum-users,smb-os-discovery target

  # SSL/TLS analysis
  nmap -p 443 --script ssl-enum-ciphers,ssl-cert target

  # DNS zone transfer
  nmap -p 53 --script dns-zone-transfer --script-args dns-zone-transfer.domain=example.com target
  ```
- [SSLyze](https://github.com/nabla-c0d3/sslyze) — TLS configuration analysis.
  ```bash
  sslyze --regular example.com
  ```
- [TestSSL](https://github.com/drwetter/testssl.sh) — Comprehensive TLS/SSL testing.
  ```bash
  ./testssl.sh --parallel https://example.com
  ```
- [DNSRecon](https://github.com/darkoperator/dnsrecon) — DNS enumeration and zone transfer testing.
  ```bash
  dnsrecon -d example.com -t axfr  # Zone transfer
  dnsrecon -d example.com -t std   # Standard enum
  dnsrecon -d example.com -t brt -D wordlist.txt  # Bruteforce
  ```
- [Fierce](https://github.com/mschwager/fierce) — DNS reconnaissance and subdomain fuzzer.
- **Zone Transfer Test:**
  ```bash
  dig axfr @ns1.example.com example.com
  ```
- **SMTP Reconnaissance:**
  ```bash
  nmap -p 25 --script smtp-enum-users,smtp-commands target
  ```
- **SNMP Enumeration:**
  ```bash
  snmpwalk -c public -v1 target.ip
  onesixtyone -c community_strings.txt target.ip
  ```

---

## OSINT & Passive Recon

> Intelligence without touching the target. Zero noise, zero attribution.

### People & Identity Intelligence
- [LinkedIn](https://linkedin.com/) — Employee enumeration, technology stack (job postings!), org chart.
- [Hunter.io](https://hunter.io/) — Email format discovery and employee email generation.
- [Phonebook.cz](https://phonebook.cz/) — Email, domain, and URL intelligence.
- [IntelX](https://intelx.io/) — Dark web, paste sites, breached credential search.
- [HaveIBeenPwned API](https://haveibeenpwned.com/API/v3) — Check breach exposure for target emails.

### Threat Intelligence Platforms
- [Shodan](https://www.shodan.io/) — Internet-connected device search. Master dork reference:
  ```
  org:"Target Corporation" port:22
  ssl.cert.subject.cn:"*.example.com" 200
  http.title:"Target Dashboard" 200
  ```
- [Censys](https://search.censys.io/) — Certificate and host data.
- [FOFA](https://fofa.info/) — Chinese internet intelligence platform.
- [GreyNoise](https://www.greynoise.io/) — Classify IPs as internet scanners vs. targeted activity.
- [Shodan Dork Collection](https://github.com/lothos612/shodan)
- [VirusTotal](https://www.virustotal.com/) — Domain/IP/URL intelligence.
  ```bash
  curl "https://www.virustotal.com/api/v3/domains/example.com/subdomains" \
    -H "x-apikey: YOUR_KEY" | jq -r '.data[].id'
  ```
- [URLScan.io](https://urlscan.io/) — Passive browsing history, DOM analysis.
- [SecurityTrails](https://securitytrails.com/) — Historical DNS, IP history, WHOIS.
- [PassiveTotal/RiskIQ](https://community.riskiq.com/) — Passive DNS, certificate intel.

### Paste & Leak Sites
- [Pastebin](https://pastebin.com/) — `site:pastebin.com "example.com" password`
- [IntelX](https://intelx.io/) — Indexed paste sites and dark web leaks.
- [Psbdmp](https://psbdmp.ws/) — Pastebin dump search.
- [GhostProject](https://ghostproject.fr/) — Email breach search.

### DNS History & WHOIS
```bash
# WHOIS history
curl "https://api.securitytrails.com/v1/domain/example.com/whois/history" \
  -H "APIKEY: YOUR_KEY"

# Historical DNS
curl "https://api.securitytrails.com/v1/domain/example.com/dns/history/a" \
  -H "APIKEY: YOUR_KEY"
```

---

## Mobile Application Recon

> Mobile apps are in-scope on most programs and are often undertested.

### Static Analysis (iOS)
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — Automated mobile security framework.
- [iPatching](https://github.com/Siguza/ipatching) — iOS binary patching.
- **Extract IPA:** AppStore tools or `ideviceinstaller`.
- Examine `Info.plist` for API keys, URL schemes, permissions.

### Static Analysis (Android)
- [MobSF](https://github.com/MobSF/Mobile-Security-Framework-MobSF) — APK static analysis.
  ```bash
  docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf
  ```
- [APKTool](https://github.com/iBotPeaches/Apktool) — Decompile APK.
  ```bash
  apktool d target.apk -o decompiled/
  ```
- [Jadx](https://github.com/skylot/jadx) — Decompile to readable Java.
- [Dex2jar](https://github.com/pxb1988/dex2jar) — Convert DEX to JAR.
- **Extract Secrets from APK:**
  ```bash
  # Search for hardcoded secrets
  grep -r "api_key\|apikey\|secret\|password\|token\|auth" decompiled/ --include="*.java" --include="*.xml"

  # Find URLs and endpoints
  grep -r "http\|https" decompiled/ --include="*.java" | grep -v "www.w3.org\|schema\|xmlns"
  ```
- **Check `AndroidManifest.xml`** for exported activities, intent filters, permissions.

### Dynamic Analysis
- [Frida](https://frida.re/) — Dynamic instrumentation toolkit. Hook methods at runtime.
  ```bash
  frida -U -l ssl_bypass.js -f com.target.app --no-pause
  ```
- [Objection](https://github.com/sensepost/objection) — Runtime mobile exploration (wraps Frida).
  ```bash
  objection -g com.target.app explore
  # Bypass SSL pinning
  ios sslpinning disable
  android sslpinning disable
  ```
- [BurpSuite + Proxy** — Intercept mobile traffic via proxy config.
- [mitmproxy](https://mitmproxy.org/) — Open source MITM proxy.
- [Charles Proxy](https://www.charlesproxy.com/) — HTTP debugging proxy for mobile.

---

## Cloud-Specific Recon

### AWS Specific
```bash
# Check for public S3 buckets
for bucket in $(cat potential_buckets.txt); do
  aws s3 ls s3://$bucket --no-sign-request 2>/dev/null && echo "[OPEN] $bucket"
done

# Enumerate via boto3 (if creds found)
python3 -c "import boto3; sts=boto3.client('sts'); print(sts.get_caller_identity())"
```

- **AWS Metadata Endpoint (SSRF target):** `http://169.254.169.254/latest/meta-data/`
- **IMDSv2 (newer, requires PUT first):**
  ```bash
  TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ -H "X-aws-ec2-metadata-token: $TOKEN"
  ```

### GCP Specific
- **GCP Metadata:** `http://metadata.google.internal/computeMetadata/v1/`
- Check for GCS bucket misconfigurations via `gsutil ls gs://bucket-name`.

### Azure Specific
- **Azure Metadata:** `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- Check for exposed Azure Blob Storage: `https://account.blob.core.windows.net/container/?restype=container&comp=list`

---

## Vulnerability Scanning

> Nuclei is the single most important tool here. Keep templates updated daily.

- [Nuclei](https://github.com/projectdiscovery/nuclei) — Fast, template-based vulnerability scanning.
  ```bash
  # Update templates
  nuclei -update-templates

  # Full scan pipeline
  nuclei -l alive_hosts.txt \
    -t nuclei-templates/ \
    -es info \
    -severity low,medium,high,critical \
    -o nuclei_results.txt \
    -stats

  # Specific vulnerability classes
  nuclei -l alive_hosts.txt -t nuclei-templates/cves/ -o cve_results.txt
  nuclei -l alive_hosts.txt -t nuclei-templates/exposures/ -o exposure_results.txt
  nuclei -l alive_hosts.txt -t nuclei-templates/misconfiguration/ -o misconfig_results.txt

  # New templates only (daily run)
  nuclei -l alive_hosts.txt -t nuclei-templates/ -nt -o new_template_hits.txt
  ```
- [Nikto](https://github.com/sullo/nikto) — Web server scanner.
  ```bash
  nikto -h https://example.com -ssl -Format htm -output nikto_report.html
  ```
- [Jaeles](https://github.com/jaeles-project/jaeles) — Web application testing framework.
- [Dalfox](https://github.com/hahwul/dalfox) — XSS scanner.
  ```bash
  cat xss_candidates.txt | dalfox pipe --skip-bav -o xss_results.txt
  ```
- [SQLMAP](https://github.com/sqlmapproject/sqlmap) — SQL injection detection and exploitation.
  ```bash
  sqlmap -l burp_requests.txt --batch --level=3 --risk=2 --dbs
  ```
- [SSRFire](https://github.com/ksharinarayanan/SSRFire) — Automated SSRF detection.
- [OpenRedirector](https://github.com/devanshbatham/OpenRedireX) — Open redirect scanner.
- [CORSTest](https://github.com/RUB-NDS/CORStest) — CORS misconfiguration scanner.
  ```bash
  python3 corstest.py -p 50 alive_hosts.txt
  ```
- [405scanner](https://github.com/dashYe/405scanner) — HTTP method enumeration.

---

## Monitoring & Continuous Recon

> The best bugs come from watching for changes — new assets, new endpoints, new vulnerabilities.

- [ReconFTW](https://github.com/six2dez/reconftw) — Full automated recon pipeline.
  ```bash
  ./reconftw.sh -d example.com -a -o output/
  ```
- [Sublert](https://github.com/yassineaboukir/sublert) — Monitor CT logs for new subdomains.
- [CertStream](https://certstream.calidog.io/) — Real-time new certificate monitoring.
- [Notify](https://github.com/projectdiscovery/notify) — Stream tool outputs to Slack/Discord/Telegram.
  ```bash
  nuclei -l new_assets.txt -t nuclei-templates/ | notify -id slack_bbh
  ```
- [Findomain](https://findomain.app/) — Has built-in monitoring mode.
  ```bash
  findomain -t example.com --monitoring --postgres-database bbh
  ```
- [Recon-Pipeline](https://github.com/epi052/recon-pipeline) — Luigi-based automated recon pipeline.
- [GitHub-Monitor](https://github.com/CNCF/gitjacker) — Monitor GitHub repositories for secrets.
- [SecurityHeader.com](https://securityheaders.com/) — Monitor header regressions.
- [Shodan Monitor](https://monitor.shodan.io/) — Alert on new IPs for your org's ASN.
- **Cron-based differential monitoring:**
  ```bash
  # Run daily, diff against previous results
  subfinder -d example.com -silent -o /tmp/subs_today.txt
  diff /data/subs_yesterday.txt /tmp/subs_today.txt | grep "^>" | awk '{print $2}' > /data/new_subs.txt
  cat /data/new_subs.txt | notify -id discord
  mv /tmp/subs_today.txt /data/subs_yesterday.txt
  ```

---

## Automation Frameworks

> Pipeline everything. Manual recon doesn't scale.

- [ReconFTW](https://github.com/six2dez/reconftw) — The most feature-complete all-in-one framework.
- [BBot](https://github.com/blacklanternsecurity/bbot) — Modular, extensible, Pythonic.
- [Axiom](https://github.com/pry0cc/axiom) — Distributed scanning framework for cloud fleet deployments.
  ```bash
  # Spin up 10 instances and distribute scanning
  axiom-scan subs.txt -m httpx -o httpx_results.txt --fleet 10
  ```
- [Osmedeus](https://github.com/j3ssie/osmedeus) — Workflow-based offensive recon.
- [BBRF](https://github.com/honoki/bbrf-client) — Bug Bounty Recon Framework — centralized asset management.
- [Chaos](https://chaos.projectdiscovery.io/) — ProjectDiscovery's recon data API.
  ```bash
  chaos -key YOUR_KEY -d example.com -silent | httpx -silent -o live.txt
  ```
- [Recon-ng](https://github.com/lanmaster53/recon-ng) — Full-featured OSINT framework.

---

## Reporting and Documentation

> A bug that isn't documented clearly is a bug that won't be paid. Writing matters.

### Report Structure
1. **Title** — Concise, vuln-class specific. e.g., `Stored XSS in /profile/bio allows account takeover`
2. **Severity** — CVSS score + your justification.
3. **CWE/CVE** — Reference the relevant weakness.
4. **Summary** — 2-3 sentence technical overview.
5. **Impact** — Concrete business impact. What can an attacker actually *do*?
6. **Steps to Reproduce** — Numbered, exact, reproducible. Include full HTTP requests.
7. **Proof of Concept** — Screenshot, video, or code demonstrating the vulnerability.
8. **Suggested Fix** — Show you understand the root cause.
9. **References** — OWASP, CVE, relevant papers.

### Tools
- [Obsidian](https://obsidian.md/) — Linked markdown notes. Best for methodology and target tracking.
- [Notion](https://notion.so/) — Team-friendly structured notes.
- [Burp Suite** — Save all captured requests/responses as evidence.
- [Flameshot](https://github.com/flameshot-org/flameshot) — Screenshot annotation.
- [Asciinema](https://asciinema.org/) — Terminal session recording for PoC.
- [CVSS Calculator](https://www.first.org/cvss/calculator/3.1) — Precise severity scoring.

### Note-Taking Structure (Obsidian Vault)
```
BBH/
├── targets/
│   └── example.com/
│       ├── scope.md
│       ├── assets.md         # All discovered assets
│       ├── endpoints.md      # All interesting endpoints
│       ├── findings/
│       │   ├── finding-001.md
│       │   └── finding-002.md
│       └── notes.md
└── methodology/
    ├── checklists/
    └── one-liners.md
```

---

## Wordlists & Resources

### Must-Have Wordlists
| Purpose | Source |
|---------|--------|
| Subdomain Bruteforce | [Assetnote wordlists](https://wordlists.assetnote.io/) |
| DNS All-in-One | [all.txt by JHaddix](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056) |
| Directory Fuzzing | [SecLists/Discovery/Web-Content](https://github.com/danielmiessler/SecLists) |
| API Routes | [Assetnote routes-large.txt](https://wordlists.assetnote.io/) |
| Parameters | [SecLists/Discovery/Web-Content/burp-parameter-names.txt](https://github.com/danielmiessler/SecLists) |
| Passwords | [SecLists/Passwords](https://github.com/danielmiessler/SecLists) |
| Permutations | [gotator built-ins + custom] |
| DNS Resolvers | [Public Resolvers by Trickest](https://github.com/trickest/resolvers) |

### API Keys to Configure
- Shodan, Censys, SecurityTrails, VirusTotal, GitHub, Hunter.io, Chaos, FOFA, URLScan.io, Subfinder sources config.

### Learning & Reference
- [HackerOne Hacktivity](https://hackerone.com/hacktivity) — Public disclosed reports.
- [Pentester Land](https://pentester.land/list-of-bug-bounty-writeups.html) — Bug bounty writeup aggregator.
- [PortSwigger Web Security Academy](https://portswigger.net/web-security) — Deep-dive vulnerability labs.
- [Bug Bounty Forum](https://bugbountyforum.com/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings) — Payload reference.
- [HackTricks](https://book.hacktricks.xyz/) — Comprehensive pentest reference.
- [NahamSec Recon Playlist](https://www.youtube.com/c/nahamsec)

---

## One-Liner Cheat Sheet

```bash
# =============================================
# FULL RECON PIPELINE (Single Target)
# =============================================

TARGET="example.com"
OUTPUT="output/$TARGET"
mkdir -p $OUTPUT

# 1. Passive subdomain enumeration
subfinder -d $TARGET -all -silent -o $OUTPUT/subs_passive.txt
assetfinder --subs-only $TARGET >> $OUTPUT/subs_passive.txt
gau --subs $TARGET | unfurl -u domains | sort -u >> $OUTPUT/subs_passive.txt
waybackurls $TARGET | unfurl -u domains | sort -u >> $OUTPUT/subs_passive.txt

# 2. Combine and deduplicate
cat $OUTPUT/subs_passive.txt | sort -u > $OUTPUT/subs_all.txt

# 3. DNS bruteforce
puredns bruteforce wordlists/all.txt $TARGET -r resolvers.txt -o $OUTPUT/subs_brute.txt

# 4. Permutation
cat $OUTPUT/subs_all.txt | gotator -perm permutations.txt -depth 1 -numbers 3 | \
  puredns resolve -r resolvers.txt -o $OUTPUT/subs_perms.txt

# 5. Final merge and resolve
cat $OUTPUT/subs_*.txt | sort -u | \
  puredns resolve -r resolvers.txt -o $OUTPUT/resolved.txt

# 6. Find live HTTP(S) services
httpx -l $OUTPUT/resolved.txt -silent -status-code -title -tech-detect \
  -o $OUTPUT/live_http.txt

# 7. Screenshot
cat $OUTPUT/live_http.txt | awk '{print $1}' | aquatone -out $OUTPUT/screenshots/

# 8. Content discovery on all live hosts
feroxbuster --stdin -w wordlists/raft-large-directories.txt \
  -x php,asp,aspx,html,txt,json,bak -o $OUTPUT/ferox_results.txt \
  < <(awk '{print $1}' $OUTPUT/live_http.txt)

# 9. Vulnerability scan
nuclei -l $OUTPUT/resolved.txt -t nuclei-templates/ -es info \
  -o $OUTPUT/nuclei_results.txt -stats

# 10. Port scan
masscan -p0-65535 --rate 10000 -iL $OUTPUT/resolved.txt \
  -oG $OUTPUT/masscan_all.txt

# =============================================
# QUICK WINS ONE-LINERS
# =============================================

# Find all .js files and extract endpoints
cat $OUTPUT/live_http.txt | awk '{print $1}' | subjs | \
  xargs -I{} python3 linkfinder.py -i {} -o cli 2>/dev/null | \
  sort -u | grep "^/" > $OUTPUT/js_endpoints.txt

# Find all parameters from historical data
gau $TARGET | grep "?" | uro | tee $OUTPUT/params_raw.txt

# GF pattern filter for interesting params
cat $OUTPUT/params_raw.txt | gf xss > $OUTPUT/xss_candidates.txt
cat $OUTPUT/params_raw.txt | gf sqli > $OUTPUT/sqli_candidates.txt
cat $OUTPUT/params_raw.txt | gf ssrf > $OUTPUT/ssrf_candidates.txt
cat $OUTPUT/params_raw.txt | gf redirect > $OUTPUT/redirect_candidates.txt

# Subdomain takeover check
subzy run --targets $OUTPUT/resolved.txt --concurrency 100 \
  --output $OUTPUT/takeover_results.txt

# Find exposed .git directories
cat $OUTPUT/live_http.txt | awk '{print $1}' | \
  xargs -I{} curl -s -o /dev/null -w "%{http_code} {}\n" {}/.git/HEAD | \
  grep "^200" > $OUTPUT/exposed_git.txt

# Check for CORS misconfigurations
python3 corstest.py -p 50 $OUTPUT/resolved.txt > $OUTPUT/cors_results.txt

# S3 bucket enumeration from company name variants
for word in company company-dev company-prod company-assets company-backup company-static; do
  aws s3 ls s3://$word --no-sign-request 2>/dev/null && echo "[OPEN] $word"
done
```

---

> **Maintained by [RemmyNine](https://github.com/RemmyNine)** | Contributions welcome via PR.
> Keep your tools updated. Keep your templates updated. Recon never stops.
