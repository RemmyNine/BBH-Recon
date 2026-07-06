# 04. Active Reconnaissance & Network Discovery

Active reconnaissance involves direct interaction with target systems to map hostnames, resolve DNS entries, scan network ports, and identify running services.

---

## Table of Contents
- [DNS Bruteforcing & Permutation](#dns-bruteforcing--permutation)
  - [Algorithmic Permutations & Heuristics](#algorithmic-permutations--heuristics)
- [Subdomain Takeover Auditing](#subdomain-takeover-auditing)
- [IP Space, ASN & BGP Route Discovery](#ip-space-asn--bgp-route-discovery)
  - [Autonomous Systems & BGP Analysis](#autonomous-systems--bgp-analysis)
- [Port Scanning & Service Fingerprinting](#port-scanning--service-fingerprinting)
- [Host Header, SNI & VHost Fuzzing](#host-header-sni--vhost-fuzzing)
  - [SNI vs Host Header Fuzzing Mechanics](#sni-vs-host-header-fuzzing-mechanics)
- [Defensive Analysis: Port Scan Telemetry](#defensive-analysis-port-scan-telemetry)

---

## DNS Bruteforcing & Permutation

Static subdomain enumeration misses internal/dev environments that are not indexed. Active DNS bruteforcing and permutations resolve those records directly.

### Resolvers Setup
Always supply a clean, validated list of public resolvers to avoid false positives and network rate-limiting.
- Download verified resolvers from: [Trickest/resolvers](https://github.com/trickest/resolvers).

### Tools & Commands
- **[PureDNS](https://github.com/d3mondev/puredns)**: A powerful resolver that filters out wildcard DNS responses.
  ```bash
  # Run static bruteforcing
  puredns bruteforce wordlists/all.txt example.com -r resolvers.txt -o puredns_results.txt
  
  # Validate a list of passive subdomains
  puredns resolve subs_passive.txt -r resolvers.txt -o resolved_subs.txt
  ```
- **[MassDNS](https://github.com/blechschmidt/massdns)**: High-speed engine for executing bulk DNS lookups.
  ```bash
  massdns -r resolvers.txt -t A -o S -w massdns_resolved.txt subdomains_list.txt
  ```

### DNS Permutation Engines
Generating mutations of known subdomains (adding prefixes like `dev-`, suffixes like `-v2`, or environment markers) surfaces hidden resources.
- **[Gotator](https://github.com/Josue87/gotator)**: Generate highly targeted permutation lists.
  ```bash
  gotator -sub resolved_subs.txt -perm permutations.txt -depth 1 -numbers 3 -mindup -adv -md | sort -u > perm_list.txt
  ```
- **[DNSGen](https://github.com/AlephNullSK/dnsgen)**: Algorithmic permutation tool.
  ```bash
  cat resolved_subs.txt | dnsgen - | puredns resolve -r resolvers.txt -o perm_resolved.txt
  ```

### Algorithmic Permutations & Heuristics
Static mutation lists (word replacements) are generic. Advanced permutation tools use heuristic algorithms:
1. **Numeric Iteration**: If `api-01.target.com` exists, the engine automatically checks `api-02` through `api-99`.
2. **Delimited Splitting**: Breaking domains by dashes or dots (`dev.infra.target.com` -> `infra.dev.target.com` or `dev-infra-target`).
3. **Entropy-Based Fuzzing**: Identifying low-entropy word transitions common to network administrators (e.g., `prod`, `stag`, `internal`, `test`, `uat`, `admin`, `vpn`).

---

## Subdomain Takeover Auditing

A subdomain takeover occurs when a DNS record points to a third-party cloud service (e.g., S3, GitHub Pages, Heroku, Azure) that has been deleted or unconfigured, allowing an external party to claim it.

### Automatic Scanning
- **[Nuclei](https://github.com/projectdiscovery/nuclei)**: Scan with takeover-specific templates.
  ```bash
  nuclei -l resolved_subs.txt -t nuclei-templates/takeovers/ -o takeover_results.txt
  ```
- **[Subzy](https://github.com/LukaSikic/subzy)**: Dedicated tool designed for concurrent takeover checks.
  ```bash
  subzy run --targets resolved_subs.txt --concurrency 100 --hide_fails
  ```

### Manual Validation Check
Always double-check CNAME resolutions before documenting a takeover:
```bash
dig CNAME subdomain.example.com +short
```
Cross-reference the returned CNAME target with the profiles in [Can-I-take-over-XYZ](https://github.com/EdOverflow/can-i-take-over-xyz).

---

## IP Space, ASN & BGP Route Discovery

Identify the client's registered IP address blocks (CIDRs) and Autonomous System Numbers (ASNs) to widen target discovery.

### Mapping Tools
- **[Metabigor](https://github.com/j3ssie/metabigor)**: Query BGP tables and organization data.
  ```bash
  echo "Target Corporation" | metabigor net --org -o cidrs.txt
  ```
- **Amass Intel**: Map organization names to registered ASNs.
  ```bash
  amass intel -org "Target Corporation" -asn
  ```
- **IP Info Lookup**:
  ```bash
  curl -s "https://ipinfo.io/AS12345" | jq '.prefixes[].prefix'
  ```

### Autonomous Systems & BGP Analysis
Autonomous Systems (AS) route internet traffic via Border Gateway Protocol (BGP).
- **Prefix Discovery**: Querying regional registries (ARIN, RIPE, APNIC, LACNIC, AFRINIC) using organization handles retrieves entire IP segments owned directly by the target.
- **Route Monitoring**: Analyzing historical BGP routing updates reveals network boundary changes and temporarily advertised networks (which are often poorly protected).

---

## Port Scanning & Service Fingerprinting

Identify open ports, running protocols, and application versions on discovered CIDRs and IP targets.

### Masscan (High Volume Scanning)
Scan large ranges at high speeds, then feed results into Nmap for verification.
```bash
masscan -p0-65535 --rate 25000 -iL cidrs.txt -oG masscan_output.txt
```

### Nmap / RustScan (Deep Fingerprinting)
- **RustScan**: Speeds up Nmap execution by performing initial port scans.
  ```bash
  rustscan -a live_ips.txt --range 1-65535 -- -sV -sC -oN nmap_output.txt
  ```
- **Nmap Targeted Scan**:
  ```bash
  nmap -sV -sC -p 22,80,443,8080,8443 -iL live_ips.txt -oA nmap_targeted
  ```

### Key Ports to Watch
| Port | Common Protocols / Targets |
|------|---------------------------|
| 21   | FTP (anonymous access)     |
| 22   | SSH                       |
| 23   | Telnet                    |
| 80/443 | HTTP / HTTPS            |
| 445  | SMB (EternalBlue, shares) |
| 1433/3306/5432 | Database ports   |
| 3389 | RDP                       |
| 6379 | Redis                     |
| 8080/8443/8888 | Alternative HTTP |
| 9200 | Elasticsearch             |

---

## Host Header, SNI & VHost Fuzzing

Web servers hosting multiple domains determine routing based on the HTTP `Host` header or TLS handshake parameters.

### SNI vs Host Header Fuzzing Mechanics
- **TLS SNI (Server Name Indication)**: Sent during the initial TLS Client Hello handshake. The router or proxy uses it to route traffic before decrypting the TLS layer.
- **HTTP Host Header**: Sent within the encrypted HTTP request.
- **VHost Discovery**: Modern reverse proxies (e.g. Cloudflare, Cloudfront) discard requests if the SNI domain name does not match their internal routing maps. True virtual host discovery requires matching the SNI parameter to the Host header.

### FFuF Host Fuzzing
```bash
ffuf -w subdomains_wordlist.txt -u "https://TARGET_IP" -H "Host: FUZZ.example.com" \
  -mc 200,301,302,403 -t 50 -o vhost_hits.json
```
Filter out default generic responses by matching size/word counts (`-fs` or `-fw`).

---

## Defensive Analysis: Port Scan Telemetry

Active network scanning triggers immediate intrusion detection system alerts.

- **Firewall & IPS Event Correlation**: Network gateways monitor incoming TCP connection states. Scans are identified by:
  - **SYN Scans**: High volume of TCP SYN packets followed immediately by RST packets (half-open scanning).
  - **FIN/NULL/Xmas Scans**: Packets with unusual flag combinations that bypass standard stateless firewalls.
- **Defensive Mitigations**:
  - **Fail2ban / IP Tables Rate Limiting**: Block IPs that exceed a specified number of new connections per second.
  - **Port Knocking**: Hide sensitive ports (like SSH/RDP) behind a sequence of closed-port connection attempts.
