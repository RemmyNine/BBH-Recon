# 04. Active Reconnaissance & Network Discovery

Active reconnaissance involves direct interaction with target systems to map hostnames, resolve DNS entries, scan network ports, and identify running services.

---

## Table of Contents
- [DNS Bruteforcing & Permutation](#dns-bruteforcing--permutation)
- [Subdomain Takeover Auditing](#subdomain-takeover-auditing)
- [IP Space & ASN Mapping](#ip-space--asn-mapping)
- [Port Scanning & Service Fingerprinting](#port-scanning--service-fingerprinting)
- [Host Header & VHost Fuzzing](#host-header--vhost-fuzzing)

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

## IP Space & ASN Mapping

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

## Host Header & VHost Fuzzing

Web servers hosting multiple domains determine routing based on the HTTP `Host` header. Fuzzing this header can expose hidden administrative portals.

### FFuF Host Fuzzing
```bash
ffuf -w subdomains_wordlist.txt -u "https://TARGET_IP" -H "Host: FUZZ.example.com" \
  -mc 200,301,302,403 -t 50 -o vhost_hits.json
```
Filter out default generic responses by matching size/word counts (`-fs` or `-fw`).
