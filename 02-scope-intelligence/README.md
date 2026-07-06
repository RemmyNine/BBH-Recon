# 02. Scope, Target Profiling & Corporate Intelligence

Before initiating active enumeration, you must understand the target's organizational boundary, legal boundaries, and corporate footprint. This section covers programmatic scope parsing, business hierarchy mapping, passive OSINT, and email/DNS historical intelligence.

---

## Table of Contents
- [Scope Expansion & Target Profiling](#scope-expansion--target-profiling)
- [Corporate Infrastructure Mapping](#corporate-infrastructure-mapping)
- [Email & Identity Harvesting](#email--identity-harvesting)
- [Search Engine Dorking](#search-engine-dorking)
- [Passive Threat Intelligence & Shodan](#passive-threat-intelligence--shodan)
- [DNS History & WHOIS Records](#dns-history--whois-records)

---

## Scope Expansion & Target Profiling

Understanding wildcards, acquisitions, and parent/subsidiary relationships is critical to mapping out the target landscape.

### Automating Scope Extraction
Rather than copy-pasting domains from bug bounty platforms, query the APIs programmatically to build clean target lists.

- **[bbscope](https://github.com/sw33tLie/bbscope)**: Extract in-scope targets directly from HackerOne, Bugcrowd, and Intigriti.
  ```bash
  # Extract in-scope URLs/domains from a HackerOne program
  bbscope h1 -t YOUR_H1_API_TOKEN -o output/in_scope_domains.txt
  ```
- **[chaos-client](https://github.com/projectdiscovery/chaos-client)**: Pull public subdomains from ProjectDiscovery's pre-compiled internet database.
  ```bash
  chaos -key YOUR_CHAOS_API_KEY -d example.com -silent -o chaos_subs.txt
  ```

---

## Corporate Infrastructure Mapping

For large organizations, mapping corporate entities, acquisitions, and joint ventures reveals forgotten or unmonitored staging/development infrastructure.

### Business Registries & Financial Disclosures
- **Crunchbase & PitchBook**: Identify acquired subsidiaries and corporate funding timelines.
- **SEC EDGAR Search**: Search for public filings (especially Form 10-K, Item 1A - Risk Factors or Item 2 - Properties) to extract lists of subsidiaries and physical office locations.
- **OpenCorporates**: Query registration data globally to find matching company registration details (directors, registration numbers).
- **DMARC Org Domains**: Analyze DMARC records to identify other domains associated with the parent organization.

---

## Email & Identity Harvesting

Harvesting employee emails serves two passive recon purposes: identifying cloud tenant structures and discovering past data leaks.

### Tools for Email Harvesting
- **[theHarvester](https://github.com/laramies/theHarvester)**: Gather emails, subdomains, and hosts from multiple public sources.
  ```bash
  theHarvester -d example.com -b all -l 500 -f harvest_results
  ```
- **Hunter.io**: Discover common corporate email address structures (e.g., `first.last@company.com`).
- **Phonebook.cz**: Query domain-related email outputs passively.

### Paste & Breach Sites
Once emails are discovered, cross-reference them to identify historical data breaches containing leaked credentials:
- **IntelX**: Deep-web and paste-site search engine.
- **HaveIBeenPwned API**: Query credential breach lists for target corporate email prefixes.

---

## Search Engine Dorking

Advanced search engine operators (Google Dorks) bypass active detection controls to index hidden files and directories.

### Common Google Dorks for Recon
| Google Dork | Purpose |
|-------------|---------|
| `site:example.com ext:doc OR ext:docx OR ext:xls OR ext:xlsx OR ext:pdf "internal"` | Find sensitive internal documents |
| `site:example.com ext:conf OR ext:config OR ext:env OR ext:yaml OR ext:json` | Locate backup or leaked configurations |
| `site:example.com inurl:"/api/" OR inurl:"/v1/" OR inurl:"/v2/"` | Find API endpoints indexable by engines |
| `"© 2026 Target Corp. All Rights Reserved." -site:target.com` | Find external sites owned by the organization |
| `site:*.s3.amazonaws.com "target-name"` | Locate public S3 buckets |

---

## Passive Threat Intelligence & Shodan

Threat intelligence engines allow you to query passive port scans, TLS certificates, and service banners without sending packets directly to the target.

### Shodan Dorks for Passive Infrastructure Mapping
- Find all systems using the target's SSL/TLS certificate:
  ```text
  ssl.cert.subject.cn:"*.example.com"
  ```
- Search by organization name (ASN registration):
  ```text
  org:"Target Corporation"
  ```
- Identify specific server response banners:
  ```text
  http.title:"Target Internal Login"
  ```

### Censys & FOFA
- **Censys Query**: Search using DNS Names or SSL subjects.
  ```text
  parsed.names: example.com
  ```
- **FOFA Query**: Find web systems matching target headers or parameters.
  ```text
  domain="example.com"
  ```

---

## DNS History & WHOIS Records

Historical DNS and WHOIS records reveal old IP associations, registrar configurations, and physical address details used by network administrators.

### SecurityTrails API Queries
- **Historical WHOIS**: Retrieve previous ownership information.
  ```bash
  curl -s "https://api.securitytrails.com/v1/domain/example.com/whois/history" \
    -H "APIKEY: YOUR_KEY" | jq .
  ```
- **Historical DNS A-Records**: Track IP changes over the last decade.
  ```bash
  curl -s "https://api.securitytrails.com/v1/domain/example.com/dns/history/a" \
    -H "APIKEY: YOUR_KEY" | jq .
  ```
