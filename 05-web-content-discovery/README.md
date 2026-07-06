# 05. Web Content Discovery & Endpoint Analysis

Content discovery locates hidden assets, routes, configuration backups, parameters, and sensitive JavaScript logic on verified live web hosts.

---

## Table of Contents
- [Directory & Path Fuzzing](#directory--path-fuzzing)
  - [Heuristics & Soft-404 Handling](#heuristics--soft-404-handling)
- [Crawler & Spider Tools](#crawler--spider-tools)
- [Historical Endpoint Mining](#historical-endpoint-mining)
- [API & GraphQL Profiling](#api--graphql-profiling)
  - [API Spec Reconstruction](#api-spec-reconstruction)
- [JavaScript Analysis & Secrets Extraction](#javascript-analysis--secrets-extraction)
  - [Abstract Syntax Tree (AST) Parsing](#abstract-syntax-tree-ast-parsing)
- [Defensive Auditing: Rate Limiting & Detection](#defensive-auditing-rate-limiting--detection)

---

## Directory & Path Fuzzing

Fuzzing paths uses structured wordlists to locate non-linked pages, developer backup files, and administrative panels.

### Recommended Wordlists
- **SecLists**: `SecLists/Discovery/Web-Content/raft-large-directories.txt`
- **Assetnote**: Technology-specific wordlists (e.g., IIS, Nginx, PHP, Spring Boot) from [wordlists.assetnote.io](https://wordlists.assetnote.io/).

### Tools & Commands
- **[FeroxBuster](https://github.com/epi052/feroxbuster)**: A high-performance recursive directory fuzzer written in Rust.
  ```bash
  feroxbuster -u https://example.com -w wordlists/raft-large-directories.txt \
    -x php,asp,aspx,jsp,html,txt,json,bak,sql,config \
    --auto-tune --smart-filter -o ferox_results.txt
  ```
- **[FFuF (Fuzz Faster U Fool)](https://github.com/ffuf/ffuf)**: Highly flexible fuzzer, ideal for custom filters and headers.
  ```bash
  # Directory search with custom response code filtering
  ffuf -u https://example.com/FUZZ -w wordlists/raft-large-directories.txt \
    -mc 200,301,302,403 -o ffuf_dirs.json -of json
  ```
- **[GoBuster](https://github.com/OJ/gobuster)**: Simple directory buster with multiple module supports.
  ```bash
  gobuster dir -u https://example.com -w wordlists/common.txt -x php,html,bak
  ```

### Backup & Sensitive Extensions to Watch
Ensure your fuzzing profiles always test for variations of discovered files appended with:
`.bak`, `.old`, `.tmp`, `.swp`, `.1`, `.orig`, `.save`, `.sql`, `.dump`, `.log`, `.cfg`, `.conf`, `.env`, `.pem`, `.key`, `.xml`, `.yaml`, `.yml`, `.json`, `.tar.gz`, `.zip`

### Heuristics & Soft-404 Handling
Many modern web frameworks return `200 OK` status codes for non-existent pages, embedding error messages within the body (Soft-404s).
- **Dynamic Calibration**: Tools like FFuF and Feroxbuster can dynamically filter responses based on line count (`-fl`), word count (`-fw`), or character length (`-fs`).
- **Wildcard Detection**: Send a request to a randomized path (e.g., `/uniquepath_123_xyz`) before starting. Record its response length and body hash to filter out wildcard matches automatically.

---

## Crawler & Spider Tools

Crawling maps user paths, inputs, and form parameters by systematically traversing href links and JS scripts.

- **[Katana](https://github.com/projectdiscovery/katana)**: Modern CLI crawler supporting active JS execution and deep crawling.
  ```bash
  katana -u https://example.com -depth 5 -js-crawl -passive -o katana_results.txt
  ```

---

## Historical Endpoint Mining

Extract URLs indexed by search engines and internet archives to find decommissioned paths that are still active on the server.

- **GAU / Waybackurls**:
  ```bash
  # Aggregate endpoints from Gau
  gau --subs --threads 5 example.com | tee gau_endpoints.txt
  ```
- **URLScan.io API Queries**:
  ```bash
  curl -s "https://urlscan.io/api/v1/search/?q=domain:example.com&size=1000" \
    | jq -r '.results[].page.url' > urlscan_endpoints.txt
  ```
- **Filter and Deduplicate**:
  ```bash
  cat gau_endpoints.txt urlscan_endpoints.txt | sort -u | grep -E "api|v1|v2|admin|upload" > interesting_endpoints.txt
  ```

---

## API & GraphQL Profiling

Application Programming Interfaces (APIs) represent highly functional endpoints.

### API Discovery Checklists
Check standard path schemas for Swagger or OpenAPI JSON descriptors:
- `/swagger.json`, `/swagger/v1/swagger.json`
- `/api-docs`, `/openapi.json`
- `/v1/api-docs`, `/.well-known/openapi`
- `/api/swagger-ui.html`

### Tools & Commands
- **[Kiterunner](https://github.com/assetnote/kiterunner)**: Designed specifically for API routing discovery using custom wordlists.
  ```bash
  kr scan https://api.example.com -w wordlists/routes-large.kite -o api_results.txt
  ```
- **[Arjun](https://github.com/s0md3v/Arjun)**: Finds hidden parameters accepted by API endpoints.
  ```bash
  arjun -u https://api.example.com/endpoint -m GET,POST,JSON
  ```
- **[Clairvoyance](https://github.com/nikitastupin/clairvoyance)**: Reconstructs a GraphQL schema when schema introspection is disabled.
  ```bash
  clairvoyance -u https://example.com/graphql -o schema.json
  ```

### API Spec Reconstruction
When Swagger pages are disabled, you can reconstruct the schema from raw endpoint lists:
1. Map variables using token identification (e.g., `/api/v1/user/{id}`).
2. Feed endpoints into automated tools (e.g., `mitmproxy` scripts or custom parsers) to auto-generate OpenAPI v3 JSON templates.

---

## JavaScript Analysis & Secrets Extraction

Analyzing client-side JavaScript allows you to extract API keys, tokens, backend routes, and business logic configurations.

### Automated Scraping
- **[Subjs](https://github.com/lc/subjs)**: Extract all JavaScript file URLs hosted on the target system.
  ```bash
  cat alive_hosts.txt | subjs | tee js_file_urls.txt
  ```
- **[LinkFinder](https://github.com/GerbenJavado/LinkFinder)**: Extracts endpoint URLs and relative paths from JavaScript files.
  ```bash
  python3 linkfinder.py -i https://example.com/main.js -o cli
  ```
- **[SecretFinder](https://github.com/m4ll0k/SecretFinder)**: Inspects JS source code for API keys, AWS credentials, and tokens using regex profiles.
  ```bash
  python3 SecretFinder.py -i https://example.com/main.js -o cli
  ```

### Webpack Reconstruct
- **[Webpack Exploit / Decompiler](https://github.com/lzghzr/webpack-explode)**: If the target site hosts a source map file (e.g., `main.js.map`), decompile the bundle to reconstruct the original frontend source tree.

### Abstract Syntax Tree (AST) Parsing
Standard regex scanners miss dynamically generated paths (e.g., `url = host + "/v1/" + endpoint`).
- **Concept**: AST parsing reads JavaScript code and constructs a logical syntax tree. Tools query tree node transitions (e.g., `Identifier` concatenated with `Literal`) to identify compiled endpoints.
- **Implementation**: Node.js scripts using libraries like `esprima` or `acorn` parse script variables programmatically to isolate base URLs and route matrices.

---

## Defensive Auditing: Rate Limiting & Detection

Web Application Firewalls (WAFs) and API Gateways actively monitor request velocities to block scanning traffic.

### Evasion Concepts (Theoretical Mechanics)
- **Header Injection**: Some WAFs trust headers for source IP determination. Scanners rotate standard headers:
  `X-Forwarded-For`, `X-Real-IP`, `X-Originating-IP`, `CF-Connecting-IP`
- **Request Pacing**: Introduce high random jitter (e.g., 500ms to 2000ms delay between actions) to stay beneath rate-limiting thresholds.

### Defensive Telemetry
- **API Gateway Logging**: Systems monitor request volume per IP client and cross-reference proxy header modifications against actual network layer source addresses.
- **Outlier Analysis**: SIEM rule engines flag IPs that trigger high volumes of `404 Not Found` or `403 Forbidden` status codes within a compressed window.
