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
  - [GraphQL Attack Surface Profiling](#graphql-attack-surface-profiling)
    - [Batching & Alias-Based Attacks](#batching--alias-based-attacks)
    - [Depth & Cyclic Query Denial of Service](#depth--cyclic-query-denial-of-service)
    - [Field Suggestion & Error Enumeration](#field-suggestion--error-enumeration)
  - [JWT, OAuth & Authentication Endpoint Discovery](#jwt-oauth--authentication-endpoint-discovery)
  - [CORS Misconfiguration Discovery](#cors-misconfiguration-discovery)
  - [Cross-Origin PostMessage Analysis](#cross-origin-postmessage-analysis)
- [CMS-Specific Content Discovery](#cms-specific-content-discovery)
  - [WordPress Enumeration](#wordpress-enumeration)
  - [Drupal & Joomla Fingerprinting](#drupal--joomla-fingerprinting)
  - [Microsoft SharePoint / Exchange Discovery](#microsoft-sharepoint--exchange-discovery)
- [Single-Page Application (SPA) & Headless Crawling](#single-page-application-spa--headless-crawling)
  - [Shadow DOM & Dynamic Route Discovery](#shadow-dom--dynamic-route-discovery)
- [WebSocket Endpoint Discovery](#websocket-endpoint-discovery)
- [Blind SSRF Detection via Content Discovery](#blind-ssrf-detection-via-content-discovery)
- [Dependency Confusion & Package Manager Endpoints](#dependency-confusion--package-manager-endpoints)
- [Client-Side Prototype Pollution & DOM Analysis](#client-side-prototype-pollution--dom-analysis)
- [Advanced WAF Bypass for Content Discovery](#advanced-waf-bypass-for-content-discovery)
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

### GraphQL Attack Surface Profiling
GraphQL endpoints provide a single `/graphql` route that exposes the entire data model. The attack surface extends far beyond introspection probing.

#### Batching & Alias-Based Attacks
GraphQL supports query batching—multiple operations bundled in a single HTTP request—which can be exploited to bypass rate limiting and brute-force authentication mechanisms.
- **Concept**: Instead of sending 100 sequential login mutation attempts, an operator sends a single batched payload with 100 aliased mutations. The server processes all operations before returning a unified response, effectively circumventing per-request rate limiting counters.
- **Detection**: Send a request body containing an array of GraphQL queries (`[{ query: "..." }, { query: "..." }]`). If the server returns an array of responses, batching is enabled.
- **Defensive Mitigation**: Disable query batching in Apollo Server or GraphQL Yoga middleware; implement per-operation cost analysis instead of per-request counting.

#### Depth & Cyclic Query Denial of Service
Poorly configured GraphQL resolvers allow recursive field traversal that exhausts server resources.
- **Mechanics**: Craft deeply nested queries (e.g., `{ user { posts { author { posts { author { ... } } } } } }`) or cyclic fragments that cause infinite recursion in relational data models.
- **Detection**: Submit a query with `__typename` introspection nested 20+ levels deep. Monitor response time and server CPU utilization.
- **Defensive Mitigation**: Configure maximum query depth (typically 5–10 levels) and maximum query complexity scores per operation.

#### Field Suggestion & Error Enumeration
When introspection is disabled, detailed error messages often leak schema information.
- **Field Suggestion Leaks**: Sending a malformed query with a non-existent field triggers error responses containing suggested field names. Operators iterate through field name variants to reconstruct the schema field-by-field.
- **Fragment-Driven Enumeration**: Use inline fragments (`... on TypeName`) and observe error messages to determine which types exist and which fields are valid for each type.
- **Tooling**: [GraphQL Cop](https://github.com/dolevf/graphql-cop), [BatchQL](https://github.com/assetnote/batchql), [Graphw00f](https://github.com/dolevf/graphw00f).

### JWT, OAuth & Authentication Endpoint Discovery
Modern web applications delegate authentication to JSON Web Tokens (JWT), OAuth 2.0, and OpenID Connect (OIDC) providers.

- **OIDC Discovery Endpoint**: Most OIDC-compliant identity providers expose a discovery document at `/.well-known/openid-configuration`. This JSON file enumerates authorization, token, userinfo, and JWKS (JSON Web Key Set) endpoints.
  ```bash
  curl -s "https://target.com/.well-known/openid-configuration" | jq .
  ```
- **JWKS Endpoint Analysis**: The `jwks_uri` endpoint contains the public keys used to sign JWTs. If the key uses a weak algorithm (e.g., RS256 with insufficient key size) or symmetric signing (`HS256`) where the server misconfigures the key source, token forgery becomes feasible.
- **OAuth Misconfiguration Signatures**:
  - Look for endpoints accepting `redirect_uri` parameters with open redirect patterns.
  - Test `state` parameter omission (CSRF on OAuth flows).
  - Check for `response_type=token` (implicit flow) exposing access tokens in URL fragments.
- **JWT Algorithm Confusion Endpoints**: Identify API routes that accept JWTs and test header injection (e.g., changing `alg` from `RS256` to `none` or `HS256` with a leaked public key as the HMAC secret).

### CORS Misconfiguration Discovery
Cross-Origin Resource Sharing (CORS) misconfigurations allow attacker-controlled domains to read authenticated API responses.

- **Discovery Mechanics**: Append an `Origin` header to authenticated requests targeting API endpoints. A vulnerable server reflects the attacker's origin into the `Access-Control-Allow-Origin` response header.
  ```bash
  curl -s -H "Origin: https://attacker.com" "https://api.target.com/user/profile" -I
  ```
- **Dangerous Patterns**:
  - **Null Origin Reflection**: Servers that allow `Origin: null` enable sandboxed iframe exploits.
  - **Subdomain Wildcard**: `Access-Control-Allow-Origin: *.target.com` on a domain with user-controlled subdomains (e.g., GitHub Pages `*.github.io` inside the org).
  - **Pre-Domain Reflection**: Servers matching origin suffixes (e.g., allowing `attacker.target.com.evil.com`).
- **Tools**: [CORScanner](https://github.com/chenjj/CORScanner), [Corsy](https://github.com/s0md3v/Corsy).

### Cross-Origin PostMessage Analysis
The `window.postMessage` API enables cross-origin communication between windows, tabs, and iframes. Misconfigured message listeners create privilege escalation and cross-origin data leakage vectors.

- **Detection**: Parse all JavaScript files for `addEventListener("message", ...)` and `postMessage(` calls. Identify the expected origin filter (often a wildcard `*` or regex with bypassable patterns).
- **Attack Vectors**:
  - **Missing Origin Validation**: If the listener does not validate `event.origin`, any external page can send crafted messages.
  - **Regex Origin Bypass**: Patterns like `/^https:\/\/.*\.target\.com$/` fail to match subdomains such as `attacker.com/target.com`.
  - **Wildcard Target Origin**: `postMessage(data, '*')` leaks sensitive data to any listening frame.
- **Tooling**: [PMHooker](https://github.com/romw314/PMHooker), browser DevTools `monitorEvents(window, 'message')`.

---

## CMS-Specific Content Discovery

### WordPress Enumeration
WordPress powers ~43% of the web and exposes a standardized set of paths and API endpoints.
- **Version Detection**: `/readme.html`, `/wp-json/wp/v2/users` (REST API), chained to `/license.txt`.
- **Plugin & Theme Enumeration**: `/wp-content/plugins/{slug}/readme.txt` often leaks version numbers. The REST API route `/wp-json/wp/v2/plugins` enumerates active plugins if improperly secured.
- **User Enumeration**: `/wp-json/wp/v2/users` returns JSON arrays of authors including usernames and profile metadata. Legacy `?author=1` parameter iterates user IDs via redirect behavior.
- **Tooling**: [WPScan](https://github.com/wpscanteam/wpscan), [WordPress-Exploit-Framework](https://github.com/rastating/wordpress-exploit-framework).

### Drupal & Joomla Fingerprinting
- **Drupal Indicators**:
  - `/CHANGELOG.txt` exposes the core version.
  - `/core/install.php` reveals installation status.
  - Drupal's default administrator path: `/user/login`.
- **Joomla Indicators**:
  - `/administrator/manifests/files/joomla.xml` contains version information.
  - `/language/en-GB/en-GB.xml` also exposes the CMS version.
  - `/components/` and `/modules/` directory listings enumerate installed extensions.
- **Crawler Fingerprint**: Both platforms embed generator meta tags in HTML `<head>` that disclose exact version strings.

### Microsoft SharePoint / Exchange Discovery
- **SharePoint**:
  - Discovery endpoints: `/_api/web/lists`, `/_layouts/15/user.aspx`, `/_vti_bin/`.
  - SharePoint Web Services (`/sites/*/_vti_bin/`) expose SOAP endpoints for list data extraction.
- **Microsoft Exchange**:
  - Exchange Web Services (EWS) endpoint: `/EWS/Exchange.asmx`.
  - Autodiscover: `/autodiscover/autodiscover.xml`, `/autodiscover/autodiscover.svc`.
  - Outlook Web App (OWA) paths: `/owa/`, `/ecp/` (Exchange Control Panel).
  - ActiveSync: `/Microsoft-Server-ActiveSync` used for mobile device synchronization.

---

## Single-Page Application (SPA) & Headless Crawling

Traditional crawlers fail on SPAs because content loads dynamically via JavaScript XMLHttpRequest calls. Headless browser automation captures routing maps generated client-side.

### Shadow DOM & Dynamic Route Discovery
- **[Playwright](https://github.com/microsoft/playwright)** / **[Puppeteer](https://github.com/puppeteer/puppeteer)**: Launch a headless Chromium instance to intercept all XHR and Fetch API calls during page hydration.
  ```bash
  # Playwright route interception script
  npx playwright script --target https://spa.target.com
  ```
- **JavaScript Router Extraction**: SPAs built with React Router, Vue Router, or Angular Router embed structured route tables in bundled JS. Decompile the main chunk file and search for route definitions (e.g., `path: "/dashboard"`, `component: DashboardPage`).
- **WebSocket Interception**: SPAs often open persistent WebSocket connections for real-time data (chat, notifications, live dashboards). Capture WebSocket URLs during headless browsing to discover additional backend services.
- **Service Worker Analysis**: Parse service worker registration files (`sw.js`) to identify cached route patterns and offline-first API endpoints.
- **[Hakrawler](https://github.com/hakluke/hakrawler)**: A fast Golang-based crawler with basic JS-aware link parsing.
- **[Gospider](https://github.com/jaeles-project/gospider)**: A fast web spider with JavaScript rendering support.

---

## WebSocket Endpoint Discovery

WebSocket connections upgrade HTTP connections to persistent, bidirectional streams.

- **Identification**: Look for HTTP requests with `Upgrade: websocket` and `Connection: Upgrade` headers in proxy logs. WebSocket URLs use the `ws://` or `wss://` (TLS-secured) scheme.
- **Endpoint Patterns**: Common paths include `/ws`, `/socket.io/`, `/stomp`, `/realtime`, and `/signalr`.
- **Protocol Analysis**:
  - **Socket.IO**: Uses Engine.IO for transport negotiation. Discovery through `/socket.io/?EIO=4&transport=polling`.
  - **STOMP (Simple Text Oriented Messaging Protocol)**: Used by Spring WebSocket and RabbitMQ. Check for `/stomp` endpoints with `Sec-WebSocket-Protocol: v10.stomp`.
  - **SignalR (ASP.NET)**: Microsoft's real-time library negotiates via `/signalr/negotiate` before upgrading.
- **Security Considerations**: WebSocket connections bypass standard CORS restrictions. Unauthenticated WebSocket endpoints may leak real-time data, broadcast privileged notifications, or accept command injection payloads.

---

## Blind SSRF Detection via Content Discovery

Server-Side Request Forgery (SSRF) allows forcing the server to make HTTP requests to internal-only systems. Content discovery helps locate SSRF entry points.

- **Common SSRF Parameter Locations**: Webhook callbacks, URL importers (`file=http://`, `url=`, `path=`), PDF generators, image proxy/thumbnailing services, and OAuth `redirect_uri` fields.
- **Parameter Discovery**: Use Arjun or a custom FFuF run with an SSRF parameter wordlist (e.g., `callback`, `webhook`, `url`, `uri`, `dest`, `redirect`, `proxy`, `path`, `endpoint`, `host`, `domain`, `feed`, `src`) to identify parameters that accept URLs.
  ```bash
  ffuf -u "https://target.com/api/import?FUZZ=http://collaborator.burpcollaborator.net" \
    -w ssrf_params.txt -mc 200,301,302 -t 30
  ```
- **Cloud Metadata Endpoints**: When an SSRF is confirmed, target cloud metadata services:
  - **AWS**: `http://169.254.169.254/latest/meta-data/`
  - **GCP**: `http://metadata.google.internal/computeMetadata/v1/`
  - **Azure**: `http://169.254.169.254/metadata/instance?api-version=2021-02-01`
- **Blind SSRF Confirmation**: Use out-of-band callback services (Burp Collaborator, [Interactsh](https://github.com/projectdiscovery/interactsh)) to detect DNS/HTTP callbacks from the target server.

---

## Dependency Confusion & Package Manager Endpoints

Organizations using private package registries (npm, PyPI, NuGet) often expose configuration files during content discovery.

- **Discovery Files**:
  - `.npmrc` — npm registry configuration with `//registry.npmjs.org/:_authToken=` tokens.
  - `pip.conf` / `.pypirc` — Python package index credentials.
  - `nuget.config` — NuGet server URLs and API keys.
  - `Gemfile` / `Gemfile.lock` — Ruby dependency manifests.
- **Mechanism**: If a private package name matches a public one (name collision), the package manager may prefer the higher-versioned public package—enabling dependency confusion attacks.
- **Repository URL Fingerprinting**: Private registries at URLs like `https://pkgs.dev.azure.com/{ORG}/` found in config files can be targeted for further credential brute-forcing.

---

## Client-Side Prototype Pollution & DOM Analysis

Prototype pollution injects properties into JavaScript object prototypes, enabling XSS, property injection, and privilege escalation entirely on the client side.

- **Source Identification**: Use AST analysis on JavaScript bundles to identify merge, clone, extend, or deep-assign operations that process user-controlled input (`location.hash`, `document.cookie`, `postMessage` data, URL query parameters).
- **Gadget Discovery**: After a polluted property is injected into `Object.prototype`, it propagates to every object in the runtime. Analyze code paths to find "gadgets"—functions where an unexpected property modifies application logic (e.g., bypassing authorization checks or injecting script tags).
- **Detection Tooling**: [PPFinder](https://github.com/yesbhautik/PP-Finder), [DOM Invader](https://portswigger.net/burp/documentation/dom-invader) (Burp Suite built-in), [BlackFan's client-side prototype pollution gadgets](https://github.com/BlackFan/client-side-prototype-pollution).
- **Server-Side Prototype Pollution**: Node.js backends using libraries like `lodash.merge()` or `extend()` without safe-mode flags. Inject payloads via JSON body parameters with `__proto__` or `constructor.prototype` keys.

---

## Advanced WAF Bypass for Content Discovery

Modern Web Application Firewalls (Cloudflare, AWS WAF, Imperva, F5 ASM) deploy behavioral analysis, bot scores, and JA3 fingerprinting to block automated scanners.

- **TLS Fingerprint Spoofing**: Tools like [curl-impersonate](https://github.com/lwthiker/curl-impersonate) or [BoringSSL-based Python wrappers](https://github.com/yifeikong/curl_cffi) emulate the exact TLS handshake of Chrome, Firefox, or Safari browsers to bypass JA3/JA4 detection.
  ```bash
  curl-impersonate-chrome -s "https://target.com/api" -o /dev/null -w "%{http_code}"
  ```
- **HTTP/2 Multiplexing**: WAF inspection engines often implement incomplete HTTP/2 frame analysis. Smuggling directory brute-force requests via HTTP/2 streams that share a single TCP connection can evade per-connection rate limits.
- **IP Rotation & Proxy Cascading**: Distribute scan traffic across residential proxy networks ([BrightData](https://brightdata.com/), [Proxyrack](https://www.proxyrack.com/)) with randomized `User-Agent`, `Accept-Language`, and `Sec-CH-UA` client hint headers per request.
- **Cache Poisoning via Content Discovery**: Non-existent paths (`/static/js/FUZZ`) that trigger server errors cached by the CDN can be exploited. After discovering a cacheable error page, inject a stored XSS payload into the error body that persists in the CDN cache for all users. Defensive mitigation involves setting `Cache-Control: no-store` on error responses.

### Defensive Telemetry: API Gateway & WAF Auditing

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
