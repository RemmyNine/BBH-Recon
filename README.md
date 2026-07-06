# BBH-Recon Framework

> A **comprehensive, practitioner-grade** reconnaissance framework for bug bounty hunting and red team operations. 

The framework has been reorganized into a folderized structure to improve navigation and scalability. Each module contains detailed tool workflows, configuration notes, and operational checklists.

---

## 🗺️ Reorganized Table of Contents

### 1. [01. Operational Security & Infrastructure](./01-opsec-infrastructure/README.md)
* VPS selection & secure provisioning.
* Setting up stealth redirectors (Nginx, CDNs) to protect team assets.
* Proxychains configuration and IP rotation techniques (Tor, AWS API Gateway / FireProx).
* Operational environment isolation and legal safe harbor compliance.

### 2. [02. Scope, Target Profiling & Corporate OSINT](./02-scope-intelligence/README.md)
* Programmatic scope parsing from Bug Bounty platforms using `bbscope`.
* Business hierarchy mapping (acquisitions, subsidiaries) via public company registries (SEC, Crunchbase).
* Passive email and identity harvesting.
* Search engine dorking (Google Hacking Database) for sensitive data leakage.
* Threat intelligence search queries (Shodan, Censys, FOFA).
* Historical DNS and WHOIS tracking.

### 3. [03. Passive Reconnaissance](./03-passive-recon/README.md)
* Passive subdomain gathering using aggregators (`subfinder`, `bbot`, `amass`, `assetfinder`).
* Certificate Transparency (CT) log mining (direct SQL queries to crt.sh and real-time CertStream monitoring).
* Historical archive URL scraping (Wayback Machine, GAU).
* Ad-network tag correlation to link unknown assets.

### 4. [04. Active Reconnaissance & Network Discovery](./04-active-recon/README.md)
* DNS bruteforcing and permutation workflows (`puredns`, `gotator`, `dnsgen`).
* Subdomain takeover verification mechanisms.
* ASN and IP space mapping (`metabigor`, BGP tables).
* Mass port scanning and version fingerprinting (`masscan`, `nmap`, `rustscan`).
* Virtual host fuzzing (`ffuf`).

### 5. [05. Web Content Discovery](./05-web-content-discovery/README.md)
* Recursive directory and file fuzzing (`feroxbuster`, `ffuf`).
* Active web crawling (`katana`).
* API and GraphQL schema discovery (`kiterunner`, `arjun`, `clairvoyance`).
* JavaScript analysis, endpoint extraction (`linkfinder`), and secret scanning (`secretfinder`).

### 6. [06. Cloud Reconnaissance](./06-cloud-recon/README.md)
* AWS storage bucket discovery, permission checks, and IMDSv1/v2 metadata retrieval.
* Google Cloud Storage bucket validation and metadata checks.
* Azure blob containers analysis and instance metadata.
* Multi-cloud storage scanning (`cloudbrute`).

### 7. [07. Vulnerability Assessment & Analysis](./07-vulnerability-assessment/README.md)
* Technology stack detection and version matching.
* Parameter fuzzing, deduplication (`uro`), and injection mapping.
* Authentication analysis (JWT testing, OAuth 2.0 validation, session tracking).
* Automated vulnerability scanning pipelines using `nuclei`.

### 8. [08. Red Team Tradecraft & Detection Engineering](./08-red-team-tradecraft/README.md)
* **New Module**: In-depth analysis of stealth C2 infrastructure redirectors.
* **Passive SSL/TLS Handshake Fingerprints**: Overview of JA3/JA4 and JARM signature behaviors.
* **Active Directory Discovery**: Querying Microsoft 365 and Federated Identity Providers.
* **Defense Evasion**: Network scan rate optimization (low-and-slow) and protocol blending.
* **Blue Team Detection**: Writing Suricata rules, Sigma templates, and tracking beaconing signatures.

### 9. [09. Monitoring & Continuous Reconnaissance](./09-monitoring-automation/README.md)
* Real-time CT monitoring and notification pipelines.
* Custom bash scripting for daily differential scanning.
* Distributed scanning architectures utilizing cloud fleets (`axiom`).
* Setting up notifier outputs (`notify`) for Discord and Slack.

### 10. [10. Reporting, Resources & Cheat Sheets](./10-reporting-resources/README.md)
* Writing high-impact vulnerability reports.
* Reference links for must-have wordlists.
* Unified one-liner cheat sheets (full domain resolution, exposed `.git` discovery, S3 enumeration).

---

> **Maintained by [RemmyNine](https://github.com/RemmyNine)** | Contributions welcome via PR.
