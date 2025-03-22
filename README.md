# BBH-Recon
This repository provides a structured approach to the reconnaissance phase, tailored for bug bounty hunting and red team operations.  Reconnaissance is a critical undertaking that involves identifying potential attack surfaces, gathering pertinent target information, and informing subsequent vulnerability discovery or attack simulation efforts. This guide emphasizes thoroughness and organization, aligning with industry best practices to facilitate effective and efficient security assessments.

## Table of Content
- [Wide Recon](#wide-recon)
- [Asset Discovery](#asset-discovery)
- [Content Discovery](#content-discovery)
- [Technology Fingerprinting](#technology-fingerprinting)
- [Parameter Analysis](#parameter-analysis)
- [Authentication Analysis](#authentication-analysis)
- [Monitoring & Continuous Recon](#monitoring--continuous-recon)
- [Vulnerability Scanning](#vulnerability-scanning)
- [Automation Frameworks](#automation-frameworks)
- [Reporting and Documentation](#reporting-and-documentation)

## Wide-Recon
### Subdomain Enumeration
- [Subfinder](https://github.com/projectdiscovery/subfinder) - GOAT, Config before you use it. Run it using `subfinder -dL target.txt -all -recursive -o output`
- [BBot](https://github.com/blacklanternsecurity/bbot) - An alternative to subfinder.
- [Amass](https://github.com/owasp-amass/amass) - In-depth subdomain enumeration with multiple sources
- [DNSDumpster](https://dnsdumpster.com/)
- [Sublist3r](https://github.com/aboul3la/Sublist3r) - Subdomain discovery using various sources
- [AssetFinder](https://github.com/tomnomnom/assetfinder) - Find domains and subdomains related to a domain
- [crtSh Postgress DB](https://github.com/RemmyNine/Methodology/blob/main/crtsh.sh) - Connect to pqdb and extract subdomains. Also manually use this website for some validations.
- [AbuseIPDB](https://github.com/atxiii/small-tools-for-hunters/tree/main/abuse-ip) - Use Atxii Script.
- [Altdns](https://github.com/infosec-au/altdns) - For permutation generation
- Favicon Hash - Search the hash in Shodan --> Write a script to calculate the mm3 hash and search it in shodan.io
- [Gau](https://github.com/lc/gau) - `gau --subs example.com | unfurl -u domain | tee >> subs.txt`
- [Waybackurls](https://github.com/tomnomnom/waybackurls) - `echo domain.com | waybackurls | unfurl -u domains |‌ tee >> wbuRes.txt`
- [GitHub-Subdomains](https://github.com/gwen001/github-subdomains) - Find subdomains on GitHub
- [Shosubgo](https://github.com/incogbyte/shosubgo) - Enumerate subdomains with Shodan
- Host Header fuzzing on IP + URL.tld -> `ffuf -w wordlist.txt -u "https://domain.tld" -H "host: FUZZ" -H 'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0'`
- PTR Record from IP
- Scan ports 80, 443, and 8080 on the target IP address to discover new URLs.
- Reverse DNS lookup
- [Adtracker](https://github.com/dhn/udon) - Use Udon, [BuiltWith](https://builtwith.com/) to use same Ad ID to search for similar domains/subdomains.
- [Censys](https://censys.io/) - Search for certificates to find subdomains
- [Dnsprobe](https://github.com/projectdiscovery/dnsprobe) - DNS probe utility for resolving and validating subdomains

### DNS Bruteforce
- [PureDNS](https://github.com/d3mondev/puredns) - Do a static DNS bruteforce with multiple wordlists. Assetnote, all.txt by JHaddix and SecLists are good options.
- [MassDNS](https://github.com/blechschmidt/massdns) - High-performance DNS stub resolver for bulk lookups
- [Gotator](https://github.com/Josue87/gotator) and [DNSGen](https://github.com/AlephNullSK/dnsgen) - This gonna be a second-time/dynamic DNS bruteforce using permutation. *DO NOT SKIP THIS PART*

### Subdomain Takeover
- [Nuclei](https://github.com/projectdiscovery/nuclei) with takeover templates
- [Subzy](https://github.com/LukaSikic/subzy) - Subdomain takeover vulnerability checker
- [Can-I-Take-Over-XYZ](https://github.com/EdOverflow/can-i-take-over-xyz) - Reference for subdomain takeover vulnerabilities

### IP Space Discovery
- [Nmap](https://nmap.org/) - Network discovery and security auditing
- [Masscan](https://github.com/robertdavidgraham/masscan) - TCP port scanner, faster than nmap
- [IPInfo](https://ipinfo.io/) - IP address data provider
- [Shodan](https://www.shodan.io/) - Search engine for Internet-connected devices
- [Censys](https://censys.io/) - Search engine for Internet-connected devices

## Asset-Discovery
- Find ASNs + CIDRs + IP, NameServers --> PortScan + Reverse DNS Lookup
  - [ASNLookup](https://github.com/yassineaboukir/Asnlookup) - Look up organization ASNs
  - [Amass](https://github.com/OWASP/Amass) - In-depth asset discovery
  - [BGPView](https://bgpview.io/) - BGP ASN lookup
  - [WhoisXML](https://www.whoisxmlapi.com/) - Comprehensive domain & IP data
- Unique Strings, Copyrights
  - [Nuclei](https://github.com/projectdiscovery/nuclei) with custom templates
- Find new assets in news, Stock market, Partners, about us
  - LinkedIn, Crunchbase, SEC filings
- Find new assets on crunchbase and similar websites
  - [Crunchbase](https://www.crunchbase.com/)
  - [ZoomInfo](https://www.zoominfo.com/)
  - [PitchBook](https://pitchbook.com/)
- Emails --> Reverse email lookup
  - [Hunter.io](https://hunter.io/)
  - [Clearbit Connect](https://connect.clearbit.com/)
  - [TheHarvester](https://github.com/laramies/theHarvester)
- MailServers + Certificate --> Reverse MX + SSL Search (For SSL use crtsh)
  - [SecurityTrails](https://securitytrails.com/)
  - [mxtoolbox](https://mxtoolbox.com/)
- Search on different search engines (Google, Bing, Yandex)
  - [Searx](https://searx.github.io/searx/) - Metasearch engine
- Google Dorks (acquired by company, company. All Rights Reserved., © 2021 company. All Rights Reserved., company. All Rights Reserved." -inurl:company, acquired by target. target subsidiaries)
  - [Google Hacking Database](https://www.exploit-db.com/google-hacking-database)
  - [OSINT Framework](https://osintframework.com/)
- Search SSL on Shodan, FOFA and Censys
  - [Shodan](https://www.shodan.io/)
  - [FOFA](https://fofa.info/)
  - [Censys](https://censys.io/)
- Find same DMARC Information [DMARC Live](https://dmarc.live/info/yahoo.com)
- Cloud Resources Discovery
  - [AWS S3 Buckets](https://github.com/securing/DumpsterDiver)
  - [GCP Buckets](https://github.com/RhinoSecurityLabs/GCPBucketBrute)
  - [Azure Storage](https://github.com/NetSPI/MicroBurst)
- GitHub Reconnaissance
  - [GitRob](https://github.com/michenriksen/gitrob)
  - [TruffleHog](https://github.com/trufflesecurity/trufflehog)
  - [GitHub-Dorks](https://github.com/techgaun/github-dorks)

## Content-Discovery
- [FeroxBuster](https://github.com/epi052/feroxbuster) - Recursive Fuzzer
- [FFuF](https://github.com/ffuf/ffuf) - All in one fuzzer.
- [DirSearch](https://github.com/evilsocket/dirsearch) - Web path scanner. This is the Golang implementation.
- [Katana](https://github.com/projectdiscovery/katana) - Crawler for scraping juicy files, link and endpoint.
- [GoBuster](https://github.com/OJ/gobuster) - Directory/file & DNS busting tool
- [Linkfinder](https://github.com/GerbenJavado/LinkFinder) - Discover endpoints in JavaScript files
- Historical Content Analysis
  - [Wayback Machine](https://archive.org/web/)
  - [CommonCrawl](https://commoncrawl.org/)
  - [Waybackurls](https://github.com/tomnomnom/waybackurls)
- API Discovery
  - [Kiterunner](https://github.com/assetnote/kiterunner) - API discovery tool
  - [Postman](https://www.postman.com/)
  - [APICheck](https://github.com/BBVA/apicheck)
- GraphQL Discovery
  - [GraphQLmap](https://github.com/swisskyrepo/GraphQLmap)
  - [InQL](https://github.com/doyensec/inql)
- JavaScript Analysis
  - [JSParser](https://github.com/nahamsec/JSParser)
  - [SecretFinder](https://github.com/m4ll0k/SecretFinder)
  - [JSScanner](https://github.com/0x240x23elu/JSScanner)

## Technology-Fingerprinting
- [Wappalyzer](https://www.wappalyzer.com/) - Identify technologies on websites
- [Whatweb](https://github.com/urbanadventurer/whatweb) - Next generation web scanner
- [Wafw00f](https://github.com/EnableSecurity/wafw00f) - Identify and fingerprint WAF products
- [httpx](https://github.com/projectdiscovery/httpx) - Fast HTTP toolkit
- [Nuclei](https://github.com/projectdiscovery/nuclei) with tech-detect templates
- [Retirejs](https://github.com/RetireJS/retire.js) - Scanner detecting the use of JavaScript libraries with known vulnerabilities
- CMS Specific Tools
  - [WPScan](https://github.com/wpscanteam/wpscan) - WordPress vulnerability scanner
  - [JoomScan](https://github.com/OWASP/joomscan) - Joomla vulnerability scanner
  - [Droopescan](https://github.com/droope/droopescan) - Scanner for Drupal, Silverstripe, and WordPress
- [Aquatone](https://github.com/michenriksen/aquatone) - Visual inspection of websites across many hosts

## Parameter-Analysis
- [Arjun](https://github.com/s0md3v/Arjun) - HTTP parameter discovery suite
- [Parameth](https://github.com/maK-/parameth) - This tool can be used to brute discover GET and POST parameters
- [ParamSpider](https://github.com/devanshbatham/ParamSpider) - Mining parameters from dark corners of Web Archives
- [X8](https://github.com/jakobdoerr/x8) - Hidden parameters discovery suite
- Parameter Pollution Testing
  - [Param-Miner](https://github.com/PortSwigger/param-miner) - Burp extension for parameter mining
  - Custom scripts to test for HTTP Parameter Pollution
- [GF](https://github.com/tomnomnom/gf) - A wrapper around grep to avoid typing common patterns
- [GF-Patterns](https://github.com/1ndianl33t/Gf-Patterns) - Collection of patterns for gf tool

## Authentication-Analysis
- [Burp Intruder](https://portswigger.net/burp/documentation/desktop/tools/intruder) - For brute force testing
- [Hydra](https://github.com/vanhauser-thc/thc-hydra) - Password cracking tool
- [JWT_Tool](https://github.com/ticarpi/jwt_tool) - Toolkit for testing, tweaking and cracking JWTs
- [OAuth 2.0 Testing Tools](https://oauth.tools/)
- [Autorepeater](https://github.com/nccgroup/autorepeater) - Automated HTTP request repeating with Burp Suite
- [JWT-Cracker](https://github.com/lmammino/jwt-cracker) - Simple HS256 JWT token brute force cracker

## Monitoring--Continuous-Recon
- [ReconFTW](https://github.com/six2dez/reconftw) - Automated reconnaissance framework
- [Findomain-Monitoring](https://findomain.app/monitor/) - Subdomain monitoring
- [Nuclei](https://github.com/projectdiscovery/nuclei) with automation
- [Notify](https://github.com/projectdiscovery/notify) - Stream output from recon tools to various notification services
- [Subdomainizer](https://github.com/nsonaniya2010/SubDomainizer) - Tool for finding hidden subdomains and secrets
- [Sublert](https://github.com/yassineaboukir/sublert) - Security and reconnaissance tool to monitor new subdomains
- [SubOver](https://github.com/Ice3man543/SubOver) - Powerful subdomain takeover tool
- [Delta](https://github.com/dsopas/rfd-checker) - Check for reflected file download vulnerabilities
- [Security Header Scanner](https://securityheaders.com/) - Evaluate HTTP security headers
- [Recon-Pipeline](https://github.com/epi052/recon-pipeline) - Automated reconnaissance pipeline
- [Github-Monitor](https://github.com/ActivityWatch/aw-watcher-web) - Monitor GitHub for sensitive information

## Vulnerability-Scanning
- [Nuclei](https://github.com/projectdiscovery/nuclei) - Fast and customizable vulnerability scanner

