# BBH-Recon
This repository aims to provide a comprehensive and structured approach to the reconnaissance (recon) phase of bug bounty hunting. The recon phase is crucial in identifying potential attack surfaces and gathering valuable 
information about a target before attempting to find vulnerabilities.
___
## Table of Content
- [Wide Recon](#Wide-Recon)
- [Asset Discovery](#Asset-Discovery)
-  [Content-Discovery](#Content-Discovery)

___
#### Wide-Recon
- [Wide Recon](#WideRecon)
    - [Subdomain Enumerating](#Subdomain_Enumerating)
        - [Subfinder](https://github.com/projectdiscovery/subfinder) - GOAT, Config before you use it. Run it using `subfinder -dL target.txt -all -recursive -o output`
        - [BBot](https://github.com/blacklanternsecurity/bbot) - An alternative to subfinder.
        - [DNSDumpster](https://dnsdumpster.com/)
        - [crtSh Postgress DB](https://github.com/RemmyNine/Methodology/blob/main/crtsh.sh) -- Connect to pqdb and extract subdomains. Also manually use this website for some validations.
        - [AbuseIPDB](https://github.com/atxiii/small-tools-for-hunters/tree/main/abuse-ip) -- Use Atxii Script.
        - Favicon Hash -- Search the hash in Shodan --> Write a script to calculate the mm3 hash and search it in shodan.io
        - [Gau](https://github.com/lc/gau) --  `gau --subs example.com | unfurl -u domain | tee >> subs.txt`
        - [Waybackurls](https://github.com/tomnomnom/waybackurls) -- `echo domain.com | waybackurls | unfurl -u domains |‌ tee >> wbuRes.txt`
        - Host Header fuzzing on IP + URL.tld -> `fuf -w wordlist.txt -u "https://domaint.tld" -H "host: FUZZ" -H '### Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0`
        - PTR Record from IP
        - Scan ports 80, 443, and 8080 on the target IP address to discover new URLs.
        - Reverse DNS lookup
        - [Adtracker](https://github.com/dhn/udon) -- Use Udon, [BuiltWith](https://builtwith.com/) to use same Ad ID to search for similar domains/subdomains.
      - {DNS BureForce](#DnsBF)
          - [PureDNS](https://github.com/d3mondev/puredns) --> Do a static DNS bruteforce with multiple worldlist. Assetnote, all.txt by JHaddix and SecLists are good options.
          - [Gotator](https://github.com/Josue87/gotator) and [DNSGen](https://github.com/AlephNullSK/dnsgen) --> This gonna be a second-time/dynamic DNS bruteforce using permutation. *DO NOT SKIP THIS PART*
___

### Asset-Discovery

- [Asset Discovery](#AssetDiscovery)
    - Find ASNs + CIDRs + IP, NameServers --> PortScan + Reverse DNS Lookup
    - Unqiue Strings, Copyrights.
    - Find new assets on news, Stock market, Partners, about us.
    - Find new assets on crunchbase and similar websites.
    - Emails --> Reverse email lookup
    - MailServers + Certificate --> Reverse MX + SSL Search (For SSL use crtsh)
    - Search on different search engines (Google, Bing, Yandex)
    - Google Dorks (acquired by company, company. All Rights Reserved., © 2021 company. All Rights Reserved., company. All Rights Reserved." -inurl:company, acquired by target. target subsidiaries)
    - Search SSL on Shodan, FOFA and Censys.
    - Find same DMARC Information [DMARC Live)[https://dmarc.live/info/yahoo.com]
___

### Content-Discovery
- [Content Discovery](#Content_Discovery)
    - [FeroxBuster](https://github.com/epi052/feroxbuster) - Recursive Fuzzer
    - [FFuF](https://github.com/ffuf/ffuf) - All in one fuzzer.
    - [DirSearch](https://github.com/evilsocket/dirsearch) - Web path scanner. This is the Golang implementation.
    - [Katana](https://github.com/projectdiscovery/katana) - Crawler for scraping juicy files, link and endpoint.
