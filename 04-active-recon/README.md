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
- [SNMP Enumeration](#snmp-enumeration)
- [SMTP User Enumeration](#smtp-user-enumeration)
- [RDP NLA & CredSSP Fingerprinting](#rdp-nla--credssp-fingerprinting)
- [NFS & RPC Service Enumeration](#nfs--rpc-service-enumeration)
- [LDAP Anonymous Bind Enumeration](#ldap-anonymous-bind-enumeration)
- [DNSSEC & Zone Walking Analysis](#dnssec--zone-walking-analysis)
- [Advanced Service Fingerprinting & Banner Grabbing](#advanced-service-fingerprinting--banner-grabbing)
  - [Protocol-Specific Probing](#protocol-specific-probing)
  - [TCP/IP Stack Fingerprinting](#tcpip-stack-fingerprinting)
- [SIP / VoIP Infrastructure Enumeration](#sip--voip-infrastructure-enumeration)
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

## SNMP Enumeration

Simple Network Management Protocol (UDP port 161) exposes device configuration, network interfaces, running processes, and installed software when configured with weak community strings.

- **Community String Brute-Forcing**: Default read-only strings are `public`, `private`, `c internal`, and `manager`. Write access (`rwcommunity`) enables remote reconfiguration.
  ```bash
  onesixtyone -c community_strings.txt -i live_ips.txt -o snmp_results.txt
  snmp-check -c public 192.168.1.1
  ```
- **OID (Object Identifier) Enumeration**: Once a valid community string is obtained, walk the SNMP MIB tree to extract critical data:
  - **System Information**: `1.3.6.1.2.1.1` (sysDescr, sysContact, sysName, sysLocation).
  - **Network Interfaces**: `1.3.6.1.2.1.2` (interface names, IP addresses, MAC addresses).
  - **Running Processes**: `1.3.6.1.2.1.25.4.2.1` (HOST-RESOURCES-MIB).
  - **Installed Software**: `1.3.6.1.2.1.25.6.3.1` (software inventory).
  - **TCP Connection Table**: `1.3.6.1.2.1.6.13` (active connections with remote IPs).
  ```bash
  snmpwalk -v2c -c public 192.168.1.1 1.3.6.1.2.1.1
  ```
- **SNMPv3 USM Discovery**: SNMPv3 uses a User-based Security Model (USM). Although encrypted, the EngineID and EngineBoots parameters can be passively collected to fingerprint the device manufacturer and uptime.
- **Defensive Note**: SNMP enumeration is rarely noticed by IDS systems because SNMP traffic volume is typically low and uses connectionless UDP.

---

## SMTP User Enumeration

Mail servers listening on TCP ports 25, 465 (SMTPS), and 587 (submission) can be queried to validate email addresses and enumerate internal users.

- **VRFY Command**: The `VRFY` command asks the server to verify a mailbox. If the mailbox exists, the server returns user information; if not, an error code.
- **EXPN Command**: The `EXPN` command expands a mailing list alias into its member addresses.
- **RCPT TO Probing**: Even when `VRFY` and `EXPN` are disabled, the `RCPT TO:` command in the SMTP envelope returns different status codes for valid and invalid recipients during the mail transaction.
  ```bash
  # SMTP user enumeration with smtp-user-enum
  smtp-user-enum -M VRFY -U users.txt -t mail.target.com
  smtp-user-enum -M RCPT -U users.txt -t mail.target.com
  ```
- **NTLM Info Leakage via SMTP**: Exchange servers configured with NTLM authentication on port 587 can leak internal hostnames and domain names through the NTLM challenge-response handshake, even without valid credentials.
  ```bash
  nmap -p 587 --script smtp-ntlm-info mail.target.com
  ```

---

## RDP NLA & CredSSP Fingerprinting

Remote Desktop Protocol (TCP port 3389) reveals operating system version, fully qualified domain name (FQDN), and NLA/CredSSP configuration through its TLS handshake and initial `x.224 Connection Request` packet.

- **NLA (Network Level Authentication) Detection**: NLA requires clients to authenticate before establishing a full RDP session. The presence of NLA indicates a modern Windows Server/Desktop configured with security best practices; its absence indicates legacy or embedded Windows systems (XP, Server 2003, Windows Embedded, IoT).
- **RDP Security Protocol Analysis**:
  ```bash
  # Extract RDP banner and NLA status
  nmap -p 3389 --script rdp-ntlm-info --script-args rdp-ntlm-info.protocols=ssl 192.168.1.1
  ```
- **CredSSP Fingerprinting**: Credential Security Support Provider (CredSSP) tunnels NTLM/Kerberos authentication through the RDP TLS channel. The NTLM challenge contains the target's NetBIOS name, DNS domain name, and DNS hostname.
- **TLS Certificate Analysis**: RDP servers present self-signed certificates with the machine's hostname in the `commonName` field. This passively reveals internal naming conventions (e.g., `SRV-DC01.corp.target.local`).

---

## NFS & RPC Service Enumeration

Network File System (NFS) and Remote Procedure Call (RPC) services running on UNIX/Linux hosts expose shared filesystems and service registries.

- **RPC Portmapper Enumeration** (TCP/UDP 111):
  The `rpcbind` service maps RPC program numbers to TCP/UDP ports, revealing all RPC-based services.
  ```bash
  rpcinfo -p 192.168.1.1
  nmap -sV -p 111 --script rpcinfo 192.168.1.1
  ```
- **NFS Export Enumeration** (TCP/UDP 2049):
  NFS exports configured without host-based access controls (`*` wildcards, `/24` CIDRs) can be mounted from any IP.
  ```bash
  showmount -e 192.168.1.1
  nmap -sV -p 111,2049 --script nfs-showmount 192.168.1.1
  ```
- **NFSv4 Pseudo-Filesystem**: NFSv4 consolidates mount points under a single pseudo-filesystem root (`/`). Mounting the root directory and recursively listing contents reveals the entire export tree without requiring the `showmount` utility.
  ```bash
  mount -t nfs 192.168.1.1:/ /mnt/nfs -o nolock
  ls -laR /mnt/nfs
  ```

---

## LDAP Anonymous Bind Enumeration

Lightweight Directory Access Protocol (LDAP) services on TCP ports 389 and 636 (LDAPS) may permit anonymous (unauthenticated) binds that leak Active Directory domain information, user lists, group memberships, and password policy configuration.

- **Anonymous Bind Testing**:
  ```bash
  ldapsearch -x -H ldap://192.168.1.1 -b "dc=target,dc=local" -s base "(objectClass=*)" namingcontexts
  ```
- **Naming Context Extraction**: The RootDSE query returns default naming contexts, revealing the exact AD domain DN structure.
- **User & Group Enumeration**:
  ```bash
  nmap -p 389 --script ldap-search --script-args 'ldap.username="",ldap.password="",ldap.qfilter="(objectClass=user)"' 192.168.1.1
  ```
- **Password Policy Retrieval**: Anonymous LDAP queries can read the domain password policy (minimum length, complexity requirements, lockout threshold) from the `domainPasswordPolicy` attribute.
  ```bash
  ldapsearch -x -H ldap://192.168.1.1 -b "dc=target,dc=local" "(objectClass=domainDNS)" lockoutDuration lockoutThreshold maxPwdAge minPwdLength
  ```
- **Defensive Telemetry**: Windows Event ID **2889** (Directory Service) logs successful anonymous LDAP binds. Event ID **1644** logs expensive/suspicious LDAP queries.

---

## DNSSEC & Zone Walking Analysis

Domain Name System Security Extensions (DNSSEC) add cryptographic signatures to DNS records. However, NSEC/NSEC3 records introduced for authenticated denial of existence can be abused for zone walking.

- **NSEC Zone Walking**: DNSSEC with NSEC records reveals the complete zone contents. Each NSEC record points to the "next" domain name in the zone in lexicographic order, enabling a full zone enumeration by iterating through NSEC responses.
  ```bash
  ldns-walk target.com
  nmap --script dns-nsec-enum --script-args dns-nsec-enum.domain=target.com
  ```
- **NSEC3 Mitigation**: NSEC3 hashes domain names before chaining records, making zone walking computationally feasible but significantly slower. Offline cracking of NSEC3 hashes using GPU-accelerated hashcat reveals the original subdomain names.
  ```bash
  # Collect NSEC3 hashes and crack offline
  hashcat -m 8300 -a 3 nsec3_hashes.txt ?l?l?l?l?l?l?l?l --increment
  ```
- **DNSSEC Validation Testing**: Query for DNSKEY, DS, and RRSIG records to determine whether the zone is properly signed and verify chain-of-trust integrity. Misconfigured DNSSEC can lead to resolvers falling back to unsigned responses.

---

## Advanced Service Fingerprinting & Banner Grabbing

Beyond simple port scanning, each service protocol yields unique fingerprints through protocol-specific probes.

### Protocol-Specific Probing
| Service | Port | Fingerprint Technique |
|---------|------|-----------------------|
| SSH | 22 | Banner string (`SSH-2.0-OpenSSH_8.9p1`), KEX algorithm offer |
| FTP | 21 | Banner (`220 FTP Server ready`), AUTH TLS command response |
| MySQL | 3306 | Greeting packet (version, salt, capabilities flags) |
| PostgreSQL | 5432 | Startup packet response (version, auth method) |
| Redis | 6379 | `INFO` command (version, OS, connected clients, keyspace) |
| MongoDB | 27017 | `ismaster` / `buildInfo` commands (version, replica set) |
| Elasticsearch | 9200 | `GET /` response (cluster name, version, lucene version) |
| Memcached | 11211 | `stats` command (version, uptime, item counts, slabs) |
| Docker | 2375/2376 | `GET /containers/json` (exposed Docker daemon API) |
| Kubernetes | 6443, 10250 | `GET /version` on kubelet API, `/api/v1/pods` |
| RabbitMQ | 15672 | `/api/overview` management endpoint |
| Jenkins | 8080 | `/api/json?pretty=true` instance info, `/script` Groovy console |
| Cisco Smart Install | 4786 | `copy tftp flash` command without authentication |

- **Aggregator**: [Dockerized banner grabbing](https://github.com/ncrocfer/whatportis) with WhatPortIs or a custom Nmap NSE script pipeline.

### TCP/IP Stack Fingerprinting
Operating system identification via passive TCP/IP analysis (p0f-style) reveals kernel version and architecture without sending a single probe packet.
- **TTL (Time to Live) Analysis**: Initial packet TTL values correlate strongly with OS families:
  - 64: Linux/FreeBSD/macOS.
  - 128: Windows.
  - 255: Solaris, Cisco IOS, network devices.
- **TCP Window Size**: Window scaling factors and initial window sizes form a unique OS signature.
- **Don't Fragment (DF) Bit**: Linux kernels set DF=1 on all packets; Windows sets DF=0 for non-PMTU-discovery traffic.
- **Timestamp Option Order**: TCP options ordering (MSS, Window Scale, SACK Permitted, Timestamp) differs predictably between OS stacks.

---

## SIP / VoIP Infrastructure Enumeration

Session Initiation Protocol (SIP) on UDP/TCP port 5060 (and TLS on 5061) powers enterprise VoIP phone systems (Cisco Unified Communications Manager, Avaya Aura, Asterisk/FreePBX).

- **SIP OPTIONS Flooding**: The `OPTIONS` method returns supported methods, server version, and User-Agent strings without requiring authentication.
  ```bash
  svmap 192.168.1.0/24 -p 5060
  ```
- **Extension Enumeration via INVITE/REGISTER Response Analysis**: Even when registration fails, the server response differentiates between valid extensions (`401 Unauthorized`) and invalid extensions (`404 Not Found`), enabling user enumeration.
  ```bash
  svwar -m INVITE -e 1000-2000 192.168.1.1
  ```
- **VoIP VLAN Discovery**: Cisco IP phones often use CDP (Cisco Discovery Protocol) or LLDP (Link Layer Discovery Protocol) to negotiate the voice VLAN. This reveals the dedicated VoIP network segment segregated from corporate data traffic.
- **SIP Security**: Default credentials (e.g., `admin:admin` on FreePBX), unencrypted RTP media streams, and TFTP provisioning servers (`port 69`) serving unencrypted phone configuration files with SIP credentials in plaintext XML.

---

## Defensive Analysis: Port Scan Telemetry

Active network scanning triggers immediate intrusion detection system alerts.

- **Firewall & IPS Event Correlation**: Network gateways monitor incoming TCP connection states. Scans are identified by:
  - **SYN Scans**: High volume of TCP SYN packets followed immediately by RST packets (half-open scanning).
  - **FIN/NULL/Xmas Scans**: Packets with unusual flag combinations that bypass standard stateless firewalls.
- **Defensive Mitigations**:
  - **Fail2ban / IP Tables Rate Limiting**: Block IPs that exceed a specified number of new connections per second.
  - **Port Knocking**: Hide sensitive ports (like SSH/RDP) behind a sequence of closed-port connection attempts.
