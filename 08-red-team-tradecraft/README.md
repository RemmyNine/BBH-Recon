# 08. Red Team Tradecraft, Infrastructure & Detection Engineering

This section covers the theoretical mechanics of Red Team infrastructure design, stealthy reconnaissance, and the corresponding defensive telemetry used by Blue Teams to detect and mitigate these activities.

---

## Table of Contents
- [Tiered Infrastructure Architecture (C2 Design)](#tiered-infrastructure-architecture-c2-design)
  - [Defensive Analysis: JARM & JA3/JA4 Fingerprinting](#defensive-analysis-jarm--ja3ja4-fingerprinting)
- [External Active Directory & Tenant Profiling](#external-active-directory--tenant-profiling)
  - [Defensive Analysis: Monitoring Tenant Footprints](#defensive-analysis-monitoring-tenant-footprints)
- [Defense Evasion in Network Reconnaissance](#defense-evasion-in-network-reconnaissance)
  - [Defensive Analysis: Beaconing & Scan Detection](#defensive-analysis-beaconing--scan-detection)
- [Edge Device & Initial Access Profiling](#edge-device--initial-access-profiling)
  - [Defensive Analysis: Perimeter Hardening & Threat Telemetry](#defensive-analysis-perimeter-hardening--threat-telemetry)

---

## Tiered Infrastructure Architecture (C2 Design)

Modern Red Team operations separate the primary Command & Control (C2) servers from direct interaction with the target network. This is achieved using a tiered proxy model.

```mermaid
graph TD
    Target[Target Network] -->|HTTP/HTTPS Traffic| Redirector[Tier 1 Redirector (CDN / Nginx)]
    Redirector -->|Proxy Forwarding| TeamServer[Tier 2 C2 Team Server]
    TeamServer -->|Administrative Access| Operator[Red Team Operator Console]
    
    style Target fill:#f9f,stroke:#333,stroke-width:2px
    style Redirector fill:#bbf,stroke:#333,stroke-width:2px
    style TeamServer fill:#fbb,stroke:#333,stroke-width:2px
```

### 1. Tier 1: Front-end Redirectors
- **Purpose**: Receive incoming agent beacons or scanning callbacks.
- **Mechanics**: Configured using standard reverse proxies (Nginx, Apache) or Content Delivery Networks (CDNs).
- **Domain Fronting**: An evasion technique where a request is routed through a major CDN provider, masking the true host header. While many CDNs have restricted this, custom configurations (e.g., abusing HTTP Host headers on legacy servers) are still analyzed in academic evasion studies.

### 2. Tier 2: Team Servers
- **Purpose**: Manage agent states, deliver tasking, and compile execution logs.
- **OpSec Rule**: Team servers must never interact with the target directly. Access is restricted exclusively to authorized operator IPs via SSH tunnels or VPNs.

---

### Defensive Analysis: JARM & JA3/JA4 Fingerprinting

Security monitoring systems detect custom redirectors and C2 listeners without analyzing the payloads themselves, by looking at SSL/TLS handshake behaviors.

#### JARM (Active TLS Fingerprinting)
JARM is an active TLS fingerprinting tool. It sends 10 customized TLS Client Hello packets to a target port and analyzes the server responses to compile a 62-character cryptographic fingerprint.
- **Detection**: C2 frameworks (e.g., Cobalt Strike, Sliver) have default JARM signatures. Security tools search Shodan/Censys for these signatures to flag malicious servers.
- **Mitigation**: Red Teams configure Nginx/Apache redirectors to use standard, unmodified TLS stacks (like default Debian Apache configurations) to blend in. Blue Teams monitor inbound traffic to identify mismatching certificates/JARM signatures.

#### JA3/JA4 (Passive TLS Fingerprinting)
JA3/JA4 hashes the parameters of the TLS Client Hello packet sent by the client.
- **Detection**: If a scanner or C2 agent uses a custom TLS library (e.g., Go’s `crypto/tls` or custom Python sockets), its JA3/JA4 fingerprint will differ from standard browsers like Chrome or Edge.
- **Rule Example (Suricata)**:
  ```text
  alert tls $HOME_NET any -> $EXTERNAL_NET any (msg:"MALICIOUS JA3/JA4 SSL Client Fingerprint Detected"; ja3.hash:"[KNOWN_MALICIOUS_HASH]"; sid:1000001; rev:1;)
  ```

---

## External Active Directory & Tenant Profiling

During external reconnaissance, mapping a target’s Identity Provider (IdP) infrastructure reveals active usernames, email structures, and authentication portals.

### 1. Microsoft 365 / Azure AD Tenant Discovery
Microsoft exposes specific endpoints that allow organizations to query domain federation status passively.

- **Mechanics**: Querying the OpenID Configuration or Autodiscover endpoints reveals details about the tenant.
  - Endpoint: `https://login.microsoftonline.com/getuserrealm.aspx?login=user@target.com&xml=1`
  - Response Data:
    - `NameSpaceType`: Identifies whether the domain is `Managed` (handled directly by Azure AD) or `Federated` (redirected to an on-premise ADFS server).
    - `FederationBrandName`: Indicates the primary identity provider domain name.
    - `AuthURL`: The exact URL where users are redirected to authenticate (e.g., ADFS portal).

### 2. Identity Provider Fingerprinting
Organizations routing authentication through external services expose login endpoints:
- **Okta**: `https://target.okta.com`
- **Active Directory Federation Services (ADFS)**: `/adfs/ls/idpinitiatedsignon.aspx`
- **PingFederate**: `/pingfederate/`

---

### Defensive Analysis: Monitoring Tenant Footprints

Defenders monitor Azure Active Directory and on-premise Active Directory access to block tenant enumeration and brute-forcing.

- **Mitigation Strategies**:
  - **Tenant Restrictions**: Configure firewall or web gateway rules to restrict outbound M365 access only to approved corporate directory tenants.
  - **Blocking Legacy Authentication**: Disable legacy protocols (e.g., IMAP, POP3, SMTP authentication) that bypass Multi-Factor Authentication (MFA).
- **Log Correlation**: Monitor Azure Active Directory Sign-in Logs (specifically Event ID `4625` on ADFS or failed sign-in status codes like `50053` - Account Locked, `50126` - Invalid Credentials).

---

## Defense Evasion in Network Reconnaissance

Aggressive port scanning triggers immediate alerts on modern Security Information and Event Management (SIEM) systems. Defensive evasion during scanning focuses on minimizing signature detection.

### 1. Time Domain Manipulation (Slow and Low)
Standard scanners send packets in rapid bursts. Evasion relies on extending the delay between packets to prevent threshold-based IDS triggers.
- **Mechanics**: Setting randomized intervals (jitter) between port queries. For example, sending one port probe every 5–10 minutes from a rotating IP network.

### 2. Protocol Blending
- **User-Agent Customization**: Modifying HTTP headers to match the typical software profile of the target organization (e.g., matching the specific browser versions used by corporate employees).
- **TLS Cipher Suite Alignment**: Ensuring that scanning tools utilize the identical cipher ordering and client flags as standard web browsers, avoiding default curl or Python footprints.

---

### Defensive Analysis: Beaconing & Scan Detection

Blue Teams use statistical and network flow analysis to detect low-and-slow scanning operations.

- **NetFlow / IPFIX Tracking**:
  - **Beaconing Detection**: Analyzing NetFlow data for consistent connections over long intervals (e.g., a single packet sent exactly every 60 seconds).
  - **Statistical Outliers**: Identifying external IPs that connect to multiple distinct destination ports but transfer zero payload data.
- **Sigma Detection Rule Concept**:
  ```yaml
  title: Network Scan via Port Outlier Analysis
  status: experimental
  description: Detects an external IP scanning multiple ports within a sliding window.
  logsource:
      category: firewall
  detection:
      selection:
          action: blocked
      filter:
          destination_port|count: 10
          destination_ip|count_distinct: 1
      timeframe: 5m
      condition: selection and filter
  ```

---

## Edge Device & Initial Access Profiling

External perimeter systems, such as virtual private networks (VPNs) and firewalls, serve as gatekeepers to the internal network.

### 1. Edge Device Identification
Attack surface mapping involves cataloging the model, manufacturer, and software version of all internet-facing gateways:
- **Fortinet FortiGate**: Identified via `/remote/login` or specific CSS parameters.
- **Palo Alto GlobalProtect**: Identified by specific XML schemas on `/global-protect/`.
- **Pulse Secure / Ivanti**: Identified via `/dana-na/`.

### 2. Software Vulnerability Mapping
Cross-referencing discovered edge device versions with public databases (such as the CISA Known Exploited Vulnerabilities (KEV) Catalog) provides immediate insight into organizational patching latency.

---

## Defensive Analysis: Perimeter Hardening & Threat Telemetry

Securing edge devices requires rigorous authentication, patching, and access control policies.

- **Mitigation & Defense**:
  - **Multi-Factor Authentication (MFA)**: Enforce MFA (preferably FIDO2 hardware tokens) on all external gateways.
  - **Geofencing**: Restrict access to administrative interfaces based on originating country or specific source IP ranges.
  - **Virtual Patching**: Deploy Web Application Firewalls (WAFs) configured with virtual patches for critical edge vulnerabilities while waiting for system administrators to apply vendor updates.
- **Threat Hunting Logs**:
  - Review VPN authentication logs for geographically impossible logins (e.g., a user authenticates from London and Tokyo within 30 minutes).
  - Track requests targeting unusual endpoints on edge appliances (such as `/remote/fgt_lang` or other path patterns associated with historic vulnerabilities).
