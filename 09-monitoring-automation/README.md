# 09. Monitoring & Continuous Reconnaissance

Reconnaissance is a continuous process. Implementing automation pipelines allows you to detect new assets, updated DNS records, and newly deployed services the moment they go live.

---

## Table of Contents
- [Continuous Asset Monitoring](#continuous-asset-monitoring)
- [Cron-Based Differential Tracking](#cron-based-differential-tracking)
- [Distributed Scanning Frameworks](#distributed-scanning-frameworks)
- [Notification Engines](#notification-engines)

---

## Continuous Asset Monitoring

Monitoring tracking databases and public log streams helps surface target infrastructure modifications.

### Tools for Asset Monitoring
- **[Sublert](https://github.com/yassineaboukir/sublert)**: A python script that queries crt.sh certificate logs for specified domains and sends Slack notifications when new subdomains are discovered.
- **[CertStream](https://certstream.calidog.io/)**: Monitors real-time SSL/TLS certificate issuances. Useful for tracking new hosts as they are initialized.
- **[Findomain Monitoring](https://findomain.app/)**: Findomain features a dedicated database flag to monitor subdomains and track new entries:
  ```bash
  findomain -t example.com --monitoring --postgres-database bbh
  ```

---

## Cron-Based Differential Tracking

You can set up local cron scripts to execute scanning tools daily and compare the current findings against previous logs.

### Differential Recon Shell Script
The following bash script executes subdomain discovery and outputs only the *newly added* domains to a notification channel.

```bash
#!/bin/bash
# run_recon.sh

TARGET="example.com"
DATA_DIR="/data/recon/$TARGET"
mkdir -p "$DATA_DIR"

# Run passive discovery
subfinder -d "$TARGET" -silent -o "/tmp/subs_today.txt"

# If previous results do not exist, initialize database
if [ ! -f "$DATA_DIR/subs_database.txt" ]; then
    mv "/tmp/subs_today.txt" "$DATA_DIR/subs_database.txt"
    echo "[+] Initialized subdomain database for $TARGET"
    exit 0
fi

# Compare today's run with database
sort -u "/tmp/subs_today.txt" -o "/tmp/subs_today.txt"
sort -u "$DATA_DIR/subs_database.txt" -o "$DATA_DIR/subs_database.txt"

# Extract new entries
comm -13 "$DATA_DIR/subs_database.txt" "/tmp/subs_today.txt" > "$DATA_DIR/new_subs.txt"

# If new subdomains found, alert and merge
if [ -s "$DATA_DIR/new_subs.txt" ]; then
    echo "[!] New subdomains discovered:"
    cat "$DATA_DIR/new_subs.txt"
    
    # Forward results to Slack/Discord via notify
    cat "$DATA_DIR/new_subs.txt" | notify -id discord_recon
    
    # Append to main database
    cat "$DATA_DIR/new_subs.txt" >> "$DATA_DIR/subs_database.txt"
fi

# Clean up
rm "/tmp/subs_today.txt"
```

To run this script automatically every day at 12:00 AM, append the following line to your crontab (`crontab -e`):
```text
0 0 * * * /bin/bash /opt/scripts/run_recon.sh
```

---

## Distributed Scanning Frameworks

For large-scale targets, distributing scans across multiple cloud hosts shortens execution windows and splits network traffic footprints.

### Axiom (Distributed Cloud Scanning)
- **[Axiom](https://github.com/pry0cc/axiom)**: Spins up ephemeral VPS fleets across cloud providers (DigitalOcean, AWS, Linode) to distribute tasks like port scanning, HTTP checking, or path fuzzing.
  ```bash
  # Initialize a fleet of 10 scanning instances
  axiom-fleet -i 10
  
  # Distribute a subdomain resolution task across the fleet
  axiom-scan resolved_subs.txt -m httpx -o live_hosts.txt --fleet 10
  
  # Delete fleet instances when scan is complete
  axiom-rm f
  ```

---

## Notification Engines

Sending live data feeds to messaging platforms ensures you can validate issues immediately.

- **[Notify (ProjectDiscovery)](https://github.com/projectdiscovery/notify)**: Standard tool for streaming console outputs directly to Slack, Discord, Telegram, or custom webhooks.
  Configuration file is located at `~/.config/notify/provider-config.yaml`.
  ```yaml
  # Config template
  discord:
    - id: "discord_recon"
      discord_webhook_url: "https://discord.com/api/webhooks/YOUR_KEY"
  ```
  Usage:
  ```bash
  nuclei -l new_hosts.txt -t nuclei-templates/ -severity critical | notify -id discord_recon
  ```
