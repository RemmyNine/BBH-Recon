# 10. Reporting, Resources & One-Liner Cheat Sheets

Creating a clear report is crucial for bug bounty hunting and pentesting. This section covers reporting structures, essential wordlists, learning resources, and one-liner pipelines.

---

## Table of Contents
- [Reporting Framework](#reporting-framework)
- [Essential Wordlists](#essential-wordlists)
- [One-Liner Cheat Sheets](#one-liner-cheat-sheets)

---

## Reporting Framework

A professional vulnerability report should clearly describe the vulnerability, its business impact, and how to fix it.

### Standard Report Template
1. **Title**: Structured, vulnerability-class specific (e.g., `Stored XSS in /api/profile allows Session Hijacking`).
2. **CWE Reference**: (e.g., `CWE-79: Improper Neutralization of Input During Web Page Generation`).
3. **Severity / CVSS**: Precise calculator breakdown (e.g., `CVSS v3.1 Score: 8.2 High`).
4. **Summary**: A concise technical description of the vulnerability.
5. **Business Impact**: Explain what an attacker can achieve (e.g., unauthorized data modification, access to corporate data).
6. **Steps to Reproduce**: Numbered, step-by-step reproduction instructions. Always supply raw HTTP requests or copy-pasteable scripts.
7. **Proof of Concept (PoC)**: Embed annotated screenshots, videos, or scripts.
8. **Remediation**: Actionable patching advice.

---

## Essential Wordlists

| Wordlist Purpose | Recommended Wordlist Source |
|------------------|-----------------------------|
| Subdomain Bruteforcing | [Assetnote commons.txt](https://wordlists.assetnote.io/) or [JHaddix all.txt](https://gist.github.com/jhaddix/86a06c5dc309d08580a018c66354a056) |
| Directory Discovery | [SecLists/Discovery/Web-Content/raft-large-directories.txt](https://github.com/danielmiessler/SecLists) |
| API Route Discovery | [Assetnote routes-large.txt](https://wordlists.assetnote.io/) |
| Parameter Fuzzing | [SecLists/Discovery/Web-Content/burp-parameter-names.txt](https://github.com/danielmiessler/SecLists) |
| Credentials & Password Lists | [SecLists/Passwords/Common-Credentials/10-million-password-list-top-100000.txt](https://github.com/danielmiessler/SecLists) |

---

## One-Liner Cheat Sheets

These commands combine multiple tools to automate standard workflows.

### 1. Full Subdomain Discovery Pipeline
```bash
# Set Target
TARGET="example.com"
OUTPUT="recon_results/$TARGET"
mkdir -p "$OUTPUT"

# Run passive aggregators
subfinder -d "$TARGET" -silent > "$OUTPUT/passive.txt"
assetfinder --subs-only "$TARGET" >> "$OUTPUT/passive.txt"
sort -u "$OUTPUT/passive.txt" -o "$OUTPUT/passive.txt"

# Resolve and filter live hosts
cat "$OUTPUT/passive.txt" | httpx -silent -status-code -tech-detect -o "$OUTPUT/live_hosts.txt"
```

### 2. Extract Endpoints from JavaScript Files
```bash
# Extract JS files, download them, and search for relative path references
cat "$OUTPUT/live_hosts.txt" | awk '{print $1}' | subjs \
  | xargs -I{} curl -s -k {} | grep -oE "\/[a-zA-Z0-9_.-]{2,}\/[a-zA-Z0-9_/.-]*" \
  | sort -u > "$OUTPUT/extracted_paths.txt"
```

### 3. Exposed .git Directories Check
```bash
# Check if /.git/HEAD is publicly accessible on live web hosts
cat "$OUTPUT/live_hosts.txt" | awk '{print $1}' \
  | xargs -I{} curl -s -o /dev/null -w "%{http_code} {}\n" "{}/.git/HEAD" \
  | grep "^200" > "$OUTPUT/exposed_git_repos.txt"
```

### 4. S3 Bucket Public Listing Check
```bash
# Enumerate basic name permutations of a target organization for open S3 access
for suffix in backup assets dev prod logs staging static; do
    aws s3 ls "s3://example-$suffix" --no-sign-request 2>/dev/null && echo "[OPEN BUCKET] s3://example-$suffix"
done
```
