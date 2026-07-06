<#
.SYNOPSIS
    Magnus - Offensive Security Bug Bounty & Recon Automation Script
.DESCRIPTION
    A modular PowerShell recon automation framework covering subdomain enumeration,
    live HTTP discovery, port scanning, endpoint collection, content discovery,
    technology fingerprinting, takeover checks, vulnerability scanning, and crawling.

    Author  : RemmyNine
    License : GPL-3.0
    Repo    : https://github.com/RemmyNine/OffensiveSecurity

.PARAMETER Target
    Target domain or file containing targets (e.g., example.com or targets.txt).
    Used with: --recon, --passive, --content, --tech, --takeover, --vuln, --crawl, --endpoints

.PARAMETER Recon
    Full recon workflow: passive subdomain enumeration -> DNS resolution ->
    HTTP live discovery (with proper User-Agent & rate limits) -> top-ports scan.

.PARAMETER Endpoints
    Wayback Machine + GAU endpoint collection. Merges, deduplicates, and cleans URLs.

.PARAMETER Content
    Directory / path fuzzing on live hosts using FFuF with smart rate-limiting.

.PARAMETER Tech
    Technology stack fingerprinting (Wappalyzer signatures) on live HTTP hosts.

.PARAMETER Takeover
    Subdomain takeover check using Nuclei takeover templates and Subzy.

.PARAMETER Vuln
    Run Nuclei vulnerability templates against live HTTP/HTTPS hosts.

.PARAMETER Passive
    Passive-only reconnaissance (Subfinder + crt.sh + Assetfinder, no active probing).

.PARAMETER Crawl
    Recursive crawling with Katana to extract endpoints, forms, and JS file URLs.

.PARAMETER Ports
    Comprehensive port scan (top 1000) with service version detection via Nmap on live hosts.

.PARAMETER Concurrency
    Thread count for tools that support it. Default: 25.

.PARAMETER OutputDir
    Base output directory. Default: .\magnus-out\<target>\
.EXAMPLE
    .\magnus.ps1 --recon example.com
    .\magnus.ps1 --recon targets.txt
    .\magnus.ps1 -gp example.com
    .\magnus.ps1 --content example.com
    .\magnus.ps1 --takeover subs.txt
    .\magnus.ps1 --vuln example.com --concurrency 15
#>

[CmdletBinding(DefaultParameterSetName = 'Recon')]
param(
    [Parameter(Position = 0, Mandatory = $false)]
    [string]$Target,

    [Parameter(ParameterSetName = 'Recon')]
    [switch]$Recon,

    [Parameter(ParameterSetName = 'Endpoints')]
    [Alias('gp')]
    [switch]$Endpoints,

    [Parameter(ParameterSetName = 'Content')]
    [switch]$Content,

    [Parameter(ParameterSetName = 'Tech')]
    [switch]$Tech,

    [Parameter(ParameterSetName = 'Takeover')]
    [switch]$Takeover,

    [Parameter(ParameterSetName = 'Vuln')]
    [switch]$Vuln,

    [Parameter(ParameterSetName = 'Passive')]
    [switch]$Passive,

    [Parameter(ParameterSetName = 'Crawl')]
    [switch]$Crawl,

    [Parameter(ParameterSetName = 'Ports')]
    [switch]$Ports,

    [ValidateRange(5, 100)]
    [int]$Concurrency = 25,

    [string]$OutputDir,

    [Alias('h')]
    [switch]$Help
)

# ----------------------------------------------------------------------------
# Banner, Config & Bootstrap
# ----------------------------------------------------------------------------
$Banner = @"

  __  __                               
 |  \/  |  __ _  _ _   __ _  _  _  ___
 | |\/| | / _` || ' \ / _` || || |(_-<
 |_|  |_| \__, ||_||_|\__, | \_,_|/__/
           |___/       |___/           
       Offensive Security * BBH + Red Team
"@

Write-Host $Banner -ForegroundColor Cyan

$ScriptRoot   = $PSScriptRoot
$Timestamp    = Get-Date -Format "yyyyMMdd_HHmmss"

# -- Default output directory --
if (-not $OutputDir) {
    $SafeName   = if ($Target -match '\.') { $Target -replace '[\\/:*?"<>|]', '_' } else { "multi-target" }
    $OutputDir  = Join-Path (Get-Location) "magnus-out\$SafeName"
}

$SubsDir      = Join-Path $OutputDir "subdomains"
$HttpDir      = Join-Path $OutputDir "http"
$PortsDir     = Join-Path $OutputDir "ports"
$ContentDir   = Join-Path $OutputDir "content"
$EndpointsDir = Join-Path $OutputDir "endpoints"
$TechDir      = Join-Path $OutputDir "tech"
$TakeoverDir  = Join-Path $OutputDir "takeover"
$VulnDir      = Join-Path $OutputDir "vuln"
$CrawlDir     = Join-Path $OutputDir "crawl"

$AllDirs = @($SubsDir, $HttpDir, $PortsDir, $ContentDir, $EndpointsDir, $TechDir, $TakeoverDir, $VulnDir, $CrawlDir)

foreach ($Dir in $AllDirs) {
    if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
}

# -- Resolver & Wordlist paths (set these to your local paths) --
$ResolversFile  = Join-Path $ScriptRoot "resolvers.txt"
$SubsWordlist   = Join-Path (Join-Path $ScriptRoot "wordlists") "subdomains-top1m.txt"
$ContentWordlist = Join-Path (Join-Path $ScriptRoot "wordlists") "raft-medium-directories.txt"
$Permutations   = Join-Path (Join-Path $ScriptRoot "wordlists") "permutations.txt"

# Download default resolvers if missing
if (-not (Test-Path $ResolversFile)) {
    Write-Host "[*] Downloading verified resolvers..." -ForegroundColor Yellow
    try {
        Invoke-WebRequest -Uri "https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt" `
            -OutFile $ResolversFile -ErrorAction Stop
    } catch {
        Write-Host "[!] Failed to download resolvers. Using fallback list." -ForegroundColor Red
        @"
8.8.8.8
8.8.4.4
1.1.1.1
1.0.0.1
9.9.9.9
"@ | Out-File -FilePath $ResolversFile -Encoding utf8
    }
}

# -- User-Agent rotation list (modern browser profiles) --
$UserAgents = @(
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36 Edg/126.0.0.0"
)

function Get-RandomUA {
    return $UserAgents[(Get-Random -Maximum $UserAgents.Count)]
}

# -- Rate-limit delay (ms) --
$RateLimitDelay = 1500

# ----------------------------------------------------------------------------
# Helper Functions
# ----------------------------------------------------------------------------

function Write-Step {
    param([string]$Message)
    Write-Host "`n============================================================" -ForegroundColor DarkGray
    Write-Host " >> $Message" -ForegroundColor Green
    Write-Host "============================================================" -ForegroundColor DarkGray
}

function Resolve-Target {
    param([string]$Input)
    $InputFile  = Join-Path $OutputDir "targets.txt"
    $TargetList = @()

    if (Test-Path -LiteralPath $Input) {
        Write-Host "[i] Reading targets from file: $Input" -ForegroundColor Gray
        $TargetList = Get-Content -LiteralPath $Input | Where-Object { $_ -match '\S' } | ForEach-Object { $_.Trim() }
    } else {
        Write-Host "[i] Single target: $Input" -ForegroundColor Gray
        $TargetList = @($Input.Trim())
    }

    $TargetList | ForEach-Object {
        $_ -replace '^https?://', '' -replace '/.*$', ''
    } | Sort-Object -Unique | Out-File -FilePath $InputFile -Encoding utf8

    return $InputFile, $TargetList
}

function Invoke-RateLimited {
    param([scriptblock]$ScriptBlock, [string]$Description)
    try {
        & $ScriptBlock
    } catch {
        Write-Host "[!] $Description failed: $_" -ForegroundColor Red
    }
    Start-Sleep -Milliseconds $RateLimitDelay
}

# ----------------------------------------------------------------------------
# 1. PASSIVE RECON
# ----------------------------------------------------------------------------
function Invoke-PassiveRecon {
    param([string]$TargetDomain, [string]$OutFile)
    Write-Step "PASSIVE SUBDOMAIN ENUMERATION - $TargetDomain"

    $tmpSubfinder = "$env:TEMP\subfinder_$Timestamp.txt"
    $tmpAssetfinder = "$env:TEMP\assetfinder_$Timestamp.txt"
    $tmpCrtsh = "$env:TEMP\crtsh_$Timestamp.txt"

    Write-Host "[+] subfinder" -ForegroundColor Gray
    try { subfinder -d $TargetDomain -all -silent -o $tmpSubfinder } catch { Write-Host "[!] subfinder missing or failed" -ForegroundColor Red }

    Write-Host "[+] assetfinder" -ForegroundColor Gray
    try { assetfinder --subs-only $TargetDomain | Out-File -FilePath $tmpAssetfinder -Encoding utf8 } catch { Write-Host "[!] assetfinder missing or failed" -ForegroundColor Red }

    Write-Host "[+] crt.sh" -ForegroundColor Gray
    try {
        $CrtshUri = "https://crt.sh/?q=%25.$TargetDomain" + '&output=json'
        $CrtshResp = Invoke-RestMethod -Uri $CrtshUri -TimeoutSec 30
        $CrtshResp | ForEach-Object { $_.name_value } | ForEach-Object { $_ -split '\n' } |
            Where-Object { $_ -like "*.$TargetDomain" -or $_ -eq $TargetDomain } | Sort-Object -Unique |
            Out-File -FilePath $tmpCrtsh -Encoding utf8
    } catch { Write-Host "[!] crt.sh query failed" -ForegroundColor Red }

    Write-Host "[*] Merging and deduplicating passive results..." -ForegroundColor Yellow
    @($tmpSubfinder, $tmpAssetfinder, $tmpCrtsh) | ForEach-Object {
        if (Test-Path $_) { Get-Content -LiteralPath $_ }
    } | Where-Object { $_ -match '\S' } | Sort-Object -Unique | Out-File -FilePath $OutFile -Encoding utf8

    $Count = (Get-Content -LiteralPath $OutFile | Measure-Object).Count
    Write-Host "[+] Passive recon complete: $Count unique subdomains" -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# 2. DNS RESOLUTION
# ----------------------------------------------------------------------------
function Invoke-DNSResolve {
    param([string]$SubsIn, [string]$ResolvedOut)
    Write-Step "DNS RESOLUTION"

    if (-not (Get-Command puredns -ErrorAction SilentlyContinue)) {
        Write-Host "[!] puredns not found - falling back to dnsx" -ForegroundColor Red
        if (Get-Command dnsx -ErrorAction SilentlyContinue) {
            dnsx -l $SubsIn -r $ResolversFile -silent -o $ResolvedOut
        } else {
            Write-Host "[!] No DNS resolver available. Skipping resolution." -ForegroundColor Red
            Copy-Item -LiteralPath $SubsIn -Destination $ResolvedOut -Force
        }
        return
    }

    puredns resolve $SubsIn -r $ResolversFile --write-wildcards -o $ResolvedOut
    $Resolved = (Get-Content -LiteralPath $ResolvedOut -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "[+] Resolved subdomains: $Resolved" -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# 3. HTTP LIVE DISCOVERY
# ----------------------------------------------------------------------------
function Invoke-HTTPDiscovery {
    param([string]$ResolvedIn)
    Write-Step "HTTP/HTTPS LIVE DISCOVERY"

    $LiveHttp  = Join-Path $HttpDir "live-http.txt"
    $LiveHttps = Join-Path $HttpDir "live-https.txt"
    $AllLive   = Join-Path $HttpDir "live-all.txt"

    if (-not (Get-Command httpx -ErrorAction SilentlyContinue)) {
        Write-Host "[!] httpx not found. Skipping HTTP discovery." -ForegroundColor Red
        return $null
    }

    # HTTP probe
    httpx -l $ResolvedIn -silent -title -status-code -tech-detect -websocket `
        -random-agent -threads $Concurrency -rate-limit 10 -timeout 8 `
        -o $LiveHttp -http-probe -http2

    # HTTPS probe
    httpx -l $ResolvedIn -silent -title -status-code -tech-detect `
        -random-agent -threads $Concurrency -rate-limit 10 -timeout 8 `
        -o $LiveHttps -http2

    @($LiveHttp, $LiveHttps) | ForEach-Object {
        if (Test-Path $_) { Get-Content -LiteralPath $_ }
    } | Sort-Object -Unique | Out-File -FilePath $AllLive -Encoding utf8

    $LiveCount = (Get-Content -LiteralPath $AllLive -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "[+] Live HTTP(S) hosts: $LiveCount" -ForegroundColor Green

    # Extract just the URLs (first column) for port scanning
    $LiveUrlsOut = Join-Path $HttpDir "live-urls.txt"
    Get-Content -LiteralPath $AllLive -ErrorAction SilentlyContinue | ForEach-Object {
        ($_ -split '\s+')[0]
    } | Where-Object { $_ -match '^https?://' } | Sort-Object -Unique | Out-File -FilePath $LiveUrlsOut -Encoding utf8

    return $LiveUrlsOut
}

# ----------------------------------------------------------------------------
# 4. PORT SCAN (Top CDN-Common Ports)
# ----------------------------------------------------------------------------
function Invoke-PortScan {
    param([string]$LiveUrlsFile)
    Write-Step "PORT SCANNING (Top CDN-Common Ports)"

    if (-not (Get-Command naabu -ErrorAction SilentlyContinue)) {
        Write-Host "[!] naabu not found. Trying nmap..." -ForegroundColor Red
        if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
            Write-Host "[!] No port scanner available. Skipping." -ForegroundColor Red
            return
        }
        Invoke-NmapScan -InputFile $LiveUrlsFile
        return
    }

    # Top CDN-common ports: 80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090, 9443
    $TopPorts = "80,443,8080,8443,8000,8888,3000,5000,9090,9443"

    $UrlPorts = Join-Path $PortsDir "naabu-ports.txt"
    naabu -list $LiveUrlsFile -p $TopPorts -rate 500 -c $Concurrency -silent -o $UrlPorts

    if (Test-Path $UrlPorts) {
        $PortCount = (Get-Content -LiteralPath $UrlPorts | Measure-Object).Count
        Write-Host "[+] Open ports found: $PortCount entries" -ForegroundColor Green
    }
}

function Invoke-NmapScan {
    param([string]$InputFile)
    $NmapOut = Join-Path $PortsDir "nmap-ports.xml"
    $NmapTxt = Join-Path $PortsDir "nmap-ports.txt"
    $TopPorts = "80,443,8080,8443,8000,8888,3000,5000,9090,9443"

    $Targets = Get-Content -LiteralPath $InputFile | ForEach-Object { $_ -replace '^https?://', '' -replace ':\d+$', '' } | Sort-Object -Unique
    if (-not $Targets) { return }
    $TargetsStr = $Targets -join ' '

    nmap -p $TopPorts -sV --open --script http-title,ssl-cert `
        -T4 --max-retries 1 --max-rtt-timeout 1500ms `
        -oX $NmapOut -oN $NmapTxt $TargetsStr

    Write-Host "[+] Nmap scan complete -> $NmapTxt" -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# ENDPOINT COLLECTION (-gp / --endpoints)
# ----------------------------------------------------------------------------
function Invoke-EndpointCollection {
    param([string]$TargetDomain)
    Write-Step "ENDPOINT COLLECTION (Wayback + GAU)"

    $WaybackOut  = "$env:TEMP\wayback_$Timestamp.txt"
    $GauOut      = "$env:TEMP\gau_$Timestamp.txt"
    $MergedOut   = Join-Path $EndpointsDir "endpoints-merged.txt"
    $CleanedOut  = Join-Path $EndpointsDir "endpoints-cleaned.txt"

    Write-Host "[+] waybackurls" -ForegroundColor Gray
    try {
        echo $TargetDomain | waybackurls | Out-File -FilePath $WaybackOut -Encoding utf8
    } catch { Write-Host "[!] waybackurls failed" -ForegroundColor Red }

    Write-Host "[+] gau (Get All URLs)" -ForegroundColor Gray
    try {
        gau --subs --threads 5 $TargetDomain | Out-File -FilePath $GauOut -Encoding utf8
    } catch { Write-Host "[!] gau failed" -ForegroundColor Red }

    Write-Host "[*] Merging and deduplicating..." -ForegroundColor Yellow
    @($WaybackOut, $GauOut) | ForEach-Object {
        if (Test-Path $_) { Get-Content -LiteralPath $_ }
    } | Where-Object { $_ -match '\S' } | Sort-Object -Unique | Out-File -FilePath $MergedOut -Encoding utf8

    $MergedCount = (Get-Content -LiteralPath $MergedOut -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "[+] Merged endpoints: $MergedCount" -ForegroundColor Green

    # Clean with uro (dedup + filter boring extensions)
    Write-Host "[+] Cleaning with uro..." -ForegroundColor Gray
    if (Get-Command uro -ErrorAction SilentlyContinue) {
        Get-Content -LiteralPath $MergedOut | uro --no-filter-hasparams | Out-File -FilePath $CleanedOut -Encoding utf8
    } else {
        # Fallback: manual dedup filtering
        Get-Content -LiteralPath $MergedOut |
            Where-Object { $_ -notmatch '\.(css|ico|woff|woff2|svg|png|jpg|jpeg|gif|ttf|eot)(\?|$)' } |
            Sort-Object -Unique | Out-File -FilePath $CleanedOut -Encoding utf8
    }

    $CleanedCount = (Get-Content -LiteralPath $CleanedOut -ErrorAction SilentlyContinue | Measure-Object).Count
    Write-Host "[+] Cleaned endpoints: $CleanedCount" -ForegroundColor Green

    # Show interesting results
    Write-Host "`n===== INTERESTING ENDPOINTS =====" -ForegroundColor Cyan
    $Patterns = @("api", "v1", "v2", "admin", "upload", "download", "config", "backup", "debug", "graphql", "swagger", "openapi", ".json", ".xml", ".env", ".log", ".sql")
    $Interesting = Get-Content -LiteralPath $CleanedOut | ForEach-Object {
        foreach ($P in $Patterns) { if ($_ -match $P) { return $_; break } }
    }
    if ($Interesting) {
        $Interesting | Select-Object -First 80 | ForEach-Object { Write-Host "  $_" -ForegroundColor White }
    }
    Write-Host "==================================`n" -ForegroundColor Cyan

    Write-Host "[+] Results saved:" -ForegroundColor Green
    Write-Host "    Merged  : $MergedOut" -ForegroundColor Gray
    Write-Host "    Cleaned : $CleanedOut" -ForegroundColor Gray
}

# ----------------------------------------------------------------------------
# CONTENT DISCOVERY (--content)
# ----------------------------------------------------------------------------
function Invoke-ContentDiscovery {
    param([string]$Input)
    Write-Step "WEB CONTENT DISCOVERY"

    $ResolvedFile = Join-Path $HttpDir "live-urls.txt"
    $FfufDir      = Join-Path $ContentDir "ffuf"
    if (-not (Test-Path $FfufDir)) { New-Item -ItemType Directory -Path $FfufDir -Force | Out-Null }

    # Resolve live hosts first if they don't already exist
    if (-not (Test-Path $ResolvedFile)) {
        $PassiveSubs = Join-Path $SubsDir "passive-subs.txt"
        Invoke-PassiveRecon -TargetDomain $Input -OutFile $PassiveSubs
        $ResolvedSubs = Join-Path $SubsDir "resolved-subs.txt"
        Invoke-DNSResolve -SubsIn $PassiveSubs -ResolvedOut $ResolvedSubs
        $null = Invoke-HTTPDiscovery -ResolvedIn $ResolvedSubs
    }

    if (-not (Test-Path $ResolvedFile)) {
        Write-Host "[!] No live hosts found. Skipping content discovery." -ForegroundColor Red
        return
    }

    if (-not (Get-Command ffuf -ErrorAction SilentlyContinue)) {
        Write-Host "[!] ffuf not found. Skipping content discovery." -ForegroundColor Red
        return
    }

    # Ensure content wordlist exists
    $Wl = $ContentWordlist
    if (-not (Test-Path $Wl)) {
        Write-Host "[!] Content wordlist not found at: $Wl" -ForegroundColor Red
        Write-Host "[*] Using SecLists raft-medium-directories from GitHub..." -ForegroundColor Yellow
        $Wl = "$env:TEMP\raft-medium-directories.txt"
        try {
            Invoke-WebRequest -Uri "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-directories.txt" `
                -OutFile $Wl -ErrorAction Stop
        } catch { Write-Host "[!] Download failed. Skipping." -ForegroundColor Red; return }
    }

    $LiveUrls = Get-Content -LiteralPath $ResolvedFile | Where-Object { $_ -match '\S' }
    $MaxHosts = [Math]::Min($LiveUrls.Count, 15)

    Write-Host "[+] Fuzzing $MaxHosts live hosts..." -ForegroundColor Green

    for ($i = 0; $i -lt $MaxHosts; $i++) {
        $Url    = $LiveUrls[$i]
        $HostId = ($Url -replace 'https?://', '' -replace '[^a-zA-Z0-9]', '_')
        $FfufOut = Join-Path $FfufDir "${HostId}.json"

        Write-Host "  [$($i+1)/$MaxHosts] $Url" -ForegroundColor Gray
        try {
            ffuf -u "$Url/FUZZ" -w $Wl -mc 200,301,302,403,405 `
                -t 10 -rate 5 -p "1-3" `
                -H "User-Agent: $(Get-RandomUA)" `
                -o $FfufOut -of json -noninteractive `
                -timeout 8 2>$null
        } catch { Write-Host "    [!] FFuF error: $_" -ForegroundColor Red }
        Start-Sleep -Seconds 2
    }

    Write-Host "[+] Content discovery results saved to: $FfufDir" -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# TECHNOLOGY FINGERPRINTING (--tech)
# ----------------------------------------------------------------------------
function Invoke-TechFingerprint {
    param([string]$Input)
    Write-Step "TECHNOLOGY STACK FINGERPRINTING"

    $ResolvedFile = Join-Path $HttpDir "live-urls.txt"
    $TechOut      = Join-Path $TechDir "tech-stack.txt"
    $TechJson     = Join-Path $TechDir "tech-stack.json"

    # Resolve live hosts first
    if (-not (Test-Path $ResolvedFile)) {
        $PassiveSubs = Join-Path $SubsDir "passive-subs.txt"
        Invoke-PassiveRecon -TargetDomain $Input -OutFile $PassiveSubs
        $ResolvedSubs = Join-Path $SubsDir "resolved-subs.txt"
        Invoke-DNSResolve -SubsIn $PassiveSubs -ResolvedOut $ResolvedSubs
        $null = Invoke-HTTPDiscovery -ResolvedIn $ResolvedSubs
    }

    if (-not (Test-Path $ResolvedFile)) {
        Write-Host "[!] No live hosts found." -ForegroundColor Red
        return
    }

    if (-not (Get-Command httpx -ErrorAction SilentlyContinue)) {
        Write-Host "[!] httpx not found." -ForegroundColor Red
        return
    }

    httpx -l $ResolvedFile -silent -title -status-code -tech-detect -websocket `
        -server -cdn -ip -cname -random-agent -threads $Concurrency `
        -timeout 10 -o $TechOut -json -j $TechJson

    Write-Host "[+] Technology report" -ForegroundColor Green
    if (Test-Path $TechOut) {
        $TechLines = Get-Content -LiteralPath $TechOut
        Write-Host "  Live hosts with tech stack: $($TechLines.Count)" -ForegroundColor White

        # Summary
        Write-Host "`n---- TECH SUMMARY ----" -ForegroundColor Cyan
        $TechSummary = @{}
        $TechLines | ForEach-Object {
            $Line = $_
            if ($Line -match '\[([^\]]+)\]') {
                $Matches[1] -split ',' | ForEach-Object {
                    $T = $_.Trim()
                    if ($T) { $TechSummary[$T]++ }
                }
            }
        }
        $TechSummary.GetEnumerator() | Sort-Object Value -Descending |
            Select-Object -First 20 | ForEach-Object {
                Write-Host "  $($_.Key)  ($($_.Value) hosts)" -ForegroundColor White
            }
        Write-Host "-----------------------`n" -ForegroundColor Cyan
    }

    Write-Host "[+] Results saved to: $TechDir" -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# SUBDOMAIN TAKEOVER CHECK (--takeover)
# ----------------------------------------------------------------------------
function Invoke-TakeoverCheck {
    param([string]$Input)
    Write-Step "SUBDOMAIN TAKEOVER CHECK"

    $ResolvedFile = Join-Path $HttpDir "live-urls.txt"
    $NucleiTakeover = Join-Path $TakeoverDir "nuclei-takeovers.txt"
    $SubzyOut       = Join-Path $TakeoverDir "subzy-takeovers.txt"

    # Build subdomain list
    $SubFile = $Input
    if (-not (Test-Path $Input) -or (Get-Item -LiteralPath $Input).Length -eq 0) {
        $PassiveSubs = Join-Path $SubsDir "passive-subs.txt"
        if (Test-Path $PassiveSubs) {
            $SubFile = $PassiveSubs
        } else {
            $SubFile = Join-Path $SubsDir "passive-subs.txt"
            Invoke-PassiveRecon -TargetDomain $Input -OutFile $SubFile
        }
    }

    Write-Host "[+] Nuclei takeover scan..." -ForegroundColor Gray
    if (Get-Command nuclei -ErrorAction SilentlyContinue) {
        nuclei -l $SubFile -t ~/nuclei-templates/takeovers/ -silent `
            -concurrency $Concurrency -timeout 10 -o $NucleiTakeover 2>$null
    } else {
        Write-Host "[!] nuclei not found. Skipping." -ForegroundColor Red
    }

    Write-Host "[+] Subzy takeover check..." -ForegroundColor Gray
    if (Get-Command subzy -ErrorAction SilentlyContinue) {
        subzy run --targets $SubFile --concurrency $Concurrency --hide_fails | Out-File -FilePath $SubzyOut -Encoding utf8
    } else {
        Write-Host "[!] subzy not found. Skipping." -ForegroundColor Red
    }

    # Display findings
    Write-Host "`n===== TAKEOVER FINDINGS =====" -ForegroundColor Cyan
    if ((Test-Path $NucleiTakeover) -and ((Get-Content -LiteralPath $NucleiTakeover).Count -gt 0)) {
        Write-Host "  [Nuclei] Potential takeovers:" -ForegroundColor Yellow
        Get-Content -LiteralPath $NucleiTakeover | Select-Object -First 20 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    }
    if ((Test-Path $SubzyOut) -and ((Get-Content -LiteralPath $SubzyOut).Count -gt 0)) {
        Write-Host "  [Subzy] Potential takeovers:" -ForegroundColor Yellow
        Get-Content -LiteralPath $SubzyOut | Select-Object -First 20 | ForEach-Object { Write-Host "    $_" -ForegroundColor Red }
    }
    if (((Test-Path $NucleiTakeover) -and ((Get-Content -LiteralPath $NucleiTakeover).Count -eq 0) -or (-not (Test-Path $NucleiTakeover))) -and
        ((Test-Path $SubzyOut) -and ((Get-Content -LiteralPath $SubzyOut).Count -eq 0) -or (-not (Test-Path $SubzyOut)))) {
        Write-Host "  No potential takeovers found." -ForegroundColor Green
    }
    Write-Host "===============================`n" -ForegroundColor Cyan
    Write-Host "[+] Results saved to: $TakeoverDir" -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# VULNERABILITY SCAN (--vuln)
# ----------------------------------------------------------------------------
function Invoke-VulnScan {
    param([string]$Input)
    Write-Step "VULNERABILITY SCANNING (Nuclei)"

    $ResolvedFile = Join-Path $HttpDir "live-urls.txt"
    $VulnOut      = Join-Path $VulnDir "nuclei-vulns.txt"

    if (-not (Test-Path $ResolvedFile)) {
        $PassiveSubs = Join-Path $SubsDir "passive-subs.txt"
        Invoke-PassiveRecon -TargetDomain $Input -OutFile $PassiveSubs
        $ResolvedSubs = Join-Path $SubsDir "resolved-subs.txt"
        Invoke-DNSResolve -SubsIn $PassiveSubs -ResolvedOut $ResolvedSubs
        $null = Invoke-HTTPDiscovery -ResolvedIn $ResolvedSubs
    }

    if (-not (Test-Path $ResolvedFile)) {
        Write-Host "[!] No live hosts found." -ForegroundColor Red
        return
    }

    if (-not (Get-Command nuclei -ErrorAction SilentlyContinue)) {
        Write-Host "[!] nuclei not found. Install: go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" -ForegroundColor Red
        return
    }

    Write-Host "[+] Running nuclei with CVE, exposures, misconfig, and default-login templates..." -ForegroundColor Gray
    nuclei -l $ResolvedFile -t ~/nuclei-templates/http/cves/ `
        -t ~/nuclei-templates/http/exposures/ `
        -t ~/nuclei-templates/http/misconfiguration/ `
        -t ~/nuclei-templates/http/default-logins/ `
        -t ~/nuclei-templates/http/vulnerabilities/ `
        -severity critical,high,medium `
        -concurrency $Concurrency -timeout 10 -retries 1 `
        -stats -silent -o $VulnOut 2>$null

    if (Test-Path $VulnOut) {
        $VulnCount = (Get-Content -LiteralPath $VulnOut | Measure-Object).Count
        Write-Host "`n===== VULNERABILITY FINDINGS =====" -ForegroundColor Cyan
        Get-Content -LiteralPath $VulnOut | ForEach-Object {
            $Color = if ($_ -match '\[critical\]') { 'Red' }
                     elseif ($_ -match '\[high\]') { 'Magenta' }
                     elseif ($_ -match '\[medium\]') { 'Yellow' }
                     else { 'White' }
            Write-Host "  $_" -ForegroundColor $Color
        }
        Write-Host "====================================" -ForegroundColor Cyan
        Write-Host "[+] Nuclei found $VulnCount findings" -ForegroundColor Yellow
    }
    Write-Host "[+] Results saved to: $VulnDir" -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# CRAWL (--crawl)
# ----------------------------------------------------------------------------
function Invoke-Crawl {
    param([string]$Input)
    Write-Step "WEB CRAWLING (Katana)"

    $ResolvedFile = Join-Path $HttpDir "live-urls.txt"
    $CrawlOut     = Join-Path $CrawlDir "katana-output.txt"
    $JSUrlsOut    = Join-Path $CrawlDir "js-urls.txt"

    if (-not (Test-Path $ResolvedFile)) {
        $PassiveSubs = Join-Path $SubsDir "passive-subs.txt"
        Invoke-PassiveRecon -TargetDomain $Input -OutFile $PassiveSubs
        $ResolvedSubs = Join-Path $SubsDir "resolved-subs.txt"
        Invoke-DNSResolve -SubsIn $PassiveSubs -ResolvedOut $ResolvedSubs
        $null = Invoke-HTTPDiscovery -ResolvedIn $ResolvedSubs
    }

    if (-not (Test-Path $ResolvedFile)) {
        Write-Host "[!] No live hosts found." -ForegroundColor Red
        return
    }

    if (-not (Get-Command katana -ErrorAction SilentlyContinue)) {
        Write-Host "[!] katana not found." -ForegroundColor Red
        return
    }

    $LiveUrls = Get-Content -LiteralPath $ResolvedFile | Where-Object { $_ -match '\S' } | Select-Object -First 20

    Write-Host "[+] Crawling up to $($LiveUrls.Count) live hosts..." -ForegroundColor Green
    katana -list $ResolvedFile -depth 3 -js-crawl -crawl-duration 120 `
        -field url -concurrency $Concurrency -rate-limit 15 -silent `
        -H "User-Agent: $(Get-RandomUA)" -o $CrawlOut 2>$null

    # Extract JS URLs separately
    if (Test-Path $CrawlOut) {
        Select-String -LiteralPath $CrawlOut -Pattern '\.js(\?|$)' | ForEach-Object { $_.Line } |
            Sort-Object -Unique | Out-File -FilePath $JSUrlsOut -Encoding utf8

        $CrawlCount   = (Get-Content -LiteralPath $CrawlOut | Measure-Object).Count
        $JSCount      = (Get-Content -LiteralPath $JSUrlsOut -ErrorAction SilentlyContinue | Measure-Object).Count
        Write-Host "[+] Crawled endpoints: $CrawlCount" -ForegroundColor Green
        Write-Host "[+] JavaScript files found: $JSCount" -ForegroundColor Green
    }

    Write-Host "[+] Results saved to: $CrawlDir" -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# COMPREHENSIVE PORT SCAN (--ports)
# ----------------------------------------------------------------------------
function Invoke-ComprehensivePortScan {
    param([string]$Input)
    Write-Step "COMPREHENSIVE PORT SCAN (Top 1000)"

    $ResolvedFile = Join-Path $HttpDir "live-urls.txt"
    $FullPorts    = Join-Path $PortsDir "full-ports.txt"
    $FullPortsXml = Join-Path $PortsDir "full-ports.xml"

    if (-not (Test-Path $ResolvedFile)) {
        $PassiveSubs = Join-Path $SubsDir "passive-subs.txt"
        Invoke-PassiveRecon -TargetDomain $Input -OutFile $PassiveSubs
        $ResolvedSubs = Join-Path $SubsDir "resolved-subs.txt"
        Invoke-DNSResolve -SubsIn $PassiveSubs -ResolvedOut $ResolvedSubs
        $null = Invoke-HTTPDiscovery -ResolvedIn $ResolvedSubs
    }

    if (-not (Test-Path $ResolvedFile)) {
        Write-Host "[!] No live hosts found. Attempting with raw IPs..." -ForegroundColor Red
        $PassiveSubs = Join-Path $SubsDir "passive-subs.txt"
        if (Test-Path $PassiveSubs) {
            $ResolvedSubs = Join-Path $SubsDir "resolved-subs.txt"
            Invoke-DNSResolve -SubsIn $PassiveSubs -ResolvedOut $ResolvedSubs
        }
    }

    if (-not (Get-Command nmap -ErrorAction SilentlyContinue)) {
        Write-Host "[!] nmap not found. Skipping." -ForegroundColor Red
        return
    }

    $TargetList = Get-Content -LiteralPath $ResolvedFile -ErrorAction SilentlyContinue |
        ForEach-Object { $_ -replace '^https?://', '' -replace ':\d+$', '' } | Sort-Object -Unique
    if (-not $TargetList) { Write-Host "[!] No targets to scan." -ForegroundColor Red; return }

    $TargetsStr = $TargetList -join ' '
    Write-Host "[+] Running Nmap top 1000 port scan on $($TargetList.Count) targets..." -ForegroundColor Green

    nmap -sV -sC --top-ports 1000 --open -T4 --max-retries 2 `
        --max-rtt-timeout 1500ms --min-rate 300 -oX $FullPortsXml -oN $FullPorts `
        $TargetsStr

    Write-Host "[+] Comprehensive port scan complete -> $FullPorts" -ForegroundColor Green
}

# ----------------------------------------------------------------------------
# FULL RECON WORKFLOW (--recon)
# ----------------------------------------------------------------------------
function Invoke-FullRecon {
    param([string]$TargetDomain)
    Write-Step "FULL RECON WORKFLOW - $TargetDomain"
    Write-Host "  Output Directory: $OutputDir" -ForegroundColor DarkGray

    # 1. Passive Subdomain Enumeration
    $PassiveSubs = Join-Path $SubsDir "passive-subs.txt"
    Invoke-PassiveRecon -TargetDomain $TargetDomain -OutFile $PassiveSubs

    # 2. DNS Resolution
    $ResolvedSubs = Join-Path $SubsDir "resolved-subs.txt"
    Invoke-DNSResolve -SubsIn $PassiveSubs -ResolvedOut $ResolvedSubs

    # 3. Permutation & Bruteforce (optional, if gotator + dnsgen available)
    Write-Step "PERMUTATION ENGINE (Optional)"
    $PermFile = Join-Path $SubsDir "permutations.txt"
    try {
        if ((Get-Command gotator -ErrorAction SilentlyContinue) -and (Test-Path $Permutations)) {
            gotator -sub $ResolvedSubs -perm $Permutations -depth 1 -numbers 3 -mindup -adv -md | Sort-Object -Unique | Out-File -FilePath $PermFile -Encoding utf8
        } elseif (Get-Command dnsgen -ErrorAction SilentlyContinue) {
            Get-Content -LiteralPath $ResolvedSubs | dnsgen - | Sort-Object -Unique | Out-File -FilePath $PermFile -Encoding utf8
        }
        if ((Test-Path $PermFile) -and ((Get-Item -LiteralPath $PermFile).Length -gt 0)) {
            Write-Host "[+] Permutations generated. Resolving..." -ForegroundColor Green
            $FullSubs = Join-Path $SubsDir "all-subs.txt"
            @($ResolvedSubs, $PermFile) | ForEach-Object { if (Test-Path $_) { Get-Content -LiteralPath $_ } } |
                Sort-Object -Unique | Out-File -FilePath $FullSubs -Encoding utf8
            $FullResolved = Join-Path $SubsDir "all-resolved.txt"
            Invoke-DNSResolve -SubsIn $FullSubs -ResolvedOut $FullResolved
            $ResolvedFile = $FullResolved
        } else {
            $ResolvedFile = $ResolvedSubs
        }
    } catch {
        Write-Host "[!] Permutation failed. Continuing with resolved subs only." -ForegroundColor Yellow
        $ResolvedFile = $ResolvedSubs
    }

    # 4. HTTP Live Discovery
    $LiveUrlsFile = Invoke-HTTPDiscovery -ResolvedIn $ResolvedFile

    # 5. Port Scan (Top CDN-Common Ports)
    if ($LiveUrlsFile) {
        Invoke-PortScan -LiveUrlsFile $LiveUrlsFile
    }

    Write-Step "RECON COMPLETE"
    Write-Host "  Passive subs     : $PassiveSubs"   -ForegroundColor Gray
    Write-Host "  Resolved subs    : $ResolvedFile"  -ForegroundColor Gray
    Write-Host "  Live HTTP(S)     : $HttpDir"       -ForegroundColor Gray
    Write-Host "  Port scans       : $PortsDir"      -ForegroundColor Gray
    Write-Host "  Full output dir  : $OutputDir"     -ForegroundColor Gray
}

# ----------------------------------------------------------------------------
# HELP DISPLAY
# ----------------------------------------------------------------------------
function Show-Help {
    Write-Host ""
    Write-Host "DESCRIPTION:" -ForegroundColor Cyan
    Write-Host "  Magnus is a modular offensive security recon automation framework."
    Write-Host "  It covers subdomain enumeration, live HTTP discovery, port scanning,"
    Write-Host "  endpoint collection, content discovery, technology fingerprinting,"
    Write-Host "  subdomain takeover checks, vulnerability scanning, and web crawling."
    Write-Host ""
    Write-Host "USAGE:" -ForegroundColor Cyan
    Write-Host "  .\magnus.ps1 [MODE] <target> [OPTIONS]" -ForegroundColor White
    Write-Host ""
    Write-Host "  Target can be a domain (example.com) or a file containing targets."
    Write-Host ""
    Write-Host "MODES:" -ForegroundColor Cyan
    Write-Host "  --recon, -Recon          " -ForegroundColor Yellow -NoNewline
    Write-Host "Full recon workflow (passive subs -> DNS resolve -> HTTP probe -> port scan)"
    Write-Host "  --passive, -Passive      " -ForegroundColor Yellow -NoNewline
    Write-Host "Passive-only recon (Subfinder + crt.sh + Assetfinder, no active probing)"
    Write-Host "  -gp, --endpoints         " -ForegroundColor Yellow -NoNewline
    Write-Host "Wayback Machine + GAU endpoint collection, merge and deduplicate"
    Write-Host "  --content, -Content      " -ForegroundColor Yellow -NoNewline
    Write-Host "Directory/path fuzzing on live hosts using FFuF with smart rate-limiting"
    Write-Host "  --tech, -Tech            " -ForegroundColor Yellow -NoNewline
    Write-Host "Technology stack fingerprinting (Wappalyzer signatures) on live hosts"
    Write-Host "  --takeover, -Takeover    " -ForegroundColor Yellow -NoNewline
    Write-Host "Subdomain takeover check using Nuclei takeover templates and Subzy"
    Write-Host "  --vuln, -Vuln            " -ForegroundColor Yellow -NoNewline
    Write-Host "Run Nuclei vulnerability templates against live HTTP/HTTPS hosts"
    Write-Host "  --crawl, -Crawl          " -ForegroundColor Yellow -NoNewline
    Write-Host "Recursive crawling with Katana to extract endpoints, forms, and JS URLs"
    Write-Host "  --ports, -Ports          " -ForegroundColor Yellow -NoNewline
    Write-Host "Comprehensive Nmap top 1000 port scan with service version detection"
    Write-Host ""
    Write-Host "OPTIONS:" -ForegroundColor Cyan
    Write-Host "  -Concurrency <N>         " -ForegroundColor Yellow -NoNewline
    Write-Host "Thread count for tools that support it (5-100, default: 25)"
    Write-Host "  -OutputDir <path>        " -ForegroundColor Yellow -NoNewline
    Write-Host "Base output directory (default: .\magnus-out\<target>\)"
    Write-Host "  -h, -Help                " -ForegroundColor Yellow -NoNewline
    Write-Host "Show this help message and exit"
    Write-Host ""
    Write-Host "REQUIRED TOOLS:" -ForegroundColor Cyan
    Write-Host "  Core      : " -ForegroundColor DarkGray -NoNewline
    Write-Host "subfinder, httpx, naabu/nmap"
    Write-Host "  Passive   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "assetfinder, crt.sh (built-in)"
    Write-Host "  DNS       : " -ForegroundColor DarkGray -NoNewline
    Write-Host "puredns or dnsx"
    Write-Host "  Endpoints : " -ForegroundColor DarkGray -NoNewline
    Write-Host "waybackurls, gau, uro"
    Write-Host "  Content   : " -ForegroundColor DarkGray -NoNewline
    Write-Host "ffuf"
    Write-Host "  Takeover  : " -ForegroundColor DarkGray -NoNewline
    Write-Host "nuclei, subzy"
    Write-Host "  Crawl     : " -ForegroundColor DarkGray -NoNewline
    Write-Host "katana"
    Write-Host "  Optional  : " -ForegroundColor DarkGray -NoNewline
    Write-Host "gotator, dnsgen"
    Write-Host ""
    Write-Host "EXAMPLES:" -ForegroundColor Cyan
    Write-Host "  .\magnus.ps1 --recon example.com" -ForegroundColor Green
    Write-Host "      Run full recon pipeline on example.com"
    Write-Host ""
    Write-Host "  .\magnus.ps1 --recon targets.txt" -ForegroundColor Green
    Write-Host "      Run full recon on all domains listed in targets.txt"
    Write-Host ""
    Write-Host "  .\magnus.ps1 -gp example.com" -ForegroundColor Green
    Write-Host "      Collect endpoints from Wayback Machine and GAU"
    Write-Host ""
    Write-Host "  .\magnus.ps1 --vuln example.com --concurrency 15" -ForegroundColor Green
    Write-Host "      Run vulnerability scan with 15 threads"
    Write-Host ""
    Write-Host "  .\magnus.ps1 --passive example.com -OutputDir C:\results" -ForegroundColor Green
    Write-Host "      Passive recon with custom output directory"
    Write-Host ""
    Write-Host "  Author  : RemmyNine" -ForegroundColor DarkGray
    Write-Host "  License : GPL-3.0" -ForegroundColor DarkGray
    Write-Host "  Repo    : https://github.com/RemmyNine/OffensiveSecurity" -ForegroundColor DarkGray
    Write-Host ""
}

# ----------------------------------------------------------------------------
# MAIN DISPATCH
# ----------------------------------------------------------------------------

# Handle -h / -Help first
if ($Help) {
    Show-Help
    exit 0
}

if (-not $Target -and ($Recon -or $Endpoints -or $Content -or $Tech -or $Passive -or $Crawl -or $Ports)) {
    Write-Host "[!] Target required for this mode. Usage: .\magnus.ps1 --recon example.com" -ForegroundColor Red
    Write-Host "    Run .\magnus.ps1 -h for full help." -ForegroundColor DarkGray
    exit 1
}

# Determine mode: if no flags set but target given, default to --recon
if (-not ($Recon -or $Endpoints -or $Content -or $Tech -or $Takeover -or $Vuln -or $Passive -or $Crawl -or $Ports)) {
    if ($Target) { $Recon = $true }
    else {
        Show-Help
        exit 0
    }
}

$DomainForFile = $Target

# Dispatch to the right function
if ($Recon) {
    $TargetsFile, $DomainList = Resolve-Target -Input $Target
    foreach ($D in $DomainList) {
        $safeD = $D -replace '[\\/:*?"<>|]', '_'
        $OutputDir = Join-Path (Get-Location) "magnus-out\$safeD"
        $SubsDir, $HttpDir, $PortsDir, $ContentDir, $EndpointsDir, $TechDir, $TakeoverDir, $VulnDir, $CrawlDir = $AllDirs | ForEach-Object {
            $_ -replace [regex]::Escape((Join-Path (Get-Location) "magnus-out\*")), (Join-Path (Get-Location) "magnus-out\$safeD")
        }
        # Re-create dirs
        foreach ($Dir in @($SubsDir, $HttpDir, $PortsDir, $ContentDir, $EndpointsDir, $TechDir, $TakeoverDir, $VulnDir, $CrawlDir)) {
            if (-not (Test-Path $Dir)) { New-Item -ItemType Directory -Path $Dir -Force | Out-Null }
        }
        Invoke-FullRecon -TargetDomain $D
    }
}
elseif ($Endpoints)  { Invoke-EndpointCollection -TargetDomain $Target }
elseif ($Content)    { Invoke-ContentDiscovery -Input $Target }
elseif ($Tech)       { Invoke-TechFingerprint -Input $Target }
elseif ($Takeover)   { Invoke-TakeoverCheck -Input $Target }
elseif ($Vuln)       { Invoke-VulnScan -Input $Target }
elseif ($Passive)    {
    $PassiveSubs = Join-Path $SubsDir "passive-subs.txt"
    Invoke-PassiveRecon -TargetDomain $Target -OutFile $PassiveSubs
}
elseif ($Crawl)      { Invoke-Crawl -Input $Target }
elseif ($Ports)      { Invoke-ComprehensivePortScan -Input $Target }

$FinishTime = Get-Date -Format 'HH:mm:ss'
Write-Host "`nMagnus finished at $FinishTime." -ForegroundColor Cyan
