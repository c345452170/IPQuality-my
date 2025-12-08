<#!
.SYNOPSIS
    Cross-platform IP quality inspector for PowerShell.
.DESCRIPTION
    Provides a PowerShell-native way to fetch IP information using multiple public data sources.
    Attempts to mirror the Linux bash script capabilities where possible without external dependencies.
.PARAMETER IPv4
    Query only IPv4 connectivity.
.PARAMETER IPv6
    Query only IPv6 connectivity.
.PARAMETER Address
    Explicit IP address to check; if omitted, public addresses are discovered automatically.
.PARAMETER Proxy
    Optional proxy URL (http/https/socks) used for outbound HTTP requests.
.PARAMETER Json
    Output raw JSON instead of a formatted table.
.PARAMETER Output
    Path to write report output. When set, console output still appears unless -Quiet is passed.
.PARAMETER Quiet
    Suppress console output and only write to the specified output file.
.EXAMPLE
    pwsh ./ip.ps1
.EXAMPLE
    pwsh ./ip.ps1 -IPv4 -Proxy "http://user:pass@127.0.0.1:8080" -Json
#>
param(
    [switch]$IPv4,
    [switch]$IPv6,
    [string]$Address,
    [string]$Proxy,
    [switch]$Json,
    [string]$Output,
    [switch]$Quiet
)

$ErrorActionPreference = 'Stop'

function Invoke-Http {
    param(
        [Parameter(Mandatory)] [string]$Uri
    )

    $invokeParams = @{ Uri = $Uri; Method = 'Get'; TimeoutSec = 12; ErrorAction = 'Stop' }
    if ($Proxy) { $invokeParams['Proxy'] = $Proxy }
    try {
        return Invoke-RestMethod @invokeParams
    } catch {
        return $null
    }
}

function Get-PublicIP {
    param(
        [Parameter(Mandatory)] [ValidateSet('4','6')] [string]$Family
    )
    $endpoint = if ($Family -eq '6') { 'https://api64.ipify.org?format=json' } else { 'https://api.ipify.org?format=json' }
    $result = Invoke-Http -Uri $endpoint
    return $result?.ip
}

function Get-IpapiProfile {
    param([string]$IP)
    $response = Invoke-Http -Uri "https://ipapi.is/?q=$IP"
    if (-not $response) { return $null }
    return [ordered]@{
        Provider    = 'ipapi.is'
        Country     = $response.country
        Region      = $response.region
        City        = $response.city
        ASN         = $response.asn
        ISP         = $response.isp
        Latitude    = $response.latitude
        Longitude   = $response.longitude
        VPN         = $response.vpn
        Proxy       = $response.proxy
        Hosting     = $response.hosting
        Security    = $response.security
        RiskScore   = $response.risk
    }
}

function Get-IpinfoProfile {
    param([string]$IP)
    $response = Invoke-Http -Uri "https://ipinfo.io/$IP/json"
    if (-not $response) { return $null }
    return [ordered]@{
        Provider  = 'ipinfo.io'
        Country   = $response.country
        Region    = $response.region
        City      = $response.city
        ASN       = $response.org
        Location  = $response.loc
        Postal    = $response.postal
        Timezone  = $response.timezone
    }
}

function Get-IpwhoisProfile {
    param([string]$IP)
    $response = Invoke-Http -Uri "https://ipwho.is/$IP"
    if (-not $response) { return $null }
    return [ordered]@{
        Provider = 'ipwho.is'
        Country  = $response.country
        Region   = $response.region
        City     = $response.city
        ASN      = $response.connection.asn
        ISP      = $response.connection.isp
        Type     = $response.type
        Risk     = $response.security.risk
        Threats  = $response.security.threat_level
    }
}

function Resolve-IPTargets {
    if ($Address) { return @($Address) }

    $targets = @()
    if (-not $IPv6) {
        $ipv4 = Get-PublicIP -Family '4'
        if ($ipv4) { $targets += $ipv4 }
    }
    if (-not $IPv4) {
        $ipv6 = Get-PublicIP -Family '6'
        if ($ipv6) { $targets += $ipv6 }
    }

    return $targets
}

function Collect-IPProfile {
    param([string]$IP)

    $profile = [ordered]@{
        Address = $IP
        Timestamp = (Get-Date).ToString('u')
        Sources = @()
    }

    $sources = @(
        Get-IpapiProfile -IP $IP,
        Get-IpinfoProfile -IP $IP,
        Get-IpwhoisProfile -IP $IP
    ) | Where-Object { $_ }

    $profile.Sources = $sources
    return $profile
}

function Format-ProfileTable {
    param([hashtable]$Profile)

    $lines = @()
    $lines += ('=' * 60)
    $lines += "IP: {0}" -f $Profile.Address
    $lines += "Time: {0}" -f $Profile.Timestamp
    $lines += ('-' * 60)

    foreach ($src in $Profile.Sources) {
        $lines += "[{0}]" -f $src.Provider
        $lines += "  Country : {0}" -f ($src.Country -join ', ')
        if ($src.Region)    { $lines += "  Region  : $($src.Region)" }
        if ($src.City)      { $lines += "  City    : $($src.City)" }
        if ($src.ASN)       { $lines += "  ASN/ISP : $($src.ASN)" }
        if ($src.ISP -and -not $src.ASN) { $lines += "  ISP     : $($src.ISP)" }
        if ($src.Location)  { $lines += "  Geo     : $($src.Location)" }
        if ($src.Latitude -and $src.Longitude) {
            $lines += "  Geo     : $($src.Latitude), $($src.Longitude)"
        }
        if ($src.Type)      { $lines += "  Type    : $($src.Type)" }
        if ($src.Security)  { $lines += "  Security: $($src.Security)" }
        if ($src.Risk)      { $lines += "  Risk    : $($src.Risk)" }
        if ($src.RiskScore) { $lines += "  Risk    : $($src.RiskScore)" }
        if ($src.VPN -ne $null) { $lines += "  VPN     : $($src.VPN)" }
        if ($src.Proxy -ne $null) { $lines += "  Proxy   : $($src.Proxy)" }
        if ($src.Hosting -ne $null) { $lines += "  Hosting : $($src.Hosting)" }
        if ($src.Threats)   { $lines += "  Threats : $($src.Threats)" }
        $lines += ('-' * 60)
    }

    if (-not $Profile.Sources) {
        $lines += "No data sources responded. Check your connectivity or proxy settings."
    }
    return $lines -join [Environment]::NewLine
}

$targets = Resolve-IPTargets
if (-not $targets) {
    Write-Warning 'No public IP address could be determined. Specify -Address to force a lookup.'
    exit 1
}

$reports = @()
foreach ($ip in $targets) {
    $reports += Collect-IPProfile -IP $ip
}

if ($Json) {
    $outputContent = $reports | ConvertTo-Json -Depth 6
} else {
    $formatted = $reports | ForEach-Object { Format-ProfileTable -Profile $_ }
    $outputContent = $formatted -join ([Environment]::NewLine + [Environment]::NewLine)
}

if ($Output) {
    $dir = Split-Path -Parent $Output
    if ($dir -and -not (Test-Path $dir)) { New-Item -ItemType Directory -Force -Path $dir | Out-Null }
    $outputContent | Out-File -FilePath $Output -Encoding UTF8
}

if (-not $Quiet) {
    Write-Output $outputContent
}
