#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
$TargetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $Root 'target' }
$Cache = Join-Path $TargetDir 'packaging\cache'
$Work = Join-Path $TargetDir 'packaging\wintun-windows'
$Out = Join-Path $Root 'apps\desktop\src-tauri\resources\wintun-windows'

$Pins = @{}
foreach ($line in Get-Content (Join-Path $Root 'packaging\wintun\VERSION')) {
    if ($line -match '^([A-Z0-9_]+)=(.*)$') { $Pins[$Matches[1]] = $Matches[2].Trim('"') }
}
foreach ($key in 'WINTUN_VERSION', 'WINTUN_URL', 'WINTUN_SHA256', 'WINTUN_DLL_SHA256', 'WINTUN_PUBLISHER', 'WINTUN_ISSUER', 'WINTUN_ISSUER_SHA256') {
    if (-not $Pins[$key]) { throw "$key missing from packaging/wintun/VERSION" }
}
foreach ($key in 'WINTUN_SHA256', 'WINTUN_DLL_SHA256', 'WINTUN_ISSUER_SHA256') {
    if ($Pins[$key] -notmatch '^[0-9a-f]{64}$') { throw "$key in packaging/wintun/VERSION is not a SHA-256" }
}

function Get-Sha256([string]$Path) {
    return (Get-FileHash -Algorithm SHA256 -LiteralPath $Path).Hash.ToLower()
}

function Get-Verified([string]$Url, [string]$Sha, [string]$Dest) {
    $ok = (Test-Path $Dest) -and ((Get-Sha256 $Dest) -eq $Sha)
    if (-not $ok) {
        Write-Host "downloading $Url"
        New-Item -ItemType Directory -Force (Split-Path $Dest) | Out-Null
        Invoke-WebRequest -Uri $Url -OutFile "$Dest.part" -UseBasicParsing
        Move-Item -Force "$Dest.part" $Dest
    }
    $got = Get-Sha256 $Dest
    if ($got -ne $Sha) {
        Remove-Item -Force $Dest
        throw "SHA-256 mismatch for ${Url}: expected $Sha, got $got"
    }
}

function Assert-WintunSigned([string]$Path) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid') { throw "$Path signature is $($sig.Status)" }
    $signer = $sig.SignerCertificate
    $publisher = $signer.GetNameInfo('SimpleName', $false)
    if ($publisher -ne $Pins['WINTUN_PUBLISHER']) { throw "$Path is signed by an unexpected publisher: $($signer.Subject)" }
    $issuerName = $signer.GetNameInfo('SimpleName', $true)
    if ($issuerName -ne $Pins['WINTUN_ISSUER']) { throw "$Path signer has an unexpected issuer: $($signer.Issuer)" }

    $chain = New-Object Security.Cryptography.X509Certificates.X509Chain
    $chain.ChainPolicy.RevocationMode = 'NoCheck'
    # the leaf has expired; the timestamp keeps the signature valid
    $chain.ChainPolicy.VerificationFlags = 'IgnoreNotTimeValid'
    try {
        $embedded = New-Object Security.Cryptography.X509Certificates.X509Certificate2Collection
        $embedded.Import($Path)
        $chain.ChainPolicy.ExtraStore.AddRange($embedded)
    } catch {
        Write-Host "could not read the embedded certificates of ${Path}: $_"
    }
    [void]$chain.Build($signer)
    if ($chain.ChainElements.Count -lt 2) { throw "cannot build the certificate chain of $Path" }
    $issuer = $chain.ChainElements[1].Certificate
    $issuerSha = ([BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($issuer.RawData)) -replace '-', '').ToLower()
    if ($issuerSha -ne $Pins['WINTUN_ISSUER_SHA256']) { throw "$Path issuer certificate SHA-256 is $issuerSha, expected $($Pins['WINTUN_ISSUER_SHA256'])" }
}

$version = $Pins['WINTUN_VERSION']
$zip = Join-Path $Cache "wintun-$version.zip"
Get-Verified $Pins['WINTUN_URL'] $Pins['WINTUN_SHA256'] $zip

if (Test-Path $Work) { Remove-Item -Recurse -Force $Work }
New-Item -ItemType Directory -Force $Work | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
$archive = [IO.Compression.ZipFile]::OpenRead($zip)
try {
    foreach ($name in 'wintun/bin/amd64/wintun.dll', 'wintun/LICENSE.txt') {
        $entry = $archive.GetEntry($name)
        if (-not $entry) { throw "$name not found in $zip" }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entry, (Join-Path $Work $entry.Name), $true)
    }
} finally {
    $archive.Dispose()
}

$dll = Join-Path $Work 'wintun.dll'
$got = Get-Sha256 $dll
if ($got -ne $Pins['WINTUN_DLL_SHA256']) { throw "wintun.dll SHA-256 is $got, expected $($Pins['WINTUN_DLL_SHA256'])" }
Assert-WintunSigned $dll

if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
New-Item -ItemType Directory -Force $Out | Out-Null
Copy-Item $dll $Out
Copy-Item (Join-Path $Work 'LICENSE.txt') $Out
Set-Content -NoNewline -Path (Join-Path $Out 'VERSION') -Value "$version`n"

Write-Host "staged $Out"
Get-ChildItem -File $Out | ForEach-Object { Write-Host "  $($_.Name)" }
