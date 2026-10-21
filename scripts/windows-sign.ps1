param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('pre', 'post')]
    [string]$Phase,
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = 'Stop'

$timestampUrl = if ($env:WINDOWS_TIMESTAMP_URL) { $env:WINDOWS_TIMESTAMP_URL } else { 'http://timestamp.digicert.com' }
$usePfx = [bool]$env:WINDOWS_CERTIFICATE
$useAzure = [bool]($env:AZURE_TRUSTED_SIGNING_ENDPOINT -and $env:AZURE_TRUSTED_SIGNING_ACCOUNT -and $env:AZURE_CERTIFICATE_PROFILE -and $env:AZURE_CODESIGNING_DLIB)

if (-not $usePfx -and -not $useAzure) {
    Write-Warning "No signing credentials set; leaving $Path unsigned"
    exit 0
}

function Find-SignTool {
    if ($env:SIGNTOOL) { return $env:SIGNTOOL }
    $onPath = Get-Command signtool.exe -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    $kits = Join-Path ${env:ProgramFiles(x86)} 'Windows Kits\10\bin'
    $found = Get-ChildItem -Path $kits -Filter signtool.exe -Recurse -ErrorAction SilentlyContinue |
        Where-Object { $_.Directory.Name -eq 'x64' } |
        Sort-Object {
            $version = $null
            if ([version]::TryParse($_.Directory.Parent.Name, [ref]$version)) { $version } else { [version]'0.0' }
        } |
        Select-Object -Last 1
    if (-not $found) { throw 'signtool.exe not found; set SIGNTOOL' }
    return $found.FullName
}

function Get-Targets {
    $item = Get-Item -LiteralPath $Path
    if (-not $item.PSIsContainer) { return @($item) }
    $patterns = if ($Phase -eq 'pre') { @('*.exe', '*.dll') } else { @('*.msi') }
    Get-ChildItem -LiteralPath $item.FullName -Recurse -File -Include $patterns
}

function Test-Skip([IO.FileInfo]$File) {
    # bundled OpenVPN files and wintun.dll keep their upstream signatures, which the daemon pins
    if ($File.FullName -match '[\\/](openvpn|openvpn-windows)[\\/]') { return $true }
    if ($File.Name -eq 'wintun.dll') { return $true }
    return (Get-AuthenticodeSignature -LiteralPath $File.FullName).Status -eq 'Valid'
}

function Import-PfxThumbprint {
    $bytes = [Convert]::FromBase64String($env:WINDOWS_CERTIFICATE)
    $flags = [Security.Cryptography.X509Certificates.X509KeyStorageFlags]'PersistKeySet, UserKeySet'
    $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2(
        $bytes, $env:WINDOWS_CERTIFICATE_PASSWORD, $flags)
    $store = New-Object Security.Cryptography.X509Certificates.X509Store('My', 'CurrentUser')
    $store.Open('ReadWrite')
    try {
        if (-not $store.Certificates.Find('FindByThumbprint', $cert.Thumbprint, $false).Count) {
            $store.Add($cert)
        }
    } finally {
        $store.Close()
    }
    return $cert.Thumbprint
}

function Get-SignArgs {
    if ($usePfx) {
        $thumbprint = Import-PfxThumbprint
        return @('sign', '/fd', 'sha256', '/tr', $timestampUrl, '/td', 'sha256', '/s', 'My', '/sha1', $thumbprint)
    }
    $metadata = Join-Path ([IO.Path]::GetTempPath()) 'wyvpn-trusted-signing.json'
    @{
        Endpoint               = $env:AZURE_TRUSTED_SIGNING_ENDPOINT
        CodeSigningAccountName = $env:AZURE_TRUSTED_SIGNING_ACCOUNT
        CertificateProfileName = $env:AZURE_CERTIFICATE_PROFILE
    } | ConvertTo-Json | Set-Content -LiteralPath $metadata -Encoding UTF8
    $azureTimestamp = if ($env:WINDOWS_TIMESTAMP_URL) { $timestampUrl } else { 'http://timestamp.acs.microsoft.com' }
    return @('sign', '/fd', 'sha256', '/tr', $azureTimestamp, '/td', 'sha256', '/dlib', $env:AZURE_CODESIGNING_DLIB, '/dmdf', $metadata)
}

$targets = @(Get-Targets | Where-Object { -not (Test-Skip $_) })
if (-not $targets.Count) {
    Write-Output "Nothing to sign in $Path"
    exit 0
}

$signtool = Find-SignTool
$signArgs = Get-SignArgs
foreach ($file in $targets) {
    Write-Output "Signing $($file.FullName)"
    & $signtool @signArgs $file.FullName
    if ($LASTEXITCODE -ne 0) { throw "signtool sign failed for $($file.FullName)" }
    & $signtool verify /pa $file.FullName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "signature verification failed for $($file.FullName)" }
}
