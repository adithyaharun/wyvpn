#Requires -Version 5.1
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
$TargetDir = if ($env:CARGO_TARGET_DIR) { $env:CARGO_TARGET_DIR } else { Join-Path $Root 'target' }
$Cache = Join-Path $TargetDir 'packaging\cache'
$Work = Join-Path $TargetDir 'packaging\openvpn-windows'
$Out = Join-Path $Root 'apps\desktop\src-tauri\resources\openvpn-windows'

$Pins = @{}
foreach ($line in Get-Content (Join-Path $Root 'packaging\openvpn\VERSION')) {
    if ($line -match '^([A-Z0-9_]+)=(.*)$') { $Pins[$Matches[1]] = $Matches[2].Trim('"') }
}
foreach ($key in 'OPENVPN_VERSION', 'OPENVPN_SOURCE_URL', 'OPENVPN_SOURCE_SHA256', 'OPENVPN_WINDOWS_MSI_URL', 'OPENVPN_WINDOWS_MSI_SHA256', 'OPENVPN_WINDOWS_PUBLISHER') {
    if (-not $Pins[$key]) { throw "$key missing from packaging/openvpn/VERSION" }
}

function Get-Verified([string]$Url, [string]$Sha, [string]$Dest) {
    if ($Sha -notmatch '^[0-9a-f]{64}$') { throw "missing or placeholder SHA-256 for $Url" }
    $ok = (Test-Path $Dest) -and ((Get-FileHash -Algorithm SHA256 $Dest).Hash.ToLower() -eq $Sha)
    if (-not $ok) {
        Write-Host "downloading $Url"
        New-Item -ItemType Directory -Force (Split-Path $Dest) | Out-Null
        Invoke-WebRequest -Uri $Url -OutFile "$Dest.part" -UseBasicParsing
        Move-Item -Force "$Dest.part" $Dest
    }
    $got = (Get-FileHash -Algorithm SHA256 $Dest).Hash.ToLower()
    if ($got -ne $Sha) {
        Remove-Item -Force $Dest
        throw "SHA-256 mismatch for ${Url}: expected $Sha, got $got"
    }
}

function Assert-Signed([string]$Path, [string[]]$Publishers) {
    $sig = Get-AuthenticodeSignature -FilePath $Path
    if ($sig.Status -ne 'Valid') { throw "$Path signature is $($sig.Status)" }
    $subject = $sig.SignerCertificate.Subject
    if (-not ($Publishers | Where-Object { $subject -match ('(^|, )O="?' + [regex]::Escape($_)) })) {
        throw "$Path is signed by an unexpected publisher: $subject"
    }
}

function Get-MsiRows([string]$Msi, [string]$Query, [int]$Columns) {
    $installer = New-Object -ComObject WindowsInstaller.Installer
    $db = $installer.GetType().InvokeMember('OpenDatabase', 'InvokeMethod', $null, $installer, @($Msi, 0))
    $view = $db.GetType().InvokeMember('OpenView', 'InvokeMethod', $null, $db, @($Query))
    $view.GetType().InvokeMember('Execute', 'InvokeMethod', $null, $view, $null) | Out-Null
    $rows = @()
    while ($true) {
        $rec = $view.GetType().InvokeMember('Fetch', 'InvokeMethod', $null, $view, $null)
        if ($null -eq $rec) { break }
        $row = for ($i = 1; $i -le $Columns; $i++) {
            $rec.GetType().InvokeMember('StringData', 'GetProperty', $null, $rec, [object[]]@([int]$i))
        }
        $rows += , @($row)
    }
    $view.GetType().InvokeMember('Close', 'InvokeMethod', $null, $view, $null) | Out-Null
    return , $rows
}

function Get-LongName([string]$Name) {
    $source = ($Name -split ':')[-1]
    return ($source -split '\|')[-1]
}

$version = $Pins['OPENVPN_VERSION']
$msi = Join-Path $Cache ([IO.Path]::GetFileName($Pins['OPENVPN_WINDOWS_MSI_URL']))
$tarball = Join-Path $Cache "openvpn-$version.tar.gz"
Get-Verified $Pins['OPENVPN_WINDOWS_MSI_URL'] $Pins['OPENVPN_WINDOWS_MSI_SHA256'] $msi
Get-Verified $Pins['OPENVPN_SOURCE_URL'] $Pins['OPENVPN_SOURCE_SHA256'] $tarball

$OpenVpnPublisher = $Pins['OPENVPN_WINDOWS_PUBLISHER']
Assert-Signed $msi @($OpenVpnPublisher)

if (Test-Path $Work) { Remove-Item -Recurse -Force $Work }
$image = Join-Path $Work 'image'
New-Item -ItemType Directory -Force $image | Out-Null
$log = Join-Path $Work 'msiexec.log'
$proc = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/a', "`"$msi`"", '/qn', "TARGETDIR=`"$image`"", '/l*v', "`"$log`"")
if ($proc.ExitCode -ne 0) { throw "msiexec /a failed with $($proc.ExitCode); see $log" }

$openvpnExe = @(Get-ChildItem -Path $image -Recurse -File -Filter 'openvpn.exe')
if ($openvpnExe.Count -ne 1) { throw "expected one openvpn.exe in the MSI, found $($openvpnExe.Count)" }
$binDir = $openvpnExe[0].DirectoryName

if (Test-Path $Out) { Remove-Item -Recurse -Force $Out }
New-Item -ItemType Directory -Force $Out | Out-Null

$tapctl = Join-Path $binDir 'tapctl.exe'
if (-not (Test-Path $tapctl)) { throw "tapctl.exe not found next to openvpn.exe" }
# openvpnservmsg.dll ships unsigned and only serves OpenVPN's own Windows service, which we do not install
$binaries = @($openvpnExe[0], (Get-Item $tapctl)) + @(Get-ChildItem -Path $binDir -File -Filter '*.dll' | Where-Object Name -ne 'openvpnservmsg.dll')
foreach ($file in $binaries) {
    Assert-Signed $file.FullName @($OpenVpnPublisher, 'Microsoft Corporation')
    Copy-Item $file.FullName $Out
}

# msiexec /a skips the merge-module driver files, so they come straight from the embedded cabinet
$sevenZip = Get-Command 7z -ErrorAction SilentlyContinue
if (-not $sevenZip) { throw "7z is required to unpack the ovpn-dco driver from the MSI" }
$cabDir = Join-Path $Work 'cab'
& $sevenZip.Source x -y "-o$cabDir" $msi | Out-Null
if ($LASTEXITCODE -ne 0) { throw "7z could not unpack $msi" }
foreach ($cab in @(Get-ChildItem -Path $cabDir -File -Filter '*.cab')) {
    & $sevenZip.Source x -y "-o$cabDir" $cab.FullName | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "7z could not unpack $($cab.Name)" }
}

$files = Get-MsiRows $msi 'SELECT `File`, `FileName`, `Component_` FROM `File`' 3
$variants = @{ 'nx20' = 'driver'; 'nx21' = 'driver\win11' }
foreach ($variant in $variants.Keys) {
    $driverOut = Join-Path $Out $variants[$variant]
    New-Item -ItemType Directory -Force $driverOut | Out-Null
    foreach ($ext in 'inf', 'sys', 'cat') {
        $candidates = @($files | Where-Object { (Get-LongName $_[1]) -eq "ovpn-dco.$ext" })
        $row = $candidates | Where-Object { $_[2] -match $variant } | Select-Object -First 1
        # the nx20 inf carries no variant suffix
        if (-not $row -and $variant -eq 'nx20') { $row = $candidates | Where-Object { $_[2] -notmatch 'nx2[01]' } | Select-Object -First 1 }
        if (-not $row) { throw "ovpn-dco.$ext ($variant) not found in the MSI" }
        $path = Join-Path $cabDir $row[0]
        if (-not (Test-Path -LiteralPath $path)) { throw "cabinet entry $($row[0]) not found" }
        Copy-Item -LiteralPath $path (Join-Path $driverOut "ovpn-dco.$ext")
    }
    Assert-Signed (Join-Path $driverOut 'ovpn-dco.cat') @('Microsoft Corporation')
    $sys = Get-AuthenticodeSignature -FilePath (Join-Path $driverOut 'ovpn-dco.sys')
    if ($sys.Status -ne 'Valid' -and $sys.Status -ne 'NotSigned') { throw "ovpn-dco.sys ($variant) signature is $($sys.Status)" }
}

$src = Join-Path $Work 'src'
New-Item -ItemType Directory -Force $src | Out-Null
& (Join-Path $env:SystemRoot 'System32\tar.exe') -xzf $tarball -C $src "openvpn-$version/COPYING" "openvpn-$version/COPYRIGHT.GPL"
if ($LASTEXITCODE -ne 0) { throw "failed to extract license files from $tarball" }
Copy-Item (Join-Path $src "openvpn-$version\COPYRIGHT.GPL") (Join-Path $Out 'LICENSE')
Copy-Item (Join-Path $src "openvpn-$version\COPYING") (Join-Path $Out 'COPYING')
Set-Content -NoNewline -Path (Join-Path $Out 'VERSION') -Value "$version`n"

Write-Host "staged $Out"
Get-ChildItem -Recurse -File $Out | ForEach-Object { Write-Host "  $($_.FullName.Substring($Out.Length + 1))" }
