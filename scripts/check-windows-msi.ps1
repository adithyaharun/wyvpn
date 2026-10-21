#Requires -Version 5.1
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$Root = Split-Path -Parent $PSScriptRoot
$Pins = @{}
foreach ($line in Get-Content (Join-Path $Root 'packaging\wintun\VERSION')) {
    if ($line -match '^([A-Z0-9_]+)=(.*)$') { $Pins[$Matches[1]] = $Matches[2].Trim('"') }
}
foreach ($key in 'WINTUN_DLL_SHA256', 'WINTUN_PUBLISHER') {
    if (-not $Pins[$key]) { throw "$key missing from packaging/wintun/VERSION" }
}

$item = Get-Item -LiteralPath $Path
$msis = @(if ($item.PSIsContainer) { Get-ChildItem -LiteralPath $item.FullName -File -Filter '*.msi' } else { $item })
if (-not $msis.Count) { throw "no .msi found in $Path" }

foreach ($msi in $msis) {
    $image = Join-Path ([IO.Path]::GetTempPath()) ("wyvpn-msi-" + [guid]::NewGuid())
    try {
        $log = "$image.log"
        $proc = Start-Process msiexec.exe -Wait -PassThru -ArgumentList @('/a', "`"$($msi.FullName)`"", '/qn', "TARGETDIR=`"$image`"", '/l*v', "`"$log`"")
        if ($proc.ExitCode -ne 0) { throw "msiexec /a $($msi.Name) failed with $($proc.ExitCode); see $log" }

        $daemon = @(Get-ChildItem -LiteralPath $image -Recurse -File -Filter 'wyvpnd.exe')
        if ($daemon.Count -ne 1) { throw "$($msi.Name): expected one wyvpnd.exe, found $($daemon.Count)" }
        $wintun = @(Get-ChildItem -LiteralPath $image -Recurse -File -Filter 'wintun.dll')
        if ($wintun.Count -ne 1) { throw "$($msi.Name): expected one wintun.dll, found $($wintun.Count)" }
        if ($wintun[0].DirectoryName -ne $daemon[0].DirectoryName) {
            throw "$($msi.Name): wintun.dll is in $($wintun[0].DirectoryName), not next to wyvpnd.exe in $($daemon[0].DirectoryName)"
        }

        $got = (Get-FileHash -Algorithm SHA256 -LiteralPath $wintun[0].FullName).Hash.ToLower()
        if ($got -ne $Pins['WINTUN_DLL_SHA256']) { throw "$($msi.Name): wintun.dll SHA-256 is $got, expected $($Pins['WINTUN_DLL_SHA256'])" }
        $sig = Get-AuthenticodeSignature -FilePath $wintun[0].FullName
        if ($sig.Status -ne 'Valid') { throw "$($msi.Name): wintun.dll signature is $($sig.Status)" }
        $publisher = $sig.SignerCertificate.GetNameInfo('SimpleName', $false)
        if ($publisher -ne $Pins['WINTUN_PUBLISHER']) { throw "$($msi.Name): wintun.dll is signed by $($sig.SignerCertificate.Subject)" }

        Write-Output "$($msi.Name): wintun.dll next to wyvpnd.exe, SHA-256 $got, signed by $publisher"
    } finally {
        if (Test-Path -LiteralPath $image) { Remove-Item -Recurse -Force -LiteralPath $image }
    }
}
