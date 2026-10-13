param(
    [Parameter(Mandatory = $true)]
    [ValidateSet('Install', 'Uninstall')]
    [string]$Action,
    [switch]$RemoveData
)

$ErrorActionPreference = 'Stop'

$dataDir = Join-Path $env:ProgramData 'WyVPN'
$openvpnDir = Join-Path $PSScriptRoot 'openvpn'
$driverInf = Join-Path $openvpnDir 'driver\ovpn-dco.inf'
$win11Inf = Join-Path $openvpnDir 'driver\win11\ovpn-dco.inf'
if ([Environment]::OSVersion.Version.Build -ge 22000 -and (Test-Path -LiteralPath $win11Inf)) {
    $driverInf = $win11Inf
}
$tapctl = Join-Path $openvpnDir 'tapctl.exe'
$pnputil = Join-Path $env:SystemRoot 'System32\pnputil.exe'
$icacls = Join-Path $env:SystemRoot 'System32\icacls.exe'
$stateKey = 'HKLM:\SOFTWARE\WyVPN'
$driverValue = 'DcoDriverInf'
$adapterName = 'WyVPN'
$systemSid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-18'
$adminsSid = New-Object Security.Principal.SecurityIdentifier 'S-1-5-32-544'

function Test-ReparsePoint([string]$Path) {
    $item = Get-Item -LiteralPath $Path -Force
    return -not $item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint)
}

function Test-TrustedDir([string]$Path) {
    try {
        if (Test-ReparsePoint $Path) {
            return $false
        }
        $owner = (Get-Acl -LiteralPath $Path).GetOwner([Security.Principal.SecurityIdentifier])
        return $owner -eq $systemSid -or $owner -eq $adminsSid
    } catch {
        return $false
    }
}

function Set-DataDirAcl {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($systemSid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($sid in $systemSid, $adminsSid) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule(
            $sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        $acl.AddAccessRule($rule)
    }
    Set-Acl -LiteralPath $dataDir -AclObject $acl
}

function Reset-DataDir {
    if (Test-ReparsePoint $dataDir) {
        throw "$dataDir is a link or file and cannot be reclaimed"
    }
    & $icacls $dataDir /setowner '*S-1-5-18' /L /Q
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /setowner failed with exit code $LASTEXITCODE"
    }
    Set-DataDirAcl
    & $icacls $dataDir /setowner '*S-1-5-18' /T /C /L /Q
    if ($LASTEXITCODE -ne 0) {
        throw "icacls /setowner /T failed with exit code $LASTEXITCODE"
    }
    if (Get-ChildItem -LiteralPath $dataDir -Force) {
        & $icacls (Join-Path $dataDir '*') /reset /T /C /L /Q
        if ($LASTEXITCODE -ne 0) {
            throw "icacls /reset failed with exit code $LASTEXITCODE"
        }
    }
}

function Lock-DataDir {
    # ProgramData lets any user pre-create this folder, so a squatted one is moved aside or reclaimed
    if ((Test-Path -LiteralPath $dataDir) -and -not (Test-TrustedDir $dataDir)) {
        $aside = 'WyVPN.untrusted-{0:yyyyMMddHHmmss}' -f (Get-Date)
        try {
            Rename-Item -LiteralPath $dataDir -NewName $aside
            Write-Output "Moved untrusted $dataDir to $aside"
        } catch {
            Write-Warning "Could not move $dataDir aside ($_); taking ownership instead"
            try {
                Reset-DataDir
            } catch {
                throw "Untrusted $dataDir could not be moved aside or reclaimed: $_. Delete it and run the installer again."
            }
            Write-Output "Reclaimed untrusted $dataDir"
        }
    }
    New-Item -ItemType Directory -Path $dataDir -Force | Out-Null
    Set-DataDirAcl
    if (-not (Test-TrustedDir $dataDir)) {
        throw "$dataDir is not owned by SYSTEM or Administrators after locking it down"
    }
}

function Get-Adapter {
    Get-NetAdapter -Name $adapterName -IncludeHidden -ErrorAction SilentlyContinue
}

function Get-DcoPackages {
    @(Get-WindowsDriver -Online |
        Where-Object { [IO.Path]::GetFileName($_.OriginalFileName) -eq 'ovpn-dco.inf' } |
        ForEach-Object { $_.Driver })
}

function Get-OwnedDcoPackages {
    $value = Get-ItemProperty -LiteralPath $stateKey -Name $driverValue -ErrorAction SilentlyContinue
    if ($value) { @($value.$driverValue | Where-Object { $_ }) } else { @() }
}

function Install-Driver {
    if (-not (Test-Path -LiteralPath $driverInf)) {
        throw "Missing $driverInf"
    }
    $before = Get-DcoPackages
    & $pnputil /add-driver $driverInf /install
    # 259: staged but no device to bind yet; 3010: reboot required
    if (@(0, 259, 3010) -notcontains $LASTEXITCODE) {
        throw "pnputil /add-driver failed with exit code $LASTEXITCODE"
    }
    $published = @(Get-DcoPackages | Where-Object { $before -notcontains $_ })
    if ($published.Count) {
        $owned = @(Get-OwnedDcoPackages) + $published | Select-Object -Unique
        New-Item -Path $stateKey -Force | Out-Null
        New-ItemProperty -LiteralPath $stateKey -Name $driverValue -PropertyType MultiString -Value ([string[]]$owned) -Force | Out-Null
    }
    if (-not (Test-Path -LiteralPath $tapctl)) {
        Write-Warning "Missing $tapctl; no adapter created"
        return
    }
    if (-not (Get-Adapter)) {
        & $tapctl create --hwid ovpn-dco --name $adapterName
        if ($LASTEXITCODE -ne 0) {
            throw "tapctl create failed with exit code $LASTEXITCODE"
        }
    }
}

function Uninstall-Driver {
    $adapter = Get-Adapter
    if ($adapter -and (Test-Path -LiteralPath $tapctl)) {
        & $tapctl delete $adapter.InterfaceGuid
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "tapctl delete failed with exit code $LASTEXITCODE"
        }
    }
    $present = Get-DcoPackages
    foreach ($package in Get-OwnedDcoPackages) {
        if ($present -notcontains $package) {
            continue
        }
        # no /uninstall: another OpenVPN install may still bind this package to its own adapter
        & $pnputil /delete-driver $package
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Kept driver package $package (pnputil exit code $LASTEXITCODE)"
        }
    }
    Remove-ItemProperty -LiteralPath $stateKey -Name $driverValue -ErrorAction SilentlyContinue
}

function Remove-DataDir {
    if (Test-Path -LiteralPath $dataDir) {
        # rmdir /s does not follow junctions, unlike Remove-Item -Recurse on Windows PowerShell 5.1
        & "$env:SystemRoot\System32\cmd.exe" /d /c rmdir /s /q "$dataDir"
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "rmdir failed with exit code $LASTEXITCODE"
        }
    }
}

switch ($Action) {
    'Install' {
        Lock-DataDir
        Install-Driver
    }
    'Uninstall' {
        try { Uninstall-Driver } catch { Write-Warning $_ }
        if ($RemoveData) {
            try { Remove-DataDir } catch { Write-Warning $_ }
        }
    }
}
exit 0
