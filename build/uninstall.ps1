# uninstall.ps1 - send unload token, stop and delete the driver (Administrator)
#
# sc.exe is NOT used here: this machine's security policy blacklists sc.exe,
# while the SCM APIs still work, so the unload logic lives in user\service_ctl.py
# (advapi32). The service name is auto-detected from ActiveDevice - after a few
# upgrades there may be several instances on the box, and a hard-coded name
# would uninstall the wrong one.
param(
    [string]$ServiceName = ""
)

$ErrorActionPreference = "Stop"
$RootPath = Split-Path -Parent $PSScriptRoot

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[elevate] not administrator - requesting UAC ..." -ForegroundColor Yellow
    $relaunch = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"{0}"' -f $PSCommandPath))
    foreach ($k in $PSBoundParameters.Keys) {
        $relaunch += "-$k"
        $v = "$($PSBoundParameters[$k])"
        if ($v -match "\s") { $relaunch += ('"{0}"' -f $v) } else { $relaunch += $v }
    }
    Start-Process -FilePath "powershell" -Verb RunAs -ArgumentList $relaunch | Out-Null
    return
}

$py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $py) { throw "python not found in PATH" }

$argList = @("$RootPath\user\service_ctl.py", "uninstall")
if ($ServiceName -ne "") { $argList += @("--service", $ServiceName) }

& $py.Source @argList
if ($LASTEXITCODE -ne 0) { throw "uninstall failed: $LASTEXITCODE" }
Write-Host "DONE"
