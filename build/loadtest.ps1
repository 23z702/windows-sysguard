# loadtest.ps1 - controlled experiment to find WHY sysguard.sys fails to load
#
# Images (all signed with the same test cert):
#   probe.sys       does nothing but write a marker          -> control
#   sysguard.sys    full driver, WITH the LDR-flag patch
#   sysguard_np.sys full driver, WITHOUT the LDR-flag patch   -> bisect
#
# Decision tree (stops as soon as something loads):
#   1. probe       @ project build folder
#   2. probe       @ System32\drivers
#   3. sysguard    @ project build folder
#   4. sysguard    @ System32\drivers        (only if 3 failed)
#   5. sysguard_np @ project build folder    (only if 3 and 4 failed)
#
# Run as Administrator:  powershell -ExecutionPolicy Bypass -File build\loadtest.ps1
# If Huorong asks whether to allow loading a driver, click ALLOW.

$ErrorActionPreference = "Continue"

$Root    = Split-Path -Parent $PSScriptRoot
$Build   = Join-Path $Root "build"
$DrvDir  = Join-Path $env:SystemRoot "System32\drivers"

# Old images may have been archived into build\old\ by build\cleanup_old.py - look in both
function Find-Artifact([string]$Name) {
    foreach ($dir in @($Build, (Join-Path $Build "old"))) {
        $p = Join-Path $dir $Name
        if (Test-Path $p) { return $p }
    }
    return $null
}

$SysFile = Find-Artifact "sysguard.sys"
$NpFile  = Find-Artifact "sysguard_np.sys"
$PrbFile = Find-Artifact "probe.sys"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[elevate] not administrator - requesting UAC ..." -ForegroundColor Yellow
    Start-Process -FilePath "powershell" -Verb RunAs `
        -ArgumentList @("-NoProfile", "-ExecutionPolicy", "Bypass", "-NoExit",
                        "-File", ('"{0}"' -f $PSCommandPath)) | Out-Null
    return
}

foreach ($n in @("sysguard.sys", "sysguard_np.sys", "probe.sys")) {
    if (-not (Find-Artifact $n)) {
        throw ("missing: {0}  (run build\build.sh, or copy it back from build\old\)" -f $n)
    }
}

$script:rows = @()
$script:loadedWhere = $null

function Kill-Service([string]$Name) {
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    sc.exe stop $Name 2>&1 | Out-Null
    Start-Sleep -Milliseconds 400
    sc.exe delete $Name 2>&1 | Out-Null
    # wait until the service key is really gone, otherwise re-creating the same name
    # hits "marked for deletion" (1072/1073)
    for ($i = 0; $i -lt 10; $i++) {
        if (-not (Test-Path $key)) { break }
        Start-Sleep -Milliseconds 300
    }
}

function Test-Load([string]$Label, [string]$Name, [string]$ImagePath, [bool]$Cleanup) {
    Kill-Service $Name
    $createOut = ""
    $ok = $false
    for ($try = 0; $try -lt 3; $try++) {
        $createOut = (sc.exe create $Name type= kernel start= demand error= normal binPath= "$ImagePath" 2>&1 | Out-String).Trim()
        if ($LASTEXITCODE -eq 0) { $ok = $true; break }
        Start-Sleep -Milliseconds 700
    }
    if (-not $ok) {
        $script:rows += [pscustomobject]@{ Test = $Label; Result = "create failed"; Code = -1; Detail = $createOut }
        return $false
    }
    $startOut = (sc.exe start $Name 2>&1 | Out-String).Trim()
    $code = $LASTEXITCODE
    $oneLine = (($startOut -split "`r?`n") | Where-Object { $_.Trim() -ne "" }) -join " | "

    if ($code -eq 0) {
        $script:rows += [pscustomobject]@{ Test = $Label; Result = "LOADED"; Code = 0; Detail = "" }
    } else {
        $script:rows += [pscustomobject]@{ Test = $Label; Result = "failed"; Code = $code; Detail = $oneLine }
    }
    if ($Cleanup) { Kill-Service $Name }
    return ($code -eq 0)
}

Write-Host ""
Write-Host "================ driver load experiment ================"
$os = Get-CimInstance Win32_OperatingSystem
Write-Host ("OS : " + $os.Caption + "  build " + $os.BuildNumber)
Write-Host ""
Write-Host "step 1  probe       @ build folder"
$probeDesktop = Test-Load "probe @ build folder"     "sgprobe1" $PrbFile $true

Write-Host "step 2  probe       @ System32\drivers"
$probeCopy = Join-Path $DrvDir "sgprobe_tmp.sys"
Copy-Item $PrbFile $probeCopy -Force
$probeDrivers = Test-Load "probe @ System32\drivers" "sgprobe2" "\SystemRoot\System32\drivers\sgprobe_tmp.sys" $true
Remove-Item $probeCopy -Force -ErrorAction SilentlyContinue

# marker proves DriverEntry actually executed at least once
$markerRan = $false
if (Test-Path "HKLM:\SOFTWARE\SysGuardProbe") {
    $v = (Get-ItemProperty -Path "HKLM:\SOFTWARE\SysGuardProbe" -Name Entered -ErrorAction SilentlyContinue).Entered
    if ($v) { $markerRan = $true }
}

Write-Host "step 3  sysguard    @ build folder"
$guardDesktop = Test-Load "sysguard @ build folder" "sysguard" $SysFile $false
if ($guardDesktop) { $script:loadedWhere = "build folder" }

$guardDrivers = $false
if (-not $guardDesktop) {
    Write-Host "step 4  sysguard    @ System32\drivers"
    Copy-Item $SysFile (Join-Path $DrvDir "sysguard.sys") -Force
    $guardDrivers = Test-Load "sysguard @ System32\drivers" "sysguard" "\SystemRoot\System32\drivers\sysguard.sys" $false
    if ($guardDrivers) { $script:loadedWhere = "System32\drivers" }
}

$npDesktop = $null
if (-not $guardDesktop -and -not $guardDrivers) {
    Write-Host "step 5  sysguard_np @ build folder   (no LDR patch)"
    $npDesktop = Test-Load "sysguard_np @ build folder" "sysguard_np" $NpFile $true
}

Write-Host ""
Write-Host "================ results ================"
foreach ($r in $script:rows) {
    $line = "  {0,-28} {1,-14} {2}" -f $r.Test, $r.Result, $(if ($r.Code -ge 0) { "code=" + $r.Code } else { "" })
    if ($r.Result -eq "LOADED") { Write-Host $line -ForegroundColor Green }
    elseif ($r.Result -eq "failed") { Write-Host $line -ForegroundColor Red }
    else { Write-Host $line -ForegroundColor Yellow }
    if ($r.Detail) { Write-Host ("      " + $r.Detail) -ForegroundColor DarkGray }
}
if ($markerRan) { Write-Host "  probe marker present -> DriverEntry executed at least once" -ForegroundColor Green }

Write-Host ""
Write-Host "================ conclusion ================"
if ($script:loadedWhere) {
    Write-Host ("sysguard is LOADED from " + $script:loadedWhere + ".") -ForegroundColor Green
    Write-Host "Next:  python user\huorong_gui.py"
}
elseif ($probeDesktop -and ($npDesktop -eq $true)) {
    Write-Host "Probe loads; only the build WITHOUT the LDR patch loads." -ForegroundColor Yellow
    Write-Host "=> The LDR-flag patch is what gets rejected on this machine."
    Write-Host "   Next: drop ObRegisterCallbacks, use a mechanism that needs no patch."
}
elseif ($probeDesktop -and $npDesktop -eq $false) {
    Write-Host "Probe loads, both sysguard builds fail." -ForegroundColor Yellow
    Write-Host "=> Driver loading works; sysguard's image content is rejected as a whole."
    Write-Host "   Next: stub out one subsystem at a time until it loads."
}
elseif (-not $probeDesktop -and $probeDrivers) {
    Write-Host "Probe only loads from System32\drivers." -ForegroundColor Yellow
    Write-Host "=> The Desktop path is part of the problem."
}
elseif (-not $probeDesktop -and -not $probeDrivers) {
    Write-Host "Even the trivial probe cannot load from anywhere." -ForegroundColor Red
    Write-Host "=> Driver loading itself is blocked; sysguard's code is irrelevant so far."
    Write-Host "   Check Huorong driver-load protection, or watch for a popup that needs ALLOW."
}
else {
    Write-Host "Mixed result - read the table above." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "final state:"
$q = (sc.exe query sysguard 2>&1 | Out-String).Trim()
$lines = ($q -split "`r?`n") | Where-Object { $_.Trim() -ne "" } | Select-Object -First 4
foreach ($l in $lines) { Write-Host ("  " + $l) }
