# install.ps1 - install and load a sysguard build (self-elevating, idempotent)
#
#   powershell -File build\install.ps1                      # build\sysguard_v4.sys -> sysguard3 (auto-picks a free name)
#   powershell -File build\install.ps1 -SysName sysguard_v4 -ServiceName sysguard3
#   powershell -File build\install.ps1 -Force               # reload even if the same image is already running
#
# Why this script is written this way
# -----------------------------------
# The driver protects its OWN service key (\SERVICES\<name>) against delete/write.
# So "delete the old entry, then create it again" ALWAYS fails on a running
# instance: DeleteService returns success but only marks the key, our registry
# callback refuses the actual delete, and the next CreateService gets
# 1072 (ERROR_SERVICE_MARKED_FOR_DELETE). That is what used to happen here.
#
# Therefore:
#   1. already running this exact image (path + recorded SHA256) -> nothing to do
#   2. name is free                                             -> create it
#   3. name exists but unusable (running another image, marked for delete,
#      protected against deletion)                              -> fall through to
#                                                                 the next free name
#                                                                 (sysguard4, 5, ...)
param(
    [string]$SysName = "sysguard_v4",
    [string]$ServiceName = "sysguard3",
    [switch]$Force
)

$ErrorActionPreference = "Stop"

$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Host "[elevate] not administrator - requesting UAC ..." -ForegroundColor Yellow
    $argList = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ('"{0}"' -f $PSCommandPath))
    foreach ($k in $PSBoundParameters.Keys) {
        $argList += "-$k"
        $v = "$($PSBoundParameters[$k])"
        if ($v -match "\s") { $argList += ('"{0}"' -f $v) } else { $argList += $v }
    }
    Start-Process -FilePath "powershell" -Verb RunAs -ArgumentList $argList | Out-Null
    return
}

$RootPath = Split-Path -Parent $PSScriptRoot
$SysFile  = Join-Path $RootPath "build\$SysName.sys"
# Install records live OUTSIDE \SERVICES\<name>, which the driver protects.
$MetaRoot = "HKLM:\SOFTWARE\SysGuard\Installed"

$StepNames = @{
    0 = "DriverEntry start"
    1 = "IoCreateDevice"
    2 = "IoCreateSymbolicLink"
    3 = "ObRegisterCallbacks"
    4 = "ZwOpenKey(service key)"
    5 = "ObReferenceObjectByHandle(key)"
    6 = "CmRegisterCallbackEx"
    9 = "loaded OK"
}

function Show-Breadcrumb {
    param([string]$Name)
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name\Parameters"
    $raw = (Get-ItemProperty -Path $key -Name Breadcrumb -ErrorAction SilentlyContinue).Breadcrumb
    if (-not $raw) {
        Write-Host "  [diag] no breadcrumb -> DriverEntry never executed."
        Write-Host "         The image was rejected before any of our code ran."
        return
    }
    $step = [BitConverter]::ToUInt32($raw, 0)
    $st   = [UInt32]([BitConverter]::ToUInt32($raw, 4))
    $nm   = $StepNames[[int]$step]
    if (-not $nm) { $nm = "step $step" }
    $hex  = "0x{0:X8}" -f $st
    Write-Host ("  [diag] breadcrumb: step={0} ({1})  status={2}" -f $step, $nm, $hex)
    if ($step -eq 3 -and $hex -eq "0xC01C0011") {
        Write-Host "         altitude collision: another driver already uses that altitude."
        Write-Host "         The driver probes 349000.., this should not happen anymore."
    }
    if ($step -eq 6 -and $hex -ne "0x00000000") {
        Write-Host "         registry callback NOT active -> service key is writable/deletable."
    }
}

function Get-SvcInfo {
    param([string]$Name)
    $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$Name"
    if (-not (Test-Path $key)) { return $null }
    $p = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
    $flag = $null
    if ($p -and ($p.PSObject.Properties.Name -contains "DeleteFlag")) { $flag = [int]$p.DeleteFlag }
    $state = ""
    try { $state = (Get-Service -Name $Name -ErrorAction Stop).Status.ToString() } catch { $state = "" }
    [pscustomobject]@{
        Name      = $Name
        ImagePath = "$($p.ImagePath)"
        Start     = $p.Start
        DeleteFlag = $flag
        State     = $state
    }
}

function Normalize-Path {
    param([string]$Path)
    if (-not $Path) { return "" }
    $p = $Path.Trim().Trim('"')
    # \??\C:\...  ->  C:\...      (regex: backslash, question, question, backslash)
    $p = $p -replace '^\\\?\?\\', ''
    # \\?\C:\...  ->  C:\...
    $p = $p -replace '^\\\\\?\\', ''
    # \SystemRoot\System32\...  ->  C:\Windows\System32\...
    $p = $p -replace '^\\SystemRoot\\', "$env:SystemRoot\"
    return $p
}

function Test-SamePath {
    param([string]$A, [string]$B)
    $na = Normalize-Path $A
    $nb = Normalize-Path $B
    if (-not $na -or -not $nb) { return $false }
    return [string]::Equals($na, $nb, [StringComparison]::OrdinalIgnoreCase)
}

function Get-Meta {
    param([string]$Name)
    $k = Join-Path $MetaRoot $Name
    if (-not (Test-Path $k)) { return $null }
    return (Get-ItemProperty -Path $k -ErrorAction SilentlyContinue)
}

function Set-Meta {
    param([string]$Name, [string]$ImagePath, [string]$Hash)
    if (-not (Test-Path $MetaRoot)) { New-Item -Path $MetaRoot -Force | Out-Null }
    $k = Join-Path $MetaRoot $Name
    if (-not (Test-Path $k)) { New-Item -Path $k -Force | Out-Null }
    Set-ItemProperty -Path $k -Name ImagePath   -Value $ImagePath
    Set-ItemProperty -Path $k -Name Sha256      -Value $Hash
    Set-ItemProperty -Path $k -Name InstalledAt -Value (Get-Date -Format s)
}

function Get-NameCandidates {
    param([string]$Base)
    $out    = @($Base)
    $prefix = $Base
    $next   = 1
    if ($Base -match '^(.*?)(\d+)$') {
        $prefix = $matches[1]
        $next   = [int]$matches[2] + 1
    }
    for ($i = $next; $i -lt ($next + 20); $i++) { $out += ("{0}{1}" -f $prefix, $i) }
    return $out
}

if (-not (Test-Path $SysFile)) { throw "$SysFile not found. Run build\build.sh first." }

# sc.exe is not used anywhere: some environments blacklist it, while the SCM APIs
# always work. All service mutations go through user\service_ctl.py (advapi32).
$Py = (Get-Command python -ErrorAction SilentlyContinue)
if (-not $Py) { throw "python not found in PATH (needed for service_ctl.py)" }
$Ctl = Join-Path $RootPath "user\service_ctl.py"

# Python 3.15 writes UTF-8 (PEP 686), but PowerShell 5.1 decodes native output
# with the OEM code page (936 here), so every Chinese line turns into mojibake.
# Pin BOTH sides to UTF-8 for the duration of a call, then put the old values
# back. PYTHONIOENCODING alone is not enough (verified), and leaving the console
# code page at 65001 would corrupt whatever the user runs next in this window.
function With-Utf8 {
    param([scriptblock]$Body)
    $oldEnc = $null
    try { $oldEnc = [Console]::OutputEncoding } catch { }
    $oldIo  = $env:PYTHONIOENCODING
    try {
        [Console]::OutputEncoding = [System.Text.Encoding]::UTF8
        $env:PYTHONIOENCODING = "utf-8"
        & $Body
    } finally {
        if ($null -ne $oldEnc) { try { [Console]::OutputEncoding = $oldEnc } catch { } }
        if ($null -eq $oldIo)  { Remove-Item Env:\PYTHONIOENCODING -ErrorAction SilentlyContinue }
        else                   { $env:PYTHONIOENCODING = $oldIo }
    }
}

function Invoke-Ctl {
    param([string[]]$CtlArgs)
    $out  = With-Utf8 { & $Py.Source $Ctl @CtlArgs 2>&1 }
    $code = $LASTEXITCODE
    $text = ($out | Out-String).Trim()
    $winerr = $null
    $m = [regex]::Match($text, "ERR=(\d+)")
    if ($m.Success) { $winerr = [int]$m.Groups[1].Value }
    [pscustomobject]@{ Exit = $code; Text = $text; WinErr = $winerr }
}

function Show-CtlText {
    param([string]$Text)
    foreach ($line in ($Text -split "`r?`n")) {
        if ($line.Trim() -ne "") { Write-Host ("      " + $line) }
    }
}

$sig  = Get-AuthenticodeSignature $SysFile
$hash = (Get-FileHash -Path $SysFile -Algorithm SHA256).Hash
Write-Host ("[0/5] signature: " + $sig.Status + "   signer: " + $sig.SignerCertificate.Subject)
Write-Host ("      image    : " + $SysFile)
Write-Host ("      sha256   : " + $hash.Substring(0, 16) + "...")

# ---------------------------------------------------------------- 1. inspect
Write-Host "[1/5] inspecting existing service"
$existing = Get-SvcInfo $ServiceName
$skipAll  = $false

if ($existing -and -not $Force) {
    $samePath = Test-SamePath $existing.ImagePath $SysFile
    $meta     = Get-Meta $ServiceName
    $sameHash = ($meta -and $meta.Sha256 -and ($meta.Sha256 -eq $hash))

    if ($existing.State -eq "Running" -and $samePath -and $sameHash) {
        Write-Host ("      {0} is already running THIS image (sha256 matches) - nothing to do" -f $ServiceName) -ForegroundColor Green
        Write-Host  "      rebuilt the driver? run with -Force to load the new binary"
        $skipAll = $true
    }
    elseif ($existing.State -eq "Running" -and $samePath -and -not $meta) {
        Write-Host ("      {0} is running this path, but there is no install record yet" -f $ServiceName) -ForegroundColor Yellow
        Write-Host  "      assuming it is current; use -Force if you just rebuilt"
        Set-Meta $ServiceName $SysFile $hash
        $skipAll = $true
    }
    elseif ($existing.State -eq "Running") {
        Write-Host ("      {0} is RUNNING a different image:" -f $ServiceName)
        Write-Host ("        loaded : " + $existing.ImagePath)
        Write-Host  "      it cannot be deleted while it protects itself -> will use the next free name"
    }
    else {
        Write-Host ("      {0} exists but is not running (state='{1}', DeleteFlag={2})" -f $ServiceName, $existing.State, $existing.DeleteFlag)
    }
}
elseif ($existing -and $Force) {
    Write-Host ("      -Force: a running instance cannot be replaced in place (it protects its own key)")
    Write-Host  "      -> the new build goes to the next free service name, the old one keeps running"
    Write-Host  "      note: the SAME .sys file cannot be loaded twice (the kernel reports err 2)."
    Write-Host  "            rebuilt in place? uninstall the old instance first:"
    Write-Host ("              python user\service_ctl.py uninstall --service " + $ServiceName)
}
else {
    Write-Host ("      {0} does not exist yet" -f $ServiceName)
}

# ---------------------------------------------------------------- 2. create
$chosen = $ServiceName

if (-not $skipAll) {
    Write-Host "[2/5] creating kernel service"
    $chosen = $null
    foreach ($cand in (Get-NameCandidates $ServiceName)) {
        $info = Get-SvcInfo $cand
        if ($info) {
            if ($info.State -eq "Running") {
                Write-Host ("      {0,-11} in use (RUNNING) - next name" -f $cand)
                continue
            }
            if ($info.DeleteFlag) {
                Write-Host ("      {0,-11} marked for delete - next name" -f $cand)
                continue
            }
            Invoke-Ctl @("delete", "--service", $cand) | Out-Null
            Start-Sleep -Milliseconds 400
            if (Get-SvcInfo $cand) {
                Write-Host ("      {0,-11} leftover key refused to go away - next name" -f $cand)
                continue
            }
            Write-Host ("      {0,-11} leftover key removed, reusing the name" -f $cand)
        }

        $r = Invoke-Ctl @("create", "--service", $cand, "--image", $SysFile)
        if ($r.Exit -eq 0) { $chosen = $cand; Show-CtlText $r.Text; break }

        Write-Host ("      {0,-11} create failed {1} - next name" -f $cand, $r.WinErr)
        if ($r.WinErr -notin @(1072, 1073, 183)) {
            Show-CtlText $r.Text
            throw "service_ctl create failed ($($r.WinErr))"
        }
    }
    if (-not $chosen) {
        throw "no usable service name (tried '$ServiceName' and 20 more). Reboot clears delete-pending keys."
    }
    Write-Host ("      service name: " + $chosen) -ForegroundColor Green
}

# ---------------------------------------------------------------- 3. start
if (-not $skipAll) {
    Write-Host "[3/5] starting driver"
    $r = Invoke-Ctl @("start", "--service", $chosen)
    if ($r.Exit -ne 0) {
        $code = $r.WinErr
        Show-CtlText $r.Text
        Write-Host ""
        Write-Host "  start FAILED with code $code" -ForegroundColor Red
        Show-Breadcrumb $chosen
        Write-Host ""
        Write-Host "  What the code means:"
        Write-Host "    2   the loader could not find the image (path / pre-load rejection)"
        Write-Host "    5   the image was opened but rejected (driver-load protection)"
        Write-Host "    577 the image failed signature validation"
        Write-Host ""
        Write-Host "  Next step - run the controlled experiment, it isolates the cause:"
        Write-Host "    powershell -ExecutionPolicy Bypass -File build\loadtest.ps1"
        # do not leave an empty service key behind, it would become delete-pending
        Invoke-Ctl @("delete", "--service", $chosen) | Out-Null
        throw "driver start failed: $code"
    }
    Show-CtlText $r.Text
    Set-Meta $chosen $SysFile $hash
}

# ---------------------------------------------------------------- 4. verify
Write-Host "[4/5] verify"
$svc = Get-Service -Name $chosen -ErrorAction SilentlyContinue
if ($svc) { Write-Host ("      service  : {0}  {1}" -f $svc.Name, $svc.Status) }
$drv = Get-CimInstance Win32_SystemDriver -Filter ("Name='{0}'" -f $chosen) -ErrorAction SilentlyContinue
if ($drv) { Write-Host ("      driver   : state={0} started={1}" -f $drv.State, $drv.Started) }
Write-Host ("      image    : " + $SysFile)
Show-Breadcrumb $chosen
# Captured rather than streamed: PowerShell then decodes the UTF-8 bytes itself
# and Write-Host emits real Unicode, so this reads correctly on any console code
# page and in a redirected log alike.
$drvInfo = With-Utf8 { & $Py.Source "$RootPath\user\guard_ctl.py" 2>&1 }
foreach ($line in ($drvInfo -split "`r?`n")) {
    Write-Host $line
}
Write-Host ""
Write-Host ("OK. service: " + $chosen + "   image: build\" + $SysName + ".sys")
Write-Host "Start UI       :  python user\huorong_gui.py"
Write-Host ("Kill test      :  python user\killtest.py --spawn --service " + $chosen)
Write-Host  "Clean leftovers:  python build\cleanup_old.py"
