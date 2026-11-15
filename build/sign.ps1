# sign.ps1 [name] - create a test code-signing cert and sign build\<name>.sys
# Requires admin. testsigning is already enabled on this machine.
param([string]$Name = "sysguard")

$ErrorActionPreference = "Stop"

$RootPath = Split-Path -Parent $PSScriptRoot
$SysFile  = Join-Path $RootPath "build\$Name.sys"
$PfxFile  = Join-Path $RootPath "build\sysguard.pfx"
$CerFile  = Join-Path $RootPath "build\sysguard.cer"
$PfxPass  = "sysguard-test"
$SignTool = "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe"

if (-not (Test-Path $PfxFile)) {
    Write-Host "[1/3] creating self-signed code signing certificate"
    $cert = New-SelfSignedCertificate -Type CodeSigningCert -Subject "CN=SysGuard Test Signing" -CertStoreLocation Cert:\LocalMachine\My -HashAlgorithm SHA256 -KeyUsage DigitalSignature -KeyLength 2048 -NotAfter (Get-Date).AddYears(5)

    $sec = ConvertTo-SecureString -String $PfxPass -Force -AsPlainText
    Export-PfxCertificate -Cert $cert -FilePath $PfxFile -Password $sec | Out-Null
    Export-Certificate   -Cert $cert -FilePath $CerFile | Out-Null

    Write-Host "[2/3] importing cert into Root and TrustedPublisher"
    Import-Certificate -FilePath $CerFile -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
    Import-Certificate -FilePath $CerFile -CertStoreLocation Cert:\LocalMachine\TrustedPublisher | Out-Null
} else {
    Write-Host "[1/3] reuse existing pfx: $PfxFile"
}

Write-Host "[3/3] signing $SysFile"
& $SignTool sign /f $PfxFile /p $PfxPass /fd sha256 /v $SysFile
if ($LASTEXITCODE -ne 0) { throw "signtool sign failed" }

& $SignTool verify /pa $SysFile
Write-Host "DONE"
